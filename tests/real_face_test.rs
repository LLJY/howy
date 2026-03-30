//! Real-face test: loads a camera frame and runs full SCRFD + ArcFace pipeline.

use std::time::Instant;

use howy_common::config::HowyConfig;
use howy_daemon::inference::InferenceEngine;

const MODEL_DIR: &str = "dist/howdy_onnx/_internal/onnx-data";
const FRAME_PATH: &str = "/tmp/camera_frame.bgr";
const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    println!("=== howy real face test ===\n");

    // Load models
    let mut config = HowyConfig::default();
    config.ml.detector_model = format!("{MODEL_DIR}/det_10g.onnx");
    config.ml.recognizer_model = format!("{MODEL_DIR}/w600k_r50.onnx");
    config.ml.provider = std::env::var("HOWY_PROVIDER").unwrap_or_else(|_| "cpu".to_string());
    config.ml.det_threshold = 0.3;

    println!("[1] Loading models...");
    let engine = InferenceEngine::new(&config).expect("Failed to load models");
    engine.warmup().expect("Warmup failed");
    println!("    Models loaded and warmed up\n");

    // Load camera frame
    println!("[2] Loading camera frame from {FRAME_PATH}...");
    let bgr_data = std::fs::read(FRAME_PATH).expect("Failed to read frame file");
    assert_eq!(
        bgr_data.len(),
        (WIDTH * HEIGHT * 3) as usize,
        "Frame size mismatch"
    );
    println!(
        "    Frame loaded: {WIDTH}x{HEIGHT} ({} bytes)\n",
        bgr_data.len()
    );

    // Detection
    println!("[3] Running face detection...");
    let t0 = Instant::now();
    let faces = engine
        .detect(&bgr_data, WIDTH, HEIGHT)
        .expect("Detection failed");
    let det_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("    Found {} face(s) in {:.1}ms", faces.len(), det_ms);

    for (i, f) in faces.iter().enumerate() {
        println!(
            "    Face {i}: bbox=[{},{},{},{}] score={:.4}",
            f.bbox[0], f.bbox[1], f.bbox[2], f.bbox[3], f.score
        );
        let lm = f.landmark_points();
        println!("             landmarks: left_eye=({:.0},{:.0}) right_eye=({:.0},{:.0}) nose=({:.0},{:.0})",
            lm[0].0, lm[0].1, lm[1].0, lm[1].1, lm[2].0, lm[2].1);
    }

    if faces.is_empty() {
        println!("\n    FAIL: No faces detected in camera frame!");
        println!("    This likely means:");
        println!("    - Camera was not pointed at a face");
        println!("    - SCRFD postprocessing has a bug");
        println!(
            "    - Detection threshold too high (current: {})",
            config.ml.det_threshold
        );
        std::process::exit(1);
    }

    // Full pipeline: detect + encode
    println!("\n[4] Running full pipeline (detect + align + encode)...");
    let t0 = Instant::now();
    let analyzed = engine
        .analyze(&bgr_data, WIDTH, HEIGHT)
        .expect("Analyze failed");
    let full_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "    Full pipeline: {:.1}ms for {} face(s)",
        full_ms,
        analyzed.len()
    );

    for (i, f) in analyzed.iter().enumerate() {
        if let Some(ref emb) = f.embedding {
            let norm: f32 = emb.iter().map(|x| x * x).sum::<f32>().sqrt();
            let has_nan = emb.iter().any(|x| x.is_nan());
            let has_inf = emb.iter().any(|x| x.is_infinite());
            println!(
                "    Face {i}: embedding dim={} L2norm={:.4} nan={} inf={}",
                emb.len(),
                norm,
                has_nan,
                has_inf
            );

            assert_eq!(emb.len(), 512, "Expected 512-dim embedding");
            assert!(
                (norm - 1.0).abs() < 0.02,
                "Embedding should be L2-normalized, got {norm}"
            );
            assert!(!has_nan, "Embedding contains NaN");
            assert!(!has_inf, "Embedding contains Inf");

            // Print first 10 values for debugging
            println!("             first 10 values: {:?}", &emb[..10]);
            println!("    PASS: Face {i} embedding valid");
        } else {
            println!("    Face {i}: NO EMBEDDING (this is a bug)");
        }
    }

    // Consistency: same frame twice should give same embedding
    println!("\n[5] Consistency check...");
    let a1 = engine.analyze(&bgr_data, WIDTH, HEIGHT).unwrap();
    let a2 = engine.analyze(&bgr_data, WIDTH, HEIGHT).unwrap();
    if let (Some(e1), Some(e2)) = (
        a1.first().and_then(|f| f.embedding.as_ref()),
        a2.first().and_then(|f| f.embedding.as_ref()),
    ) {
        let sim: f32 = e1.iter().zip(e2.iter()).map(|(a, b)| a * b).sum();
        println!("    Self-similarity: {sim:.6}");
        assert!(
            sim > 0.99,
            "Same frame should give near-identical embeddings"
        );
        println!("    PASS: Deterministic embeddings\n");
    }

    println!("=== ALL REAL FACE TESTS PASSED ===");
}
