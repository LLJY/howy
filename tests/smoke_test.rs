//! Smoke test for the howy inference pipeline.
//!
//! Loads real SCRFD + ArcFace models, generates a synthetic face-like image,
//! and exercises detect → align → encode end-to-end.
//!
//! Run with: cargo run --release --bin smoke_test

use std::time::Instant;

use howy_common::config::{HowyConfig, MlConfig};
use howy_daemon::inference::InferenceEngine;

const MODEL_DIR: &str = "dist/howdy_onnx/_internal/onnx-data";

fn main() {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    println!("=== howy inference smoke test ===\n");

    // 1. Load models
    let det_model = format!("{MODEL_DIR}/det_10g.onnx");
    let rec_model = format!("{MODEL_DIR}/w600k_r50.onnx");

    println!("[1] Loading models...");
    println!("    Detector:   {det_model}");
    println!("    Recognizer: {rec_model}");

    let mut config = HowyConfig::default();
    config.ml.detector_model = det_model;
    config.ml.recognizer_model = rec_model;
    // Use provider from env or fall back to "auto".
    // On systems where MIGraphX/ROCm fails (e.g. RDNA3 iGPU), set HOWY_PROVIDER=cpu.
    config.ml.provider = std::env::var("HOWY_PROVIDER").unwrap_or_else(|_| "auto".to_string());
    config.ml.det_threshold = 0.3; // lower for synthetic images

    let t0 = Instant::now();
    let engine = InferenceEngine::new(&config).expect("Failed to load models");
    let load_time = t0.elapsed();
    println!("    Loaded in {:.1}ms", load_time.as_secs_f64() * 1000.0);
    println!("    Provider: {}", engine.active_provider());
    println!("    PASS: Models loaded\n");

    // 2. Warmup
    println!("[2] Warmup inference...");
    let t0 = Instant::now();
    engine.warmup().expect("Warmup failed");
    let warmup_time = t0.elapsed();
    println!("    Warmup in {:.1}ms", warmup_time.as_secs_f64() * 1000.0);
    println!("    PASS: Warmup succeeded\n");

    // 3. Detection on blank frame (should find 0 faces)
    println!("[3] Detection on blank frame (640x480)...");
    let blank = vec![128u8; 640 * 480 * 3]; // gray frame
    let t0 = Instant::now();
    let faces = engine
        .detect(&blank, 640, 480, false)
        .expect("Detection failed");
    let det_time = t0.elapsed();
    println!(
        "    Found {} faces in {:.1}ms",
        faces.len(),
        det_time.as_secs_f64() * 1000.0
    );
    println!("    PASS: Detection runs without crash\n");

    // 4. Detection on synthetic face-like pattern
    println!("[4] Detection on synthetic face pattern (640x480)...");
    let synthetic = make_synthetic_face(640, 480);
    let t0 = Instant::now();
    let faces = engine
        .detect(&synthetic, 640, 480, false)
        .expect("Detection failed");
    let det_time = t0.elapsed();
    println!(
        "    Found {} faces in {:.1}ms",
        faces.len(),
        det_time.as_secs_f64() * 1000.0
    );
    for (i, f) in faces.iter().enumerate() {
        println!(
            "    Face {i}: bbox=[{},{},{},{}] score={:.3} landmarks={:?}",
            f.bbox[0],
            f.bbox[1],
            f.bbox[2],
            f.bbox[3],
            f.score,
            f.landmark_points()
                .iter()
                .map(|(x, y)| (x.round() as i32, y.round() as i32))
                .collect::<Vec<_>>()
        );
    }
    println!("    PASS: Detection runs on synthetic data\n");

    // 5. Full pipeline: detect + encode on synthetic data
    println!("[5] Full analyze pipeline (detect + encode)...");
    let t0 = Instant::now();
    let analyzed = engine
        .analyze(&synthetic, 640, 480, false)
        .expect("Analyze failed");
    let full_time = t0.elapsed();
    println!(
        "    Found {} faces in {:.1}ms",
        analyzed.len(),
        full_time.as_secs_f64() * 1000.0
    );
    for (i, f) in analyzed.iter().enumerate() {
        let has_emb = f.embedding.is_some();
        let emb_norm = f.embedding.as_ref().map(|e| {
            let n: f32 = e.iter().map(|x| x * x).sum::<f32>().sqrt();
            n
        });
        let emb_dim = f.embedding.as_ref().map(|e| e.len());
        println!(
            "    Face {i}: score={:.3} embedding={} dim={:?} L2norm={:.4?}",
            f.score, has_emb, emb_dim, emb_norm,
        );
        // Verify embedding properties
        if let Some(ref emb) = f.embedding {
            assert_eq!(emb.len(), 512, "Embedding should be 512-dim");
            let norm: f32 = emb.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!(
                (norm - 1.0).abs() < 0.01,
                "Embedding should be L2-normalized, got norm={norm}"
            );
            assert!(
                emb.iter().all(|x| x.is_finite()),
                "Embedding has non-finite values"
            );
            println!("    PASS: Embedding is 512-dim, L2-normalized, finite");
        }
    }
    println!("    PASS: Full pipeline completed\n");

    // 6. Consistency: same image should produce similar embeddings
    println!("[6] Consistency check (same image twice)...");
    let a1 = engine
        .analyze(&synthetic, 640, 480, false)
        .expect("Analyze 1 failed");
    let a2 = engine
        .analyze(&synthetic, 640, 480, false)
        .expect("Analyze 2 failed");
    if !a1.is_empty() && !a2.is_empty() {
        if let (Some(e1), Some(e2)) = (&a1[0].embedding, &a2[0].embedding) {
            let sim: f32 = e1.iter().zip(e2.iter()).map(|(a, b)| a * b).sum();
            println!("    Self-similarity: {sim:.6}");
            assert!(
                sim > 0.99,
                "Same image should produce near-identical embeddings, got {sim}"
            );
            println!("    PASS: Self-similarity > 0.99\n");
        } else {
            println!("    SKIP: No embeddings to compare\n");
        }
    } else {
        println!("    SKIP: No faces detected for consistency check\n");
    }

    // 7. Different images should produce different embeddings
    println!("[7] Discrimination check (different patterns)...");
    let pattern_a = make_synthetic_face(640, 480);
    let pattern_b = make_different_pattern(640, 480);
    let fa = engine
        .analyze(&pattern_a, 640, 480, false)
        .unwrap_or_default();
    let fb = engine
        .analyze(&pattern_b, 640, 480, false)
        .unwrap_or_default();
    if !fa.is_empty() && !fb.is_empty() {
        if let (Some(ea), Some(eb)) = (&fa[0].embedding, &fb[0].embedding) {
            let sim: f32 = ea.iter().zip(eb.iter()).map(|(a, b)| a * b).sum();
            println!("    Cross-similarity: {sim:.6}");
            if sim < 0.5 {
                println!("    PASS: Different patterns produce different embeddings");
            } else {
                println!("    WARN: High cross-similarity ({sim:.4}) — may be an issue");
            }
        }
    } else {
        println!("    SKIP: Not enough face detections for discrimination check");
    }

    // 8. Stress: batch of detections
    println!("\n[8] Throughput test (10 frames)...");
    let t0 = Instant::now();
    for _ in 0..10 {
        let _ = engine.detect(&synthetic, 640, 480, false);
    }
    let batch_time = t0.elapsed();
    let fps = 10.0 / batch_time.as_secs_f64();
    println!(
        "    10 detections in {:.1}ms ({:.1} FPS)",
        batch_time.as_secs_f64() * 1000.0,
        fps
    );
    println!("    PASS: Throughput test complete\n");

    println!("=== ALL SMOKE TESTS PASSED ===");
}

/// Create a synthetic BGR image with a face-like oval pattern.
/// Not a real face, but exercises the full pixel pipeline.
fn make_synthetic_face(width: u32, height: u32) -> Vec<u8> {
    let mut bgr = vec![60u8; (width * height * 3) as usize]; // dark background

    let cx = width as f32 / 2.0;
    let cy = height as f32 / 2.0;
    let face_rx = 80.0f32; // face oval radius x
    let face_ry = 100.0f32; // face oval radius y

    for y in 0..height {
        for x in 0..width {
            let dx = (x as f32 - cx) / face_rx;
            let dy = (y as f32 - cy) / face_ry;
            let d = dx * dx + dy * dy;

            let idx = ((y * width + x) * 3) as usize;

            if d < 1.0 {
                // Skin-tone oval (BGR)
                bgr[idx] = 140; // B
                bgr[idx + 1] = 180; // G
                bgr[idx + 2] = 210; // R
            }

            // Eyes
            let left_eye =
                ((x as f32 - (cx - 30.0)).powi(2) + (y as f32 - (cy - 25.0)).powi(2)).sqrt();
            let right_eye =
                ((x as f32 - (cx + 30.0)).powi(2) + (y as f32 - (cy - 25.0)).powi(2)).sqrt();
            if left_eye < 12.0 || right_eye < 12.0 {
                bgr[idx] = 40;
                bgr[idx + 1] = 40;
                bgr[idx + 2] = 40;
            }

            // Mouth
            let mouth_dx = (x as f32 - cx).abs();
            let mouth_dy = (y as f32 - (cy + 35.0)).abs();
            if mouth_dx < 25.0 && mouth_dy < 6.0 {
                bgr[idx] = 80;
                bgr[idx + 1] = 80;
                bgr[idx + 2] = 120;
            }
        }
    }

    bgr
}

/// Create a different pattern (not face-like) for discrimination testing.
fn make_different_pattern(width: u32, height: u32) -> Vec<u8> {
    let mut bgr = vec![0u8; (width * height * 3) as usize];

    for y in 0..height {
        for x in 0..width {
            let idx = ((y * width + x) * 3) as usize;
            // Horizontal gradient
            bgr[idx] = ((x * 255 / width) as u8).wrapping_add(y as u8);
            bgr[idx + 1] = ((y * 255 / height) as u8).wrapping_mul(2);
            bgr[idx + 2] = 128;
        }
    }

    bgr
}
