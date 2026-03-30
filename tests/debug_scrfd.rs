//! Debug SCRFD model outputs — print tensor names, shapes, and value ranges.

use howy_common::config::HowyConfig;
use howy_daemon::inference::InferenceEngine;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;

const MODEL_DIR: &str = "dist/howdy_onnx/_internal/onnx-data";

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_target(false)
        .init();

    println!("=== SCRFD Model Debug ===\n");

    let det_path = format!("{MODEL_DIR}/det_10g.onnx");

    // Open session directly to inspect I/O
    let session = Session::builder()
        .unwrap()
        .with_optimization_level(GraphOptimizationLevel::Level2)
        .unwrap()
        .commit_from_file(&det_path)
        .unwrap();

    println!("Inputs:");
    for input in session.inputs() {
        println!("  name={:?}", input.name());
    }

    println!("\nOutputs ({} total):", session.outputs().len());
    for (i, output) in session.outputs().iter().enumerate() {
        println!("  [{i}] name={:?}", output.name());
    }

    println!("\nOutputs ({} total):", session.outputs().len());
    for (i, output) in session.outputs().iter().enumerate() {
        println!("  [{i}] name={:?}", output.name());
    }

    // Now run inference and print output shapes + value ranges
    println!("\n--- Running inference on 640x480 test frame ---\n");

    let frame = std::fs::read("/tmp/camera_frame.bgr").expect("read frame");
    let config = HowyConfig::default();

    // Preprocess manually like the engine does
    let det_w = 640u32;
    let det_h = 640u32;
    let src_w = 640u32;
    let src_h = 480u32;
    let scale = f32::min(det_w as f32 / src_w as f32, det_h as f32 / src_h as f32);
    println!("Scale: {scale}");

    use ndarray::Array4;
    use ort::value::TensorRef;

    let pad_value: f32 = -127.5 / 128.0;
    let new_w = (src_w as f32 * scale) as u32;
    let new_h = (src_h as f32 * scale) as u32;
    println!("Resized: {new_w}x{new_h} -> padded to {det_w}x{det_h}");

    let mut nchw = Array4::<f32>::from_elem((1, 3, det_h as usize, det_w as usize), pad_value);
    for y in 0..new_h {
        for x in 0..new_w {
            let src_x = (x as f32 / scale).min((src_w - 1) as f32);
            let src_y = (y as f32 / scale).min((src_h - 1) as f32);
            let sx = src_x as u32;
            let sy = src_y as u32;
            let src_idx = ((sy * src_w + sx) * 3) as usize;
            if src_idx + 2 < frame.len() {
                nchw[[0, 0, y as usize, x as usize]] = (frame[src_idx + 2] as f32 - 127.5) / 128.0;
                nchw[[0, 1, y as usize, x as usize]] = (frame[src_idx + 1] as f32 - 127.5) / 128.0;
                nchw[[0, 2, y as usize, x as usize]] = (frame[src_idx] as f32 - 127.5) / 128.0;
            }
        }
    }

    let input_name = session.inputs()[0].name().to_string();
    let tensor = TensorRef::from_array_view(&nchw).unwrap();
    let mut sess = session;
    let outputs = sess.run(ort::inputs![&input_name => tensor]).unwrap();

    println!("\nOutput tensors:");
    for i in 0..outputs.len() {
        let arr = outputs[i].try_extract_array::<f32>().unwrap();
        let shape = arr.shape().to_vec();
        let flat = arr.as_slice().unwrap();
        let min = flat.iter().cloned().fold(f32::INFINITY, f32::min);
        let max = flat.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let above_zero = flat.iter().filter(|&&x| x > 0.0).count();
        let above_half = flat.iter().filter(|&&x| x > 0.5).count();
        let above_03 = flat.iter().filter(|&&x| x > 0.3).count();
        println!(
            "  [{i}] shape={shape:?} min={min:.4} max={max:.4} >0={above_zero} >0.3={above_03} >0.5={above_half}"
        );
    }

    // SCRFD det_10g output names tell us the order
    // Output names already printed above from session.outputs()
}
