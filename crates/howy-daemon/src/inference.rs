//! ONNX inference engine: SCRFD face detection + ArcFace face recognition.
//!
//! Uses the `ort` crate for ONNX Runtime, supporting CUDA, TensorRT,
//! MIGraphX, OpenVINO, and CPU execution providers.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use ndarray::Array4;
use ort::execution_providers::{
    CPUExecutionProvider, CUDAExecutionProvider, ExecutionProvider, MIGraphXExecutionProvider,
    OpenVINOExecutionProvider, TensorRTExecutionProvider,
};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::builder::SessionBuilder;
use ort::session::Session;
use ort::value::TensorRef;
use tracing::{info, warn};

/// Helper macro to convert ort errors into anyhow errors.
/// The ort::Error type is generic over a context type, so we use a closure.
macro_rules! map_ort {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::anyhow!("ort: {e}"))
    };
}

use howy_common::config::HowyConfig;
use howy_common::face::Face;

/// Standard ArcFace alignment destination landmarks for 112x112 crop.
const ARCFACE_DST: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// The inference engine holding loaded ONNX sessions.
pub struct InferenceEngine {
    detector: Mutex<Session>,
    recognizer: Mutex<Session>,
    det_input_name: String,
    rec_input_name: String,
    det_size: (u32, u32),
    det_threshold: f32,
    active_provider: String,
    detector_path: PathBuf,
    recognizer_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderKind {
    TensorRt,
    Cuda,
    Migraphx,
    OpenVino,
    Cpu,
}

impl ProviderKind {
    fn name(self) -> &'static str {
        match self {
            Self::TensorRt => "tensorrt",
            Self::Cuda => "cuda",
            Self::Migraphx => "migraphx",
            Self::OpenVino => "openvino",
            Self::Cpu => "cpu",
        }
    }
}

impl InferenceEngine {
    /// Create a new inference engine, loading and preparing ONNX models.
    pub fn new(config: &HowyConfig) -> Result<Self> {
        // Resolve model paths
        let detector_path = resolve_model_path(&config.ml.detector_model, "det_10g.onnx")?;
        let recognizer_path = resolve_model_path(&config.ml.recognizer_model, "w600k_r50.onnx")?;

        info!("Loading detector: {}", detector_path.display());
        info!("Loading recognizer: {}", recognizer_path.display());

        // Build execution providers based on config. The working MIGraphX
        // deployment on this host relies on ORT_MIGRAPHX_* environment-based
        // cache configuration; do not reintroduce explicit save/load model paths.
        let det_plan = build_execution_providers(&config.ml.provider, "detector")?;
        let rec_plan = build_execution_providers(&config.ml.provider, "recognizer")?;

        // Create detector session
        let mut det_builder = map_ort!(Session::builder())?;
        det_builder =
            map_ort!(det_builder.with_optimization_level(GraphOptimizationLevel::Level2))?;

        if config.ml.threads > 0 {
            det_builder = map_ort!(det_builder.with_intra_threads(config.ml.threads))?;
        }

        let (mut det_builder, det_provider) =
            configure_execution_providers(det_builder, &det_plan, "detector")?;
        let detector = map_ort!(det_builder.commit_from_file(&detector_path))
            .context("failed to load detector model")?;

        // Create recognizer session
        let mut rec_builder = map_ort!(Session::builder())?;
        rec_builder =
            map_ort!(rec_builder.with_optimization_level(GraphOptimizationLevel::Level2))?;

        if config.ml.threads > 0 {
            rec_builder = map_ort!(rec_builder.with_intra_threads(config.ml.threads))?;
        }

        let (mut rec_builder, rec_provider) =
            configure_execution_providers(rec_builder, &rec_plan, "recognizer")?;
        let recognizer = map_ort!(rec_builder.commit_from_file(&recognizer_path))
            .context("failed to load recognizer model")?;

        // Get input names
        let det_input_name = detector.inputs()[0].name().to_string();
        let rec_input_name = recognizer.inputs()[0].name().to_string();

        let active_provider = if det_provider == rec_provider {
            det_provider
        } else {
            let fallback = if det_provider == "cpu" || rec_provider == "cpu" {
                "cpu".to_string()
            } else {
                det_provider.clone()
            };
            warn!(
                detector_provider = %det_provider,
                recognizer_provider = %rec_provider,
                effective_provider = %fallback,
                "Detector and recognizer registered different execution providers"
            );
            fallback
        };

        info!("Detector input: {det_input_name}");
        info!("Recognizer input: {rec_input_name}");

        Ok(Self {
            detector: Mutex::new(detector),
            recognizer: Mutex::new(recognizer),
            det_input_name,
            rec_input_name,
            det_size: (config.ml.det_width, config.ml.det_height),
            det_threshold: config.ml.det_threshold,
            active_provider,
            detector_path,
            recognizer_path,
        })
    }

    pub fn active_provider(&self) -> &str {
        &self.active_provider
    }

    pub fn detector_model_path(&self) -> String {
        self.detector_path.display().to_string()
    }

    pub fn recognizer_model_path(&self) -> String {
        self.recognizer_path.display().to_string()
    }

    /// Run a warmup inference to prime the execution provider.
    pub fn warmup(&self) -> Result<()> {
        info!("Running warmup inference...");
        let dummy = vec![0u8; 480 * 640 * 3];
        let _ = self.detect(&dummy, 640, 480)?;
        info!("Warmup complete");
        Ok(())
    }

    /// Detect faces in a raw BGR image buffer.
    ///
    /// Returns detected faces with bounding boxes, landmarks, and confidence scores.
    /// Embeddings are NOT computed here — call `encode` separately.
    pub fn detect(&self, bgr_data: &[u8], width: u32, height: u32) -> Result<Vec<Face>> {
        let (det_w, det_h) = self.det_size;

        // Preprocess: resize, pad, normalize, transpose to NCHW
        let input = preprocess_detection(bgr_data, width, height, det_w, det_h);
        let scale = f32::min(det_w as f32 / width as f32, det_h as f32 / height as f32);

        // Run detector
        let mut detector = self
            .detector
            .lock()
            .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;
        let input_tensor = map_ort!(TensorRef::from_array_view(&input))?;
        let outputs = map_ort!(detector.run(ort::inputs![&self.det_input_name => input_tensor]))?;

        // Post-process SCRFD outputs
        let faces = postprocess_scrfd(
            &outputs,
            scale,
            width,
            height,
            det_w,
            det_h,
            self.det_threshold,
        )?;

        Ok(faces)
    }

    /// Compute a 512-dimensional ArcFace embedding for a detected face.
    pub fn encode(
        &self,
        bgr_data: &[u8],
        width: u32,
        height: u32,
        face: &Face,
    ) -> Result<Vec<f32>> {
        // Align face to standard 112x112 position using landmarks
        let aligned = align_face(bgr_data, width, height, &face.landmark_points());

        // Preprocess for recognizer: RGB, normalize, NCHW
        let input = preprocess_recognition(&aligned);

        // Run recognizer
        let mut recognizer = self
            .recognizer
            .lock()
            .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;
        let input_tensor = map_ort!(TensorRef::from_array_view(&input))?;
        let outputs = map_ort!(recognizer.run(ort::inputs![&self.rec_input_name => input_tensor]))?;

        // Extract and normalize embedding
        let embedding_view = map_ort!(outputs[0].try_extract_array::<f32>())?;
        let mut embedding: Vec<f32> = embedding_view.iter().copied().collect();

        // L2 normalize
        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut embedding {
                *v /= norm;
            }
        }

        Ok(embedding)
    }

    /// Detect faces and compute embeddings in one call.
    pub fn analyze(&self, bgr_data: &[u8], width: u32, height: u32) -> Result<Vec<Face>> {
        let mut faces = self.detect(bgr_data, width, height)?;

        for face in &mut faces {
            let embedding = self.encode(bgr_data, width, height, face)?;
            face.embedding = Some(embedding);
        }

        Ok(faces)
    }
}

// ---------------------------------------------------------------------------
// Preprocessing
// ---------------------------------------------------------------------------

/// Preprocess a BGR image for SCRFD detection.
/// Returns an Array4 in NCHW format, float32, normalized.
fn preprocess_detection(
    bgr_data: &[u8],
    src_w: u32,
    src_h: u32,
    det_w: u32,
    det_h: u32,
) -> Array4<f32> {
    let scale = f32::min(det_w as f32 / src_w as f32, det_h as f32 / src_h as f32);
    let new_w = (src_w as f32 * scale) as u32;
    let new_h = (src_h as f32 * scale) as u32;

    // Create padded output
    let pad_value: f32 = -127.5 / 128.0;
    let mut padded = vec![pad_value; (det_h * det_w * 3) as usize];

    // Simple bilinear resize + BGR->RGB + normalize
    for y in 0..new_h {
        for x in 0..new_w {
            let src_x = (x as f32 / scale).min((src_w - 1) as f32);
            let src_y = (y as f32 / scale).min((src_h - 1) as f32);

            let sx = src_x as u32;
            let sy = src_y as u32;
            let src_idx = ((sy * src_w + sx) * 3) as usize;

            if src_idx + 2 < bgr_data.len() {
                let dst_idx = ((y * det_w + x) * 3) as usize;
                // BGR -> RGB and normalize
                padded[dst_idx] = (bgr_data[src_idx + 2] as f32 - 127.5) / 128.0; // R
                padded[dst_idx + 1] = (bgr_data[src_idx + 1] as f32 - 127.5) / 128.0; // G
                padded[dst_idx + 2] = (bgr_data[src_idx] as f32 - 127.5) / 128.0;
                // B
            }
        }
    }

    // HWC -> NCHW
    let mut nchw = Array4::<f32>::zeros((1, 3, det_h as usize, det_w as usize));
    for y in 0..det_h as usize {
        for x in 0..det_w as usize {
            let hwc_idx = (y * det_w as usize + x) * 3;
            nchw[[0, 0, y, x]] = padded[hwc_idx]; // R
            nchw[[0, 1, y, x]] = padded[hwc_idx + 1]; // G
            nchw[[0, 2, y, x]] = padded[hwc_idx + 2]; // B
        }
    }

    nchw
}

/// Preprocess a 112x112 aligned face for ArcFace recognition.
fn preprocess_recognition(aligned_rgb: &[u8]) -> Array4<f32> {
    let mut nchw = Array4::<f32>::zeros((1, 3, 112, 112));

    for y in 0..112usize {
        for x in 0..112usize {
            let idx = (y * 112 + x) * 3;
            nchw[[0, 0, y, x]] = (aligned_rgb[idx] as f32 - 127.5) / 127.5; // R
            nchw[[0, 1, y, x]] = (aligned_rgb[idx + 1] as f32 - 127.5) / 127.5; // G
            nchw[[0, 2, y, x]] = (aligned_rgb[idx + 2] as f32 - 127.5) / 127.5; // B
        }
    }

    nchw
}

// ---------------------------------------------------------------------------
// Post-processing
// ---------------------------------------------------------------------------

/// Post-process SCRFD detector outputs into Face structs.
fn postprocess_scrfd(
    outputs: &ort::session::SessionOutputs<'_>,
    scale: f32,
    img_w: u32,
    img_h: u32,
    det_w: u32,
    det_h: u32,
    threshold: f32,
) -> Result<Vec<Face>> {
    let mut faces = Vec::new();
    let strides: [u32; 3] = [8, 16, 32];
    let num_outputs = outputs.len();

    // SCRFD outputs: for each stride: scores, bboxes, landmarks
    // Standard det_10g has 9 outputs (3 strides x 3)
    for (stride_idx, &stride) in strides.iter().enumerate() {
        let scores_idx = stride_idx;
        let bbox_idx = stride_idx + 3;
        let lm_idx = stride_idx + 6;

        if scores_idx >= num_outputs || bbox_idx >= num_outputs {
            break;
        }

        let scores = map_ort!(outputs[scores_idx].try_extract_array::<f32>())?;
        let bboxes = map_ort!(outputs[bbox_idx].try_extract_array::<f32>())?;
        let landmarks = if lm_idx < num_outputs {
            Some(map_ort!(outputs[lm_idx].try_extract_array::<f32>())?)
        } else {
            None
        };

        let fmap_h = det_h / stride;
        let fmap_w = det_w / stride;

        let scores_flat = scores.as_slice().unwrap_or(&[]);
        let bboxes_flat = bboxes.as_slice().unwrap_or(&[]);
        let lm_flat = landmarks.as_ref().and_then(|l| l.as_slice());
        let num_cells = (fmap_h * fmap_w) as usize;
        if num_cells == 0 {
            continue;
        }

        let num_anchors = scores_flat.len() / num_cells;
        if num_anchors == 0 {
            continue;
        }

        for i in 0..scores_flat.len() {
            if scores_flat[i] <= threshold {
                continue;
            }

            let cell_idx = i / num_anchors;
            if cell_idx >= num_cells {
                continue;
            }

            let anchor_x = (cell_idx % fmap_w as usize) as f32 * stride as f32;
            let anchor_y = (cell_idx / fmap_w as usize) as f32 * stride as f32;

            // Decode bbox (distance from anchor)
            let bi = i * 4;
            if bi + 3 >= bboxes_flat.len() {
                continue;
            }

            let x1 = ((anchor_x - bboxes_flat[bi] * stride as f32) / scale)
                .max(0.0)
                .min(img_w as f32);
            let y1 = ((anchor_y - bboxes_flat[bi + 1] * stride as f32) / scale)
                .max(0.0)
                .min(img_h as f32);
            let x2 = ((anchor_x + bboxes_flat[bi + 2] * stride as f32) / scale)
                .max(0.0)
                .min(img_w as f32);
            let y2 = ((anchor_y + bboxes_flat[bi + 3] * stride as f32) / scale)
                .max(0.0)
                .min(img_h as f32);

            // Decode landmarks
            let mut lm = [0.0f32; 10];
            if let Some(lm_data) = lm_flat {
                let li = i * 10;
                if li + 9 < lm_data.len() {
                    for k in 0..5 {
                        lm[k * 2] = (lm_data[li + k * 2] * stride as f32 + anchor_x) / scale;
                        lm[k * 2 + 1] =
                            (lm_data[li + k * 2 + 1] * stride as f32 + anchor_y) / scale;
                    }
                }
            } else {
                // Estimate landmarks from bbox
                let w = x2 - x1;
                let h = y2 - y1;
                lm = [
                    x1 + w * 0.3,
                    y1 + h * 0.3, // left eye
                    x1 + w * 0.7,
                    y1 + h * 0.3, // right eye
                    x1 + w * 0.5,
                    y1 + h * 0.55, // nose
                    x1 + w * 0.35,
                    y1 + h * 0.75, // left mouth
                    x1 + w * 0.65,
                    y1 + h * 0.75, // right mouth
                ];
            }

            faces.push(Face {
                bbox: [x1 as i32, y1 as i32, x2 as i32, y2 as i32],
                landmarks: lm,
                score: scores_flat[i],
                embedding: None,
            });
        }
    }

    // NMS
    if faces.len() > 1 {
        faces = nms(faces, 0.4);
    }

    Ok(faces)
}

/// Non-maximum suppression.
fn nms(mut faces: Vec<Face>, iou_thresh: f32) -> Vec<Face> {
    faces.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut suppressed = vec![false; faces.len()];
    let mut result = Vec::new();

    for i in 0..faces.len() {
        if suppressed[i] {
            continue;
        }
        result.push(faces[i].clone());

        for j in (i + 1)..faces.len() {
            if suppressed[j] {
                continue;
            }
            if iou(&faces[i], &faces[j]) > iou_thresh {
                suppressed[j] = true;
            }
        }
    }

    result
}

fn iou(a: &Face, b: &Face) -> f32 {
    let xx1 = a.x1().max(b.x1()) as f32;
    let yy1 = a.y1().max(b.y1()) as f32;
    let xx2 = (a.x2().min(b.x2()) as f32).max(xx1);
    let yy2 = (a.y2().min(b.y2()) as f32).max(yy1);

    let inter = (xx2 - xx1) * (yy2 - yy1);
    let area_a = a.width() as f32 * a.height() as f32;
    let area_b = b.width() as f32 * b.height() as f32;
    let union = area_a + area_b - inter;

    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

// ---------------------------------------------------------------------------
// Face alignment
// ---------------------------------------------------------------------------

/// Align a face to the standard 112x112 ArcFace position.
/// Uses a simple similarity transform estimated from 5-point landmarks.
/// Returns RGB pixel data (112*112*3 bytes).
fn align_face(bgr_data: &[u8], width: u32, height: u32, landmarks: &[(f32, f32); 5]) -> Vec<u8> {
    // Estimate similarity transform from src landmarks to ArcFace dst landmarks
    let (a, b, tx, ty) = estimate_similarity_transform(landmarks, &ARCFACE_DST);

    let mut aligned = vec![0u8; 112 * 112 * 3];

    for dy in 0..112u32 {
        for dx in 0..112u32 {
            // Inverse transform: find source pixel
            let src_x = a * dx as f32 - b * dy as f32 + tx;
            let src_y = b * dx as f32 + a * dy as f32 + ty;

            let x0 = src_x.floor() as i32;
            let y0 = src_y.floor() as i32;
            let x1 = x0 + 1;
            let y1 = y0 + 1;
            let fx = src_x - x0 as f32;
            let fy = src_y - y0 as f32;
            let dst_idx = (dy * 112 + dx) as usize * 3;

            if x0 >= 0 && x1 < width as i32 && y0 >= 0 && y1 < height as i32 {
                for c in 0..3 {
                    let src_c = if c == 0 {
                        2
                    } else if c == 2 {
                        0
                    } else {
                        1
                    };
                    let src_idx = |x: i32, y: i32| -> usize {
                        (y as u32 * width + x as u32) as usize * 3 + src_c
                    };

                    let v00 = bgr_data[src_idx(x0, y0)] as f32;
                    let v10 = bgr_data[src_idx(x1, y0)] as f32;
                    let v01 = bgr_data[src_idx(x0, y1)] as f32;
                    let v11 = bgr_data[src_idx(x1, y1)] as f32;
                    let val = v00 * (1.0 - fx) * (1.0 - fy)
                        + v10 * fx * (1.0 - fy)
                        + v01 * (1.0 - fx) * fy
                        + v11 * fx * fy;
                    aligned[dst_idx + c] = val.clamp(0.0, 255.0) as u8;
                }
            }
        }
    }

    aligned
}

/// Estimate a similarity transform (rotation + uniform scale + translation)
/// from source points to destination points using least squares.
/// Returns (a, b, tx, ty) where the transform is:
///   dst_x = a * src_x - b * src_y + tx
///   dst_y = b * src_x + a * src_y + ty
///
/// For the inverse (used in warp), we need the inverse of this.
fn estimate_similarity_transform(
    src: &[(f32, f32); 5],
    dst: &[[f32; 2]; 5],
) -> (f32, f32, f32, f32) {
    // Build linear system: for each point pair (sx,sy) -> (dx,dy):
    //   dx = a*sx - b*sy + tx
    //   dy = b*sx + a*sy + ty

    let n = 5.0f32;
    let mut sum_sx = 0.0f32;
    let mut sum_sy = 0.0f32;
    let mut sum_dx = 0.0f32;
    let mut sum_dy = 0.0f32;
    let mut sum_sx2_sy2 = 0.0f32;
    let mut sum_sx_dx_sy_dy = 0.0f32;
    let mut sum_sx_dy_m_sy_dx = 0.0f32;

    for i in 0..5 {
        let (sx, sy) = src[i];
        let (dx, dy) = (dst[i][0], dst[i][1]);

        sum_sx += sx;
        sum_sy += sy;
        sum_dx += dx;
        sum_dy += dy;
        sum_sx2_sy2 += sx * sx + sy * sy;
        sum_sx_dx_sy_dy += sx * dx + sy * dy;
        sum_sx_dy_m_sy_dx += sx * dy - sy * dx;
    }

    // Solve 4x4 system (simplified for similarity transform)
    let det = n * sum_sx2_sy2 - sum_sx * sum_sx - sum_sy * sum_sy;

    if det.abs() < 1e-10 {
        // Fallback: identity-like transform
        return (1.0, 0.0, 0.0, 0.0);
    }

    let a = (sum_sx2_sy2 * sum_dx - sum_sx * sum_sx_dx_sy_dy + sum_sy * sum_sx_dy_m_sy_dx) / det;
    let _ = a; // We need to solve properly

    // Simpler approach: compute from mean-centered points
    let cx_s = sum_sx / n;
    let cy_s = sum_sy / n;
    let cx_d = sum_dx / n;
    let cy_d = sum_dy / n;

    let mut num_a = 0.0f32;
    let mut num_b = 0.0f32;
    let mut denom = 0.0f32;

    for i in 0..5 {
        let (sx, sy) = (src[i].0 - cx_s, src[i].1 - cy_s);
        let (dx, dy) = (dst[i][0] - cx_d, dst[i][1] - cy_d);

        num_a += sx * dx + sy * dy;
        num_b += sx * dy - sy * dx;
        denom += sx * sx + sy * sy;
    }

    if denom.abs() < 1e-10 {
        return (1.0, 0.0, 0.0, 0.0);
    }

    let a = num_a / denom;
    let b = num_b / denom;
    let tx = cx_d - a * cx_s + b * cy_s;
    let ty = cy_d - b * cx_s - a * cy_s;

    // We return the INVERSE transform for warping (dst -> src)
    let det_inv = a * a + b * b;
    if det_inv.abs() < 1e-10 {
        return (1.0, 0.0, 0.0, 0.0);
    }

    let a_inv = a / det_inv;
    let b_inv = -b / det_inv;
    let tx_inv = -(a_inv * tx - b_inv * ty);
    let ty_inv = -(b_inv * tx + a_inv * ty);

    (a_inv, b_inv, tx_inv, ty_inv)
}

// ---------------------------------------------------------------------------
// Execution Provider setup
// ---------------------------------------------------------------------------

/// Build the ordered execution-provider plan based on config string.
fn build_execution_providers(provider: &str, _model_tag: &str) -> Result<Vec<ProviderKind>> {
    let plan = match provider.trim().to_ascii_lowercase().as_str() {
        "auto" => vec![
            ProviderKind::TensorRt,
            ProviderKind::Cuda,
            ProviderKind::Migraphx,
            ProviderKind::OpenVino,
            ProviderKind::Cpu,
        ],
        "tensorrt" => vec![ProviderKind::TensorRt, ProviderKind::Cpu],
        "cuda" => vec![ProviderKind::Cuda, ProviderKind::Cpu],
        "migraphx" => vec![ProviderKind::Migraphx, ProviderKind::Cpu],
        "openvino" => vec![ProviderKind::OpenVino, ProviderKind::Cpu],
        "" | "cpu" => vec![ProviderKind::Cpu],
        other => {
            warn!("Provider '{other}' is not enabled in this build, falling back to CPU");
            vec![ProviderKind::Cpu]
        }
    };

    Ok(plan)
}

fn configure_execution_providers(
    mut session_builder: SessionBuilder,
    providers: &[ProviderKind],
    model_tag: &str,
) -> Result<(SessionBuilder, String)> {
    let mut active_provider: Option<&'static str> = None;

    for provider in providers {
        let registered = match provider {
            ProviderKind::TensorRt => register_provider(
                &mut session_builder,
                TensorRTExecutionProvider::default(),
                provider.name(),
                model_tag,
                false,
            )?,
            ProviderKind::Cuda => register_provider(
                &mut session_builder,
                CUDAExecutionProvider::default(),
                provider.name(),
                model_tag,
                false,
            )?,
            ProviderKind::Migraphx => register_provider(
                &mut session_builder,
                MIGraphXExecutionProvider::default(),
                provider.name(),
                model_tag,
                false,
            )?,
            ProviderKind::OpenVino => register_provider(
                &mut session_builder,
                OpenVINOExecutionProvider::default(),
                provider.name(),
                model_tag,
                false,
            )?,
            ProviderKind::Cpu => register_provider(
                &mut session_builder,
                CPUExecutionProvider::default(),
                provider.name(),
                model_tag,
                true,
            )?,
        };

        if registered && active_provider.is_none() {
            active_provider = Some(provider.name());
        }
    }

    Ok((
        session_builder,
        active_provider
            .unwrap_or(ProviderKind::Cpu.name())
            .to_string(),
    ))
}

fn register_provider<E>(
    session_builder: &mut SessionBuilder,
    provider: E,
    provider_name: &'static str,
    model_tag: &str,
    required: bool,
) -> Result<bool>
where
    E: ExecutionProvider,
{
    match provider.register(session_builder) {
        Ok(()) => {
            info!(provider = provider_name, model = model_tag, "Registered execution provider");
            Ok(true)
        }
        Err(err) if required => Err(anyhow::anyhow!(
            "failed to register required execution provider '{provider_name}' for {model_tag}: {err}"
        )),
        Err(err) => {
            warn!(
                provider = provider_name,
                model = model_tag,
                error = %err,
                "Execution provider registration failed, continuing to fallback providers"
            );
            Ok(false)
        }
    }
}

/// Resolve a model path: use explicit path if set, otherwise search standard locations.
fn resolve_model_path(configured: &str, default_name: &str) -> Result<PathBuf> {
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Ok(path);
        }
        bail!("Configured model not found: {configured}");
    }

    // Check systemd credentials directory
    if let Ok(creds_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        let cred_path = PathBuf::from(&creds_dir).join(default_name);
        if cred_path.is_file() {
            info!(
                "Using model from systemd credentials: {}",
                cred_path.display()
            );
            return Ok(cred_path);
        }
    }

    // Search standard locations
    match howy_common::paths::find_model(default_name) {
        Some(path) => Ok(path),
        None => bail!(
            "Model '{}' not found in standard locations. \
             Install models to {} or set the path in config.",
            default_name,
            howy_common::paths::ONNX_DATA_DIR,
        ),
    }
}
