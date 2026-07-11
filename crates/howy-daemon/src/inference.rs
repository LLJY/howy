//! ONNX inference engine: SCRFD face detection + ArcFace face recognition.
//!
//! Uses the `ort` crate for ONNX Runtime, supporting CUDA, TensorRT,
//! MIGraphX, OpenVINO, and CPU execution providers.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use ndarray::ArrayView4;
use ort::execution_providers::{
    CPUExecutionProvider, CUDAExecutionProvider, ExecutionProvider, MIGraphXExecutionProvider,
    OpenVINOExecutionProvider, TensorRTExecutionProvider,
};
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::builder::SessionBuilder;
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
use howy_common::face::{self, Face};

/// Standard ArcFace alignment destination landmarks for 112x112 crop.
const ARCFACE_DST: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

const SCRFD_STRIDES: [usize; 3] = [8, 16, 32];
const SCRFD_ANCHORS_PER_CELL: usize = 2;
const SCRFD_GROUP_WIDTHS: [usize; 3] = [1, 4, 10];
const SCRFD_OUTPUT_COUNT: usize = SCRFD_STRIDES.len() * SCRFD_GROUP_WIDTHS.len();
/// Reject degenerate ArcFace outputs while remaining far below any useful embedding norm.
const MIN_RECOGNIZER_L2_NORM: f64 = 1.0e-12;

/// Detector session with pre-allocated input buffer.
struct DetectorState {
    session: Session,
    /// Pre-allocated NCHW buffer: 1 * 3 * det_h * det_w.
    input_buf: Vec<f32>,
    det_w: usize,
    det_h: usize,
}

/// Recognizer session with pre-allocated input buffer.
struct RecognizerState {
    session: Session,
    /// Pre-allocated NCHW buffer: 1 * 3 * 112 * 112 = 37632 floats.
    input_buf: Vec<f32>,
}

/// The inference engine holding loaded ONNX sessions.
pub struct InferenceEngine {
    detector: Mutex<DetectorState>,
    recognizer: Mutex<RecognizerState>,
    det_input_name: String,
    rec_input_name: String,
    det_size: (u32, u32),
    det_threshold: f32,
    registered_preferred_provider: String,
    detector_path: PathBuf,
    recognizer_path: PathBuf,
}

/// Opt-in ONNX Runtime profiling destinations used only by experiment harnesses.
pub struct InferenceProfiling {
    pub detector_path: PathBuf,
    pub recognizer_path: PathBuf,
    /// Harness-only precision pin applied through the MIGraphX provider API.
    pub migraphx_fp16: Option<bool>,
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
        Self::new_inner(config, true, None, None)
    }

    /// Create an engine with independent detector and recognizer ORT profiles.
    pub fn new_profiled(config: &HowyConfig, profiling: InferenceProfiling) -> Result<Self> {
        Self::new_inner(config, true, Some(profiling), None)
    }

    /// Create profiled sessions from parent-pinned ONNX bytes.
    pub fn new_profiled_from_memory(
        config: &HowyConfig,
        profiling: InferenceProfiling,
        detector_model: &[u8],
        recognizer_model: &[u8],
    ) -> Result<Self> {
        Self::new_inner(
            config,
            true,
            Some(profiling),
            Some((detector_model, recognizer_model)),
        )
    }

    fn new_inner(
        config: &HowyConfig,
        register_cpu_fallback: bool,
        profiling: Option<InferenceProfiling>,
        model_bytes: Option<(&[u8], &[u8])>,
    ) -> Result<Self> {
        // Harness sessions consume parent-pinned bytes and never reopen model paths.
        let (detector_path, recognizer_path) = if model_bytes.is_some() {
            (
                PathBuf::from("<pinned-detector-memory>"),
                PathBuf::from("<pinned-recognizer-memory>"),
            )
        } else {
            (
                resolve_model_path(&config.ml.detector_model, "det_10g.onnx")?,
                resolve_model_path(&config.ml.recognizer_model, "w600k_r50.onnx")?,
            )
        };

        if model_bytes.is_some() {
            info!("Loading detector and recognizer from pinned memory");
        } else {
            info!("Loading detector: {}", detector_path.display());
            info!("Loading recognizer: {}", recognizer_path.display());
        }

        // Build execution providers based on config. The working MIGraphX
        // deployment on this host relies on ORT_MIGRAPHX_* environment-based
        // cache configuration; do not reintroduce explicit save/load model paths.
        let det_plan = build_execution_providers(&config.ml.provider, register_cpu_fallback)?;
        let rec_plan = build_execution_providers(&config.ml.provider, register_cpu_fallback)?;

        // Create detector session
        let mut det_builder = map_ort!(Session::builder())?;
        det_builder =
            map_ort!(det_builder.with_optimization_level(GraphOptimizationLevel::Level2))?;

        if config.ml.threads > 0 {
            det_builder = map_ort!(det_builder.with_intra_threads(config.ml.threads))?;
        }
        if let Some(profiling) = profiling.as_ref() {
            det_builder = map_ort!(det_builder.with_profiling(&profiling.detector_path))?;
        }

        let fp16 = profiling
            .as_ref()
            .and_then(|profiling| profiling.migraphx_fp16);
        let (mut det_builder, det_provider) =
            configure_execution_providers(det_builder, &det_plan, "detector", fp16)?;
        let det_session = match model_bytes {
            Some((detector, _)) => map_ort!(det_builder.commit_from_memory(detector)),
            None => map_ort!(det_builder.commit_from_file(&detector_path)),
        }
        .context("failed to load detector model")?;

        // Create recognizer session
        let mut rec_builder = map_ort!(Session::builder())?;
        rec_builder =
            map_ort!(rec_builder.with_optimization_level(GraphOptimizationLevel::Level2))?;

        if config.ml.threads > 0 {
            rec_builder = map_ort!(rec_builder.with_intra_threads(config.ml.threads))?;
        }
        if let Some(profiling) = profiling.as_ref() {
            rec_builder = map_ort!(rec_builder.with_profiling(&profiling.recognizer_path))?;
        }

        let (mut rec_builder, rec_provider) =
            configure_execution_providers(rec_builder, &rec_plan, "recognizer", fp16)?;
        let rec_session = match model_bytes {
            Some((_, recognizer)) => map_ort!(rec_builder.commit_from_memory(recognizer)),
            None => map_ort!(rec_builder.commit_from_file(&recognizer_path)),
        }
        .context("failed to load recognizer model")?;

        // Get input names
        let det_input_name = det_session.inputs()[0].name().to_string();
        let rec_input_name = rec_session.inputs()[0].name().to_string();

        let det_w = config.ml.det_width as usize;
        let det_h = config.ml.det_height as usize;

        let registered_preferred_provider = if det_provider == rec_provider {
            det_provider
        } else {
            warn!(
                detector_registered_preference = %det_provider,
                recognizer_registered_preference = %rec_provider,
                "Detector and recognizer registered different execution providers"
            );
            "mixed".to_string()
        };

        info!("Detector input: {det_input_name}");
        info!("Recognizer input: {rec_input_name}");

        Ok(Self {
            detector: Mutex::new(DetectorState {
                session: det_session,
                input_buf: vec![0.0f32; 3 * det_w * det_h],
                det_w,
                det_h,
            }),
            recognizer: Mutex::new(RecognizerState {
                session: rec_session,
                input_buf: vec![0.0f32; 3 * 112 * 112],
            }),
            det_input_name,
            rec_input_name,
            det_size: (config.ml.det_width, config.ml.det_height),
            det_threshold: config.ml.det_threshold,
            registered_preferred_provider,
            detector_path,
            recognizer_path,
        })
    }

    /// Provider registered first for both sessions; this is not graph-placement evidence.
    pub fn registered_preferred_provider(&self) -> &str {
        &self.registered_preferred_provider
    }

    /// Compatibility accessor for existing status and smoke-test callers.
    #[allow(dead_code)]
    pub fn active_provider(&self) -> &str {
        self.registered_preferred_provider()
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
        let _ = self.detect(&dummy, 640, 480, false)?;
        info!("Warmup complete");
        Ok(())
    }

    /// Run the recognizer directly with a deterministic synthetic NCHW tensor.
    pub fn warmup_recognizer(&self) -> Result<()> {
        let synthetic_input: Vec<f32> = (0..3 * 112 * 112)
            .map(|index| ((index % 256) as f32 - 127.5) / 128.0)
            .collect();
        let input_view = ArrayView4::from_shape((1, 3, 112, 112), synthetic_input.as_slice())
            .map_err(|e| anyhow::anyhow!("recognizer warmup tensor shape error: {e}"))?;
        let input_tensor = map_ort!(TensorRef::from_array_view(input_view))?;

        let mut recognizer = self
            .recognizer
            .lock()
            .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;
        let outputs = map_ort!(
            recognizer
                .session
                .run(ort::inputs![&self.rec_input_name => input_tensor])
        )?;
        let _ = extract_valid_recognizer_output(&outputs)?;
        Ok(())
    }

    /// Explicitly finish both opt-in profiles and return ORT's actual paths.
    pub fn end_profiling(&self) -> Result<(String, String)> {
        let detector_path = {
            let mut detector = self
                .detector
                .lock()
                .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;
            map_ort!(detector.session.end_profiling())?
        };
        let recognizer_path = {
            let mut recognizer = self
                .recognizer
                .lock()
                .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;
            map_ort!(recognizer.session.end_profiling())?
        };
        Ok((detector_path, recognizer_path))
    }

    /// Detect faces in a raw BGR or grayscale image buffer.
    ///
    /// Returns detected faces with bounding boxes, landmarks, and confidence scores.
    /// Embeddings are NOT computed here — call `encode` separately.
    pub fn detect(&self, data: &[u8], width: u32, height: u32, is_gray: bool) -> Result<Vec<Face>> {
        // Validate buffer before acquiring mutex to avoid poisoning on bad input.
        validate_frame_buffer(data, width, height, is_gray)?;

        let mut det = self
            .detector
            .lock()
            .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;

        let det_w = det.det_w;
        let det_h = det.det_h;
        let (cfg_det_w, cfg_det_h) = self.det_size;
        debug_assert_eq!(cfg_det_w as usize, det_w);
        debug_assert_eq!(cfg_det_h as usize, det_h);
        let scale = f32::min(det_w as f32 / width as f32, det_h as f32 / height as f32);

        preprocess_detection_into(
            &mut det.input_buf,
            data,
            width as usize,
            height as usize,
            det_w,
            det_h,
            is_gray,
        );

        let DetectorState {
            session, input_buf, ..
        } = &mut *det;
        let input_view = ArrayView4::from_shape((1, 3, det_h, det_w), input_buf.as_slice())
            .map_err(|e| anyhow::anyhow!("tensor shape error: {e}"))?;
        let input_tensor = map_ort!(TensorRef::from_array_view(input_view))?;
        let outputs = map_ort!(session.run(ort::inputs![&self.det_input_name => input_tensor]))?;
        validate_scrfd_outputs(&outputs, det_w, det_h)?;

        // Post-process SCRFD outputs
        let faces = postprocess_scrfd(
            &outputs,
            scale,
            width,
            height,
            det_w as u32,
            det_h as u32,
            self.det_threshold,
        )?;

        Ok(faces)
    }

    /// Compute a 512-dimensional ArcFace embedding for a detected face.
    pub fn encode(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        face: &Face,
        is_gray: bool,
    ) -> Result<Vec<f32>> {
        validate_frame_buffer(data, width, height, is_gray)?;

        let mut rec = self
            .recognizer
            .lock()
            .map_err(|e| anyhow::anyhow!("inference lock poisoned: {e}"))?;

        align_and_preprocess_recognition(
            &mut rec.input_buf,
            data,
            width as usize,
            height as usize,
            &face.landmark_points(),
            is_gray,
        );

        let RecognizerState { session, input_buf } = &mut *rec;
        let input_view = ArrayView4::from_shape((1, 3, 112, 112), input_buf.as_slice())
            .map_err(|e| anyhow::anyhow!("tensor shape error: {e}"))?;
        let input_tensor = map_ort!(TensorRef::from_array_view(input_view))?;
        let outputs = map_ort!(session.run(ort::inputs![&self.rec_input_name => input_tensor]))?;

        // Extract, validate, and normalize embedding.
        let embedding = extract_valid_recognizer_output(&outputs)?;
        Ok(normalize_arcface_embedding(embedding))
    }

    /// Detect faces and compute embeddings in one call.
    pub fn analyze(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        is_gray: bool,
    ) -> Result<Vec<Face>> {
        let mut faces = self.detect(data, width, height, is_gray)?;

        for face in &mut faces {
            let embedding = self.encode(data, width, height, face, is_gray)?;
            face.embedding = Some(embedding);
        }

        Ok(faces)
    }
}

fn validate_output_count(model: &str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        bail!("{model} returned {actual} outputs; expected exactly {expected}");
    }
    Ok(())
}

fn validate_scrfd_output_facts(
    output_index: usize,
    det_w: usize,
    det_h: usize,
    shape: &[usize],
    contiguous_data: Option<&[f32]>,
) -> Result<()> {
    let stride_index = output_index % SCRFD_STRIDES.len();
    let group_index = output_index / SCRFD_STRIDES.len();
    let stride = *SCRFD_STRIDES
        .get(stride_index)
        .context("SCRFD output index exceeds stride groups")?;
    let group_width = *SCRFD_GROUP_WIDTHS
        .get(group_index)
        .context("SCRFD output index exceeds score/box/landmark groups")?;

    if det_w == 0 || det_h == 0 || det_w % stride != 0 || det_h % stride != 0 {
        bail!("SCRFD input dimensions must be non-zero multiples of stride {stride}");
    }
    let anchors = (det_w / stride)
        .checked_mul(det_h / stride)
        .and_then(|cells| cells.checked_mul(SCRFD_ANCHORS_PER_CELL))
        .context("SCRFD expected anchor count overflowed")?;
    let rank_shape_valid = shape == [anchors, group_width] || shape == [1, anchors, group_width];
    if !rank_shape_valid {
        bail!(
            "SCRFD output {output_index} has shape {shape:?}; expected [{anchors}, {group_width}] or [1, {anchors}, {group_width}]"
        );
    }

    let data = contiguous_data
        .ok_or_else(|| anyhow::anyhow!("SCRFD output {output_index} is not contiguous"))?;
    let expected_len = anchors
        .checked_mul(group_width)
        .context("SCRFD expected output length overflowed")?;
    if data.len() != expected_len {
        bail!(
            "SCRFD output {output_index} has {} values; expected {expected_len}",
            data.len()
        );
    }
    if data.iter().any(|value| !value.is_finite()) {
        bail!("SCRFD output {output_index} contains non-finite values");
    }
    Ok(())
}

fn validate_scrfd_outputs(
    outputs: &ort::session::SessionOutputs<'_>,
    det_w: usize,
    det_h: usize,
) -> Result<()> {
    validate_output_count("SCRFD", outputs.len(), SCRFD_OUTPUT_COUNT)?;
    for output_index in 0..SCRFD_OUTPUT_COUNT {
        let output = map_ort!(outputs[output_index].try_extract_array::<f32>())?;
        validate_scrfd_output_facts(
            output_index,
            det_w,
            det_h,
            output.shape(),
            output.as_slice(),
        )?;
    }
    Ok(())
}

fn validate_recognizer_output_facts(
    shape: &[usize],
    contiguous_data: Option<&[f32]>,
) -> Result<()> {
    if shape != [1, face::FACE_EMBEDDING_DIM] {
        bail!(
            "recognizer output has shape {shape:?}; expected [1, {}]",
            face::FACE_EMBEDDING_DIM
        );
    }
    let data =
        contiguous_data.ok_or_else(|| anyhow::anyhow!("recognizer output is not contiguous"))?;
    if data.len() != face::FACE_EMBEDDING_DIM {
        bail!(
            "recognizer output has {} values; expected {}",
            data.len(),
            face::FACE_EMBEDDING_DIM
        );
    }
    if data.iter().any(|value| !value.is_finite()) {
        bail!("recognizer output contains non-finite values");
    }

    let norm = data
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    if norm <= MIN_RECOGNIZER_L2_NORM {
        bail!("recognizer output L2 norm is too small");
    }
    Ok(())
}

fn extract_valid_recognizer_output(outputs: &ort::session::SessionOutputs<'_>) -> Result<Vec<f32>> {
    validate_output_count("recognizer", outputs.len(), 1)?;
    let output = map_ort!(outputs[0].try_extract_array::<f32>())?;
    let data = output
        .as_slice()
        .ok_or_else(|| anyhow::anyhow!("recognizer output is not contiguous"))?;
    validate_recognizer_output_facts(output.shape(), Some(data))?;
    Ok(data.to_vec())
}

/// Preserve the accepted Route 1 ArcFace normalization order exactly.
fn normalize_arcface_embedding(mut embedding: Vec<f32>) -> Vec<f32> {
    let norm: f32 = embedding
        .iter()
        .map(|value| value * value)
        .sum::<f32>()
        .sqrt();
    if norm > 0.0 {
        for value in &mut embedding {
            *value /= norm;
        }
    }
    embedding
}

#[cfg(test)]
mod tests {
    use super::{
        InferenceEngine, ProviderKind, SCRFD_OUTPUT_COUNT, build_execution_providers,
        normalize_arcface_embedding, validate_output_count, validate_recognizer_output_facts,
        validate_scrfd_output_facts,
    };
    use howy_common::config::HowyConfig;
    use howy_common::face::FACE_EMBEDDING_DIM;

    #[test]
    fn output_counts_are_exact() {
        assert!(validate_output_count("SCRFD", SCRFD_OUTPUT_COUNT, SCRFD_OUTPUT_COUNT).is_ok());
        assert!(
            validate_output_count("SCRFD", SCRFD_OUTPUT_COUNT - 1, SCRFD_OUTPUT_COUNT).is_err()
        );
        assert!(
            validate_output_count("SCRFD", SCRFD_OUTPUT_COUNT + 1, SCRFD_OUTPUT_COUNT).is_err()
        );
        assert!(validate_output_count("recognizer", 0, 1).is_err());
        assert!(validate_output_count("recognizer", 2, 1).is_err());
    }

    #[test]
    fn scrfd_accepts_actual_and_explicit_batch_shapes() {
        let scores = vec![0.0; 12_800];
        assert!(validate_scrfd_output_facts(0, 640, 640, &[12_800, 1], Some(&scores)).is_ok());
        assert!(validate_scrfd_output_facts(0, 640, 640, &[1, 12_800, 1], Some(&scores)).is_ok());

        let boxes = vec![0.0; 3_200 * 4];
        assert!(validate_scrfd_output_facts(4, 640, 640, &[3_200, 4], Some(&boxes)).is_ok());
        let landmarks = vec![0.0; 800 * 10];
        assert!(validate_scrfd_output_facts(8, 640, 640, &[800, 10], Some(&landmarks)).is_ok());
    }

    #[test]
    fn scrfd_rejects_bad_shape_length_layout_and_values() {
        let valid = vec![0.0; 12_800];
        assert!(validate_scrfd_output_facts(0, 640, 640, &[1, 1, 12_800], Some(&valid)).is_err());
        assert!(validate_scrfd_output_facts(0, 640, 640, &[12_800, 4], Some(&valid)).is_err());
        assert!(
            validate_scrfd_output_facts(0, 640, 640, &[12_800, 1], Some(&valid[..10])).is_err()
        );
        assert!(validate_scrfd_output_facts(0, 640, 640, &[12_800, 1], None).is_err());

        let mut non_finite = valid;
        non_finite[0] = f32::NAN;
        assert!(validate_scrfd_output_facts(0, 640, 640, &[12_800, 1], Some(&non_finite)).is_err());
        non_finite[0] = f32::INFINITY;
        assert!(validate_scrfd_output_facts(0, 640, 640, &[12_800, 1], Some(&non_finite)).is_err());
    }

    #[test]
    fn recognizer_requires_exact_shape_contiguous_finite_nonzero_data() {
        let valid = vec![1.0; FACE_EMBEDDING_DIM];
        assert!(validate_recognizer_output_facts(&[1, FACE_EMBEDDING_DIM], Some(&valid)).is_ok());
        assert!(validate_recognizer_output_facts(&[FACE_EMBEDDING_DIM], Some(&valid)).is_err());
        assert!(
            validate_recognizer_output_facts(&[1, FACE_EMBEDDING_DIM, 1], Some(&valid)).is_err()
        );
        assert!(validate_recognizer_output_facts(&[2, FACE_EMBEDDING_DIM], Some(&valid)).is_err());
        assert!(
            validate_recognizer_output_facts(
                &[1, FACE_EMBEDDING_DIM],
                Some(&valid[..FACE_EMBEDDING_DIM - 1]),
            )
            .is_err()
        );
        assert!(validate_recognizer_output_facts(&[1, FACE_EMBEDDING_DIM], None).is_err());
        assert!(
            validate_recognizer_output_facts(
                &[1, FACE_EMBEDDING_DIM],
                Some(&vec![0.0; FACE_EMBEDDING_DIM])
            )
            .is_err()
        );

        let mut non_finite = valid;
        non_finite[0] = f32::NAN;
        assert!(
            validate_recognizer_output_facts(&[1, FACE_EMBEDDING_DIM], Some(&non_finite)).is_err()
        );
        non_finite[0] = f32::NEG_INFINITY;
        assert!(
            validate_recognizer_output_facts(&[1, FACE_EMBEDDING_DIM], Some(&non_finite)).is_err()
        );
    }

    #[test]
    fn arcface_normalization_is_bit_exact_with_accepted_route1() {
        let input: Vec<f32> = (0..FACE_EMBEDDING_DIM)
            .map(|index| ((index as i32 % 37) - 18) as f32 * 0.03125 + index as f32 * 0.000_001)
            .collect();

        // Accepted Route 1 implementation, kept independently here as the regression oracle.
        let mut expected = input.clone();
        let norm: f32 = expected
            .iter()
            .map(|value| value * value)
            .sum::<f32>()
            .sqrt();
        if norm > 0.0 {
            for value in &mut expected {
                *value /= norm;
            }
        }

        let actual = normalize_arcface_embedding(input);
        assert_eq!(actual.len(), expected.len());
        for (index, (actual, expected)) in actual.iter().zip(&expected).enumerate() {
            assert_eq!(
                actual.to_bits(),
                expected.to_bits(),
                "normalization changed at embedding index {index}"
            );
        }
    }

    #[test]
    fn cached_accelerated_registration_plan_omits_cpu() {
        assert_eq!(
            build_execution_providers("migraphx", false).unwrap(),
            vec![ProviderKind::Migraphx]
        );
        assert_eq!(
            build_execution_providers("migraphx", true).unwrap(),
            vec![ProviderKind::Migraphx, ProviderKind::Cpu]
        );
    }

    #[test]
    #[ignore = "requires HOWY_TEST_MODEL_DIR with real SCRFD and ArcFace ONNX models"]
    fn real_cpu_models_pass_shared_output_validation() {
        let model_dir = std::env::var("HOWY_TEST_MODEL_DIR").expect("HOWY_TEST_MODEL_DIR is set");
        let mut config = HowyConfig::default();
        config.ml.provider = "cpu".to_string();
        config.ml.detector_model = format!("{model_dir}/det_10g.onnx");
        config.ml.recognizer_model = format!("{model_dir}/w600k_r50.onnx");
        config.ml.det_width = 640;
        config.ml.det_height = 640;

        let engine = InferenceEngine::new(&config).expect("real CPU models load");
        assert_eq!(engine.registered_preferred_provider(), "cpu");
        engine.warmup().expect("detector warmup validates outputs");
        engine
            .warmup_recognizer()
            .expect("recognizer warmup validates output");
        engine
            .detect(&vec![0_u8; 640 * 480 * 3], 640, 480, false)
            .expect("production detector validates real outputs");
    }
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

/// Validate frame buffer length matches declared dimensions and format.
/// Called before acquiring mutex to prevent panics from poisoning sessions.
fn validate_frame_buffer(data: &[u8], width: u32, height: u32, is_gray: bool) -> Result<()> {
    let channels: u32 = if is_gray { 1 } else { 3 };
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|v| v.checked_mul(channels as usize))
        .ok_or_else(|| anyhow::anyhow!("frame dimensions overflow: {width}x{height}x{channels}"))?;

    if data.len() < expected {
        bail!(
            "frame buffer too small: got {} bytes, expected {} ({width}x{height}x{channels})",
            data.len(),
            expected,
        );
    }
    if width == 0 || height == 0 {
        bail!("frame dimensions must be non-zero: {width}x{height}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Preprocessing
// ---------------------------------------------------------------------------

/// Preprocess a BGR or grayscale image for SCRFD detection.
/// Writes directly into `dst` in NCHW layout (3 * det_h * det_w floats).
fn preprocess_detection_into(
    dst: &mut [f32],
    src: &[u8],
    src_w: usize,
    src_h: usize,
    det_w: usize,
    det_h: usize,
    is_gray: bool,
) {
    const NORM_SUB: f32 = 127.5;
    const NORM_DIV: f32 = 1.0 / 128.0;
    const PAD: f32 = -NORM_SUB * NORM_DIV;

    let plane = det_w * det_h;
    let scale = f32::min(det_w as f32 / src_w as f32, det_h as f32 / src_h as f32);
    let new_w = (src_w as f32 * scale) as usize;
    let new_h = (src_h as f32 * scale) as usize;

    let (r_plane, rest) = dst.split_at_mut(plane);
    let (g_plane, b_plane) = rest.split_at_mut(plane);

    // --- Identity-scale fast path (common case: 640xN → 640x640) ---
    if src_w == det_w && new_w == det_w {
        // Source rows map 1:1 — no X remap needed, just copy+normalize.
        if is_gray {
            for y in 0..new_h.min(src_h) {
                let src_row = y * src_w;
                let dst_row = y * det_w;
                for x in 0..src_w {
                    let val = (src[src_row + x] as f32 - NORM_SUB) * NORM_DIV;
                    r_plane[dst_row + x] = val;
                    g_plane[dst_row + x] = val;
                    b_plane[dst_row + x] = val;
                }
            }
        } else {
            for y in 0..new_h.min(src_h) {
                let src_row = y * src_w * 3;
                let dst_row = y * det_w;
                for x in 0..src_w {
                    let si = src_row + x * 3;
                    let di = dst_row + x;
                    r_plane[di] = (src[si + 2] as f32 - NORM_SUB) * NORM_DIV;
                    g_plane[di] = (src[si + 1] as f32 - NORM_SUB) * NORM_DIV;
                    b_plane[di] = (src[si] as f32 - NORM_SUB) * NORM_DIV;
                }
            }
        }

        // Pad only the bottom rows (new_h..det_h) — right side doesn't need
        // padding because src_w == det_w.
        if new_h < det_h {
            for y in new_h..det_h {
                let dst_row = y * det_w;
                for x in 0..det_w {
                    r_plane[dst_row + x] = PAD;
                    g_plane[dst_row + x] = PAD;
                    b_plane[dst_row + x] = PAD;
                }
            }
        }
        return;
    }

    // --- Generic scaled path (with partial padding) ---

    // Fill only the padding regions, not the image region.
    // Right padding: columns new_w..det_w for rows 0..new_h
    if new_w < det_w {
        for y in 0..new_h {
            let dst_row = y * det_w;
            for x in new_w..det_w {
                r_plane[dst_row + x] = PAD;
                g_plane[dst_row + x] = PAD;
                b_plane[dst_row + x] = PAD;
            }
        }
    }
    // Bottom padding: all columns for rows new_h..det_h
    if new_h < det_h {
        for y in new_h..det_h {
            let dst_row = y * det_w;
            for x in 0..det_w {
                r_plane[dst_row + x] = PAD;
                g_plane[dst_row + x] = PAD;
                b_plane[dst_row + x] = PAD;
            }
        }
    }

    // Remap with coordinate computation
    if is_gray {
        for y in 0..new_h {
            let src_y = ((y as f32 / scale) as usize).min(src_h - 1);
            let dst_row = y * det_w;
            let src_row = src_y * src_w;
            for x in 0..new_w {
                let src_x = ((x as f32 / scale) as usize).min(src_w - 1);
                let val = (src[src_row + src_x] as f32 - NORM_SUB) * NORM_DIV;
                let di = dst_row + x;
                r_plane[di] = val;
                g_plane[di] = val;
                b_plane[di] = val;
            }
        }
    } else {
        for y in 0..new_h {
            let src_y = ((y as f32 / scale) as usize).min(src_h - 1);
            let dst_row = y * det_w;
            let src_row_start = src_y * src_w * 3;
            for x in 0..new_w {
                let src_x = ((x as f32 / scale) as usize).min(src_w - 1);
                let si = src_row_start + src_x * 3;
                let di = dst_row + x;
                r_plane[di] = (src[si + 2] as f32 - NORM_SUB) * NORM_DIV;
                g_plane[di] = (src[si + 1] as f32 - NORM_SUB) * NORM_DIV;
                b_plane[di] = (src[si] as f32 - NORM_SUB) * NORM_DIV;
            }
        }
    }
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

    // SCRFD outputs: for each stride: scores, bboxes, landmarks
    // Standard det_10g has 9 outputs (3 strides x 3), validated before this call.
    for (stride_idx, &stride) in SCRFD_STRIDES.iter().enumerate() {
        let scores_idx = stride_idx;
        let bbox_idx = stride_idx + 3;
        let lm_idx = stride_idx + 6;

        let scores = map_ort!(outputs[scores_idx].try_extract_array::<f32>())?;
        let bboxes = map_ort!(outputs[bbox_idx].try_extract_array::<f32>())?;
        let landmarks = map_ort!(outputs[lm_idx].try_extract_array::<f32>())?;

        let fmap_h = det_h as usize / stride;
        let fmap_w = det_w as usize / stride;

        let scores_flat = scores
            .as_slice()
            .context("validated SCRFD scores became non-contiguous")?;
        let bboxes_flat = bboxes
            .as_slice()
            .context("validated SCRFD boxes became non-contiguous")?;
        let lm_flat = landmarks
            .as_slice()
            .context("validated SCRFD landmarks became non-contiguous")?;
        let num_cells = fmap_h * fmap_w;
        let num_anchors = SCRFD_ANCHORS_PER_CELL;

        for (i, score) in scores_flat.iter().copied().enumerate() {
            if score <= threshold {
                continue;
            }

            let cell_idx = i / num_anchors;
            if cell_idx >= num_cells {
                continue;
            }

            let anchor_x = (cell_idx % fmap_w) as f32 * stride as f32;
            let anchor_y = (cell_idx / fmap_w) as f32 * stride as f32;

            // Decode bbox (distance from anchor)
            let bi = i * 4;
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
            let li = i * 10;
            for k in 0..5 {
                lm[k * 2] = (lm_flat[li + k * 2] * stride as f32 + anchor_x) / scale;
                lm[k * 2 + 1] = (lm_flat[li + k * 2 + 1] * stride as f32 + anchor_y) / scale;
            }

            faces.push(Face {
                bbox: [x1 as i32, y1 as i32, x2 as i32, y2 as i32],
                landmarks: lm,
                score,
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

    if union <= 0.0 { 0.0 } else { inter / union }
}

// ---------------------------------------------------------------------------
// Face alignment
// ---------------------------------------------------------------------------

/// Align face and preprocess for recognition in one fused pass.
/// Writes directly into `dst` in NCHW layout (3 * 112 * 112 floats).
/// `estimate_similarity_transform` already returns the inverse warp used here.
fn align_and_preprocess_recognition(
    dst: &mut [f32],
    src: &[u8],
    width: usize,
    height: usize,
    landmarks: &[(f32, f32); 5],
    is_gray: bool,
) {
    const NORM_SUB: f32 = 127.5;
    const NORM_DIV: f32 = 1.0 / 127.5;
    const DEFAULT_VAL: f32 = (0.0 - NORM_SUB) * NORM_DIV;

    let plane = 112 * 112;
    for v in dst.iter_mut() {
        *v = DEFAULT_VAL;
    }

    let (r_plane, rest) = dst.split_at_mut(plane);
    let (g_plane, b_plane) = rest.split_at_mut(plane);

    let (a, b, tx, ty) = estimate_similarity_transform(landmarks, &ARCFACE_DST);

    for dy in 0..112usize {
        let row_sx = -b * dy as f32 + tx;
        let row_sy = a * dy as f32 + ty;
        let row_offset = dy * 112;

        for dx in 0..112usize {
            let src_x = a * dx as f32 + row_sx;
            let src_y = b * dx as f32 + row_sy;

            let x0 = src_x.floor() as i32;
            let y0 = src_y.floor() as i32;
            let x1 = x0 + 1;
            let y1 = y0 + 1;

            if x0 < 0 || x1 >= width as i32 || y0 < 0 || y1 >= height as i32 {
                continue;
            }

            let fx = src_x - x0 as f32;
            let fy = src_y - y0 as f32;
            let w00 = (1.0 - fx) * (1.0 - fy);
            let w10 = fx * (1.0 - fy);
            let w01 = (1.0 - fx) * fy;
            let w11 = fx * fy;
            let di = row_offset + dx;

            if is_gray {
                let idx = |x: i32, y: i32| -> usize { y as usize * width + x as usize };
                let val = src[idx(x0, y0)] as f32 * w00
                    + src[idx(x1, y0)] as f32 * w10
                    + src[idx(x0, y1)] as f32 * w01
                    + src[idx(x1, y1)] as f32 * w11;
                let nval = (val - NORM_SUB) * NORM_DIV;
                r_plane[di] = nval;
                g_plane[di] = nval;
                b_plane[di] = nval;
            } else {
                let idx = |x: i32, y: i32| -> usize { (y as usize * width + x as usize) * 3 };
                let p00 = idx(x0, y0);
                let p10 = idx(x1, y0);
                let p01 = idx(x0, y1);
                let p11 = idx(x1, y1);

                r_plane[di] = ((src[p00 + 2] as f32 * w00
                    + src[p10 + 2] as f32 * w10
                    + src[p01 + 2] as f32 * w01
                    + src[p11 + 2] as f32 * w11)
                    - NORM_SUB)
                    * NORM_DIV;
                g_plane[di] = ((src[p00 + 1] as f32 * w00
                    + src[p10 + 1] as f32 * w10
                    + src[p01 + 1] as f32 * w01
                    + src[p11 + 1] as f32 * w11)
                    - NORM_SUB)
                    * NORM_DIV;
                b_plane[di] = ((src[p00] as f32 * w00
                    + src[p10] as f32 * w10
                    + src[p01] as f32 * w01
                    + src[p11] as f32 * w11)
                    - NORM_SUB)
                    * NORM_DIV;
            }
        }
    }
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

/// Build the ordered execution-provider registration plan based on config.
fn build_execution_providers(
    provider: &str,
    register_cpu_fallback: bool,
) -> Result<Vec<ProviderKind>> {
    let mut plan = match provider.trim().to_ascii_lowercase().as_str() {
        "auto" => vec![
            ProviderKind::TensorRt,
            ProviderKind::Cuda,
            ProviderKind::Migraphx,
            ProviderKind::OpenVino,
            ProviderKind::Cpu,
        ],
        "tensorrt" => vec![ProviderKind::TensorRt],
        "cuda" => vec![ProviderKind::Cuda],
        "migraphx" => vec![ProviderKind::Migraphx],
        "openvino" => vec![ProviderKind::OpenVino],
        "" | "cpu" => vec![ProviderKind::Cpu],
        other => {
            warn!("Provider '{other}' is not enabled in this build, falling back to CPU");
            vec![ProviderKind::Cpu]
        }
    };

    if !provider.trim().eq_ignore_ascii_case("cpu") {
        if register_cpu_fallback && !plan.contains(&ProviderKind::Cpu) {
            plan.push(ProviderKind::Cpu);
        } else if !register_cpu_fallback {
            plan.retain(|provider| *provider != ProviderKind::Cpu);
        }
    }

    Ok(plan)
}

fn configure_execution_providers(
    mut session_builder: SessionBuilder,
    providers: &[ProviderKind],
    model_tag: &str,
    migraphx_fp16: Option<bool>,
) -> Result<(SessionBuilder, String)> {
    let mut registered_preference: Option<&'static str> = None;

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
                MIGraphXExecutionProvider::default()
                    .with_fp16(migraphx_fp16.unwrap_or(false))
                    .with_fp8(false)
                    .with_int8(false)
                    .with_exhaustive_tune(false),
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

        if registered && registered_preference.is_none() {
            registered_preference = Some(provider.name());
        }
    }

    let registered_preference = registered_preference
        .ok_or_else(|| anyhow::anyhow!("no execution provider registered for {model_tag}"))?;
    Ok((session_builder, registered_preference.to_string()))
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
            info!(
                provider = provider_name,
                model = model_tag,
                "Registered execution provider"
            );
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
