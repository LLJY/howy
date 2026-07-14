//! ONNX inference engine: SCRFD face detection + ArcFace face recognition.
//!
//! Uses the `ort` crate for ONNX Runtime, supporting CUDA, TensorRT,
//! MIGraphX, OpenVINO, and CPU execution providers.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
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
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Helper macro to convert ort errors into anyhow errors.
/// The ort::Error type is generic over a context type, so we use a closure.
macro_rules! map_ort {
    ($expr:expr) => {
        $expr.map_err(|e| anyhow::anyhow!("ort: {e}"))
    };
}

use howy_common::config::HowyConfig;
use howy_common::face::{self, Face};
use howy_common::storage::ModelDigest;

use crate::mode1_key::CredentialSourceIdentity;

#[derive(Debug)]
struct ModelCredentialAlias;

impl std::fmt::Display for ModelCredentialAlias {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("model selection aliases the Mode 1 storage credential")
    }
}

impl std::error::Error for ModelCredentialAlias {}

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
pub const MAX_RECOGNIZER_MODEL_BYTES: u64 = 192 * 1024 * 1024;

/// Detector session with pre-allocated input buffer.
struct DetectorState {
    session: Session,
    /// Pre-allocated NCHW buffer: 1 * 3 * det_h * det_w.
    input_buf: Zeroizing<Vec<f32>>,
    det_w: usize,
    det_h: usize,
}

/// Recognizer session with pre-allocated input buffer.
struct RecognizerState {
    session: Session,
    /// Pre-allocated NCHW buffer: 1 * 3 * 112 * 112 = 37632 floats.
    input_buf: Zeroizing<Vec<f32>>,
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

/// Descriptor-bound model selected by explicit or automatic resolution.
///
/// The display path is retained for diagnostics, while all subsequent reads
/// and ONNX parsing use the already-validated descriptor through procfs.
#[derive(Debug)]
pub struct ResolvedModel {
    display_path: PathBuf,
    file: File,
}

/// One startup snapshot of both production model descriptors.
pub struct ResolvedModels {
    detector: ResolvedModel,
    recognizer: ResolvedModel,
}

impl ResolvedModels {
    pub fn detector(&self) -> &ResolvedModel {
        &self.detector
    }

    pub fn recognizer(&self) -> &ResolvedModel {
        &self.recognizer
    }
}

impl ResolvedModel {
    pub fn display_path(&self) -> &Path {
        &self.display_path
    }

    fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub fn read_all(&self) -> Result<Vec<u8>> {
        let descriptor_path = self.descriptor_path();
        let mut file = File::open(&descriptor_path).with_context(|| {
            format!(
                "failed to reopen pinned model descriptor for {}",
                self.display_path.display()
            )
        })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).with_context(|| {
            format!(
                "failed to read exact model bytes from {}",
                self.display_path.display()
            )
        })?;
        Ok(bytes)
    }

    /// Stream a digest from the pinned descriptor under a checked byte cap.
    /// No model-sized allocation is created for storage readiness.
    pub fn sha256_digest_bounded(&self, maximum_bytes: u64) -> Result<ModelDigest> {
        self.sha256_digest_bounded_cancellable(maximum_bytes, || false)
    }

    /// Stream a digest from the pinned recognizer descriptor while polling a
    /// caller-owned deadline. Descriptor metadata is exact before and after the
    /// stream, so a provisioning result cannot bind a drifted model.
    pub fn sha256_digest_bounded_cancellable(
        &self,
        maximum_bytes: u64,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<ModelDigest> {
        let expected_length = self.file.metadata()?.len();
        if expected_length == 0 || expected_length > maximum_bytes {
            bail!("pinned recognizer model size is outside the storage readiness limit");
        }
        let before = self.file.metadata()?;
        let identity = (
            before.dev(),
            before.ino(),
            before.uid(),
            before.gid(),
            before.mode(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        );
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        while total < expected_length {
            if cancelled() {
                bail!("recognizer digest cancelled by readiness deadline");
            }
            let amount = usize::try_from((expected_length - total).min(buffer.len() as u64))?;
            let read = self
                .file
                .read_at(&mut buffer[..amount], total)
                .with_context(|| {
                    format!(
                        "failed to stream pinned recognizer model {}",
                        self.display_path.display()
                    )
                })?;
            if read == 0 {
                bail!("pinned recognizer model became shorter while it was hashed");
            }
            total = total
                .checked_add(read as u64)
                .context("pinned recognizer model length overflow")?;
            if total > maximum_bytes {
                bail!("pinned recognizer model exceeds the storage readiness limit");
            }
            hasher.update(&buffer[..read]);
        }
        let mut extra = [0u8; 1];
        if self.file.read_at(&mut extra, expected_length)? != 0 {
            bail!("pinned recognizer model became longer while it was hashed");
        }
        let after = self.file.metadata()?;
        let after_identity = (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        );
        if total != expected_length || after_identity != identity {
            bail!("pinned recognizer model changed while storage binding was computed");
        }
        Ok(ModelDigest::new(hasher.finalize().into()))
    }
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
        let models = resolve_models(config, None)?;
        Self::new_inner(config, true, None, None, Some(&models))
    }

    /// Create a production engine from the startup-pinned model snapshot.
    pub fn new_with_resolved_models(config: &HowyConfig, models: &ResolvedModels) -> Result<Self> {
        Self::new_inner(config, true, None, None, Some(models))
    }

    /// Create an engine with independent detector and recognizer ORT profiles.
    pub fn new_profiled(config: &HowyConfig, profiling: InferenceProfiling) -> Result<Self> {
        let models = resolve_models(config, None)?;
        Self::new_inner(config, true, Some(profiling), None, Some(&models))
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
            None,
        )
    }

    fn new_inner(
        config: &HowyConfig,
        register_cpu_fallback: bool,
        profiling: Option<InferenceProfiling>,
        model_bytes: Option<(&[u8], &[u8])>,
        resolved_models: Option<&ResolvedModels>,
    ) -> Result<Self> {
        // Harness sessions consume parent-pinned bytes and never reopen model paths.
        let (detector_path, recognizer_path) = match resolved_models {
            Some(models) => (
                models.detector.display_path.clone(),
                models.recognizer.display_path.clone(),
            ),
            None if model_bytes.is_some() => (
                PathBuf::from("<pinned-detector-memory>"),
                PathBuf::from("<pinned-recognizer-memory>"),
            ),
            None => bail!("resolved model descriptors are required"),
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
            None => {
                let models = resolved_models.expect("resolved model descriptors");
                map_ort!(det_builder.commit_from_file(models.detector.descriptor_path()))
            }
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
            None => {
                let models = resolved_models.expect("resolved model descriptors");
                map_ort!(rec_builder.commit_from_file(models.recognizer.descriptor_path()))
            }
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
                input_buf: Zeroizing::new(vec![0.0f32; 3 * det_w * det_h]),
                det_w,
                det_h,
            }),
            recognizer: Mutex::new(RecognizerState {
                session: rec_session,
                input_buf: Zeroizing::new(vec![0.0f32; 3 * 112 * 112]),
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

    pub(crate) fn plaintext_scratch_bytes(&self) -> Result<usize> {
        inference_plaintext_scratch_bytes(self.det_size.0, self.det_size.1)
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

pub(crate) fn inference_plaintext_scratch_bytes(
    detector_width: u32,
    detector_height: u32,
) -> Result<usize> {
    let detector_width = usize::try_from(detector_width).context("detector width overflow")?;
    let detector_height = usize::try_from(detector_height).context("detector height overflow")?;
    let detector_input = detector_width
        .checked_mul(detector_height)
        .and_then(|pixels| pixels.checked_mul(3))
        .and_then(|values| values.checked_mul(std::mem::size_of::<f32>()))
        .context("detector input accounting overflow")?;
    let recognizer_input = 3usize
        .checked_mul(112)
        .and_then(|values| values.checked_mul(112))
        .and_then(|values| values.checked_mul(std::mem::size_of::<f32>()))
        .context("recognizer input accounting overflow")?;
    let persistent_inputs = detector_input
        .checked_add(recognizer_input)
        .context("inference input accounting overflow")?;

    let mut anchors = 0usize;
    let mut detector_output_values = 0usize;
    for stride in SCRFD_STRIDES {
        if detector_width == 0
            || detector_height == 0
            || detector_width % stride != 0
            || detector_height % stride != 0
        {
            bail!("SCRFD dimensions must be nonzero multiples of stride {stride}");
        }
        let level_anchors = detector_width
            .checked_div(stride)
            .and_then(|width| {
                detector_height
                    .checked_div(stride)
                    .and_then(|height| width.checked_mul(height))
            })
            .and_then(|cells| cells.checked_mul(SCRFD_ANCHORS_PER_CELL))
            .context("SCRFD anchor accounting overflow")?;
        anchors = anchors
            .checked_add(level_anchors)
            .context("SCRFD anchor accounting overflow")?;
        let level_outputs = SCRFD_GROUP_WIDTHS.iter().try_fold(0usize, |total, width| {
            level_anchors
                .checked_mul(*width)
                .and_then(|values| total.checked_add(values))
        });
        detector_output_values = detector_output_values
            .checked_add(level_outputs.context("SCRFD output accounting overflow")?)
            .context("SCRFD output accounting overflow")?;
    }
    let detector_outputs = detector_output_values
        .checked_mul(std::mem::size_of::<f32>())
        .context("SCRFD output-byte accounting overflow")?;
    // NMS simultaneously owns the full candidate vector, a full result vector,
    // and one suppression byte per candidate. Provider-private execution
    // workspace is deliberately outside the daemon-owned biometric plaintext
    // budget; every bounded CPU-visible input, output, candidate, and copy is in it.
    let candidate_nms = anchors
        .checked_mul(
            std::mem::size_of::<Face>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<bool>()))
                .context("SCRFD candidate-size accounting overflow")?,
        )
        .context("SCRFD candidate accounting overflow")?;
    let detector_phase = detector_outputs
        .checked_add(candidate_nms)
        .context("detector phase accounting overflow")?;

    // ORT's ArcFace output and the daemon-owned extraction copy coexist before
    // normalization returns the copy to the caller.
    let recognizer_outputs = face::FACE_EMBEDDING_DIM
        .checked_mul(std::mem::size_of::<f32>())
        .and_then(|bytes| bytes.checked_mul(2))
        .context("recognizer output accounting overflow")?;
    let recognizer_phase = anchors
        .checked_mul(std::mem::size_of::<Face>())
        .and_then(|faces| faces.checked_add(recognizer_outputs))
        .context("recognizer phase accounting overflow")?;

    persistent_inputs
        .checked_add(detector_phase.max(recognizer_phase))
        .context("inference phase accounting overflow")
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
        InferenceEngine, ModelCredentialAlias, ProviderKind, SCRFD_OUTPUT_COUNT,
        build_execution_providers, normalize_arcface_embedding, resolve_model_path,
        resolve_model_path_with_credential_directory, validate_output_count,
        validate_recognizer_output_facts, validate_scrfd_output_facts,
    };
    use crate::mode1_key::{CredentialSourceIdentity, MODE1_CREDENTIAL_NAME};
    use howy_common::config::HowyConfig;
    use howy_common::face::FACE_EMBEDDING_DIM;
    use howy_common::storage::recognizer_model_digest;
    use std::cell::Cell;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    fn temporary_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "howy-model-alias-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn mode0_guard_rejects_direct_symlink_hardlink_and_proc_fd_aliases_before_model_read() {
        let root = temporary_directory("all");
        let credential_directory = root.join("credentials");
        let models = root.join("models");
        std::fs::create_dir(&credential_directory).unwrap();
        std::fs::create_dir(&models).unwrap();
        let credential_path = credential_directory.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&credential_path, [0x5a; 32]).unwrap();
        let credential = File::open(&credential_path).unwrap();
        let guard = CredentialSourceIdentity::from_descriptor_metadata(
            &File::open(&credential_directory)
                .unwrap()
                .metadata()
                .unwrap(),
            &credential.metadata().unwrap(),
            None,
        );
        let symlink = models.join("symlink.onnx");
        let hardlink = models.join("hardlink.onnx");
        std::os::unix::fs::symlink(&credential_path, &symlink).unwrap();
        std::fs::hard_link(&credential_path, &hardlink).unwrap();
        let proc_fd = format!("/proc/self/fd/{}", credential.as_raw_fd());

        for alias in [
            credential_path.to_string_lossy().into_owned(),
            symlink.to_string_lossy().into_owned(),
            hardlink.to_string_lossy().into_owned(),
            proc_fd,
        ] {
            let model_reads = Cell::new(0_u32);
            let result =
                resolve_model_path(&alias, "w600k_r50.onnx", Some(guard)).and_then(|model| {
                    model_reads.set(model_reads.get() + 1);
                    model.read_all()
                });
            let error = result.unwrap_err();
            assert!(error.downcast_ref::<ModelCredentialAlias>().is_some());
            assert_eq!(model_reads.get(), 0, "model bytes read for alias {alias}");
        }

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_key_name_is_never_a_generic_model_credential_name() {
        let root = temporary_directory("name");
        let credential_path = root.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&credential_path, [0x33; 32]).unwrap();
        let directory = File::open(&root).unwrap();
        let credential = File::open(&credential_path).unwrap();
        let guard = CredentialSourceIdentity::from_descriptor_metadata(
            &directory.metadata().unwrap(),
            &credential.metadata().unwrap(),
            None,
        );
        let error = resolve_model_path("", MODE1_CREDENTIAL_NAME, Some(guard)).unwrap_err();
        assert!(error.downcast_ref::<ModelCredentialAlias>().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn automatic_model_credentials_accept_only_the_legitimate_fixed_names() {
        let root = temporary_directory("fixed-credentials");
        let storage_key = root.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&storage_key, [0x22; 32]).unwrap();
        let directory = File::open(&root).unwrap();
        let credential = File::open(&storage_key).unwrap();
        let guard = CredentialSourceIdentity::from_descriptor_metadata(
            &directory.metadata().unwrap(),
            &credential.metadata().unwrap(),
            None,
        );
        for name in ["det_10g.onnx", "w600k_r50.onnx"] {
            std::fs::write(root.join(name), name.as_bytes()).unwrap();
            let model = resolve_model_path_with_credential_directory(
                "",
                name,
                Some(guard),
                Some(root.as_os_str()),
            )
            .unwrap();
            assert_eq!(model.read_all().unwrap(), name.as_bytes());
        }
        let generic_name = "not-a-howdy-model-credential.onnx";
        std::fs::write(root.join(generic_name), b"generic").unwrap();
        assert!(
            resolve_model_path_with_credential_directory(
                "",
                generic_name,
                Some(guard),
                Some(root.as_os_str()),
            )
            .is_err()
        );
        let error = resolve_model_path_with_credential_directory(
            "",
            MODE1_CREDENTIAL_NAME,
            Some(guard),
            Some(root.as_os_str()),
        )
        .unwrap_err();
        assert!(error.downcast_ref::<ModelCredentialAlias>().is_some());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ordinary_and_symlinked_noncredential_models_remain_supported() {
        let root = temporary_directory("ordinary");
        let credential_directory = root.join("credentials");
        std::fs::create_dir(&credential_directory).unwrap();
        let credential_path = credential_directory.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&credential_path, [0x11; 32]).unwrap();
        let credential = File::open(&credential_path).unwrap();
        let guard = CredentialSourceIdentity::from_descriptor_metadata(
            &File::open(&credential_directory)
                .unwrap()
                .metadata()
                .unwrap(),
            &credential.metadata().unwrap(),
            None,
        );
        let model_path = root.join("w600k_r50.onnx");
        let model_link = root.join("recognizer-current.onnx");
        std::fs::write(&model_path, b"ordinary-model").unwrap();
        std::os::unix::fs::symlink(&model_path, &model_link).unwrap();

        for path in [&model_path, &model_link] {
            let model =
                resolve_model_path(path.to_str().unwrap(), "w600k_r50.onnx", Some(guard)).unwrap();
            assert_eq!(model.read_all().unwrap(), b"ordinary-model");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_and_primary_and_cpu_attempts_share_original_pinned_model_inodes() {
        let root = temporary_directory("provider-retry-pinning");
        let detector_path = root.join("detector.onnx");
        let recognizer_path = root.join("recognizer.onnx");
        let detector_b = root.join("detector-b.onnx");
        let recognizer_b = root.join("recognizer-b.onnx");
        let detector_a_bytes = b"detector inode A";
        let recognizer_a_bytes = b"recognizer inode A";
        std::fs::write(&detector_path, detector_a_bytes).unwrap();
        std::fs::write(&recognizer_path, recognizer_a_bytes).unwrap();
        std::fs::write(&detector_b, b"detector replacement B").unwrap();
        std::fs::write(&recognizer_b, b"recognizer replacement B").unwrap();
        let mut config = HowyConfig::default();
        config.ml.detector_model = detector_path.to_string_lossy().into_owned();
        config.ml.recognizer_model = recognizer_path.to_string_lossy().into_owned();
        let models = super::resolve_models(&config, None).unwrap();
        let detector_identity = models.detector.file.metadata().unwrap();
        let recognizer_identity = models.recognizer.file.metadata().unwrap();

        let storage_bytes = models.recognizer().read_all().unwrap();
        assert_eq!(storage_bytes, recognizer_a_bytes);
        let storage_digest = recognizer_model_digest(&storage_bytes);

        std::fs::rename(&detector_path, root.join("detector-a-held")).unwrap();
        std::fs::rename(&recognizer_path, root.join("recognizer-a-held")).unwrap();
        std::os::unix::fs::symlink(&detector_b, &detector_path).unwrap();
        std::os::unix::fs::symlink(&recognizer_b, &recognizer_path).unwrap();

        for attempt in ["primary", "cpu-fallback"] {
            let mut detector_attempt = File::open(models.detector().descriptor_path()).unwrap();
            let mut recognizer_attempt = File::open(models.recognizer().descriptor_path()).unwrap();
            let mut detector_bytes = Vec::new();
            let mut recognizer_bytes = Vec::new();
            detector_attempt.read_to_end(&mut detector_bytes).unwrap();
            recognizer_attempt
                .read_to_end(&mut recognizer_bytes)
                .unwrap();
            assert_eq!(detector_bytes, detector_a_bytes, "{attempt}");
            assert_eq!(recognizer_bytes, recognizer_a_bytes, "{attempt}");
            assert_eq!(
                detector_attempt.metadata().unwrap().ino(),
                detector_identity.ino()
            );
            assert_eq!(
                recognizer_attempt.metadata().unwrap().ino(),
                recognizer_identity.ino()
            );
            assert_eq!(recognizer_model_digest(&recognizer_bytes), storage_digest);
        }
        assert_eq!(
            std::fs::read(&detector_path).unwrap(),
            b"detector replacement B"
        );
        assert_eq!(
            std::fs::read(&recognizer_path).unwrap(),
            b"recognizer replacement B"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readiness_digest_streams_the_pinned_recognizer_under_an_exact_bound() {
        let root = temporary_directory("bounded-readiness-digest");
        let recognizer_path = root.join("recognizer.onnx");
        let bytes = vec![0x5a; 128 * 1024 + 17];
        std::fs::write(&recognizer_path, &bytes).unwrap();
        let recognizer =
            resolve_model_path(recognizer_path.to_str().unwrap(), "w600k_r50.onnx", None).unwrap();

        assert_eq!(
            recognizer
                .sha256_digest_bounded(bytes.len() as u64)
                .unwrap(),
            recognizer_model_digest(&bytes)
        );
        assert!(
            recognizer
                .sha256_digest_bounded(bytes.len() as u64 - 1)
                .is_err()
        );

        let empty_path = root.join("empty.onnx");
        std::fs::write(&empty_path, []).unwrap();
        let empty =
            resolve_model_path(empty_path.to_str().unwrap(), "w600k_r50.onnx", None).unwrap();
        assert!(empty.sha256_digest_bounded(1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readiness_resolves_only_the_recognizer_before_detector_startup() {
        let root = temporary_directory("recognizer-only-readiness");
        let recognizer_path = root.join("recognizer.onnx");
        std::fs::write(&recognizer_path, b"recognizer").unwrap();
        let mut config = HowyConfig::default();
        config.ml.recognizer_model = recognizer_path.to_string_lossy().into_owned();
        config.ml.detector_model = root
            .join("missing-detector.onnx")
            .to_string_lossy()
            .into_owned();

        let recognizer = super::resolve_recognizer_model(&config, None).unwrap();
        assert_eq!(recognizer.read_all().unwrap(), b"recognizer");
        assert!(super::resolve_models_with_recognizer(&config, None, recognizer).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

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
    fn plaintext_peak_covers_inputs_outputs_and_worst_case_nms() {
        assert_eq!(
            super::inference_plaintext_scratch_bytes(640, 640).unwrap(),
            9_047_328
        );
        assert!(super::inference_plaintext_scratch_bytes(641, 640).is_err());
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
    let maximum_candidates = SCRFD_STRIDES.iter().try_fold(0usize, |total, stride| {
        usize::try_from(det_w)
            .ok()
            .and_then(|width| width.checked_div(*stride))
            .and_then(|width| {
                usize::try_from(det_h)
                    .ok()
                    .and_then(|height| height.checked_div(*stride))
                    .and_then(|height| width.checked_mul(height))
            })
            .and_then(|cells| cells.checked_mul(SCRFD_ANCHORS_PER_CELL))
            .and_then(|anchors| total.checked_add(anchors))
    });
    faces
        .try_reserve_exact(maximum_candidates.context("SCRFD candidate capacity overflow")?)
        .context("failed to reserve bounded SCRFD candidates")?;

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
    result.reserve_exact(faces.len());

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

fn path_is_exact_credential_location(
    path: &Path,
    credential_guard: CredentialSourceIdentity,
) -> Result<bool> {
    if path.file_name() != Some(credential_guard.credential_name().as_ref()) {
        return Ok(false);
    }
    let parent = path
        .parent()
        .context("model credential candidate has no parent directory")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)
        .with_context(|| {
            format!(
                "failed to inspect model credential directory {}",
                parent.display()
            )
        })?;
    Ok(credential_guard.matches_directory(&directory.metadata()?))
}

fn open_model_candidate(
    path: PathBuf,
    credential_guard: Option<CredentialSourceIdentity>,
) -> Result<ResolvedModel> {
    if let Some(guard) = credential_guard {
        if path_is_exact_credential_location(&path, guard)? {
            return Err(ModelCredentialAlias.into());
        }
    }

    // Symlinks are intentionally permitted for ordinary model deployment. The
    // opened descriptor, not the path spelling, is the security identity.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| format!("model candidate could not be opened: {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("model candidate is not a regular file: {}", path.display());
    }
    if credential_guard.is_some_and(|guard| guard.matches_credential(&metadata)) {
        return Err(ModelCredentialAlias.into());
    }
    Ok(ResolvedModel {
        display_path: path,
        file,
    })
}

/// Resolve and descriptor-bind a model: use an explicit path if set, otherwise
/// search only the two fixed model credential names and standard locations.
fn resolve_model_path(
    configured: &str,
    default_name: &str,
    credential_guard: Option<CredentialSourceIdentity>,
) -> Result<ResolvedModel> {
    let credential_directory = std::env::var_os("CREDENTIALS_DIRECTORY");
    resolve_model_path_with_credential_directory(
        configured,
        default_name,
        credential_guard,
        credential_directory.as_deref(),
    )
}

fn resolve_model_path_with_credential_directory(
    configured: &str,
    default_name: &str,
    credential_guard: Option<CredentialSourceIdentity>,
    credential_directory: Option<&OsStr>,
) -> Result<ResolvedModel> {
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        match open_model_candidate(path, credential_guard) {
            Ok(model) => return Ok(model),
            Err(error) if error.downcast_ref::<ModelCredentialAlias>().is_some() => {
                return Err(error);
            }
            Err(_) => {}
        }
        bail!("Configured model not found: {configured}");
    }

    if credential_guard.is_some_and(|guard| default_name == guard.credential_name()) {
        return Err(ModelCredentialAlias.into());
    }

    // Check systemd credentials directory
    let fixed_model_credential = matches!(default_name, "det_10g.onnx" | "w600k_r50.onnx");
    if let Some(creds_dir) = credential_directory.filter(|_| fixed_model_credential) {
        let cred_path = PathBuf::from(creds_dir).join(default_name);
        match open_model_candidate(cred_path, credential_guard) {
            Ok(model) => {
                info!(
                    "Using model from systemd credentials: {}",
                    model.display_path().display()
                );
                return Ok(model);
            }
            Err(error) if error.downcast_ref::<ModelCredentialAlias>().is_some() => {
                return Err(error);
            }
            Err(_) => {}
        }
    }

    // Search standard locations
    match howy_common::paths::find_model(default_name) {
        Some(path) => open_model_candidate(path, credential_guard),
        None => bail!(
            "Model '{}' not found in standard locations. \
             Install models to {} or set the path in config.",
            default_name,
            howy_common::paths::ONNX_DATA_DIR,
        ),
    }
}

/// Resolve both model paths exactly once into the startup descriptor snapshot.
pub fn resolve_models(
    config: &HowyConfig,
    credential_guard: Option<CredentialSourceIdentity>,
) -> Result<ResolvedModels> {
    let recognizer = resolve_recognizer_model(config, credential_guard)?;
    resolve_models_with_recognizer(config, credential_guard, recognizer)
}

/// Resolve only the recognizer descriptor needed to bind storage readiness.
pub fn resolve_recognizer_model(
    config: &HowyConfig,
    credential_guard: Option<CredentialSourceIdentity>,
) -> Result<ResolvedModel> {
    resolve_model_path(
        &config.ml.recognizer_model,
        "w600k_r50.onnx",
        credential_guard,
    )
}

/// Resolve the detector after storage readiness while retaining the exact
/// recognizer descriptor already used for the storage model digest.
pub fn resolve_models_with_recognizer(
    config: &HowyConfig,
    credential_guard: Option<CredentialSourceIdentity>,
    recognizer: ResolvedModel,
) -> Result<ResolvedModels> {
    Ok(ResolvedModels {
        detector: resolve_model_path(&config.ml.detector_model, "det_10g.onnx", credential_guard)?,
        recognizer,
    })
}
