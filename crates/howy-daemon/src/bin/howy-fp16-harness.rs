//! Experimental, non-installed FP32/FP16 numerical-drift harness.
//!
//! The parent pins every input byte, creates fresh locked caches, and launches
//! hermetic one-precision workers. Detailed records only cross a capability-
//! protected inherited Unix socket; stdout is aggregate-only.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bincode::Options;
use howy_common::config::HowyConfig;
use howy_common::face::{self, FACE_EMBEDDING_DIM};
use howy_daemon::inference::{InferenceEngine, InferenceProfiling};
use image::ImageReader;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROTOCOL_VERSION: u32 = 2;
const ORT_CRATE_VERSION: &str = "2.0.0-rc.12";
const PROTOCOL_FD: RawFd = 3;
const CACHE_FD: RawFd = 4;
const PROFILE_FD: RawFd = 5;
const CAPABILITY_BYTES: usize = 32;

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_FIXTURES: usize = 32;
const MAX_FIXTURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_FIXTURE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PIXELS_PER_FIXTURE: u64 = 8_000_000;
const MAX_TOTAL_PIXELS: u64 = 32_000_000;
const MAX_FACES_PER_FIXTURE: usize = 16;
const MAX_ENROLLED_MODEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENROLLED_MODELS: usize = 256;
const MAX_LABEL_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 128;
const MAX_ONNX_MODEL_BYTES: usize = 192 * 1024 * 1024;
const MAX_TOTAL_ONNX_BYTES: usize = 256 * 1024 * 1024;
const MAX_PROTOCOL_BYTES: usize = 320 * 1024 * 1024;
const MAX_PROFILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROC_MAPS_BYTES: usize = 4 * 1024 * 1024;
const MAX_WIRE_STRING_BYTES: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 32;
const MAX_PROFILE_NODES: usize = 20_000;
const MAX_PROFILE_EVENTS: usize = 100_000;
const MAX_CACHE_ARTIFACTS: usize = 4096;
const MAX_CACHE_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const MAX_TOTAL_CACHE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RUNTIME_LIBRARIES: usize = 64;
const MAX_DIRECTORY_ENTRIES: usize = 8192;
const MAX_CACHE_DIRECTORY_DEPTH: usize = 16;
const DEFAULT_WORKER_DEADLINE_SECS: u64 = 600;
const MAX_WORKER_DEADLINE_SECS: u64 = 3600;
const DEFAULT_PAIRS: usize = 2;
const MAX_PAIRS: usize = 16;
const EMBEDDING_NORM_TOLERANCE: f64 = 1.0e-3;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_FLAGS: u64 = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

struct BoundedString<const MAX: usize>(String);

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<const MAX: usize>;
        impl<'de, const MAX: usize> serde::de::Visitor<'de> for Visitor<MAX> {
            type Value = BoundedString<MAX>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a UTF-8 string of at most {MAX} bytes")
            }
            fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("wire_string_limit"));
                }
                Ok(BoundedString(value.to_owned()))
            }
            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("wire_string_limit"));
                }
                Ok(BoundedString(value))
            }
        }
        deserializer.deserialize_str(Visitor::<MAX>)
    }
}

fn deserialize_string_limited<'de, D, const MAX: usize>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(BoundedString::<MAX>::deserialize(deserializer)?.0)
}

fn deserialize_vec_limited<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for Visitor<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence of at most {MAX} items")
        }
        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX {
                return Err(serde::de::Error::custom("wire_collection_limit"));
            }
            let mut values = Vec::with_capacity(hint);
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(serde::de::Error::custom("wire_collection_limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Visitor::<T, MAX>(std::marker::PhantomData))
}

macro_rules! bounded_string_deserializer {
    ($name:ident, $max:expr) => {
        fn $name<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_string_limited::<D, $max>(deserializer)
        }
    };
}

macro_rules! bounded_vec_deserializer {
    ($name:ident, $max:expr) => {
        fn $name<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
        where
            D: serde::Deserializer<'de>,
            T: Deserialize<'de>,
        {
            deserialize_vec_limited::<D, T, $max>(deserializer)
        }
    };
}

bounded_string_deserializer!(deserialize_digest, 64);
bounded_string_deserializer!(deserialize_short_string, 128);
bounded_string_deserializer!(deserialize_wire_string, MAX_WIRE_STRING_BYTES);
bounded_vec_deserializer!(deserialize_fixture_bytes, MAX_FIXTURE_BYTES);
bounded_vec_deserializer!(deserialize_onnx_bytes, MAX_ONNX_MODEL_BYTES);
bounded_vec_deserializer!(deserialize_fixtures, MAX_FIXTURES);
bounded_vec_deserializer!(deserialize_cache_artifacts, MAX_CACHE_ARTIFACTS);
bounded_vec_deserializer!(deserialize_runtime_libraries, MAX_RUNTIME_LIBRARIES);
bounded_vec_deserializer!(deserialize_records, MAX_FIXTURES);
bounded_vec_deserializer!(deserialize_faces, MAX_FACES_PER_FIXTURE);
bounded_vec_deserializer!(deserialize_embedding, FACE_EMBEDDING_DIM);

fn deserialize_optional_enrolled_bytes<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<Vec<u8>>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an optional bounded enrolled model")
        }
        fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_vec_limited::<D, u8, MAX_ENROLLED_MODEL_BYTES>(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(Visitor)
}

fn deserialize_environment_strings<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values =
        deserialize_vec_limited::<D, BoundedString<128>, MAX_ENVIRONMENT_ENTRIES>(deserializer)?;
    Ok(values.into_iter().map(|value| value.0).collect())
}

fn deserialize_environment_map<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded environment map")
        }
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            if map.size_hint().unwrap_or(0) > MAX_ENVIRONMENT_ENTRIES {
                return Err(serde::de::Error::custom("wire_environment_limit"));
            }
            let mut values = BTreeMap::new();
            while let Some((key, value)) =
                map.next_entry::<BoundedString<128>, BoundedString<MAX_WIRE_STRING_BYTES>>()?
            {
                if values.len() == MAX_ENVIRONMENT_ENTRIES {
                    return Err(serde::de::Error::custom("wire_environment_limit"));
                }
                values.insert(key.0, value.0);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor)
}

fn deserialize_providers<'de, D>(deserializer: D) -> std::result::Result<BTreeSet<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = deserialize_vec_limited::<D, BoundedString<128>, 16>(deserializer)?;
    Ok(values.into_iter().map(|value| value.0).collect())
}

fn deserialize_placement_nodes<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, PlacementNode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, PlacementNode>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded placement map")
        }
        fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            if map.size_hint().unwrap_or(0) > MAX_PROFILE_NODES {
                return Err(serde::de::Error::custom("wire_placement_limit"));
            }
            let mut values = BTreeMap::new();
            while let Some((key, value)) =
                map.next_entry::<BoundedString<MAX_WIRE_STRING_BYTES>, PlacementNode>()?
            {
                if values.len() == MAX_PROFILE_NODES {
                    return Err(serde::de::Error::custom("wire_placement_limit"));
                }
                values.insert(key.0, value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Visitor)
}

const DEFAULT_MIN_FACE_IOU: f64 = 0.95;
const DEFAULT_MAX_DETECTOR_SCORE_DRIFT: f64 = 0.01;
const DEFAULT_MAX_LANDMARK_RMSE: f64 = 1.0;
const DEFAULT_MIN_EMBEDDING_COSINE: f64 = 0.999;
const DEFAULT_MAX_ENROLLED_SCORE_DRIFT: f64 = 0.01;

const CLEARED_ENV: &[&str] = &[
    "ORT_MIGRAPHX_SAVE_COMPILED_MODEL",
    "ORT_MIGRAPHX_LOAD_COMPILED_MODEL",
    "ORT_MIGRAPHX_SAVE_MODEL_PATH",
    "ORT_MIGRAPHX_LOAD_MODEL_PATH",
    "ORT_MIGRAPHX_INT8_CALIBRATION_TABLE_NAME",
    "ORT_MIGRAPHX_DUMP_EP_CONTEXT_MODEL",
    "MIGRAPHX_MLIR_DUMP",
    "MIGRAPHX_TRACE_COMPILE",
    "MIGRAPHX_TRACE_EVAL",
    "MIGRAPHX_TRACE_PASSES",
    "MIGRAPHX_ENABLE_MLIR",
    "MIGRAPHX_ENABLE_CK",
    "MIGRAPHX_ENABLE_HIPRTC_WORKAROUNDS",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[serde(rename_all = "lowercase")]
enum Precision {
    Fp32,
    Fp16,
}

impl Precision {
    fn name(self) -> &'static str {
        match self {
            Self::Fp32 => "fp32",
            Self::Fp16 => "fp16",
        }
    }

    fn fp16(self) -> bool {
        self == Self::Fp16
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Zeroize)]
#[serde(rename_all = "snake_case")]
enum WorkerPhase {
    CacheGeneration,
    LoadedCacheMeasurement,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum FixtureClass {
    Positive,
    Negative,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(deserialize_with = "deserialize_fixtures")]
    fixtures: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    #[serde(deserialize_with = "deserialize_wire_string")]
    path: String,
    class: FixtureClass,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PinnedFixture {
    #[zeroize(skip)]
    index: usize,
    #[zeroize(skip)]
    class: FixtureClass,
    #[serde(deserialize_with = "deserialize_digest")]
    digest: String,
    #[serde(deserialize_with = "deserialize_fixture_bytes")]
    encoded: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct PinnedCorpus {
    #[serde(deserialize_with = "deserialize_digest")]
    detector_digest: String,
    #[serde(deserialize_with = "deserialize_onnx_bytes")]
    detector_model: Vec<u8>,
    #[serde(deserialize_with = "deserialize_digest")]
    recognizer_digest: String,
    #[serde(deserialize_with = "deserialize_onnx_bytes")]
    recognizer_model: Vec<u8>,
    #[serde(deserialize_with = "deserialize_optional_enrolled_bytes")]
    enrolled_model: Option<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_fixtures")]
    fixtures: Vec<PinnedFixture>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Gates {
    min_face_iou: f64,
    max_detector_score_drift: f64,
    max_landmark_rmse: f64,
    min_embedding_cosine: f64,
    max_enrolled_score_drift: f64,
}

impl Default for Gates {
    fn default() -> Self {
        Self {
            min_face_iou: DEFAULT_MIN_FACE_IOU,
            max_detector_score_drift: DEFAULT_MAX_DETECTOR_SCORE_DRIFT,
            max_landmark_rmse: DEFAULT_MAX_LANDMARK_RMSE,
            min_embedding_cosine: DEFAULT_MIN_EMBEDDING_COSINE,
            max_enrolled_score_drift: DEFAULT_MAX_ENROLLED_SCORE_DRIFT,
        }
    }
}

#[derive(Debug)]
struct ParentConfig {
    experiment_root: PathBuf,
    fixture_dir: PathBuf,
    manifest: PathBuf,
    detector_model: PathBuf,
    recognizer_model: PathBuf,
    enrolled_model: Option<PathBuf>,
    result: PathBuf,
    diagnostics: Option<PathBuf>,
    threshold: f32,
    hsa_override: String,
    configured_gpu_target: String,
    pairs: usize,
    deadline: Duration,
    allow_mixed: bool,
    gates: Gates,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct EnvironmentAttestation {
    #[serde(deserialize_with = "deserialize_environment_map")]
    set: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_environment_strings")]
    cleared: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct Provenance {
    precision: Precision,
    #[serde(deserialize_with = "deserialize_digest")]
    detector_digest: String,
    #[serde(deserialize_with = "deserialize_digest")]
    recognizer_digest: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    ort_crate_version: String,
    ort_api_version: u32,
    #[serde(deserialize_with = "deserialize_wire_string")]
    ort_runtime_version: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    configured_gpu_target: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    hsa_override: String,
    recognition_threshold_bits: u32,
    inference_threads: usize,
    #[serde(deserialize_with = "deserialize_short_string")]
    provider_name: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    graph_optimization_level: String,
    provider_api_fp16: bool,
    provider_api_fp8: bool,
    provider_api_int8: bool,
    provider_api_exhaustive_tune: bool,
    environment: EnvironmentAttestation,
    #[serde(deserialize_with = "deserialize_digest")]
    corpus_digest: String,
    provider_stack: ProviderStackProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct RuntimeLibraryDigest {
    #[serde(deserialize_with = "deserialize_short_string")]
    name: String,
    #[serde(deserialize_with = "deserialize_wire_string")]
    path: String,
    #[serde(deserialize_with = "deserialize_digest")]
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct ProviderStackProvenance {
    #[serde(deserialize_with = "deserialize_runtime_libraries")]
    libraries: Vec<RuntimeLibraryDigest>,
    has_ort_core: bool,
    has_ort_migraphx_provider: bool,
    has_migraphx: bool,
    has_hip: bool,
    has_rocm_runtime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
struct CacheArtifact {
    #[serde(deserialize_with = "deserialize_wire_string")]
    relative_name: String,
    size: u64,
    #[serde(deserialize_with = "deserialize_digest")]
    sha256: String,
    device: u64,
    inode: u64,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactStamp {
    device: u64,
    inode: u64,
    length: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl ArtifactStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct CacheManifest {
    provenance: Provenance,
    #[serde(deserialize_with = "deserialize_cache_artifacts")]
    artifacts: Vec<CacheArtifact>,
}

#[derive(Serialize)]
struct WorkerRequestRef<'a> {
    protocol_version: u32,
    capability: [u8; CAPABILITY_BYTES],
    phase: WorkerPhase,
    precision: Precision,
    cache_dir: &'a str,
    profile_dir: &'a str,
    threshold: f32,
    configured_gpu_target: &'a str,
    hsa_override: &'a str,
    environment: &'a EnvironmentAttestation,
    expected_provenance: Option<&'a Provenance>,
    corpus_digest: &'a str,
    corpus: &'a PinnedCorpus,
}

#[derive(Deserialize)]
struct WorkerRequest {
    protocol_version: u32,
    capability: [u8; CAPABILITY_BYTES],
    phase: WorkerPhase,
    precision: Precision,
    #[serde(deserialize_with = "deserialize_wire_string")]
    cache_dir: String,
    #[serde(deserialize_with = "deserialize_wire_string")]
    profile_dir: String,
    threshold: f32,
    #[serde(deserialize_with = "deserialize_short_string")]
    configured_gpu_target: String,
    #[serde(deserialize_with = "deserialize_short_string")]
    hsa_override: String,
    environment: EnvironmentAttestation,
    expected_provenance: Option<Provenance>,
    #[serde(deserialize_with = "deserialize_digest")]
    corpus_digest: String,
    corpus: PinnedCorpus,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
struct PlacementFacts {
    migraphx_events: u64,
    cpu_events: u64,
    unknown_events: u64,
    #[serde(deserialize_with = "deserialize_providers")]
    providers: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_placement_nodes")]
    nodes: BTreeMap<String, PlacementNode>,
    mode: PlacementMode,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
struct PlacementNode {
    #[serde(deserialize_with = "deserialize_short_string")]
    provider: String,
    invocation_count: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PlacementMode {
    AllMigraphx,
    Mixed,
    #[default]
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerOutput {
    protocol_version: u32,
    capability: [u8; CAPABILITY_BYTES],
    phase: WorkerPhase,
    precision: Precision,
    #[serde(deserialize_with = "deserialize_short_string")]
    registered_preference: String,
    #[serde(deserialize_with = "deserialize_digest")]
    corpus_digest: String,
    provenance: Provenance,
    detector_placement: PlacementFacts,
    recognizer_placement: PlacementFacts,
    #[serde(deserialize_with = "deserialize_records")]
    records: Vec<ImageRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ImageRecord {
    #[zeroize(skip)]
    index: usize,
    #[zeroize(skip)]
    class: FixtureClass,
    #[zeroize(skip)]
    decode_ms: f64,
    #[zeroize(skip)]
    detector_pipeline_ms: f64,
    #[zeroize(skip)]
    recognizer_pipeline_ms: f64,
    #[zeroize(skip)]
    enrolled_matching_ms: f64,
    #[zeroize(skip)]
    complete_fixture_ms: f64,
    #[serde(deserialize_with = "deserialize_faces")]
    faces: Vec<FaceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct FaceRecord {
    bbox: [i32; 4],
    landmarks: [f32; 10],
    detector_score: f32,
    #[serde(deserialize_with = "deserialize_embedding")]
    embedding: Vec<f32>,
    enrolled_score: Option<f32>,
    decision: Option<bool>,
}

#[derive(Debug, Serialize)]
struct Report {
    protocol_version: u32,
    run_id: String,
    evidence_scope: &'static str,
    fixture_count: usize,
    pair_count: usize,
    placement_policy: &'static str,
    provenance: PublicProvenance,
    placement: Vec<PublicPairPlacement>,
    gates: GateReport,
    metrics: MetricReport,
    fp32_timings: TimingReport,
    fp16_timings: TimingReport,
    paired_complete_fixture_delta_ms: Distribution,
    parent_matching_and_comparison_ms: Distribution,
    process_order: Vec<Vec<Precision>>,
    cache_generation_process_ms: Distribution,
    loaded_cache_measurement_process_ms: Distribution,
    cache_artifact_unchanged: bool,
    all_required_gates_passed: bool,
}

#[derive(Debug, Serialize)]
struct PublicProvenance {
    configured_gpu_target: String,
    hsa_override: String,
    hsa_override_source: &'static str,
    provider_provenance_match: bool,
    precision_controls: BTreeMap<String, String>,
    isolated_arm_caches: bool,
}

#[derive(Debug, Serialize)]
struct PublicPairPlacement {
    pair: usize,
    fp32_registered_preference: String,
    fp16_registered_preference: String,
    fp32_detector: PublicPlacement,
    fp32_recognizer: PublicPlacement,
    fp16_detector: PublicPlacement,
    fp16_recognizer: PublicPlacement,
}

#[derive(Debug, Serialize)]
struct PublicPlacement {
    mode: PlacementMode,
    migraphx_executed_events: u64,
    cpu_executed_events: u64,
    unknown_executed_events: u64,
    provider_set: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Distribution {
    count: usize,
    min: f64,
    mean: f64,
    median: f64,
    max: f64,
    p95: Option<f64>,
}

#[derive(Debug, Serialize)]
struct TimingReport {
    image_decode_ms: Distribution,
    detector_preprocess_run_postprocess_ms: Distribution,
    recognizer_alignment_run_ms: Distribution,
    enrolled_matching_ms: Distribution,
    complete_fixture_ms: Distribution,
}

#[derive(Debug, Serialize)]
struct MetricReport {
    box_iou: Distribution,
    detector_score_abs_drift: Distribution,
    landmark_point_rmse_pixels: Distribution,
    embedding_cosine: Distribution,
    enrolled_score_abs_drift: Distribution,
    matched_faces: usize,
    unmatched_faces: usize,
    threshold_flips: usize,
    decision_testing_evaluated: bool,
}

#[derive(Debug, Serialize)]
struct GateReport {
    face_iou: GateResult,
    detector_score_drift: GateResult,
    landmark_rmse: GateResult,
    embedding_cosine: GateResult,
    enrolled_score_drift: OptionalGateResult,
    threshold_flips: OptionalGateResult,
    unmatched_faces: GateResult,
}

#[derive(Debug, Serialize)]
struct GateResult {
    comparator: &'static str,
    value: f64,
    limit: f64,
    evaluated_count: usize,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct OptionalGateResult {
    comparator: &'static str,
    value: Option<f64>,
    limit: f64,
    evaluated_count: usize,
    passed: Option<bool>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureBlob {
    bytes: Vec<u8>,
    digest: String,
    #[zeroize(skip)]
    identity: (u64, u64),
}

struct ArmLayout {
    cache: File,
    profiles: File,
    _lock: File,
}

struct PairLayout {
    fp32: ArmLayout,
    fp16: ArmLayout,
}

struct ExperimentLayout {
    root: File,
    run_name: String,
    pairs: Vec<PairLayout>,
}

impl Drop for ExperimentLayout {
    fn drop(&mut self) {
        let _ = remove_tree_at(self.root.as_raw_fd(), &self.run_name);
    }
}

struct ExperimentRoot {
    fd: File,
}

struct PendingOutput {
    parent: File,
    temporary: CString,
    final_name: CString,
    file: File,
    published: bool,
}

impl PendingOutput {
    fn new(root: &File, path: &Path) -> Result<Self> {
        let (parent, final_name) = open_output_parent(root, path)?;
        let temporary = CString::new(format!(".tmp-{}", hex::encode(random_bytes::<16>()?)))?;
        let file = openat2_file(
            parent.as_raw_fd(),
            Path::new(OsStr::from_bytes(temporary.as_bytes())),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_APPEND,
            0o600,
        )?;
        Ok(Self {
            parent,
            temporary,
            final_name: CString::new(final_name.as_bytes())?,
            file,
            published: false,
        })
    }

    fn publish(&mut self) -> Result<()> {
        self.file.sync_all()?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.final_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("diagnostic_publish_failed");
        }
        self.published = true;
        Ok(())
    }
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if !self.published {
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.temporary.as_ptr(), 0);
            }
        }
    }
}

#[derive(Default)]
struct PairOutputs {
    fp32: Option<WorkerOutput>,
    fp16: Option<WorkerOutput>,
}

fn main() {
    unsafe { libc::umask(0o077) };
    if real_main().is_err() {
        eprintln!("experimental FP16 harness failed: code=HARNESS_OPERATION_FAILED");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--worker") {
        return worker_entry(&args[1..]);
    }
    let config = parse_parent_args(&args)?;
    let repo = repository_root()?;
    validate_config_paths(&config)?;
    let root = open_experiment_root(&config.experiment_root, &repo)?;
    let mut diagnostic = config
        .diagnostics
        .as_ref()
        .map(|path| PendingOutput::new(&root.fd, path))
        .transpose()?;
    match run_parent(
        &config,
        &root,
        diagnostic.as_ref().map(|output| &output.file),
    ) {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Some(output) = diagnostic.as_mut() {
                let detail = redact_diagnostic(&format!("{error:#}"), &config);
                let _ = output.file.write_all(detail.as_bytes());
                let _ = output.publish();
            }
            Err(anyhow::anyhow!("parent_stage_failed"))
        }
    }
}

fn validate_config_paths(config: &ParentConfig) -> Result<()> {
    for path in [
        &config.fixture_dir,
        &config.manifest,
        &config.detector_model,
        &config.recognizer_model,
        &config.result,
    ] {
        validate_relative_os_path(path)?;
    }
    if let Some(path) = config.enrolled_model.as_ref() {
        validate_relative_os_path(path)?;
    }
    if let Some(path) = config.diagnostics.as_ref() {
        validate_relative_os_path(path)?;
        if path == &config.result {
            bail!("diagnostic_result_alias");
        }
    }
    for output in [Some(&config.result), config.diagnostics.as_ref()]
        .into_iter()
        .flatten()
    {
        if output.starts_with(&config.fixture_dir)
            || output == &config.manifest
            || output == &config.detector_model
            || output == &config.recognizer_model
            || config.enrolled_model.as_ref() == Some(output)
        {
            bail!("output_input_path_overlap");
        }
    }
    Ok(())
}

fn parse_parent_args(args: &[OsString]) -> Result<ParentConfig> {
    let values = parse_flags(args)?;
    let gates = Gates {
        min_face_iou: optional_f64(&values, "min-face-iou", DEFAULT_MIN_FACE_IOU)?,
        max_detector_score_drift: optional_f64(
            &values,
            "max-detector-score-drift",
            DEFAULT_MAX_DETECTOR_SCORE_DRIFT,
        )?,
        max_landmark_rmse: optional_f64(&values, "max-landmark-rmse", DEFAULT_MAX_LANDMARK_RMSE)?,
        min_embedding_cosine: optional_f64(
            &values,
            "min-embedding-cosine",
            DEFAULT_MIN_EMBEDDING_COSINE,
        )?,
        max_enrolled_score_drift: optional_f64(
            &values,
            "max-enrolled-score-drift",
            DEFAULT_MAX_ENROLLED_SCORE_DRIFT,
        )?,
    };
    let threshold = required_f32(&values, "threshold")?;
    validate_numeric_configuration(threshold, gates)?;
    let pairs = optional_usize(&values, "pairs", DEFAULT_PAIRS)?;
    let deadline_secs = optional_u64(
        &values,
        "worker-deadline-secs",
        DEFAULT_WORKER_DEADLINE_SECS,
    )?;
    if !(1..=MAX_PAIRS).contains(&pairs) || !(1..=MAX_WORKER_DEADLINE_SECS).contains(&deadline_secs)
    {
        bail!("invalid repetition/deadline limit");
    }
    let hsa_override = required_string(&values, "hsa-override")?;
    let configured_gpu_target = required_string(&values, "configured-gpu-target")?;
    validate_hsa_override(&hsa_override)?;
    validate_token(&configured_gpu_target, 64, false)?;
    Ok(ParentConfig {
        experiment_root: required_path(&values, "experiment-root")?,
        fixture_dir: required_path(&values, "fixtures")?,
        manifest: required_path(&values, "manifest")?,
        detector_model: required_path(&values, "detector-model")?,
        recognizer_model: required_path(&values, "recognizer-model")?,
        enrolled_model: optional_path(&values, "model-file"),
        result: required_path(&values, "result")?,
        diagnostics: optional_path(&values, "diagnostics"),
        threshold,
        hsa_override,
        configured_gpu_target,
        pairs,
        deadline: Duration::from_secs(deadline_secs),
        allow_mixed: flag(&values, "allow-mixed-placement"),
        gates,
    })
}

fn parse_flags(args: &[OsString]) -> Result<BTreeMap<String, Option<OsString>>> {
    let flags = ["allow-mixed-placement"];
    let allowed = [
        "experiment-root",
        "fixtures",
        "manifest",
        "detector-model",
        "recognizer-model",
        "model-file",
        "result",
        "diagnostics",
        "threshold",
        "hsa-override",
        "configured-gpu-target",
        "pairs",
        "worker-deadline-secs",
        "min-face-iou",
        "max-detector-score-drift",
        "max-landmark-rmse",
        "min-embedding-cosine",
        "max-enrolled-score-drift",
        "allow-mixed-placement",
    ];
    let mut values = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index]
            .to_str()
            .context("non_utf8_argument")?
            .strip_prefix("--")
            .context("invalid_argument_syntax")?
            .to_string();
        if !allowed.contains(&key.as_str()) || values.contains_key(&key) {
            bail!("unknown_or_duplicate_argument");
        }
        if flags.contains(&key.as_str()) {
            values.insert(key, None);
            index += 1;
        } else {
            let value = args
                .get(index + 1)
                .context("missing_argument_value")?
                .clone();
            values.insert(key, Some(value));
            index += 2;
        }
    }
    Ok(values)
}

fn required_string(values: &BTreeMap<String, Option<OsString>>, name: &str) -> Result<String> {
    values
        .get(name)
        .and_then(Option::as_ref)
        .and_then(|value| value.to_str())
        .map(str::to_owned)
        .with_context(|| format!("missing_{name}"))
}

fn required_path(values: &BTreeMap<String, Option<OsString>>, name: &str) -> Result<PathBuf> {
    values
        .get(name)
        .and_then(Option::as_ref)
        .map(PathBuf::from)
        .with_context(|| format!("missing_{name}"))
}

fn optional_path(values: &BTreeMap<String, Option<OsString>>, name: &str) -> Option<PathBuf> {
    values.get(name).and_then(Option::as_ref).map(PathBuf::from)
}

fn required_f32(values: &BTreeMap<String, Option<OsString>>, name: &str) -> Result<f32> {
    required_string(values, name)?
        .parse()
        .with_context(|| format!("invalid_{name}"))
}

fn optional_f64(
    values: &BTreeMap<String, Option<OsString>>,
    name: &str,
    default: f64,
) -> Result<f64> {
    values
        .get(name)
        .and_then(Option::as_ref)
        .map(|value| {
            value
                .to_str()
                .context("non_utf8_number")?
                .parse()
                .context("invalid_number")
        })
        .unwrap_or(Ok(default))
}

fn optional_usize(
    values: &BTreeMap<String, Option<OsString>>,
    name: &str,
    default: usize,
) -> Result<usize> {
    Ok(values
        .get(name)
        .and_then(Option::as_ref)
        .map(|value| value.to_str().unwrap_or("").parse())
        .transpose()?
        .unwrap_or(default))
}

fn optional_u64(
    values: &BTreeMap<String, Option<OsString>>,
    name: &str,
    default: u64,
) -> Result<u64> {
    Ok(values
        .get(name)
        .and_then(Option::as_ref)
        .map(|value| value.to_str().unwrap_or("").parse())
        .transpose()?
        .unwrap_or(default))
}

fn flag(values: &BTreeMap<String, Option<OsString>>, name: &str) -> bool {
    values.get(name).is_some_and(Option::is_none)
}

fn validate_numeric_configuration(threshold: f32, gates: Gates) -> Result<()> {
    let values = [
        f64::from(threshold),
        gates.min_face_iou,
        gates.max_detector_score_drift,
        gates.max_landmark_rmse,
        gates.min_embedding_cosine,
        gates.max_enrolled_score_drift,
    ];
    if values.iter().any(|value| !value.is_finite())
        || !(0.0..=1.0).contains(&threshold)
        || !(0.0..=1.0).contains(&gates.min_face_iou)
        || !(0.0..=1.0).contains(&gates.min_embedding_cosine)
        || gates.max_detector_score_drift < 0.0
        || gates.max_landmark_rmse < 0.0
        || gates.max_enrolled_score_drift < 0.0
    {
        bail!("invalid_numeric_configuration");
    }
    Ok(())
}

fn validate_token(value: &str, max: usize, dots_only: bool) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= max
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '.'
                || (!dots_only && matches!(character, '_' | '-' | ':'))
        });
    if !valid {
        bail!("invalid_provenance_token");
    }
    Ok(())
}

fn validate_hsa_override(value: &str) -> Result<()> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > 3
                || !component
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
    {
        bail!("invalid_hsa_override");
    }
    Ok(())
}

fn run_parent(
    config: &ParentConfig,
    root: &ExperimentRoot,
    diagnostics: Option<&File>,
) -> Result<()> {
    let mut corpus = pin_corpus(config, root)?;
    let corpus_digest = corpus_digest(&corpus)?;
    let layout = create_experiment_layout(root, config.pairs)?;
    let run_id = layout
        .run_name
        .strip_prefix("run-")
        .context("run_id_missing")?
        .to_owned();
    let mut pair_outputs = Vec::with_capacity(config.pairs);
    let mut generation_durations = Vec::new();
    let mut measurement_durations = Vec::new();

    for (pair_index, pair_layout) in layout.pairs.iter().enumerate() {
        let order = pair_order(pair_index);
        let mut generation = HashMap::new();
        for precision in order {
            let arm = arm_layout(pair_layout, precision);
            let environment = reviewed_environment(precision, &config.hsa_override)?;
            let started = Instant::now();
            let output = launch_worker(
                config,
                &corpus,
                arm,
                precision,
                WorkerPhase::CacheGeneration,
                &environment,
                None,
                &corpus_digest,
                diagnostics,
            )?;
            generation_durations.push(elapsed_ms(started.elapsed()));
            validate_worker_output(
                &output,
                precision,
                WorkerPhase::CacheGeneration,
                0,
                config.threshold,
                &corpus_digest,
            )?;
            verify_output_provenance(&output, config, &corpus, precision, &environment)?;
            let generated_artifacts = inventory_cache(&arm.cache)?;
            if generated_artifacts.is_empty() {
                bail!("cache_mxr_inventory_empty");
            }
            let artifacts = make_cache_artifacts_read_only(&arm.cache, &generated_artifacts)?;
            let manifest = CacheManifest {
                provenance: output.provenance,
                artifacts,
            };
            write_cache_provenance(&arm.cache, &manifest)?;
            generation.insert(precision, manifest);
        }

        let mut measured = PairOutputs::default();
        for precision in order {
            let arm = arm_layout(pair_layout, precision);
            let environment = reviewed_environment(precision, &config.hsa_override)?;
            let expected = generation
                .get(&precision)
                .context("missing_generation_provenance")?;
            verify_cache_provenance(&arm.cache, expected)?;
            verify_cache_inventory(&arm.cache, &expected.artifacts)?;
            let started = Instant::now();
            let output = launch_worker(
                config,
                &corpus,
                arm,
                precision,
                WorkerPhase::LoadedCacheMeasurement,
                &environment,
                Some(&expected.provenance),
                &corpus_digest,
                diagnostics,
            )?;
            measurement_durations.push(elapsed_ms(started.elapsed()));
            validate_worker_output(
                &output,
                precision,
                WorkerPhase::LoadedCacheMeasurement,
                corpus.fixtures.len(),
                config.threshold,
                &corpus_digest,
            )?;
            verify_output_provenance(&output, config, &corpus, precision, &environment)?;
            verify_cache_inventory(&arm.cache, &expected.artifacts)?;
            verify_cache_provenance(&arm.cache, expected)?;
            if output.provenance != expected.provenance {
                bail!("measurement_provenance_mismatch");
            }
            match precision {
                Precision::Fp32 => measured.fp32 = Some(output),
                Precision::Fp16 => measured.fp16 = Some(output),
            }
        }
        pair_outputs.push(measured);
    }

    let (report, passed) = build_report(
        config,
        &corpus,
        &pair_outputs,
        generation_durations,
        measurement_durations,
        &run_id,
    )?;
    for pair in &mut pair_outputs {
        if let Some(output) = pair.fp32.as_mut() {
            scrub_worker_output(output);
        }
        if let Some(output) = pair.fp16.as_mut() {
            scrub_worker_output(output);
        }
    }
    let bytes = serde_json::to_vec_pretty(&report)?;
    write_atomic_at(&root.fd, &config.result, &bytes)?;
    std::io::stdout().write_all(&bytes)?;
    std::io::stdout().write_all(b"\n")?;
    if let Some(model) = corpus.enrolled_model.as_mut() {
        model.zeroize();
    }
    if !passed {
        bail!("gates_rejected");
    }
    Ok(())
}

fn worker_entry(args: &[OsString]) -> Result<()> {
    for fd in [PROTOCOL_FD, CACHE_FD, PROFILE_FD] {
        set_fd_cloexec(fd)?;
    }
    if args.len() != 2
        || args[0] != "--protocol-fd"
        || args[1]
            .to_str()
            .and_then(|value| value.parse::<RawFd>().ok())
            != Some(PROTOCOL_FD)
    {
        bail!("worker_invocation_rejected");
    }
    let capability_text =
        Zeroizing::new(env::var("HOWY_FP16_CAPABILITY").context("worker_capability_missing")?);
    let capability = decode_capability(&capability_text)?;
    let mut protocol = unsafe { UnixStream::from_raw_fd(PROTOCOL_FD) };
    let mut request: WorkerRequest = read_frame(&mut protocol, MAX_PROTOCOL_BYTES)?;
    if request.protocol_version != PROTOCOL_VERSION || request.capability != capability {
        bail!("worker_capability_rejected");
    }
    let mut output = run_worker(&mut request)?;
    write_frame(&mut protocol, &output, MAX_PROTOCOL_BYTES)?;
    protocol.flush()?;
    scrub_worker_output(&mut output);
    Ok(())
}

fn scrub_worker_output(output: &mut WorkerOutput) {
    for record in &mut output.records {
        record.zeroize();
    }
}

fn run_worker(request: &mut WorkerRequest) -> Result<WorkerOutput> {
    validate_actual_environment(&request.environment)?;
    validate_inherited_directory_fd(CACHE_FD)?;
    validate_inherited_directory_fd(PROFILE_FD)?;
    if request.cache_dir != "/proc/self/fd/4" || request.profile_dir != "/proc/self/fd/5" {
        bail!("worker_fd_path_contract_mismatch");
    }
    let cache_value = request.cache_dir.as_str();
    if request
        .environment
        .set
        .get("ORT_MIGRAPHX_CACHE_PATH")
        .map(String::as_str)
        != Some(cache_value)
        || request
            .environment
            .set
            .get("ORT_MIGRAPHX_MODEL_CACHE_PATH")
            .map(String::as_str)
            != Some(cache_value)
    {
        bail!("worker_cache_attestation_mismatch");
    }
    validate_numeric_configuration(request.threshold, Gates::default())?;
    let detector_digest = digest_hex(&request.corpus.detector_model);
    let recognizer_digest = digest_hex(&request.corpus.recognizer_model);
    let actual_corpus_digest = corpus_digest(&request.corpus)?;
    if detector_digest != request.corpus.detector_digest
        || recognizer_digest != request.corpus.recognizer_digest
        || verify_corpus_digest(&request.corpus_digest, &actual_corpus_digest).is_err()
    {
        bail!("worker_corpus_digest_mismatch");
    }

    let detector_profile_base = Path::new(&request.profile_dir).join(format!(
        "{}-{}-detector.json",
        request.precision.name(),
        phase_name(request.phase)
    ));
    let recognizer_profile_base = Path::new(&request.profile_dir).join(format!(
        "{}-{}-recognizer.json",
        request.precision.name(),
        phase_name(request.phase)
    ));
    let mut config = HowyConfig::default();
    config.ml.provider = "migraphx".into();
    config.ml.recognition_threshold = request.threshold;
    let engine = InferenceEngine::new_profiled_from_memory(
        &config,
        InferenceProfiling {
            detector_path: detector_profile_base,
            recognizer_path: recognizer_profile_base,
            migraphx_fp16: Some(request.precision.fp16()),
        },
        &request.corpus.detector_model,
        &request.corpus.recognizer_model,
    )?;
    let registered_preference = engine.registered_preferred_provider().to_string();
    engine.warmup()?;
    engine.warmup_recognizer()?;

    let enrolled = request
        .corpus
        .enrolled_model
        .as_ref()
        .map(|bytes| parse_and_validate_enrolled_model(bytes))
        .transpose()?;
    let mut records = Vec::new();
    if request.phase == WorkerPhase::LoadedCacheMeasurement {
        records.reserve(request.corpus.fixtures.len());
        for fixture in &request.corpus.fixtures {
            records.push(measure_fixture(
                &engine,
                fixture,
                enrolled.as_ref(),
                request.threshold,
            )?);
        }
    }
    let (detector_path, recognizer_path) = engine.end_profiling()?;
    let detector_placement = parse_profile(Path::new(&detector_path), PROFILE_FD)?;
    let recognizer_placement = parse_profile(Path::new(&recognizer_path), PROFILE_FD)?;
    let provenance = Provenance {
        precision: request.precision,
        detector_digest,
        recognizer_digest,
        ort_crate_version: ORT_CRATE_VERSION.into(),
        ort_api_version: ort::MINOR_VERSION,
        ort_runtime_version: ort_runtime_version()?,
        configured_gpu_target: request.configured_gpu_target.clone(),
        hsa_override: request.hsa_override.clone(),
        recognition_threshold_bits: request.threshold.to_bits(),
        inference_threads: config.ml.threads,
        provider_name: "migraphx".into(),
        graph_optimization_level: "level2".into(),
        provider_api_fp16: request.precision.fp16(),
        provider_api_fp8: false,
        provider_api_int8: false,
        provider_api_exhaustive_tune: false,
        environment: request.environment.clone(),
        corpus_digest: actual_corpus_digest.clone(),
        provider_stack: inspect_provider_stack()?,
    };
    if let Some(expected) = request.expected_provenance.as_ref() {
        verify_provider_stack_match(&expected.provider_stack, &provenance.provider_stack)?;
        if expected != &provenance {
            bail!("worker_provenance_mismatch");
        }
    }
    request.corpus.zeroize();
    Ok(WorkerOutput {
        protocol_version: PROTOCOL_VERSION,
        capability: request.capability,
        phase: request.phase,
        precision: request.precision,
        registered_preference,
        corpus_digest: actual_corpus_digest,
        provenance,
        detector_placement,
        recognizer_placement,
        records,
    })
}

fn validate_inherited_directory_fd(fd: RawFd) -> Result<()> {
    let duplicate = duplicate_fd_for_exec(fd)?;
    let metadata = duplicate.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("worker_directory_fd_invalid");
    }
    Ok(())
}

fn measure_fixture(
    engine: &InferenceEngine,
    fixture: &PinnedFixture,
    enrolled: Option<&SecureEnrolledModels>,
    threshold: f32,
) -> Result<ImageRecord> {
    let complete_started = Instant::now();
    let decode_started = Instant::now();
    let (pre_width, pre_height) = inspect_image_dimensions(&fixture.encoded)?;
    let mut reader =
        ImageReader::new(std::io::Cursor::new(&fixture.encoded)).with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(pre_width);
    limits.max_image_height = Some(pre_height);
    limits.max_alloc = Some(MAX_PIXELS_PER_FIXTURE * 4);
    reader.limits(limits);
    let decoded = ZeroizingDynamicImage(reader.decode()?);
    let rgb = ZeroizingRgbImage(Some(decoded.0.to_rgb8()));
    let (width, height) = rgb.dimensions()?;
    validate_pixels(width, height)?;
    if (width, height) != (pre_width, pre_height) {
        bail!("decoded_dimension_mismatch");
    }
    let mut bgr = Zeroizing::new(rgb.into_raw()?);
    for pixel in bgr.chunks_exact_mut(3) {
        pixel.swap(0, 2);
    }
    let decode_ms = elapsed_ms(decode_started.elapsed());

    let detector_started = Instant::now();
    let mut faces = ZeroizingDetectedFaces(engine.detect(&bgr, width, height, false)?);
    let detector_pipeline_ms = elapsed_ms(detector_started.elapsed());
    if faces.0.len() > MAX_FACES_PER_FIXTURE {
        bail!("face_limit_exceeded");
    }
    let mut recognizer_pipeline_ms = 0.0;
    let mut enrolled_matching_ms = 0.0;
    let mut face_records = Vec::with_capacity(faces.0.len());
    for face in &mut faces.0 {
        let recognizer_started = Instant::now();
        let mut embedding = Zeroizing::new(engine.encode(&bgr, width, height, face, false)?);
        validate_normalized_embedding(&embedding)?;
        recognizer_pipeline_ms += elapsed_ms(recognizer_started.elapsed());
        let matching_started = Instant::now();
        let (enrolled_score, decision) = match enrolled {
            Some(models) => {
                let (matched, score) = face::find_best_match_flat(
                    &embedding,
                    &models.flat_embeddings,
                    models.count,
                    threshold,
                );
                (Some(score), Some(matched.is_some()))
            }
            None => (None, None),
        };
        enrolled_matching_ms += elapsed_ms(matching_started.elapsed());
        face_records.push(FaceRecord {
            bbox: face.bbox,
            landmarks: face.landmarks,
            detector_score: face.score,
            embedding: std::mem::take(&mut *embedding),
            enrolled_score,
            decision,
        });
    }
    Ok(ImageRecord {
        index: fixture.index,
        class: fixture.class,
        decode_ms,
        detector_pipeline_ms,
        recognizer_pipeline_ms,
        enrolled_matching_ms,
        complete_fixture_ms: elapsed_ms(complete_started.elapsed()),
        faces: face_records,
    })
}

struct ZeroizingDetectedFaces(Vec<face::Face>);

impl Zeroize for ZeroizingDetectedFaces {
    fn zeroize(&mut self) {
        for face in &mut self.0 {
            face.bbox.zeroize();
            face.landmarks.zeroize();
            face.score.zeroize();
            face.embedding.zeroize();
        }
    }
}

impl Drop for ZeroizingDetectedFaces {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingDetectedFaces {}

fn phase_name(phase: WorkerPhase) -> &'static str {
    match phase {
        WorkerPhase::CacheGeneration => "generate",
        WorkerPhase::LoadedCacheMeasurement => "measure",
    }
}

fn launch_worker(
    config: &ParentConfig,
    corpus: &PinnedCorpus,
    arm: &ArmLayout,
    precision: Precision,
    phase: WorkerPhase,
    environment: &EnvironmentAttestation,
    expected: Option<&Provenance>,
    corpus_digest: &str,
    diagnostics: Option<&File>,
) -> Result<WorkerOutput> {
    ensure_child_subreaper()?;
    let capability = random_capability()?;
    let capability_text = Zeroizing::new(hex::encode(capability));
    let (mut parent_protocol, child_protocol) = UnixStream::pair()?;
    let child_protocol_exec = duplicate_fd_for_exec(child_protocol.as_raw_fd())?;
    let cache_exec = duplicate_fd_for_exec(arm.cache.as_raw_fd())?;
    let profile_exec = duplicate_fd_for_exec(arm.profiles.as_raw_fd())?;
    let child_fd = child_protocol_exec.as_raw_fd();
    let cache_fd = cache_exec.as_raw_fd();
    let profile_fd = profile_exec.as_raw_fd();
    let parent_pid = unsafe { libc::getpid() };
    let mut command = Command::new(env::current_exe()?);
    let stderr = match diagnostics {
        Some(file) => Stdio::from(file.try_clone()?),
        None => Stdio::null(),
    };
    command
        .arg("--worker")
        .arg("--protocol-fd")
        .arg(PROTOCOL_FD.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    configure_worker_environment(&mut command, &capability_text, environment);
    unsafe {
        command.pre_exec(move || {
            libc::umask(0o077);
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                libc::_exit(125);
            }
            for (source, target) in [
                (child_fd, PROTOCOL_FD),
                (cache_fd, CACHE_FD),
                (profile_fd, PROFILE_FD),
            ] {
                if source == target {
                    if libc::fcntl(target, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                } else if libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().context("worker_spawn_failed")?;
    let deadline = Instant::now() + config.deadline;
    drop(child_protocol);
    let mut guard = ChildGuard::new(child);
    let request = WorkerRequestRef {
        protocol_version: PROTOCOL_VERSION,
        capability,
        phase,
        precision,
        cache_dir: "/proc/self/fd/4",
        profile_dir: "/proc/self/fd/5",
        threshold: config.threshold,
        configured_gpu_target: &config.configured_gpu_target,
        hsa_override: &config.hsa_override,
        environment,
        expected_provenance: expected,
        corpus_digest,
        corpus,
    };
    parent_protocol.set_nonblocking(true)?;
    let request = encode_frame(&request, MAX_PROTOCOL_BYTES)?;
    write_all_deadline(&mut parent_protocol, &request, deadline)?;
    parent_protocol.shutdown(std::net::Shutdown::Write)?;
    let output =
        read_frame_deadline::<WorkerOutput>(&mut parent_protocol, MAX_PROTOCOL_BYTES, deadline)?;
    require_eof_deadline(&mut parent_protocol, deadline)?;
    let status = guard.wait_until(deadline)?;
    if !status.success() {
        bail!("worker_failed");
    }
    if output.capability != capability {
        bail!("worker_output_capability_mismatch");
    }
    guard.success_finalize(deadline)?;
    Ok(output)
}

fn ensure_child_subreaper() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        return Err(std::io::Error::last_os_error()).context("child_subreaper_failed");
    }
    Ok(())
}

fn duplicate_fd_for_exec(fd: RawFd) -> Result<File> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error()).context("worker_fd_dup_failed");
    }
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

fn configure_worker_environment(
    command: &mut Command,
    capability: &str,
    environment: &EnvironmentAttestation,
) {
    command.env_clear().env("HOWY_FP16_CAPABILITY", capability);
    for (key, value) in &environment.set {
        command.env(key, value);
    }
    for key in &environment.cleared {
        command.env_remove(key);
    }
}

struct ChildGuard {
    child: Option<Child>,
    pgid: i32,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        let pgid = child.id() as i32;
        Self {
            child: Some(child),
            pgid,
        }
    }
    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().unwrap()
    }
    fn wait_until(&mut self, deadline: Instant) -> Result<ExitStatus> {
        loop {
            if Instant::now() >= deadline {
                self.terminate_and_reap();
                bail!("worker_deadline_exceeded");
            }
            if let Some(status) = self.child_mut().try_wait()? {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn signal_group(&self, signal: i32) {
        unsafe {
            libc::kill(-self.pgid, signal);
        }
    }
    fn reap_group_children(&self) {
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(-self.pgid, &mut status, libc::WNOHANG) };
            if result <= 0 {
                break;
            }
        }
    }
    fn group_exists(&self) -> bool {
        if unsafe { libc::kill(-self.pgid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    fn wait_group_gone(&self, deadline: Instant) -> bool {
        loop {
            self.reap_group_children();
            if !self.group_exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn success_finalize(&mut self, deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            bail!("worker_deadline_exceeded");
        }
        self.reap_group_children();
        if self.group_exists() {
            self.signal_group(libc::SIGTERM);
            let grace = (Instant::now() + Duration::from_millis(100)).min(deadline);
            if !self.wait_group_gone(grace) {
                self.signal_group(libc::SIGKILL);
                if !self.wait_group_gone(deadline) {
                    bail!("worker_process_group_survived_success");
                }
            }
        }
        if self.group_exists() {
            bail!("worker_process_group_survived_success");
        }
        self.child.take();
        Ok(())
    }
    fn terminate_and_reap(&mut self) {
        if self.child.is_none() {
            return;
        }
        self.signal_group(libc::SIGTERM);
        let grace = Instant::now() + Duration::from_millis(100);
        while Instant::now() < grace {
            if self.child_mut().try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.signal_group(libc::SIGKILL);
        let _ = self.child_mut().wait();
        let cleanup_deadline = Instant::now() + Duration::from_millis(500);
        let _ = self.wait_group_gone(cleanup_deadline);
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.terminate_and_reap();
            self.child.take();
        }
    }
}

fn reviewed_environment(precision: Precision, hsa: &str) -> Result<EnvironmentAttestation> {
    let mut set = BTreeMap::new();
    set.insert("PATH".into(), "/usr/bin:/bin".into());
    set.insert("LANG".into(), "C".into());
    set.insert("LC_ALL".into(), "C".into());
    set.insert("RUST_LOG".into(), "warn".into());
    set.insert("HSA_OVERRIDE_GFX_VERSION".into(), hsa.into());
    set.insert(
        "ORT_MIGRAPHX_FP16_ENABLE".into(),
        if precision.fp16() { "1" } else { "0" }.into(),
    );
    for key in [
        "ORT_MIGRAPHX_BF16_ENABLE",
        "ORT_MIGRAPHX_FP8_ENABLE",
        "ORT_MIGRAPHX_INT8_ENABLE",
        "ORT_MIGRAPHX_EXHAUSTIVE_TUNE",
        "ORT_MIGRAPHX_DUMP_MODEL",
    ] {
        set.insert(key.into(), "0".into());
    }
    let cache = "/proc/self/fd/4".to_string();
    set.insert("ORT_MIGRAPHX_MODEL_CACHE_PATH".into(), cache.clone());
    set.insert("ORT_MIGRAPHX_CACHE_PATH".into(), cache);
    Ok(EnvironmentAttestation {
        set,
        cleared: CLEARED_ENV
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    })
}

fn validate_actual_environment(expected: &EnvironmentAttestation) -> Result<()> {
    for (key, value) in &expected.set {
        if env::var_os(key).as_deref() != Some(std::ffi::OsStr::new(value)) {
            bail!("worker_environment_attestation_mismatch");
        }
    }
    if expected
        .cleared
        .iter()
        .any(|key| env::var_os(key).is_some())
    {
        bail!("worker_environment_clearance_mismatch");
    }
    let mut allowed = expected.set.keys().cloned().collect::<BTreeSet<_>>();
    allowed.insert("HOWY_FP16_CAPABILITY".into());
    if env::vars_os().any(|(key, _)| !allowed.contains(&key.to_string_lossy().to_string())) {
        bail!("worker_environment_not_hermetic");
    }
    Ok(())
}

fn pin_corpus(config: &ParentConfig, root: &ExperimentRoot) -> Result<PinnedCorpus> {
    let mut manifest_blob = secure_read_at(&root.fd, &config.manifest, MAX_MANIFEST_BYTES, true)?;
    let fixture_root = secure_directory_at(&root.fd, &config.fixture_dir)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_blob.bytes)?;
    manifest_blob.bytes.zeroize();
    if manifest.fixtures.is_empty() || manifest.fixtures.len() > MAX_FIXTURES {
        bail!("manifest_entry_limit");
    }
    let mut path_set = HashSet::new();
    let mut identity_set = HashSet::new();
    identity_set.insert(manifest_blob.identity);
    let mut digest_set = HashSet::new();
    digest_set.insert(manifest_blob.digest.clone());
    let mut total_bytes = 0usize;
    let mut total_pixels = 0u64;
    let mut fixtures = Vec::with_capacity(manifest.fixtures.len());
    for (index, entry) in manifest.fixtures.iter().enumerate() {
        validate_relative_path(&entry.path)?;
        if !path_set.insert(entry.path.clone()) {
            bail!("duplicate_fixture_path");
        }
        let mut blob = secure_read_at(
            &fixture_root,
            Path::new(&entry.path),
            MAX_FIXTURE_BYTES,
            true,
        )?;
        if !identity_set.insert(blob.identity) || !digest_set.insert(blob.digest.clone()) {
            bail!("duplicate_fixture_file_or_content");
        }
        total_bytes = total_bytes
            .checked_add(blob.bytes.len())
            .context("fixture_size_overflow")?;
        if total_bytes > MAX_TOTAL_FIXTURE_BYTES {
            bail!("fixture_total_byte_limit");
        }
        let (width, height) = inspect_image_dimensions(&blob.bytes)?;
        let pixels = u64::from(width) * u64::from(height);
        if pixels > MAX_PIXELS_PER_FIXTURE {
            bail!("fixture_pixel_limit");
        }
        total_pixels = total_pixels.checked_add(pixels).context("pixel_overflow")?;
        if total_pixels > MAX_TOTAL_PIXELS {
            bail!("fixture_total_pixel_limit");
        }
        fixtures.push(PinnedFixture {
            index,
            class: entry.class,
            digest: std::mem::take(&mut blob.digest),
            encoded: std::mem::take(&mut blob.bytes),
        });
    }
    let mut detector =
        secure_read_at(&root.fd, &config.detector_model, MAX_ONNX_MODEL_BYTES, true)?;
    let mut recognizer = secure_read_at(
        &root.fd,
        &config.recognizer_model,
        MAX_ONNX_MODEL_BYTES,
        true,
    )?;
    if detector.bytes.len() + recognizer.bytes.len() > MAX_TOTAL_ONNX_BYTES {
        bail!("onnx_total_byte_limit");
    }
    if detector.identity == recognizer.identity || detector.digest == recognizer.digest {
        bail!("duplicate_onnx_models");
    }
    if !identity_set.insert(detector.identity) || !identity_set.insert(recognizer.identity) {
        bail!("input_file_alias");
    }
    if !digest_set.insert(detector.digest.clone()) || !digest_set.insert(recognizer.digest.clone())
    {
        bail!("input_content_alias");
    }
    let enrolled_model = config
        .enrolled_model
        .as_ref()
        .map(|path| {
            let mut blob = secure_read_at(&root.fd, path, MAX_ENROLLED_MODEL_BYTES, true)?;
            if !identity_set.insert(blob.identity) {
                bail!("duplicate_sensitive_file");
            }
            if !digest_set.insert(blob.digest.clone()) {
                bail!("duplicate_sensitive_content");
            }
            parse_and_validate_enrolled_model(&blob.bytes)?;
            Ok::<_, anyhow::Error>(std::mem::take(&mut blob.bytes))
        })
        .transpose()?;
    Ok(PinnedCorpus {
        detector_digest: std::mem::take(&mut detector.digest),
        detector_model: std::mem::take(&mut detector.bytes),
        recognizer_digest: std::mem::take(&mut recognizer.digest),
        recognizer_model: std::mem::take(&mut recognizer.bytes),
        enrolled_model,
        fixtures,
    })
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn openat2_file(dirfd: RawFd, path: &Path, flags: i32, mode: u32) -> Result<File> {
    openat2_file_resolve(dirfd, path, flags, mode, RESOLVE_FLAGS)
}

fn openat2_file_resolve(
    dirfd: RawFd,
    path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> Result<File> {
    validate_relative_os_path(path)?;
    let path = CString::new(path.as_os_str().as_bytes()).context("path_contains_nul")?;
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("openat2_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_experiment_root(path: &Path, repo: &Path) -> Result<ExperimentRoot> {
    if !path.is_absolute() {
        bail!("experiment_root_must_be_absolute");
    }
    let relative = path
        .strip_prefix(Path::new("/"))
        .context("experiment_root_invalid")?;
    validate_relative_os_path(relative)?;
    let slash = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let fd = openat2_file(
        slash.as_raw_fd(),
        relative,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = fd.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("insecure_experiment_root");
    }
    let normalized = Path::new("/").join(relative);
    if normalized.starts_with(repo) {
        bail!("repository_path_rejected");
    }
    Ok(ExperimentRoot { fd })
}

fn secure_read_at(
    parent: &File,
    path: &Path,
    max_bytes: usize,
    private: bool,
) -> Result<SecureBlob> {
    let mut file = openat2_file(
        parent.as_raw_fd(),
        path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("input_not_regular");
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("input_owner_mismatch");
    }
    if private && !matches!(metadata.mode() & 0o7777, 0o400 | 0o600) {
        bail!("private_input_mode_too_open");
    }
    let size = usize::try_from(metadata.len()).context("input_size_overflow")?;
    if size == 0 || size > max_bytes {
        bail!("input_size_limit");
    }
    let mut bytes = Vec::with_capacity(size);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != size {
        bail!("input_size_changed");
    }
    let after = file.metadata()?;
    if metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
        || metadata.ctime() != after.ctime()
        || metadata.ctime_nsec() != after.ctime_nsec()
    {
        bail!("input_changed_during_read");
    }
    Ok(SecureBlob {
        digest: digest_hex(&bytes),
        bytes,
        identity: (metadata.dev(), metadata.ino()),
    })
}

fn secure_directory_at(parent: &File, path: &Path) -> Result<File> {
    let fd = openat2_file(
        parent.as_raw_fd(),
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    let metadata = fd.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("insecure_directory");
    }
    Ok(fd)
}

fn validate_relative_path(value: &str) -> Result<()> {
    validate_relative_os_path(Path::new(value))
}

fn validate_relative_os_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.to_str().is_none()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe_relative_path");
    }
    Ok(())
}

fn repository_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("repository_root_missing")?
        .canonicalize()
        .map_err(Into::into)
}

fn create_experiment_layout(root: &ExperimentRoot, pairs: usize) -> Result<ExperimentLayout> {
    let run_name = format!("run-{}", hex::encode(random_bytes::<16>()?));
    let run = mkdir_open_at(&root.fd, &run_name)?;
    let mut layouts = Vec::with_capacity(pairs);
    for pair in 0..pairs {
        let pair_dir = mkdir_open_at(&run, &format!("pair-{pair:02}"))?;
        layouts.push(PairLayout {
            fp32: create_arm_layout(&pair_dir, Precision::Fp32)?,
            fp16: create_arm_layout(&pair_dir, Precision::Fp16)?,
        });
    }
    Ok(ExperimentLayout {
        root: root.fd.try_clone()?,
        run_name,
        pairs: layouts,
    })
}

fn create_arm_layout(parent: &File, precision: Precision) -> Result<ArmLayout> {
    let arm = mkdir_open_at(parent, precision.name())?;
    let cache = mkdir_open_at(&arm, "cache")?;
    let profiles = mkdir_open_at(&arm, "profiles")?;
    let lock = openat2_file(
        cache.as_raw_fd(),
        Path::new(".exclusive.lock"),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("cache_lock_unavailable");
    }
    Ok(ArmLayout {
        cache,
        profiles,
        _lock: lock,
    })
}

fn mkdir_open_at(parent: &File, name: &str) -> Result<File> {
    let name = CString::new(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error()).context("mkdirat_failed");
    }
    openat2_file(
        parent.as_raw_fd(),
        Path::new(OsStr::from_bytes(name.as_bytes())),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
}

fn arm_layout(pair: &PairLayout, precision: Precision) -> &ArmLayout {
    match precision {
        Precision::Fp32 => &pair.fp32,
        Precision::Fp16 => &pair.fp16,
    }
}

fn list_directory_names(fd: RawFd) -> Result<Vec<OsString>> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error()).context("directory_dup_failed");
    }
    if unsafe { libc::lseek(duplicate, 0, libc::SEEK_SET) } < 0 {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error()).context("directory_rewind_failed");
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error()).context("fdopendir_failed");
    }
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(error).context("readdir_failed");
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            if names.len() == MAX_DIRECTORY_ENTRIES {
                unsafe { libc::closedir(directory) };
                bail!("directory_entry_limit");
            }
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    names.sort();
    Ok(names)
}

fn statat_nofollow(fd: RawFd, name: &OsStr) -> Result<libc::stat> {
    let name = CString::new(name.as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("fstatat_failed");
    }
    Ok(unsafe { stat.assume_init() })
}

fn inventory_cache(cache: &File) -> Result<Vec<CacheArtifact>> {
    fn walk(fd: RawFd, prefix: &str, depth: usize, output: &mut Vec<CacheArtifact>) -> Result<()> {
        if depth > MAX_CACHE_DIRECTORY_DEPTH {
            bail!("cache_directory_depth_limit");
        }
        for name in list_directory_names(fd)? {
            let name_text = name.to_str().context("cache_name_non_utf8")?;
            if prefix.is_empty() && matches!(name_text, ".exclusive.lock" | "provenance.json") {
                continue;
            }
            let relative = if prefix.is_empty() {
                name_text.to_owned()
            } else {
                format!("{prefix}/{name_text}")
            };
            let stat = statat_nofollow(fd, &name)?;
            let kind = stat.st_mode & libc::S_IFMT;
            if kind == libc::S_IFDIR {
                let directory = openat2_file(
                    fd,
                    Path::new(&name),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                )?;
                let metadata = directory.metadata()?;
                if !metadata.is_dir()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o7777 != 0o700
                {
                    bail!("cache_directory_not_private");
                }
                walk(directory.as_raw_fd(), &relative, depth + 1, output)?;
            } else if kind == libc::S_IFREG {
                if output.len() == MAX_CACHE_ARTIFACTS {
                    bail!("cache_artifact_limit");
                }
                let mut file = openat2_file(
                    fd,
                    Path::new(&name),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0,
                )?;
                let before = file.metadata()?;
                if !before.is_file()
                    || before.uid() != unsafe { libc::geteuid() }
                    || before.mode() & 0o077 != 0
                {
                    bail!("cache_artifact_not_private");
                }
                let before_stamp = ArtifactStamp::from_metadata(&before);
                let (sha256, size) = digest_reader(&mut file, MAX_CACHE_ARTIFACT_BYTES)?;
                let after_stamp = ArtifactStamp::from_metadata(&file.metadata()?);
                verify_hash_coherence(&before_stamp, &after_stamp, size)?;
                output.push(CacheArtifact {
                    relative_name: relative,
                    size,
                    sha256,
                    device: before_stamp.device,
                    inode: before_stamp.inode,
                    mode: before.mode() & 0o7777,
                    mtime: before_stamp.mtime,
                    mtime_nsec: before_stamp.mtime_nsec,
                    ctime: before_stamp.ctime,
                    ctime_nsec: before_stamp.ctime_nsec,
                });
            } else {
                bail!("cache_non_regular_artifact");
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    walk(cache.as_raw_fd(), "", 0, &mut output)?;
    output.sort();
    if output
        .iter()
        .try_fold(0u64, |total, artifact| total.checked_add(artifact.size))
        .context("cache_total_size_overflow")?
        > MAX_TOTAL_CACHE_BYTES
    {
        bail!("cache_total_size_limit");
    }
    if !output
        .iter()
        .any(|artifact| artifact.relative_name.ends_with(".mxr"))
    {
        bail!("cache_mxr_inventory_empty");
    }
    Ok(output)
}

fn verify_cache_inventory(cache: &File, expected: &[CacheArtifact]) -> Result<()> {
    if inventory_cache(cache)? != expected {
        bail!("cache_artifact_inventory_changed");
    }
    Ok(())
}

fn verify_hash_coherence(
    before: &ArtifactStamp,
    after: &ArtifactStamp,
    bytes_read: u64,
) -> Result<()> {
    if before != after || before.length != bytes_read {
        bail!("artifact_changed_during_hash");
    }
    Ok(())
}

fn make_cache_artifacts_read_only(
    cache: &File,
    generated: &[CacheArtifact],
) -> Result<Vec<CacheArtifact>> {
    verify_cache_inventory(cache, generated)?;
    for artifact in generated {
        let file = openat2_file(
            cache.as_raw_fd(),
            Path::new(&artifact.relative_name),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )?;
        let metadata = file.metadata()?;
        let stamp = ArtifactStamp::from_metadata(&metadata);
        if stamp.device != artifact.device
            || stamp.inode != artifact.inode
            || stamp.length != artifact.size
            || stamp.mtime != artifact.mtime
            || stamp.mtime_nsec != artifact.mtime_nsec
            || stamp.ctime != artifact.ctime
            || stamp.ctime_nsec != artifact.ctime_nsec
        {
            bail!("cache_artifact_changed_before_read_only");
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } != 0 {
            return Err(std::io::Error::last_os_error()).context("cache_artifact_read_only_failed");
        }
    }
    let readonly = inventory_cache(cache)?;
    if readonly.len() != generated.len() {
        bail!("cache_artifact_read_only_inventory_changed");
    }
    for (before, after) in generated.iter().zip(&readonly) {
        if before.relative_name != after.relative_name
            || before.size != after.size
            || before.sha256 != after.sha256
            || before.device != after.device
            || before.inode != after.inode
            || before.mtime != after.mtime
            || before.mtime_nsec != after.mtime_nsec
            || after.mode != 0o400
        {
            bail!("cache_artifact_read_only_mismatch");
        }
    }
    Ok(readonly)
}

fn digest_reader(reader: &mut File, maximum: usize) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).context("digest_size_overflow")?;
        if total > maximum {
            bail!("digest_size_limit");
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), total as u64))
}

fn remove_tree_at(parent: RawFd, name: &str) -> Result<()> {
    remove_tree_at_depth(parent, name, 0)
}

fn remove_tree_at_depth(parent: RawFd, name: &str, depth: usize) -> Result<()> {
    if depth > MAX_CACHE_DIRECTORY_DEPTH + 4 {
        bail!("cleanup_directory_depth_limit");
    }
    let directory = openat2_file(
        parent,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    for child in list_directory_names(directory.as_raw_fd())? {
        let stat = statat_nofollow(directory.as_raw_fd(), &child)?;
        let child_name = child.to_str().context("cleanup_name_non_utf8")?;
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            remove_tree_at_depth(directory.as_raw_fd(), child_name, depth + 1)?;
        } else {
            let child = CString::new(child.as_bytes())?;
            if unsafe { libc::unlinkat(directory.as_raw_fd(), child.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error()).context("cleanup_unlinkat_failed");
            }
        }
    }
    drop(directory);
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cleanup_rmdir_failed");
    }
    Ok(())
}

fn corpus_digest(corpus: &PinnedCorpus) -> Result<String> {
    let mut hasher = Sha256::new();
    fn add(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    add(&mut hasher, corpus.detector_digest.as_bytes());
    add(&mut hasher, &corpus.detector_model);
    add(&mut hasher, corpus.recognizer_digest.as_bytes());
    add(&mut hasher, &corpus.recognizer_model);
    match corpus.enrolled_model.as_ref() {
        Some(model) => {
            hasher.update([1]);
            add(&mut hasher, model);
        }
        None => hasher.update([0]),
    }
    hasher.update((corpus.fixtures.len() as u64).to_le_bytes());
    for fixture in &corpus.fixtures {
        hasher.update((fixture.index as u64).to_le_bytes());
        hasher.update([match fixture.class {
            FixtureClass::Positive => 1,
            FixtureClass::Negative => 2,
        }]);
        add(&mut hasher, fixture.digest.as_bytes());
        add(&mut hasher, &fixture.encoded);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verify_corpus_digest(expected: &str, actual: &str) -> Result<()> {
    if expected.len() != 64 || actual.len() != 64 || expected != actual {
        bail!("corpus_digest_mismatch");
    }
    Ok(())
}

fn inspect_provider_stack() -> Result<ProviderStackProvenance> {
    let mut maps_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/proc/self/maps")?;
    let mut maps = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut maps_file)
        .take((MAX_PROC_MAPS_BYTES + 1) as u64)
        .read_to_end(&mut maps)?;
    if maps.len() > MAX_PROC_MAPS_BYTES {
        bail!("provider_maps_size_limit");
    }
    let maps = std::str::from_utf8(&maps).context("provider_maps_non_utf8")?;
    let mut paths = BTreeSet::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let path = Path::new(path);
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .context("provider_library_name_invalid")?;
        if is_provider_stack_library(name) {
            if line.ends_with(" (deleted)") {
                bail!("provider_library_deleted");
            }
            paths.insert(path.to_path_buf());
        }
    }
    if paths.len() > MAX_RUNTIME_LIBRARIES {
        bail!("provider_library_count_limit");
    }
    let mut libraries = Vec::with_capacity(paths.len());
    for path in paths {
        libraries.push(hash_trusted_runtime_library(&path)?);
    }
    libraries.sort_by(|left, right| left.path.cmp(&right.path));
    let names = libraries
        .iter()
        .map(|library| library.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let provenance = ProviderStackProvenance {
        has_ort_core: names
            .iter()
            .any(|name| name.starts_with("libonnxruntime.so") && !name.contains("providers")),
        has_ort_migraphx_provider: names
            .iter()
            .any(|name| name.contains("onnxruntime_providers_migraphx")),
        has_migraphx: names.iter().any(|name| name.starts_with("libmigraphx")),
        has_hip: names.iter().any(|name| name.starts_with("libamdhip64")),
        has_rocm_runtime: names
            .iter()
            .any(|name| name.starts_with("libhsa-runtime64")),
        libraries,
    };
    validate_provider_stack(&provenance)?;
    Ok(provenance)
}

fn is_provider_stack_library(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("onnxruntime")
        || name.starts_with("libmigraphx")
        || name.starts_with("libamdhip64")
        || name.starts_with("libhsa-runtime64")
        || name.starts_with("librocblas")
        || name.starts_with("libmiopen")
        || name.starts_with("libhiprtc")
        || name.starts_with("librocsolver")
        || name.starts_with("librocrand")
        || name.starts_with("librocfft")
}

fn validate_provider_stack(provenance: &ProviderStackProvenance) -> Result<()> {
    if provenance.libraries.is_empty()
        || !provenance.has_ort_core
        || !provenance.has_ort_migraphx_provider
        || !provenance.has_migraphx
        || !provenance.has_hip
        || !provenance.has_rocm_runtime
    {
        bail!("provider_stack_incomplete");
    }
    Ok(())
}

fn verify_provider_stack_match(
    expected: &ProviderStackProvenance,
    actual: &ProviderStackProvenance,
) -> Result<()> {
    validate_provider_stack(expected)?;
    validate_provider_stack(actual)?;
    if expected != actual {
        bail!("provider_stack_mismatch");
    }
    Ok(())
}

fn hash_trusted_runtime_library(path: &Path) -> Result<RuntimeLibraryDigest> {
    if !path.is_absolute()
        || !(path.starts_with("/usr/lib")
            || path.starts_with("/usr/local/lib")
            || path.starts_with("/lib")
            || path.starts_with("/opt/rocm"))
    {
        bail!("runtime_library_path_not_trusted");
    }
    let slash = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    let relative = path.strip_prefix("/")?;
    let mut file = openat2_file_resolve(
        slash.as_raw_fd(),
        relative,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
        RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("runtime_library_not_trusted");
    }
    let before = ArtifactStamp::from_metadata(&metadata);
    let (sha256, size) = digest_reader(&mut file, 1024 * 1024 * 1024)?;
    let after = ArtifactStamp::from_metadata(&file.metadata()?);
    verify_hash_coherence(&before, &after, size)?;
    Ok(RuntimeLibraryDigest {
        name: path
            .file_name()
            .context("runtime_library_name_missing")?
            .to_string_lossy()
            .into(),
        path: path.to_string_lossy().into_owned(),
        sha256,
        size,
    })
}

fn write_cache_provenance(cache: &File, manifest: &CacheManifest) -> Result<()> {
    write_atomic_at(
        cache,
        Path::new("provenance.json"),
        &serde_json::to_vec(manifest)?,
    )
}

fn verify_cache_provenance(cache: &File, expected: &CacheManifest) -> Result<()> {
    let bytes = secure_read_at(cache, Path::new("provenance.json"), 1024 * 1024, true)?;
    let actual: CacheManifest = serde_json::from_slice(&bytes.bytes)?;
    if &actual != expected {
        bail!("cache_provenance_mismatch");
    }
    Ok(())
}

fn write_atomic_at(root: &File, path: &Path, bytes: &[u8]) -> Result<()> {
    let (parent, name) = open_output_parent(root, path)?;
    let temporary = format!(".tmp-{}", hex::encode(random_bytes::<16>()?));
    let mut file = openat2_file(
        parent.as_raw_fd(),
        Path::new(&temporary),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    )?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = unlink_file_at(parent.as_raw_fd(), &temporary);
        return Err(error.into());
    }
    drop(file);
    let temporary = CString::new(temporary)?;
    let name = CString::new(name.as_bytes())?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            temporary.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) };
        return Err(error).context("atomic_output_create_failed");
    }
    Ok(())
}

fn open_output_parent(root: &File, path: &Path) -> Result<(File, OsString)> {
    validate_relative_os_path(path)?;
    let name = path
        .file_name()
        .context("output_name_missing")?
        .to_os_string();
    let parent = path.parent().context("output_parent_missing")?;
    let parent = if parent.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        secure_directory_at(root, parent)?
    };
    Ok((parent, name))
}

fn unlink_file_at(parent: RawFd, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("unlinkat_failed");
    }
    Ok(())
}

fn inspect_image_dimensions(bytes: &[u8]) -> Result<(u32, u32)> {
    let reader = ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    let (width, height) = reader.into_dimensions()?;
    validate_pixels(width, height)?;
    Ok((width, height))
}

struct ZeroizingDynamicImage(image::DynamicImage);

impl Zeroize for ZeroizingDynamicImage {
    fn zeroize(&mut self) {
        use image::DynamicImage::*;
        match &mut self.0 {
            ImageLuma8(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageLumaA8(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgb8(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgba8(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageLuma16(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageLumaA16(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgb16(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgba16(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgb32F(image) => image.as_flat_samples_mut().samples.zeroize(),
            ImageRgba32F(image) => image.as_flat_samples_mut().samples.zeroize(),
            _ => {}
        }
    }
}

impl Drop for ZeroizingDynamicImage {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingDynamicImage {}

struct ZeroizingRgbImage(Option<image::RgbImage>);

impl ZeroizingRgbImage {
    fn dimensions(&self) -> Result<(u32, u32)> {
        Ok(self.0.as_ref().context("rgb_image_missing")?.dimensions())
    }

    fn into_raw(mut self) -> Result<Vec<u8>> {
        Ok(self.0.take().context("rgb_image_missing")?.into_raw())
    }
}

impl Zeroize for ZeroizingRgbImage {
    fn zeroize(&mut self) {
        if let Some(mut image) = self.0.take() {
            image.as_flat_samples_mut().samples.zeroize();
        }
    }
}

impl Drop for ZeroizingRgbImage {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingRgbImage {}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureEnrolledModels {
    username: Zeroizing<String>,
    labels: Zeroizing<Vec<Zeroizing<String>>>,
    flat_embeddings: Zeroizing<Vec<f32>>,
    #[zeroize(skip)]
    count: usize,
}

struct ModelReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ModelReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .context("model_length_overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("model_truncated")?;
        self.offset = end;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bounded_len(&mut self, maximum: usize) -> Result<usize> {
        let value = usize::try_from(self.u64()?).context("model_length_overflow")?;
        if value > maximum {
            bail!("model_collection_limit");
        }
        Ok(value)
    }
    fn string(&mut self, maximum: usize) -> Result<Zeroizing<String>> {
        let length = self.bounded_len(maximum)?;
        Ok(Zeroizing::new(
            std::str::from_utf8(self.take(length)?)?.to_owned(),
        ))
    }
}

fn parse_and_validate_enrolled_model(bytes: &[u8]) -> Result<SecureEnrolledModels> {
    let mut reader = ModelReader { bytes, offset: 0 };
    let username = reader.string(MAX_USERNAME_BYTES)?;
    let count = reader.bounded_len(MAX_ENROLLED_MODELS)?;
    if count == 0 {
        bail!("enrolled_model_empty");
    }
    let mut labels = Zeroizing::new(Vec::with_capacity(count));
    let mut flat_embeddings = Zeroizing::new(Vec::with_capacity(count * FACE_EMBEDDING_DIM));
    for _ in 0..count {
        labels.push(reader.string(MAX_LABEL_BYTES)?);
        let _created = reader.u64()?;
        let embedding_count = reader.bounded_len(FACE_EMBEDDING_DIM)?;
        if embedding_count != FACE_EMBEDDING_DIM {
            bail!("invalid_embedding_length");
        }
        let start = flat_embeddings.len();
        for _ in 0..FACE_EMBEDDING_DIM {
            flat_embeddings.push(f32::from_le_bytes(reader.take(4)?.try_into().unwrap()));
        }
        validate_normalized_embedding(&flat_embeddings[start..])?;
    }
    if reader.offset != bytes.len() {
        bail!("model_trailing_data");
    }
    Ok(SecureEnrolledModels {
        username,
        labels,
        flat_embeddings,
        count,
    })
}

fn validate_normalized_embedding(embedding: &[f32]) -> Result<()> {
    if embedding.len() != FACE_EMBEDDING_DIM || embedding.iter().any(|value| !value.is_finite()) {
        bail!("invalid_embedding");
    }
    let norm = embedding
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt();
    if (norm - 1.0).abs() > EMBEDDING_NORM_TOLERANCE {
        bail!("embedding_not_normalized");
    }
    Ok(())
}

fn parse_profile(path: &Path, profile_fd: RawFd) -> Result<PlacementFacts> {
    if path.parent() != Some(Path::new("/proc/self/fd/5")) {
        bail!("profile_path_escaped");
    }
    let name = path.file_name().context("profile_name_missing")?;
    let mut file = openat2_file(
        profile_fd,
        Path::new(name),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )?;
    let metadata = file.metadata()?;
    let size = usize::try_from(metadata.len()).context("profile_size_overflow")?;
    if !metadata.is_file() || size == 0 || size > MAX_PROFILE_BYTES {
        bail!("profile_size_limit");
    }
    let mut bytes = Vec::with_capacity(size);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != size {
        bail!("profile_size_changed");
    }
    parse_profile_json(&bytes)
}

fn parse_profile_json(bytes: &[u8]) -> Result<PlacementFacts> {
    struct ProfileEvents(Vec<Value>);
    impl<'de> Deserialize<'de> for ProfileEvents {
        fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = ProfileEvents;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a bounded ORT profile event array")
                }
                fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut events = Vec::new();
                    while let Some(event) = sequence.next_element()? {
                        if events.len() == MAX_PROFILE_EVENTS {
                            return Err(serde::de::Error::custom("profile_event_limit"));
                        }
                        events.push(event);
                    }
                    Ok(ProfileEvents(events))
                }
            }
            deserializer.deserialize_seq(Visitor)
        }
    }
    let events = serde_json::from_slice::<ProfileEvents>(bytes)
        .context("profile_json_invalid")?
        .0;
    let mut facts = PlacementFacts::default();
    for event in events {
        if event.get("cat").and_then(Value::as_str) != Some("Node") {
            continue;
        }
        if event.get("ph").and_then(Value::as_str) != Some("X")
            || event.get("dur").and_then(Value::as_f64).is_none()
        {
            bail!("profile_node_event_incomplete");
        }
        let provider = event
            .get("args")
            .and_then(|args| args.get("provider"))
            .and_then(Value::as_str)
            .context("profile_provider_missing")?;
        let name = event
            .get("name")
            .and_then(Value::as_str)
            .context("profile_node_identity_missing")?;
        let operation = event
            .get("args")
            .and_then(|args| args.get("op_name"))
            .and_then(Value::as_str)
            .context("profile_operation_identity_missing")?;
        if provider.len() > 128 || name.len() > 1024 || operation.len() > 128 {
            bail!("profile_identity_string_limit");
        }
        let node_index = event
            .get("args")
            .and_then(|args| args.get("node_index"))
            .map(|value| {
                value
                    .as_u64()
                    .map(|value| value.to_string())
                    .or_else(|| value.as_str().map(str::to_owned))
            })
            .flatten()
            .context("profile_node_index_missing")?;
        if node_index.len() > 32 || !node_index.chars().all(|value| value.is_ascii_digit()) {
            bail!("profile_node_index_invalid");
        }
        facts.providers.insert(provider.to_string());
        let identity = format!("{node_index}|{name}|{operation}");
        if !facts.nodes.contains_key(&identity) && facts.nodes.len() == MAX_PROFILE_NODES {
            bail!("profile_node_limit");
        }
        let node = facts
            .nodes
            .entry(identity)
            .or_insert_with(|| PlacementNode {
                provider: provider.to_string(),
                invocation_count: 0,
            });
        if node.provider != provider {
            bail!("profile_identity_provider_changed");
        }
        node.invocation_count += 1;
        if provider == "MIGraphXExecutionProvider" {
            facts.migraphx_events += 1;
        } else if provider == "CPUExecutionProvider" {
            facts.cpu_events += 1;
        } else {
            facts.unknown_events += 1;
        }
    }
    facts.mode = if facts.migraphx_events == 0 || facts.unknown_events > 0 {
        PlacementMode::Invalid
    } else if facts.cpu_events > 0 {
        PlacementMode::Mixed
    } else {
        PlacementMode::AllMigraphx
    };
    Ok(facts)
}

fn validate_worker_output(
    output: &WorkerOutput,
    precision: Precision,
    phase: WorkerPhase,
    records: usize,
    threshold: f32,
    corpus_digest: &str,
) -> Result<()> {
    if output.protocol_version != PROTOCOL_VERSION
        || output.precision != precision
        || output.phase != phase
        || output.records.len() != records
        || output.registered_preference != "migraphx"
        || verify_corpus_digest(corpus_digest, &output.corpus_digest).is_err()
    {
        bail!("worker_output_contract_mismatch");
    }
    validate_record_indices(&output.records)?;
    for record in &output.records {
        if [
            record.decode_ms,
            record.detector_pipeline_ms,
            record.recognizer_pipeline_ms,
            record.enrolled_matching_ms,
            record.complete_fixture_ms,
        ]
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
            || record.faces.len() > MAX_FACES_PER_FIXTURE
        {
            bail!("worker_record_numeric_invalid");
        }
        for face in &record.faces {
            if !face.detector_score.is_finite()
                || face.landmarks.iter().any(|value| !value.is_finite())
            {
                bail!("worker_face_numeric_invalid");
            }
            validate_normalized_embedding(&face.embedding)?;
            match (face.enrolled_score, face.decision) {
                (Some(score), Some(decision))
                    if score.is_finite() && decision == (score >= threshold) => {}
                (None, None) => {}
                _ => bail!("worker_decision_invalid"),
            }
        }
    }
    Ok(())
}

fn validate_record_indices(records: &[ImageRecord]) -> Result<()> {
    if records
        .iter()
        .enumerate()
        .any(|(index, record)| record.index != index)
    {
        bail!("worker_record_order_mismatch");
    }
    Ok(())
}

fn verify_output_provenance(
    output: &WorkerOutput,
    config: &ParentConfig,
    corpus: &PinnedCorpus,
    precision: Precision,
    environment: &EnvironmentAttestation,
) -> Result<()> {
    let provenance = &output.provenance;
    let expected_corpus_digest = corpus_digest(corpus)?;
    if provenance.precision != precision
        || provenance.detector_digest != corpus.detector_digest
        || provenance.recognizer_digest != corpus.recognizer_digest
        || provenance.ort_crate_version != ORT_CRATE_VERSION
        || provenance.ort_api_version != ort::MINOR_VERSION
        || provenance.ort_runtime_version.is_empty()
        || provenance.configured_gpu_target != config.configured_gpu_target
        || provenance.hsa_override != config.hsa_override
        || provenance.recognition_threshold_bits != config.threshold.to_bits()
        || provenance.inference_threads != HowyConfig::default().ml.threads
        || provenance.provider_name != "migraphx"
        || provenance.graph_optimization_level != "level2"
        || provenance.provider_api_fp16 != precision.fp16()
        || provenance.provider_api_fp8
        || provenance.provider_api_int8
        || provenance.provider_api_exhaustive_tune
        || &provenance.environment != environment
        || verify_corpus_digest(&expected_corpus_digest, &provenance.corpus_digest).is_err()
        || verify_corpus_digest(&expected_corpus_digest, &output.corpus_digest).is_err()
        || validate_provider_stack(&provenance.provider_stack).is_err()
    {
        bail!("worker_provenance_invalid");
    }
    Ok(())
}

fn build_report(
    config: &ParentConfig,
    corpus: &PinnedCorpus,
    outputs: &[PairOutputs],
    generation_ms: Vec<f64>,
    measurement_ms: Vec<f64>,
    run_id: &str,
) -> Result<(Report, bool)> {
    let mut ious = Vec::new();
    let mut score_drifts = Vec::new();
    let mut landmark_errors = Vec::new();
    let mut embedding_cosines = Vec::new();
    let mut enrolled_drifts = Vec::new();
    let mut deltas = Vec::new();
    let mut matching_ms = Vec::new();
    let mut fp32_records = Vec::new();
    let mut fp16_records = Vec::new();
    let mut placement = Vec::new();
    let mut matched_faces = 0usize;
    let mut unmatched_faces = 0usize;
    let mut flips = 0usize;
    let decisions_evaluated = corpus.enrolled_model.is_some();

    for (pair_index, pair) in outputs.iter().enumerate() {
        let fp32 = pair.fp32.as_ref().context("fp32_output_missing")?;
        let fp16 = pair.fp16.as_ref().context("fp16_output_missing")?;
        validate_placement_pair(config.allow_mixed, fp32, fp16)?;
        placement.push(public_pair_placement(pair_index, fp32, fp16));
        for (expected_index, (left, right)) in fp32.records.iter().zip(&fp16.records).enumerate() {
            if left.index != expected_index
                || right.index != expected_index
                || left.class != corpus.fixtures[expected_index].class
                || right.class != left.class
            {
                bail!("record_pairing_mismatch");
            }
            deltas.push(right.complete_fixture_ms - left.complete_fixture_ms);
            let matching_started = Instant::now();
            let pairs =
                global_face_assignment(&left.faces, &right.faces, config.gates.min_face_iou);
            unmatched_faces += left.faces.len() + right.faces.len() - pairs.len() * 2;
            for (left_index, right_index, iou) in pairs {
                matched_faces += 1;
                let left_face = &left.faces[left_index];
                let right_face = &right.faces[right_index];
                ious.push(iou);
                score_drifts.push(
                    (f64::from(left_face.detector_score) - f64::from(right_face.detector_score))
                        .abs(),
                );
                landmark_errors.push(landmark_point_rmse(
                    &left_face.landmarks,
                    &right_face.landmarks,
                ));
                embedding_cosines.push(embedding_cosine(
                    &left_face.embedding,
                    &right_face.embedding,
                )?);
                match (left_face.enrolled_score, right_face.enrolled_score) {
                    (Some(left), Some(right)) => {
                        enrolled_drifts.push((f64::from(left) - f64::from(right)).abs());
                        if left_face.decision != right_face.decision {
                            flips += 1;
                        }
                    }
                    (None, None) if !decisions_evaluated => {}
                    _ => bail!("decision_evaluation_mismatch"),
                }
            }
            matching_ms.push(elapsed_ms(matching_started.elapsed()));
        }
        fp32_records.extend(fp32.records.iter().cloned());
        fp16_records.extend(fp16.records.iter().cloned());
    }
    let metrics = MetricReport {
        box_iou: distribution(&ious),
        detector_score_abs_drift: distribution(&score_drifts),
        landmark_point_rmse_pixels: distribution(&landmark_errors),
        embedding_cosine: distribution(&embedding_cosines),
        enrolled_score_abs_drift: distribution(&enrolled_drifts),
        matched_faces,
        unmatched_faces,
        threshold_flips: flips,
        decision_testing_evaluated: decisions_evaluated,
    };
    let gates = gate_report(config.gates, &metrics);
    let required = gates.face_iou.passed
        && gates.detector_score_drift.passed
        && gates.landmark_rmse.passed
        && gates.embedding_cosine.passed
        && gates.unmatched_faces.passed
        && gates.enrolled_score_drift.passed.unwrap_or(true)
        && gates.threshold_flips.passed.unwrap_or(true);
    let mut controls = BTreeMap::new();
    controls.insert("fp32".into(), "provider_api=false,environment=0".into());
    controls.insert("fp16".into(), "provider_api=true,environment=1".into());
    controls.insert("bf16_fp8_int8_exhaustive_dump".into(), "disabled".into());
    Ok((
        Report {
            protocol_version: PROTOCOL_VERSION,
            run_id: run_id.to_owned(),
            evidence_scope: "paired numerical drift only; not FAR/FRR evidence",
            fixture_count: corpus.fixtures.len(),
            pair_count: outputs.len(),
            placement_policy: if config.allow_mixed {
                "mixed_allowed"
            } else {
                "all_migraphx_required"
            },
            provenance: PublicProvenance {
                configured_gpu_target: config.configured_gpu_target.clone(),
                hsa_override: config.hsa_override.clone(),
                hsa_override_source: "configured_cli_value_not_queried_hardware_identity",
                provider_provenance_match: true,
                precision_controls: controls,
                isolated_arm_caches: true,
            },
            placement,
            gates,
            metrics,
            fp32_timings: timing_report(&fp32_records),
            fp16_timings: timing_report(&fp16_records),
            paired_complete_fixture_delta_ms: distribution(&deltas),
            parent_matching_and_comparison_ms: distribution(&matching_ms),
            process_order: (0..outputs.len())
                .map(|index| pair_order(index).to_vec())
                .collect(),
            cache_generation_process_ms: distribution(&generation_ms),
            loaded_cache_measurement_process_ms: distribution(&measurement_ms),
            cache_artifact_unchanged: true,
            all_required_gates_passed: required,
        },
        required,
    ))
}

fn validate_placement_pair(
    allow_mixed: bool,
    fp32: &WorkerOutput,
    fp16: &WorkerOutput,
) -> Result<()> {
    for facts in [
        &fp32.detector_placement,
        &fp32.recognizer_placement,
        &fp16.detector_placement,
        &fp16.recognizer_placement,
    ] {
        if !placement_allowed(facts, allow_mixed) {
            bail!("placement_policy_rejected");
        }
    }
    for (left, right) in [
        (&fp32.detector_placement, &fp16.detector_placement),
        (&fp32.recognizer_placement, &fp16.recognizer_placement),
    ] {
        if !placement_facts_comparable(left, right) {
            bail!("placement_not_comparable");
        }
    }
    Ok(())
}

fn placement_facts_comparable(left: &PlacementFacts, right: &PlacementFacts) -> bool {
    left.nodes == right.nodes
}

fn placement_allowed(facts: &PlacementFacts, allow_mixed: bool) -> bool {
    facts.mode == PlacementMode::AllMigraphx || (allow_mixed && facts.mode == PlacementMode::Mixed)
}

fn public_pair_placement(
    pair: usize,
    fp32: &WorkerOutput,
    fp16: &WorkerOutput,
) -> PublicPairPlacement {
    PublicPairPlacement {
        pair,
        fp32_registered_preference: fp32.registered_preference.clone(),
        fp16_registered_preference: fp16.registered_preference.clone(),
        fp32_detector: public_placement(&fp32.detector_placement),
        fp32_recognizer: public_placement(&fp32.recognizer_placement),
        fp16_detector: public_placement(&fp16.detector_placement),
        fp16_recognizer: public_placement(&fp16.recognizer_placement),
    }
}

fn public_placement(facts: &PlacementFacts) -> PublicPlacement {
    PublicPlacement {
        mode: facts.mode,
        migraphx_executed_events: facts.migraphx_events,
        cpu_executed_events: facts.cpu_events,
        unknown_executed_events: facts.unknown_events,
        provider_set: facts.providers.clone(),
    }
}

fn gate_report(gates: Gates, metrics: &MetricReport) -> GateReport {
    let decision_count = metrics.enrolled_score_abs_drift.count;
    GateReport {
        face_iou: gate(
            ">=",
            metrics.box_iou.min,
            gates.min_face_iou,
            metrics.box_iou.count,
            metrics.box_iou.count > 0 && metrics.box_iou.min >= gates.min_face_iou,
        ),
        detector_score_drift: gate(
            "<=",
            metrics.detector_score_abs_drift.max,
            gates.max_detector_score_drift,
            metrics.detector_score_abs_drift.count,
            metrics.detector_score_abs_drift.count > 0
                && metrics.detector_score_abs_drift.max <= gates.max_detector_score_drift,
        ),
        landmark_rmse: gate(
            "<=",
            metrics.landmark_point_rmse_pixels.max,
            gates.max_landmark_rmse,
            metrics.landmark_point_rmse_pixels.count,
            metrics.landmark_point_rmse_pixels.count > 0
                && metrics.landmark_point_rmse_pixels.max <= gates.max_landmark_rmse,
        ),
        embedding_cosine: gate(
            ">=",
            metrics.embedding_cosine.min,
            gates.min_embedding_cosine,
            metrics.embedding_cosine.count,
            metrics.embedding_cosine.count > 0
                && metrics.embedding_cosine.min >= gates.min_embedding_cosine,
        ),
        enrolled_score_drift: optional_gate(
            "<=",
            metrics.enrolled_score_abs_drift.max,
            gates.max_enrolled_score_drift,
            decision_count,
            metrics.decision_testing_evaluated.then_some(
                decision_count > 0
                    && metrics.enrolled_score_abs_drift.max <= gates.max_enrolled_score_drift,
            ),
        ),
        threshold_flips: optional_gate(
            "==",
            metrics.threshold_flips as f64,
            0.0,
            decision_count,
            metrics
                .decision_testing_evaluated
                .then_some(decision_count > 0 && metrics.threshold_flips == 0),
        ),
        unmatched_faces: gate(
            "==",
            metrics.unmatched_faces as f64,
            0.0,
            metrics.matched_faces + metrics.unmatched_faces,
            metrics.unmatched_faces == 0,
        ),
    }
}

fn gate(
    comparator: &'static str,
    value: f64,
    limit: f64,
    evaluated_count: usize,
    passed: bool,
) -> GateResult {
    GateResult {
        comparator,
        value,
        limit,
        evaluated_count,
        passed,
    }
}

fn optional_gate(
    comparator: &'static str,
    value: f64,
    limit: f64,
    evaluated_count: usize,
    passed: Option<bool>,
) -> OptionalGateResult {
    OptionalGateResult {
        comparator,
        value: passed.map(|_| value),
        limit,
        evaluated_count,
        passed,
    }
}

fn timing_report(records: &[ImageRecord]) -> TimingReport {
    TimingReport {
        image_decode_ms: distribution(
            &records
                .iter()
                .map(|record| record.decode_ms)
                .collect::<Vec<_>>(),
        ),
        detector_preprocess_run_postprocess_ms: distribution(
            &records
                .iter()
                .map(|record| record.detector_pipeline_ms)
                .collect::<Vec<_>>(),
        ),
        recognizer_alignment_run_ms: distribution(
            &records
                .iter()
                .map(|record| record.recognizer_pipeline_ms)
                .collect::<Vec<_>>(),
        ),
        enrolled_matching_ms: distribution(
            &records
                .iter()
                .map(|record| record.enrolled_matching_ms)
                .collect::<Vec<_>>(),
        ),
        complete_fixture_ms: distribution(
            &records
                .iter()
                .map(|record| record.complete_fixture_ms)
                .collect::<Vec<_>>(),
        ),
    }
}

fn distribution(values: &[f64]) -> Distribution {
    if values.is_empty() {
        return Distribution::default();
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    };
    let p95 =
        (sorted.len() >= 20).then(|| sorted[((sorted.len() - 1) as f64 * 0.95).ceil() as usize]);
    Distribution {
        count: sorted.len(),
        min: sorted[0],
        mean: sorted.iter().sum::<f64>() / sorted.len() as f64,
        median,
        max: *sorted.last().unwrap(),
        p95,
    }
}

fn global_face_assignment(
    left: &[FaceRecord],
    right: &[FaceRecord],
    floor: f64,
) -> Vec<(usize, usize, f64)> {
    let matrix = left
        .iter()
        .map(|left| {
            right
                .iter()
                .map(|right| bbox_iou(left.bbox, right.bbox))
                .collect()
        })
        .collect::<Vec<Vec<_>>>();
    global_assignment_matrix(&matrix, floor)
}

#[derive(Clone)]
struct Assignment {
    score: f64,
    count: usize,
    choices: Vec<Option<usize>>,
}

fn global_assignment_matrix(matrix: &[Vec<f64>], floor: f64) -> Vec<(usize, usize, f64)> {
    if matrix.is_empty() || matrix[0].is_empty() {
        return Vec::new();
    }
    let right_count = matrix[0].len();
    if right_count > MAX_FACES_PER_FIXTURE || matrix.len() > MAX_FACES_PER_FIXTURE {
        return Vec::new();
    }
    fn solve(
        i: usize,
        mask: u32,
        matrix: &[Vec<f64>],
        floor: f64,
        memo: &mut HashMap<(usize, u32), Assignment>,
    ) -> Assignment {
        if i == matrix.len() {
            return Assignment {
                score: 0.0,
                count: 0,
                choices: Vec::new(),
            };
        }
        if let Some(value) = memo.get(&(i, mask)) {
            return value.clone();
        }
        let mut tail = solve(i + 1, mask, matrix, floor, memo);
        tail.choices.insert(0, None);
        let mut best = tail;
        for right in 0..matrix[i].len() {
            if mask & (1 << right) != 0 || matrix[i][right] < floor {
                continue;
            }
            let mut candidate = solve(i + 1, mask | (1 << right), matrix, floor, memo);
            candidate.score += matrix[i][right];
            candidate.count += 1;
            candidate.choices.insert(0, Some(right));
            if assignment_better(&candidate, &best) {
                best = candidate;
            }
        }
        memo.insert((i, mask), best.clone());
        best
    }
    let assignment = solve(0, 0, matrix, floor, &mut HashMap::new());
    assignment
        .choices
        .into_iter()
        .enumerate()
        .filter_map(|(left, right)| right.map(|right| (left, right, matrix[left][right])))
        .collect()
}

fn assignment_better(left: &Assignment, right: &Assignment) -> bool {
    match left.score.total_cmp(&right.score) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => {
            left.count > right.count
                || (left.count == right.count
                    && assignment_key(&left.choices) < assignment_key(&right.choices))
        }
    }
}

fn assignment_key(choices: &[Option<usize>]) -> Vec<usize> {
    choices
        .iter()
        .map(|choice| choice.unwrap_or(usize::MAX))
        .collect()
}

fn bbox_iou(left: [i32; 4], right: [i32; 4]) -> f64 {
    let width = (left[2].min(right[2]) - left[0].max(right[0])).max(0) as f64;
    let height = (left[3].min(right[3]) - left[1].max(right[1])).max(0) as f64;
    let intersection = width * height;
    let left_area = ((left[2] - left[0]).max(0) * (left[3] - left[1]).max(0)) as f64;
    let right_area = ((right[2] - right[0]).max(0) * (right[3] - right[1]).max(0)) as f64;
    let union = left_area + right_area - intersection;
    if union > 0.0 {
        intersection / union
    } else {
        0.0
    }
}

fn landmark_point_rmse(left: &[f32; 10], right: &[f32; 10]) -> f64 {
    (left
        .chunks_exact(2)
        .zip(right.chunks_exact(2))
        .map(|(left, right)| {
            (f64::from(left[0]) - f64::from(right[0])).powi(2)
                + (f64::from(left[1]) - f64::from(right[1])).powi(2)
        })
        .sum::<f64>()
        / 5.0)
        .sqrt()
}

fn embedding_cosine(left: &[f32], right: &[f32]) -> Result<f64> {
    validate_normalized_embedding(left)?;
    validate_normalized_embedding(right)?;
    Ok(f64::from(
        face::cosine_similarity(left, right).map_err(anyhow::Error::msg)?,
    ))
}

fn pair_order(index: usize) -> [Precision; 2] {
    if index % 2 == 0 {
        [Precision::Fp32, Precision::Fp16]
    } else {
        [Precision::Fp16, Precision::Fp32]
    }
}

fn validate_pixels(width: u32, height: u32) -> Result<()> {
    if u64::from(width) * u64::from(height) > MAX_PIXELS_PER_FIXTURE {
        bail!("decoded_pixel_limit");
    }
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn random_capability() -> Result<[u8; CAPABILITY_BYTES]> {
    random_bytes()
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/urandom")?;
    let mut bytes = [0u8; N];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn decode_capability(value: &str) -> Result<[u8; CAPABILITY_BYTES]> {
    let bytes = hex::decode(value).context("capability_decode_failed")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("capability_length_invalid"))
}

fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T, cap: usize) -> Result<()> {
    writer.write_all(&encode_frame(value, cap)?)?;
    Ok(())
}

fn encode_frame<T: Serialize>(value: &T, cap: usize) -> Result<Zeroizing<Vec<u8>>> {
    let payload = Zeroizing::new(bincode::serialize(value)?);
    if payload.len() > cap || payload.len() > u32::MAX as usize {
        bail!("protocol_payload_overflow");
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read, cap: usize) -> Result<T> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > cap {
        bail!("protocol_payload_overflow");
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    reader.read_exact(&mut payload)?;
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(length as u64)
        .reject_trailing_bytes()
        .deserialize(&payload)?;
    Ok(value)
}

fn write_all_deadline(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            bail!("worker_deadline_exceeded");
        }
        match stream.write(bytes) {
            Ok(0) => bail!("protocol_write_closed"),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_deadline(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            bail!("worker_deadline_exceeded");
        }
        match stream.read(bytes) {
            Ok(0) => bail!("protocol_unexpected_eof"),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_deadline(stream.as_raw_fd(), libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_frame_deadline<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    cap: usize,
    deadline: Instant,
) -> Result<T> {
    let mut length = [0u8; 4];
    read_exact_deadline(stream, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > cap {
        bail!("protocol_payload_overflow");
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    read_exact_deadline(stream, &mut payload, deadline)?;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(length as u64)
        .reject_trailing_bytes()
        .deserialize(&payload)?)
}

fn require_eof_deadline(stream: &mut UnixStream, deadline: Instant) -> Result<()> {
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            bail!("worker_deadline_exceeded");
        }
        match stream.read(&mut byte) {
            Ok(0) => return Ok(()),
            Ok(_) => bail!("protocol_trailing_data"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_deadline(stream.as_raw_fd(), libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn poll_deadline(fd: RawFd, events: i16, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("worker_deadline_exceeded")?;
    let timeout = i32::try_from(remaining.as_millis().saturating_add(1)).unwrap_or(i32::MAX);
    let mut pollfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
    if result == 0 {
        bail!("worker_deadline_exceeded");
    }
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("protocol_poll_failed");
    }
    Ok(())
}

fn set_fd_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("fd_cloexec_failed");
    }
    Ok(())
}

fn ort_runtime_version() -> Result<String> {
    let base = unsafe { ort::sys::OrtGetApiBase() };
    if base.is_null() {
        bail!("ort_api_base_missing");
    }
    let version = unsafe { ((*base).GetVersionString)() };
    if version.is_null() {
        bail!("ort_runtime_version_missing");
    }
    Ok(unsafe { CStr::from_ptr(version) }
        .to_string_lossy()
        .into_owned())
}

fn elapsed_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn redact_diagnostic(detail: &str, config: &ParentConfig) -> String {
    let mut redacted = detail.to_string();
    for path in [
        Some(&config.experiment_root),
        Some(&config.fixture_dir),
        Some(&config.manifest),
        Some(&config.detector_model),
        Some(&config.recognizer_model),
        config.enrolled_model.as_ref(),
        Some(&config.result),
        config.diagnostics.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        redacted = redacted.replace(&path.to_string_lossy().to_string(), "<redacted-path>");
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "howy-fp16-v2-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn test_root(path: &Path) -> ExperimentRoot {
        open_experiment_root(path, &repository_root().unwrap()).unwrap()
    }

    fn unit_embedding(index: usize) -> Vec<f32> {
        let mut value = vec![0.0; FACE_EMBEDDING_DIM];
        value[index] = 1.0;
        value
    }

    fn face_record(bbox: [i32; 4]) -> FaceRecord {
        FaceRecord {
            bbox,
            landmarks: [0.0; 10],
            detector_score: 0.9,
            embedding: unit_embedding(0),
            enrolled_score: None,
            decision: None,
        }
    }

    #[test]
    fn environment_is_scrubbed_and_fully_attested() {
        let env = reviewed_environment(Precision::Fp16, "11.0.2").unwrap();
        assert_eq!(env.set["ORT_MIGRAPHX_FP16_ENABLE"], "1");
        for key in [
            "ORT_MIGRAPHX_BF16_ENABLE",
            "ORT_MIGRAPHX_FP8_ENABLE",
            "ORT_MIGRAPHX_INT8_ENABLE",
            "ORT_MIGRAPHX_EXHAUSTIVE_TUNE",
            "ORT_MIGRAPHX_DUMP_MODEL",
        ] {
            assert_eq!(env.set[key], "0");
        }
        assert!(
            env.cleared
                .contains(&"ORT_MIGRAPHX_SAVE_COMPILED_MODEL".to_string())
        );
        let mut command = Command::new("true");
        configure_worker_environment(&mut command, "capability", &env);
        let configured = command
            .get_envs()
            .map(|(key, _)| key.to_string_lossy().to_string())
            .collect::<BTreeSet<_>>();
        assert!(!configured.contains("HOME"));
        assert!(configured.contains("HOWY_FP16_CAPABILITY"));
        assert!(configured.contains("ORT_MIGRAPHX_FP16_ENABLE"));
    }

    #[test]
    fn cache_layout_is_unique_private_and_exclusively_locked() {
        let root = temp_dir("layout");
        let root_fd = test_root(&root);
        let layout = create_experiment_layout(&root_fd, 2).unwrap();
        assert_ne!(
            layout.pairs[0].fp32.cache.metadata().unwrap().ino(),
            layout.pairs[0].fp16.cache.metadata().unwrap().ino()
        );
        assert_eq!(
            layout.pairs[0]
                .fp32
                .cache
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(
            openat2_file(
                layout.pairs[0].fp32.cache.as_raw_fd(),
                Path::new(".exclusive.lock"),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
            .is_err()
        );
        let competing = openat2_file(
            layout.pairs[0].fp32.cache.as_raw_fd(),
            Path::new(".exclusive.lock"),
            libc::O_WRONLY | libc::O_CLOEXEC,
            0,
        )
        .unwrap();
        assert_ne!(
            unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        drop(layout);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn experiment_layout_drop_removes_private_run_tree() {
        let root = temp_dir("layout-cleanup");
        let root_fd = test_root(&root);
        let layout = create_experiment_layout(&root_fd, 1).unwrap();
        let run = layout.run_name.clone();
        assert!(
            openat2_file(
                root_fd.fd.as_raw_fd(),
                Path::new(&run),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0
            )
            .is_ok()
        );
        drop(layout);
        assert!(
            openat2_file(
                root_fd.fd.as_raw_fd(),
                Path::new(&run),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0
            )
            .is_err()
        );
        fs::remove_dir(root).unwrap();
    }

    fn test_provenance(precision: Precision) -> Provenance {
        Provenance {
            precision,
            detector_digest: "detector".into(),
            recognizer_digest: "recognizer".into(),
            ort_crate_version: ORT_CRATE_VERSION.into(),
            ort_api_version: ort::MINOR_VERSION,
            ort_runtime_version: "runtime".into(),
            configured_gpu_target: "gfx-test".into(),
            hsa_override: "11.0.2".into(),
            recognition_threshold_bits: 0.5f32.to_bits(),
            inference_threads: HowyConfig::default().ml.threads,
            provider_name: "migraphx".into(),
            graph_optimization_level: "level2".into(),
            provider_api_fp16: precision.fp16(),
            provider_api_fp8: false,
            provider_api_int8: false,
            provider_api_exhaustive_tune: false,
            environment: reviewed_environment(precision, "11.0.2").unwrap(),
            corpus_digest: "0".repeat(64),
            provider_stack: test_provider_stack(),
        }
    }

    fn test_provider_stack() -> ProviderStackProvenance {
        let names = [
            "libonnxruntime.so",
            "libonnxruntime_providers_migraphx.so",
            "libmigraphx.so",
            "libamdhip64.so",
            "libhsa-runtime64.so",
        ];
        ProviderStackProvenance {
            libraries: names
                .into_iter()
                .map(|name| RuntimeLibraryDigest {
                    name: name.into(),
                    path: format!("/usr/lib/{name}"),
                    sha256: "1".repeat(64),
                    size: 1,
                })
                .collect(),
            has_ort_core: true,
            has_ort_migraphx_provider: true,
            has_migraphx: true,
            has_hip: true,
            has_rocm_runtime: true,
        }
    }

    #[test]
    fn cache_provenance_round_trips_and_mismatch_fails() {
        let root = temp_dir("provenance");
        let root_fd = test_root(&root);
        let layout = create_experiment_layout(&root_fd, 1).unwrap();
        let cache = &layout.pairs[0].fp32.cache;
        write_atomic_at(cache, Path::new("compiled.mxr"), b"cache").unwrap();
        let provenance = CacheManifest {
            provenance: test_provenance(Precision::Fp32),
            artifacts: inventory_cache(cache).unwrap(),
        };
        write_cache_provenance(cache, &provenance).unwrap();
        verify_cache_provenance(cache, &provenance).unwrap();
        let mismatch = CacheManifest {
            provenance: test_provenance(Precision::Fp16),
            artifacts: provenance.artifacts.clone(),
        };
        assert!(verify_cache_provenance(cache, &mismatch).is_err());
        drop(layout);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn nofollow_and_repository_paths_are_rejected() {
        let root = temp_dir("nofollow");
        let root_fd = test_root(&root);
        let file = root.join("private");
        fs::write(&file, b"bytes").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(secure_read_at(&root_fd.fd, Path::new("link"), 100, true).is_err());
        assert!(
            open_experiment_root(&repository_root().unwrap(), &repository_root().unwrap()).is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn securely_opened_bytes_remain_pinned_after_path_replacement() {
        let root = temp_dir("pinned");
        let root_fd = test_root(&root);
        let path = root.join("fixture");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let pinned = secure_read_at(&root_fd.fd, Path::new("fixture"), 100, true).unwrap();
        let replacement = root.join("replacement");
        fs::write(&replacement, b"changed!").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(pinned.bytes, b"original");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_fixture_identity_and_content_are_detected() {
        let bytes = b"same";
        assert_eq!(digest_hex(bytes), digest_hex(bytes));
        let mut identities = HashSet::new();
        assert!(identities.insert((1, 2)));
        assert!(!identities.insert((1, 2)));
        let mut digests = HashSet::new();
        assert!(digests.insert(digest_hex(bytes)));
        assert!(!digests.insert(digest_hex(bytes)));
    }

    #[test]
    fn capability_protocol_uses_dedicated_socket_and_rejects_overflow() {
        assert!(worker_entry(&[]).is_err());
        let (mut left, mut right) = UnixStream::pair().unwrap();
        let capability = [7u8; CAPABILITY_BYTES];
        let writer = thread::spawn(move || write_frame(&mut left, &capability, 64).unwrap());
        let decoded: [u8; CAPABILITY_BYTES] = read_frame(&mut right, 64).unwrap();
        writer.join().unwrap();
        assert_eq!(decoded, capability);
        assert!(write_frame(&mut Vec::new(), &vec![0u8; 100], 10).is_err());
    }

    #[test]
    fn protocol_blocked_write_obeys_absolute_deadline() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let bytes = vec![7u8; 8 * 1024 * 1024];
        assert!(
            write_all_deadline(
                &mut writer,
                &bytes,
                Instant::now() + Duration::from_millis(20)
            )
            .is_err()
        );
    }

    #[test]
    fn child_guard_times_out_kills_and_reaps_process_group() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("exec sleep 5");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let mut guard = ChildGuard::new(child);
        assert!(
            guard
                .wait_until(Instant::now() + Duration::from_millis(20))
                .is_err()
        );
        assert!(guard.child_mut().try_wait().unwrap().is_some());
    }

    #[test]
    fn sanitized_profile_fixture_reports_complete_event_facts() {
        let bytes = include_bytes!("../../../../tests/fixtures/ort_profile_sanitized.json");
        let facts = parse_profile_json(bytes).unwrap();
        assert_eq!(facts.migraphx_events, 3);
        assert_eq!(facts.cpu_events, 1);
        assert_eq!(facts.mode, PlacementMode::Mixed);
        assert_eq!(
            facts.nodes["0|detector_kernel_time|Conv"].invocation_count,
            1
        );
        assert_eq!(
            facts.nodes["1|recognizer_kernel_time|Gemm"].invocation_count,
            2
        );
    }

    #[test]
    fn profile_parser_rejects_unknown_and_malformed_placement() {
        let unknown =
            br#"[{"cat":"Node","ph":"X","dur":1,"name":"x","args":{"provider":"UnknownEP","op_name":"Test","node_index":"0"}}]"#;
        assert_eq!(
            parse_profile_json(unknown).unwrap().mode,
            PlacementMode::Invalid
        );
        assert!(parse_profile_json(br#"[{"cat":"Node"}]"#).is_err());
    }

    #[test]
    fn profile_reader_is_bounded_to_its_private_directory() {
        let root = temp_dir("profile-path");
        let profile_dir = root.join("profiles");
        fs::create_dir(&profile_dir).unwrap();
        let profile = profile_dir.join("profile.json");
        fs::write(
            &profile,
            include_bytes!("../../../../tests/fixtures/ort_profile_sanitized.json"),
        )
        .unwrap();
        let profile_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&profile_dir)
            .unwrap();
        assert!(
            parse_profile(
                Path::new("/proc/self/fd/5/profile.json"),
                profile_fd.as_raw_fd()
            )
            .is_ok()
        );

        let outside = root.join("outside.json");
        fs::write(
            &outside,
            include_bytes!("../../../../tests/fixtures/ort_profile_sanitized.json"),
        )
        .unwrap();
        assert!(
            parse_profile(
                Path::new("/proc/self/fd/5/outside.json"),
                profile_fd.as_raw_fd()
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_placement_requires_explicit_policy() {
        let facts = parse_profile_json(include_bytes!(
            "../../../../tests/fixtures/ort_profile_sanitized.json"
        ))
        .unwrap();
        assert!(!placement_allowed(&facts, false));
        assert!(placement_allowed(&facts, true));
        let invalid = parse_profile_json(
            br#"[{"cat":"Node","ph":"X","dur":1,"name":"x","args":{"provider":"UnknownEP","op_name":"Test","node_index":"0"}}]"#,
        )
        .unwrap();
        assert!(!placement_allowed(&invalid, true));
    }

    #[test]
    fn production_match_parity_uses_shared_flat_routine() {
        let query = unit_embedding(1);
        let mut known = unit_embedding(0);
        known.extend(unit_embedding(1));
        let expected = face::find_best_match_flat(&query, &known, 2, 0.5);
        let actual = face::find_best_match_flat(&query, &known, 2, 0.5);
        assert_eq!(actual, expected);
        assert_eq!(actual.0, Some(1));
    }

    #[test]
    fn global_assignment_beats_greedy_crossing_and_breaks_ties() {
        let crossing = vec![vec![0.9, 0.8], vec![0.85, 0.1]];
        let assignment = global_assignment_matrix(&crossing, 0.05);
        assert_eq!(
            assignment
                .iter()
                .map(|(_, right, _)| *right)
                .collect::<Vec<_>>(),
            [1, 0]
        );
        let ties = vec![vec![1.0, 1.0], vec![1.0, 1.0]];
        assert_eq!(global_assignment_matrix(&ties, 0.5)[0].1, 0);
    }

    #[test]
    fn global_assignment_respects_iou_floor_and_multiple_faces() {
        let matrix = vec![
            vec![0.99, 0.2, 0.1],
            vec![0.1, 0.98, 0.2],
            vec![0.2, 0.1, 0.4],
        ];
        let assignment = global_assignment_matrix(&matrix, 0.95);
        assert_eq!(assignment.len(), 2);
    }

    #[test]
    fn landmark_rmse_is_point_based() {
        let left = [0.0; 10];
        let right = [3.0, 4.0, 3.0, 4.0, 3.0, 4.0, 3.0, 4.0, 3.0, 4.0];
        assert_eq!(landmark_point_rmse(&left, &right), 5.0);
    }

    #[test]
    fn numeric_configuration_rejects_nan_and_bad_threshold() {
        let mut gates = Gates::default();
        gates.max_landmark_rmse = f64::NAN;
        assert!(validate_numeric_configuration(0.5, gates).is_err());
        assert!(validate_numeric_configuration(1.1, Gates::default()).is_err());
        assert!(validate_hsa_override("11.0.2").is_ok());
        assert!(validate_hsa_override("arbitrary").is_err());
    }

    #[test]
    fn no_model_decision_gate_is_not_marked_passing() {
        let metrics = MetricReport {
            box_iou: distribution(&[1.0]),
            detector_score_abs_drift: distribution(&[0.0]),
            landmark_point_rmse_pixels: distribution(&[0.0]),
            embedding_cosine: distribution(&[1.0]),
            enrolled_score_abs_drift: Distribution::default(),
            matched_faces: 1,
            unmatched_faces: 0,
            threshold_flips: 0,
            decision_testing_evaluated: false,
        };
        let gates = gate_report(Gates::default(), &metrics);
        assert_eq!(gates.threshold_flips.passed, None);
        assert_eq!(gates.enrolled_score_drift.passed, None);
    }

    #[test]
    fn every_numeric_gate_reports_failure_at_bad_boundary() {
        let bad = MetricReport {
            box_iou: distribution(&[0.94]),
            detector_score_abs_drift: distribution(&[0.02]),
            landmark_point_rmse_pixels: distribution(&[1.1]),
            embedding_cosine: distribution(&[0.998]),
            enrolled_score_abs_drift: distribution(&[0.02]),
            matched_faces: 1,
            unmatched_faces: 1,
            threshold_flips: 1,
            decision_testing_evaluated: true,
        };
        let gates = gate_report(Gates::default(), &bad);
        assert!(!gates.face_iou.passed);
        assert!(!gates.detector_score_drift.passed);
        assert!(!gates.landmark_rmse.passed);
        assert!(!gates.embedding_cosine.passed);
        assert_eq!(gates.enrolled_score_drift.passed, Some(false));
        assert_eq!(gates.threshold_flips.passed, Some(false));
        assert!(!gates.unmatched_faces.passed);
    }

    #[test]
    fn normalized_enrolled_models_are_required() {
        assert!(validate_normalized_embedding(&unit_embedding(0)).is_ok());
        assert!(validate_normalized_embedding(&vec![0.0; FACE_EMBEDDING_DIM]).is_err());
    }

    #[test]
    fn output_redaction_removes_all_configured_paths() {
        let root = temp_dir("redact");
        let config = ParentConfig {
            experiment_root: root.clone(),
            fixture_dir: root.join("fixtures"),
            manifest: root.join("manifest"),
            detector_model: root.join("detector"),
            recognizer_model: root.join("recognizer"),
            enrolled_model: None,
            result: root.join("result"),
            diagnostics: None,
            threshold: 0.5,
            hsa_override: "11.0.2".into(),
            configured_gpu_target: "gfx1103".into(),
            pairs: 2,
            deadline: Duration::from_secs(1),
            allow_mixed: false,
            gates: Gates::default(),
        };
        let detail =
            redact_diagnostic(&format!("failed {}", config.fixture_dir.display()), &config);
        assert!(!detail.contains(&root.to_string_lossy().to_string()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ab_ba_order_alternates() {
        assert_eq!(pair_order(0), [Precision::Fp32, Precision::Fp16]);
        assert_eq!(pair_order(1), [Precision::Fp16, Precision::Fp32]);
    }

    #[test]
    fn distributions_report_median_range_and_conditional_percentile() {
        let short = distribution(&[3.0, 1.0, 2.0]);
        assert_eq!(
            (short.min, short.mean, short.median, short.max, short.p95),
            (1.0, 2.0, 2.0, 3.0, None)
        );
        assert!(
            distribution(&(0..20).map(f64::from).collect::<Vec<_>>())
                .p95
                .is_some()
        );
    }

    #[test]
    fn public_report_field_names_do_not_expose_records() {
        let public = PublicProvenance {
            configured_gpu_target: "configured-target".into(),
            hsa_override: "11.0.2".into(),
            hsa_override_source: "configured_cli_value_not_queried_hardware_identity",
            provider_provenance_match: true,
            precision_controls: BTreeMap::new(),
            isolated_arm_caches: true,
        };
        let names = format!(
            "{}{}",
            serde_json::to_string(&public).unwrap(),
            serde_json::to_string(&public_placement(&PlacementFacts::default())).unwrap()
        );
        for forbidden in [
            "path",
            "sha256",
            "digest",
            "detector_sha",
            "recognizer_sha",
            "corpus_sha",
            "runtime_libraries",
            "username",
            "label",
            "embedding",
            "bbox",
            "landmarks",
            "node_identities",
        ] {
            assert!(!names.contains(forbidden));
        }
    }

    #[test]
    fn atomic_result_refuses_existing_target_and_uses_private_mode() {
        let root = temp_dir("result");
        let root_fd = test_root(&root);
        let result = root.join("aggregate.json");
        write_atomic_at(&root_fd.fd, Path::new("aggregate.json"), b"{}").unwrap();
        assert_eq!(
            fs::metadata(&result).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_atomic_at(&root_fd.fd, Path::new("aggregate.json"), b"other").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn face_assignment_fixture_helper_is_deterministic() {
        let left = vec![face_record([0, 0, 10, 10]), face_record([20, 0, 30, 10])];
        let right = left.clone();
        assert_eq!(global_face_assignment(&left, &right, 0.95).len(), 2);
    }

    #[test]
    fn worker_record_indices_must_exactly_follow_manifest_order() {
        let record = ImageRecord {
            index: 1,
            class: FixtureClass::Positive,
            decode_ms: 0.0,
            detector_pipeline_ms: 0.0,
            recognizer_pipeline_ms: 0.0,
            enrolled_matching_ms: 0.0,
            complete_fixture_ms: 0.0,
            faces: Vec::new(),
        };
        assert!(validate_record_indices(&[record]).is_err());
    }

    #[test]
    fn intermediate_directory_swap_cannot_redirect_held_fd() {
        let root = temp_dir("directory-swap");
        let inside = root.join("inside");
        fs::create_dir(&inside).unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(inside.join("secret"), b"pinned").unwrap();
        fs::set_permissions(inside.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
        let root_fd = test_root(&root);
        let held = secure_directory_at(&root_fd.fd, Path::new("inside")).unwrap();
        fs::rename(&inside, root.join("moved")).unwrap();
        std::os::unix::fs::symlink("moved", &inside).unwrap();
        let pinned = secure_read_at(&held, Path::new("secret"), 64, true).unwrap();
        assert_eq!(pinned.bytes, b"pinned");
        assert!(secure_read_at(&root_fd.fd, Path::new("inside/secret"), 64, true).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_success_finalization_removes_descendant_process_group() {
        ensure_child_subreaper().unwrap();
        let root = temp_dir("descendant");
        let pid_file = root.join("pid");
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "sleep 5 & child=$!; printf '%s' \"$child\" > '{}'",
            pid_file.display()
        ));
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let mut guard = ChildGuard::new(child);
        let deadline = Instant::now() + Duration::from_secs(2);
        guard.wait_until(deadline).unwrap();
        let descendant: i32 = fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        let pgid = guard.pgid;
        guard.success_finalize(deadline).unwrap();
        assert_ne!(unsafe { libc::kill(descendant, 0) }, 0);
        assert_ne!(unsafe { libc::kill(-pgid, 0) }, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malicious_wire_collection_length_is_rejected_before_allocation() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Probe(#[serde(deserialize_with = "deserialize_fixture_bytes")] Vec<u8>);
        let malicious = u64::MAX.to_le_bytes();
        let result = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize::<Probe>(&malicious);
        assert!(result.is_err());
    }

    #[test]
    fn exact_corpus_digest_detects_any_payload_change() {
        let mut corpus = PinnedCorpus {
            detector_digest: digest_hex(b"detector"),
            detector_model: b"detector".to_vec(),
            recognizer_digest: digest_hex(b"recognizer"),
            recognizer_model: b"recognizer".to_vec(),
            enrolled_model: None,
            fixtures: vec![PinnedFixture {
                index: 0,
                class: FixtureClass::Positive,
                digest: digest_hex(b"fixture"),
                encoded: b"fixture".to_vec(),
            }],
        };
        let expected = corpus_digest(&corpus).unwrap();
        assert!(verify_corpus_digest(&expected, &expected).is_ok());
        assert!(verify_corpus_digest(&expected, &"f".repeat(64)).is_err());
        corpus.fixtures[0].encoded[0] ^= 1;
        assert_ne!(corpus_digest(&corpus).unwrap(), expected);
    }

    #[test]
    fn oversized_image_is_rejected_from_header_before_decode() {
        let mut bmp = vec![0u8; 54];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&(54u32).to_le_bytes());
        bmp[10..14].copy_from_slice(&(54u32).to_le_bytes());
        bmp[14..18].copy_from_slice(&(40u32).to_le_bytes());
        bmp[18..22].copy_from_slice(&(10_000i32).to_le_bytes());
        bmp[22..26].copy_from_slice(&(10_000i32).to_le_bytes());
        bmp[26..28].copy_from_slice(&(1u16).to_le_bytes());
        bmp[28..30].copy_from_slice(&(24u16).to_le_bytes());
        assert!(inspect_image_dimensions(&bmp).is_err());
    }

    #[test]
    fn cache_inventory_rejects_mutation_and_new_artifact() {
        let root = temp_dir("cache-mutation");
        let root_fd = test_root(&root);
        let layout = create_experiment_layout(&root_fd, 1).unwrap();
        let cache = &layout.pairs[0].fp32.cache;
        write_atomic_at(cache, Path::new("compiled.mxr"), b"original").unwrap();
        let expected = inventory_cache(cache).unwrap();
        let mut artifact = openat2_file(
            cache.as_raw_fd(),
            Path::new("compiled.mxr"),
            libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
            0,
        )
        .unwrap();
        artifact.write_all(b"changed").unwrap();
        drop(artifact);
        assert!(verify_cache_inventory(cache, &expected).is_err());
        write_atomic_at(cache, Path::new("new.mxr"), b"new").unwrap();
        assert!(verify_cache_inventory(cache, &expected).is_err());
        drop(layout);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn provider_swap_fails_even_with_equal_aggregate_counts() {
        let left = parse_profile_json(
            br#"[{"cat":"Node","ph":"X","dur":1,"name":"a","args":{"provider":"MIGraphXExecutionProvider","op_name":"Conv","node_index":"0"}},{"cat":"Node","ph":"X","dur":1,"name":"b","args":{"provider":"CPUExecutionProvider","op_name":"Shape","node_index":"1"}}]"#,
        )
        .unwrap();
        let right = parse_profile_json(
            br#"[{"cat":"Node","ph":"X","dur":1,"name":"a","args":{"provider":"CPUExecutionProvider","op_name":"Conv","node_index":"0"}},{"cat":"Node","ph":"X","dur":1,"name":"b","args":{"provider":"MIGraphXExecutionProvider","op_name":"Shape","node_index":"1"}}]"#,
        )
        .unwrap();
        assert_eq!(left.migraphx_events, right.migraphx_events);
        assert_eq!(left.cpu_events, right.cpu_events);
        assert!(!placement_facts_comparable(&left, &right));
    }

    #[test]
    fn zeroizing_wrapper_clears_observable_borrow_on_drop() {
        struct Observable<'a>(&'a mut [u8]);
        impl Zeroize for Observable<'_> {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        let mut secret = [7u8; 32];
        {
            let _guard = Zeroizing::new(Observable(&mut secret));
        }
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn detailed_face_record_zeroizes_every_biometric_field() {
        let mut record = FaceRecord {
            bbox: [1, 2, 3, 4],
            landmarks: [5.0; 10],
            detector_score: 0.9,
            embedding: unit_embedding(0),
            enrolled_score: Some(0.8),
            decision: Some(true),
        };
        record.zeroize();
        assert_eq!(record.bbox, [0; 4]);
        assert_eq!(record.landmarks, [0.0; 10]);
        assert_eq!(record.detector_score, 0.0);
        assert!(record.embedding.is_empty());
        assert_eq!(record.enrolled_score, None);
        assert_eq!(record.decision, None);
    }

    #[test]
    fn enrolled_model_allocations_and_error_owner_are_zeroizable() {
        let models = howy_common::face::UserModels {
            username: "private-user".into(),
            models: vec![howy_common::face::FaceModel {
                label: "private-label".into(),
                created: 1,
                embedding: unit_embedding(0),
            }],
        };
        let encoded = bincode::serialize(&models).unwrap();
        let mut secure = parse_and_validate_enrolled_model(&encoded).unwrap();
        secure.zeroize();
        assert!(secure.username.is_empty());
        assert!(secure.labels.is_empty());
        assert!(secure.flat_embeddings.is_empty());

        let mut corpus = PinnedCorpus {
            detector_digest: "d".repeat(64),
            detector_model: b"detector".to_vec(),
            recognizer_digest: "r".repeat(64),
            recognizer_model: b"recognizer".to_vec(),
            enrolled_model: Some(vec![0xff; 16]),
            fixtures: Vec::new(),
        };
        assert!(
            parse_and_validate_enrolled_model(corpus.enrolled_model.as_ref().unwrap()).is_err()
        );
        corpus.zeroize();
        assert!(corpus.detector_model.is_empty());
        assert!(corpus.recognizer_model.is_empty());
        assert_eq!(corpus.enrolled_model, None);
    }

    #[test]
    fn decoded_dynamic_image_backing_is_explicitly_zeroizable() {
        let image = image::RgbImage::from_raw(1, 1, vec![1, 2, 3]).unwrap();
        let mut guarded = ZeroizingDynamicImage(image::DynamicImage::ImageRgb8(image));
        guarded.zeroize();
        assert_eq!(guarded.0.as_bytes(), &[0, 0, 0]);
    }

    #[test]
    fn hash_coherence_detects_mtime_and_ctime_changes() {
        let before = ArtifactStamp {
            device: 1,
            inode: 2,
            length: 3,
            mtime: 4,
            mtime_nsec: 5,
            ctime: 6,
            ctime_nsec: 7,
        };
        let mut changed = before.clone();
        changed.mtime += 1;
        assert!(verify_hash_coherence(&before, &changed, 3).is_err());
        changed = before.clone();
        changed.ctime_nsec += 1;
        assert!(verify_hash_coherence(&before, &changed, 3).is_err());
    }

    #[test]
    fn generated_cache_artifacts_become_read_only_for_measurement() {
        let root = temp_dir("cache-read-only");
        let root_fd = test_root(&root);
        let layout = create_experiment_layout(&root_fd, 1).unwrap();
        let cache = &layout.pairs[0].fp32.cache;
        write_atomic_at(cache, Path::new("compiled.mxr"), b"cache").unwrap();
        let generated = inventory_cache(cache).unwrap();
        let readonly = make_cache_artifacts_read_only(cache, &generated).unwrap();
        assert_eq!(readonly[0].mode, 0o400);
        verify_cache_inventory(cache, &readonly).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                openat2_file(
                    cache.as_raw_fd(),
                    Path::new("compiled.mxr"),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                    0,
                )
                .is_err()
            );
        }
        drop(layout);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn provider_stack_absence_and_digest_mismatch_fail() {
        let expected = test_provider_stack();
        validate_provider_stack(&expected).unwrap();
        let mut absent = expected.clone();
        absent.has_hip = false;
        assert!(validate_provider_stack(&absent).is_err());
        let mut mismatch = expected.clone();
        mismatch.libraries[0].sha256 = "2".repeat(64);
        assert!(verify_provider_stack_match(&expected, &mismatch).is_err());
    }

    #[test]
    fn recognizer_and_enrolled_matching_timings_are_separate() {
        let record = ImageRecord {
            index: 0,
            class: FixtureClass::Positive,
            decode_ms: 1.0,
            detector_pipeline_ms: 2.0,
            recognizer_pipeline_ms: 3.0,
            enrolled_matching_ms: 4.0,
            complete_fixture_ms: 10.0,
            faces: Vec::new(),
        };
        let report = timing_report(&[record]);
        assert_eq!(report.recognizer_alignment_run_ms.mean, 3.0);
        assert_eq!(report.enrolled_matching_ms.mean, 4.0);
    }
}
