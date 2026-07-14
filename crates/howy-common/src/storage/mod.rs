//! Frozen storage records, pure HOWYENC1/HOWYPLN1 codecs, and backend contracts.
//!
//! These types are deliberately independent of the legacy serde/bincode face
//! structs. Authorization, NSS lookup, and concrete filesystem transactions
//! live in later layers; this module validates records and defines the shared
//! synchronous storage/lease interfaces.

mod codec;
mod contracts;
mod crypto;
mod legacy;
mod namespace;

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, Write};

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::config::EmbeddingSecurityMode;

pub use codec::{
    EncryptedHeader, HOWYENC1_FIXED_INSPECTION_BYTES, HOWYENC1_MAX_INSPECTION_BYTES,
    HOWYENC1_MAX_RECORD_BYTES, HOWYPLN1_FIXED_INSPECTION_BYTES, HOWYPLN1_MAX_INSPECTION_BYTES,
    PlaintextHeaderInspection, decode_canonical_payload, decode_howyenc1, decode_howypln1,
    encode_canonical_payload, encode_howyenc1, encode_howypln1, inspect_howyenc1,
    inspect_howyenc1_metadata, inspect_howypln1_metadata,
};
pub use contracts::{
    ABSENT_GENERATION, AppendAdmissionShape, AppendRequest, AppendResult, AuthModel,
    AuthenticationCachePromotion, AuthenticationLoad, BackendHealth, BackendUnavailable,
    BudgetPermit, CachedAuthModel, CancellationSignal, CandidatePresence, ClearRequest,
    ClearResult, EnrollmentAdmission, EnrollmentMetadata, IoOperation, LeaseKind, MetadataList,
    ModelLease, OuterRecordClassification, OuterRecordStatus, PlaintextAllocationEstimate,
    PlaintextBudget, PromptOpaqueIdentity, PromptStorageSnapshot, ReloadResult, RemoveRequest,
    RemoveResult, StorageBackend, StorageBackendError, StorageIoError, StorageOperation,
};
pub use crypto::{NonceGenerator, OsRandomSource, RandomSource};
pub(crate) use crypto::{decrypt_aes_256_gcm, encrypt_aes_256_gcm};
pub use legacy::{
    DecodedPlaintextRecord, LegacyGenerationHasher, LegacySourceEncoding, PlaintextRecordFormat,
    checked_next_generation, decode_plaintext_record, generate_enrollment_id, legacy_enrollment_id,
    legacy_generation, recognizer_model_digest,
};
pub use namespace::{
    ALL_RECORD_NAMESPACES, NamespaceActivity, NamespaceRecordPaths, NamespaceSelection,
    PurgeTarget, RecordCondition, RecordIncompatibility, RecordInventory, RecordNamespace,
    RecordPath, RecordPathKind, STORAGE_DIRECTORY_MODE, STORAGE_RECORD_MODE, TransitionActivation,
    TransitionDecision, TransitionFilesystemEffects, decide_namespace_transition,
};

pub const EMBEDDING_DIMENSION: usize = 512;
pub const MAX_ENTRIES: usize = 1_000;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_PLAINTEXT_BYTES: usize = 2_621_440;
pub const AES_256_KEY_BYTES: usize = 32;
pub const GCM_NONCE_BYTES: usize = 12;
pub const GCM_TAG_BYTES: usize = 16;
pub(crate) const CANONICAL_PAYLOAD_FIXED_BYTES: usize = 8;
pub(crate) const CANONICAL_ENTRY_FIXED_BYTES: usize =
    16 + 8 + 2 + 2 + EMBEDDING_DIMENSION * size_of::<f32>();

pub type Aes256Key = [u8; AES_256_KEY_BYTES];
pub type GcmNonce = [u8; GCM_NONCE_BYTES];
pub type GcmTag = [u8; GCM_TAG_BYTES];

/// Serialized biometric plaintext with zeroizing ownership and redacted formatting.
///
/// Bytes are exposed only through explicit access or a consuming write. The
/// value intentionally does not implement cloning, display, serde, or slice
/// dereferencing so routine formatting and copying cannot expose the payload.
pub struct SensitiveBytes {
    bytes: Zeroizing<Box<[u8]>>,
}

impl SensitiveBytes {
    pub(crate) fn from_zeroizing(mut bytes: Zeroizing<Vec<u8>>) -> Self {
        let exact = if bytes.capacity() == bytes.len() {
            std::mem::take(&mut *bytes).into_boxed_slice()
        } else {
            let exact = Box::<[u8]>::from(bytes.as_slice());
            bytes.zeroize();
            exact
        };
        Self {
            bytes: Zeroizing::new(exact),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Write the complete payload, then zeroize its allocation on return.
    ///
    /// The allocation is also zeroized if the writer returns an error after a
    /// partial write.
    pub fn write_to<W: Write + ?Sized>(self, writer: &mut W) -> io::Result<()> {
        writer.write_all(self.as_slice())
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("len", &self.len())
            .finish()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StorageError {
    #[error("canonical username must be 1..64 ASCII bytes matching [A-Za-z0-9._-]+")]
    InvalidUsername,
    #[error("invalid {format} magic")]
    InvalidMagic { format: &'static str },
    #[error("unsupported {format} version {version}")]
    UnsupportedVersion { format: &'static str, version: u16 },
    #[error("unsupported HOWYENC1 algorithm {0}")]
    UnsupportedAlgorithm(u16),
    #[error("unsupported encrypted storage mode {0}")]
    UnsupportedMode(u8),
    #[error("embedding security mode {0} has no supported storage namespace")]
    UnsupportedNamespaceMode(u8),
    #[error("unknown {format} flags 0x{flags:x}")]
    UnknownFlags { format: &'static str, flags: u16 },
    #[error("invalid {format} reserved field")]
    InvalidReserved { format: &'static str },
    #[error("invalid {format} length")]
    InvalidLength { format: &'static str },
    #[error("{field} exceeds the frozen v1 limit")]
    LimitExceeded { field: &'static str },
    #[error("integer overflow while processing {0}")]
    IntegerOverflow(&'static str),
    #[error("unable to allocate bounded {0}")]
    AllocationFailed(&'static str),
    #[error("record generation must be at least 1")]
    InvalidGeneration,
    #[error("key epoch must be at least 1")]
    InvalidEpoch,
    #[error("embedding dimension must be 512, got {0}")]
    InvalidEmbeddingDimension(u16),
    #[error("header and payload entry counts differ")]
    EntryCountMismatch,
    #[error("enrollment ID must be nonzero")]
    ZeroEnrollmentId,
    #[error("duplicate enrollment ID")]
    DuplicateEnrollmentId,
    #[error("label is not valid UTF-8")]
    InvalidLabelUtf8,
    #[error("embedding contains a NaN or infinite value")]
    NonFiniteEmbedding,
    #[error("record {0} does not match the expected binding")]
    BindingMismatch(&'static str),
    #[error("AES-256-GCM authentication failed")]
    AuthenticationFailed,
    #[error("random source failed: {0}")]
    RandomSource(String),
    #[error("random source returned a duplicate nonce")]
    DuplicateNonce,
    #[error("invalid nonce write ceiling")]
    InvalidNonceCeiling,
    #[error("v1 per-key encryption write ceiling reached")]
    NonceWriteLimitExceeded,
    #[error("record generation overflow")]
    GenerationOverflow,
    #[error("legacy enrollment record could not be decoded")]
    InvalidLegacyRecord,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalUsername(String);

impl CanonicalUsername {
    pub fn new(username: impl Into<String>) -> Result<Self, StorageError> {
        let username = username.into();
        if !crate::paths::is_canonical_username(&username) {
            return Err(StorageError::InvalidUsername);
        }
        Ok(Self(username))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for CanonicalUsername {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalUsername")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalUsername {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for CanonicalUsername {
    type Error = StorageError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModelDigest([u8; 32]);

impl ModelDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnrollmentId([u8; 16]);

impl EnrollmentId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, StorageError> {
        if bytes == [0; 16] {
            return Err(StorageError::ZeroEnrollmentId);
        }
        Ok(Self(bytes))
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, PartialEq)]
pub struct EnrollmentEntry {
    enrollment_id: EnrollmentId,
    created_unix_seconds: u64,
    label: Zeroizing<Box<str>>,
    embedding: Zeroizing<[f32; EMBEDDING_DIMENSION]>,
}

impl EnrollmentEntry {
    pub fn new(
        enrollment_id: EnrollmentId,
        created_unix_seconds: u64,
        label: impl Into<String>,
        embedding: [f32; EMBEDDING_DIMENSION],
    ) -> Result<Self, StorageError> {
        // Protect the fixed embedding before a custom label conversion can
        // panic, then transfer both wrappers unchanged into final ownership.
        let embedding = Zeroizing::new(embedding);
        let label = Zeroizing::new(label.into().into_boxed_str());
        Self::new_zeroizing_fields(enrollment_id, created_unix_seconds, label, embedding)
    }

    pub(crate) fn new_zeroizing_fields(
        enrollment_id: EnrollmentId,
        created_unix_seconds: u64,
        label: Zeroizing<Box<str>>,
        embedding: Zeroizing<[f32; EMBEDDING_DIMENSION]>,
    ) -> Result<Self, StorageError> {
        let entry = Self {
            enrollment_id,
            created_unix_seconds,
            label,
            embedding,
        };
        if entry.label.len() > MAX_LABEL_BYTES {
            return Err(StorageError::LimitExceeded { field: "label" });
        }
        if entry.embedding.iter().any(|value| !value.is_finite()) {
            return Err(StorageError::NonFiniteEmbedding);
        }
        Ok(entry)
    }

    pub fn try_from_embedding_vec(
        enrollment_id: EnrollmentId,
        created_unix_seconds: u64,
        label: impl Into<String>,
        embedding: Vec<f32>,
    ) -> Result<Self, StorageError> {
        let embedding = zeroize::Zeroizing::new(embedding);
        let actual = embedding.len();
        if actual != EMBEDDING_DIMENSION {
            return Err(StorageError::InvalidEmbeddingDimension(
                u16::try_from(actual).unwrap_or(u16::MAX),
            ));
        }
        let mut fixed = Zeroizing::new([0.0; EMBEDDING_DIMENSION]);
        fixed.copy_from_slice(&embedding);
        let label = Zeroizing::new(label.into().into_boxed_str());
        Self::new_zeroizing_fields(enrollment_id, created_unix_seconds, label, fixed)
    }

    pub const fn enrollment_id(&self) -> EnrollmentId {
        self.enrollment_id
    }

    pub const fn created_unix_seconds(&self) -> u64 {
        self.created_unix_seconds
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn embedding(&self) -> &[f32; EMBEDDING_DIMENSION] {
        &self.embedding
    }

    pub fn plaintext_allocation_bytes(&self) -> usize {
        size_of::<Self>() + self.label.len()
    }
}

impl fmt::Debug for EnrollmentEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentEntry")
            .field("enrollment_id", &self.enrollment_id)
            .field("created_unix_seconds", &self.created_unix_seconds)
            .field("label_bytes", &self.label.len())
            .field("embedding_dimension", &EMBEDDING_DIMENSION)
            .finish_non_exhaustive()
    }
}

impl Zeroize for EnrollmentEntry {
    fn zeroize(&mut self) {
        self.label.zeroize();
        self.embedding.zeroize();
    }
}

impl Drop for EnrollmentEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq)]
pub struct EnrollmentRecord {
    generation: u64,
    recognizer_model_sha256: ModelDigest,
    username: CanonicalUsername,
    entries: Box<[EnrollmentEntry]>,
}

impl fmt::Debug for EnrollmentRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentRecord")
            .field("generation", &self.generation)
            .field("recognizer_model_sha256", &self.recognizer_model_sha256)
            .field("username", &self.username)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl EnrollmentRecord {
    pub fn new(
        generation: u64,
        recognizer_model_sha256: ModelDigest,
        username: CanonicalUsername,
        entries: Vec<EnrollmentEntry>,
    ) -> Result<Self, StorageError> {
        Self::from_boxed_entries(
            generation,
            recognizer_model_sha256,
            username,
            entries.into_boxed_slice(),
        )
    }

    /// Construct a record from exact-capacity entry ownership. Mode 1 decode
    /// and mutation paths use this to avoid retained `Vec` spare capacity.
    pub fn from_boxed_entries(
        generation: u64,
        recognizer_model_sha256: ModelDigest,
        username: CanonicalUsername,
        entries: Box<[EnrollmentEntry]>,
    ) -> Result<Self, StorageError> {
        if generation == 0 {
            return Err(StorageError::InvalidGeneration);
        }
        if entries.len() > MAX_ENTRIES {
            return Err(StorageError::LimitExceeded {
                field: "entry count",
            });
        }
        if entries.iter().enumerate().any(|(index, entry)| {
            entries[..index]
                .iter()
                .any(|prior| prior.enrollment_id() == entry.enrollment_id())
        }) {
            return Err(StorageError::DuplicateEnrollmentId);
        }
        Ok(Self {
            generation,
            recognizer_model_sha256,
            username,
            entries,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn recognizer_model_sha256(&self) -> ModelDigest {
        self.recognizer_model_sha256
    }

    pub fn username(&self) -> &CanonicalUsername {
        &self.username
    }

    pub fn entries(&self) -> &[EnrollmentEntry] {
        &self.entries
    }

    /// Exact sensitive heap ownership: one boxed entry slice plus exact boxed
    /// label bytes. Embeddings are inline in each entry.
    pub fn plaintext_allocation_bytes(&self) -> usize {
        self.entries.iter().fold(0usize, |bytes, entry| {
            bytes.saturating_add(entry.plaintext_allocation_bytes())
        })
    }

    /// Consume a decoded record while retaining its zeroizing entry ownership.
    ///
    /// Mutation backends use this to avoid simultaneously allocating duplicate
    /// old and replacement records under the plaintext-memory budget.
    pub fn into_entries(mut self) -> Vec<EnrollmentEntry> {
        std::mem::take(&mut self.entries).into_vec()
    }
}

impl Zeroize for EnrollmentRecord {
    fn zeroize(&mut self) {
        self.entries.zeroize();
    }
}

impl Drop for EnrollmentRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StorageMode {
    AeadCached = 1,
    AeadEphemeral = 2,
}

impl StorageMode {
    pub const fn identifier(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for StorageMode {
    type Error = StorageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AeadCached),
            2 => Ok(Self::AeadEphemeral),
            _ => Err(StorageError::UnsupportedMode(value)),
        }
    }
}

impl TryFrom<EmbeddingSecurityMode> for StorageMode {
    type Error = StorageError;

    fn try_from(value: EmbeddingSecurityMode) -> Result<Self, Self::Error> {
        match value {
            EmbeddingSecurityMode::AeadCached => Ok(Self::AeadCached),
            EmbeddingSecurityMode::AeadEphemeral => Ok(Self::AeadEphemeral),
            other => Err(StorageError::UnsupportedMode(other as u8)),
        }
    }
}
