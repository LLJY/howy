//! Synchronous storage, lease, and plaintext-memory accounting contracts.
//!
//! Callers perform authorization and NSS canonicalization before invoking a
//! backend. Backends are responsible only for storage semantics and operate on
//! [`CanonicalUsername`] values.

use std::fmt;
use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::{
    CANONICAL_ENTRY_FIXED_BYTES, CANONICAL_PAYLOAD_FIXED_BYTES, CanonicalUsername,
    EMBEDDING_DIMENSION, EncryptedHeader, EnrollmentEntry, EnrollmentId, EnrollmentRecord,
    GCM_TAG_BYTES, MAX_ENTRIES, MAX_LABEL_BYTES, MAX_PLAINTEXT_BYTES, ModelDigest,
};

/// Generation used when no record exists. The first successful append advances it to one.
pub const ABSENT_GENERATION: u64 = 0;

/// Conservative allocation contract for a decrypt/decode/flatten transaction.
///
/// Backends reserve [`Self::cold_load_peak_bytes`] for authentication loads and
/// [`Self::mutation_peak_bytes`] for transforms. The mutation peak explicitly
/// accounts for the canonical plaintext buffer and the separate AEAD in-place
/// staging allocation which coexist during encryption, plus the decoded record
/// (including label allocations) and flat authentication model. Concrete
/// backends enforce the reservation later. [`Self::peak_bytes`] remains a
/// compatibility alias for the mutation peak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextAllocationEstimate {
    encoded_payload_bytes: usize,
    aead_staging_bytes: usize,
    source_decoded_record_bytes: usize,
    decoded_record_bytes: usize,
    flat_auth_model_bytes: usize,
    cold_load_peak_bytes: usize,
    mutation_peak_bytes: usize,
    peak_bytes: usize,
}

impl PlaintextAllocationEstimate {
    /// Conservative admission estimate for a bounded plaintext source before
    /// its entry count is trusted. The possible count is clamped to what can
    /// physically fit in the configured payload byte limit.
    pub fn for_plaintext_limits(
        max_payload_bytes: usize,
        configured_max_entries: usize,
    ) -> Result<Self, StorageBackendError> {
        if max_payload_bytes > MAX_PLAINTEXT_BYTES || configured_max_entries > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("plaintext limits"));
        }
        let possible_entries = max_payload_bytes.saturating_sub(CANONICAL_PAYLOAD_FIXED_BYTES)
            / CANONICAL_ENTRY_FIXED_BYTES;
        let entry_count = configured_max_entries.min(possible_entries);
        let entry_count = u32::try_from(entry_count)
            .map_err(|_| StorageBackendError::InvalidInput("entry count"))?;
        Self::from_payload_shape(max_payload_bytes, entry_count)
    }

    /// Estimate from an already bounded outer header, before AEAD allocation.
    pub fn for_encrypted_header(header: &EncryptedHeader) -> Result<Self, StorageBackendError> {
        Self::from_payload_shape(header.plaintext_length(), header.entry_count())
    }

    /// Exact estimate for encoding or transforming an in-memory record.
    pub fn for_record(record: &EnrollmentRecord) -> Result<Self, StorageBackendError> {
        let entry_count = u32::try_from(record.entries().len())
            .map_err(|_| StorageBackendError::InvalidInput("entry count"))?;
        let labels = record
            .entries()
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(entry.label().len())
            })
            .ok_or(StorageBackendError::InvalidInput("record byte length"))?;
        let fixed_entries = record
            .entries()
            .len()
            .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
            .ok_or(StorageBackendError::InvalidInput("record byte length"))?;
        let payload_bytes = CANONICAL_PAYLOAD_FIXED_BYTES
            .checked_add(fixed_entries)
            .and_then(|bytes| bytes.checked_add(labels))
            .ok_or(StorageBackendError::InvalidInput("record byte length"))?;
        Self::from_payload_shape(payload_bytes, entry_count)
    }

    /// Estimate an already-validated logical payload shape. Concrete backends
    /// use this after descriptor-bound header inspection and before reserving
    /// mutation memory.
    pub fn for_payload_shape(
        payload_bytes: usize,
        entry_count: usize,
    ) -> Result<Self, StorageBackendError> {
        let entry_count = u32::try_from(entry_count)
            .map_err(|_| StorageBackendError::InvalidInput("entry count"))?;
        Self::from_payload_shape(payload_bytes, entry_count)
    }

    /// Exact logical shape after appending bounded entries to an inspected
    /// encrypted record (or creating a new record when `current` is absent).
    pub fn for_append_shape(
        current: Option<&EncryptedHeader>,
        new_entries: usize,
        new_label_bytes: usize,
    ) -> Result<Self, StorageBackendError> {
        if new_entries == 0 || new_entries > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("append entry count"));
        }
        let maximum_labels = new_entries
            .checked_mul(MAX_LABEL_BYTES)
            .ok_or(StorageBackendError::InvalidInput("append label bytes"))?;
        if new_label_bytes > maximum_labels {
            return Err(StorageBackendError::InvalidInput("append label bytes"));
        }
        let current_entries = current
            .map(|header| usize::try_from(header.entry_count()))
            .transpose()
            .map_err(|_| StorageBackendError::InvalidInput("entry count"))?
            .unwrap_or(0);
        let entry_count = current_entries
            .checked_add(new_entries)
            .ok_or(StorageBackendError::InvalidInput("entry count"))?;
        if entry_count > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("entry count"));
        }
        let current_payload = current
            .map(EncryptedHeader::plaintext_length)
            .unwrap_or(CANONICAL_PAYLOAD_FIXED_BYTES);
        let payload_bytes = new_entries
            .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
            .and_then(|bytes| bytes.checked_add(new_label_bytes))
            .and_then(|bytes| bytes.checked_add(current_payload))
            .ok_or(StorageBackendError::InvalidInput("payload byte length"))?;
        let mut estimate = Self::for_payload_shape(payload_bytes, entry_count)?;
        if let Some(current) = current {
            let source = Self::for_encrypted_header(current)?;
            estimate.source_decoded_record_bytes = source.decoded_record_bytes;
            estimate.mutation_peak_bytes = estimate
                .mutation_peak_bytes
                .checked_add(source.decoded_record_bytes)
                .ok_or(StorageBackendError::InvalidInput(
                    "plaintext mutation byte length",
                ))?;
            estimate.peak_bytes = estimate.mutation_peak_bytes;
        }
        Ok(estimate)
    }

    /// Conservative exact-capacity replacement estimate when the removed
    /// entry's label length is not known until after authenticated decode. The
    /// final record is bounded by the current record shape, and source+final
    /// entry owners are both charged while the replacement is constructed.
    pub fn for_replacement_of_encrypted_header(
        current: &EncryptedHeader,
    ) -> Result<Self, StorageBackendError> {
        let mut estimate = Self::for_encrypted_header(current)?;
        estimate.source_decoded_record_bytes = estimate.decoded_record_bytes;
        estimate.mutation_peak_bytes = estimate
            .mutation_peak_bytes
            .checked_add(estimate.source_decoded_record_bytes)
            .ok_or(StorageBackendError::InvalidInput(
                "plaintext mutation byte length",
            ))?;
        estimate.peak_bytes = estimate.mutation_peak_bytes;
        Ok(estimate)
    }

    fn from_payload_shape(
        payload_bytes: usize,
        entry_count: u32,
    ) -> Result<Self, StorageBackendError> {
        if payload_bytes > MAX_PLAINTEXT_BYTES {
            return Err(StorageBackendError::InvalidInput("payload byte length"));
        }
        let entry_count = usize::try_from(entry_count)
            .map_err(|_| StorageBackendError::InvalidInput("entry count"))?;
        if entry_count > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("entry count"));
        }
        let fixed_payload = entry_count
            .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
            .and_then(|bytes| bytes.checked_add(CANONICAL_PAYLOAD_FIXED_BYTES))
            .ok_or(StorageBackendError::InvalidInput("payload byte length"))?;
        let label_bytes = payload_bytes
            .checked_sub(fixed_payload)
            .ok_or(StorageBackendError::InvalidInput("payload byte length"))?;
        let decoded_record_bytes = entry_count
            .checked_mul(size_of::<EnrollmentEntry>())
            .and_then(|bytes| bytes.checked_add(label_bytes))
            .ok_or(StorageBackendError::InvalidInput("record byte length"))?;
        let flat_auth_model_bytes = auth_model_allocation_bytes(entry_count, label_bytes)?;
        let aead_staging_bytes =
            payload_bytes
                .checked_add(GCM_TAG_BYTES)
                .ok_or(StorageBackendError::InvalidInput(
                    "AEAD staging byte length",
                ))?;
        // Ciphertext, the public header, and AAD are deliberately outside the
        // plaintext budget. During a cold decrypt the AEAD staging allocation
        // becomes plaintext and overlaps the decoded record; flattening starts
        // only after that staging owner has been dropped. Mutation encoding has
        // the larger simultaneous final-record shape below; append/replacement
        // constructors add the still-live authenticated source record.
        let decrypt_and_decode = aead_staging_bytes.checked_add(decoded_record_bytes).ok_or(
            StorageBackendError::InvalidInput("plaintext cold-load byte length"),
        )?;
        let decode_and_flatten = decoded_record_bytes
            .checked_add(flat_auth_model_bytes)
            .ok_or(StorageBackendError::InvalidInput(
                "plaintext cold-load byte length",
            ))?;
        let cold_load_peak_bytes = decrypt_and_decode.max(decode_and_flatten);
        let mutation_peak_bytes = decoded_record_bytes
            .checked_add(flat_auth_model_bytes)
            .and_then(|bytes| bytes.checked_add(payload_bytes))
            .and_then(|bytes| bytes.checked_add(aead_staging_bytes))
            .ok_or(StorageBackendError::InvalidInput(
                "plaintext peak byte length",
            ))?;
        Ok(Self {
            encoded_payload_bytes: payload_bytes,
            aead_staging_bytes,
            source_decoded_record_bytes: 0,
            decoded_record_bytes,
            flat_auth_model_bytes,
            cold_load_peak_bytes,
            mutation_peak_bytes,
            peak_bytes: mutation_peak_bytes,
        })
    }

    pub const fn encoded_payload_bytes(self) -> usize {
        self.encoded_payload_bytes
    }

    pub const fn decoded_record_bytes(self) -> usize {
        self.decoded_record_bytes
    }

    pub const fn source_decoded_record_bytes(self) -> usize {
        self.source_decoded_record_bytes
    }

    pub const fn aead_staging_bytes(self) -> usize {
        self.aead_staging_bytes
    }

    pub const fn flat_auth_model_bytes(self) -> usize {
        self.flat_auth_model_bytes
    }

    pub const fn cold_load_peak_bytes(self) -> usize {
        self.cold_load_peak_bytes
    }

    pub const fn mutation_peak_bytes(self) -> usize {
        self.mutation_peak_bytes
    }

    pub const fn peak_bytes(self) -> usize {
        self.peak_bytes
    }
}

fn auth_model_allocation_bytes(
    entry_count: usize,
    label_bytes: usize,
) -> Result<usize, StorageBackendError> {
    entry_count
        .checked_mul(EMBEDDING_DIMENSION)
        .and_then(|values| values.checked_mul(size_of::<f32>()))
        .and_then(|bytes| {
            entry_count
                .checked_mul(size_of::<EnrollmentId>())
                .and_then(|id_bytes| bytes.checked_add(id_bytes))
        })
        .and_then(|bytes| {
            entry_count
                .checked_mul(size_of::<Zeroizing<Box<str>>>())
                .and_then(|label_owner_bytes| bytes.checked_add(label_owner_bytes))
        })
        .and_then(|bytes| bytes.checked_add(label_bytes))
        .ok_or(StorageBackendError::InvalidInput("model byte length"))
}

/// Stable operation names for policy-independent dispatch and instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageOperation {
    CandidatePresence,
    Authenticate,
    ListMetadata,
    Append,
    Remove,
    Clear,
    Reload,
    Health,
    VerifyRecord,
}

/// Storage I/O phases. This intentionally cannot contain a path or OS error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    Inspect,
    Open,
    Read,
    Create,
    Write,
    Sync,
    Rename,
    Remove,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inspect => "inspect",
            Self::Open => "open",
            Self::Read => "read",
            Self::Create => "create",
            Self::Write => "write",
            Self::Sync => "sync",
            Self::Rename => "rename",
            Self::Remove => "remove",
        })
    }
}

/// Sanitized I/O failure retaining only the operation class and [`io::ErrorKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("storage I/O {operation} failed ({kind:?})")]
pub struct StorageIoError {
    operation: IoOperation,
    kind: io::ErrorKind,
}

impl StorageIoError {
    pub fn new(operation: IoOperation, error: &io::Error) -> Self {
        Self {
            operation,
            kind: error.kind(),
        }
    }

    pub const fn operation(self) -> IoOperation {
        self.operation
    }

    pub const fn kind(self) -> io::ErrorKind {
        self.kind
    }
}

/// Errors shared by all storage modes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StorageBackendError {
    #[error("enrollment record is absent")]
    Absent,
    #[error("storage generation conflict (current generation {current_generation})")]
    Conflict { current_generation: u64 },
    #[error("storage mode mismatch")]
    ModeMismatch,
    #[error("storage key or key epoch mismatch")]
    KeyMismatch,
    #[error("recognizer model mismatch")]
    ModelMismatch,
    #[error("storage record is corrupt")]
    Corrupt,
    #[error("storage record authentication failed")]
    AuthenticationFailed,
    #[error("storage record generation overflow")]
    GenerationOverflow,
    #[error("storage backend is unavailable")]
    Unavailable,
    #[error(
        "plaintext memory budget exceeded (requested {requested} bytes, {available} available)"
    )]
    MemoryBudgetExceeded { requested: usize, available: usize },
    #[error("invalid storage input: {0}")]
    InvalidInput(&'static str),
    #[error(transparent)]
    Io(#[from] StorageIoError),
}

/// Public readiness classification. It does not inspect or authenticate a user record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    Ready,
    Unavailable(BackendUnavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendUnavailable {
    NotInitialized,
    KeyUnavailable,
    PermissionDenied,
    Io,
    Integrity,
}

/// A syntactically valid record candidate discovered without authenticating plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePresence {
    Absent,
    Candidate { generation: u64 },
}

/// Fixed-size opaque identity used by prompt transaction snapshots.
///
/// Backends bind this to the live backend/key instance, not a configured key
/// name or path. Formatting is deliberately redacted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PromptOpaqueIdentity([u8; 32]);

impl PromptOpaqueIdentity {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for PromptOpaqueIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptOpaqueIdentity([REDACTED])")
    }
}

/// One backend-linearized prompt preflight snapshot.
///
/// Implementations capture readiness, candidate generation, live backend/key
/// identity, and storage-policy generation while holding the same lock that
/// serializes relevant mutations. A mutation after this method returns is
/// logically post-snapshot and therefore post-commit when this snapshot is used
/// for final Commit promotion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PromptStorageSnapshot {
    health: BackendHealth,
    candidate: CandidatePresence,
    backend_identity: PromptOpaqueIdentity,
    policy_generation: PromptOpaqueIdentity,
}

impl PromptStorageSnapshot {
    pub const fn new(
        health: BackendHealth,
        candidate: CandidatePresence,
        backend_identity: PromptOpaqueIdentity,
        policy_generation: PromptOpaqueIdentity,
    ) -> Self {
        Self {
            health,
            candidate,
            backend_identity,
            policy_generation,
        }
    }

    pub const fn health(self) -> BackendHealth {
        self.health
    }

    pub const fn candidate(self) -> CandidatePresence {
        self.candidate
    }

    pub const fn backend_identity(self) -> PromptOpaqueIdentity {
        self.backend_identity
    }

    pub const fn policy_generation(self) -> PromptOpaqueIdentity {
        self.policy_generation
    }
}

impl fmt::Debug for PromptStorageSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptStorageSnapshot")
            .field("health", &self.health)
            .field("candidate", &self.candidate)
            .field("backend_identity", &self.backend_identity)
            .field("policy_generation", &self.policy_generation)
            .finish()
    }
}

impl CandidatePresence {
    pub const fn generation(self) -> u64 {
        match self {
            Self::Absent => ABSENT_GENERATION,
            Self::Candidate { generation } => generation,
        }
    }
}

/// Reload-time classification based on backend readiness and bounded outer inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterRecordClassification {
    Candidate { generation: u64 },
    ModeMismatch,
    KeyMismatch,
    ModelMismatch,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterRecordStatus {
    username: CanonicalUsername,
    classification: OuterRecordClassification,
}

impl OuterRecordStatus {
    pub fn new(username: CanonicalUsername, classification: OuterRecordClassification) -> Self {
        Self {
            username,
            classification,
        }
    }

    pub fn username(&self) -> &CanonicalUsername {
        &self.username
    }

    pub const fn classification(&self) -> OuterRecordClassification {
        self.classification
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadResult {
    health: BackendHealth,
    records: Vec<OuterRecordStatus>,
}

impl ReloadResult {
    pub fn new(health: BackendHealth, records: Vec<OuterRecordStatus>) -> Self {
        Self { health, records }
    }

    pub const fn health(&self) -> BackendHealth {
        self.health
    }

    pub fn records(&self) -> &[OuterRecordStatus] {
        &self.records
    }
}

/// Non-secret enrollment information returned by list and authenticated verify.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentMetadata {
    enrollment_id: EnrollmentId,
    label: Zeroizing<String>,
    created_unix_seconds: u64,
    generation: u64,
}

impl EnrollmentMetadata {
    fn from_entry(entry: &EnrollmentEntry, generation: u64) -> Self {
        Self {
            enrollment_id: entry.enrollment_id(),
            label: Zeroizing::new(entry.label().to_owned()),
            created_unix_seconds: entry.created_unix_seconds(),
            generation,
        }
    }

    pub const fn enrollment_id(&self) -> EnrollmentId {
        self.enrollment_id
    }

    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    pub const fn created_unix_seconds(&self) -> u64 {
        self.created_unix_seconds
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for EnrollmentMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentMetadata")
            .field("enrollment_id", &self.enrollment_id)
            .field("label_bytes", &self.label.len())
            .field("created_unix_seconds", &self.created_unix_seconds)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataList {
    generation: u64,
    entries: Vec<EnrollmentMetadata>,
}

impl MetadataList {
    pub fn from_record(record: &EnrollmentRecord) -> Self {
        Self {
            generation: record.generation(),
            entries: record
                .entries()
                .iter()
                .map(|entry| EnrollmentMetadata::from_entry(entry, record.generation()))
                .collect(),
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn entries(&self) -> &[EnrollmentMetadata] {
        &self.entries
    }
}

/// Pre-validated, contiguous authentication model compatible with cosine matching.
///
/// Labels and embeddings retain exact-capacity zeroizing boxed ownership from
/// validation through final lease drop; IDs are non-secret.
pub struct AuthModel {
    generation: u64,
    model_digest: ModelDigest,
    dimension: usize,
    enrollment_ids: Box<[EnrollmentId]>,
    labels: Box<[Zeroizing<Box<str>>]>,
    flat_embeddings: Zeroizing<Box<[f32]>>,
    plaintext_bytes: usize,
}

impl AuthModel {
    pub fn new(
        generation: u64,
        model_digest: ModelDigest,
        dimension: usize,
        enrollment_ids: Vec<EnrollmentId>,
        labels: Vec<String>,
        flat_embeddings: Vec<f32>,
    ) -> Result<Self, StorageBackendError> {
        // Establish exact-capacity, zeroizing ownership before validation. The
        // public Vec-based compatibility API may receive spare capacity, so it
        // copies into boxed storage and wipes the caller allocation.
        let mut labels = Zeroizing::new(labels);
        let exact_labels = labels
            .iter()
            .map(|label| Zeroizing::new(Box::<str>::from(label.as_str())))
            .collect::<Vec<_>>();
        debug_assert_eq!(exact_labels.capacity(), exact_labels.len());
        let exact_labels = exact_labels.into_boxed_slice();
        labels.zeroize();
        let mut flat_embeddings = Zeroizing::new(flat_embeddings);
        let exact_embeddings = Zeroizing::new(Box::<[f32]>::from(flat_embeddings.as_slice()));
        flat_embeddings.zeroize();
        Self::new_exact(
            generation,
            model_digest,
            dimension,
            enrollment_ids.into_boxed_slice(),
            exact_labels,
            exact_embeddings,
        )
    }

    fn new_exact(
        generation: u64,
        model_digest: ModelDigest,
        dimension: usize,
        enrollment_ids: Box<[EnrollmentId]>,
        labels: Box<[Zeroizing<Box<str>>]>,
        flat_embeddings: Zeroizing<Box<[f32]>>,
    ) -> Result<Self, StorageBackendError> {
        let plaintext_bytes = (|| {
            if generation == ABSENT_GENERATION {
                return Err(StorageBackendError::InvalidInput("generation"));
            }
            if dimension != EMBEDDING_DIMENSION {
                return Err(StorageBackendError::InvalidInput("embedding dimension"));
            }
            if enrollment_ids.len() != labels.len() {
                return Err(StorageBackendError::InvalidInput("model metadata count"));
            }
            if enrollment_ids.len() > MAX_ENTRIES {
                return Err(StorageBackendError::InvalidInput("entry count"));
            }
            let embedding_count = enrollment_ids
                .len()
                .checked_mul(dimension)
                .ok_or(StorageBackendError::InvalidInput("embedding count"))?;
            if flat_embeddings.len() != embedding_count {
                return Err(StorageBackendError::InvalidInput("flat embedding length"));
            }
            if flat_embeddings.iter().any(|value| !value.is_finite()) {
                return Err(StorageBackendError::InvalidInput("non-finite embedding"));
            }
            if labels.iter().any(|label| label.len() > MAX_LABEL_BYTES) {
                return Err(StorageBackendError::InvalidInput("label"));
            }
            if enrollment_ids
                .iter()
                .enumerate()
                .any(|(index, id)| enrollment_ids[..index].contains(id))
            {
                return Err(StorageBackendError::InvalidInput("duplicate enrollment ID"));
            }

            let label_bytes = labels
                .iter()
                .try_fold(0usize, |total, label| total.checked_add(label.len()))
                .ok_or(StorageBackendError::InvalidInput("model byte length"))?;
            auth_model_allocation_bytes(enrollment_ids.len(), label_bytes)
        })()?;

        Ok(Self {
            generation,
            model_digest,
            dimension,
            enrollment_ids,
            labels,
            flat_embeddings,
            plaintext_bytes,
        })
    }

    pub fn from_record(record: &EnrollmentRecord) -> Result<Self, StorageBackendError> {
        let ids = record
            .entries()
            .iter()
            .map(EnrollmentEntry::enrollment_id)
            .collect::<Vec<_>>();
        debug_assert_eq!(ids.capacity(), ids.len());
        let ids = ids.into_boxed_slice();
        let labels = record
            .entries()
            .iter()
            .map(|entry| Zeroizing::new(Box::<str>::from(entry.label())))
            .collect::<Vec<_>>();
        debug_assert_eq!(labels.capacity(), labels.len());
        let labels = labels.into_boxed_slice();
        let embedding_count = record
            .entries()
            .len()
            .checked_mul(EMBEDDING_DIMENSION)
            .ok_or(StorageBackendError::InvalidInput("embedding count"))?;
        let mut embeddings = Zeroizing::new(vec![0.0; embedding_count].into_boxed_slice());
        for (destination, entry) in embeddings
            .chunks_exact_mut(EMBEDDING_DIMENSION)
            .zip(record.entries())
        {
            destination.copy_from_slice(entry.embedding());
        }
        Self::new_exact(
            record.generation(),
            record.recognizer_model_sha256(),
            EMBEDDING_DIMENSION,
            ids,
            labels,
            embeddings,
        )
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn model_digest(&self) -> ModelDigest {
        self.model_digest
    }

    pub const fn dimension(&self) -> usize {
        self.dimension
    }

    pub fn enrollment_ids(&self) -> &[EnrollmentId] {
        &self.enrollment_ids
    }

    pub fn labels(&self) -> impl ExactSizeIterator<Item = &str> {
        self.labels.iter().map(|label| label.as_ref().as_ref())
    }

    pub fn flat_embeddings(&self) -> &[f32] {
        &self.flat_embeddings
    }

    pub fn embedding(&self, index: usize) -> Option<&[f32]> {
        let start = index.checked_mul(self.dimension)?;
        let end = start.checked_add(self.dimension)?;
        self.flat_embeddings.get(start..end)
    }

    pub const fn entry_count(&self) -> usize {
        self.enrollment_ids.len()
    }

    pub const fn plaintext_bytes(&self) -> usize {
        self.plaintext_bytes
    }
}

impl fmt::Debug for AuthModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthModel")
            .field("generation", &self.generation)
            .field("model_digest", &self.model_digest)
            .field("dimension", &self.dimension)
            .field("entry_count", &self.entry_count())
            .field("plaintext_bytes", &self.plaintext_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct BudgetState {
    used: usize,
}

#[derive(Debug)]
struct BudgetInner {
    limit: usize,
    state: Mutex<BudgetState>,
}

/// Cloneable handle to one hard plaintext-byte budget.
#[derive(Debug, Clone)]
pub struct PlaintextBudget {
    inner: Arc<BudgetInner>,
}

impl PlaintextBudget {
    pub fn new(limit: usize) -> Result<Self, StorageBackendError> {
        if limit == 0 {
            return Err(StorageBackendError::InvalidInput("plaintext budget"));
        }
        Ok(Self {
            inner: Arc::new(BudgetInner {
                limit,
                state: Mutex::new(BudgetState { used: 0 }),
            }),
        })
    }

    pub fn limit(&self) -> usize {
        self.inner.limit
    }

    pub fn used(&self) -> usize {
        self.lock_state().used
    }

    pub fn available(&self) -> usize {
        self.inner.limit.saturating_sub(self.used())
    }

    pub fn owns(&self, permit: &BudgetPermit) -> bool {
        Arc::ptr_eq(&self.inner, &permit.inner)
    }

    /// Reserve bytes for a cache entry, request lease, or transient operation buffer.
    pub fn reserve(&self, bytes: usize) -> Result<BudgetPermit, StorageBackendError> {
        if bytes == 0 {
            return Err(StorageBackendError::InvalidInput("zero-byte reservation"));
        }
        let mut state = self.lock_state();
        let available = self.inner.limit.saturating_sub(state.used);
        let new_used =
            state
                .used
                .checked_add(bytes)
                .ok_or(StorageBackendError::MemoryBudgetExceeded {
                    requested: bytes,
                    available,
                })?;
        if new_used > self.inner.limit {
            return Err(StorageBackendError::MemoryBudgetExceeded {
                requested: bytes,
                available,
            });
        }
        state.used = new_used;
        drop(state);
        Ok(BudgetPermit {
            inner: Arc::clone(&self.inner),
            bytes,
            release_guard: None,
        })
    }

    /// Atomically reserve a backend transform and caller-owned enrollment
    /// plaintext before capture or decoding begins.
    pub fn reserve_enrollment(
        &self,
        operation_bytes: usize,
        input_bytes: usize,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        if operation_bytes == 0 || input_bytes == 0 {
            return Err(StorageBackendError::InvalidInput("enrollment reservation"));
        }
        let total = operation_bytes.checked_add(input_bytes).ok_or(
            StorageBackendError::MemoryBudgetExceeded {
                requested: usize::MAX,
                available: self.available(),
            },
        )?;
        let mut combined = self.reserve(total)?;
        let input = combined.split_off(input_bytes)?;
        Ok(EnrollmentAdmission {
            operation: combined,
            input,
            release_guard: None,
        })
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, BudgetState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Unique RAII reservation. Permits are never cloned or implicitly split.
pub struct BudgetPermit {
    inner: Arc<BudgetInner>,
    bytes: usize,
    release_guard: Option<Box<dyn Send + Sync>>,
}

impl fmt::Debug for BudgetPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetPermit")
            .field("bytes", &self.bytes)
            .field("has_release_guard", &self.release_guard.is_some())
            .finish_non_exhaustive()
    }
}

impl BudgetPermit {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reduce this reservation without ever creating an unaccounted interval.
    ///
    /// This is used when a transient decode/flatten reservation becomes the
    /// long-lived reservation owned by an immutable cached model.
    pub fn shrink_to(mut self, bytes: usize) -> Result<Self, StorageBackendError> {
        if bytes == 0 || bytes > self.bytes {
            return Err(StorageBackendError::InvalidInput("permit shrink size"));
        }
        let released = self.bytes - bytes;
        if released != 0 {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.used = state
                .used
                .checked_sub(released)
                .expect("plaintext budget permit accounting underflow");
            self.bytes = bytes;
        }
        Ok(self)
    }

    fn split_off(&mut self, bytes: usize) -> Result<Self, StorageBackendError> {
        if bytes == 0 || bytes >= self.bytes {
            return Err(StorageBackendError::InvalidInput("permit split size"));
        }
        self.bytes -= bytes;
        Ok(Self {
            inner: Arc::clone(&self.inner),
            bytes,
            release_guard: None,
        })
    }
}

/// One atomic admission split between backend commit work and enrollment
/// plaintext retained by the request handler. Both permits use the backend's
/// existing hard budget and release through the same RAII accounting.
pub struct EnrollmentAdmission {
    operation: BudgetPermit,
    input: BudgetPermit,
    release_guard: Option<Box<dyn Send + Sync>>,
}

impl fmt::Debug for EnrollmentAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentAdmission")
            .field("operation", &self.operation)
            .field("input", &self.input)
            .field("has_release_guard", &self.release_guard.is_some())
            .finish()
    }
}

impl EnrollmentAdmission {
    /// Retain a backend-specific admission guard until the caller-owned input
    /// permit is dropped. This lets a backend reject a second same-user
    /// enrollment before it can hoard another plaintext reservation.
    pub fn with_release_guard(mut self, guard: Box<dyn Send + Sync>) -> Self {
        self.release_guard = Some(guard);
        self
    }

    pub fn into_parts(self) -> (BudgetPermit, BudgetPermit) {
        let Self {
            operation,
            mut input,
            release_guard,
        } = self;
        input.release_guard = release_guard;
        (operation, input)
    }
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.used = state
            .used
            .checked_sub(self.bytes)
            .expect("plaintext budget permit accounting underflow");
    }
}

struct BudgetedAuthModel {
    model: AuthModel,
    _permit: BudgetPermit,
}

impl BudgetedAuthModel {
    fn new(model: AuthModel, permit: BudgetPermit) -> Result<Self, StorageBackendError> {
        if permit.bytes() < model.plaintext_bytes() {
            return Err(StorageBackendError::InvalidInput(
                "model reservation is too small",
            ));
        }
        Ok(Self {
            model,
            _permit: permit,
        })
    }
}

/// Immutable cached model. Every clone shares one Arc and one budget permit.
/// The permit therefore remains charged until cache ownership and all leases end.
#[derive(Clone)]
pub struct CachedAuthModel(Arc<BudgetedAuthModel>);

impl CachedAuthModel {
    pub fn new(model: AuthModel, permit: BudgetPermit) -> Result<Self, StorageBackendError> {
        BudgetedAuthModel::new(model, permit).map(|inner| Self(Arc::new(inner)))
    }

    pub fn lease(&self) -> ModelLease {
        ModelLease {
            inner: ModelLeaseInner::Cached(self.clone()),
        }
    }
}

impl fmt::Debug for CachedAuthModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CachedAuthModel")
            .field("model", &self.0.model)
            .finish_non_exhaustive()
    }
}

impl Deref for CachedAuthModel {
    type Target = AuthModel;

    fn deref(&self) -> &Self::Target {
        &self.0.model
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseKind {
    Cached,
    Ephemeral,
}

/// One authentication lease API for cached and request-local model ownership.
///
/// Cached variants share their Arc-owned permit when cloned by the cache;
/// ephemeral variants uniquely own their permit and cannot be cloned.
pub struct ModelLease {
    inner: ModelLeaseInner,
}

enum ModelLeaseInner {
    Cached(CachedAuthModel),
    Ephemeral(BudgetedAuthModel),
}

impl ModelLease {
    pub fn ephemeral(model: AuthModel, permit: BudgetPermit) -> Result<Self, StorageBackendError> {
        BudgetedAuthModel::new(model, permit).map(|model| Self {
            inner: ModelLeaseInner::Ephemeral(model),
        })
    }

    pub const fn kind(&self) -> LeaseKind {
        match &self.inner {
            ModelLeaseInner::Cached(_) => LeaseKind::Cached,
            ModelLeaseInner::Ephemeral(_) => LeaseKind::Ephemeral,
        }
    }
}

impl fmt::Debug for ModelLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelLease")
            .field("kind", &self.kind())
            .field("model", &self.deref())
            .finish()
    }
}

impl Deref for ModelLease {
    type Target = AuthModel;

    fn deref(&self) -> &Self::Target {
        match &self.inner {
            ModelLeaseInner::Cached(model) => model,
            ModelLeaseInner::Ephemeral(model) => &model.model,
        }
    }
}

/// Deferred publication of an authentication cold load into a shared backend
/// cache. The backend owns all coherence validation; dropping this value must
/// publish nothing and release/zeroize its provisional ownership normally.
pub trait AuthenticationCachePromotion: Send {
    /// Returns whether this exact provisional value was published. A false
    /// result is a benign coherence race with newer backend/cache state.
    fn promote_if(
        self: Box<Self>,
        publish: &mut dyn FnMut() -> bool,
    ) -> Result<bool, StorageBackendError>;

    /// Unconditionally attempt publication. Supervisors that own a live
    /// connection must use [`Self::promote_if`] so their final predicate is
    /// evaluated at the backend's insertion linearization point.
    fn promote(self: Box<Self>) -> Result<bool, StorageBackendError> {
        self.promote_if(&mut || true)
    }
}

/// Authentication plaintext plus an optional supervisor-owned cache promotion.
///
/// Warm cache hits and ephemeral backends have no promotion. Cold cached loads
/// can remain private to one active transaction until its supervisor accepts a
/// terminal result.
pub struct AuthenticationLoad {
    lease: ModelLease,
    promotion: Option<Box<dyn AuthenticationCachePromotion>>,
}

impl AuthenticationLoad {
    pub fn committed(lease: ModelLease) -> Self {
        Self {
            lease,
            promotion: None,
        }
    }

    pub fn provisional(
        lease: ModelLease,
        promotion: Box<dyn AuthenticationCachePromotion>,
    ) -> Self {
        Self {
            lease,
            promotion: Some(promotion),
        }
    }

    pub fn take_promotion(&mut self) -> Option<Box<dyn AuthenticationCachePromotion>> {
        self.promotion.take()
    }

    /// Consume the load and retain only its model lease. Callers should use
    /// this only for paths whose cache publication has already been committed;
    /// any still-provisional promotion is deliberately dropped.
    pub fn into_lease(self) -> ModelLease {
        self.lease
    }

    pub fn has_provisional_promotion(&self) -> bool {
        self.promotion.is_some()
    }
}

impl fmt::Debug for AuthenticationLoad {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationLoad")
            .field("lease", &self.lease)
            .field("has_provisional_promotion", &self.promotion.is_some())
            .finish()
    }
}

impl Deref for AuthenticationLoad {
    type Target = AuthModel;

    fn deref(&self) -> &Self::Target {
        &self.lease
    }
}

#[derive(Clone, Copy)]
pub struct AppendRequest<'a> {
    username: &'a CanonicalUsername,
    expected_generation: u64,
    entries: &'a [EnrollmentEntry],
}

impl fmt::Debug for AppendRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppendRequest")
            .field("username", &self.username)
            .field("expected_generation", &self.expected_generation)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<'a> AppendRequest<'a> {
    pub fn new(
        username: &'a CanonicalUsername,
        expected_generation: u64,
        entries: &'a [EnrollmentEntry],
    ) -> Result<Self, StorageBackendError> {
        if entries.is_empty() {
            return Err(StorageBackendError::InvalidInput("empty append"));
        }
        Ok(Self {
            username,
            expected_generation,
            entries,
        })
    }

    pub const fn username(&self) -> &CanonicalUsername {
        self.username
    }

    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub const fn entries(&self) -> &[EnrollmentEntry] {
        self.entries
    }
}

/// Upper bound for the entries an admitted enrollment request can append.
///
/// The backend combines this request-local shape with the already-inspected
/// current record header, so admission is based on the actual bounded record
/// rather than the globally configured maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendAdmissionShape {
    max_new_entries: usize,
    max_new_label_bytes: usize,
}

impl AppendAdmissionShape {
    pub fn new(
        max_new_entries: usize,
        max_new_label_bytes: usize,
    ) -> Result<Self, StorageBackendError> {
        if max_new_entries == 0 || max_new_entries > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput(
                "admitted append entry count",
            ));
        }
        let maximum_labels = max_new_entries.checked_mul(MAX_LABEL_BYTES).ok_or(
            StorageBackendError::InvalidInput("admitted append label bytes"),
        )?;
        if max_new_label_bytes > maximum_labels {
            return Err(StorageBackendError::InvalidInput(
                "admitted append label bytes",
            ));
        }
        Ok(Self {
            max_new_entries,
            max_new_label_bytes,
        })
    }

    pub const fn max_new_entries(self) -> usize {
        self.max_new_entries
    }

    pub const fn max_new_label_bytes(self) -> usize {
        self.max_new_label_bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RemoveRequest<'a> {
    username: &'a CanonicalUsername,
    expected_generation: u64,
    enrollment_id: EnrollmentId,
}

impl<'a> RemoveRequest<'a> {
    pub fn new(
        username: &'a CanonicalUsername,
        expected_generation: u64,
        enrollment_id: EnrollmentId,
    ) -> Result<Self, StorageBackendError> {
        if expected_generation == ABSENT_GENERATION {
            return Err(StorageBackendError::InvalidInput("remove generation"));
        }
        Ok(Self {
            username,
            expected_generation,
            enrollment_id,
        })
    }

    pub const fn username(&self) -> &CanonicalUsername {
        self.username
    }

    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub const fn enrollment_id(&self) -> EnrollmentId {
        self.enrollment_id
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClearRequest<'a> {
    username: &'a CanonicalUsername,
    expected_generation: u64,
}

impl<'a> ClearRequest<'a> {
    pub fn new(
        username: &'a CanonicalUsername,
        expected_generation: u64,
    ) -> Result<Self, StorageBackendError> {
        if expected_generation == ABSENT_GENERATION {
            return Err(StorageBackendError::InvalidInput("clear generation"));
        }
        Ok(Self {
            username,
            expected_generation,
        })
    }

    pub const fn username(&self) -> &CanonicalUsername {
        self.username
    }

    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendResult {
    generation: u64,
    appended: usize,
    total_entries: usize,
}

impl AppendResult {
    pub const fn new(generation: u64, appended: usize, total_entries: usize) -> Self {
        Self {
            generation,
            appended,
            total_entries,
        }
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn appended(self) -> usize {
        self.appended
    }

    pub const fn total_entries(self) -> usize {
        self.total_entries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveResult {
    generation: u64,
    enrollment_id: EnrollmentId,
}

impl RemoveResult {
    pub const fn new(generation: u64, enrollment_id: EnrollmentId) -> Self {
        Self {
            generation,
            enrollment_id,
        }
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn enrollment_id(self) -> EnrollmentId {
        self.enrollment_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearResult {
    generation: u64,
    removed: usize,
}

/// Shared cooperative cancellation boundary for long-running storage work.
///
/// Implementations must sample this signal before retaining a new plaintext
/// lease and at safe interruption points during cache-miss work. Cancellation
/// is intentionally represented as backend unavailability on the public wire;
/// the connection supervisor owns the terminal cancellation policy.
pub trait CancellationSignal: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

impl ClearResult {
    pub const fn new(removed: usize) -> Self {
        Self {
            generation: ABSENT_GENERATION,
            removed,
        }
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn removed(self) -> usize {
        self.removed
    }
}

/// Synchronous backend contract for the daemon's thread-based request workers.
///
/// Implementations receive already-authorized, already-canonical usernames.
/// Mutation implementations serialize per username and never retry conflicts.
pub trait StorageBackend: Send + Sync {
    fn prompt_snapshot(
        &self,
        username: &CanonicalUsername,
    ) -> Result<PromptStorageSnapshot, StorageBackendError>;

    fn candidate_presence(
        &self,
        username: &CanonicalUsername,
    ) -> Result<CandidatePresence, StorageBackendError>;

    fn authenticate(&self, username: &CanonicalUsername)
    -> Result<ModelLease, StorageBackendError>;

    fn authenticate_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<ModelLease, StorageBackendError> {
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let lease = self.authenticate(username)?;
        if cancellation.is_cancelled() {
            drop(lease);
            Err(StorageBackendError::Unavailable)
        } else {
            Ok(lease)
        }
    }

    /// Active prompt authentication boundary. Cached backends may return a
    /// transaction-private cold load whose publication is deferred to the
    /// connection supervisor. Prompt-off callers continue using `authenticate`.
    fn authenticate_active(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<AuthenticationLoad, StorageBackendError> {
        self.authenticate_cancellable(username, cancellation)
            .map(AuthenticationLoad::committed)
    }

    fn list_metadata(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError>;

    fn append(&self, request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError>;

    /// Reserve commit transformation capacity and request-owned enrollment
    /// plaintext in one hard-budget transaction before camera/inference work.
    fn admit_enrollment(
        &self,
        username: &CanonicalUsername,
        plaintext_bytes: usize,
        append_shape: AppendAdmissionShape,
    ) -> Result<EnrollmentAdmission, StorageBackendError>;

    /// Append using transform capacity obtained from [`Self::admit_enrollment`].
    fn append_admitted(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError>;

    fn remove(&self, request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError>;

    fn clear(&self, request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError>;

    fn reload(&self) -> Result<ReloadResult, StorageBackendError>;

    fn health(&self) -> BackendHealth;

    /// Authenticate and validate the selected record, returning metadata only.
    fn verify_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError>;
}
