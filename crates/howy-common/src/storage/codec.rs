use zeroize::Zeroizing;

use super::{
    Aes256Key, CANONICAL_ENTRY_FIXED_BYTES, CANONICAL_PAYLOAD_FIXED_BYTES, CanonicalUsername,
    EMBEDDING_DIMENSION, EnrollmentEntry, EnrollmentId, EnrollmentRecord, GCM_TAG_BYTES, GcmNonce,
    GcmTag, MAX_ENTRIES, MAX_LABEL_BYTES, MAX_PLAINTEXT_BYTES, ModelDigest, NonceGenerator,
    RandomSource, SensitiveBytes, StorageError, StorageMode, decrypt_aes_256_gcm,
    encrypt_aes_256_gcm,
};

const HOWYENC1_MAGIC: &[u8; 8] = b"HOWYENC1";
const HOWYPLN1_MAGIC: &[u8; 8] = b"HOWYPLN1";
const FORMAT_VERSION: u16 = 1;
const PAYLOAD_VERSION: u16 = 1;
const AES_256_GCM_ALGORITHM: u16 = 1;
const HOWYENC1_FIXED_HEADER: usize = 88;
const HOWYPLN1_FIXED_HEADER: usize = 54;

/// Bytes before the variable HOWYPLN1 username.
pub const HOWYPLN1_FIXED_INSPECTION_BYTES: usize = HOWYPLN1_FIXED_HEADER;
/// Largest frozen HOWYPLN1 header plus username and canonical-payload metadata.
pub const HOWYPLN1_MAX_INSPECTION_BYTES: usize =
    HOWYPLN1_FIXED_HEADER + 64 + CANONICAL_PAYLOAD_FIXED_BYTES;
/// Bytes before the variable HOWYENC1 username.
pub const HOWYENC1_FIXED_INSPECTION_BYTES: usize = HOWYENC1_FIXED_HEADER;
/// Largest frozen HOWYENC1 header, including a canonical username.
pub const HOWYENC1_MAX_INSPECTION_BYTES: usize = HOWYENC1_FIXED_HEADER + 64;
/// Largest complete frozen HOWYENC1 record.
pub const HOWYENC1_MAX_RECORD_BYTES: usize =
    HOWYENC1_MAX_INSPECTION_BYTES + MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextHeaderInspection {
    generation: u64,
    entry_count: u32,
}

impl PlaintextHeaderInspection {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn entry_count(self) -> u32 {
        self.entry_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedHeader {
    mode: StorageMode,
    key_epoch: u64,
    record_generation: u64,
    plaintext_length: usize,
    entry_count: u32,
    recognizer_model_sha256: ModelDigest,
    nonce: GcmNonce,
    username: CanonicalUsername,
    header_length: usize,
}

impl EncryptedHeader {
    pub const fn mode(&self) -> StorageMode {
        self.mode
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub const fn record_generation(&self) -> u64 {
        self.record_generation
    }

    pub const fn plaintext_length(&self) -> usize {
        self.plaintext_length
    }

    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    pub const fn recognizer_model_sha256(&self) -> ModelDigest {
        self.recognizer_model_sha256
    }

    pub const fn nonce(&self) -> GcmNonce {
        self.nonce
    }

    pub fn username(&self) -> &CanonicalUsername {
        &self.username
    }

    pub const fn header_length(&self) -> usize {
        self.header_length
    }
}

/// Encode sensitive canonical plaintext into guaranteed zeroizing ownership.
pub fn encode_canonical_payload(record: &EnrollmentRecord) -> Result<SensitiveBytes, StorageError> {
    let entry_count =
        u32::try_from(record.entries().len()).map_err(|_| StorageError::LimitExceeded {
            field: "entry count",
        })?;
    let mut payload_length = CANONICAL_PAYLOAD_FIXED_BYTES;
    for entry in record.entries() {
        if entry.label().len() > MAX_LABEL_BYTES {
            return Err(StorageError::LimitExceeded { field: "label" });
        }
        if entry.embedding().iter().any(|value| !value.is_finite()) {
            return Err(StorageError::NonFiniteEmbedding);
        }
        payload_length = payload_length
            .checked_add(CANONICAL_ENTRY_FIXED_BYTES)
            .and_then(|length| length.checked_add(entry.label().len()))
            .ok_or(StorageError::IntegerOverflow("canonical payload length"))?;
    }
    if payload_length > MAX_PLAINTEXT_BYTES {
        return Err(StorageError::LimitExceeded {
            field: "canonical plaintext",
        });
    }

    let mut payload = Zeroizing::new(Vec::new());
    payload
        .try_reserve_exact(payload_length)
        .map_err(|_| StorageError::AllocationFailed("canonical payload"))?;
    payload.extend_from_slice(&PAYLOAD_VERSION.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&entry_count.to_le_bytes());
    for entry in record.entries() {
        payload.extend_from_slice(entry.enrollment_id().as_bytes());
        payload.extend_from_slice(&entry.created_unix_seconds().to_le_bytes());
        payload.extend_from_slice(&(entry.label().len() as u16).to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(entry.label().as_bytes());
        for value in entry.embedding() {
            payload.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    debug_assert_eq!(payload.len(), payload_length);
    debug_assert_eq!(payload.capacity(), payload_length);
    Ok(SensitiveBytes::from_zeroizing(payload))
}

/// Decode a complete canonical payload with exact-EOF validation.
///
/// This pure, bounded entry point is suitable for corpus tests and fuzzing.
pub fn decode_canonical_payload(bytes: &[u8]) -> Result<Vec<EnrollmentEntry>, StorageError> {
    decode_payload_with_expected_count(bytes, None)
}

fn decode_payload_with_expected_count(
    bytes: &[u8],
    expected_entry_count: Option<u32>,
) -> Result<Vec<EnrollmentEntry>, StorageError> {
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(StorageError::LimitExceeded {
            field: "canonical plaintext",
        });
    }
    let mut reader = Reader::new(bytes, "canonical payload");
    let payload_version = reader.read_u16()?;
    if payload_version != PAYLOAD_VERSION {
        return Err(StorageError::UnsupportedVersion {
            format: "canonical payload",
            version: payload_version,
        });
    }
    if reader.read_u16()? != 0 {
        return Err(StorageError::InvalidReserved {
            format: "canonical payload",
        });
    }
    let entry_count = reader.read_u32()?;
    if expected_entry_count.is_some_and(|expected| expected != entry_count) {
        return Err(StorageError::EntryCountMismatch);
    }
    let entry_count_usize = usize::try_from(entry_count)
        .map_err(|_| StorageError::IntegerOverflow("payload entry count"))?;
    if entry_count_usize > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }
    let minimum_entries_length = entry_count_usize
        .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
        .ok_or(StorageError::IntegerOverflow("payload entry lengths"))?;
    if reader.remaining() < minimum_entries_length {
        return Err(StorageError::InvalidLength {
            format: "canonical payload",
        });
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count_usize)
        .map_err(|_| StorageError::AllocationFailed("payload entries"))?;
    for _ in 0..entry_count_usize {
        let enrollment_id = EnrollmentId::new(reader.read_array::<16>()?)?;
        if entries
            .iter()
            .any(|entry: &EnrollmentEntry| entry.enrollment_id() == enrollment_id)
        {
            return Err(StorageError::DuplicateEnrollmentId);
        }
        let created_unix_seconds = reader.read_u64()?;
        let label_length = usize::from(reader.read_u16()?);
        if label_length > MAX_LABEL_BYTES {
            return Err(StorageError::LimitExceeded { field: "label" });
        }
        if reader.read_u16()? != 0 {
            return Err(StorageError::InvalidReserved {
                format: "canonical payload entry",
            });
        }
        let label_bytes = reader.take(label_length)?;
        // Establish zeroizing ownership before any later fallible read. This
        // prevents a valid label from surviving an embedding truncation/error.
        let label = Zeroizing::new(
            std::str::from_utf8(label_bytes)
                .map_err(|_| StorageError::InvalidLabelUtf8)?
                .into(),
        );
        let embedding_bytes = reader.take(EMBEDDING_DIMENSION * 4)?;
        let mut embedding = Zeroizing::new([0.0f32; EMBEDDING_DIMENSION]);
        for (destination, encoded) in embedding.iter_mut().zip(embedding_bytes.chunks_exact(4)) {
            let encoded: &[u8; 4] = encoded
                .try_into()
                .expect("chunks_exact(4) always yields four-byte chunks");
            *destination = f32::from_le_bytes(*encoded);
        }
        entries.push(EnrollmentEntry::new_zeroizing_fields(
            enrollment_id,
            created_unix_seconds,
            label,
            embedding,
        )?);
    }
    reader.finish()?;
    debug_assert_eq!(entries.len(), entry_count_usize);
    debug_assert_eq!(entries.capacity(), entry_count_usize);
    Ok(entries)
}

pub fn encode_howypln1(record: &EnrollmentRecord) -> Result<SensitiveBytes, StorageError> {
    let payload = encode_canonical_payload(record)?;
    let username = record.username().as_bytes();
    let total_length = HOWYPLN1_FIXED_HEADER
        .checked_add(username.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(StorageError::IntegerOverflow("HOWYPLN1 length"))?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(total_length)
        .map_err(|_| StorageError::AllocationFailed("HOWYPLN1 record"))?;
    output.extend_from_slice(HOWYPLN1_MAGIC);
    output.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&record.generation().to_le_bytes());
    output.extend_from_slice(record.recognizer_model_sha256().as_bytes());
    output.extend_from_slice(&(username.len() as u16).to_le_bytes());
    output.extend_from_slice(username);
    output.extend_from_slice(payload.as_slice());
    Ok(SensitiveBytes::from_zeroizing(output))
}

/// Decode HOWYPLN1 and require the namespace-independent username/model bindings.
pub fn decode_howypln1(
    bytes: &[u8],
    expected_username: &CanonicalUsername,
    expected_model: ModelDigest,
) -> Result<EnrollmentRecord, StorageError> {
    let mut reader = Reader::new(bytes, "HOWYPLN1");
    if reader.take(8)? != HOWYPLN1_MAGIC {
        return Err(StorageError::InvalidMagic { format: "HOWYPLN1" });
    }
    let version = reader.read_u16()?;
    if version != FORMAT_VERSION {
        return Err(StorageError::UnsupportedVersion {
            format: "HOWYPLN1",
            version,
        });
    }
    let flags = reader.read_u16()?;
    if flags != 0 {
        return Err(StorageError::UnknownFlags {
            format: "HOWYPLN1",
            flags,
        });
    }
    let generation = reader.read_u64()?;
    if generation == 0 {
        return Err(StorageError::InvalidGeneration);
    }
    let model = ModelDigest::new(reader.read_array::<32>()?);
    let username_length = usize::from(reader.read_u16()?);
    if !(1..=64).contains(&username_length) {
        return Err(StorageError::InvalidUsername);
    }
    let username_bytes = reader.take(username_length)?;
    let username = CanonicalUsername::new(
        std::str::from_utf8(username_bytes).map_err(|_| StorageError::InvalidUsername)?,
    )?;
    if &username != expected_username {
        return Err(StorageError::BindingMismatch("username"));
    }
    if model != expected_model {
        return Err(StorageError::BindingMismatch("recognizer model"));
    }
    let entries = decode_canonical_payload(reader.remainder())?;
    EnrollmentRecord::new(generation, model, username, entries)
}

/// Inspect only the frozen HOWYPLN1 header, username, and payload metadata.
///
/// `metadata_prefix` must contain exactly the fixed header, encoded username,
/// and the eight-byte canonical payload prefix. Entry bodies and embeddings are
/// deliberately not accepted or decoded here. `exact_source_length` supplies
/// the descriptor's stable file-size envelope.
pub fn inspect_howypln1_metadata(
    metadata_prefix: &[u8],
    exact_source_length: usize,
    expected_username: &CanonicalUsername,
    expected_model: ModelDigest,
    configured_max_entries: usize,
) -> Result<PlaintextHeaderInspection, StorageError> {
    if configured_max_entries == 0 || configured_max_entries > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }
    if metadata_prefix.len() > HOWYPLN1_MAX_INSPECTION_BYTES {
        return Err(StorageError::InvalidLength { format: "HOWYPLN1" });
    }
    let mut reader = Reader::new(metadata_prefix, "HOWYPLN1 metadata");
    if reader.take(8)? != HOWYPLN1_MAGIC {
        return Err(StorageError::InvalidMagic { format: "HOWYPLN1" });
    }
    let version = reader.read_u16()?;
    if version != FORMAT_VERSION {
        return Err(StorageError::UnsupportedVersion {
            format: "HOWYPLN1",
            version,
        });
    }
    let flags = reader.read_u16()?;
    if flags != 0 {
        return Err(StorageError::UnknownFlags {
            format: "HOWYPLN1",
            flags,
        });
    }
    let generation = reader.read_u64()?;
    if generation == 0 {
        return Err(StorageError::InvalidGeneration);
    }
    let model = ModelDigest::new(reader.read_array::<32>()?);
    let username_length = usize::from(reader.read_u16()?);
    if !(1..=64).contains(&username_length) {
        return Err(StorageError::InvalidUsername);
    }
    let username = CanonicalUsername::new(
        std::str::from_utf8(reader.take(username_length)?)
            .map_err(|_| StorageError::InvalidUsername)?,
    )?;
    if &username != expected_username {
        return Err(StorageError::BindingMismatch("username"));
    }
    if model != expected_model {
        return Err(StorageError::BindingMismatch("recognizer model"));
    }
    let payload_version = reader.read_u16()?;
    if payload_version != PAYLOAD_VERSION {
        return Err(StorageError::UnsupportedVersion {
            format: "canonical payload",
            version: payload_version,
        });
    }
    if reader.read_u16()? != 0 {
        return Err(StorageError::InvalidReserved {
            format: "canonical payload",
        });
    }
    let entry_count = reader.read_u32()?;
    reader.finish()?;
    let entry_count_usize = usize::try_from(entry_count)
        .map_err(|_| StorageError::IntegerOverflow("payload entry count"))?;
    if entry_count_usize > configured_max_entries || entry_count_usize > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }

    let minimum_length = metadata_prefix
        .len()
        .checked_add(
            entry_count_usize
                .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
                .ok_or(StorageError::IntegerOverflow("HOWYPLN1 entry envelope"))?,
        )
        .ok_or(StorageError::IntegerOverflow("HOWYPLN1 length envelope"))?;
    let maximum_length = minimum_length
        .checked_add(
            entry_count_usize
                .checked_mul(MAX_LABEL_BYTES)
                .ok_or(StorageError::IntegerOverflow("HOWYPLN1 label envelope"))?,
        )
        .ok_or(StorageError::IntegerOverflow("HOWYPLN1 length envelope"))?;
    if !(minimum_length..=maximum_length).contains(&exact_source_length) {
        return Err(StorageError::InvalidLength { format: "HOWYPLN1" });
    }

    Ok(PlaintextHeaderInspection {
        generation,
        entry_count,
    })
}

/// Encode a production HOWYENC1 record using the backend's process-lifetime
/// nonce generator. `key` remains caller-owned and must live in zeroizing
/// storage; this function does not alter borrowed key bytes.
pub fn encode_howyenc1<R: RandomSource>(
    record: &EnrollmentRecord,
    mode: StorageMode,
    key_epoch: u64,
    key: &Aes256Key,
    nonce_generator: &mut NonceGenerator<R>,
) -> Result<Vec<u8>, StorageError> {
    let nonce = nonce_generator.generate()?;
    encode_howyenc1_with_nonce(record, mode, key_epoch, key, nonce)
}

fn encode_howyenc1_with_nonce(
    record: &EnrollmentRecord,
    mode: StorageMode,
    key_epoch: u64,
    key: &Aes256Key,
    nonce: GcmNonce,
) -> Result<Vec<u8>, StorageError> {
    if key_epoch == 0 {
        return Err(StorageError::InvalidEpoch);
    }
    let payload = encode_canonical_payload(record)?;
    let plaintext_length =
        u32::try_from(payload.len()).map_err(|_| StorageError::LimitExceeded {
            field: "canonical plaintext",
        })?;
    let entry_count =
        u32::try_from(record.entries().len()).map_err(|_| StorageError::LimitExceeded {
            field: "entry count",
        })?;
    let username = record.username().as_bytes();
    let header_length = HOWYENC1_FIXED_HEADER
        .checked_add(username.len())
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 header length"))?;
    let encoded_header_length = u16::try_from(header_length)
        .map_err(|_| StorageError::IntegerOverflow("HOWYENC1 header length"))?;

    let mut header = Vec::new();
    header
        .try_reserve_exact(header_length)
        .map_err(|_| StorageError::AllocationFailed("HOWYENC1 header"))?;
    header.extend_from_slice(HOWYENC1_MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    header.extend_from_slice(&AES_256_GCM_ALGORITHM.to_le_bytes());
    header.push(mode.identifier());
    header.push(0);
    header.extend_from_slice(&encoded_header_length.to_le_bytes());
    header.extend_from_slice(&key_epoch.to_le_bytes());
    header.extend_from_slice(&record.generation().to_le_bytes());
    header.extend_from_slice(&plaintext_length.to_le_bytes());
    header.extend_from_slice(&entry_count.to_le_bytes());
    header.extend_from_slice(&(EMBEDDING_DIMENSION as u16).to_le_bytes());
    header.extend_from_slice(&(username.len() as u16).to_le_bytes());
    header.extend_from_slice(record.recognizer_model_sha256().as_bytes());
    header.extend_from_slice(&nonce);
    header.extend_from_slice(username);
    debug_assert_eq!(header.len(), header_length);

    let (ciphertext, tag) = encrypt_aes_256_gcm(key, &nonce, &header, payload.as_slice())?;
    let ciphertext = Zeroizing::new(ciphertext);
    let tag = Zeroizing::new(tag);
    let total_length = header_length
        .checked_add(ciphertext.len())
        .and_then(|length| length.checked_add(GCM_TAG_BYTES))
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 total length"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total_length)
        .map_err(|_| StorageError::AllocationFailed("HOWYENC1 record"))?;
    output.extend_from_slice(&header);
    output.extend_from_slice(ciphertext.as_slice());
    output.extend_from_slice(tag.as_slice());
    Ok(output)
}

fn inspect_howyenc1_header_prefix(
    bytes: &[u8],
    exact_source_length: usize,
) -> Result<EncryptedHeader, StorageError> {
    let mut reader = Reader::new(bytes, "HOWYENC1");
    if reader.take(8)? != HOWYENC1_MAGIC {
        return Err(StorageError::InvalidMagic { format: "HOWYENC1" });
    }
    let version = reader.read_u16()?;
    if version != FORMAT_VERSION {
        return Err(StorageError::UnsupportedVersion {
            format: "HOWYENC1",
            version,
        });
    }
    let algorithm = reader.read_u16()?;
    if algorithm != AES_256_GCM_ALGORITHM {
        return Err(StorageError::UnsupportedAlgorithm(algorithm));
    }
    let mode = StorageMode::try_from(reader.read_u8()?)?;
    let flags = reader.read_u8()?;
    if flags != 0 {
        return Err(StorageError::UnknownFlags {
            format: "HOWYENC1",
            flags: u16::from(flags),
        });
    }
    let header_length = usize::from(reader.read_u16()?);
    let key_epoch = reader.read_u64()?;
    if key_epoch == 0 {
        return Err(StorageError::InvalidEpoch);
    }
    let record_generation = reader.read_u64()?;
    if record_generation == 0 {
        return Err(StorageError::InvalidGeneration);
    }
    let plaintext_length = usize::try_from(reader.read_u32()?)
        .map_err(|_| StorageError::IntegerOverflow("HOWYENC1 plaintext length"))?;
    if plaintext_length > MAX_PLAINTEXT_BYTES {
        return Err(StorageError::LimitExceeded {
            field: "HOWYENC1 plaintext",
        });
    }
    let entry_count = reader.read_u32()?;
    let entry_count_usize = usize::try_from(entry_count)
        .map_err(|_| StorageError::IntegerOverflow("HOWYENC1 entry count"))?;
    if entry_count_usize > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }
    let embedding_dimension = reader.read_u16()?;
    if usize::from(embedding_dimension) != EMBEDDING_DIMENSION {
        return Err(StorageError::InvalidEmbeddingDimension(embedding_dimension));
    }
    let username_length = usize::from(reader.read_u16()?);
    if !(1..=64).contains(&username_length) {
        return Err(StorageError::InvalidUsername);
    }
    let recognizer_model_sha256 = ModelDigest::new(reader.read_array::<32>()?);
    let nonce = reader.read_array::<12>()?;
    let expected_header_length = HOWYENC1_FIXED_HEADER
        .checked_add(username_length)
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 header length"))?;
    if header_length != expected_header_length {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    let total_length = header_length
        .checked_add(plaintext_length)
        .and_then(|length| length.checked_add(GCM_TAG_BYTES))
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 total length"))?;
    if exact_source_length != total_length {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    let minimum_payload_length = CANONICAL_PAYLOAD_FIXED_BYTES
        .checked_add(
            entry_count_usize
                .checked_mul(CANONICAL_ENTRY_FIXED_BYTES)
                .ok_or(StorageError::IntegerOverflow("HOWYENC1 entry lengths"))?,
        )
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 payload length"))?;
    if plaintext_length < minimum_payload_length {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    let username = CanonicalUsername::new(
        std::str::from_utf8(reader.take(username_length)?)
            .map_err(|_| StorageError::InvalidUsername)?,
    )?;

    Ok(EncryptedHeader {
        mode,
        key_epoch,
        record_generation,
        plaintext_length,
        entry_count,
        recognizer_model_sha256,
        nonce,
        username,
        header_length,
    })
}

/// Validate and inspect the complete outer HOWYENC1 envelope without decrypting it.
///
/// Length and count checks happen before any allocation based on attacker bytes.
pub fn inspect_howyenc1(bytes: &[u8]) -> Result<EncryptedHeader, StorageError> {
    inspect_howyenc1_header_prefix(bytes, bytes.len())
}

/// Inspect only the bounded public HOWYENC1 header and validate every public
/// namespace binding before ciphertext allocation or AEAD.
///
/// `header_prefix` must contain exactly the fixed header and encoded username;
/// `exact_source_length` is the length obtained from the already-open record
/// descriptor. Ciphertext and tag bytes are deliberately not accepted here.
#[allow(clippy::too_many_arguments)]
pub fn inspect_howyenc1_metadata(
    header_prefix: &[u8],
    exact_source_length: usize,
    expected_mode: StorageMode,
    expected_key_epoch: u64,
    expected_username: &CanonicalUsername,
    expected_model: ModelDigest,
    configured_max_entries: usize,
    configured_max_plaintext_bytes: usize,
) -> Result<EncryptedHeader, StorageError> {
    if !(HOWYENC1_FIXED_INSPECTION_BYTES..=HOWYENC1_MAX_INSPECTION_BYTES)
        .contains(&header_prefix.len())
    {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    if configured_max_entries == 0 || configured_max_entries > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }
    if configured_max_plaintext_bytes == 0 || configured_max_plaintext_bytes > MAX_PLAINTEXT_BYTES {
        return Err(StorageError::LimitExceeded {
            field: "HOWYENC1 plaintext",
        });
    }

    let header = inspect_howyenc1_header_prefix(header_prefix, exact_source_length)?;
    if header_prefix.len() != header.header_length {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    if header.entry_count as usize > configured_max_entries {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }
    if header.plaintext_length > configured_max_plaintext_bytes {
        return Err(StorageError::LimitExceeded {
            field: "HOWYENC1 plaintext",
        });
    }
    if header.mode != expected_mode {
        return Err(StorageError::BindingMismatch("storage mode"));
    }
    if header.key_epoch != expected_key_epoch {
        return Err(StorageError::BindingMismatch("key epoch"));
    }
    if &header.username != expected_username {
        return Err(StorageError::BindingMismatch("username"));
    }
    if header.recognizer_model_sha256 != expected_model {
        return Err(StorageError::BindingMismatch("recognizer model"));
    }
    Ok(header)
}

/// Decode an encrypted record after checking all public outer bindings.
///
/// `key` remains caller-owned and is never zeroized here. Callers must retain
/// borrowed key bytes in guaranteed zeroizing storage.
pub fn decode_howyenc1(
    bytes: &[u8],
    key: &Aes256Key,
    expected_mode: StorageMode,
    expected_key_epoch: u64,
    expected_username: &CanonicalUsername,
    expected_model: ModelDigest,
) -> Result<EnrollmentRecord, StorageError> {
    let header = inspect_howyenc1(bytes)?;
    if header.mode != expected_mode {
        return Err(StorageError::BindingMismatch("storage mode"));
    }
    if header.key_epoch != expected_key_epoch {
        return Err(StorageError::BindingMismatch("key epoch"));
    }
    if &header.username != expected_username {
        return Err(StorageError::BindingMismatch("username"));
    }
    if header.recognizer_model_sha256 != expected_model {
        return Err(StorageError::BindingMismatch("recognizer model"));
    }
    let ciphertext_end = header
        .header_length
        .checked_add(header.plaintext_length)
        .ok_or(StorageError::IntegerOverflow("HOWYENC1 ciphertext end"))?;
    let ciphertext = bytes
        .get(header.header_length..ciphertext_end)
        .ok_or(StorageError::InvalidLength { format: "HOWYENC1" })?;
    let tag = Zeroizing::new(
        <GcmTag>::try_from(
            bytes
                .get(ciphertext_end..)
                .ok_or(StorageError::InvalidLength { format: "HOWYENC1" })?,
        )
        .map_err(|_| StorageError::InvalidLength { format: "HOWYENC1" })?,
    );
    let aad = bytes
        .get(..header.header_length)
        .ok_or(StorageError::InvalidLength { format: "HOWYENC1" })?;
    let payload = decrypt_aes_256_gcm(key, &header.nonce, aad, ciphertext, &tag)?;
    if payload.len() != header.plaintext_length {
        return Err(StorageError::InvalidLength { format: "HOWYENC1" });
    }
    let entries = decode_payload_with_expected_count(&payload, Some(header.entry_count))?;
    EnrollmentRecord::new(
        header.record_generation,
        header.recognizer_model_sha256,
        header.username,
        entries,
    )
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    format: &'static str,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], format: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            format,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StorageError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StorageError::IntegerOverflow("decoder offset"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(StorageError::InvalidLength {
                format: self.format,
            })?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], StorageError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageError::InvalidLength {
                format: self.format,
            })
    }

    fn read_u8(&mut self) -> Result<u8, StorageError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, StorageError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, StorageError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn remainder(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn finish(self) -> Result<(), StorageError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StorageError::InvalidLength {
                format: self.format,
            })
        }
    }
}
