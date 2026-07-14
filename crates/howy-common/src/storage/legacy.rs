use std::collections::HashSet;

use bincode::Options;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::face::UserModels;

use super::{
    CanonicalUsername, EMBEDDING_DIMENSION, EnrollmentEntry, EnrollmentId, EnrollmentRecord,
    MAX_ENTRIES, MAX_LABEL_BYTES, ModelDigest, RandomSource, StorageError, decode_howypln1,
};

const LEGACY_ID_DOMAIN: &[u8] = b"howy-legacy-id-v1\0";
const LEGACY_GENERATION_DOMAIN: &[u8] = b"howy-legacy-generation-v1\0";
const HOWYPLN1_MAGIC: &[u8; 8] = b"HOWYPLN1";

/// Bounded incremental form of the frozen legacy generation derivation.
pub struct LegacyGenerationHasher {
    hasher: Sha256,
    remaining: u64,
}

impl LegacyGenerationHasher {
    pub fn new(exact_source_length: u64, maximum_source_length: u64) -> Result<Self, StorageError> {
        if exact_source_length > maximum_source_length {
            return Err(StorageError::InvalidLength {
                format: "legacy source",
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(LEGACY_GENERATION_DOMAIN);
        hasher.update(exact_source_length.to_le_bytes());
        Ok(Self {
            hasher,
            remaining: exact_source_length,
        })
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| StorageError::IntegerOverflow("legacy source length"))?;
        self.remaining = self
            .remaining
            .checked_sub(length)
            .ok_or(StorageError::InvalidLength {
                format: "legacy source",
            })?;
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<u64, StorageError> {
        if self.remaining != 0 {
            return Err(StorageError::InvalidLength {
                format: "legacy source",
            });
        }
        Ok(generation_from_digest(self.hasher.finalize().into()))
    }
}

struct ZeroizingLegacyModels(UserModels);

impl Drop for ZeroizingLegacyModels {
    fn drop(&mut self) {
        self.0.username.zeroize();
        for model in &mut self.0.models {
            model.label.zeroize();
            model.embedding.zeroize();
        }
        self.0.models.clear();
    }
}

/// Legacy decoding permitted for the selected mode-0 source path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacySourceEncoding {
    /// The authoritative `.bin` path historically accepted bincode first and
    /// JSON from the same bytes if bincode decoding failed.
    BincodeThenJson,
    /// The `.json` fallback is JSON-only and is selected only when `.bin` is absent.
    JsonOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextRecordFormat {
    HowyPln1,
    Legacy,
}

#[derive(Debug, PartialEq)]
pub struct DecodedPlaintextRecord {
    record: EnrollmentRecord,
    format: PlaintextRecordFormat,
}

impl DecodedPlaintextRecord {
    const fn new(record: EnrollmentRecord, format: PlaintextRecordFormat) -> Self {
        Self { record, format }
    }

    pub fn record(&self) -> &EnrollmentRecord {
        &self.record
    }

    pub fn into_record(self) -> EnrollmentRecord {
        self.record
    }

    pub const fn format(&self) -> PlaintextRecordFormat {
        self.format
    }
}

/// Decode one exact mode-0 source file and bind it to the canonical NSS name
/// and current recognizer model.
///
/// HOWYPLN1 is always decoded as the frozen format. Other authoritative
/// `.bin` bytes retain the historical bincode-then-JSON behavior; a selected
/// `.json` fallback is JSON-only. Legacy IDs use original entry ordinals and
/// the generation token covers the complete, unmodified source byte string.
pub fn decode_plaintext_record(
    complete_source_bytes: &[u8],
    source_encoding: LegacySourceEncoding,
    expected_username: &CanonicalUsername,
    expected_model: ModelDigest,
    configured_max_entries: usize,
) -> Result<DecodedPlaintextRecord, StorageError> {
    if complete_source_bytes.starts_with(HOWYPLN1_MAGIC) {
        return decode_howypln1(complete_source_bytes, expected_username, expected_model)
            .map(|record| DecodedPlaintextRecord::new(record, PlaintextRecordFormat::HowyPln1));
    }
    if configured_max_entries == 0 || configured_max_entries > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }

    let legacy: UserModels = match source_encoding {
        LegacySourceEncoding::BincodeThenJson => {
            // bincode's top-level helpers historically use fixed integers and
            // allow trailing bytes. Recreate those options while adding a
            // hard read limit to prevent attacker-sized allocations.
            let limit = u64::try_from(complete_source_bytes.len())
                .map_err(|_| StorageError::IntegerOverflow("legacy source length"))?;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(limit)
                .deserialize(complete_source_bytes)
                .or_else(|_| serde_json::from_slice(complete_source_bytes))
                .map_err(|_| StorageError::InvalidLegacyRecord)?
        }
        LegacySourceEncoding::JsonOnly => serde_json::from_slice(complete_source_bytes)
            .map_err(|_| StorageError::InvalidLegacyRecord)?,
    };
    let mut legacy = ZeroizingLegacyModels(legacy);

    if legacy.0.username != expected_username.as_str() {
        return Err(StorageError::BindingMismatch("username"));
    }
    if legacy.0.models.len() > configured_max_entries || legacy.0.models.len() > MAX_ENTRIES {
        return Err(StorageError::LimitExceeded {
            field: "entry count",
        });
    }

    let generation = legacy_generation(complete_source_bytes)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(legacy.0.models.len())
        .map_err(|_| StorageError::AllocationFailed("legacy entries"))?;
    for (ordinal, model) in legacy.0.models.iter_mut().enumerate() {
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| StorageError::IntegerOverflow("legacy entry ordinal"))?;
        let id = legacy_enrollment_id(
            expected_username,
            ordinal,
            model.created,
            &model.label,
            &model.embedding,
        )?;
        let label = std::mem::take(&mut model.label);
        let embedding = std::mem::take(&mut model.embedding);
        entries.push(EnrollmentEntry::try_from_embedding_vec(
            id,
            model.created,
            label,
            embedding,
        )?);
    }
    let record = EnrollmentRecord::new(
        generation,
        expected_model,
        expected_username.clone(),
        entries,
    )?;
    Ok(DecodedPlaintextRecord::new(
        record,
        PlaintextRecordFormat::Legacy,
    ))
}

pub fn recognizer_model_digest(exact_file_bytes: &[u8]) -> ModelDigest {
    ModelDigest::new(Sha256::digest(exact_file_bytes).into())
}

pub fn legacy_enrollment_id(
    username: &CanonicalUsername,
    original_entry_ordinal: u32,
    created_unix_seconds: u64,
    label: &str,
    embedding: &[f32],
) -> Result<EnrollmentId, StorageError> {
    if label.len() > MAX_LABEL_BYTES {
        return Err(StorageError::LimitExceeded { field: "label" });
    }
    if embedding.len() != EMBEDDING_DIMENSION {
        return Err(StorageError::InvalidEmbeddingDimension(
            u16::try_from(embedding.len()).unwrap_or(u16::MAX),
        ));
    }
    if embedding.iter().any(|value| !value.is_finite()) {
        return Err(StorageError::NonFiniteEmbedding);
    }
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_ID_DOMAIN);
    hasher.update((username.as_bytes().len() as u16).to_le_bytes());
    hasher.update(username.as_bytes());
    hasher.update(original_entry_ordinal.to_le_bytes());
    hasher.update(created_unix_seconds.to_le_bytes());
    hasher.update((label.len() as u16).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((EMBEDDING_DIMENSION as u16).to_le_bytes());
    for value in embedding {
        hasher.update(value.to_bits().to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    legacy_id_from_digest_prefix(id)
}

fn legacy_id_from_digest_prefix(mut id: [u8; 16]) -> Result<EnrollmentId, StorageError> {
    if id == [0; 16] {
        id[15] = 1;
    }
    EnrollmentId::new(id)
}

pub fn legacy_generation(complete_source_bytes: &[u8]) -> Result<u64, StorageError> {
    let source_length = u64::try_from(complete_source_bytes.len())
        .map_err(|_| StorageError::IntegerOverflow("legacy source length"))?;
    let mut hasher = LegacyGenerationHasher::new(source_length, source_length)?;
    hasher.update(complete_source_bytes)?;
    hasher.finish()
}

fn generation_from_digest(digest: [u8; 32]) -> u64 {
    for chunk in digest.chunks_exact(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let candidate = u64::from_le_bytes(bytes);
        if candidate != 0 {
            return candidate;
        }
    }
    1
}

pub fn checked_next_generation(generation: u64) -> Result<u64, StorageError> {
    generation
        .checked_add(1)
        .ok_or(StorageError::GenerationOverflow)
}

pub fn generate_enrollment_id<R: RandomSource>(
    source: &mut R,
    existing: &HashSet<EnrollmentId>,
) -> Result<EnrollmentId, StorageError> {
    let mut bytes = [0u8; 16];
    source
        .fill_bytes(&mut bytes)
        .map_err(StorageError::RandomSource)?;
    let id = EnrollmentId::new(bytes)?;
    if existing.contains(&id) {
        return Err(StorageError::DuplicateEnrollmentId);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{
        LegacyGenerationHasher, generation_from_digest, legacy_generation,
        legacy_id_from_digest_prefix,
    };

    #[test]
    fn all_zero_generation_digest_maps_to_one() {
        assert_eq!(generation_from_digest([0; 32]), 1);
    }

    #[test]
    fn generation_uses_first_nonzero_little_endian_chunk() {
        let mut digest = [0u8; 32];
        digest[9] = 2;
        digest[16] = 9;
        assert_eq!(generation_from_digest(digest), 512);
    }

    #[test]
    fn all_zero_legacy_id_digest_prefix_maps_to_nonzero_id() {
        assert_eq!(
            legacy_id_from_digest_prefix([0; 16]).unwrap().as_bytes(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn streaming_legacy_generation_matches_exact_source_derivation() {
        let source = b"exact legacy source bytes across several chunks";
        let mut streaming =
            LegacyGenerationHasher::new(source.len() as u64, source.len() as u64).unwrap();
        for chunk in source.chunks(3) {
            streaming.update(chunk).unwrap();
        }
        assert_eq!(
            streaming.finish().unwrap(),
            legacy_generation(source).unwrap()
        );
    }
}
