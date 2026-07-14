use std::collections::HashSet;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use super::{Aes256Key, GCM_TAG_BYTES, GcmNonce, GcmTag, StorageError};

/// Maximum accepted encryption nonces permitted under one v1 key in one daemon
/// process.
///
/// Root-authorized enrollment mutations are expected to be many orders of
/// magnitude below this limit. At 12 bytes per nonce, the logical nonce payload
/// is exactly 786,432 bytes. The tracker performs one fallible reserve, permits
/// at most twice as many `HashSet` capacity units (1,572,864 bytes of key-slot
/// payload), and never grows after that reserve. Hash-table control bytes and
/// allocator metadata are implementation-specific fixed overhead for that one
/// allocation.
///
/// V1 deliberately retains independently random 96-bit OS nonces rather than
/// inventing a crash-persistent counter. Restarting the daemon resets this
/// in-memory duplicate detector, so this finite process-lifetime ceiling is a
/// fail-closed resource bound, not a durable global invocation counter.
pub const MAX_ENCRYPTIONS_PER_KEY_V1: u64 = 65_536;

const MAX_NONCE_TRACKER_CAPACITY: usize = 2 * MAX_ENCRYPTIONS_PER_KEY_V1 as usize;

/// Minimal injectable interface used for nonces and enrollment IDs.
pub trait RandomSource {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String>;
}

impl<T: RandomSource + ?Sized> RandomSource for Box<T> {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
        (**self).fill_bytes(destination)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
        getrandom::fill(destination).map_err(|error| error.to_string())
    }
}

/// Process-lifetime nonce generator for one backend.
///
/// The generator never evicts accepted nonces and rejects any duplicate. A
/// backend must retain one generator for its entire process lifetime and route
/// every write under its key through that instance. Accepted nonces, including
/// those consumed by a later failed durable write, remain tracked. The fixed v1
/// write ceiling bounds this set and fails closed rather than wrapping or
/// evicting an accepted nonce.
pub struct NonceGenerator<R = OsRandomSource> {
    source: R,
    seen: HashSet<GcmNonce>,
    accepted: u64,
    ceiling: u64,
    allocated_capacity: Option<usize>,
}

impl Default for NonceGenerator<OsRandomSource> {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceGenerator<OsRandomSource> {
    pub fn new() -> Self {
        Self {
            source: OsRandomSource,
            seen: HashSet::new(),
            accepted: 0,
            ceiling: MAX_ENCRYPTIONS_PER_KEY_V1,
            allocated_capacity: None,
        }
    }
}

impl<R: RandomSource> NonceGenerator<R> {
    /// Construct an injected generator while retaining the production v1
    /// ceiling. Production backends use [`NonceGenerator::new`]; this entry
    /// point exists for deterministic backend and codec verification.
    pub fn from_source(source: R) -> Self {
        Self {
            source,
            seen: HashSet::new(),
            accepted: 0,
            ceiling: MAX_ENCRYPTIONS_PER_KEY_V1,
            allocated_capacity: None,
        }
    }

    /// Construct an injected generator with a lower fail-closed ceiling.
    ///
    /// The ceiling may only tighten the frozen v1 maximum. This is useful for
    /// deterministic policy-boundary tests without performing billions of
    /// encryption attempts.
    pub fn from_source_with_ceiling(source: R, ceiling: u64) -> Result<Self, StorageError> {
        if ceiling == 0 || ceiling > MAX_ENCRYPTIONS_PER_KEY_V1 {
            return Err(StorageError::InvalidNonceCeiling);
        }
        Ok(Self {
            source,
            seen: HashSet::new(),
            accepted: 0,
            ceiling,
            allocated_capacity: None,
        })
    }

    pub(crate) fn generate(&mut self) -> Result<GcmNonce, StorageError> {
        if self.accepted >= self.ceiling {
            return Err(StorageError::NonceWriteLimitExceeded);
        }

        // Reserve the complete process-lifetime table before consulting the
        // random source. There is no later growth, eviction, or retry-on-full.
        // A capacity unexpectedly larger than the reviewed bound is released
        // and rejected rather than silently accepting an implementation-driven
        // memory increase.
        if self.allocated_capacity.is_none() {
            let requested = usize::try_from(self.ceiling)
                .map_err(|_| StorageError::AllocationFailed("nonce tracker"))?;
            self.seen
                .try_reserve(requested)
                .map_err(|_| StorageError::AllocationFailed("nonce tracker"))?;
            let capacity = self.seen.capacity();
            if capacity < requested || capacity > MAX_NONCE_TRACKER_CAPACITY {
                self.seen = HashSet::new();
                return Err(StorageError::AllocationFailed("nonce tracker"));
            }
            self.allocated_capacity = Some(capacity);
        }

        let mut nonce = [0u8; 12];
        self.source
            .fill_bytes(&mut nonce)
            .map_err(StorageError::RandomSource)?;
        if !self.seen.insert(nonce) {
            return Err(StorageError::DuplicateNonce);
        }
        self.accepted = self
            .accepted
            .checked_add(1)
            .ok_or(StorageError::NonceWriteLimitExceeded)?;
        Ok(nonce)
    }

    #[cfg(test)]
    pub(crate) fn accepted_count(&self) -> u64 {
        self.accepted
    }

    #[cfg(test)]
    pub(crate) fn tracker_capacity(&self) -> usize {
        self.seen.capacity()
    }
}

/// Low-level helper. `key` remains caller-owned and is never zeroized here;
/// callers must retain borrowed key material in guaranteed zeroizing storage.
pub(crate) fn encrypt_aes_256_gcm(
    key: &Aes256Key,
    nonce: &GcmNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, GcmTag), StorageError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StorageError::AuthenticationFailed)?;
    let nonce = Nonce::from(*nonce);
    let combined_len = plaintext
        .len()
        .checked_add(GCM_TAG_BYTES)
        .ok_or(StorageError::IntegerOverflow("AES-GCM output length"))?;
    // The in-place buffer is zeroizing before plaintext is copied into it, so
    // allocation, AEAD failure, and unwind paths cannot drop a plaintext copy
    // without a wipe.
    let mut combined = Zeroizing::new(Vec::new());
    combined
        .try_reserve_exact(combined_len)
        .map_err(|_| StorageError::AllocationFailed("AES-GCM output"))?;
    combined.extend_from_slice(plaintext);
    debug_assert_eq!(combined.capacity(), combined_len);
    cipher
        .encrypt_in_place(&nonce, aad, &mut *combined)
        .map_err(|_| StorageError::AuthenticationFailed)?;
    let tag_offset = combined
        .len()
        .checked_sub(GCM_TAG_BYTES)
        .ok_or(StorageError::InvalidLength { format: "AES-GCM" })?;
    let tag_bytes = Zeroizing::new(combined.split_off(tag_offset));
    let tag: GcmTag = tag_bytes
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::InvalidLength { format: "AES-GCM" })?;
    // Contents are ciphertext after successful in-place encryption, so they
    // no longer require zeroizing ownership in the returned wire buffer.
    Ok((std::mem::take(&mut *combined), tag))
}

/// Low-level helper. Returned plaintext is zeroizing from the moment in-place
/// authenticated decryption can expose it. `key` remains caller-owned; callers
/// must retain borrowed key material in guaranteed zeroizing storage.
pub(crate) fn decrypt_aes_256_gcm(
    key: &Aes256Key,
    nonce: &GcmNonce,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &GcmTag,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StorageError::AuthenticationFailed)?;
    let nonce = Nonce::from(*nonce);
    let combined_len = ciphertext
        .len()
        .checked_add(GCM_TAG_BYTES)
        .ok_or(StorageError::IntegerOverflow("AES-GCM input length"))?;
    let mut combined = Zeroizing::new(Vec::new());
    combined
        .try_reserve_exact(combined_len)
        .map_err(|_| StorageError::AllocationFailed("AES-GCM input"))?;
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    debug_assert_eq!(combined.capacity(), combined_len);
    cipher
        .decrypt_in_place(&nonce, aad, &mut *combined)
        .map_err(|_| StorageError::AuthenticationFailed)?;
    Ok(combined)
}
