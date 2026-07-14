use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use howy_common::storage::{
    AuthModel, BudgetPermit, CachedAuthModel, CanonicalUsername, EnrollmentAdmission, ModelLease,
    PlaintextBudget, StorageBackendError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelCacheLimits {
    max_users: usize,
    max_bytes: usize,
}

impl ModelCacheLimits {
    pub fn new(max_users: u32, max_bytes: u64) -> Result<Self, StorageBackendError> {
        let max_users = usize::try_from(max_users)
            .map_err(|_| StorageBackendError::InvalidInput("cache user limit"))?;
        let max_bytes = usize::try_from(max_bytes)
            .map_err(|_| StorageBackendError::InvalidInput("cache byte limit"))?;
        if max_users == 0 {
            return Err(StorageBackendError::InvalidInput("cache user limit"));
        }
        if max_bytes == 0 {
            return Err(StorageBackendError::InvalidInput("cache byte limit"));
        }
        Ok(Self {
            max_users,
            max_bytes,
        })
    }
}

struct CacheEntry {
    model: CachedAuthModel,
    bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<CanonicalUsername, CacheEntry>,
    bytes: usize,
    clock: u64,
    revision: u128,
    disabled: bool,
}

impl CacheState {
    fn next_clock(&mut self) -> u64 {
        if self.clock == u64::MAX {
            // Rollover is intentionally allocation-free. Existing entries
            // become one deterministic tie (username remains the eviction
            // tiebreaker), and the access requesting this tick becomes newer.
            for entry in self.entries.values_mut() {
                entry.last_used = 0;
            }
            self.clock = 0;
        }
        self.clock += 1;
        self.clock
    }

    fn remove(&mut self, username: &CanonicalUsername) -> Option<CacheEntry> {
        let removed = self.entries.remove(username)?;
        self.bytes = self
            .bytes
            .checked_sub(removed.bytes)
            .expect("model cache byte accounting underflow");
        self.revision += 1;
        Some(removed)
    }

    fn evict_lru_except(&mut self, protected: Option<&CanonicalUsername>) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter(|(username, _)| protected != Some(*username))
            .min_by(|(left_name, left), (right_name, right)| {
                (left.last_used, left_name.as_str()).cmp(&(right.last_used, right_name.as_str()))
            })
            .map(|(username, _)| username.clone());
        oldest.is_some_and(|username| self.remove(&username).is_some())
    }

    fn evict_lru(&mut self) -> bool {
        self.evict_lru_except(None)
    }
}

/// Daemon-only immutable model cache with deterministic LRU eviction.
///
/// Cache bytes are tracked independently from the hard plaintext budget. A
/// removed entry's budget permit remains owned by any outstanding Arc lease.
pub struct ModelCache {
    limits: ModelCacheLimits,
    budget: PlaintextBudget,
    state: Mutex<CacheState>,
}

impl ModelCache {
    pub fn new(limits: ModelCacheLimits, budget: PlaintextBudget) -> Self {
        Self {
            limits,
            budget,
            state: Mutex::new(CacheState::default()),
        }
    }

    pub fn get(&self, username: &CanonicalUsername) -> Option<ModelLease> {
        let mut state = self.lock_state();
        if state.disabled {
            return None;
        }
        let clock = state.next_clock();
        let entry = state.entries.get_mut(username)?;
        entry.last_used = clock;
        Some(entry.model.lease())
    }

    /// Return cached generation metadata without creating a model lease. This
    /// is used by prompt snapshots so an already-warm Mode 1 user does not
    /// touch storage or key material before confirmation.
    pub fn generation(&self, username: &CanonicalUsername) -> Option<u64> {
        let mut state = self.lock_state();
        if state.disabled {
            return None;
        }
        let clock = state.next_clock();
        let entry = state.entries.get_mut(username)?;
        entry.last_used = clock;
        Some(entry.model.generation())
    }

    pub fn revision(&self) -> u128 {
        self.lock_state().revision
    }

    /// Reserve transient operation memory, evicting cache-owned LRU entries
    /// until the hard global budget can admit it. Outstanding leases continue
    /// to own their permits and can therefore make this operation fail.
    pub fn reserve_operation(&self, bytes: usize) -> Result<BudgetPermit, StorageBackendError> {
        self.reserve_operation_except(bytes, None)
    }

    /// Reserve transient memory without evicting an existing authoritative
    /// cache value for the user being mutated. A failed mutation can therefore
    /// retain the previous coherent warm value while unrelated LRU entries may
    /// still be evicted to satisfy the hard global budget.
    pub fn reserve_operation_for_user(
        &self,
        bytes: usize,
        username: &CanonicalUsername,
    ) -> Result<BudgetPermit, StorageBackendError> {
        self.reserve_operation_except(bytes, Some(username))
    }

    fn reserve_operation_except(
        &self,
        bytes: usize,
        protected: Option<&CanonicalUsername>,
    ) -> Result<BudgetPermit, StorageBackendError> {
        let mut state = self.lock_state();
        if state.disabled {
            return Err(StorageBackendError::Unavailable);
        }
        loop {
            match self.budget.reserve(bytes) {
                Ok(permit) => return Ok(permit),
                Err(error @ StorageBackendError::MemoryBudgetExceeded { .. }) => {
                    if !state.evict_lru_except(protected) {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn reserve_enrollment_for_user(
        &self,
        operation_bytes: usize,
        plaintext_bytes: usize,
        username: &CanonicalUsername,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        self.reserve_enrollment_except(operation_bytes, plaintext_bytes, Some(username))
    }

    fn reserve_enrollment_except(
        &self,
        operation_bytes: usize,
        plaintext_bytes: usize,
        protected: Option<&CanonicalUsername>,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        let mut state = self.lock_state();
        if state.disabled {
            return Err(StorageBackendError::Unavailable);
        }
        loop {
            match self
                .budget
                .reserve_enrollment(operation_bytes, plaintext_bytes)
            {
                Ok(admission) => return Ok(admission),
                Err(error @ StorageBackendError::MemoryBudgetExceeded { .. }) => {
                    if !state.evict_lru_except(protected) {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn owns_permit(&self, permit: &BudgetPermit) -> bool {
        self.budget.owns(permit)
    }

    /// Insert one already-budgeted immutable model and return its first lease.
    pub fn insert(
        &self,
        username: CanonicalUsername,
        model: AuthModel,
        permit: BudgetPermit,
    ) -> Result<ModelLease, StorageBackendError> {
        let bytes = model.plaintext_bytes();
        if bytes > self.limits.max_bytes {
            return Err(StorageBackendError::MemoryBudgetExceeded {
                requested: bytes,
                available: self.limits.max_bytes,
            });
        }
        let cached = CachedAuthModel::new(model, permit)?;
        self.insert_cached(username, cached)
    }

    fn insert_cached(
        &self,
        username: CanonicalUsername,
        cached: CachedAuthModel,
    ) -> Result<ModelLease, StorageBackendError> {
        let bytes = cached.plaintext_bytes();
        if bytes > self.limits.max_bytes {
            return Err(StorageBackendError::MemoryBudgetExceeded {
                requested: bytes,
                available: self.limits.max_bytes,
            });
        }
        let mut state = self.lock_state();
        if state.disabled {
            return Err(StorageBackendError::Unavailable);
        }
        state.remove(&username);
        while state.entries.len() >= self.limits.max_users
            || state.bytes.saturating_add(bytes) > self.limits.max_bytes
        {
            if !state.evict_lru() {
                return Err(StorageBackendError::MemoryBudgetExceeded {
                    requested: bytes,
                    available: self.limits.max_bytes.saturating_sub(state.bytes),
                });
            }
        }
        let clock = state.next_clock();
        let lease = cached.lease();
        state.bytes = state
            .bytes
            .checked_add(bytes)
            .expect("model cache byte accounting overflow");
        state.entries.insert(
            username,
            CacheEntry {
                model: cached,
                bytes,
                last_used: clock,
            },
        );
        state.revision += 1;
        Ok(lease)
    }

    /// Publish a backend-created provisional model only if no cache mutation,
    /// reload, eviction, or competing cold reader changed shared state since
    /// the original miss. Existing entries are never removed or overwritten.
    pub fn insert_provisional_if_revision(
        &self,
        username: CanonicalUsername,
        expected_revision: u128,
        expected_generation: u64,
        cached: CachedAuthModel,
        publish: &mut dyn FnMut() -> bool,
    ) -> Result<bool, StorageBackendError> {
        if cached.generation() != expected_generation {
            return Err(StorageBackendError::InvalidInput(
                "provisional cache generation",
            ));
        }
        let bytes = cached.plaintext_bytes();
        if bytes > self.limits.max_bytes {
            return Ok(false);
        }
        let mut state = self.lock_state();
        if state.disabled {
            return Err(StorageBackendError::Unavailable);
        }
        if state.revision != expected_revision || state.entries.contains_key(&username) {
            return Ok(false);
        }
        // This predicate is the publication linearization point. It executes
        // while the cache lock excludes reload, readers, eviction, and newer
        // insertion. A disconnect observed after it returns true is therefore
        // post-publication; false performs no cache mutation or eviction.
        if !publish() {
            return Ok(false);
        }
        while state.entries.len() >= self.limits.max_users
            || state.bytes.saturating_add(bytes) > self.limits.max_bytes
        {
            if !state.evict_lru() {
                return Ok(false);
            }
        }
        let clock = state.next_clock();
        state.bytes = state
            .bytes
            .checked_add(bytes)
            .expect("model cache byte accounting overflow");
        state.entries.insert(
            username,
            CacheEntry {
                model: cached,
                bytes,
                last_used: clock,
            },
        );
        state.revision += 1;
        Ok(true)
    }

    pub fn invalidate(&self, username: &CanonicalUsername) {
        let mut state = self.lock_state();
        if state.remove(username).is_none() {
            state.revision += 1;
        }
    }

    pub fn clear(&self) {
        let mut state = self.lock_state();
        state.revision += 1;
        state.entries.clear();
        state.bytes = 0;
    }

    /// Permanently disable this cache instance and invalidate both committed
    /// entries and every revision-bound provisional publication.
    pub fn poison(&self) {
        let mut state = self.lock_state();
        state.disabled = true;
        state.revision = state.revision.saturating_add(1);
        state.entries.clear();
        state.bytes = 0;
    }

    #[cfg(test)]
    pub fn is_poisoned(&self) -> bool {
        self.lock_state().disabled
    }

    #[cfg(test)]
    pub fn force_clock_rollover_for_test(&self) {
        self.lock_state().clock = u64::MAX;
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    fn stats(&self) -> (usize, usize) {
        let state = self.lock_state();
        (state.entries.len(), state.bytes)
    }
}

impl fmt::Debug for ModelCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("ModelCache")
            .field("limits", &self.limits)
            .field("entry_count", &state.entries.len())
            .field("plaintext_bytes", &state.bytes)
            .finish_non_exhaustive()
    }
}

/// Weak registry of per-canonical-user serializing locks.
#[derive(Default)]
pub struct UserSerializers {
    locks: Mutex<HashMap<CanonicalUsername, Weak<Mutex<()>>>>,
}

/// Fail-fast same-user enrollment admission registry. The returned guard is
/// attached to the caller-owned input budget permit and therefore releases on
/// every success, error, panic, or abandoned request path.
#[derive(Default)]
pub struct UserAdmissionRegistry {
    active: Mutex<HashSet<CanonicalUsername>>,
}

impl UserAdmissionRegistry {
    pub fn try_acquire(
        self: &Arc<Self>,
        username: &CanonicalUsername,
    ) -> Result<UserAdmissionGuard, StorageBackendError> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !active.insert(username.clone()) {
            return Err(StorageBackendError::Unavailable);
        }
        Ok(UserAdmissionGuard {
            registry: Arc::clone(self),
            username: Some(username.clone()),
        })
    }
}

pub struct UserAdmissionGuard {
    registry: Arc<UserAdmissionRegistry>,
    username: Option<CanonicalUsername>,
}

impl Drop for UserAdmissionGuard {
    fn drop(&mut self) {
        let Some(username) = self.username.take() else {
            return;
        };
        self.registry
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&username);
    }
}

impl UserSerializers {
    pub fn for_user(&self, username: &CanonicalUsername) -> Arc<Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(username).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(username.clone(), Arc::downgrade(&lock));
        lock
    }
}

impl fmt::Debug for UserSerializers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("UserSerializers")
            .field(
                "live_lock_count",
                &locks
                    .values()
                    .filter(|lock| lock.strong_count() != 0)
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use howy_common::storage::{EMBEDDING_DIMENSION, EnrollmentId, ModelDigest, PlaintextBudget};

    use super::*;

    fn username(value: &str) -> CanonicalUsername {
        CanonicalUsername::new(value).unwrap()
    }

    fn model(generation: u64, id: u8, label_bytes: usize) -> AuthModel {
        AuthModel::new(
            generation,
            ModelDigest::new([0x42; 32]),
            EMBEDDING_DIMENSION,
            vec![EnrollmentId::new([id; 16]).unwrap()],
            vec!["x".repeat(label_bytes)],
            vec![f32::from(id); EMBEDDING_DIMENSION],
        )
        .unwrap()
    }

    fn insert(cache: &ModelCache, name: &str, model: AuthModel) -> ModelLease {
        let bytes = model.plaintext_bytes();
        let permit = cache.budget.reserve(bytes).unwrap();
        cache.insert(username(name), model, permit).unwrap()
    }

    #[test]
    fn deterministic_lru_enforces_user_and_byte_limits() {
        let sample = model(1, 1, 1).plaintext_bytes();
        let budget = PlaintextBudget::new(sample * 4).unwrap();
        let cache = ModelCache::new(
            ModelCacheLimits::new(2, u64::try_from(sample * 2).unwrap()).unwrap(),
            budget,
        );
        drop(insert(&cache, "alice", model(1, 1, 1)));
        drop(insert(&cache, "bob", model(1, 2, 1)));
        drop(cache.get(&username("alice")).unwrap());
        drop(insert(&cache, "carol", model(1, 3, 1)));
        assert!(cache.get(&username("bob")).is_none());
        assert!(cache.get(&username("alice")).is_some());
        assert!(cache.get(&username("carol")).is_some());
        assert_eq!(cache.stats(), (2, sample * 2));

        let byte_bounded = ModelCache::new(
            ModelCacheLimits::new(3, u64::try_from(sample * 2).unwrap()).unwrap(),
            PlaintextBudget::new(sample * 3).unwrap(),
        );
        drop(insert(&byte_bounded, "alice", model(1, 1, 1)));
        drop(insert(&byte_bounded, "bob", model(1, 2, 1)));
        drop(insert(&byte_bounded, "carol", model(1, 3, 1)));
        assert!(byte_bounded.get(&username("alice")).is_none());
        assert_eq!(byte_bounded.stats(), (2, sample * 2));
    }

    #[test]
    fn evicted_outstanding_lease_keeps_budget_charged_until_drop() {
        let sample = model(1, 1, 1).plaintext_bytes();
        let operation = sample + 1;
        let budget = PlaintextBudget::new(sample + operation).unwrap();
        let cache = ModelCache::new(
            ModelCacheLimits::new(1, u64::try_from(sample).unwrap()).unwrap(),
            budget.clone(),
        );
        let lease = insert(&cache, "alice", model(1, 1, 1));
        cache.invalidate(&username("alice"));
        assert_eq!(budget.used(), sample);
        assert!(matches!(
            cache.reserve_operation(operation + 1),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        drop(lease);
        let permit = cache.reserve_operation(operation + 1).unwrap();
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn poison_and_panic_paths_recover_without_leaking_permits() {
        let budget = PlaintextBudget::new(1024).unwrap();
        let cache = Arc::new(ModelCache::new(
            ModelCacheLimits::new(1, 1024).unwrap(),
            budget.clone(),
        ));
        let poison = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _guard = poison.state.lock().unwrap();
            panic!("poison cache state");
        })
        .join();
        assert_eq!(cache.stats(), (0, 0));

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _permit = cache.reserve_operation(512).unwrap();
            panic!("operation panic");
        }));
        assert!(result.is_err());
        assert_eq!(budget.used(), 0);
        assert!(cache.reserve_operation(1024).is_ok());
    }

    #[test]
    fn cache_debug_redacts_labels_and_embeddings() {
        let sensitive = "cache-secret-label";
        let model = AuthModel::new(
            1,
            ModelDigest::new([0x42; 32]),
            EMBEDDING_DIMENSION,
            vec![EnrollmentId::new([1; 16]).unwrap()],
            vec![sensitive.to_owned()],
            vec![1234.5; EMBEDDING_DIMENSION],
        )
        .unwrap();
        let bytes = model.plaintext_bytes();
        let cache = ModelCache::new(
            ModelCacheLimits::new(1, u64::try_from(bytes).unwrap()).unwrap(),
            PlaintextBudget::new(bytes).unwrap(),
        );
        drop(insert(&cache, "alice", model));
        let debug = format!("{cache:?}");
        assert!(!debug.contains(sensitive));
        assert!(!debug.contains("1234.5"));
    }

    #[test]
    fn provisional_predicate_is_under_lock_and_false_mutates_nothing() {
        let sample = model(1, 1, 1).plaintext_bytes();
        let budget = PlaintextBudget::new(sample * 2).unwrap();
        let cache = ModelCache::new(
            ModelCacheLimits::new(1, u64::try_from(sample).unwrap()).unwrap(),
            budget.clone(),
        );
        drop(insert(&cache, "alice", model(1, 1, 1)));
        let revision = cache.revision();
        let bob_model = model(1, 2, 1);
        let bob = CachedAuthModel::new(bob_model, budget.reserve(sample).unwrap()).unwrap();
        let mut publish = || {
            assert!(cache.state.try_lock().is_err());
            false
        };
        assert!(
            !cache
                .insert_provisional_if_revision(username("bob"), revision, 1, bob, &mut publish)
                .unwrap()
        );
        assert!(cache.get(&username("alice")).is_some());
        assert!(cache.get(&username("bob")).is_none());
        assert_eq!(cache.stats(), (1, sample));
        assert_eq!(budget.used(), sample);
    }

    #[test]
    fn clock_rollover_resets_in_place_and_keeps_current_hit_newest() {
        let sample = model(1, 1, 1).plaintext_bytes();
        let cache = ModelCache::new(
            ModelCacheLimits::new(2, u64::try_from(sample * 2).unwrap()).unwrap(),
            PlaintextBudget::new(sample * 3).unwrap(),
        );
        drop(insert(&cache, "alice", model(1, 1, 1)));
        drop(insert(&cache, "bob", model(1, 2, 1)));
        cache.force_clock_rollover_for_test();
        drop(cache.get(&username("alice")).unwrap());
        drop(insert(&cache, "carol", model(1, 3, 1)));
        assert!(cache.get(&username("alice")).is_some());
        assert!(cache.get(&username("bob")).is_none());
        assert!(cache.get(&username("carol")).is_some());
    }
}
