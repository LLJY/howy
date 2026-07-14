use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, TryLockError, Weak};
use std::time::Duration;

use howy_common::paths::{MODE1_MODELS_DIR, MODELS_DIR};
use howy_common::provisioning::{
    NamespaceEntryClassification, NamespaceFileType, classified_mode1_transaction_username,
    classify_mode1_namespace_entry,
};
#[cfg(test)]
use howy_common::storage::GCM_TAG_BYTES;
use howy_common::storage::{
    ABSENT_GENERATION, AppendAdmissionShape, AppendRequest, AppendResult, AuthModel,
    AuthenticationCachePromotion, AuthenticationLoad, BackendHealth, BackendUnavailable,
    BudgetPermit, CachedAuthModel, CancellationSignal, CandidatePresence, CanonicalUsername,
    ClearRequest, ClearResult, EncryptedHeader, EnrollmentAdmission, EnrollmentRecord,
    HOWYENC1_FIXED_INSPECTION_BYTES, HOWYENC1_MAX_RECORD_BYTES, IoOperation, MAX_ENTRIES,
    MAX_PLAINTEXT_BYTES, MetadataList, ModelDigest, ModelLease, NonceGenerator, OsRandomSource,
    OuterRecordClassification, OuterRecordStatus, PlaintextAllocationEstimate, PlaintextBudget,
    PromptOpaqueIdentity, PromptStorageSnapshot, RandomSource, ReloadResult, RemoveRequest,
    RemoveResult, STORAGE_DIRECTORY_MODE, STORAGE_RECORD_MODE, StorageBackend, StorageBackendError,
    StorageError, StorageIoError, StorageMode, checked_next_generation, inspect_howyenc1,
    inspect_howyenc1_metadata,
};
use tracing::warn;
use zeroize::Zeroizing;

use crate::mode1_key::Mode1KeyContext;

use super::cache::{ModelCache, ModelCacheLimits, UserAdmissionRegistry, UserSerializers};
use super::plaintext::DirectoryBehavior;

const TEMP_CREATE_ATTEMPTS: usize = 16;
const CANCELLATION_LOCK_POLL: Duration = Duration::from_millis(10);
const MAX_MODE1_NAMESPACE_ENTRIES: usize = 4_096;

#[cfg(test)]
mod allocation_probe {
    use std::cell::UnsafeCell;

    const MAX_TRACKED_ALLOCATIONS: usize = 4_096;
    const MAX_CLASS_PLAN: usize = 8;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(super) enum AllocationClass {
        #[default]
        Infrastructure,
        PlaintextSensitive,
    }

    #[derive(Clone, Copy)]
    pub(super) struct ClassRule {
        expected_bytes: usize,
        class: AllocationClass,
    }

    impl ClassRule {
        pub(super) const fn exact(expected_bytes: usize, class: AllocationClass) -> Self {
            Self {
                expected_bytes,
                class,
            }
        }

        const EMPTY: Self = Self {
            expected_bytes: 0,
            class: AllocationClass::Infrastructure,
        };
    }

    #[derive(Clone, Copy)]
    struct TrackedAllocation {
        pointer: usize,
        requested_bytes: usize,
        accounted_bytes: usize,
        class: AllocationClass,
    }

    impl TrackedAllocation {
        const EMPTY: Self = Self {
            pointer: 0,
            requested_bytes: 0,
            accounted_bytes: 0,
            class: AllocationClass::Infrastructure,
        };
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(super) struct AllocationMetrics {
        pub allocation_calls: usize,
        pub allocation_requested_bytes: usize,
        pub largest_allocation_request: usize,
        pub zeroed_allocation_calls: usize,
        pub reallocation_calls: usize,
        pub plaintext_reallocation_calls: usize,
        pub reallocation_requested_bytes: usize,
        pub reallocation_old_layout_bytes: usize,
        pub deallocation_calls: usize,
        pub deallocation_layout_bytes: usize,
        pub largest_deallocation_layout: usize,
        pub current_live_bytes: usize,
        pub peak_live_bytes: usize,
        pub current_plaintext_bytes: usize,
        pub peak_plaintext_bytes: usize,
        pub current_allocations: usize,
        pub peak_allocations: usize,
        pub operation_permit_bytes: usize,
        pub layout_mismatches: usize,
        pub classification_mismatches: usize,
        pub untracked_reallocations: usize,
        pub untracked_plaintext_reallocations: usize,
        pub untracked_reallocation_old_layout_bytes: usize,
        pub slot_overflow: bool,
    }

    struct ProbeState {
        active: bool,
        class_override: Option<AllocationClass>,
        class_plan: [ClassRule; MAX_CLASS_PLAN],
        class_plan_len: usize,
        class_plan_index: usize,
        class_plan_active: bool,
        class_plan_allows_extra: bool,
        allocations: [TrackedAllocation; MAX_TRACKED_ALLOCATIONS],
        metrics: AllocationMetrics,
    }

    impl ProbeState {
        const EMPTY: Self = Self {
            active: false,
            class_override: None,
            class_plan: [ClassRule::EMPTY; MAX_CLASS_PLAN],
            class_plan_len: 0,
            class_plan_index: 0,
            class_plan_active: false,
            class_plan_allows_extra: false,
            allocations: [TrackedAllocation::EMPTY; MAX_TRACKED_ALLOCATIONS],
            metrics: AllocationMetrics {
                allocation_calls: 0,
                allocation_requested_bytes: 0,
                largest_allocation_request: 0,
                zeroed_allocation_calls: 0,
                reallocation_calls: 0,
                plaintext_reallocation_calls: 0,
                reallocation_requested_bytes: 0,
                reallocation_old_layout_bytes: 0,
                deallocation_calls: 0,
                deallocation_layout_bytes: 0,
                largest_deallocation_layout: 0,
                current_live_bytes: 0,
                peak_live_bytes: 0,
                current_plaintext_bytes: 0,
                peak_plaintext_bytes: 0,
                current_allocations: 0,
                peak_allocations: 0,
                operation_permit_bytes: 0,
                layout_mismatches: 0,
                classification_mismatches: 0,
                untracked_reallocations: 0,
                untracked_plaintext_reallocations: 0,
                untracked_reallocation_old_layout_bytes: 0,
                slot_overflow: false,
            },
        };

        fn allocation_class(&mut self, requested_bytes: usize) -> AllocationClass {
            if self.class_plan_active && self.class_plan_index < self.class_plan_len {
                let rule = self.class_plan[self.class_plan_index];
                self.class_plan_index += 1;
                if rule.expected_bytes != requested_bytes {
                    self.metrics.classification_mismatches =
                        self.metrics.classification_mismatches.saturating_add(1);
                }
                return rule.class;
            }
            if self.class_plan_active && !self.class_plan_allows_extra {
                self.metrics.classification_mismatches =
                    self.metrics.classification_mismatches.saturating_add(1);
            }
            self.class_override
                .unwrap_or(AllocationClass::Infrastructure)
        }

        fn find(&self, pointer: usize) -> Option<usize> {
            self.allocations
                .iter()
                .position(|allocation| allocation.pointer == pointer)
        }

        fn insert(
            &mut self,
            pointer: usize,
            requested_bytes: usize,
            accounted_bytes: usize,
            class: AllocationClass,
        ) {
            let Some(slot) = self
                .allocations
                .iter_mut()
                .find(|allocation| allocation.pointer == 0)
            else {
                self.metrics.slot_overflow = true;
                return;
            };
            *slot = TrackedAllocation {
                pointer,
                requested_bytes,
                accounted_bytes,
                class,
            };
            self.metrics.current_live_bytes = self
                .metrics
                .current_live_bytes
                .saturating_add(accounted_bytes);
            self.metrics.peak_live_bytes = self
                .metrics
                .peak_live_bytes
                .max(self.metrics.current_live_bytes);
            if class == AllocationClass::PlaintextSensitive {
                self.metrics.current_plaintext_bytes = self
                    .metrics
                    .current_plaintext_bytes
                    .saturating_add(accounted_bytes);
                self.metrics.peak_plaintext_bytes = self
                    .metrics
                    .peak_plaintext_bytes
                    .max(self.metrics.current_plaintext_bytes);
            }
            self.metrics.current_allocations = self.metrics.current_allocations.saturating_add(1);
            self.metrics.peak_allocations = self
                .metrics
                .peak_allocations
                .max(self.metrics.current_allocations);
        }
    }

    struct ProbeTls(UnsafeCell<ProbeState>);

    impl Drop for ProbeTls {
        fn drop(&mut self) {}
    }

    std::thread_local! {
        static STATE: ProbeTls = const { ProbeTls(UnsafeCell::new(ProbeState::EMPTY)) };
    }

    fn try_with_state<T>(operation: impl FnOnce(&mut ProbeState) -> T) -> Option<T> {
        STATE
            .try_with(|state| {
                // SAFETY: STATE is thread-local, and allocator callbacks never
                // allocate or recursively enter this probe.
                operation(unsafe { &mut *state.0.get() })
            })
            .ok()
    }

    fn with_state<T>(operation: impl FnOnce(&mut ProbeState) -> T) -> T {
        try_with_state(operation).expect("allocation probe TLS unavailable")
    }

    pub(super) fn record_alloc(pointer: *mut u8, requested_bytes: usize, zeroed: bool) {
        if pointer.is_null() || requested_bytes == 0 {
            return;
        }
        let _ = try_with_state(|state| {
            if !state.active {
                return;
            }
            let class = state.allocation_class(requested_bytes);
            state.metrics.allocation_calls = state.metrics.allocation_calls.saturating_add(1);
            state.metrics.allocation_requested_bytes = state
                .metrics
                .allocation_requested_bytes
                .saturating_add(requested_bytes);
            state.metrics.largest_allocation_request = state
                .metrics
                .largest_allocation_request
                .max(requested_bytes);
            if zeroed {
                state.metrics.zeroed_allocation_calls =
                    state.metrics.zeroed_allocation_calls.saturating_add(1);
            }
            state.insert(pointer as usize, requested_bytes, requested_bytes, class);
        });
    }

    pub(super) fn record_dealloc(pointer: *mut u8, layout_bytes: usize) {
        if pointer.is_null() {
            return;
        }
        let _ = try_with_state(|state| {
            if !state.active {
                return;
            }
            let Some(index) = state.find(pointer as usize) else {
                return;
            };
            let tracked = state.allocations[index];
            state.allocations[index] = TrackedAllocation::EMPTY;
            if tracked.requested_bytes != layout_bytes {
                state.metrics.layout_mismatches = state.metrics.layout_mismatches.saturating_add(1);
            }
            state.metrics.deallocation_calls = state.metrics.deallocation_calls.saturating_add(1);
            state.metrics.deallocation_layout_bytes = state
                .metrics
                .deallocation_layout_bytes
                .saturating_add(layout_bytes);
            state.metrics.largest_deallocation_layout =
                state.metrics.largest_deallocation_layout.max(layout_bytes);
            state.metrics.current_live_bytes = state
                .metrics
                .current_live_bytes
                .saturating_sub(tracked.accounted_bytes);
            if tracked.class == AllocationClass::PlaintextSensitive {
                state.metrics.current_plaintext_bytes = state
                    .metrics
                    .current_plaintext_bytes
                    .saturating_sub(tracked.accounted_bytes);
            }
            state.metrics.current_allocations = state.metrics.current_allocations.saturating_sub(1);
        });
    }

    pub(super) fn record_realloc(
        old_pointer: *mut u8,
        old_layout_bytes: usize,
        new_pointer: *mut u8,
        new_requested_bytes: usize,
    ) {
        if new_pointer.is_null() {
            return;
        }
        let _ = try_with_state(|state| {
            if !state.active {
                return;
            }
            let Some(index) = state.find(old_pointer as usize) else {
                state.metrics.untracked_reallocations =
                    state.metrics.untracked_reallocations.saturating_add(1);
                state.metrics.reallocation_calls =
                    state.metrics.reallocation_calls.saturating_add(1);
                state.metrics.reallocation_requested_bytes = state
                    .metrics
                    .reallocation_requested_bytes
                    .saturating_add(new_requested_bytes);
                state.metrics.reallocation_old_layout_bytes = state
                    .metrics
                    .reallocation_old_layout_bytes
                    .saturating_add(old_layout_bytes);
                state.metrics.untracked_reallocation_old_layout_bytes = state
                    .metrics
                    .untracked_reallocation_old_layout_bytes
                    .saturating_add(old_layout_bytes);
                let class = if state.class_plan_active || state.class_override.is_some() {
                    state.allocation_class(new_requested_bytes)
                } else {
                    AllocationClass::Infrastructure
                };
                let accounted_bytes = if class == AllocationClass::PlaintextSensitive {
                    state.metrics.untracked_plaintext_reallocations = state
                        .metrics
                        .untracked_plaintext_reallocations
                        .saturating_add(1);
                    state.metrics.plaintext_reallocation_calls =
                        state.metrics.plaintext_reallocation_calls.saturating_add(1);
                    new_requested_bytes
                } else {
                    new_requested_bytes.saturating_sub(old_layout_bytes)
                };
                state.insert(
                    new_pointer as usize,
                    new_requested_bytes,
                    accounted_bytes,
                    class,
                );
                return;
            };
            let tracked = state.allocations[index];
            let new_class = if state.class_plan_active || state.class_override.is_some() {
                state.allocation_class(new_requested_bytes)
            } else {
                tracked.class
            };
            if tracked.requested_bytes != old_layout_bytes {
                state.metrics.layout_mismatches = state.metrics.layout_mismatches.saturating_add(1);
            }
            state.metrics.reallocation_calls = state.metrics.reallocation_calls.saturating_add(1);
            if tracked.class == AllocationClass::PlaintextSensitive
                || new_class == AllocationClass::PlaintextSensitive
            {
                state.metrics.plaintext_reallocation_calls =
                    state.metrics.plaintext_reallocation_calls.saturating_add(1);
            }
            state.metrics.reallocation_requested_bytes = state
                .metrics
                .reallocation_requested_bytes
                .saturating_add(new_requested_bytes);
            state.metrics.reallocation_old_layout_bytes = state
                .metrics
                .reallocation_old_layout_bytes
                .saturating_add(old_layout_bytes);
            state.metrics.current_live_bytes = state
                .metrics
                .current_live_bytes
                .saturating_sub(tracked.accounted_bytes)
                .saturating_add(new_requested_bytes);
            state.metrics.peak_live_bytes = state
                .metrics
                .peak_live_bytes
                .max(state.metrics.current_live_bytes);
            if tracked.class == AllocationClass::PlaintextSensitive {
                state.metrics.current_plaintext_bytes = state
                    .metrics
                    .current_plaintext_bytes
                    .saturating_sub(tracked.accounted_bytes);
            }
            if new_class == AllocationClass::PlaintextSensitive {
                state.metrics.current_plaintext_bytes = state
                    .metrics
                    .current_plaintext_bytes
                    .saturating_add(new_requested_bytes);
                state.metrics.peak_plaintext_bytes = state
                    .metrics
                    .peak_plaintext_bytes
                    .max(state.metrics.current_plaintext_bytes);
            }
            state.allocations[index] = TrackedAllocation {
                pointer: new_pointer as usize,
                requested_bytes: new_requested_bytes,
                accounted_bytes: new_requested_bytes,
                class: new_class,
            };
        });
    }

    struct ClassGuard {
        previous: Option<AllocationClass>,
    }

    impl Drop for ClassGuard {
        fn drop(&mut self) {
            with_state(|state| state.class_override = self.previous);
        }
    }

    pub(super) fn with_class<T>(class: AllocationClass, operation: impl FnOnce() -> T) -> T {
        let previous = with_state(|state| {
            let previous = state.class_override;
            state.class_override = Some(class);
            previous
        });
        let guard = ClassGuard { previous };
        let result = operation();
        drop(guard);
        result
    }

    struct ClassPlanGuard;

    impl Drop for ClassPlanGuard {
        fn drop(&mut self) {
            with_state(|state| {
                if state.class_plan_index != state.class_plan_len {
                    state.metrics.classification_mismatches =
                        state.metrics.classification_mismatches.saturating_add(1);
                }
                state.class_plan = [ClassRule::EMPTY; MAX_CLASS_PLAN];
                state.class_plan_len = 0;
                state.class_plan_index = 0;
                state.class_plan_active = false;
                state.class_plan_allows_extra = false;
            });
        }
    }

    pub(super) fn with_class_plan<T>(
        rules: &[ClassRule],
        allows_extra: bool,
        operation: impl FnOnce() -> T,
    ) -> T {
        assert!(rules.len() <= MAX_CLASS_PLAN);
        with_state(|state| {
            assert!(!state.class_plan_active, "allocation class plan is nested");
            state.class_plan[..rules.len()].copy_from_slice(rules);
            state.class_plan_len = rules.len();
            state.class_plan_index = 0;
            state.class_plan_active = true;
            state.class_plan_allows_extra = allows_extra;
        });
        let guard = ClassPlanGuard;
        let result = operation();
        drop(guard);
        result
    }

    pub(super) fn record_operation_permit(bytes: usize) {
        with_state(|state| {
            if state.active {
                state.metrics.operation_permit_bytes = bytes;
            }
        });
    }

    pub(super) struct Scope {
        finished: bool,
    }

    impl Scope {
        pub(super) fn start() -> Self {
            with_state(|state| {
                assert!(!state.active, "allocation probe scope is already active");
                *state = ProbeState::EMPTY;
                state.active = true;
            });
            Self { finished: false }
        }

        pub(super) fn snapshot(&self) -> AllocationMetrics {
            with_state(|state| state.metrics)
        }

        pub(super) fn checkpoint(&self) -> AllocationMetrics {
            with_state(|state| {
                let previous = state.metrics;
                state.metrics.peak_live_bytes = state.metrics.current_live_bytes;
                state.metrics.peak_plaintext_bytes = state.metrics.current_plaintext_bytes;
                state.metrics.operation_permit_bytes = 0;
                previous
            })
        }

        pub(super) fn finish(mut self) -> AllocationMetrics {
            let metrics = with_state(|state| {
                assert!(
                    state.class_override.is_none(),
                    "allocation class scope leak"
                );
                assert!(!state.class_plan_active, "allocation class plan leak");
                let metrics = state.metrics;
                *state = ProbeState::EMPTY;
                metrics
            });
            self.finished = true;
            metrics
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            if !self.finished {
                with_state(|state| *state = ProbeState::EMPTY);
            }
        }
    }
}

#[cfg(test)]
fn track_plaintext_allocations<T>(operation: impl FnOnce() -> T) -> T {
    allocation_probe::with_class(
        allocation_probe::AllocationClass::PlaintextSensitive,
        operation,
    )
}

#[cfg(not(test))]
#[inline(always)]
fn track_plaintext_allocations<T>(operation: impl FnOnce() -> T) -> T {
    operation()
}

#[cfg(test)]
fn track_decrypted_record_allocations<T>(
    username_bytes: usize,
    aead_staging_bytes: usize,
    operation: impl FnOnce() -> T,
) -> T {
    use allocation_probe::{AllocationClass, ClassRule};

    let rules = [
        ClassRule::exact(username_bytes, AllocationClass::Infrastructure),
        ClassRule::exact(aead_staging_bytes, AllocationClass::PlaintextSensitive),
    ];
    allocation_probe::with_class(AllocationClass::PlaintextSensitive, || {
        allocation_probe::with_class_plan(&rules, true, operation)
    })
}

#[cfg(not(test))]
#[inline(always)]
fn track_decrypted_record_allocations<T>(
    _username_bytes: usize,
    _aead_staging_bytes: usize,
    operation: impl FnOnce() -> T,
) -> T {
    operation()
}

#[cfg(test)]
fn track_encrypted_record_allocations<T>(
    record: &EnrollmentRecord,
    operation: impl FnOnce() -> T,
) -> T {
    use allocation_probe::{AllocationClass, ClassRule};

    let estimate = PlaintextAllocationEstimate::for_record(record)
        .expect("validated Mode 1 record has a measurable allocation shape");
    let payload_bytes = estimate.encoded_payload_bytes();
    let header_bytes = HOWYENC1_FIXED_INSPECTION_BYTES + record.username().as_str().len();
    let output_bytes = header_bytes + payload_bytes + GCM_TAG_BYTES;
    let rules = [
        ClassRule::exact(payload_bytes, AllocationClass::PlaintextSensitive),
        ClassRule::exact(header_bytes, AllocationClass::Infrastructure),
        ClassRule::exact(
            estimate.aead_staging_bytes(),
            AllocationClass::PlaintextSensitive,
        ),
        ClassRule::exact(GCM_TAG_BYTES, AllocationClass::Infrastructure),
        ClassRule::exact(output_bytes, AllocationClass::Infrastructure),
    ];
    allocation_probe::with_class(AllocationClass::Infrastructure, || {
        allocation_probe::with_class_plan(&rules, false, operation)
    })
}

#[cfg(not(test))]
#[inline(always)]
fn track_encrypted_record_allocations<T>(
    _record: &EnrollmentRecord,
    operation: impl FnOnce() -> T,
) -> T {
    operation()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode1StorageLimits {
    max_entries: usize,
    max_plaintext_bytes: usize,
}

impl Mode1StorageLimits {
    pub fn new(max_entries: u32, max_plaintext_bytes: u64) -> Result<Self, StorageBackendError> {
        let max_entries = usize::try_from(max_entries)
            .map_err(|_| StorageBackendError::InvalidInput("entry count limit"))?;
        let max_plaintext_bytes = usize::try_from(max_plaintext_bytes)
            .map_err(|_| StorageBackendError::InvalidInput("record byte limit"))?;
        if max_entries == 0 || max_entries > MAX_ENTRIES {
            return Err(StorageBackendError::InvalidInput("entry count limit"));
        }
        if max_plaintext_bytes == 0 || max_plaintext_bytes > MAX_PLAINTEXT_BYTES {
            return Err(StorageBackendError::InvalidInput("record byte limit"));
        }
        Ok(Self {
            max_entries,
            max_plaintext_bytes,
        })
    }

    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    pub const fn max_plaintext_bytes(self) -> usize {
        self.max_plaintext_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileOwnerPolicy {
    Root,
    EffectiveUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mode1BackendOptions {
    root: PathBuf,
    directory_behavior: DirectoryBehavior,
    owner_policy: FileOwnerPolicy,
}

impl Mode1BackendOptions {
    pub fn production() -> Self {
        Self {
            root: PathBuf::from(MODE1_MODELS_DIR),
            directory_behavior: DirectoryBehavior::CreateOrFix,
            owner_policy: FileOwnerPolicy::Root,
        }
    }

    /// Explicit test/tooling override. Production callers must use
    /// [`Self::production`] so Mode 1 cannot read another mode's namespace.
    pub fn path_override(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            directory_behavior: DirectoryBehavior::CreateOrFix,
            owner_policy: FileOwnerPolicy::EffectiveUser,
        }
    }

    pub fn with_directory_behavior(mut self, behavior: DirectoryBehavior) -> Self {
        self.directory_behavior = behavior;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendHookPoint {
    Filesystem,
    Key,
    Crypto,
    Nonce,
    AfterFileSync,
    CommitRename,
    TransactionStageSync,
    AfterRename,
    PrimaryDirectorySync,
    AfterDirectorySync,
    CleanupUnlink,
    FinalDirectorySync,
    RollbackRename,
    RollbackMarkerSync,
    RollbackDirectorySync,
    RollbackCleanupUnlink,
    RollbackCleanupSync,
    StaleTempCleanupUnlink,
    StaleTempCleanupSync,
}

trait BackendHooks: Send + Sync {
    fn check(&self, _point: BackendHookPoint) -> Result<(), StorageBackendError> {
        Ok(())
    }
}

struct NoBackendHooks;
impl BackendHooks for NoBackendHooks {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendPoisonReason {
    WriteRollback,
    WriteCleanup,
    ClearRollback,
    ClearCommit,
}

#[derive(Default)]
struct BackendAvailability {
    poisoned: AtomicBool,
    reason: Mutex<Option<BackendPoisonReason>>,
}

impl BackendAvailability {
    fn poison(&self, reason: BackendPoisonReason) {
        self.poisoned.store(true, Ordering::Release);
        let mut retained = self
            .reason
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if retained.is_none() {
            *retained = Some(reason);
        }
    }

    fn ensure_available(&self) -> Result<(), StorageBackendError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(StorageBackendError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn health(&self) -> BackendHealth {
        if self.poisoned.load(Ordering::Acquire) {
            BackendHealth::Unavailable(BackendUnavailable::Integrity)
        } else {
            BackendHealth::Ready
        }
    }
}

struct Mode1PromotionAuthority {
    backend_identity: PromptOpaqueIdentity,
    cache: Weak<ModelCache>,
}

struct Mode1CachePromotion {
    authority: Weak<Mode1PromotionAuthority>,
    expected_backend_identity: PromptOpaqueIdentity,
    username: CanonicalUsername,
    expected_revision: u128,
    expected_generation: u64,
    model: CachedAuthModel,
}

impl AuthenticationCachePromotion for Mode1CachePromotion {
    fn promote_if(
        self: Box<Self>,
        publish: &mut dyn FnMut() -> bool,
    ) -> Result<bool, StorageBackendError> {
        let Some(authority) = self.authority.upgrade() else {
            return Ok(false);
        };
        if authority.backend_identity != self.expected_backend_identity {
            return Ok(false);
        }
        let Some(cache) = authority.cache.upgrade() else {
            return Ok(false);
        };
        cache.insert_provisional_if_revision(
            self.username,
            self.expected_revision,
            self.expected_generation,
            self.model,
            publish,
        )
    }
}

struct InspectedRecord {
    file: File,
    header: EncryptedHeader,
    exact_length: usize,
    header_prefix: Vec<u8>,
}

struct LoadedRecord {
    record: EnrollmentRecord,
    permit: BudgetPermit,
}

pub struct Mode1StorageBackend {
    root: PathBuf,
    directory: File,
    expected_owner: u32,
    recognizer_model: ModelDigest,
    key_epoch: u64,
    limits: Mode1StorageLimits,
    cache: Arc<ModelCache>,
    promotion_authority: Arc<Mode1PromotionAuthority>,
    serializers: UserSerializers,
    admissions: Arc<UserAdmissionRegistry>,
    reload_gate: RwLock<()>,
    availability: Arc<BackendAvailability>,
    key: Mode1KeyContext,
    nonce_generator: Mutex<NonceGenerator<Box<dyn RandomSource + Send>>>,
    temporary_random: Mutex<Box<dyn RandomSource + Send>>,
    hooks: Arc<dyn BackendHooks>,
}

impl std::fmt::Debug for Mode1StorageBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mode1StorageBackend")
            .field("root", &self.root)
            .field("expected_owner", &self.expected_owner)
            .field("recognizer_model", &self.recognizer_model)
            .field("key_epoch", &self.key_epoch)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Mode1StorageBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn production(
        key: Mode1KeyContext,
        recognizer_model: ModelDigest,
        key_epoch: u64,
        limits: Mode1StorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
    ) -> Result<Self, StorageBackendError> {
        Self::new(
            Mode1BackendOptions::production(),
            key,
            recognizer_model,
            key_epoch,
            limits,
            cache_limits,
            budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        options: Mode1BackendOptions,
        key: Mode1KeyContext,
        recognizer_model: ModelDigest,
        key_epoch: u64,
        limits: Mode1StorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
    ) -> Result<Self, StorageBackendError> {
        Self::new_with_sources(
            options,
            key,
            recognizer_model,
            key_epoch,
            limits,
            cache_limits,
            budget,
            Box::new(OsRandomSource),
            Box::new(OsRandomSource),
            Arc::new(NoBackendHooks),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_sources(
        options: Mode1BackendOptions,
        key: Mode1KeyContext,
        recognizer_model: ModelDigest,
        key_epoch: u64,
        limits: Mode1StorageLimits,
        cache_limits: ModelCacheLimits,
        budget: PlaintextBudget,
        nonce_random: Box<dyn RandomSource + Send>,
        temporary_random: Box<dyn RandomSource + Send>,
        hooks: Arc<dyn BackendHooks>,
        nonce_ceiling: Option<u64>,
    ) -> Result<Self, StorageBackendError> {
        if key_epoch == 0 {
            return Err(StorageBackendError::InvalidInput("key epoch"));
        }
        if matches!(options.owner_policy, FileOwnerPolicy::Root)
            && options.root != Path::new(MODE1_MODELS_DIR)
        {
            return Err(StorageBackendError::InvalidInput("production storage root"));
        }
        let expected_owner = match options.owner_policy {
            FileOwnerPolicy::Root => 0,
            FileOwnerPolicy::EffectiveUser => {
                // SAFETY: geteuid has no arguments and no failure condition.
                unsafe { libc::geteuid() }
            }
        };

        if matches!(options.owner_policy, FileOwnerPolicy::Root) {
            let parent = open_directory_no_follow(
                Path::new(MODELS_DIR),
                options.directory_behavior,
                expected_owner,
            )?;
            validate_directory(&parent, expected_owner)?;
        }
        let directory =
            open_directory_no_follow(&options.root, options.directory_behavior, expected_owner)?;
        validate_directory(&directory, expected_owner)?;

        let cache = Arc::new(ModelCache::new(cache_limits, budget));
        let backend_identity = key.backend_identity();
        let promotion_authority = Arc::new(Mode1PromotionAuthority {
            backend_identity,
            cache: Arc::downgrade(&cache),
        });
        let nonce_generator = match nonce_ceiling {
            Some(ceiling) => NonceGenerator::from_source_with_ceiling(nonce_random, ceiling)
                .map_err(map_write_storage_error)?,
            None => NonceGenerator::from_source(nonce_random),
        };
        let backend = Self {
            root: options.root,
            directory,
            expected_owner,
            recognizer_model,
            key_epoch,
            limits,
            cache,
            promotion_authority,
            serializers: UserSerializers::default(),
            admissions: Arc::new(UserAdmissionRegistry::default()),
            reload_gate: RwLock::new(()),
            availability: Arc::new(BackendAvailability::default()),
            key,
            nonce_generator: Mutex::new(nonce_generator),
            temporary_random: Mutex::new(temporary_random),
            hooks,
        };

        // Readiness is metadata/header-only. It does not reserve plaintext,
        // decrypt a record, or populate the model cache.
        for status in backend.scan_outer_headers()? {
            match status.classification() {
                OuterRecordClassification::Candidate { .. } => {}
                OuterRecordClassification::ModeMismatch => {
                    return Err(StorageBackendError::ModeMismatch);
                }
                OuterRecordClassification::KeyMismatch => {
                    return Err(StorageBackendError::KeyMismatch);
                }
                OuterRecordClassification::ModelMismatch => {
                    return Err(StorageBackendError::ModelMismatch);
                }
                OuterRecordClassification::Corrupt => {
                    return Err(StorageBackendError::Corrupt);
                }
            }
        }
        Ok(backend)
    }

    fn hook(&self, point: BackendHookPoint) -> Result<(), StorageBackendError> {
        self.hooks.check(point)
    }

    fn ensure_available(&self) -> Result<(), StorageBackendError> {
        self.availability.ensure_available()
    }

    fn poison(&self, reason: BackendPoisonReason) -> StorageBackendError {
        // Publish unavailability before invalidating cache ownership. Cache
        // publication also has its own disabled bit, so a racing provisional
        // promotion cannot repopulate after this clear.
        self.availability.poison(reason);
        self.cache.poison();
        StorageBackendError::Unavailable
    }

    fn sync_directory(&self, point: BackendHookPoint) -> Result<(), StorageBackendError> {
        self.hook(point)?;
        self.directory
            .sync_all()
            .map_err(|error| io_error(IoOperation::Sync, error))
    }

    fn filename(username: &CanonicalUsername) -> CString {
        CString::new(format!("{}.hye", username.as_str()))
            .expect("canonical username and static extension contain no NUL")
    }

    fn open_record(&self, name: &CStr) -> io::Result<File> {
        self.hook(BackendHookPoint::Filesystem)
            .map_err(|_| io::Error::other("injected storage failure"))?;
        // SAFETY: directory and relative C string remain live for the call.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: openat returned one newly owned descriptor.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    }

    fn validate_record_file(&self, file: &File) -> Result<usize, StorageBackendError> {
        self.hook(BackendHookPoint::Filesystem)?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error(IoOperation::Inspect, error))?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_owner
            || metadata.mode() & 0o7777 != STORAGE_RECORD_MODE
            || metadata.nlink() != 1
        {
            return Err(io_error(
                IoOperation::Inspect,
                io::Error::from(io::ErrorKind::PermissionDenied),
            ));
        }
        let maximum = HOWYENC1_FIXED_INSPECTION_BYTES
            .checked_add(64)
            .and_then(|bytes| bytes.checked_add(self.limits.max_plaintext_bytes))
            .and_then(|bytes| bytes.checked_add(16))
            .ok_or(StorageBackendError::InvalidInput("record byte limit"))?;
        let length = usize::try_from(metadata.len()).map_err(|_| StorageBackendError::Corrupt)?;
        if length < HOWYENC1_FIXED_INSPECTION_BYTES + 1 + 16 || length > maximum {
            return Err(StorageBackendError::Corrupt);
        }
        Ok(length)
    }

    fn read_exact_cancellable(
        &self,
        file: &mut File,
        mut destination: &mut [u8],
        cancellation: &dyn CancellationSignal,
    ) -> Result<(), StorageBackendError> {
        while !destination.is_empty() {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            self.hook(BackendHookPoint::Filesystem)?;
            let amount = destination.len().min(8192);
            match file.read(&mut destination[..amount]) {
                Ok(0) => return Err(StorageBackendError::Corrupt),
                Ok(read) => destination = &mut destination[read..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error(IoOperation::Read, error)),
            }
        }
        Ok(())
    }

    fn inspect_record_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Option<InspectedRecord>, StorageBackendError> {
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let name = Self::filename(username);
        self.inspect_named_record_cancellable(&name, username, cancellation)
    }

    fn inspect_named_record_cancellable(
        &self,
        name: &CStr,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Option<InspectedRecord>, StorageBackendError> {
        let mut file = match self.open_record(name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(IoOperation::Open, error)),
        };
        let exact_length = self.validate_record_file(&file)?;
        let mut fixed = [0u8; HOWYENC1_FIXED_INSPECTION_BYTES];
        self.read_exact_cancellable(&mut file, &mut fixed, cancellation)?;
        let username_length = usize::from(u16::from_le_bytes([fixed[42], fixed[43]]));
        if !(1..=64).contains(&username_length) {
            return Err(StorageBackendError::Corrupt);
        }
        let header_length = HOWYENC1_FIXED_INSPECTION_BYTES
            .checked_add(username_length)
            .ok_or(StorageBackendError::Corrupt)?;
        let mut header_prefix = Vec::new();
        header_prefix
            .try_reserve_exact(header_length)
            .map_err(|_| StorageBackendError::Unavailable)?;
        header_prefix.extend_from_slice(&fixed);
        header_prefix.resize(header_length, 0);
        self.read_exact_cancellable(
            &mut file,
            &mut header_prefix[HOWYENC1_FIXED_INSPECTION_BYTES..],
            cancellation,
        )?;
        let header = inspect_howyenc1_metadata(
            &header_prefix,
            exact_length,
            StorageMode::AeadCached,
            self.key_epoch,
            username,
            self.recognizer_model,
            self.limits.max_entries,
            self.limits.max_plaintext_bytes,
        )
        .map_err(map_storage_error)?;
        Ok(Some(InspectedRecord {
            file,
            header,
            exact_length,
            header_prefix,
        }))
    }

    fn inspect_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<Option<InspectedRecord>, StorageBackendError> {
        self.inspect_record_cancellable(username, &NeverCancelled)
    }

    fn read_complete_record(
        &self,
        mut inspected: InspectedRecord,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Zeroizing<Vec<u8>>, StorageBackendError> {
        let mut bytes = Zeroizing::new(inspected.header_prefix);
        let remaining = inspected.exact_length.saturating_sub(bytes.len());
        bytes
            .try_reserve_exact(remaining)
            .map_err(|_| StorageBackendError::Unavailable)?;
        bytes.resize(inspected.exact_length, 0);
        let offset = inspected.header.header_length();
        self.read_exact_cancellable(&mut inspected.file, &mut bytes[offset..], cancellation)?;
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let mut extra = [0u8; 1];
        self.hook(BackendHookPoint::Filesystem)?;
        if inspected
            .file
            .read(&mut extra)
            .map_err(|error| io_error(IoOperation::Read, error))?
            != 0
        {
            return Err(StorageBackendError::Corrupt);
        }
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let complete_header = inspect_howyenc1(&bytes).map_err(map_storage_error)?;
        if complete_header != inspected.header {
            return Err(StorageBackendError::Corrupt);
        }
        Ok(bytes)
    }

    fn decrypt_inspected(
        &self,
        inspected: InspectedRecord,
        username: &CanonicalUsername,
        permit: BudgetPermit,
        cancellation: &dyn CancellationSignal,
    ) -> Result<LoadedRecord, StorageBackendError> {
        let estimate = PlaintextAllocationEstimate::for_encrypted_header(&inspected.header)?;
        if !self.cache.owns_permit(&permit) || permit.bytes() < estimate.cold_load_peak_bytes() {
            return Err(StorageBackendError::InvalidInput(
                "decrypt operation reservation",
            ));
        }
        let bytes = self.read_complete_record(inspected, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        self.hook(BackendHookPoint::Key)?;
        self.hook(BackendHookPoint::Crypto)?;
        let record = track_decrypted_record_allocations(
            username.as_str().len(),
            estimate.aead_staging_bytes(),
            || {
                self.key
                    .decrypt_record(&bytes, self.key_epoch, username, self.recognizer_model)
            },
        )
        .map_err(map_storage_error)?;
        debug_assert_eq!(
            record.plaintext_allocation_bytes(),
            estimate.decoded_record_bytes()
        );
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        Ok(LoadedRecord { record, permit })
    }

    fn load_record_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<LoadedRecord, StorageBackendError> {
        let inspected = self
            .inspect_record_cancellable(username, cancellation)?
            .ok_or(StorageBackendError::Absent)?;
        let estimate = PlaintextAllocationEstimate::for_encrypted_header(&inspected.header)?;
        let permit = self
            .cache
            .reserve_operation(estimate.cold_load_peak_bytes())?;
        #[cfg(test)]
        allocation_probe::record_operation_permit(permit.bytes());
        self.decrypt_inspected(inspected, username, permit, cancellation)
    }

    fn load_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<LoadedRecord, StorageBackendError> {
        self.load_record_cancellable(username, &NeverCancelled)
    }

    fn load_optional_for_mutation(
        &self,
        username: &CanonicalUsername,
        inspected: Option<InspectedRecord>,
        permit: BudgetPermit,
    ) -> Result<(Option<EnrollmentRecord>, BudgetPermit), StorageBackendError> {
        let Some(inspected) = inspected else {
            return Ok((None, permit));
        };
        let loaded = self.decrypt_inspected(inspected, username, permit, &NeverCancelled)?;
        Ok((Some(loaded.record), loaded.permit))
    }

    fn cache_committed_model(
        &self,
        username: &CanonicalUsername,
        model: Option<AuthModel>,
        operation: BudgetPermit,
    ) {
        // The durable record is authoritative at this point. Never retain a
        // stale cache entry if the replacement cannot fit cache policy.
        self.cache.invalidate(username);
        let Some(model) = model else {
            return;
        };
        let bytes = model.plaintext_bytes();
        if let Ok(permit) = operation.shrink_to(bytes) {
            let _ = self.cache.insert(username.clone(), model, permit);
        }
    }

    fn append_estimate(
        &self,
        inspected: Option<&InspectedRecord>,
        entries: &[howy_common::storage::EnrollmentEntry],
    ) -> Result<PlaintextAllocationEstimate, StorageBackendError> {
        let label_bytes = entries
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(entry.label().len())
            })
            .ok_or(StorageBackendError::InvalidInput("append label bytes"))?;
        let estimate = PlaintextAllocationEstimate::for_append_shape(
            inspected.map(|record| &record.header),
            entries.len(),
            label_bytes,
        )?;
        let current_entries = inspected
            .map(|record| record.header.entry_count() as usize)
            .unwrap_or(0);
        if current_entries.saturating_add(entries.len()) > self.limits.max_entries
            || estimate.encoded_payload_bytes() > self.limits.max_plaintext_bytes
        {
            return Err(StorageBackendError::InvalidInput("record shape"));
        }
        Ok(estimate)
    }

    fn admitted_append_estimate(
        &self,
        inspected: Option<&InspectedRecord>,
        shape: AppendAdmissionShape,
    ) -> Result<PlaintextAllocationEstimate, StorageBackendError> {
        let estimate = PlaintextAllocationEstimate::for_append_shape(
            inspected.map(|record| &record.header),
            shape.max_new_entries(),
            shape.max_new_label_bytes(),
        )?;
        let current_entries = inspected
            .map(|record| record.header.entry_count() as usize)
            .unwrap_or(0);
        if current_entries.saturating_add(shape.max_new_entries()) > self.limits.max_entries
            || estimate.encoded_payload_bytes() > self.limits.max_plaintext_bytes
        {
            return Err(StorageBackendError::InvalidInput("record shape"));
        }
        Ok(estimate)
    }

    fn inspected_generation(inspected: Option<&InspectedRecord>) -> u64 {
        inspected.map_or(ABSENT_GENERATION, |record| {
            record.header.record_generation()
        })
    }

    fn write_record(&self, record: &EnrollmentRecord) -> Result<(), StorageBackendError> {
        self.hook(BackendHookPoint::Key)?;
        self.hook(BackendHookPoint::Crypto)?;
        self.hook(BackendHookPoint::Nonce)?;
        let encoded = track_encrypted_record_allocations(record, || {
            let mut nonces = self
                .nonce_generator
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.key
                .encrypt_record(record, self.key_epoch, &mut *nonces)
        })
        .map_err(map_write_storage_error)?;
        let encoded = Zeroizing::new(encoded);
        if encoded.len() > HOWYENC1_MAX_RECORD_BYTES {
            return Err(StorageBackendError::InvalidInput("record byte length"));
        }

        let destination = Self::filename(record.username());
        let destination_exists = match self.open_record(&destination) {
            Ok(file) => {
                self.validate_record_file(&file)?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(io_error(IoOperation::Open, error)),
        };

        let mut last_collision = None;
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let suffix = self.random_temp_suffix()?;
            let temporary =
                CString::new(format!(".{}.tmp.{suffix}", destination.to_string_lossy()))
                    .expect("generated temporary name contains no NUL");
            match self.create_temp(&temporary) {
                Ok(mut file) => {
                    let prepared = (|| {
                        use std::io::Write;
                        file.write_all(&encoded)
                            .map_err(|error| io_error(IoOperation::Write, error))?;
                        file.sync_all()
                            .map_err(|error| io_error(IoOperation::Sync, error))?;
                        self.hook(BackendHookPoint::AfterFileSync)?;
                        Ok(())
                    })();
                    drop(file);
                    if let Err(error) = prepared {
                        self.cleanup_non_authoritative_temp(&temporary);
                        return Err(error);
                    }
                    return self.commit_temporary(&temporary, &destination, destination_exists);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_collision = Some(error);
                }
                Err(error) => return Err(io_error(IoOperation::Create, error)),
            }
        }
        Err(io_error(
            IoOperation::Create,
            last_collision.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
        ))
    }

    fn commit_temporary(
        &self,
        temporary: &CStr,
        destination: &CStr,
        destination_exists: bool,
    ) -> Result<(), StorageBackendError> {
        let staged;
        let transaction = if destination_exists {
            staged = replace_artifact_marker(temporary, b".tmp.", b".staged.")?;
            if let Err(error) = rename_at(self.directory.as_raw_fd(), temporary, &staged)
                .map_err(|error| io_error(IoOperation::Rename, error))
            {
                self.cleanup_non_authoritative_temp(temporary);
                return Err(error);
            }
            if let Err(error) = self.sync_directory(BackendHookPoint::TransactionStageSync) {
                self.cleanup_non_authoritative_temp(&staged);
                return Err(error);
            }
            staged.as_c_str()
        } else {
            temporary
        };
        let rename_result = self.hook(BackendHookPoint::CommitRename).and_then(|()| {
            if destination_exists {
                rename_exchange(self.directory.as_raw_fd(), transaction, destination)
                    .map_err(|error| io_error(IoOperation::Rename, error))
            } else {
                rename_no_replace(self.directory.as_raw_fd(), transaction, destination)
                    .map_err(|error| io_error(IoOperation::Rename, error))
            }
        });
        if let Err(error) = rename_result {
            // renameat2 failure is atomic: the active destination (or its
            // absence) remains authoritative. Cleanup failure is diagnostic,
            // not backend poison, because the temp never became active.
            self.cleanup_non_authoritative_temp(transaction);
            return Err(error);
        }

        let commit_result = self
            .hook(BackendHookPoint::AfterRename)
            .and_then(|()| self.sync_directory(BackendHookPoint::PrimaryDirectorySync))
            .and_then(|()| self.hook(BackendHookPoint::AfterDirectorySync));
        if let Err(error) = commit_result {
            if self
                .rollback_temporary(transaction, destination, destination_exists)
                .is_err()
            {
                return Err(self.poison(BackendPoisonReason::WriteRollback));
            }
            return Err(error);
        }

        // A replacement is not complete until the exchanged old record is
        // removed and that unlink is durable. Failure leaves a valid new active
        // record but an incompletely committed transaction, so the backend is
        // poisoned rather than serving potentially misleading cache state.
        if destination_exists {
            if self.hook(BackendHookPoint::CleanupUnlink).is_err()
                || unlink_at(self.directory.as_raw_fd(), transaction).is_err()
                || self
                    .sync_directory(BackendHookPoint::FinalDirectorySync)
                    .is_err()
            {
                return Err(self.poison(BackendPoisonReason::WriteCleanup));
            }
        }
        Ok(())
    }

    fn cleanup_non_authoritative_temp(&self, temporary: &CStr) {
        let unlinked = self
            .hook(BackendHookPoint::StaleTempCleanupUnlink)
            .and_then(|()| {
                unlink_at(self.directory.as_raw_fd(), temporary)
                    .map_err(|error| io_error(IoOperation::Remove, error))
            })
            .is_ok();
        let durable = unlinked
            && self
                .sync_directory(BackendHookPoint::StaleTempCleanupSync)
                .is_ok();
        if !durable {
            warn!(
                unlinked,
                "Mode 1 retained or could not durably clean a non-authoritative temporary artifact"
            );
        }
    }

    fn rollback_temporary(
        &self,
        temporary: &CStr,
        destination: &CStr,
        destination_existed: bool,
    ) -> Result<(), ()> {
        let rollback = if destination_existed {
            let rollback =
                replace_artifact_marker(temporary, b".staged.", b".rollback.").map_err(|_| ())?;
            rename_at(self.directory.as_raw_fd(), temporary, &rollback).map_err(|_| ())?;
            self.sync_directory(BackendHookPoint::RollbackMarkerSync)
                .map_err(|_| ())?;
            rollback
        } else {
            replace_artifact_marker(temporary, b".tmp.", b".rollback.").map_err(|_| ())?
        };
        self.hook(BackendHookPoint::RollbackRename)
            .map_err(|_| ())?;
        let renamed = if destination_existed {
            rename_exchange(self.directory.as_raw_fd(), &rollback, destination)
        } else {
            rename_at(self.directory.as_raw_fd(), destination, &rollback)
        };
        renamed.map_err(|_| ())?;
        self.sync_directory(BackendHookPoint::RollbackDirectorySync)
            .map_err(|_| ())?;
        self.hook(BackendHookPoint::RollbackCleanupUnlink)
            .map_err(|_| ())?;
        unlink_at(self.directory.as_raw_fd(), &rollback).map_err(|_| ())?;
        self.sync_directory(BackendHookPoint::RollbackCleanupSync)
            .map_err(|_| ())
    }

    fn random_temp_suffix(&self) -> Result<String, StorageBackendError> {
        let mut bytes = [0u8; 16];
        self.temporary_random
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fill_bytes(&mut bytes)
            .map_err(|_| StorageBackendError::Unavailable)?;
        Ok(hex_lower(&bytes))
    }

    fn create_temp(&self, name: &CStr) -> io::Result<File> {
        self.hook(BackendHookPoint::Filesystem)
            .map_err(|_| io::Error::other("injected storage failure"))?;
        // SAFETY: directory and relative C string remain live for the call.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                STORAGE_RECORD_MODE,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned one newly owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        // SAFETY: file is live and mode has no pointer arguments.
        if unsafe { libc::fchmod(file.as_raw_fd(), STORAGE_RECORD_MODE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.expected_owner
            || metadata.mode() & 0o7777 != STORAGE_RECORD_MODE
            || metadata.nlink() != 1
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(file)
    }

    fn append_locked(
        &self,
        request: AppendRequest<'_>,
        inspected: Option<InspectedRecord>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError> {
        let estimate = self.append_estimate(inspected.as_ref(), request.entries())?;
        if !self.cache.owns_permit(&operation) || operation.bytes() < estimate.mutation_peak_bytes()
        {
            return Err(StorageBackendError::InvalidInput(
                "append operation reservation",
            ));
        }
        #[cfg(test)]
        allocation_probe::record_operation_permit(operation.bytes());
        let (loaded, operation) =
            self.load_optional_for_mutation(request.username(), inspected, operation)?;
        let current_generation = loaded
            .as_ref()
            .map_or(ABSENT_GENERATION, EnrollmentRecord::generation);
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        let total = loaded
            .as_ref()
            .map_or(0, |record| record.entries().len())
            .checked_add(request.entries().len())
            .ok_or(StorageBackendError::InvalidInput("entry count"))?;
        if total > self.limits.max_entries {
            return Err(StorageBackendError::InvalidInput("entry count"));
        }
        let generation = match loaded.as_ref() {
            Some(record) => {
                checked_next_generation(record.generation()).map_err(map_storage_error)?
            }
            None => 1,
        };
        // Keep the authenticated source alive so its allocation is wiped on
        // drop. Build the final record in one exact requested layout; moving a
        // Vec that later reallocates could otherwise abandon stale embedding
        // bytes in the allocator's old block.
        let final_username = request.username().clone();
        let record = track_plaintext_allocations(|| {
            let mut entries = Vec::with_capacity(total);
            if let Some(source) = loaded.as_ref() {
                entries.extend(source.entries().iter().cloned());
            }
            entries.extend(request.entries().iter().cloned());
            debug_assert_eq!(entries.len(), total);
            debug_assert_eq!(entries.capacity(), total);
            EnrollmentRecord::from_boxed_entries(
                generation,
                self.recognizer_model,
                final_username,
                entries.into_boxed_slice(),
            )
        })
        .map_err(map_mutation_record_error)?;
        let model = track_plaintext_allocations(|| AuthModel::from_record(&record))?;
        let observed_peak = loaded
            .as_ref()
            .map_or(0, EnrollmentRecord::plaintext_allocation_bytes)
            .saturating_add(record.plaintext_allocation_bytes())
            .saturating_add(model.plaintext_bytes())
            .saturating_add(estimate.encoded_payload_bytes())
            .saturating_add(estimate.aead_staging_bytes());
        debug_assert_eq!(observed_peak, estimate.mutation_peak_bytes());
        debug_assert!(observed_peak <= operation.bytes());
        self.write_record(&record)?;
        self.ensure_available()?;
        let result = AppendResult::new(generation, request.entries().len(), total);
        drop(record);
        self.cache_committed_model(request.username(), Some(model), operation);
        Ok(result)
    }

    fn authenticate_cold(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
        provisional: bool,
    ) -> Result<AuthenticationLoad, StorageBackendError> {
        let provisional_revision = provisional.then(|| self.cache.revision());
        let loaded = self.load_record_cancellable(username, cancellation)?;
        if loaded.record.entries().is_empty() {
            return Err(StorageBackendError::Absent);
        }
        let model = track_plaintext_allocations(|| AuthModel::from_record(&loaded.record))?;
        let observed_peak = loaded
            .record
            .plaintext_allocation_bytes()
            .saturating_add(model.plaintext_bytes());
        debug_assert!(observed_peak <= loaded.permit.bytes());
        let expected_generation = model.generation();
        let model_bytes = model.plaintext_bytes();
        drop(loaded.record);
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        let permit = loaded.permit.shrink_to(model_bytes)?;
        if !provisional {
            let lease = self.cache.insert(username.clone(), model, permit)?;
            if cancellation.is_cancelled() {
                self.cache.invalidate(username);
                drop(lease);
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(AuthenticationLoad::committed(lease));
        }

        let expected_revision = provisional_revision.expect("provisional revision was captured");
        let cached = CachedAuthModel::new(model, permit)?;
        let lease = cached.lease();
        let promotion = Box::new(Mode1CachePromotion {
            authority: Arc::downgrade(&self.promotion_authority),
            expected_backend_identity: self.key.backend_identity(),
            username: username.clone(),
            expected_revision,
            expected_generation,
            model: cached,
        });
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        Ok(AuthenticationLoad::provisional(lease, promotion))
    }

    fn scan_outer_headers(&self) -> Result<Vec<OuterRecordStatus>, StorageBackendError> {
        self.hook(BackendHookPoint::Filesystem)?;
        validate_directory(&self.directory, self.expected_owner)?;
        let mut records = Vec::new();
        let mut stale_temps = 0usize;
        let mut cleaned_temps = 0usize;
        let mut retained_temps = 0usize;
        for_each_directory_name(&self.directory, MAX_MODE1_NAMESPACE_ENTRIES, |name_bytes| {
            let metadata = namespace_entry_metadata(&self.directory, name_bytes)?;
            let file_type = if metadata.file_type().is_file() {
                NamespaceFileType::Regular
            } else if metadata.file_type().is_dir() {
                NamespaceFileType::Directory
            } else if metadata.file_type().is_symlink() {
                NamespaceFileType::Symlink
            } else {
                NamespaceFileType::Other
            };
            let entry_classification =
                classify_mode1_namespace_entry(name_bytes, file_type, metadata.nlink());
            let username = match &entry_classification {
                NamespaceEntryClassification::Authoritative { username } => {
                    CanonicalUsername::new(username).map_err(map_storage_error)?
                }
                NamespaceEntryClassification::Temporary => {
                    stale_temps = stale_temps.saturating_add(1);
                    if self.cleanup_stale_temp(name_bytes) {
                        cleaned_temps = cleaned_temps.saturating_add(1);
                    } else {
                        retained_temps = retained_temps.saturating_add(1);
                    }
                    return Ok(());
                }
                NamespaceEntryClassification::Staged => {
                    let Some(username) =
                        classified_mode1_transaction_username(name_bytes, &entry_classification)
                            .and_then(|value| CanonicalUsername::new(&value).ok())
                    else {
                        return Err(StorageBackendError::Corrupt);
                    };
                    if self.staged_write_is_pre_exchange(name_bytes, &username) {
                        stale_temps = stale_temps.saturating_add(1);
                        if self.cleanup_stale_temp(name_bytes) {
                            cleaned_temps = cleaned_temps.saturating_add(1);
                        } else {
                            retained_temps = retained_temps.saturating_add(1);
                        }
                        return Ok(());
                    }
                    self.availability.poison(BackendPoisonReason::WriteRollback);
                    self.cache.poison();
                    return Err(StorageBackendError::Corrupt);
                }
                NamespaceEntryClassification::Clear => {
                    self.availability.poison(BackendPoisonReason::ClearRollback);
                    self.cache.poison();
                    return Err(StorageBackendError::Corrupt);
                }
                NamespaceEntryClassification::Rollback => {
                    self.availability.poison(BackendPoisonReason::WriteRollback);
                    self.cache.poison();
                    return Err(StorageBackendError::Corrupt);
                }
                NamespaceEntryClassification::Symlink
                | NamespaceEntryClassification::Directory
                | NamespaceEntryClassification::Hardlink
                | NamespaceEntryClassification::NonUtf8
                | NamespaceEntryClassification::Unknown => {
                    return Err(StorageBackendError::Corrupt);
                }
            };
            let classification = match self.inspect_record(&username) {
                Ok(Some(inspected)) => OuterRecordClassification::Candidate {
                    generation: inspected.header.record_generation(),
                },
                Ok(None) => return Ok(()),
                Err(StorageBackendError::ModeMismatch) => OuterRecordClassification::ModeMismatch,
                Err(StorageBackendError::KeyMismatch) => OuterRecordClassification::KeyMismatch,
                Err(StorageBackendError::ModelMismatch) => OuterRecordClassification::ModelMismatch,
                Err(StorageBackendError::Io(error))
                    if error.kind() == io::ErrorKind::PermissionDenied =>
                {
                    return Err(StorageBackendError::Io(error));
                }
                Err(_) => OuterRecordClassification::Corrupt,
            };
            records
                .try_reserve(1)
                .map_err(|_| StorageBackendError::Unavailable)?;
            records.push(OuterRecordStatus::new(username, classification));
            Ok(())
        })?;
        let cleanup_sync_failed = cleaned_temps != 0
            && self
                .sync_directory(BackendHookPoint::StaleTempCleanupSync)
                .is_err();
        if stale_temps != 0 {
            warn!(
                stale_temp_count = stale_temps,
                cleaned_temp_count = cleaned_temps,
                retained_temp_count = retained_temps,
                cleanup_sync_failed,
                "Mode 1 ignored bounded non-authoritative pre-rename artifacts"
            );
        }
        records.sort_by(|left, right| left.username().as_str().cmp(right.username().as_str()));
        Ok(records)
    }

    fn cleanup_stale_temp(&self, name: &[u8]) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        let file = match self.open_record(&name) {
            Ok(file) => file,
            Err(_) => return false,
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        if !metadata.is_file()
            || metadata.uid() != self.expected_owner
            || metadata.mode() & 0o7777 != STORAGE_RECORD_MODE
            || metadata.nlink() != 1
        {
            return false;
        }
        drop(file);
        self.hook(BackendHookPoint::StaleTempCleanupUnlink).is_ok()
            && unlink_at(self.directory.as_raw_fd(), &name).is_ok()
    }

    fn staged_write_is_pre_exchange(&self, name: &[u8], username: &CanonicalUsername) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        let Ok(Some(staged)) =
            self.inspect_named_record_cancellable(&name, username, &NeverCancelled)
        else {
            return false;
        };
        let Ok(Some(active)) = self.inspect_record(username) else {
            return false;
        };
        active
            .header
            .record_generation()
            .checked_add(1)
            .is_some_and(|generation| generation == staged.header.record_generation())
    }

    fn clear_record(&self, username: &CanonicalUsername) -> Result<(), StorageBackendError> {
        let destination = Self::filename(username);
        let mut last_collision = None;
        for _ in 0..TEMP_CREATE_ATTEMPTS {
            let suffix = self.random_temp_suffix()?;
            let tombstone =
                CString::new(format!(".{}.clear.{suffix}", destination.to_string_lossy()))
                    .expect("generated tombstone name contains no NUL");
            match rename_no_replace(self.directory.as_raw_fd(), &destination, &tombstone) {
                Ok(()) => {
                    let commit_result = self
                        .hook(BackendHookPoint::AfterRename)
                        .and_then(|()| self.sync_directory(BackendHookPoint::PrimaryDirectorySync))
                        .and_then(|()| self.hook(BackendHookPoint::AfterDirectorySync));
                    if let Err(error) = commit_result {
                        if self.rollback_clear(&tombstone, &destination).is_err() {
                            return Err(self.poison(BackendPoisonReason::ClearRollback));
                        }
                        return Err(error);
                    }

                    let unlink_result = self.hook(BackendHookPoint::CleanupUnlink).and_then(|()| {
                        unlink_at(self.directory.as_raw_fd(), &tombstone)
                            .map_err(|error| io_error(IoOperation::Remove, error))
                    });
                    if let Err(error) = unlink_result {
                        if self.rollback_clear(&tombstone, &destination).is_err() {
                            return Err(self.poison(BackendPoisonReason::ClearRollback));
                        }
                        return Err(error);
                    }
                    if self
                        .sync_directory(BackendHookPoint::FinalDirectorySync)
                        .is_err()
                    {
                        return Err(self.poison(BackendPoisonReason::ClearCommit));
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_collision = Some(error)
                }
                Err(error) => return Err(io_error(IoOperation::Remove, error)),
            }
        }
        Err(io_error(
            IoOperation::Remove,
            last_collision.unwrap_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists)),
        ))
    }

    fn rollback_clear(&self, tombstone: &CStr, destination: &CStr) -> Result<(), ()> {
        self.hook(BackendHookPoint::RollbackRename)
            .map_err(|_| ())?;
        rename_at(self.directory.as_raw_fd(), tombstone, destination).map_err(|_| ())?;
        self.sync_directory(BackendHookPoint::RollbackDirectorySync)
            .map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn cached_generation_for_test(&self, username: &CanonicalUsername) -> Option<u64> {
        self.cache.generation(username)
    }

    #[cfg(test)]
    fn poison_reason_for_test(&self) -> Option<BackendPoisonReason> {
        *self
            .availability
            .reason
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl StorageBackend for Mode1StorageBackend {
    fn prompt_snapshot(
        &self,
        username: &CanonicalUsername,
    ) -> Result<PromptStorageSnapshot, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        if let Some(generation) = self.cache.generation(username) {
            self.ensure_available()?;
            return Ok(PromptStorageSnapshot::new(
                BackendHealth::Ready,
                CandidatePresence::Candidate { generation },
                self.key.backend_identity(),
                PromptOpaqueIdentity::new(self.recognizer_model.into_bytes()),
            ));
        }
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let candidate = if let Some(generation) = self.cache.generation(username) {
            CandidatePresence::Candidate { generation }
        } else {
            match self.inspect_record(username)? {
                Some(inspected) if inspected.header.entry_count() != 0 => {
                    CandidatePresence::Candidate {
                        generation: inspected.header.record_generation(),
                    }
                }
                Some(_) | None => CandidatePresence::Absent,
            }
        };
        self.ensure_available()?;
        Ok(PromptStorageSnapshot::new(
            BackendHealth::Ready,
            candidate,
            self.key.backend_identity(),
            PromptOpaqueIdentity::new(self.recognizer_model.into_bytes()),
        ))
    }

    fn candidate_presence(
        &self,
        username: &CanonicalUsername,
    ) -> Result<CandidatePresence, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        if let Some(generation) = self.cache.generation(username) {
            self.ensure_available()?;
            return Ok(CandidatePresence::Candidate { generation });
        }
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        if let Some(generation) = self.cache.generation(username) {
            self.ensure_available()?;
            return Ok(CandidatePresence::Candidate { generation });
        }
        let result = match self.load_record(username) {
            Ok(loaded) if loaded.record.entries().is_empty() => Ok(CandidatePresence::Absent),
            Ok(loaded) => Ok(CandidatePresence::Candidate {
                generation: loaded.record.generation(),
            }),
            Err(StorageBackendError::Absent) => Ok(CandidatePresence::Absent),
            Err(error) => Err(error),
        };
        self.ensure_available()?;
        result
    }

    fn authenticate(
        &self,
        username: &CanonicalUsername,
    ) -> Result<ModelLease, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        if let Some(lease) = self.cache.get(username) {
            self.ensure_available()?;
            return Ok(lease);
        }
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        if let Some(lease) = self.cache.get(username) {
            self.ensure_available()?;
            return Ok(lease);
        }
        let result = self
            .authenticate_cold(username, &NeverCancelled, false)
            .map(AuthenticationLoad::into_lease);
        self.ensure_available()?;
        result
    }

    fn authenticate_cancellable(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<ModelLease, StorageBackendError> {
        let load = self.authenticate_active_internal(username, cancellation, false)?;
        debug_assert!(!load.has_provisional_promotion());
        Ok(load.into_lease())
    }

    fn authenticate_active(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
    ) -> Result<AuthenticationLoad, StorageBackendError> {
        self.authenticate_active_internal(username, cancellation, true)
    }

    fn list_metadata(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let result = self
            .load_record(username)
            .map(|loaded| MetadataList::from_record(&loaded.record));
        self.ensure_available()?;
        result
    }

    fn append(&self, request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let inspected = self.inspect_record(request.username())?;
        let current_generation = Self::inspected_generation(inspected.as_ref());
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        let estimate = self.append_estimate(inspected.as_ref(), request.entries())?;
        let operation = self
            .cache
            .reserve_operation_for_user(estimate.mutation_peak_bytes(), request.username())?;
        self.ensure_available()?;
        self.append_locked(request, inspected, operation)
    }

    fn admit_enrollment(
        &self,
        username: &CanonicalUsername,
        plaintext_bytes: usize,
        append_shape: AppendAdmissionShape,
    ) -> Result<EnrollmentAdmission, StorageBackendError> {
        let admission_guard = self.admissions.try_acquire(username)?;
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(username);
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let inspected = self.inspect_record(username)?;
        let estimate = self.admitted_append_estimate(inspected.as_ref(), append_shape)?;
        let admission = self.cache.reserve_enrollment_for_user(
            estimate.mutation_peak_bytes(),
            plaintext_bytes,
            username,
        )?;
        self.ensure_available()?;
        Ok(admission.with_release_guard(Box::new(admission_guard)))
    }

    fn append_admitted(
        &self,
        request: AppendRequest<'_>,
        operation: BudgetPermit,
    ) -> Result<AppendResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let inspected = self.inspect_record(request.username())?;
        let current_generation = Self::inspected_generation(inspected.as_ref());
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        self.append_locked(request, inspected, operation)
    }

    fn remove(&self, request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let inspected = self.inspect_record(request.username())?;
        let current_generation = Self::inspected_generation(inspected.as_ref());
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        let estimate = inspected
            .as_ref()
            .map(|record| {
                PlaintextAllocationEstimate::for_replacement_of_encrypted_header(&record.header)
            })
            .transpose()?;
        let required = estimate.map_or(1, PlaintextAllocationEstimate::mutation_peak_bytes);
        let operation = self
            .cache
            .reserve_operation_for_user(required, request.username())?;
        #[cfg(test)]
        allocation_probe::record_operation_permit(operation.bytes());
        let (loaded, operation) =
            self.load_optional_for_mutation(request.username(), inspected, operation)?;
        let Some(record) = loaded else {
            return Err(StorageBackendError::Conflict {
                current_generation: ABSENT_GENERATION,
            });
        };
        if record.generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        }
        let Some(index) = record
            .entries()
            .iter()
            .position(|entry| entry.enrollment_id() == request.enrollment_id())
        else {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        };
        let generation = checked_next_generation(record.generation()).map_err(map_storage_error)?;
        let final_count = record.entries().len() - 1;
        let replacement_username = request.username().clone();
        let replacement = track_plaintext_allocations(|| {
            let mut entries = Vec::with_capacity(final_count);
            entries.extend(
                record
                    .entries()
                    .iter()
                    .enumerate()
                    .filter(|(entry_index, _)| *entry_index != index)
                    .map(|(_, entry)| entry.clone()),
            );
            debug_assert_eq!(entries.len(), final_count);
            debug_assert_eq!(entries.capacity(), final_count);
            EnrollmentRecord::from_boxed_entries(
                generation,
                self.recognizer_model,
                replacement_username,
                entries.into_boxed_slice(),
            )
        })
        .map_err(map_mutation_record_error)?;
        let model = if replacement.entries().is_empty() {
            None
        } else {
            Some(track_plaintext_allocations(|| {
                AuthModel::from_record(&replacement)
            })?)
        };
        let observed_peak = record
            .plaintext_allocation_bytes()
            .saturating_add(replacement.plaintext_allocation_bytes())
            .saturating_add(model.as_ref().map_or(0, AuthModel::plaintext_bytes));
        if let Some(estimate) = estimate {
            let encoding_peak = observed_peak
                .saturating_add(estimate.encoded_payload_bytes())
                .saturating_add(estimate.aead_staging_bytes());
            debug_assert!(encoding_peak <= estimate.mutation_peak_bytes());
            debug_assert!(encoding_peak <= operation.bytes());
        }
        self.write_record(&replacement)?;
        self.ensure_available()?;
        let result = RemoveResult::new(generation, request.enrollment_id());
        drop((record, replacement));
        self.cache_committed_model(request.username(), model, operation);
        Ok(result)
    }

    fn clear(&self, request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let serializer = self.serializers.for_user(request.username());
        let _user = serializer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_available()?;
        let inspected = self.inspect_record(request.username())?;
        let current_generation = Self::inspected_generation(inspected.as_ref());
        if current_generation != request.expected_generation() {
            return Err(StorageBackendError::Conflict { current_generation });
        }
        let required = inspected
            .as_ref()
            .map(|record| PlaintextAllocationEstimate::for_encrypted_header(&record.header))
            .transpose()?
            .map_or(1, PlaintextAllocationEstimate::cold_load_peak_bytes);
        let operation = self
            .cache
            .reserve_operation_for_user(required, request.username())?;
        let (loaded, _operation) =
            self.load_optional_for_mutation(request.username(), inspected, operation)?;
        let Some(record) = loaded else {
            return Err(StorageBackendError::Conflict {
                current_generation: ABSENT_GENERATION,
            });
        };
        if record.generation() != request.expected_generation() {
            return Err(StorageBackendError::Conflict {
                current_generation: record.generation(),
            });
        }
        let removed = record.entries().len();
        self.clear_record(request.username())?;
        self.ensure_available()?;
        self.cache.invalidate(request.username());
        Ok(ClearResult::new(removed))
    }

    fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
        let _reload = self
            .reload_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Poison is permanent for one backend instance. Reload cannot safely
        // infer operator intent from an indeterminate clear/rollback artifact.
        // Benign pre-rename temps are non-authoritative and are handled by the
        // bounded scan below.
        self.ensure_available()?;
        self.cache.clear();
        let records = self.scan_outer_headers()?;
        Ok(ReloadResult::new(BackendHealth::Ready, records))
    }

    fn health(&self) -> BackendHealth {
        self.availability.health()
    }

    fn verify_record(
        &self,
        username: &CanonicalUsername,
    ) -> Result<MetadataList, StorageBackendError> {
        self.list_metadata(username)
    }
}

impl Mode1StorageBackend {
    fn authenticate_active_internal(
        &self,
        username: &CanonicalUsername,
        cancellation: &dyn CancellationSignal,
        provisional: bool,
    ) -> Result<AuthenticationLoad, StorageBackendError> {
        let reload = cancellable_read_lock(&self.reload_gate, cancellation)?;
        self.ensure_available()?;
        if let Some(lease) = self.cache.get(username) {
            if cancellation.is_cancelled() || self.ensure_available().is_err() {
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(AuthenticationLoad::committed(lease));
        }
        let serializer = self.serializers.for_user(username);
        let user = cancellable_mutex_lock(&serializer, cancellation)?;
        self.ensure_available()?;
        if let Some(lease) = self.cache.get(username) {
            drop((user, reload));
            if cancellation.is_cancelled() || self.ensure_available().is_err() {
                return Err(StorageBackendError::Unavailable);
            }
            return Ok(AuthenticationLoad::committed(lease));
        }
        let result = self.authenticate_cold(username, cancellation, provisional);
        drop((user, reload));
        self.ensure_available()?;
        result
    }
}

fn cancellable_read_lock<'a, T>(
    lock: &'a RwLock<T>,
    cancellation: &dyn CancellationSignal,
) -> Result<std::sync::RwLockReadGuard<'a, T>, StorageBackendError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        match lock.try_read() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => std::thread::sleep(CANCELLATION_LOCK_POLL),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
        }
    }
}

fn cancellable_mutex_lock<'a, T>(
    lock: &'a Mutex<T>,
    cancellation: &dyn CancellationSignal,
) -> Result<std::sync::MutexGuard<'a, T>, StorageBackendError> {
    loop {
        if cancellation.is_cancelled() {
            return Err(StorageBackendError::Unavailable);
        }
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => std::thread::sleep(CANCELLATION_LOCK_POLL),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
        }
    }
}

struct NeverCancelled;
impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn open_directory_no_follow(
    path: &Path,
    behavior: DirectoryBehavior,
    expected_owner: u32,
) -> Result<File, StorageBackendError> {
    if !path.is_absolute() {
        return Err(StorageBackendError::InvalidInput("storage root"));
    }
    let mut components = path.components().peekable();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(StorageBackendError::InvalidInput("storage root"));
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| io_error(IoOperation::Open, error))?;
    while let Some(component) = components.next() {
        let Component::Normal(component) = component else {
            return Err(StorageBackendError::InvalidInput("storage root"));
        };
        let component = CString::new(component.as_encoded_bytes())
            .map_err(|_| StorageBackendError::InvalidInput("storage root"))?;
        let mut descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::NotFound
            && matches!(behavior, DirectoryBehavior::CreateOrFix)
        {
            // SAFETY: current and component remain live; mode is a value.
            if unsafe {
                libc::mkdirat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    STORAGE_DIRECTORY_MODE,
                )
            } != 0
            {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_error(IoOperation::Create, error));
                }
            }
            // SAFETY: same validated descriptor-relative component.
            descriptor = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if descriptor < 0 {
            return Err(io_error(IoOperation::Open, io::Error::last_os_error()));
        }
        // SAFETY: openat returned one newly owned descriptor.
        current = unsafe { File::from_raw_fd(descriptor) };
        if components.peek().is_none() {
            if matches!(behavior, DirectoryBehavior::CreateOrFix) {
                // SAFETY: current is live and mode is a value.
                if unsafe { libc::fchmod(current.as_raw_fd(), STORAGE_DIRECTORY_MODE) } != 0 {
                    return Err(io_error(IoOperation::Create, io::Error::last_os_error()));
                }
            }
            validate_directory(&current, expected_owner)?;
        }
    }
    Ok(current)
}

fn validate_directory(file: &File, expected_owner: u32) -> Result<(), StorageBackendError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error(IoOperation::Inspect, error))?;
    if !metadata.is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o7777 != STORAGE_DIRECTORY_MODE
    {
        return Err(io_error(
            IoOperation::Inspect,
            io::Error::from(io::ErrorKind::PermissionDenied),
        ));
    }
    Ok(())
}

fn for_each_directory_name(
    directory: &File,
    maximum_entries: usize,
    mut visit: impl FnMut(&[u8]) -> Result<(), StorageBackendError>,
) -> Result<(), StorageBackendError> {
    // Open a fresh description for `.` rather than dup'ing the backend's
    // descriptor: dup would share a directory-stream offset across reloads.
    let dot = c".";
    // SAFETY: directory and static relative C string remain live for the call.
    let scan_descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if scan_descriptor < 0 {
        return Err(io_error(IoOperation::Open, io::Error::last_os_error()));
    }
    // SAFETY: scan_descriptor is an owned directory descriptor. fdopendir consumes
    // it on success; close handles the failure path.
    let stream = unsafe { libc::fdopendir(scan_descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not consume scan_descriptor.
        unsafe { libc::close(scan_descriptor) };
        return Err(io_error(IoOperation::Open, error));
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the successful fdopendir stream.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut entry_count = 0usize;
    loop {
        // SAFETY: Linux exposes thread-local errno through this accessor.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: stream remains live and is used serially under this call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(io_error(IoOperation::Read, error));
            }
            break;
        }
        // SAFETY: readdir returns a dirent whose d_name is NUL-terminated for
        // the lifetime of the stream or until the next readdir call. Visit it
        // before advancing the stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        entry_count = entry_count
            .checked_add(1)
            .ok_or(StorageBackendError::InvalidInput(
                "mode 1 namespace entry limit",
            ))?;
        if entry_count > maximum_entries {
            return Err(StorageBackendError::InvalidInput(
                "mode 1 namespace entry limit",
            ));
        }
        visit(name)?;
    }
    Ok(())
}

fn namespace_entry_metadata(
    directory: &File,
    name: &[u8],
) -> Result<Metadata, StorageBackendError> {
    let name = CString::new(name).map_err(|_| StorageBackendError::Corrupt)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io_error(IoOperation::Open, io::Error::last_os_error()));
    }
    let entry = unsafe { File::from_raw_fd(descriptor) };
    entry
        .metadata()
        .map_err(|error| io_error(IoOperation::Inspect, error))
}

fn replace_artifact_marker(
    name: &CStr,
    from: &[u8],
    to: &[u8],
) -> Result<CString, StorageBackendError> {
    let bytes = name.to_bytes();
    let Some(offset) = bytes.windows(from.len()).position(|window| window == from) else {
        return Err(StorageBackendError::InvalidInput(
            "transaction artifact name",
        ));
    };
    let capacity = bytes
        .len()
        .checked_sub(from.len())
        .and_then(|length| length.checked_add(to.len()))
        .ok_or(StorageBackendError::InvalidInput(
            "transaction artifact name",
        ))?;
    let mut replacement = Vec::with_capacity(capacity);
    replacement.extend_from_slice(&bytes[..offset]);
    replacement.extend_from_slice(to);
    replacement.extend_from_slice(&bytes[offset + from.len()..]);
    CString::new(replacement)
        .map_err(|_| StorageBackendError::InvalidInput("transaction artifact name"))
}

fn map_storage_error(error: StorageError) -> StorageBackendError {
    match error {
        StorageError::BindingMismatch("storage mode") => StorageBackendError::ModeMismatch,
        StorageError::BindingMismatch("key epoch") => StorageBackendError::KeyMismatch,
        StorageError::BindingMismatch("recognizer model") => StorageBackendError::ModelMismatch,
        StorageError::AuthenticationFailed => StorageBackendError::AuthenticationFailed,
        StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
        StorageError::AllocationFailed(_) => StorageBackendError::Unavailable,
        _ => StorageBackendError::Corrupt,
    }
}

fn map_write_storage_error(error: StorageError) -> StorageBackendError {
    match error {
        StorageError::DuplicateNonce
        | StorageError::NonceWriteLimitExceeded
        | StorageError::RandomSource(_)
        | StorageError::AllocationFailed(_) => StorageBackendError::Unavailable,
        StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
        _ => StorageBackendError::InvalidInput("record"),
    }
}

fn map_mutation_record_error(error: StorageError) -> StorageBackendError {
    match error {
        StorageError::GenerationOverflow => StorageBackendError::GenerationOverflow,
        StorageError::AllocationFailed(_) => StorageBackendError::Unavailable,
        _ => StorageBackendError::InvalidInput("record"),
    }
}

fn io_error(operation: IoOperation, error: io::Error) -> StorageBackendError {
    StorageIoError::new(operation, &error).into()
}

fn rename_at(directory: i32, old: &CStr, new: &CStr) -> io::Result<()> {
    // SAFETY: both names are relative C strings and directory is live.
    if unsafe { libc::renameat(directory, old.as_ptr(), directory, new.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn rename_exchange(directory: i32, left: &CStr, right: &CStr) -> io::Result<()> {
    // SAFETY: both names are relative C strings and directory is live.
    if unsafe {
        libc::renameat2(
            directory,
            left.as_ptr(),
            directory,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn rename_no_replace(directory: i32, old: &CStr, new: &CStr) -> io::Result<()> {
    // SAFETY: both names are relative C strings and directory is live.
    if unsafe {
        libc::renameat2(
            directory,
            old.as_ptr(),
            directory,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_at(directory: i32, name: &CStr) -> io::Result<()> {
    // SAFETY: name is a relative C string and directory is live.
    if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::collections::VecDeque;
    use std::fs::{self, OpenOptions, Permissions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Barrier, Mutex, mpsc};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use aes_gcm::aead::{AeadInOut, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use howy_common::storage::{
        EMBEDDING_DIMENSION, EnrollmentEntry, EnrollmentId, LeaseKind, PlaintextBudget,
        decode_howyenc1,
    };

    use super::*;

    struct ThreadMeasuringAllocator;

    #[global_allocator]
    static TEST_ALLOCATOR: ThreadMeasuringAllocator = ThreadMeasuringAllocator;

    unsafe impl GlobalAlloc for ThreadMeasuringAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: this wrapper forwards the caller-provided valid layout to
            // the system allocator and returns its result unchanged.
            let pointer = unsafe { System.alloc(layout) };
            allocation_probe::record_alloc(pointer, layout.size(), false);
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            allocation_probe::record_dealloc(pointer, layout.size());
            // SAFETY: pointer/layout are forwarded unchanged to the allocator
            // that produced the allocation.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: valid caller layout is forwarded unchanged.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            allocation_probe::record_alloc(pointer, layout.size(), true);
            pointer
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: caller's allocation and new size are forwarded unchanged.
            let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
            allocation_probe::record_realloc(pointer, layout.size(), new_pointer, new_size);
            new_pointer
        }
    }

    struct AllocationCountScope(allocation_probe::Scope);

    impl AllocationCountScope {
        fn start() -> Self {
            Self(allocation_probe::Scope::start())
        }

        fn count(&self) -> usize {
            let metrics = self.0.snapshot();
            metrics
                .allocation_calls
                .saturating_add(metrics.reallocation_calls)
        }
    }

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    static ALLOCATION_MEASUREMENT_LOCK: Mutex<()> = Mutex::new(());
    static TLS_TEARDOWN_ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct AllocateDuringTlsTeardown;

    impl Drop for AllocateDuringTlsTeardown {
        fn drop(&mut self) {
            let allocation = Box::new([0xA5u8; 64]);
            std::hint::black_box(&*allocation);
            TLS_TEARDOWN_ALLOCATION_CALLS.fetch_add(1, Ordering::SeqCst);
        }
    }

    std::thread_local! {
        static ALLOCATE_DURING_TLS_TEARDOWN: AllocateDuringTlsTeardown = const { AllocateDuringTlsTeardown };
    }

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "howy-mode1-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            assert!(!path.starts_with("/etc"));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn record(&self, username: &str) -> PathBuf {
            self.0.join(format!("{username}.hye"))
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct CountingHooks {
        events: Mutex<Vec<BackendHookPoint>>,
        failures: Mutex<VecDeque<BackendHookPoint>>,
        panic_on_sensitive_call: AtomicBool,
    }

    impl CountingHooks {
        fn clear(&self) {
            self.events.lock().unwrap().clear();
        }

        fn count(&self, point: BackendHookPoint) -> usize {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == point)
                .count()
        }

        fn fail_next(&self, point: BackendHookPoint) {
            self.failures.lock().unwrap().push_back(point);
        }

        fn fail_sequence(&self, points: impl IntoIterator<Item = BackendHookPoint>) {
            self.failures.lock().unwrap().extend(points);
        }
    }

    impl BackendHooks for CountingHooks {
        fn check(&self, point: BackendHookPoint) -> Result<(), StorageBackendError> {
            self.events.lock().unwrap().push(point);
            if self.panic_on_sensitive_call.load(Ordering::SeqCst)
                && matches!(
                    point,
                    BackendHookPoint::Filesystem
                        | BackendHookPoint::Key
                        | BackendHookPoint::Crypto
                        | BackendHookPoint::Nonce
                )
            {
                panic!("warm path performed forbidden {point:?} operation");
            }
            let mut failures = self.failures.lock().unwrap();
            if failures.front() == Some(&point) {
                failures.pop_front();
                return Err(StorageBackendError::Unavailable);
            }
            Ok(())
        }
    }

    struct SequenceRandom {
        values: VecDeque<Vec<u8>>,
        next: u8,
    }

    impl SequenceRandom {
        fn new(values: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                values: values.into_iter().collect(),
                next: 0x80,
            }
        }
    }

    impl RandomSource for SequenceRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
            if let Some(value) = self.values.pop_front() {
                if value.len() != destination.len() {
                    return Err("wrong deterministic random length".into());
                }
                destination.copy_from_slice(&value);
                return Ok(());
            }
            destination.fill(self.next);
            self.next = self.next.wrapping_add(1).max(1);
            Ok(())
        }
    }

    struct CancelAfterCalls {
        calls: AtomicUsize,
        cancel_at: usize,
    }

    impl CancellationSignal for CancelAfterCalls {
        fn is_cancelled(&self) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.cancel_at
        }
    }

    fn username(value: &str) -> CanonicalUsername {
        CanonicalUsername::new(value).unwrap()
    }

    fn model() -> ModelDigest {
        ModelDigest::new([0x42; 32])
    }

    fn key(value: u8) -> Mode1KeyContext {
        Mode1KeyContext::from_test_key([value; 32])
    }

    fn limits() -> Mode1StorageLimits {
        Mode1StorageLimits::new(32, 128 * 1024).unwrap()
    }

    fn cache_limits() -> ModelCacheLimits {
        ModelCacheLimits::new(8, 4 * 1024 * 1024).unwrap()
    }

    fn entry(id: u8, label: &str) -> EnrollmentEntry {
        let mut embedding = [0.0; EMBEDDING_DIMENSION];
        embedding[usize::from(id) % EMBEDDING_DIMENSION] = 1.0;
        EnrollmentEntry::new(
            EnrollmentId::new([id; 16]).unwrap(),
            1_700_000_000 + u64::from(id),
            label,
            embedding,
        )
        .unwrap()
    }

    fn artifact_count(root: &TempRoot, marker: &[u8]) -> usize {
        fs::read_dir(root.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .windows(marker.len())
                    .any(|window| window == marker)
            })
            .count()
    }

    #[allow(clippy::too_many_arguments)]
    fn backend_with(
        root: &TempRoot,
        key_byte: u8,
        digest: ModelDigest,
        epoch: u64,
        budget: PlaintextBudget,
        nonce_values: impl IntoIterator<Item = Vec<u8>>,
        hooks: Arc<CountingHooks>,
        nonce_ceiling: Option<u64>,
    ) -> Mode1StorageBackend {
        Mode1StorageBackend::new_with_sources(
            Mode1BackendOptions::path_override(root.path()),
            key(key_byte),
            digest,
            epoch,
            limits(),
            cache_limits(),
            budget,
            Box::new(SequenceRandom::new(nonce_values)),
            Box::new(SequenceRandom::new(std::iter::empty::<Vec<u8>>())),
            hooks,
            nonce_ceiling,
        )
        .unwrap()
    }

    fn backend_with_cache_limits(
        root: &TempRoot,
        budget: PlaintextBudget,
        cache_limits: ModelCacheLimits,
        nonce_values: impl IntoIterator<Item = Vec<u8>>,
    ) -> Mode1StorageBackend {
        Mode1StorageBackend::new_with_sources(
            Mode1BackendOptions::path_override(root.path()),
            key(0x11),
            model(),
            1,
            limits(),
            cache_limits,
            budget,
            Box::new(SequenceRandom::new(nonce_values)),
            Box::new(SequenceRandom::new(std::iter::empty::<Vec<u8>>())),
            Arc::new(CountingHooks::default()),
            None,
        )
        .unwrap()
    }

    fn backend(root: &TempRoot) -> Mode1StorageBackend {
        backend_with(
            root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        )
    }

    fn bootstrap_record(root: &TempRoot) {
        let backend = backend(root);
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "desk")]).unwrap())
            .unwrap();
        drop(backend);
    }

    fn bootstrap_two_entry_record(root: &TempRoot) {
        let backend = backend_with(
            root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            [vec![1; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one"), entry(2, "second")]).unwrap())
            .unwrap();
    }

    fn bootstrap_two_users(root: &TempRoot) {
        let backend = backend_with(
            root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            [vec![1; 12], vec![2; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        let alice = username("alice");
        let bob = username("bob");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "alice")]).unwrap())
            .unwrap();
        backend
            .append(AppendRequest::new(&bob, 0, &[entry(2, "bob")]).unwrap())
            .unwrap();
    }

    fn prime_nonce_tracker_before_measurement(root: &TempRoot, backend: &Mode1StorageBackend) {
        let primer = EnrollmentRecord::new(
            1,
            model(),
            username("nonce-primer"),
            vec![entry(99, "primer")],
        )
        .unwrap();
        backend.write_record(&primer).unwrap();
        fs::remove_file(root.record("nonce-primer")).unwrap();
    }

    fn assert_backend_poisoned(
        backend: &Mode1StorageBackend,
        username: &CanonicalUsername,
        reason: BackendPoisonReason,
    ) {
        assert_eq!(
            backend.health(),
            BackendHealth::Unavailable(BackendUnavailable::Integrity)
        );
        assert_eq!(backend.poison_reason_for_test(), Some(reason));
        assert!(backend.cache.is_poisoned());
        assert_eq!(backend.cached_generation_for_test(username), None);
        assert_eq!(
            backend.authenticate(username).unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend.list_metadata(username).unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend.candidate_presence(username).unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend.prompt_snapshot(username).unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend.verify_record(username).unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend
                .append(AppendRequest::new(username, 1, &[entry(9, "blocked")]).unwrap())
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend
                .admit_enrollment(
                    username,
                    1,
                    AppendAdmissionShape::new(1, "blocked".len()).unwrap(),
                )
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend
                .remove(
                    RemoveRequest::new(username, 1, EnrollmentId::new([1; 16]).unwrap()).unwrap()
                )
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend
                .clear(ClearRequest::new(username, 1).unwrap())
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(
            backend.reload().unwrap_err(),
            StorageBackendError::Unavailable
        );
    }

    fn assert_incremental_plaintext_peak(
        metrics: allocation_probe::AllocationMetrics,
        baseline_plaintext_bytes: usize,
        expected_operation_permit: usize,
        admitted_plaintext_ceiling: usize,
    ) {
        assert!(!metrics.slot_overflow, "allocation probe slot overflow");
        assert_eq!(metrics.layout_mismatches, 0);
        assert_eq!(metrics.classification_mismatches, 0);
        assert_eq!(metrics.untracked_plaintext_reallocations, 0, "{metrics:?}");
        assert_eq!(metrics.plaintext_reallocation_calls, 0, "{metrics:?}");
        assert_eq!(metrics.operation_permit_bytes, expected_operation_permit);
        let incremental_plaintext_peak = metrics
            .peak_plaintext_bytes
            .checked_sub(baseline_plaintext_bytes)
            .expect("checkpoint plaintext peak cannot be below its live baseline");
        assert!(
            incremental_plaintext_peak <= admitted_plaintext_ceiling,
            "temporal plaintext peak {incremental_plaintext_peak} exceeded ceiling {admitted_plaintext_ceiling}: {metrics:?}"
        );
    }

    fn finish_clean_allocation_probe(
        scope: allocation_probe::Scope,
    ) -> allocation_probe::AllocationMetrics {
        let metrics = scope.finish();
        assert!(!metrics.slot_overflow, "allocation probe slot overflow");
        assert_eq!(metrics.layout_mismatches, 0);
        assert_eq!(metrics.classification_mismatches, 0);
        assert_eq!(metrics.untracked_plaintext_reallocations, 0);
        assert_eq!(metrics.current_live_bytes, 0);
        assert_eq!(metrics.current_plaintext_bytes, 0);
        assert_eq!(metrics.current_allocations, 0);
        assert_eq!(
            metrics
                .allocation_calls
                .saturating_add(metrics.untracked_reallocations),
            metrics.deallocation_calls
        );
        assert_eq!(
            metrics
                .allocation_requested_bytes
                .saturating_add(metrics.reallocation_requested_bytes)
                .saturating_add(metrics.untracked_reallocation_old_layout_bytes),
            metrics
                .deallocation_layout_bytes
                .saturating_add(metrics.reallocation_old_layout_bytes)
        );
        assert!(metrics.largest_deallocation_layout != 0);
        metrics
    }

    #[test]
    fn exact_namespace_permissions_and_no_legacy_fallback_are_enforced() {
        assert_eq!(
            Mode1BackendOptions::production().root(),
            Path::new(MODE1_MODELS_DIR)
        );
        let root = TempRoot::new();
        fs::set_permissions(root.path(), Permissions::from_mode(0o755)).unwrap();
        let backend = backend(&root);
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let alice = username("alice");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        let bytes = fs::read(root.record("alice")).unwrap();
        assert_eq!(&bytes[..8], b"HOWYENC1");
        assert_eq!(
            fs::metadata(root.record("alice"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        fs::write(root.path().join("bob.bin"), b"legacy plaintext").unwrap();
        assert_eq!(
            backend.authenticate(&username("bob")).unwrap_err(),
            StorageBackendError::Absent
        );

        let target = TempRoot::new();
        let linked = root.path().join("linked");
        symlink(target.path(), &linked).unwrap();
        assert!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(linked),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn startup_readiness_reads_only_bounded_outer_headers_and_populates_no_cache() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let hooks = Arc::new(CountingHooks::default());
        let backend = backend_with(
            &root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            std::iter::empty::<Vec<u8>>(),
            Arc::clone(&hooks),
            None,
        );
        assert!(hooks.count(BackendHookPoint::Filesystem) > 0);
        assert_eq!(hooks.count(BackendHookPoint::Key), 0);
        assert_eq!(hooks.count(BackendHookPoint::Crypto), 0);
        assert_eq!(backend.cached_generation_for_test(&username("alice")), None);
    }

    #[test]
    fn readiness_inventory_streams_under_a_hard_cap_and_rejects_ambiguous_clear_artifacts() {
        let root = TempRoot::new();
        for name in ["one", "two", "three"] {
            fs::write(root.path().join(name), []).unwrap();
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(root.path())
            .unwrap();
        assert_eq!(
            for_each_directory_name(&directory, 2, |_| Ok(())).unwrap_err(),
            StorageBackendError::InvalidInput("mode 1 namespace entry limit")
        );

        fs::write(root.path().join(".alice.hye.clear.0011"), []).unwrap();
        assert_eq!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap_err(),
            StorageBackendError::Corrupt
        );
    }

    #[test]
    fn startup_ignores_and_boundedly_cleans_only_non_authoritative_temps() {
        for cleanup_fails in [false, true] {
            let root = TempRoot::new();
            bootstrap_record(&root);
            let stale = root
                .path()
                .join(".alice.hye.tmp.00112233445566778899aabbccddeeff");
            fs::write(&stale, b"partial pre-rename bytes").unwrap();
            fs::set_permissions(&stale, Permissions::from_mode(STORAGE_RECORD_MODE)).unwrap();
            let hooks = Arc::new(CountingHooks::default());
            if cleanup_fails {
                hooks.fail_next(BackendHookPoint::StaleTempCleanupUnlink);
            }
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![9; 12]],
                Arc::clone(&hooks),
                None,
            );
            assert_eq!(
                backend
                    .authenticate(&username("alice"))
                    .unwrap()
                    .generation(),
                1
            );
            assert_eq!(backend.health(), BackendHealth::Ready);
            assert_eq!(stale.exists(), cleanup_fails);
            assert_eq!(artifact_count(&root, b".tmp."), usize::from(cleanup_fails));
        }
    }

    #[test]
    fn failed_commit_rename_cleans_or_reports_stale_temp_without_harming_active_authority() {
        for cleanup_fails in [false, true] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12], vec![2; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            hooks.fail_next(BackendHookPoint::CommitRename);
            if cleanup_fails {
                hooks.fail_next(BackendHookPoint::StaleTempCleanupUnlink);
            }
            assert_eq!(
                backend
                    .append(AppendRequest::new(&alice, 1, &[entry(2, "new")]).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable
            );
            assert_eq!(backend.health(), BackendHealth::Ready);
            assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);
            assert_eq!(
                artifact_count(&root, b".staged."),
                usize::from(cleanup_fails)
            );

            backend.reload().unwrap();
            assert_eq!(artifact_count(&root, b".staged."), 0);
            assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);
        }
    }

    #[test]
    fn guarded_key_is_wiped_once_after_backend_init_failure_and_runtime_drop() {
        let failed_root = TempRoot::new();
        fs::set_permissions(failed_root.path(), Permissions::from_mode(0o755)).unwrap();
        let failed_drop = Arc::new(AtomicUsize::new(0));
        let result = Mode1StorageBackend::new(
            Mode1BackendOptions::path_override(failed_root.path())
                .with_directory_behavior(DirectoryBehavior::RequireExisting),
            Mode1KeyContext::from_test_key_with_drop_probe([0x11; 32], Arc::clone(&failed_drop)),
            model(),
            1,
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(failed_drop.load(Ordering::SeqCst), 1);

        let live_root = TempRoot::new();
        let live_drop = Arc::new(AtomicUsize::new(0));
        let backend = Mode1StorageBackend::new(
            Mode1BackendOptions::path_override(live_root.path()),
            Mode1KeyContext::from_test_key_with_drop_probe([0x11; 32], Arc::clone(&live_drop)),
            model(),
            1,
            limits(),
            cache_limits(),
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(live_drop.load(Ordering::SeqCst), 0);
        drop(backend);
        assert_eq!(live_drop.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn valid_cold_load_then_warm_and_prompt_hits_have_zero_sensitive_events() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let hooks = Arc::new(CountingHooks::default());
        let backend = Arc::new(backend_with(
            &root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            std::iter::empty::<Vec<u8>>(),
            Arc::clone(&hooks),
            None,
        ));
        hooks.clear();
        let alice = username("alice");
        let cold = backend.authenticate(&alice).unwrap();
        assert_eq!(cold.kind(), LeaseKind::Cached);
        assert_eq!(cold.labels().collect::<Vec<_>>(), ["desk"]);
        assert!(hooks.count(BackendHookPoint::Filesystem) > 0);
        assert_eq!(hooks.count(BackendHookPoint::Key), 1);
        assert_eq!(hooks.count(BackendHookPoint::Crypto), 1);
        hooks.clear();
        hooks.panic_on_sensitive_call.store(true, Ordering::SeqCst);

        let allocation_scope = AllocationCountScope::start();
        let warm_snapshot = backend.prompt_snapshot(&alice).unwrap();
        let warm_snapshot_allocations = allocation_scope.count();
        drop(allocation_scope);
        assert_eq!(
            warm_snapshot.candidate(),
            CandidatePresence::Candidate { generation: 1 }
        );
        assert_eq!(warm_snapshot_allocations, 0);

        let allocation_scope = AllocationCountScope::start();
        for _ in 0..16 {
            let lease = backend.authenticate(&alice).unwrap();
            assert_eq!(lease.generation(), 1);
            assert_eq!(
                backend.prompt_snapshot(&alice).unwrap().candidate(),
                CandidatePresence::Candidate { generation: 1 }
            );
            let prompt_load = backend
                .authenticate_active(&alice, &NeverCancelled)
                .unwrap();
            assert!(!prompt_load.has_provisional_promotion());
            assert_eq!(prompt_load.generation(), 1);
        }
        assert_eq!(allocation_scope.count(), 0);
        drop(allocation_scope);

        backend.cache.force_clock_rollover_for_test();
        let allocation_scope = AllocationCountScope::start();
        assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);
        assert_eq!(allocation_scope.count(), 0);
        drop(allocation_scope);
        backend.cache.force_clock_rollover_for_test();
        let allocation_scope = AllocationCountScope::start();
        assert_eq!(
            backend.prompt_snapshot(&alice).unwrap().candidate(),
            CandidatePresence::Candidate { generation: 1 }
        );
        assert_eq!(allocation_scope.count(), 0);
        drop(allocation_scope);
        backend.cache.force_clock_rollover_for_test();
        let allocation_scope = AllocationCountScope::start();
        assert_eq!(
            backend
                .authenticate_active(&alice, &NeverCancelled)
                .unwrap()
                .generation(),
            1
        );
        assert_eq!(allocation_scope.count(), 0);
        drop(allocation_scope);

        let barrier = Arc::new(Barrier::new(9));
        let mut readers = Vec::new();
        for _ in 0..8 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            let alice = alice.clone();
            readers.push(std::thread::spawn(move || {
                barrier.wait();
                let allocation_scope = AllocationCountScope::start();
                let generation = backend.authenticate(&alice).unwrap().generation();
                let allocations = allocation_scope.count();
                drop(allocation_scope);
                (generation, allocations)
            }));
        }
        barrier.wait();
        for reader in readers {
            assert_eq!(reader.join().unwrap(), (1, 0));
        }
        assert_eq!(hooks.count(BackendHookPoint::Filesystem), 0);
        assert_eq!(hooks.count(BackendHookPoint::Key), 0);
        assert_eq!(hooks.count(BackendHookPoint::Crypto), 0);
        assert_eq!(hooks.count(BackendHookPoint::Nonce), 0);
    }

    #[test]
    fn active_cold_load_is_provisional_and_reload_race_blocks_promotion() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let backend = backend_with(
            &root,
            0x11,
            model(),
            1,
            budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let alice = username("alice");

        let private = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        assert!(private.has_provisional_promotion());
        assert_eq!(backend.cached_generation_for_test(&alice), None);
        drop(private);
        assert_eq!(budget.used(), 0);

        let mut private = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let stale = private.take_promotion().unwrap();
        backend.reload().unwrap();
        drop(private);
        assert!(!stale.promote().unwrap());
        assert_eq!(backend.cached_generation_for_test(&alice), None);

        let mut accepted = backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let promotion = accepted.take_promotion().unwrap();
        drop(accepted);
        assert!(promotion.promote().unwrap());
        assert_eq!(backend.cached_generation_for_test(&alice), Some(1));
    }

    #[test]
    fn wrong_key_and_all_representative_tampering_fail_closed_without_cache() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let alice = username("alice");
        let original = fs::read(root.record("alice")).unwrap();

        let wrong_key = backend_with(
            &root,
            0x22,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        assert_eq!(
            wrong_key.list_metadata(&alice).unwrap_err(),
            StorageBackendError::AuthenticationFailed
        );
        assert_eq!(wrong_key.cached_generation_for_test(&alice), None);
        drop(wrong_key);

        for mutate in 0..5 {
            fs::write(root.record("alice"), &original).unwrap();
            let backend = backend(&root);
            let mut changed = original.clone();
            match mutate {
                0 => changed[76] ^= 1, // nonce/AAD
                1 => {
                    let header = inspect_howyenc1(&changed).unwrap();
                    changed[header.header_length()] ^= 1;
                }
                2 => *changed.last_mut().unwrap() ^= 1,
                3 => changed.truncate(changed.len() - 1),
                4 => changed.extend_from_slice(&[0]),
                _ => unreachable!(),
            }
            fs::write(root.record("alice"), changed).unwrap();
            let error = backend.list_metadata(&alice).unwrap_err();
            assert!(matches!(
                error,
                StorageBackendError::AuthenticationFailed | StorageBackendError::Corrupt
            ));
            assert_eq!(backend.cached_generation_for_test(&alice), None);
        }

        fs::write(root.record("alice"), &original).unwrap();
        let backend = backend(&root);
        fs::write(root.record("bob"), &original).unwrap();
        fs::set_permissions(root.record("bob"), Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            backend.list_metadata(&username("bob")).unwrap_err(),
            StorageBackendError::Corrupt
        );
        fs::remove_file(root.record("bob")).unwrap();

        assert_eq!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                ModelDigest::new([0x99; 32]),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap_err(),
            StorageBackendError::ModelMismatch,
        );
        assert_eq!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                2,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap_err(),
            StorageBackendError::KeyMismatch,
        );
    }

    #[test]
    fn authenticated_malformed_plaintext_reaches_decoder_and_fails_closed() {
        let root = TempRoot::new();
        let backend = backend(&root);
        let alice = username("alice");
        let first = entry(1, "one");
        backend
            .append(AppendRequest::new(&alice, 0, std::slice::from_ref(&first)).unwrap())
            .unwrap();
        backend
            .remove(RemoveRequest::new(&alice, 1, first.enrollment_id()).unwrap())
            .unwrap();
        assert_eq!(backend.cached_generation_for_test(&alice), None);

        let encoded = fs::read(root.record("alice")).unwrap();
        let header = inspect_howyenc1(&encoded).unwrap();
        assert_eq!(header.entry_count(), 0);
        assert_eq!(header.plaintext_length(), 8);
        let aad = &encoded[..header.header_length()];
        let mut malformed = vec![0u8; 8];
        malformed[..2].copy_from_slice(&2u16.to_le_bytes());
        let cipher = Aes256Gcm::new_from_slice(&[0x11; 32]).unwrap();
        cipher
            .encrypt_in_place(&Nonce::from(header.nonce()), aad, &mut malformed)
            .unwrap();
        let mut replacement = aad.to_vec();
        replacement.extend_from_slice(&malformed);
        assert_eq!(replacement.len(), encoded.len());
        fs::write(root.record("alice"), replacement).unwrap();

        assert_eq!(
            backend.list_metadata(&alice).unwrap_err(),
            StorageBackendError::Corrupt
        );
        assert_eq!(backend.cached_generation_for_test(&alice), None);
    }

    #[test]
    fn symlink_insecure_hardlink_and_oversize_records_are_rejected() {
        let root = TempRoot::new();
        let target = root.path().join("target");
        let mut target_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&target)
            .unwrap();
        target_file.write_all(b"not a record").unwrap();
        symlink(&target, root.record("alice")).unwrap();
        assert!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .is_err()
        );
        fs::remove_file(root.record("alice")).unwrap();
        fs::remove_file(target).unwrap();

        bootstrap_record(&root);
        fs::set_permissions(root.record("alice"), Permissions::from_mode(0o644)).unwrap();
        assert!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .is_err()
        );
        fs::set_permissions(root.record("alice"), Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(root.record("alice"), root.path().join("second-link")).unwrap();
        assert!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .is_err()
        );
        fs::remove_file(root.path().join("second-link")).unwrap();
        fs::write(
            root.record("alice"),
            vec![0u8; HOWYENC1_MAX_RECORD_BYTES + 1],
        )
        .unwrap();
        assert!(
            Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn nonce_duplicate_write_ceiling_and_failed_write_consume_attempts() {
        let alice = username("alice");

        let duplicate_root = TempRoot::new();
        let duplicate = backend_with(
            &duplicate_root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            [vec![1; 12], vec![1; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        duplicate
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        let old = fs::read(duplicate_root.record("alice")).unwrap();
        assert_eq!(
            duplicate
                .append(AppendRequest::new(&alice, 1, &[entry(2, "two")]).unwrap())
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(fs::read(duplicate_root.record("alice")).unwrap(), old);
        assert_eq!(duplicate.cached_generation_for_test(&alice), Some(1));

        let ceiling_root = TempRoot::new();
        let ceiling = backend_with(
            &ceiling_root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            [vec![2; 12], vec![3; 12]],
            Arc::new(CountingHooks::default()),
            Some(1),
        );
        ceiling
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        assert_eq!(
            ceiling
                .append(AppendRequest::new(&alice, 1, &[entry(2, "two")]).unwrap())
                .unwrap_err(),
            StorageBackendError::Unavailable
        );

        let failed_root = TempRoot::new();
        let hooks = Arc::new(CountingHooks::default());
        let failed = backend_with(
            &failed_root,
            0x11,
            model(),
            1,
            PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            [vec![4; 12], vec![5; 12]],
            Arc::clone(&hooks),
            None,
        );
        hooks.fail_next(BackendHookPoint::AfterFileSync);
        assert!(
            failed
                .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
                .is_err()
        );
        assert!(!failed_root.record("alice").exists());
        failed
            .append(AppendRequest::new(&alice, 0, &[entry(1, "one")]).unwrap())
            .unwrap();
        assert_eq!(
            inspect_howyenc1(&fs::read(failed_root.record("alice")).unwrap())
                .unwrap()
                .nonce(),
            [5; 12]
        );
    }

    #[test]
    fn mutation_faults_roll_back_ciphertext_and_keep_previous_cache() {
        for point in [
            BackendHookPoint::AfterFileSync,
            BackendHookPoint::TransactionStageSync,
            BackendHookPoint::CommitRename,
            BackendHookPoint::AfterRename,
            BackendHookPoint::PrimaryDirectorySync,
            BackendHookPoint::AfterDirectorySync,
        ] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12], vec![2; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            let old = fs::read(root.record("alice")).unwrap();
            hooks.fail_next(point);
            assert_eq!(
                backend
                    .append(AppendRequest::new(&alice, 1, &[entry(2, "new")]).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable,
                "fault={point:?}"
            );
            assert_eq!(fs::read(root.record("alice")).unwrap(), old);
            assert_eq!(backend.cached_generation_for_test(&alice), Some(1));
            assert_eq!(
                backend
                    .authenticate(&alice)
                    .unwrap()
                    .labels()
                    .collect::<Vec<_>>(),
                ["old"]
            );
        }
    }

    #[test]
    fn clear_faults_restore_authenticated_ciphertext_and_cached_generation() {
        for point in [
            BackendHookPoint::AfterRename,
            BackendHookPoint::PrimaryDirectorySync,
            BackendHookPoint::AfterDirectorySync,
            BackendHookPoint::CleanupUnlink,
        ] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            let old = fs::read(root.record("alice")).unwrap();
            hooks.fail_next(point);
            assert_eq!(
                backend
                    .clear(ClearRequest::new(&alice, 1).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable
            );
            assert_eq!(fs::read(root.record("alice")).unwrap(), old);
            assert_eq!(backend.cached_generation_for_test(&alice), Some(1));
            assert_eq!(backend.list_metadata(&alice).unwrap().generation(), 1);
        }
    }

    #[test]
    fn rollback_rename_and_fsync_failures_permanently_poison_backend_and_cache() {
        for (rollback_failure, expected_active) in [
            (BackendHookPoint::RollbackRename, "new"),
            (BackendHookPoint::RollbackDirectorySync, "old"),
        ] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12], vec![2; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);

            hooks.fail_sequence([BackendHookPoint::PrimaryDirectorySync, rollback_failure]);
            assert_eq!(
                backend
                    .append(AppendRequest::new(&alice, 1, &[entry(2, "new")]).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable
            );
            assert_backend_poisoned(&backend, &alice, BackendPoisonReason::WriteRollback);

            // Decode the concrete active pathname without consulting the
            // poisoned backend/cache. Restart itself rejects the retained
            // transaction artifact until operator recovery.
            let active = fs::read(root.record("alice")).unwrap();
            let record = decode_howyenc1(
                &active,
                &[0x11; 32],
                StorageMode::AeadCached,
                1,
                &alice,
                model(),
            )
            .unwrap();
            assert_eq!(
                MetadataList::from_record(&record)
                    .entries()
                    .last()
                    .unwrap()
                    .label(),
                expected_active
            );
            assert_eq!(
                Mode1StorageBackend::new(
                    Mode1BackendOptions::path_override(root.path()),
                    key(0x11),
                    model(),
                    1,
                    limits(),
                    cache_limits(),
                    PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                )
                .unwrap_err(),
                StorageBackendError::Corrupt
            );
        }
    }

    #[test]
    fn committed_replacement_cleanup_uncertainty_poison_is_stage_specific() {
        for point in [
            BackendHookPoint::CleanupUnlink,
            BackendHookPoint::FinalDirectorySync,
        ] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12], vec![2; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            hooks.fail_next(point);
            assert_eq!(
                backend
                    .append(AppendRequest::new(&alice, 1, &[entry(2, "new")]).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable
            );
            assert_backend_poisoned(&backend, &alice, BackendPoisonReason::WriteCleanup);
            let active = decode_howyenc1(
                &fs::read(root.record("alice")).unwrap(),
                &[0x11; 32],
                StorageMode::AeadCached,
                1,
                &alice,
                model(),
            )
            .unwrap();
            assert_eq!(active.generation(), 2);

            let restarted = Mode1StorageBackend::new(
                Mode1BackendOptions::path_override(root.path()),
                key(0x11),
                model(),
                1,
                limits(),
                cache_limits(),
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
            );
            if point == BackendHookPoint::CleanupUnlink {
                assert_eq!(restarted.unwrap_err(), StorageBackendError::Corrupt);
                assert_eq!(artifact_count(&root, b".staged."), 1);
            } else {
                let restarted = restarted.unwrap();
                assert_eq!(restarted.authenticate(&alice).unwrap().generation(), 2);
                assert_eq!(artifact_count(&root, b".staged."), 0);
            }
        }
    }

    #[test]
    fn clear_final_fsync_and_rollback_failures_never_report_success_or_serve_cache() {
        for (failures, reason, active_exists) in [
            (
                vec![BackendHookPoint::FinalDirectorySync],
                BackendPoisonReason::ClearCommit,
                false,
            ),
            (
                vec![
                    BackendHookPoint::CleanupUnlink,
                    BackendHookPoint::RollbackRename,
                ],
                BackendPoisonReason::ClearRollback,
                false,
            ),
            (
                vec![
                    BackendHookPoint::PrimaryDirectorySync,
                    BackendHookPoint::RollbackDirectorySync,
                ],
                BackendPoisonReason::ClearRollback,
                true,
            ),
        ] {
            let root = TempRoot::new();
            let hooks = Arc::new(CountingHooks::default());
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12]],
                Arc::clone(&hooks),
                None,
            );
            let alice = username("alice");
            backend
                .append(AppendRequest::new(&alice, 0, &[entry(1, "old")]).unwrap())
                .unwrap();
            assert_eq!(backend.authenticate(&alice).unwrap().generation(), 1);
            hooks.fail_sequence(failures);
            assert_eq!(
                backend
                    .clear(ClearRequest::new(&alice, 1).unwrap())
                    .unwrap_err(),
                StorageBackendError::Unavailable
            );
            assert_eq!(root.record("alice").exists(), active_exists);
            assert_backend_poisoned(&backend, &alice, reason);
            let has_clear_tombstone = fs::read_dir(root.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .windows(7)
                    .any(|window| window == b".clear.")
            });
            assert_eq!(
                has_clear_tombstone,
                !active_exists && reason == BackendPoisonReason::ClearRollback
            );
        }
    }

    #[test]
    fn mode1_eviction_keeps_outstanding_arc_lease_valid_and_budgeted() {
        let root = TempRoot::new();
        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let backend = Mode1StorageBackend::new_with_sources(
            Mode1BackendOptions::path_override(root.path()),
            key(0x11),
            model(),
            1,
            limits(),
            ModelCacheLimits::new(1, 4 * 1024 * 1024).unwrap(),
            budget.clone(),
            Box::new(SequenceRandom::new([vec![1; 12], vec![2; 12]])),
            Box::new(SequenceRandom::new(std::iter::empty::<Vec<u8>>())),
            Arc::new(CountingHooks::default()),
            None,
        )
        .unwrap();
        let alice = username("alice");
        let bob = username("bob");
        backend
            .append(AppendRequest::new(&alice, 0, &[entry(1, "alice")]).unwrap())
            .unwrap();
        let alice_lease = backend.authenticate(&alice).unwrap();
        let charged = alice_lease.plaintext_bytes();
        backend
            .append(AppendRequest::new(&bob, 0, &[entry(2, "bob")]).unwrap())
            .unwrap();
        assert_eq!(alice_lease.labels().collect::<Vec<_>>(), ["alice"]);
        assert_eq!(backend.cached_generation_for_test(&alice), None);
        assert_eq!(backend.cached_generation_for_test(&bob), Some(1));
        let bob_charged = backend.authenticate(&bob).unwrap().plaintext_bytes();
        assert_eq!(budget.used(), charged + bob_charged);
        drop(alice_lease);
        assert_eq!(budget.used(), bob_charged);
    }

    #[test]
    fn allocator_probe_tracks_temporal_classes_realloc_nested_scopes_and_tls_teardown() {
        let _serialized = ALLOCATION_MEASUREMENT_LOCK.lock().unwrap();
        use allocation_probe::AllocationClass::{Infrastructure, PlaintextSensitive};

        let scope = allocation_probe::Scope::start();

        // Infrastructure peaks before the sensitive allocation. Subtracting a
        // cumulative infrastructure total would incorrectly mask this overrun;
        // class-at-allocation-time accounting retains the true temporal 80-byte
        // plaintext peak against the injected 64-byte ceiling.
        let staggered_infrastructure = vec![0u8; 128];
        assert_eq!(scope.snapshot().peak_plaintext_bytes, 0);
        drop(staggered_infrastructure);
        let plaintext_overrun =
            allocation_probe::with_class(PlaintextSensitive, || vec![0x5Au8; 80]);
        let overrun_metrics = scope.snapshot();
        assert!(overrun_metrics.peak_plaintext_bytes > 64);
        assert_eq!(overrun_metrics.peak_plaintext_bytes, 80);

        let (nested_plaintext, nested_infrastructure, nested_plaintext_tail) =
            allocation_probe::with_class(PlaintextSensitive, || {
                let plaintext = vec![0x11u8; 32];
                let infrastructure =
                    allocation_probe::with_class(Infrastructure, || vec![0x22u8; 256]);
                let plaintext_tail =
                    allocation_probe::with_class(PlaintextSensitive, || vec![0x33u8; 16]);
                (plaintext, infrastructure, plaintext_tail)
            });
        assert_eq!(scope.snapshot().current_plaintext_bytes, 80 + 32 + 16);

        // A realloc without an active override inherits the pointer's stored
        // sensitive class. A later realloc under an explicit infrastructure
        // scope changes ownership class exactly once without double counting.
        let mut reallocated =
            allocation_probe::with_class(PlaintextSensitive, || Vec::<u8>::with_capacity(8));
        reallocated.reserve_exact(24);
        let inherited_capacity = reallocated.capacity();
        assert!(inherited_capacity >= 24);
        let before_class_change = scope.snapshot().current_plaintext_bytes;
        allocation_probe::with_class(Infrastructure, || {
            reallocated.reserve_exact(64);
        });
        let after_class_change = scope.snapshot();
        assert!(after_class_change.plaintext_reallocation_calls >= 2);
        assert_eq!(
            after_class_change.current_plaintext_bytes,
            before_class_change - inherited_capacity
        );

        drop(reallocated);
        drop(nested_plaintext_tail);
        drop(nested_infrastructure);
        drop(nested_plaintext);
        drop(plaintext_overrun);
        let metrics = finish_clean_allocation_probe(scope);
        assert!(metrics.reallocation_calls >= 2);
        assert!(metrics.deallocation_calls != 0);

        // Initialize the teardown allocator before the probe TLS so reverse TLS
        // destruction allocates only after ProbeTls has become unavailable.
        let before = TLS_TEARDOWN_ALLOCATION_CALLS.load(Ordering::SeqCst);
        std::thread::spawn(|| {
            ALLOCATE_DURING_TLS_TEARDOWN.with(|_| {});
            let scope = allocation_probe::Scope::start();
            let plaintext =
                allocation_probe::with_class(PlaintextSensitive, || Box::new([0x44u8; 32]));
            assert_eq!(scope.snapshot().current_plaintext_bytes, 32);
            drop(plaintext);
            finish_clean_allocation_probe(scope);
        })
        .join()
        .unwrap();
        assert_eq!(
            TLS_TEARDOWN_ALLOCATION_CALLS.load(Ordering::SeqCst),
            before + 1
        );
    }

    #[test]
    fn byte_aware_allocator_bounds_real_mode1_ownership_and_exact_admission() {
        let _serialized = ALLOCATION_MEASUREMENT_LOCK.lock().unwrap();

        // Cold provisional ownership: the scope includes only decoder/AEAD and
        // exact model allocations. Unclassified descriptor, cache-map, harness,
        // username, public-header, tag, and wire-ciphertext allocations are
        // tagged as infrastructure at allocation time.
        let cold_root = TempRoot::new();
        bootstrap_record(&cold_root);
        let alice = username("alice");
        let probe = backend(&cold_root);
        let cold_header = probe.inspect_record(&alice).unwrap().unwrap().header;
        drop(probe);
        let cold_estimate =
            PlaintextAllocationEstimate::for_encrypted_header(&cold_header).unwrap();
        let cold_required = cold_estimate.cold_load_peak_bytes();
        let cold_budget = PlaintextBudget::new(cold_required).unwrap();
        let cold_backend = backend_with(
            &cold_root,
            0x11,
            model(),
            1,
            cold_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );

        let cold_scope = allocation_probe::Scope::start();
        let mut provisional = cold_backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let cold_metrics = cold_scope.snapshot();
        assert_incremental_plaintext_peak(cold_metrics, 0, cold_required, cold_required);
        assert_eq!(
            cold_metrics.current_plaintext_bytes,
            provisional.plaintext_bytes()
        );
        let discarded = provisional.take_promotion().unwrap();
        drop(provisional);
        drop(discarded);
        assert_eq!(cold_scope.snapshot().current_plaintext_bytes, 0);
        drop(cold_backend);
        finish_clean_allocation_probe(cold_scope);
        assert_eq!(cold_budget.used(), 0);

        let promoted_backend = backend_with(
            &cold_root,
            0x11,
            model(),
            1,
            cold_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let promoted_scope = allocation_probe::Scope::start();
        let mut promoted = promoted_backend
            .authenticate_active(&alice, &NeverCancelled)
            .unwrap();
        let promotion = promoted.take_promotion().unwrap();
        let promoted_bytes = promoted.plaintext_bytes();
        drop(promoted);
        assert!(promotion.promote().unwrap());
        let promoted_metrics = promoted_scope.snapshot();
        assert_incremental_plaintext_peak(promoted_metrics, 0, cold_required, cold_required);
        assert_eq!(promoted_metrics.current_plaintext_bytes, promoted_bytes);
        promoted_backend.cache.invalidate(&alice);
        assert_eq!(promoted_scope.snapshot().current_plaintext_bytes, 0);
        drop(promoted_backend);
        finish_clean_allocation_probe(promoted_scope);
        assert_eq!(cold_budget.used(), 0);

        let cold_short_budget = PlaintextBudget::new(cold_required - 1).unwrap();
        let cold_short = backend_with(
            &cold_root,
            0x11,
            model(),
            1,
            cold_short_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let cold_short_scope = allocation_probe::Scope::start();
        assert!(matches!(
            cold_short.authenticate_active(&alice, &NeverCancelled),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        let cold_short_metrics = cold_short_scope.snapshot();
        assert_eq!(cold_short_metrics.current_plaintext_bytes, 0);
        assert_eq!(cold_short_metrics.peak_plaintext_bytes, 0);
        drop(cold_short);
        finish_clean_allocation_probe(cold_short_scope);
        assert_eq!(cold_short_budget.used(), 0);

        // Append measures caller-owned entries plus simultaneous authenticated
        // source, exact final record, flattened model, payload, and AEAD staging
        // while replacing an existing cached generation.
        let append_root = TempRoot::new();
        bootstrap_record(&append_root);
        let probe = backend(&append_root);
        let append_header = probe.inspect_record(&alice).unwrap().unwrap().header;
        drop(probe);
        let append_estimate =
            PlaintextAllocationEstimate::for_append_shape(Some(&append_header), 1, "second".len())
                .unwrap();
        let append_operation = append_estimate.mutation_peak_bytes();
        let old_model_bytes = PlaintextAllocationEstimate::for_encrypted_header(&append_header)
            .unwrap()
            .flat_auth_model_bytes();
        let input_permit_bytes = 4_096;
        let append_total = old_model_bytes
            .checked_add(append_operation)
            .and_then(|bytes| bytes.checked_add(input_permit_bytes))
            .unwrap();
        let append_budget = PlaintextBudget::new(append_total).unwrap();
        let append_backend = backend_with(
            &append_root,
            0x11,
            model(),
            1,
            append_budget.clone(),
            [vec![3; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        // The fixed nonce-reuse tracker is non-plaintext process infrastructure
        // and lazily allocates on its first accepted nonce. Establish it before
        // the clean scoped baseline rather than subtracting it from the result.
        prime_nonce_tracker_before_measurement(&append_root, &append_backend);
        let append_scope = allocation_probe::Scope::start();
        drop(append_backend.authenticate(&alice).unwrap());
        assert_eq!(
            append_scope.snapshot().current_plaintext_bytes,
            old_model_bytes
        );
        append_scope.checkpoint();
        let shape = AppendAdmissionShape::new(1, "second".len()).unwrap();
        let admission = append_backend
            .admit_enrollment(&alice, input_permit_bytes, shape)
            .unwrap();
        let (operation, input) = admission.into_parts();
        assert_eq!(operation.bytes(), append_operation);
        assert_eq!(input.bytes(), input_permit_bytes);
        let caller_entries = allocation_probe::with_class(
            allocation_probe::AllocationClass::PlaintextSensitive,
            || vec![entry(2, "second")],
        );
        append_backend
            .append_admitted(
                AppendRequest::new(&alice, 1, &caller_entries).unwrap(),
                operation,
            )
            .unwrap();
        let append_metrics = append_scope.snapshot();
        assert_incremental_plaintext_peak(
            append_metrics,
            old_model_bytes,
            append_operation,
            append_operation + input_permit_bytes,
        );
        assert!(append_metrics.zeroed_allocation_calls != 0);
        drop(caller_entries);
        drop(input);
        append_backend.cache.invalidate(&alice);
        assert_eq!(append_scope.snapshot().current_plaintext_bytes, 0);
        drop(append_backend);
        finish_clean_allocation_probe(append_scope);
        assert_eq!(append_budget.used(), 0);

        let append_short_root = TempRoot::new();
        bootstrap_record(&append_short_root);
        let append_short_budget = PlaintextBudget::new(append_total - 1).unwrap();
        let append_short = backend_with(
            &append_short_root,
            0x11,
            model(),
            1,
            append_short_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let append_short_scope = allocation_probe::Scope::start();
        drop(append_short.authenticate(&alice).unwrap());
        let append_short_baseline = append_short_scope.checkpoint();
        assert!(matches!(
            append_short.admit_enrollment(&alice, input_permit_bytes, shape),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        let append_short_metrics = append_short_scope.snapshot();
        assert_eq!(
            append_short_metrics.current_plaintext_bytes,
            old_model_bytes
        );
        assert_eq!(append_short_metrics.peak_plaintext_bytes, old_model_bytes);
        assert_eq!(
            append_short_metrics.plaintext_reallocation_calls,
            append_short_baseline.plaintext_reallocation_calls
        );
        append_short.cache.invalidate(&alice);
        drop(append_short);
        finish_clean_allocation_probe(append_short_scope);
        assert_eq!(append_short_budget.used(), 0);

        // Remove performs the same source/final/cache replacement proof without
        // caller biometric input.
        let remove_root = TempRoot::new();
        bootstrap_two_entry_record(&remove_root);
        let probe = backend(&remove_root);
        let remove_header = probe.inspect_record(&alice).unwrap().unwrap().header;
        drop(probe);
        let remove_estimate =
            PlaintextAllocationEstimate::for_replacement_of_encrypted_header(&remove_header)
                .unwrap();
        let remove_operation = remove_estimate.mutation_peak_bytes();
        let remove_old_model = PlaintextAllocationEstimate::for_encrypted_header(&remove_header)
            .unwrap()
            .flat_auth_model_bytes();
        let remove_total = remove_old_model + remove_operation;
        let remove_budget = PlaintextBudget::new(remove_total).unwrap();
        let remove_backend = backend_with(
            &remove_root,
            0x11,
            model(),
            1,
            remove_budget.clone(),
            [vec![4; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        prime_nonce_tracker_before_measurement(&remove_root, &remove_backend);
        let remove_scope = allocation_probe::Scope::start();
        drop(remove_backend.authenticate(&alice).unwrap());
        remove_scope.checkpoint();
        remove_backend
            .remove(RemoveRequest::new(&alice, 1, EnrollmentId::new([1; 16]).unwrap()).unwrap())
            .unwrap();
        let remove_metrics = remove_scope.snapshot();
        assert_incremental_plaintext_peak(
            remove_metrics,
            remove_old_model,
            remove_operation,
            remove_operation,
        );
        remove_backend.cache.invalidate(&alice);
        assert_eq!(remove_scope.snapshot().current_plaintext_bytes, 0);
        drop(remove_backend);
        finish_clean_allocation_probe(remove_scope);
        assert_eq!(remove_budget.used(), 0);

        let remove_short_root = TempRoot::new();
        bootstrap_two_entry_record(&remove_short_root);
        let remove_short_budget = PlaintextBudget::new(remove_total - 1).unwrap();
        let remove_short = backend_with(
            &remove_short_root,
            0x11,
            model(),
            1,
            remove_short_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let remove_short_scope = allocation_probe::Scope::start();
        drop(remove_short.authenticate(&alice).unwrap());
        let remove_short_baseline = remove_short_scope.checkpoint();
        assert!(matches!(
            remove_short.remove(
                RemoveRequest::new(&alice, 1, EnrollmentId::new([1; 16]).unwrap()).unwrap()
            ),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        let remove_short_metrics = remove_short_scope.snapshot();
        assert_eq!(
            remove_short_metrics.current_plaintext_bytes,
            remove_old_model
        );
        assert_eq!(remove_short_metrics.peak_plaintext_bytes, remove_old_model);
        assert_eq!(
            remove_short_metrics.plaintext_reallocation_calls,
            remove_short_baseline.plaintext_reallocation_calls
        );
        remove_short.cache.invalidate(&alice);
        drop(remove_short);
        finish_clean_allocation_probe(remove_short_scope);
        assert_eq!(remove_short_budget.used(), 0);

        // LRU eviction and an outstanding Arc lease use the same tracked model
        // allocations; cache maps/keys and Arc metadata are infrastructure.
        let eviction_root = TempRoot::new();
        bootstrap_two_users(&eviction_root);
        let alice = username("alice");
        let bob = username("bob");
        let probe = backend(&eviction_root);
        let alice_header = probe.inspect_record(&alice).unwrap().unwrap().header;
        let bob_header = probe.inspect_record(&bob).unwrap().unwrap().header;
        drop(probe);
        let alice_model = PlaintextAllocationEstimate::for_encrypted_header(&alice_header)
            .unwrap()
            .flat_auth_model_bytes();
        let bob_estimate = PlaintextAllocationEstimate::for_encrypted_header(&bob_header).unwrap();
        let bob_cold = bob_estimate.cold_load_peak_bytes();
        let bob_model = bob_estimate.flat_auth_model_bytes();
        let cache_limit = alice_model.max(bob_model);
        let eviction_budget = PlaintextBudget::new(alice_model + bob_cold).unwrap();
        let eviction_backend = backend_with_cache_limits(
            &eviction_root,
            eviction_budget.clone(),
            ModelCacheLimits::new(1, u64::try_from(cache_limit).unwrap()).unwrap(),
            std::iter::empty::<Vec<u8>>(),
        );
        let eviction_scope = allocation_probe::Scope::start();
        drop(eviction_backend.authenticate(&alice).unwrap());
        eviction_scope.checkpoint();
        let bob_lease = eviction_backend.authenticate(&bob).unwrap();
        let eviction_metrics = eviction_scope.snapshot();
        assert_incremental_plaintext_peak(eviction_metrics, alice_model, bob_cold, bob_cold);
        assert_eq!(eviction_backend.cached_generation_for_test(&alice), None);
        assert_eq!(eviction_backend.cached_generation_for_test(&bob), Some(1));
        assert_eq!(eviction_metrics.current_plaintext_bytes, bob_model);
        drop(bob_lease);
        eviction_backend.cache.invalidate(&bob);
        drop(eviction_backend);
        finish_clean_allocation_probe(eviction_scope);
        assert_eq!(eviction_budget.used(), 0);

        let lease_budget = PlaintextBudget::new(alice_model + bob_cold).unwrap();
        let lease_backend = backend_with_cache_limits(
            &eviction_root,
            lease_budget.clone(),
            ModelCacheLimits::new(1, u64::try_from(cache_limit).unwrap()).unwrap(),
            std::iter::empty::<Vec<u8>>(),
        );
        let lease_scope = allocation_probe::Scope::start();
        let alice_lease = lease_backend.authenticate(&alice).unwrap();
        lease_scope.checkpoint();
        let bob_lease = lease_backend.authenticate(&bob).unwrap();
        let lease_metrics = lease_scope.snapshot();
        assert_incremental_plaintext_peak(lease_metrics, alice_model, bob_cold, bob_cold);
        assert_eq!(
            lease_metrics.current_plaintext_bytes,
            alice_model + bob_model
        );
        drop(bob_lease);
        lease_backend.cache.invalidate(&bob);
        assert_eq!(lease_scope.snapshot().current_plaintext_bytes, alice_model);
        drop(alice_lease);
        assert_eq!(lease_scope.snapshot().current_plaintext_bytes, 0);
        drop(lease_backend);
        finish_clean_allocation_probe(lease_scope);
        assert_eq!(lease_budget.used(), 0);
    }

    #[test]
    fn exact_shape_admission_transfers_one_permit_and_rejects_same_user_hoarding() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let probe = backend(&root);
        let alice = username("alice");
        let inspected = probe.inspect_record(&alice).unwrap().unwrap();
        let estimate = PlaintextAllocationEstimate::for_append_shape(
            Some(&inspected.header),
            1,
            "second".len(),
        )
        .unwrap();
        drop(probe);

        let input_bytes = 4_096;
        let exact_limit = estimate.mutation_peak_bytes() + input_bytes;
        let budget = PlaintextBudget::new(exact_limit).unwrap();
        let backend = backend_with(
            &root,
            0x11,
            model(),
            1,
            budget.clone(),
            [vec![7; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        let shape = AppendAdmissionShape::new(1, "second".len()).unwrap();
        let admission = backend
            .admit_enrollment(&alice, input_bytes, shape)
            .unwrap();
        assert_eq!(budget.used(), exact_limit);
        assert_eq!(
            backend
                .admit_enrollment(&alice, input_bytes, shape)
                .unwrap_err(),
            StorageBackendError::Unavailable
        );
        assert_eq!(budget.used(), exact_limit);

        let (operation, input) = admission.into_parts();
        let result = backend
            .append_admitted(
                AppendRequest::new(&alice, 1, &[entry(2, "second")]).unwrap(),
                operation,
            )
            .unwrap();
        assert_eq!(result.generation(), 2);
        assert!(budget.used() <= exact_limit);
        drop(input);
        drop(backend.admissions.try_acquire(&alice).unwrap());

        let constrained_root = TempRoot::new();
        bootstrap_record(&constrained_root);
        let constrained_budget = PlaintextBudget::new(exact_limit - 1).unwrap();
        let constrained = backend_with(
            &constrained_root,
            0x11,
            model(),
            1,
            constrained_budget.clone(),
            [vec![8; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        assert!(matches!(
            constrained.admit_enrollment(&alice, input_bytes, shape),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(constrained_budget.used(), 0);
    }

    #[test]
    fn crud_cas_reload_and_external_edit_coherence_match_mode0() {
        let root = TempRoot::new();
        let main_backend = backend(&root);
        let alice = username("alice");
        let first = entry(1, "one");
        assert_eq!(
            main_backend
                .append(AppendRequest::new(&alice, 0, std::slice::from_ref(&first)).unwrap())
                .unwrap(),
            AppendResult::new(1, 1, 1)
        );
        assert_eq!(
            main_backend
                .append(AppendRequest::new(&alice, 0, &[entry(2, "stale")]).unwrap())
                .unwrap_err(),
            StorageBackendError::Conflict {
                current_generation: 1
            }
        );
        let listed = main_backend.list_metadata(&alice).unwrap();
        assert_eq!(listed.generation(), 1);
        assert_eq!(listed.entries()[0].label(), "one");
        assert_eq!(
            main_backend
                .remove(RemoveRequest::new(&alice, 1, first.enrollment_id()).unwrap())
                .unwrap(),
            RemoveResult::new(2, first.enrollment_id())
        );
        assert_eq!(
            main_backend.candidate_presence(&alice).unwrap(),
            CandidatePresence::Absent
        );
        main_backend
            .append(AppendRequest::new(&alice, 2, &[entry(3, "three")]).unwrap())
            .unwrap();
        assert_eq!(
            main_backend
                .clear(ClearRequest::new(&alice, 3).unwrap())
                .unwrap(),
            ClearResult::new(1)
        );
        assert!(!root.record("alice").exists());

        main_backend
            .append(AppendRequest::new(&alice, 0, &[entry(4, "cached")]).unwrap())
            .unwrap();
        assert_eq!(main_backend.authenticate(&alice).unwrap().generation(), 1);
        let external = backend(&root);
        external
            .append(AppendRequest::new(&alice, 1, &[entry(5, "external")]).unwrap())
            .unwrap();
        drop(external);
        assert_eq!(
            main_backend
                .authenticate(&alice)
                .unwrap()
                .labels()
                .collect::<Vec<_>>(),
            ["cached"]
        );
        let reload = main_backend.reload().unwrap();
        assert_eq!(
            reload.records()[0].classification(),
            OuterRecordClassification::Candidate { generation: 2 }
        );
        assert_eq!(
            main_backend
                .authenticate(&alice)
                .unwrap()
                .labels()
                .collect::<Vec<_>>(),
            ["cached", "external"]
        );
    }

    #[test]
    fn cancellation_and_budget_pressure_publish_nothing_and_release_once() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        for cancel_at in 1..=14 {
            let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                budget.clone(),
                std::iter::empty::<Vec<u8>>(),
                Arc::new(CountingHooks::default()),
                None,
            );
            let alice = username("alice");
            let cancellation = CancelAfterCalls {
                calls: AtomicUsize::new(0),
                cancel_at,
            };
            let result = backend.authenticate_active(&alice, &cancellation);
            drop(result);
            assert_eq!(backend.cached_generation_for_test(&alice), None);
            assert_eq!(budget.used(), 0, "cancel_at={cancel_at}");
        }

        let probe = backend(&root);
        let required = {
            let inspected = probe.inspect_record(&username("alice")).unwrap().unwrap();
            PlaintextAllocationEstimate::for_encrypted_header(&inspected.header)
                .unwrap()
                .cold_load_peak_bytes()
        };
        drop(probe);
        let too_small = PlaintextBudget::new(required - 1).unwrap();
        let constrained = backend_with(
            &root,
            0x11,
            model(),
            1,
            too_small.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        assert!(matches!(
            constrained.authenticate(&username("alice")),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(too_small.used(), 0);

        let exact_budget = PlaintextBudget::new(required).unwrap();
        let exact = backend_with(
            &root,
            0x11,
            model(),
            1,
            exact_budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::new(CountingHooks::default()),
            None,
        );
        let mut provisional = exact
            .authenticate_active(&username("alice"), &NeverCancelled)
            .unwrap();
        assert!(provisional.has_provisional_promotion());
        assert_eq!(exact_budget.used(), provisional.plaintext_bytes());
        drop(provisional.take_promotion());
        drop(provisional);
        assert_eq!(exact_budget.used(), 0);
    }

    #[test]
    fn exact_replacement_capacity_admits_remove_and_one_byte_less_rejects() {
        fn seeded_root() -> TempRoot {
            let root = TempRoot::new();
            let backend = backend_with(
                &root,
                0x11,
                model(),
                1,
                PlaintextBudget::new(4 * 1024 * 1024).unwrap(),
                [vec![1; 12]],
                Arc::new(CountingHooks::default()),
                None,
            );
            let alice = username("alice");
            backend
                .append(
                    AppendRequest::new(&alice, 0, &[entry(1, "one"), entry(2, "second")]).unwrap(),
                )
                .unwrap();
            root
        }

        let root = seeded_root();
        let probe = backend(&root);
        let alice = username("alice");
        let inspected = probe.inspect_record(&alice).unwrap().unwrap();
        let required =
            PlaintextAllocationEstimate::for_replacement_of_encrypted_header(&inspected.header)
                .unwrap()
                .mutation_peak_bytes();
        drop(probe);

        let budget = PlaintextBudget::new(required).unwrap();
        let exact = backend_with(
            &root,
            0x11,
            model(),
            1,
            budget.clone(),
            [vec![2; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        let removed = exact
            .remove(RemoveRequest::new(&alice, 1, EnrollmentId::new([1; 16]).unwrap()).unwrap())
            .unwrap();
        assert_eq!(removed.generation(), 2);
        assert!(budget.used() < required);

        let too_small_root = seeded_root();
        let too_small_budget = PlaintextBudget::new(required - 1).unwrap();
        let constrained = backend_with(
            &too_small_root,
            0x11,
            model(),
            1,
            too_small_budget.clone(),
            [vec![3; 12]],
            Arc::new(CountingHooks::default()),
            None,
        );
        assert!(matches!(
            constrained.remove(
                RemoveRequest::new(&alice, 1, EnrollmentId::new([1; 16]).unwrap()).unwrap()
            ),
            Err(StorageBackendError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(too_small_budget.used(), 0);
    }

    #[test]
    fn reload_barrier_and_same_user_cold_readers_are_deadlock_free() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let backend = Arc::new(backend(&root));
        let alice = username("alice");
        let reload = backend.reload_gate.write().unwrap();
        let worker_backend = Arc::clone(&backend);
        let worker_alice = alice.clone();
        let (sent, received) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            sent.send(
                worker_backend
                    .authenticate(&worker_alice)
                    .unwrap()
                    .generation(),
            )
            .unwrap();
        });
        assert!(matches!(
            received.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(reload);
        assert_eq!(received.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        worker.join().unwrap();

        backend.cache.clear();
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);
            let alice = alice.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                backend.authenticate(&alice).unwrap().generation()
            }));
        }
        barrier.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), 1);
        }
    }

    #[test]
    fn panic_during_cold_path_releases_budget_and_does_not_publish() {
        let root = TempRoot::new();
        bootstrap_record(&root);
        let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
        let hooks = Arc::new(CountingHooks::default());
        let backend = backend_with(
            &root,
            0x11,
            model(),
            1,
            budget.clone(),
            std::iter::empty::<Vec<u8>>(),
            Arc::clone(&hooks),
            None,
        );
        hooks.clear();
        hooks.panic_on_sensitive_call.store(true, Ordering::SeqCst);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = backend.authenticate(&username("alice"));
        }));
        assert!(outcome.is_err());
        assert_eq!(backend.cached_generation_for_test(&username("alice")), None);
        assert_eq!(budget.used(), 0);
    }
}
