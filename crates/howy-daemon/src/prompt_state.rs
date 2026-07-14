//! Bounded daemon-lifetime state for prompt confirmation transactions.

use std::collections::HashMap;
use std::fmt;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use howy_common::config::{HowyConfig, PresenceMode};
use howy_common::protocol::{PROMPT_NONCE_BYTES, PROMPT_TOKEN_BYTES, PromptOriginV1};
use howy_common::storage::CancellationSignal;
use howy_common::storage::{OsRandomSource, PromptStorageSnapshot, RandomSource};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authorization::CanonicalIdentity;

const ENTROPY_ATTEMPTS: usize = 16;
const SECRET_BYTES: usize = 32;
type BindingDigest = [u8; 32];

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConnectionId(u64);

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionId([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptStateError {
    Unavailable,
    Invalid,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecuritySnapshot {
    policy_generation: [u8; 32],
    storage: PromptStorageSnapshot,
}

impl SecuritySnapshot {
    pub fn capture(config: &HowyConfig, storage: PromptStorageSnapshot) -> Self {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, b"howy-prompt-policy-v2");
        hash_field(
            &mut hasher,
            &[match config.presence.mode {
                PresenceMode::Off => 0,
                PresenceMode::Confirm => 1,
            }],
        );
        hash_field(&mut hasher, &[u8::from(config.presence.local_only)]);
        hash_u64(&mut hasher, config.presence.prompt_timeout_ms);
        hash_u64(&mut hasher, config.presence.commit_to_camera_ms);
        hash_u64(&mut hasher, config.presence.scan_timeout_ms);
        hash_u64(&mut hasher, u64::from(config.presence.max_pending_per_uid));
        hash_u64(&mut hasher, u64::from(config.presence.max_pending_global));
        hash_u64(
            &mut hasher,
            u64::try_from(config.presence.allowed_pam_services.len()).unwrap_or(u64::MAX),
        );
        for service in &config.presence.allowed_pam_services {
            hash_field(&mut hasher, service.as_bytes());
        }
        hash_field(&mut hasher, &[config.security.embedding_mode as u8]);
        hash_u64(&mut hasher, config.security.key_epoch);
        hash_u64(
            &mut hasher,
            u64::from(config.security.max_embeddings_per_user),
        );
        hash_u64(&mut hasher, config.security.max_record_bytes);
        hash_u64(&mut hasher, config.security.max_plaintext_bytes);
        hash_field(
            &mut hasher,
            config.security.cached.credential_name.as_bytes(),
        );
        hash_u64(
            &mut hasher,
            u64::from(config.security.cached.max_cached_users),
        );
        hash_u64(&mut hasher, config.security.cached.max_cache_bytes);
        hash_field(
            &mut hasher,
            &[u8::from(config.security.cached.require_mlock)],
        );
        hash_field(
            &mut hasher,
            config.security.ephemeral.sealed_key_blob.as_bytes(),
        );
        hash_field(
            &mut hasher,
            config.security.ephemeral.key_description.as_bytes(),
        );
        hash_field(
            &mut hasher,
            config.security.ephemeral.tpm_parent_handle.as_bytes(),
        );
        Self {
            policy_generation: hasher.finalize().into(),
            storage,
        }
    }

    pub const fn storage(&self) -> PromptStorageSnapshot {
        self.storage
    }

    fn constant_time_eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.policy_generation, &other.policy_generation)
            && self.storage.health() == other.storage.health()
            && self.storage.candidate() == other.storage.candidate()
            && constant_time_eq(
                &self.storage.backend_identity().into_bytes(),
                &other.storage.backend_identity().into_bytes(),
            )
            && constant_time_eq(
                &self.storage.policy_generation().into_bytes(),
                &other.storage.policy_generation().into_bytes(),
            )
    }
}

impl fmt::Debug for SecuritySnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecuritySnapshot")
            .field("policy_generation", &"[REDACTED]")
            .field("storage", &self.storage)
            .finish()
    }
}

pub struct PendingBinding {
    pub connection: ConnectionId,
    pub peer_uid: u32,
    pub target: CanonicalIdentity,
    pub client_nonce: Zeroizing<[u8; PROMPT_NONCE_BYTES]>,
    pub pam_service: String,
    pub origin: PromptOriginV1,
    pub snapshot: SecuritySnapshot,
}

impl fmt::Debug for PendingBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingBinding")
            .field("connection", &self.connection)
            .field("peer_uid", &self.peer_uid)
            .field("target", &self.target)
            .field("client_nonce", &"[REDACTED]")
            .field("pam_service", &self.pam_service)
            .field("origin", &self.origin)
            .field("snapshot", &self.snapshot)
            .finish()
    }
}

pub struct CommitBinding {
    pub connection: ConnectionId,
    pub peer_uid: u32,
    pub target: CanonicalIdentity,
    pub pam_service: String,
    pub origin: PromptOriginV1,
    pub snapshot: SecuritySnapshot,
}

trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Default)]
struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait Entropy: Send {
    fn fill(&mut self, destination: &mut [u8]) -> std::result::Result<(), ()>;
}

#[derive(Default)]
struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> std::result::Result<(), ()> {
        OsRandomSource.fill_bytes(destination).map_err(|_| ())
    }
}

#[cfg(test)]
struct DeterministicEntropy(u8);

#[cfg(test)]
impl Entropy for DeterministicEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> std::result::Result<(), ()> {
        self.0 = self.0.wrapping_add(1).max(1);
        destination.fill(self.0);
        Ok(())
    }
}

struct ProvisionalRecord {
    peer_uid: u32,
    target: CanonicalIdentity,
}

struct PendingRecord {
    connection_binding: BindingDigest,
    peer_uid: u32,
    target: CanonicalIdentity,
    nonce_binding: BindingDigest,
    pam_service: String,
    origin: PromptOriginV1,
    snapshot: SecuritySnapshot,
    expires_at: Option<Instant>,
    shutdown_waker: Option<UnixStream>,
}

enum ActiveRecord {
    Claim {
        control: Arc<ActiveControl>,
        token_lookup: BindingDigest,
    },
    Active {
        control: Arc<ActiveControl>,
        token_lookup: BindingDigest,
    },
}

struct ManagerState {
    entropy: Box<dyn Entropy>,
    instance_secret: Zeroizing<[u8; SECRET_BYTES]>,
    next_connection: u64,
    issuance_counter: u64,
    next_active: u64,
    provisional: HashMap<BindingDigest, ProvisionalRecord>,
    pending: HashMap<BindingDigest, PendingRecord>,
    pending_by_connection: HashMap<BindingDigest, BindingDigest>,
    active: HashMap<u64, ActiveRecord>,
    terminal: bool,
}

struct ManagerInner {
    state: Mutex<ManagerState>,
    changed: Condvar,
    clock: Arc<dyn Clock>,
    prompt_timeout: Duration,
    active_timeout: Duration,
    commit_to_camera_timeout: Duration,
    max_pending_per_uid: usize,
    max_pending_global: usize,
    max_active: usize,
}

#[derive(Clone)]
pub struct PromptTransactionManager {
    inner: Arc<ManagerInner>,
}

impl fmt::Debug for PromptTransactionManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptTransactionManager([REDACTED])")
    }
}

impl PromptTransactionManager {
    pub fn production(
        config: &HowyConfig,
        active_timeout: Duration,
        max_active: usize,
    ) -> Result<Self> {
        Self::new(
            Box::<OsEntropy>::default(),
            Arc::<MonotonicClock>::default(),
            Duration::from_millis(config.presence.prompt_timeout_ms),
            active_timeout,
            Duration::from_millis(config.presence.commit_to_camera_ms),
            usize::try_from(config.presence.max_pending_per_uid)
                .context("prompt per-UID limit does not fit this platform")?,
            usize::try_from(config.presence.max_pending_global)
                .context("prompt global limit does not fit this platform")?,
            max_active,
            0,
        )
        .context("failed to initialize prompt transaction manager")
    }

    #[cfg(test)]
    pub(crate) fn deterministic_for_test(
        config: &HowyConfig,
        active_timeout: Duration,
        max_active: usize,
    ) -> Self {
        Self::new(
            Box::new(DeterministicEntropy(0)),
            Arc::<MonotonicClock>::default(),
            Duration::from_millis(config.presence.prompt_timeout_ms),
            active_timeout,
            Duration::from_millis(config.presence.commit_to_camera_ms),
            usize::try_from(config.presence.max_pending_per_uid).unwrap(),
            usize::try_from(config.presence.max_pending_global).unwrap(),
            max_active,
            0,
        )
        .unwrap()
    }

    fn new(
        mut entropy: Box<dyn Entropy>,
        clock: Arc<dyn Clock>,
        prompt_timeout: Duration,
        active_timeout: Duration,
        commit_to_camera_timeout: Duration,
        max_pending_per_uid: usize,
        max_pending_global: usize,
        max_active: usize,
        issuance_counter: u64,
    ) -> Result<Self> {
        if prompt_timeout.is_zero()
            || active_timeout.is_zero()
            || commit_to_camera_timeout.is_zero()
            || max_pending_per_uid == 0
            || max_pending_global < max_pending_per_uid
            || max_active == 0
        {
            bail!("invalid prompt transaction manager limits");
        }
        let instance_secret = Zeroizing::new(generate_nonzero(&mut *entropy)?);
        Ok(Self {
            inner: Arc::new(ManagerInner {
                state: Mutex::new(ManagerState {
                    entropy,
                    instance_secret,
                    next_connection: 1,
                    issuance_counter,
                    next_active: 1,
                    provisional: HashMap::new(),
                    pending: HashMap::new(),
                    pending_by_connection: HashMap::new(),
                    active: HashMap::new(),
                    terminal: false,
                }),
                changed: Condvar::new(),
                clock,
                prompt_timeout,
                active_timeout,
                commit_to_camera_timeout,
                max_pending_per_uid,
                max_pending_global,
                max_active,
            }),
        })
    }

    pub fn new_connection(&self) -> std::result::Result<ConnectionId, PromptStateError> {
        let mut state = self.lock_state()?;
        let value = state.next_connection;
        state.next_connection = value.checked_add(1).ok_or(PromptStateError::Unavailable)?;
        Ok(ConnectionId(value))
    }

    pub fn reserve_begin(
        &self,
        connection: ConnectionId,
        peer_uid: u32,
        target: CanonicalIdentity,
    ) -> std::result::Result<BeginReservation, PromptStateError> {
        let mut state = self.lock_state()?;
        let connection_binding = connection_binding(&state.instance_secret, connection);
        if state.provisional.contains_key(&connection_binding)
            || state
                .pending_by_connection
                .contains_key(&connection_binding)
            || pending_total(&state) >= self.inner.max_pending_global
            || pending_for_uid(&state, peer_uid) >= self.inner.max_pending_per_uid
        {
            return Err(PromptStateError::Unavailable);
        }
        state
            .provisional
            .insert(connection_binding, ProvisionalRecord { peer_uid, target });
        Ok(BeginReservation {
            manager: self.clone(),
            connection_binding,
            armed: true,
        })
    }

    fn issue_reserved(
        &self,
        reserved_connection: BindingDigest,
        mut binding: PendingBinding,
    ) -> std::result::Result<PendingIssue, PromptStateError> {
        let mut state = self.lock_state()?;
        let expected_connection = connection_binding(&state.instance_secret, binding.connection);
        if !constant_time_eq(&reserved_connection, &expected_connection) {
            remove_provisional(&mut state, reserved_connection);
            return Err(PromptStateError::Invalid);
        }
        let Some(provisional) = state.provisional.remove(&reserved_connection) else {
            return Err(PromptStateError::Invalid);
        };
        if provisional.peer_uid != binding.peer_uid || provisional.target != binding.target {
            return Err(PromptStateError::Invalid);
        }
        let (token, lookup) = generate_token(&mut state)?;
        let nonce_binding = keyed_digest(
            &state.instance_secret,
            b"nonce-v2",
            &binding.client_nonce[..],
        );
        state.pending.insert(
            lookup,
            PendingRecord {
                connection_binding: reserved_connection,
                peer_uid: binding.peer_uid,
                target: provisional.target,
                nonce_binding,
                pam_service: std::mem::take(&mut binding.pam_service),
                origin: binding.origin,
                snapshot: binding.snapshot.clone(),
                expires_at: None,
                shutdown_waker: None,
            },
        );
        state
            .pending_by_connection
            .insert(reserved_connection, lookup);
        Ok(PendingIssue {
            manager: self.clone(),
            connection_binding: reserved_connection,
            lookup: Some(lookup),
            token,
        })
    }

    fn activate_pending(
        &self,
        connection_binding: BindingDigest,
        lookup: BindingDigest,
        shutdown_waker: Option<UnixStream>,
    ) -> std::result::Result<Instant, PromptStateError> {
        let now = self.inner.clock.now();
        let deadline = now
            .checked_add(self.inner.prompt_timeout)
            .ok_or(PromptStateError::Unavailable)?;
        let mut state = self.lock_state()?;
        if state.pending_by_connection.get(&connection_binding) != Some(&lookup) {
            remove_pending(&mut state, connection_binding, lookup);
            return Err(PromptStateError::Invalid);
        }
        let Some(record) = state.pending.get_mut(&lookup) else {
            state.pending_by_connection.remove(&connection_binding);
            return Err(PromptStateError::Invalid);
        };
        if record.expires_at.replace(deadline).is_some() {
            return Err(PromptStateError::Invalid);
        }
        record.shutdown_waker = shutdown_waker;
        self.inner.changed.notify_all();
        Ok(deadline)
    }

    fn claim_commit(
        &self,
        connection_binding: BindingDigest,
        expected_lookup: BindingDigest,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
    ) -> std::result::Result<CommitClaim, PromptStateError> {
        self.claim_commit_after_before_lock(
            connection_binding,
            expected_lookup,
            token,
            nonce,
            peer_uid,
            target_uid,
            || {},
        )
    }

    fn claim_commit_after_before_lock(
        &self,
        connection_binding: BindingDigest,
        expected_lookup: BindingDigest,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
        before_lock: impl FnOnce(),
    ) -> std::result::Result<CommitClaim, PromptStateError> {
        before_lock();
        let mut state = self.lock_state()?;
        let supplied_lookup = keyed_digest(&state.instance_secret, b"token-lookup-v2", token);
        let own_lookup = state
            .pending_by_connection
            .get(&connection_binding)
            .copied();
        if own_lookup != Some(expected_lookup)
            || !constant_time_eq(&supplied_lookup, &expected_lookup)
        {
            if let Some(own_lookup) = own_lookup {
                remove_pending(&mut state, connection_binding, own_lookup);
            }
            return Err(PromptStateError::Invalid);
        }
        let Some(record) = remove_pending(&mut state, connection_binding, expected_lookup) else {
            return Err(PromptStateError::Invalid);
        };
        let nonce_binding = keyed_digest(&state.instance_secret, b"nonce-v2", nonce);
        // Sample only while holding the state mutex, immediately before the
        // pending deadline participates in authorization.
        let now = self.inner.clock.now();
        if record.connection_binding != connection_binding
            || record.peer_uid != peer_uid
            || record.target.uid() != target_uid
            || !constant_time_eq(&record.nonce_binding, &nonce_binding)
            || !record.expires_at.is_some_and(|expiry| now < expiry)
        {
            return Err(PromptStateError::Invalid);
        }
        if state.active.len() >= self.inner.max_active {
            return Err(PromptStateError::Unavailable);
        }
        let active_id = state.next_active;
        state.next_active = active_id
            .checked_add(1)
            .ok_or(PromptStateError::Unavailable)?;
        let deadline = now
            .checked_add(self.inner.active_timeout)
            .ok_or(PromptStateError::Unavailable)?;
        let camera_ready_deadline = now
            .checked_add(self.inner.commit_to_camera_timeout)
            .ok_or(PromptStateError::Unavailable)?
            .min(deadline);
        let control = Arc::new(ActiveControl::new(deadline, camera_ready_deadline));
        state.active.insert(
            active_id,
            ActiveRecord::Claim {
                control: Arc::clone(&control),
                token_lookup: expected_lookup,
            },
        );
        Ok(CommitClaim {
            manager: self.clone(),
            active_id: Some(active_id),
            control,
            peer_uid: record.peer_uid,
            target: record.target,
            pam_service: record.pam_service,
            origin: record.origin,
            snapshot: record.snapshot,
        })
    }

    fn promote_claim(
        &self,
        active_id: u64,
        expected: &CommitClaim,
        binding: &CommitBinding,
    ) -> std::result::Result<(), PromptStateError> {
        let mut state = self.lock_state()?;
        let now = self.inner.clock.now();
        let live_claim = matches!(
            state.active.get(&active_id),
            Some(ActiveRecord::Claim { control, .. })
                if !control.cancelled.load(Ordering::Acquire) && now < control.deadline
        );
        let valid = live_claim
            && expected.peer_uid == binding.peer_uid
            && expected.target == binding.target
            && expected.pam_service == binding.pam_service
            && expected.origin == binding.origin
            && expected.snapshot.constant_time_eq(&binding.snapshot);
        if !valid {
            if let Some(record) = state.active.remove(&active_id) {
                record.control().cancel();
            }
            return Err(PromptStateError::Invalid);
        }
        let Some(record) = state.active.get_mut(&active_id) else {
            return Err(PromptStateError::Invalid);
        };
        match record {
            ActiveRecord::Claim {
                control,
                token_lookup,
            } => {
                *record = ActiveRecord::Active {
                    control: Arc::clone(control),
                    token_lookup: *token_lookup,
                };
                Ok(())
            }
            ActiveRecord::Active { .. } => Err(PromptStateError::Invalid),
        }
    }

    fn cancel_pending(
        &self,
        connection_binding: BindingDigest,
        expected_lookup: BindingDigest,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
    ) -> std::result::Result<(), PromptStateError> {
        self.cancel_pending_after_before_lock(
            connection_binding,
            expected_lookup,
            token,
            nonce,
            peer_uid,
            target_uid,
            || {},
        )
    }

    fn cancel_pending_after_before_lock(
        &self,
        connection_binding: BindingDigest,
        expected_lookup: BindingDigest,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
        before_lock: impl FnOnce(),
    ) -> std::result::Result<(), PromptStateError> {
        before_lock();
        let mut state = self.lock_state()?;
        let supplied_lookup = keyed_digest(&state.instance_secret, b"token-lookup-v2", token);
        let own_lookup = state
            .pending_by_connection
            .get(&connection_binding)
            .copied();
        if own_lookup != Some(expected_lookup)
            || !constant_time_eq(&supplied_lookup, &expected_lookup)
        {
            if let Some(own_lookup) = own_lookup {
                remove_pending(&mut state, connection_binding, own_lookup);
            }
            return Err(PromptStateError::Invalid);
        }
        let Some(record) = remove_pending(&mut state, connection_binding, expected_lookup) else {
            return Err(PromptStateError::Invalid);
        };
        let nonce_binding = keyed_digest(&state.instance_secret, b"nonce-v2", nonce);
        // As with Commit, mutex wait time is part of expiry and cannot be
        // hidden by a pre-lock clock sample.
        let now = self.inner.clock.now();
        if record.peer_uid == peer_uid
            && record.target.uid() == target_uid
            && constant_time_eq(&record.nonce_binding, &nonce_binding)
            && record.expires_at.is_some_and(|expiry| now < expiry)
        {
            Ok(())
        } else {
            Err(PromptStateError::Invalid)
        }
    }

    fn release_provisional(&self, connection_binding: BindingDigest) {
        if let Ok(mut state) = self.lock_state() {
            remove_provisional(&mut state, connection_binding);
        }
    }

    fn release_pending(&self, connection_binding: BindingDigest, lookup: BindingDigest) {
        if let Ok(mut state) = self.lock_state() {
            remove_pending(&mut state, connection_binding, lookup);
        }
    }

    fn release_active(&self, active_id: u64) {
        if let Ok(mut state) = self.lock_state() {
            state.active.remove(&active_id);
        }
    }

    pub fn shutdown(&self) {
        let cleanup = match self.inner.state.lock() {
            Ok(mut state) => fail_closed_locked(&mut state),
            Err(poisoned) => fail_closed_locked(&mut poisoned.into_inner()),
        };
        self.inner.changed.notify_all();
        run_cleanup(cleanup);
    }

    pub fn is_terminated(&self) -> bool {
        self.lock_state().is_err()
    }

    fn lock_state(&self) -> std::result::Result<MutexGuard<'_, ManagerState>, PromptStateError> {
        match self.inner.state.lock() {
            Ok(state) if !state.terminal => Ok(state),
            Ok(_) => Err(PromptStateError::Unavailable),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                let cleanup = fail_closed_locked(&mut state);
                drop(state);
                self.inner.changed.notify_all();
                run_cleanup(cleanup);
                Err(PromptStateError::Unavailable)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        match self.lock_state() {
            Ok(state) => (
                state.provisional.len(),
                state.pending.len(),
                state.active.len(),
            ),
            Err(_) => (0, 0, 0),
        }
    }

    #[cfg(test)]
    pub(crate) fn activated_pending_count(&self) -> usize {
        self.lock_state().map_or(0, |state| {
            state
                .pending
                .values()
                .filter(|record| record.expires_at.is_some() && record.shutdown_waker.is_some())
                .count()
        })
    }

    #[cfg(test)]
    pub(crate) fn next_connection_for_test(&self) -> u64 {
        self.lock_state().unwrap().next_connection
    }

    #[cfg(test)]
    fn poison_for_test(&self) {
        let inner = Arc::clone(&self.inner);
        let _ = std::thread::spawn(move || {
            let _guard = inner.state.lock().unwrap();
            panic!("inject prompt manager poison");
        })
        .join();
    }

    #[cfg(test)]
    fn connection_binding_for_test(&self, connection: ConnectionId) -> BindingDigest {
        let state = self.lock_state().unwrap();
        connection_binding(&state.instance_secret, connection)
    }

    #[cfg(test)]
    pub(crate) fn expire_pending_for_test(&self) {
        let mut state = self.lock_state().unwrap();
        let expired = self.inner.clock.now() - Duration::from_nanos(1);
        for pending in state.pending.values_mut() {
            pending.expires_at = Some(expired);
        }
    }
}

impl ActiveRecord {
    fn control(&self) -> &Arc<ActiveControl> {
        match self {
            Self::Claim { control, .. } | Self::Active { control, .. } => control,
        }
    }

    fn token_lookup(&self) -> &BindingDigest {
        match self {
            Self::Claim { token_lookup, .. } | Self::Active { token_lookup, .. } => token_lookup,
        }
    }
}

pub struct BeginReservation {
    manager: PromptTransactionManager,
    connection_binding: BindingDigest,
    armed: bool,
}

impl fmt::Debug for BeginReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BeginReservation([REDACTED])")
    }
}

impl BeginReservation {
    pub fn issue(
        mut self,
        binding: PendingBinding,
    ) -> std::result::Result<PendingIssue, PromptStateError> {
        self.armed = false;
        self.manager
            .issue_reserved(self.connection_binding, binding)
    }
}

impl Drop for BeginReservation {
    fn drop(&mut self) {
        if self.armed {
            self.manager.release_provisional(self.connection_binding);
            self.armed = false;
        }
    }
}

pub struct PendingIssue {
    manager: PromptTransactionManager,
    connection_binding: BindingDigest,
    lookup: Option<BindingDigest>,
    token: Zeroizing<[u8; PROMPT_TOKEN_BYTES]>,
}

impl fmt::Debug for PendingIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingIssue([REDACTED])")
    }
}

impl PendingIssue {
    pub fn token(&self) -> &[u8; PROMPT_TOKEN_BYTES] {
        &self.token
    }

    pub fn activate(&mut self) -> std::result::Result<Instant, PromptStateError> {
        self.activate_with_waker(None)
    }

    pub fn activate_with_waker(
        &mut self,
        shutdown_waker: Option<UnixStream>,
    ) -> std::result::Result<Instant, PromptStateError> {
        let lookup = self.lookup.ok_or(PromptStateError::Invalid)?;
        self.manager
            .activate_pending(self.connection_binding, lookup, shutdown_waker)
    }

    pub fn claim_commit(
        mut self,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
    ) -> std::result::Result<CommitClaim, PromptStateError> {
        let lookup = self.lookup.take().ok_or(PromptStateError::Invalid)?;
        self.manager.claim_commit(
            self.connection_binding,
            lookup,
            token,
            nonce,
            peer_uid,
            target_uid,
        )
    }

    pub fn cancel(
        mut self,
        token: &[u8; PROMPT_TOKEN_BYTES],
        nonce: &[u8; PROMPT_NONCE_BYTES],
        peer_uid: u32,
        target_uid: u32,
    ) -> std::result::Result<(), PromptStateError> {
        let lookup = self.lookup.take().ok_or(PromptStateError::Invalid)?;
        self.manager.cancel_pending(
            self.connection_binding,
            lookup,
            token,
            nonce,
            peer_uid,
            target_uid,
        )
    }

    pub fn manager_terminated(&self) -> bool {
        self.manager.is_terminated()
    }
}

impl Drop for PendingIssue {
    fn drop(&mut self) {
        if let Some(lookup) = self.lookup.take() {
            self.manager
                .release_pending(self.connection_binding, lookup);
        }
    }
}

pub struct CommitClaim {
    manager: PromptTransactionManager,
    active_id: Option<u64>,
    control: Arc<ActiveControl>,
    peer_uid: u32,
    target: CanonicalIdentity,
    pam_service: String,
    origin: PromptOriginV1,
    snapshot: SecuritySnapshot,
}

impl fmt::Debug for CommitClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommitClaim([REDACTED])")
    }
}

impl CommitClaim {
    pub fn promote(
        mut self,
        binding: CommitBinding,
    ) -> std::result::Result<ActiveLease, PromptStateError> {
        let active_id = self.active_id.ok_or(PromptStateError::Invalid)?;
        self.manager.promote_claim(active_id, &self, &binding)?;
        self.active_id = None;
        Ok(ActiveLease {
            manager: self.manager.clone(),
            active_id: Some(active_id),
            control: Arc::clone(&self.control),
        })
    }

    pub fn target(&self) -> &CanonicalIdentity {
        &self.target
    }

    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    pub fn pam_service(&self) -> &str {
        &self.pam_service
    }

    pub fn origin(&self) -> PromptOriginV1 {
        self.origin
    }

    pub fn cancellation(&self) -> ActiveCancellation {
        ActiveCancellation {
            control: Arc::clone(&self.control),
        }
    }

    pub fn deadline(&self) -> Instant {
        self.control.deadline
    }

    pub fn camera_ready_deadline(&self) -> Instant {
        self.control.camera_ready_deadline
    }
}

impl Drop for CommitClaim {
    fn drop(&mut self) {
        if let Some(active_id) = self.active_id.take() {
            self.control.cancel();
            self.manager.release_active(active_id);
        }
    }
}

struct ActiveControl {
    cancelled: AtomicBool,
    deadline: Instant,
    camera_ready_deadline: Instant,
    wake: (Mutex<()>, Condvar),
    resources: Mutex<Vec<Arc<dyn ActiveResourceCancellation>>>,
}

/// Direct cancellation endpoint for resource-owning workers. Registration is
/// atomic with active cancellation: a resource registered after cancellation
/// has begun is signalled before registration returns.
pub trait ActiveResourceCancellation: Send + Sync {
    fn cancel_resource(&self);
}

impl ActiveControl {
    fn new(deadline: Instant, camera_ready_deadline: Instant) -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            deadline,
            camera_ready_deadline,
            wake: (Mutex::new(()), Condvar::new()),
            resources: Mutex::new(Vec::new()),
        }
    }

    fn cancel(&self) -> bool {
        let (changed, resources) = {
            let resources = self
                .resources
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let changed = !self.cancelled.swap(true, Ordering::AcqRel);
            (changed, resources.clone())
        };
        for resource in resources {
            resource.cancel_resource();
        }
        if changed {
            self.wake.1.notify_all();
        }
        changed
    }

    fn register_resource(&self, resource: Arc<dyn ActiveResourceCancellation>) {
        let cancelled = {
            let mut resources = self
                .resources
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.cancelled.load(Ordering::Acquire) {
                true
            } else {
                resources.push(Arc::clone(&resource));
                false
            }
        };
        if cancelled {
            resource.cancel_resource();
        }
    }
}

pub struct ActiveLease {
    manager: PromptTransactionManager,
    active_id: Option<u64>,
    control: Arc<ActiveControl>,
}

#[derive(Clone)]
pub struct ActiveCancellation {
    control: Arc<ActiveControl>,
}

impl fmt::Debug for ActiveCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveCancellation([REDACTED])")
    }
}

impl ActiveCancellation {
    pub fn cancel(&self) -> bool {
        self.control.cancel()
    }

    pub fn is_cancelled(&self) -> bool {
        if Instant::now() >= self.control.deadline {
            self.control.cancel();
        }
        self.control.cancelled.load(Ordering::Acquire)
    }

    pub fn deadline(&self) -> Instant {
        self.control.deadline
    }

    pub fn camera_ready_deadline(&self) -> Instant {
        self.control.camera_ready_deadline
    }

    pub fn register_resource(&self, resource: Arc<dyn ActiveResourceCancellation>) {
        self.control.register_resource(resource);
    }
}

impl CancellationSignal for ActiveCancellation {
    fn is_cancelled(&self) -> bool {
        ActiveCancellation::is_cancelled(self)
    }
}

impl fmt::Debug for ActiveLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveLease([REDACTED])")
    }
}

impl ActiveLease {
    pub fn cancellation(&self) -> ActiveCancellation {
        ActiveCancellation {
            control: Arc::clone(&self.control),
        }
    }

    pub fn cancel(&self) -> bool {
        self.control.cancel()
    }

    pub fn check_deadline(&self) -> bool {
        if self.manager.inner.clock.now() >= self.control.deadline {
            self.control.cancel();
        }
        self.is_cancelled()
    }

    pub fn is_cancelled(&self) -> bool {
        self.control.cancelled.load(Ordering::Acquire)
    }

    pub fn deadline(&self) -> Instant {
        self.control.deadline
    }

    pub fn camera_ready_deadline(&self) -> Instant {
        self.control.camera_ready_deadline
    }

    pub fn wait_cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut guard = self
            .control
            .wake
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while !self.is_cancelled() {
            let remaining = self
                .control
                .deadline
                .saturating_duration_since(self.manager.inner.clock.now());
            if remaining.is_zero() {
                self.control.cancel();
                break;
            }
            let waited = self.control.wake.1.wait_timeout(guard, remaining);
            let (next, _) = waited.unwrap_or_else(|poisoned| poisoned.into_inner());
            guard = next;
        }
    }
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.control.cancel();
        if let Some(active_id) = self.active_id.take() {
            self.manager.release_active(active_id);
        }
    }
}

fn pending_total(state: &ManagerState) -> usize {
    state.provisional.len().saturating_add(state.pending.len())
}

fn pending_for_uid(state: &ManagerState, uid: u32) -> usize {
    state
        .provisional
        .values()
        .filter(|record| record.peer_uid == uid)
        .count()
        .saturating_add(
            state
                .pending
                .values()
                .filter(|record| record.peer_uid == uid)
                .count(),
        )
}

fn remove_provisional(state: &mut ManagerState, connection: BindingDigest) {
    state.provisional.remove(&connection);
}

fn remove_pending(
    state: &mut ManagerState,
    connection: BindingDigest,
    lookup: BindingDigest,
) -> Option<PendingRecord> {
    if state.pending_by_connection.get(&connection) == Some(&lookup) {
        state.pending_by_connection.remove(&connection);
    }
    state.pending.remove(&lookup)
}

struct FailClosedCleanup {
    controls: Vec<Arc<ActiveControl>>,
    shutdown_wakers: Vec<UnixStream>,
}

fn fail_closed_locked(state: &mut ManagerState) -> FailClosedCleanup {
    state.terminal = true;
    state.provisional.clear();
    let shutdown_wakers = state
        .pending
        .drain()
        .filter_map(|(_, mut record)| record.shutdown_waker.take())
        .collect();
    state.pending_by_connection.clear();
    let controls = state
        .active
        .drain()
        .map(|(_, record)| Arc::clone(record.control()))
        .collect();
    FailClosedCleanup {
        controls,
        shutdown_wakers,
    }
}

fn run_cleanup(cleanup: FailClosedCleanup) {
    for stream in cleanup.shutdown_wakers {
        let _ = stream.shutdown(Shutdown::Both);
    }
    for control in cleanup.controls {
        control.cancel();
    }
}

fn generate_nonzero(entropy: &mut dyn Entropy) -> Result<[u8; SECRET_BYTES]> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        entropy
            .fill(&mut *bytes)
            .map_err(|_| anyhow::anyhow!("OS random source failed"))?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(*bytes);
        }
    }
    bail!("OS random source repeatedly returned invalid output")
}

fn generate_token(
    state: &mut ManagerState,
) -> std::result::Result<(Zeroizing<[u8; 32]>, BindingDigest), PromptStateError> {
    for _ in 0..ENTROPY_ATTEMPTS {
        let counter = state
            .issuance_counter
            .checked_add(1)
            .ok_or(PromptStateError::Unavailable)?;
        state.issuance_counter = counter;
        let random = Zeroizing::new(
            generate_nonzero(&mut *state.entropy).map_err(|_| PromptStateError::Unavailable)?,
        );
        let token = Zeroizing::new(derive_token(&state.instance_secret, counter, &random));
        if token.iter().all(|byte| *byte == 0) {
            continue;
        }
        let lookup = keyed_digest(&state.instance_secret, b"token-lookup-v2", &token[..]);
        if !state.pending.contains_key(&lookup)
            && !state
                .active
                .values()
                .any(|record| constant_time_eq(record.token_lookup(), &lookup))
        {
            return Ok((token, lookup));
        }
    }
    Err(PromptStateError::Unavailable)
}

fn derive_token(secret: &[u8; 32], counter: u64, random: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"howy-prompt-token-v2");
    hash_field(&mut hasher, secret);
    hash_field(&mut hasher, &counter.to_le_bytes());
    hash_field(&mut hasher, random);
    hasher.finalize().into()
}

fn connection_binding(secret: &[u8; 32], connection: ConnectionId) -> BindingDigest {
    keyed_digest(
        secret,
        b"connection-binding-v2",
        &connection.0.to_le_bytes(),
    )
}

fn keyed_digest(secret: &[u8; 32], domain: &[u8], value: &[u8]) -> BindingDigest {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"howy-prompt-keyed-v2");
    hash_field(&mut hasher, secret);
    hash_field(&mut hasher, domain);
    hash_field(&mut hasher, value);
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(field);
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hash_field(hasher, &value.to_le_bytes());
}

pub(crate) fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use howy_common::storage::{
        BackendHealth, CandidatePresence, PromptOpaqueIdentity, PromptStorageSnapshot,
    };
    use std::sync::Barrier;

    struct TestClock {
        base: Instant,
        offset: Mutex<Duration>,
    }

    impl Default for TestClock {
        fn default() -> Self {
            Self {
                base: Instant::now(),
                offset: Mutex::new(Duration::ZERO),
            }
        }
    }

    impl TestClock {
        fn advance(&self, duration: Duration) {
            *self.offset.lock().unwrap() += duration;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            self.base + *self.offset.lock().unwrap()
        }
    }

    struct SequenceEntropy(u8);

    impl Entropy for SequenceEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> std::result::Result<(), ()> {
            self.0 = self.0.wrapping_add(1).max(1);
            destination.fill(self.0);
            Ok(())
        }
    }

    fn storage(generation: u64, backend: u8, policy: u8) -> PromptStorageSnapshot {
        PromptStorageSnapshot::new(
            BackendHealth::Ready,
            CandidatePresence::Candidate { generation },
            PromptOpaqueIdentity::new([backend; 32]),
            PromptOpaqueIdentity::new([policy; 32]),
        )
    }

    fn config() -> HowyConfig {
        let mut config = HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        config
    }

    fn manager_with(
        clock: Arc<TestClock>,
        per_uid: usize,
        global: usize,
        active: usize,
        issuance_counter: u64,
        entropy_seed: u8,
    ) -> PromptTransactionManager {
        PromptTransactionManager::new(
            Box::new(SequenceEntropy(entropy_seed)),
            clock,
            Duration::from_secs(10),
            Duration::from_secs(5),
            Duration::from_secs(1),
            per_uid,
            global,
            active,
            issuance_counter,
        )
        .unwrap()
    }

    fn manager(clock: Arc<TestClock>) -> PromptTransactionManager {
        manager_with(clock, 2, 4, 1, 0, 0)
    }

    #[test]
    fn sha256_domain_outputs_match_pre_consolidation_goldens() {
        let secret = [0x11; 32];
        let random = [0x22; 32];
        assert_eq!(
            derive_token(&secret, 0x0102_0304_0506_0708, &random).as_slice(),
            hex::decode("f6b5784479f016ed6cccb3b15108ed79d373ea6f5fd763833cda0e1bd9cea440")
                .unwrap()
        );
        assert_eq!(
            keyed_digest(&secret, b"domain", b"value").as_slice(),
            hex::decode("ec47152af2891f8d44cb00d949a5110aa6d16ccce4367449b65621738d314248")
                .unwrap()
        );
    }

    fn issue(
        manager: &PromptTransactionManager,
        uid: u32,
        snapshot: SecuritySnapshot,
    ) -> (PendingIssue, ConnectionId, CanonicalIdentity) {
        let connection = manager.new_connection().unwrap();
        let target = CanonicalIdentity::new(format!("user{uid}"), uid);
        let reservation = manager
            .reserve_begin(connection, uid, target.clone())
            .unwrap();
        let issue = reservation
            .issue(PendingBinding {
                connection,
                peer_uid: uid,
                target: target.clone(),
                client_nonce: Zeroizing::new([0x55; 32]),
                pam_service: "sudo".into(),
                origin: PromptOriginV1::Local,
                snapshot,
            })
            .unwrap();
        (issue, connection, target)
    }

    fn claim(mut issue: PendingIssue, uid: u32, target: &CanonicalIdentity) -> CommitClaim {
        issue.activate().unwrap();
        let token = *issue.token();
        issue
            .claim_commit(&token, &[0x55; 32], uid, target.uid())
            .unwrap()
    }

    fn promote(
        claim: CommitClaim,
        connection: ConnectionId,
        uid: u32,
        target: CanonicalIdentity,
        snapshot: SecuritySnapshot,
    ) -> std::result::Result<ActiveLease, PromptStateError> {
        claim.promote(CommitBinding {
            connection,
            peer_uid: uid,
            target,
            pam_service: "sudo".into(),
            origin: PromptOriginV1::Local,
            snapshot,
        })
    }

    #[test]
    fn derived_tokens_are_nonzero_unique_redacted_and_memory_stays_bounded() {
        let manager = manager_with(Arc::new(TestClock::default()), 2, 4, 1, 0, 0);
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 2));
        let mut first_token = Zeroizing::new([0u8; 32]);
        for cycle in 0..10_000u32 {
            let uid = 1000 + cycle % 2;
            let (mut issued, _, target) = issue(&manager, uid, snapshot.clone());
            issued.activate().unwrap();
            if cycle == 0 {
                first_token.copy_from_slice(issued.token());
                assert!(first_token.iter().any(|byte| *byte != 0));
                assert!(format!("{issued:?}").contains("REDACTED"));
            } else {
                assert!(!constant_time_eq(&first_token, issued.token()));
            }
            let token = *issued.token();
            issued
                .cancel(&token, &[0x55; 32], uid, target.uid())
                .unwrap();
            assert_eq!(manager.counts(), (0, 0, 0));
        }
    }

    #[test]
    fn issuance_counter_exhaustion_fails_closed_and_releases_reservation() {
        let manager = manager_with(Arc::new(TestClock::default()), 2, 4, 1, u64::MAX, 0);
        let connection = manager.new_connection().unwrap();
        let target = CanonicalIdentity::new("user1000", 1000);
        let reservation = manager
            .reserve_begin(connection, 1000, target.clone())
            .unwrap();
        let result = reservation.issue(PendingBinding {
            connection,
            peer_uid: 1000,
            target,
            client_nonce: Zeroizing::new([1; 32]),
            pam_service: "sudo".into(),
            origin: PromptOriginV1::Local,
            snapshot: SecuritySnapshot::capture(&config(), storage(1, 1, 1)),
        });
        assert!(matches!(result, Err(PromptStateError::Unavailable)));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn provisional_capacity_blocks_before_hooks_and_releases_on_drop() {
        let manager = manager_with(Arc::new(TestClock::default()), 1, 1, 1, 0, 0);
        let first_connection = manager.new_connection().unwrap();
        let first = manager
            .reserve_begin(
                first_connection,
                1000,
                CanonicalIdentity::new("user1000", 1000),
            )
            .unwrap();
        let second_connection = manager.new_connection().unwrap();
        assert!(matches!(
            manager.reserve_begin(
                second_connection,
                1001,
                CanonicalIdentity::new("user1001", 1001),
            ),
            Err(PromptStateError::Unavailable)
        ));
        drop(first);
        assert!(
            manager
                .reserve_begin(
                    second_connection,
                    1001,
                    CanonicalIdentity::new("user1001", 1001),
                )
                .is_ok()
        );
    }

    #[test]
    fn expired_claim_performs_only_manager_work() {
        let clock = Arc::new(TestClock::default());
        let manager = manager(Arc::clone(&clock));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (mut issued, _, target) = issue(&manager, 1000, snapshot);
        issued.activate().unwrap();
        let token = *issued.token();
        clock.advance(Duration::from_secs(10));
        assert!(matches!(
            issued.claim_commit(&token, &[0x55; 32], 1000, target.uid()),
            Err(PromptStateError::Invalid)
        ));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn commit_and_cancel_sample_time_after_contended_manager_lock() {
        for commit in [true, false] {
            let clock = Arc::new(TestClock::default());
            let manager = manager(Arc::clone(&clock));
            let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
            let (mut issued, _, target) = issue(&manager, 1000, snapshot);
            issued.activate().unwrap();
            let token = Zeroizing::new(*issued.token());
            let lookup = issued.lookup.unwrap();
            let connection_binding = issued.connection_binding;
            let worker_manager = manager.clone();
            let target_uid = target.uid();
            let entered = Arc::new(Barrier::new(2));
            let worker_entered = Arc::clone(&entered);

            let guard = manager.inner.state.lock().unwrap();
            let worker = std::thread::spawn(move || {
                if commit {
                    worker_manager
                        .claim_commit_after_before_lock(
                            connection_binding,
                            lookup,
                            &token,
                            &[0x55; 32],
                            1000,
                            target_uid,
                            || {
                                worker_entered.wait();
                            },
                        )
                        .map(|_| ())
                } else {
                    worker_manager.cancel_pending_after_before_lock(
                        connection_binding,
                        lookup,
                        &token,
                        &[0x55; 32],
                        1000,
                        target_uid,
                        || {
                            worker_entered.wait();
                        },
                    )
                }
            });
            entered.wait();
            clock.advance(Duration::from_secs(10));
            drop(guard);

            assert!(matches!(
                worker.join().unwrap(),
                Err(PromptStateError::Invalid)
            ));
            issued.lookup.take();
            drop(issued);
            assert_eq!(manager.counts(), (0, 0, 0));
        }
    }

    #[test]
    fn promotion_rejects_cancelled_or_expired_claim_and_releases_once() {
        for cancelled in [true, false] {
            let clock = Arc::new(TestClock::default());
            let manager = manager(Arc::clone(&clock));
            let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
            let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
            let claim = claim(issued, 1000, &target);
            let control = Arc::clone(&claim.control);
            if cancelled {
                assert!(claim.control.cancel());
            } else {
                clock.advance(Duration::from_secs(5));
            }
            assert!(matches!(
                promote(claim, connection, 1000, target, snapshot),
                Err(PromptStateError::Invalid)
            ));
            assert!(control.cancelled.load(Ordering::Acquire));
            assert!(!control.cancel());
            assert_eq!(manager.counts(), (0, 0, 0));
        }
    }

    #[test]
    fn successful_promotion_transfers_live_control_until_lease_drop() {
        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        let lease = promote(claim, connection, 1000, target, snapshot).unwrap();
        let control = Arc::clone(&lease.control);

        assert!(!lease.is_cancelled());
        assert_eq!(manager.counts(), (0, 0, 1));

        drop(lease);
        assert!(control.cancelled.load(Ordering::Acquire));
        assert!(!control.cancel());
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn explicit_cancel_and_active_deadline_change_only_live_leases() {
        for explicit in [true, false] {
            let clock = Arc::new(TestClock::default());
            let manager = manager(Arc::clone(&clock));
            let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
            let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
            let claim = claim(issued, 1000, &target);
            let lease = promote(claim, connection, 1000, target, snapshot).unwrap();

            assert!(!lease.is_cancelled());
            assert_eq!(manager.counts(), (0, 0, 1));
            if explicit {
                assert!(lease.cancel());
                assert!(!lease.cancel());
            } else {
                clock.advance(Duration::from_secs(5));
                assert!(lease.check_deadline());
            }
            assert!(lease.is_cancelled());
            assert_eq!(manager.counts(), (0, 0, 1));

            drop(lease);
            assert_eq!(manager.counts(), (0, 0, 0));
        }
    }

    #[test]
    fn abandoned_claim_cancels_and_releases_without_capacity_leak() {
        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, _, target) = issue(&manager, 1000, snapshot);
        let claim = claim(issued, 1000, &target);
        let control = Arc::clone(&claim.control);

        assert!(!control.cancelled.load(Ordering::Acquire));
        assert_eq!(manager.counts(), (0, 0, 1));
        drop(claim);
        assert!(control.cancelled.load(Ordering::Acquire));
        assert!(!control.cancel());
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn claim_reserves_active_before_external_revalidation_and_drop_releases() {
        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, _, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        assert_eq!(manager.counts(), (0, 0, 1));
        let (mut second, _, second_target) = issue(&manager, 1001, snapshot);
        second.activate().unwrap();
        let token = *second.token();
        assert!(matches!(
            second.claim_commit(&token, &[0x55; 32], 1001, second_target.uid()),
            Err(PromptStateError::Unavailable)
        ));
        drop(claim);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn backend_identity_policy_generation_health_and_generation_changes_invalidate() {
        for changed in [
            storage(8, 1, 1),
            storage(7, 2, 1),
            storage(7, 1, 2),
            PromptStorageSnapshot::new(
                BackendHealth::Unavailable(howy_common::storage::BackendUnavailable::Io),
                CandidatePresence::Candidate { generation: 7 },
                PromptOpaqueIdentity::new([1; 32]),
                PromptOpaqueIdentity::new([1; 32]),
            ),
        ] {
            let manager = manager(Arc::new(TestClock::default()));
            let initial = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
            let (issued, connection, target) = issue(&manager, 1000, initial);
            let claim = claim(issued, 1000, &target);
            assert!(matches!(
                promote(
                    claim,
                    connection,
                    1000,
                    target,
                    SecuritySnapshot::capture(&config(), changed),
                ),
                Err(PromptStateError::Invalid)
            ));
        }

        let manager = manager(Arc::new(TestClock::default()));
        let initial = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, initial);
        let claim = claim(issued, 1000, &target);
        let mut changed_policy = config();
        changed_policy.presence.local_only = false;
        assert!(matches!(
            promote(
                claim,
                connection,
                1000,
                target,
                SecuritySnapshot::capture(&changed_policy, storage(7, 1, 1)),
            ),
            Err(PromptStateError::Invalid)
        ));
    }

    #[test]
    fn snapshot_captured_before_post_linearization_mutation_can_promote() {
        let manager = manager(Arc::new(TestClock::default()));
        let captured = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, captured.clone());
        let claim = claim(issued, 1000, &target);
        let _post_snapshot_mutation = storage(8, 1, 1);
        assert!(promote(claim, connection, 1000, target, captured).is_ok());
    }

    #[test]
    fn duplicate_commit_cancel_and_shutdown_are_linearizable() {
        let manager = Arc::new(manager(Arc::new(TestClock::default())));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (mut issued, _, target) = issue(&manager, 1000, snapshot);
        issued.activate().unwrap();
        let token = *issued.token();
        let lookup = issued.lookup.take().unwrap();
        let connection_binding = issued.connection_binding;
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for cancel in [false, true] {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            let target = target.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                if cancel {
                    manager
                        .cancel_pending(
                            connection_binding,
                            lookup,
                            &token,
                            &[0x55; 32],
                            1000,
                            target.uid(),
                        )
                        .map(|()| false)
                } else {
                    manager
                        .claim_commit(
                            connection_binding,
                            lookup,
                            &token,
                            &[0x55; 32],
                            1000,
                            target.uid(),
                        )
                        .map(|_| true)
                }
            }));
        }
        let shutdown_manager = Arc::clone(&manager);
        let shutdown_barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            shutdown_barrier.wait();
            shutdown_manager.shutdown();
            Err(PromptStateError::Unavailable)
        }));
        barrier.wait();
        let successes = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap().ok())
            .count();
        assert!(successes <= 1);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn poison_is_permanent_cleans_state_and_wakes_active_waiter() {
        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        let lease = promote(claim, connection, 1000, target, snapshot).unwrap();
        assert!(!lease.is_cancelled());
        assert_eq!(manager.counts(), (0, 0, 1));
        let entered = Arc::new(Barrier::new(2));
        let waiter_entered = Arc::clone(&entered);
        let waiter = std::thread::spawn(move || {
            waiter_entered.wait();
            lease.wait_cancelled();
            assert!(lease.is_cancelled());
        });
        entered.wait();
        manager.poison_for_test();
        assert!(manager.is_terminated());
        waiter.join().unwrap();
        assert!(matches!(
            manager.new_connection(),
            Err(PromptStateError::Unavailable)
        ));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn shutdown_cancels_active_and_wakes_waiter() {
        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        let lease = promote(claim, connection, 1000, target, snapshot).unwrap();
        assert!(!lease.is_cancelled());
        assert_eq!(manager.counts(), (0, 0, 1));
        let entered = Arc::new(Barrier::new(2));
        let waiter_entered = Arc::clone(&entered);
        let waiter = std::thread::spawn(move || {
            waiter_entered.wait();
            lease.wait_cancelled();
            assert!(lease.is_cancelled());
        });
        entered.wait();
        manager.shutdown();
        waiter.join().unwrap();
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn resource_registered_after_active_cancel_is_cancelled_and_woken_immediately() {
        struct LateResource {
            cancelled: AtomicBool,
            wake: (Mutex<bool>, Condvar),
        }

        impl ActiveResourceCancellation for LateResource {
            fn cancel_resource(&self) {
                self.cancelled.store(true, Ordering::Release);
                *self.wake.0.lock().unwrap() = true;
                self.wake.1.notify_all();
            }
        }

        let manager = manager(Arc::new(TestClock::default()));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        let lease = promote(claim, connection, 1000, target, snapshot).unwrap();
        let cancellation = lease.cancellation();
        assert!(cancellation.cancel());

        let resource = Arc::new(LateResource {
            cancelled: AtomicBool::new(false),
            wake: (Mutex::new(false), Condvar::new()),
        });
        let waiter_resource = Arc::clone(&resource);
        let waiter = std::thread::spawn(move || {
            let mut woken = waiter_resource.wake.0.lock().unwrap();
            while !*woken {
                woken = waiter_resource.wake.1.wait(woken).unwrap();
            }
        });

        cancellation.register_resource(resource.clone());
        waiter.join().unwrap();
        assert!(resource.cancelled.load(Ordering::Acquire));
        drop(lease);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn explicit_cancellation_and_deadline_race_is_idempotent() {
        let clock = Arc::new(TestClock::default());
        let manager = manager(Arc::clone(&clock));
        let snapshot = SecuritySnapshot::capture(&config(), storage(7, 1, 1));
        let (issued, connection, target) = issue(&manager, 1000, snapshot.clone());
        let claim = claim(issued, 1000, &target);
        let lease = promote(claim, connection, 1000, target, snapshot).unwrap();
        let control = Arc::clone(&lease.control);
        let barrier = Arc::new(Barrier::new(3));
        let explicit_barrier = Arc::clone(&barrier);
        let explicit = std::thread::spawn(move || {
            explicit_barrier.wait();
            control.cancel()
        });
        clock.advance(Duration::from_secs(5));
        let deadline_barrier = Arc::clone(&barrier);
        let deadline = std::thread::spawn(move || {
            deadline_barrier.wait();
            lease.check_deadline()
        });
        barrier.wait();
        let _ = explicit.join().unwrap();
        assert!(deadline.join().unwrap());
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn connection_binding_is_instance_keyed() {
        let first = manager_with(Arc::new(TestClock::default()), 2, 4, 1, 0, 0);
        let second = manager_with(Arc::new(TestClock::default()), 2, 4, 1, 0, 9);
        let connection = ConnectionId(7);
        assert!(constant_time_eq(
            &first.connection_binding_for_test(connection),
            &first.connection_binding_for_test(connection),
        ));
        assert!(!constant_time_eq(
            &first.connection_binding_for_test(connection),
            &first.connection_binding_for_test(ConnectionId(8)),
        ));
        assert!(!constant_time_eq(
            &first.connection_binding_for_test(connection),
            &second.connection_binding_for_test(connection),
        ));
    }

    #[test]
    fn constant_time_compare_reads_every_byte() {
        let same = [0x55; 32];
        let mut first = same;
        first[0] ^= 1;
        let mut last = same;
        last[31] ^= 1;
        assert!(!constant_time_eq(&same, &first));
        assert!(!constant_time_eq(&same, &last));
        assert!(constant_time_eq(&same, &same));
    }
}
