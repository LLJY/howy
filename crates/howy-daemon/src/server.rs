//! Unix socket server for the howy daemon.
//!
//! Handles IPC requests from the PAM module and CLI tools.
//! Supports systemd socket activation via `LISTEN_FDS`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

use howy_common::config::{EmbeddingSecurityMode, HowyConfig, PresenceMode};
use howy_common::credential;
use howy_common::face;
use howy_common::ipc;
use howy_common::paths;
use howy_common::protocol::{self, Cmd, Request, RespResult, Response};
use howy_common::storage::{
    ABSENT_GENERATION, AppendAdmissionShape, AppendRequest, AuthenticationCachePromotion,
    AuthenticationLoad, BackendHealth, BackendUnavailable, BudgetPermit, CancellationSignal,
    CandidatePresence, CanonicalUsername, ClearRequest, EnrollmentEntry, EnrollmentId,
    MetadataList, OsRandomSource, OuterRecordClassification, RandomSource, RecordNamespace,
    RemoveRequest, StorageBackend, StorageBackendError, generate_enrollment_id,
};

use crate::authorization::{
    Authorization, AuthorizationContext, ConnectionPhase, Operation, SystemIdentityResolver,
    authorize_and_then,
};
use crate::camera::{
    CameraCapture, CameraCaptureError, CameraFactory, CameraFailureKind, CameraProfile,
    CameraProfileProvider, CameraProfileRequest, CameraStopOutcome, Frame, FrameFormat,
    PendingCameraCleanup, ProductionCameraFactory, ProductionCameraProfileProvider, WorkerExit,
    take_retained_camera_workers,
};
use crate::child_spawn::DaemonChildPolicy;
use crate::inference::InferenceEngine;
use crate::prompt_state::{
    ActiveCancellation, ActiveLease, CommitBinding, CommitClaim, ConnectionId, PendingBinding,
    PendingIssue, PromptStateError, PromptTransactionManager, SecuritySnapshot, constant_time_eq,
};

trait ServerInference: Send + Sync {
    fn registered_preferred_provider(&self) -> &str;
    fn detector_model_path(&self) -> String;
    fn recognizer_model_path(&self) -> String;
    fn plaintext_scratch_bytes(&self) -> Result<usize>;
    fn detect(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        is_gray: bool,
    ) -> Result<Vec<face::Face>>;
    fn encode(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        detected_face: &face::Face,
        is_gray: bool,
    ) -> Result<Vec<f32>>;
    fn analyze(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        is_gray: bool,
    ) -> Result<Vec<face::Face>>;
}

/// Non-secret process identity captured from the exact startup descriptors.
/// This is exposed only by the separately authorized root SecurityInfo method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeIdentity {
    pub config_sha256: String,
    pub credential_name: Option<String>,
    pub configured_credential_source: Option<String>,
    pub invocation_id: String,
    pub daemon_version: String,
    pub build_identity: String,
    pub binary_absolute_path: String,
    pub binary_sha256: String,
}

impl DaemonRuntimeIdentity {
    #[cfg(test)]
    fn harness_placeholder() -> Self {
        Self {
            config_sha256: "0".repeat(64),
            credential_name: None,
            configured_credential_source: None,
            invocation_id: "0".repeat(64),
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            build_identity: "test-harness".to_owned(),
            binary_absolute_path: "/test/howyd".to_owned(),
            binary_sha256: "0".repeat(64),
        }
    }
}

impl ServerInference for InferenceEngine {
    fn registered_preferred_provider(&self) -> &str {
        InferenceEngine::registered_preferred_provider(self)
    }

    fn detector_model_path(&self) -> String {
        InferenceEngine::detector_model_path(self)
    }

    fn recognizer_model_path(&self) -> String {
        InferenceEngine::recognizer_model_path(self)
    }

    fn plaintext_scratch_bytes(&self) -> Result<usize> {
        InferenceEngine::plaintext_scratch_bytes(self)
    }

    fn detect(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        is_gray: bool,
    ) -> Result<Vec<face::Face>> {
        InferenceEngine::detect(self, data, width, height, is_gray)
    }

    fn encode(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        detected_face: &face::Face,
        is_gray: bool,
    ) -> Result<Vec<f32>> {
        InferenceEngine::encode(self, data, width, height, detected_face, is_gray)
    }

    fn analyze(
        &self,
        data: &[u8],
        width: u32,
        height: u32,
        is_gray: bool,
    ) -> Result<Vec<face::Face>> {
        InferenceEngine::analyze(self, data, width, height, is_gray)
    }
}

const CAMERA_LOCK_TIMEOUT: Duration = Duration::from_secs(3);
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAPER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const CONNECTION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const CAMERA_PROFILE_PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const CAMERA_PROFILE_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const CAMERA_PROFILE_WAIT_POLL: Duration = Duration::from_millis(25);
const PROMPT_STORAGE_TIMEOUT: Duration = Duration::from_secs(2);
const ACTIVE_SUPERVISOR_POLL: Duration = Duration::from_millis(10);
const ACTIVE_WORKER_CLEANUP_TIMEOUT: Duration = Duration::from_millis(250);
/// Local peers must send their first framed request promptly.
const INITIAL_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECTION_WORKERS: usize = 64;
const RESERVED_CONNECTIONS: usize = 8;
const MAX_CONNECTIONS_PER_UID: usize = 8;
// CameraAdmission is intentionally single-flight. Prompt active admission must
// never exceed the work it will guard in the later active-authentication slice.
const PROMPT_ACTIVE_LIMIT_FROM_CAMERA_ADMISSION: usize = 1;
const MAX_BATCH_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_BATCH_FILES: usize = 256;
const MAX_BATCH_SESSION_PATH_BYTES: usize = 4_096;
const MAX_BATCH_ENCODED_BYTES_PER_FILE: u64 = 8 * 1024 * 1024;
const MAX_BATCH_TOTAL_ENCODED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BATCH_IMAGE_WIDTH: u32 = 4_096;
const MAX_BATCH_IMAGE_HEIGHT: u32 = 4_096;
const MAX_BATCH_DECODED_BYTES_PER_FILE: usize = 32 * 1024 * 1024;
const MAX_BATCH_AGGREGATE_DECODED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LIVE_FACES_PER_FRAME: usize = 64;
pub const PERF_TRACE_TARGET: &str = "howy_perf";

#[derive(Clone)]
struct CameraAdmission {
    shared: Arc<CameraAdmissionShared>,
    lifecycle: Arc<Mutex<ReaperLifecycle>>,
}

struct CameraAdmissionShared {
    queue: Mutex<AdmissionQueue>,
    available: Condvar,
}

struct AdmissionQueue {
    active: bool,
    next_ticket: u64,
    waiters: VecDeque<u64>,
}

struct CameraReaper {
    lifecycle: Arc<Mutex<ReaperLifecycle>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

struct ReaperShutdownRemainder {
    lifecycle: Option<Arc<Mutex<ReaperLifecycle>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

struct DaemonShutdownRemainder {
    reaper: ReaperShutdownRemainder,
    connection_workers: Vec<std::thread::JoinHandle<()>>,
    retained_camera_workers: Vec<std::thread::JoinHandle<()>>,
    fatal_active_workers: Vec<std::thread::JoinHandle<()>>,
}

struct CameraProfileCache {
    state: Mutex<CameraProfileState>,
    changed: Condvar,
    provider: Arc<dyn CameraProfileProvider>,
    request: CameraProfileRequest,
}

struct ProfileProbeCompletion {
    cache: Arc<CameraProfileCache>,
    generation: u64,
    completed: bool,
}

impl ProfileProbeCompletion {
    fn new(cache: Arc<CameraProfileCache>, generation: u64) -> Self {
        Self {
            cache,
            generation,
            completed: false,
        }
    }

    fn complete(mut self, result: std::result::Result<CameraProfile, String>) {
        self.cache
            .complete_probe(self.generation, result, Instant::now());
        self.completed = true;
    }
}

impl Drop for ProfileProbeCompletion {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.complete_probe(
                self.generation,
                Err("camera profile probe worker ended unexpectedly".to_string()),
                Instant::now(),
            );
        }
    }
}

enum CameraProfileState {
    Idle {
        generation: u64,
    },
    Probing {
        generation: u64,
    },
    Ready {
        profile: CameraProfile,
        generation: u64,
    },
    Failed {
        retry_at: Instant,
        generation: u64,
    },
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CameraProfileToken(u64);

#[derive(Clone)]
struct ResolvedCameraProfile {
    profile: CameraProfile,
    token: CameraProfileToken,
}

impl std::ops::Deref for ResolvedCameraProfile {
    type Target = CameraProfile;

    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

#[derive(Clone)]
struct ProfileInvalidation {
    cache: Arc<CameraProfileCache>,
    token: CameraProfileToken,
}

impl ProfileInvalidation {
    fn apply(self) -> bool {
        self.cache.invalidate_if_current(self.token)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeClaim {
    Ready,
    Wait,
    Start(u64),
    Shutdown,
}

#[derive(Clone)]
struct CameraHooks {
    profile_provider: Arc<dyn CameraProfileProvider>,
    factory: Arc<dyn CameraFactory>,
}

#[derive(Clone, Default)]
struct ServerRunHooks {
    after_accept: Option<Arc<dyn Fn() + Send + Sync>>,
    before_handle: Option<Arc<dyn Fn() + Send + Sync>>,
    camera_admission: Option<Arc<dyn Fn(CameraAdmission) + Send + Sync>>,
    runtime_identity: Option<Arc<DaemonRuntimeIdentity>>,
}

#[derive(Clone)]
struct LazyCameraHandle {
    profile: Arc<CameraProfileCache>,
    admission: CameraAdmission,
    factory: Arc<dyn CameraFactory>,
}

impl LazyCameraHandle {
    #[cfg_attr(not(test), allow(dead_code))]
    fn resolve_profile(&self, cancelled: impl FnMut() -> bool) -> Result<ResolvedCameraProfile> {
        resolve_camera_profile(&self.profile, &self.admission, cancelled)
    }

    fn resolve_profile_active(
        &self,
        active: &ActiveCancellation,
        deadline: Instant,
    ) -> Result<ResolvedCameraProfile> {
        resolve_camera_profile_active(&self.profile, &self.admission, active, deadline)
    }
}

impl CameraHooks {
    fn production(child_policy: Arc<DaemonChildPolicy>) -> Self {
        Self {
            profile_provider: Arc::new(ProductionCameraProfileProvider::default()),
            factory: Arc::new(ProductionCameraFactory::new(child_policy)),
        }
    }
}

#[derive(Default)]
struct ConnectionAccounting {
    total: usize,
    by_uid: HashMap<u32, usize>,
}

struct ConnectionPermit {
    accounting: Arc<Mutex<ConnectionAccounting>>,
    uid: u32,
}

/// Shared graceful-shutdown state used by IPC and process signals.
#[derive(Clone)]
pub struct ShutdownSignal {
    requested: Arc<AtomicBool>,
    fatal: Arc<AtomicBool>,
    fatal_active_workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    wake: Arc<(Mutex<()>, Condvar)>,
}

impl DaemonShutdownRemainder {
    fn is_empty(&self) -> bool {
        self.reaper.is_empty()
            && self.connection_workers.is_empty()
            && self.retained_camera_workers.is_empty()
            && self.fatal_active_workers.is_empty()
    }

    fn unresolved_count(&self) -> usize {
        self.reaper.unresolved_count()
            + self.connection_workers.len()
            + self.retained_camera_workers.len()
            + self.fatal_active_workers.len()
    }
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            fatal: Arc::new(AtomicBool::new(false)),
            fatal_active_workers: Arc::new(Mutex::new(Vec::new())),
            wake: Arc::new((Mutex::new(()), Condvar::new())),
        }
    }

    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.wake.1.notify_all();
    }

    fn request_fatal_with_worker(&self, worker: std::thread::JoinHandle<()>) {
        self.fatal.store(true, Ordering::Release);
        lock_unpoisoned(&self.fatal_active_workers).push(worker);
        self.request();
    }

    fn is_fatal(&self) -> bool {
        self.fatal.load(Ordering::Acquire)
    }

    fn take_fatal_active_workers(&self) -> Vec<std::thread::JoinHandle<()>> {
        std::mem::take(&mut *lock_unpoisoned(&self.fatal_active_workers))
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    fn wait_for_activity(&self, timeout: Duration) {
        if self.is_requested() {
            return;
        }
        let guard = lock_unpoisoned(&self.wake.0);
        let _guard = self
            .wake
            .1
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl CameraProfileCache {
    fn new(provider: Arc<dyn CameraProfileProvider>, request: CameraProfileRequest) -> Self {
        Self {
            state: Mutex::new(CameraProfileState::Idle { generation: 0 }),
            changed: Condvar::new(),
            provider,
            request,
        }
    }

    fn complete_probe(
        &self,
        generation: u64,
        result: std::result::Result<CameraProfile, String>,
        now: Instant,
    ) {
        let mut state = lock_unpoisoned(&self.state);
        let active_generation = match &*state {
            CameraProfileState::Probing { generation } => *generation,
            CameraProfileState::Idle { .. }
            | CameraProfileState::Ready { .. }
            | CameraProfileState::Failed { .. }
            | CameraProfileState::Shutdown => return,
        };
        if active_generation != generation {
            return;
        }
        *state = match result {
            Ok(profile) => CameraProfileState::Ready {
                profile,
                generation,
            },
            Err(error) => {
                warn!(%error, "Camera profile probe failed; bounded retry remains available");
                CameraProfileState::Failed {
                    retry_at: now + CAMERA_PROFILE_RETRY_BACKOFF,
                    generation,
                }
            }
        };
        self.changed.notify_all();
    }

    fn claim(&self, now: Instant) -> ProbeClaim {
        let mut state = lock_unpoisoned(&self.state);
        match &*state {
            CameraProfileState::Ready { .. } => ProbeClaim::Ready,
            CameraProfileState::Idle { generation } => {
                let generation = *generation;
                *state = CameraProfileState::Probing { generation };
                ProbeClaim::Start(generation)
            }
            CameraProfileState::Probing { .. } => ProbeClaim::Wait,
            CameraProfileState::Failed {
                retry_at,
                generation,
            } if now >= *retry_at => {
                let Some(generation) = generation.checked_add(1) else {
                    *state = CameraProfileState::Shutdown;
                    self.changed.notify_all();
                    return ProbeClaim::Shutdown;
                };
                *state = CameraProfileState::Probing { generation };
                ProbeClaim::Start(generation)
            }
            CameraProfileState::Failed { .. } => ProbeClaim::Wait,
            CameraProfileState::Shutdown => ProbeClaim::Shutdown,
        }
    }

    fn ready_profile(&self) -> Option<ResolvedCameraProfile> {
        let state = lock_unpoisoned(&self.state);
        match &*state {
            CameraProfileState::Ready {
                profile,
                generation,
            } => Some(ResolvedCameraProfile {
                profile: profile.clone(),
                token: CameraProfileToken(*generation),
            }),
            _ => None,
        }
    }

    fn initial_attempt_finished(&self) -> bool {
        matches!(
            &*lock_unpoisoned(&self.state),
            CameraProfileState::Ready { .. }
                | CameraProfileState::Failed { .. }
                | CameraProfileState::Shutdown
        )
    }

    fn wait_for_change(&self, deadline: Instant) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let state = lock_unpoisoned(&self.state);
        let wait = match &*state {
            CameraProfileState::Failed { retry_at, .. } => {
                remaining.min(retry_at.saturating_duration_since(Instant::now()))
            }
            CameraProfileState::Shutdown => return,
            _ => remaining,
        }
        .min(CAMERA_PROFILE_WAIT_POLL);
        if wait.is_zero() {
            return;
        }
        let _state = self
            .changed
            .wait_timeout(state, wait)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }

    fn invalidate_if_current(&self, token: CameraProfileToken) -> bool {
        let mut state = lock_unpoisoned(&self.state);
        let generation = match &*state {
            CameraProfileState::Ready { generation, .. } if *generation == token.0 => *generation,
            CameraProfileState::Idle { .. }
            | CameraProfileState::Probing { .. }
            | CameraProfileState::Ready { .. }
            | CameraProfileState::Failed { .. }
            | CameraProfileState::Shutdown => return false,
        };
        *state = CameraProfileState::Failed {
            retry_at: Instant::now(),
            generation,
        };
        self.changed.notify_all();
        true
    }

    fn shutdown(&self) {
        *lock_unpoisoned(&self.state) = CameraProfileState::Shutdown;
        self.changed.notify_all();
    }

    fn is_shutdown(&self) -> bool {
        matches!(&*lock_unpoisoned(&self.state), CameraProfileState::Shutdown)
    }

    fn provider(&self) -> Arc<dyn CameraProfileProvider> {
        Arc::clone(&self.provider)
    }

    fn request(&self) -> CameraProfileRequest {
        self.request.clone()
    }

    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match &*lock_unpoisoned(&self.state) {
            CameraProfileState::Idle { .. } => "idle",
            CameraProfileState::Probing { .. } => "probing",
            CameraProfileState::Ready { .. } => "ready",
            CameraProfileState::Failed { .. } => "failed",
            CameraProfileState::Shutdown => "shutdown",
        }
    }
}

impl ConnectionAccounting {
    fn try_acquire(accounting: &Arc<Mutex<Self>>, uid: u32) -> Option<ConnectionPermit> {
        let mut counts = lock_unpoisoned(accounting);
        let per_uid = counts.by_uid.get(&uid).copied().unwrap_or(0);
        let unprivileged_limit = MAX_CONNECTION_WORKERS - RESERVED_CONNECTIONS;
        if counts.total >= MAX_CONNECTION_WORKERS
            || (uid != 0 && counts.total >= unprivileged_limit)
            || (uid != 0 && per_uid >= MAX_CONNECTIONS_PER_UID)
        {
            return None;
        }
        counts.total += 1;
        *counts.by_uid.entry(uid).or_default() += 1;
        drop(counts);
        Some(ConnectionPermit {
            accounting: Arc::clone(accounting),
            uid,
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut counts = lock_unpoisoned(&self.accounting);
        counts.total = counts.total.saturating_sub(1);
        if let Some(count) = counts.by_uid.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.by_uid.remove(&self.uid);
            }
        }
    }
}

fn with_connection_permit(
    permit: ConnectionPermit,
    worker: impl FnOnce() + Send + 'static,
) -> impl FnOnce() + Send + 'static {
    move || {
        let _permit = permit;
        worker();
    }
}

impl ReaperShutdownRemainder {
    fn is_empty(&self) -> bool {
        self.lifecycle.is_none() && self.handle.is_none()
    }

    fn unresolved_count(&self) -> usize {
        self.lifecycle
            .as_ref()
            .map(|lifecycle| lock_unpoisoned(lifecycle).unresolved.len())
            .unwrap_or(0)
            + usize::from(self.handle.is_some())
    }
}

struct ReaperLifecycle {
    phase: ReaperPhase,
    unresolved: Vec<CleanupTask>,
}

enum ReaperPhase {
    Running(mpsc::Sender<CleanupTask>),
    Stopping,
}

struct CameraLease {
    shared: Weak<CameraAdmissionShared>,
    armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CameraAdmissionError {
    Busy,
    Cancelled,
}

/// Proof that the current call stack already owns the single camera admission
/// lease. Only capture paths may construct this token.
struct CameraAdmissionHeld<'a> {
    _lease: &'a CameraLease,
}

impl<'a> CameraAdmissionHeld<'a> {
    fn new(lease: &'a CameraLease) -> Self {
        Self { _lease: lease }
    }
}

struct CleanupTask {
    pending: PendingCameraCleanup,
    admission: Weak<CameraAdmissionShared>,
}

impl CameraReaper {
    fn new() -> Result<(CameraAdmission, Self)> {
        let (cleanup_tx, cleanup_rx) = mpsc::channel::<CleanupTask>();
        let lifecycle = Arc::new(Mutex::new(ReaperLifecycle {
            phase: ReaperPhase::Running(cleanup_tx),
            unresolved: Vec::new(),
        }));
        let worker_lifecycle = Arc::clone(&lifecycle);
        let shared = Arc::new(CameraAdmissionShared {
            queue: Mutex::new(AdmissionQueue {
                active: false,
                next_ticket: 0,
                waiters: VecDeque::new(),
            }),
            available: Condvar::new(),
        });
        let handle = std::thread::Builder::new()
            .name("howy-camera-reaper".to_string())
            .spawn(move || {
                let mut pending = Vec::<CleanupTask>::new();
                loop {
                    let mut index = 0;
                    while index < pending.len() {
                        let exit = pending[index].pending.try_complete();
                        if let Some(exit) = exit {
                            let task = pending.swap_remove(index);
                            if exit == WorkerExit::FailedPanicked {
                                error!("Camera worker panicked during reaper cleanup");
                            }
                            release_camera_admission(&task.admission);
                        } else {
                            index += 1;
                        }
                    }

                    match cleanup_rx.recv_timeout(REAPER_POLL_INTERVAL) {
                        Ok(task) => pending.push(task),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            // Disconnection is observed only after every send
                            // accepted before the stopping transition is drained.
                            lock_unpoisoned(&worker_lifecycle)
                                .unresolved
                                .extend(pending);
                            return;
                        }
                    }
                }
            })
            .context("failed to spawn camera cleanup reaper")?;
        Ok((
            CameraAdmission {
                shared,
                lifecycle: Arc::clone(&lifecycle),
            },
            Self {
                lifecycle,
                handle: Some(handle),
            },
        ))
    }
}

impl Drop for CameraReaper {
    fn drop(&mut self) {
        if self.handle.is_some() {
            let remainder = self.shutdown_bounded();
            if !remainder.is_empty() {
                let unresolved = remainder.unresolved_count();
                error!(
                    unresolved,
                    "Camera cleanup reaper shut down with unresolved owned tasks"
                );
                // Drop may run outside the daemon's explicit shutdown boundary.
                // Retain ownership rather than detaching task/worker handles.
                std::mem::forget(remainder);
            }
        }
    }
}

impl CameraReaper {
    fn shutdown_bounded(&mut self) -> ReaperShutdownRemainder {
        self.shutdown_bounded_with_hook(|| {})
    }

    fn shutdown_bounded_with_hook(
        &mut self,
        before_transition_lock: impl FnOnce(),
    ) -> ReaperShutdownRemainder {
        before_transition_lock();
        {
            let mut lifecycle = lock_unpoisoned(&self.lifecycle);
            lifecycle.phase = ReaperPhase::Stopping;
        }
        let deadline = Instant::now() + REAPER_SHUTDOWN_TIMEOUT;
        while self
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut unfinished_handle = None;
        if self
            .handle
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            if self.handle.take().unwrap().join().is_err() {
                error!("Camera cleanup reaper panicked");
            }
        } else {
            unfinished_handle = self.handle.take();
            if unfinished_handle.is_some() {
                error!("Camera cleanup reaper did not stop within bounded shutdown interval");
            }
        }
        if unfinished_handle.is_none() && self.handle.is_none() {
            reap_completed_unresolved_tasks(&self.lifecycle);
        }
        let has_unresolved = !lock_unpoisoned(&self.lifecycle).unresolved.is_empty();
        ReaperShutdownRemainder {
            lifecycle: (has_unresolved || unfinished_handle.is_some())
                .then(|| Arc::clone(&self.lifecycle)),
            handle: unfinished_handle,
        }
    }

    fn track_unleased(&self, pending: PendingCameraCleanup) -> CleanupMode {
        enqueue_cleanup_task(
            &self.lifecycle,
            CleanupTask {
                pending,
                admission: Weak::new(),
            },
        )
    }
}

impl CameraAdmission {
    fn track_unleased(&self, pending: PendingCameraCleanup) -> CleanupMode {
        enqueue_cleanup_task(
            &self.lifecycle,
            CleanupTask {
                pending,
                admission: Weak::new(),
            },
        )
    }

    fn acquire(&self, timeout: Duration) -> std::result::Result<CameraLease, Response> {
        self.acquire_cancellable(timeout, || false)
            .map_err(|_| Response::error("camera busy"))
    }

    fn acquire_cancellable(
        &self,
        timeout: Duration,
        mut cancelled: impl FnMut() -> bool,
    ) -> std::result::Result<CameraLease, CameraAdmissionError> {
        let deadline = Instant::now() + timeout;
        let mut queue = lock_unpoisoned(&self.shared.queue);
        let ticket = queue.next_ticket;
        queue.next_ticket = queue.next_ticket.wrapping_add(1);
        queue.waiters.push_back(ticket);

        loop {
            if cancelled() {
                remove_waiter(&mut queue.waiters, ticket);
                self.shared.available.notify_all();
                return Err(CameraAdmissionError::Cancelled);
            }
            if !queue.active && queue.waiters.front() == Some(&ticket) {
                queue.waiters.pop_front();
                queue.active = true;
                return Ok(CameraLease {
                    shared: Arc::downgrade(&self.shared),
                    armed: true,
                });
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                remove_waiter(&mut queue.waiters, ticket);
                self.shared.available.notify_all();
                warn!(
                    timeout_secs = timeout.as_secs(),
                    "Timed out waiting for camera admission"
                );
                return Err(CameraAdmissionError::Busy);
            }
            let waited = self
                .shared
                .available
                .wait_timeout(queue, remaining.min(CAMERA_PROFILE_WAIT_POLL));
            let (next_queue, timeout_result) = match waited {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            queue = next_queue;
            if timeout_result.timed_out()
                && Instant::now() >= deadline
                && (queue.active || queue.waiters.front() != Some(&ticket))
            {
                remove_waiter(&mut queue.waiters, ticket);
                self.shared.available.notify_all();
                warn!(
                    timeout_secs = timeout.as_secs(),
                    "Timed out waiting for camera admission"
                );
                return Err(CameraAdmissionError::Busy);
            }
        }
    }

    #[cfg(test)]
    fn handoff(&self, pending: PendingCameraCleanup, lease: CameraLease) -> CleanupMode {
        self.handoff_with_invalidation(pending, lease, None)
    }

    fn handoff_with_invalidation(
        &self,
        pending: PendingCameraCleanup,
        mut lease: CameraLease,
        invalidation: Option<ProfileInvalidation>,
    ) -> CleanupMode {
        if let Some(invalidation) = invalidation {
            invalidation.apply();
        }
        lease.armed = false;
        let task = CleanupTask {
            pending,
            admission: Arc::downgrade(&self.shared),
        };
        enqueue_cleanup_task(&self.lifecycle, task)
    }

    #[cfg(test)]
    fn handoff_with_lifecycle_hook(
        &self,
        pending: PendingCameraCleanup,
        mut lease: CameraLease,
        after_lock: impl FnOnce(),
    ) -> CleanupMode {
        lease.armed = false;
        enqueue_cleanup_task_inner(
            &self.lifecycle,
            CleanupTask {
                pending,
                admission: Arc::downgrade(&self.shared),
            },
            after_lock,
        )
    }

    #[cfg(test)]
    fn queued_waiters(&self) -> usize {
        lock_unpoisoned(&self.shared.queue).waiters.len()
    }

    #[cfg(test)]
    fn state_for_test(&self) -> (bool, usize) {
        let queue = lock_unpoisoned(&self.shared.queue);
        (queue.active, queue.waiters.len())
    }
}

fn enqueue_cleanup_task(lifecycle: &Mutex<ReaperLifecycle>, task: CleanupTask) -> CleanupMode {
    enqueue_cleanup_task_inner(lifecycle, task, || {})
}

fn enqueue_cleanup_task_inner(
    lifecycle: &Mutex<ReaperLifecycle>,
    task: CleanupTask,
    after_lock: impl FnOnce(),
) -> CleanupMode {
    let mut lifecycle = lock_unpoisoned(lifecycle);
    after_lock();
    match &lifecycle.phase {
        ReaperPhase::Stopping => {
            lifecycle.unresolved.push(task);
            CleanupMode::UnresolvedTracked
        }
        ReaperPhase::Running(sender) => {
            // Sending while holding the lifecycle lock serializes this decision
            // with the Running -> Stopping transition; no sender clone escapes.
            if let Err(error) = sender.send(task) {
                lifecycle.phase = ReaperPhase::Stopping;
                lifecycle.unresolved.push(error.0);
                CleanupMode::UnresolvedTracked
            } else {
                CleanupMode::ReaperHandoff
            }
        }
    }
}

fn reap_completed_unresolved_tasks(lifecycle: &Mutex<ReaperLifecycle>) {
    let mut lifecycle = lock_unpoisoned(lifecycle);
    let mut index = 0;
    while index < lifecycle.unresolved.len() {
        if let Some(exit) = lifecycle.unresolved[index].pending.try_complete() {
            let task = lifecycle.unresolved.swap_remove(index);
            if exit == WorkerExit::FailedPanicked {
                error!("Camera worker panicked during final unresolved cleanup reap");
            }
            release_camera_admission(&task.admission);
        } else {
            index += 1;
        }
    }
}

fn remove_waiter(waiters: &mut VecDeque<u64>, ticket: u64) {
    if let Some(index) = waiters.iter().position(|queued| *queued == ticket) {
        waiters.remove(index);
    }
}

impl Drop for CameraLease {
    fn drop(&mut self) {
        if self.armed {
            release_camera_admission(&self.shared);
            self.armed = false;
        }
    }
}

fn release_camera_admission(shared: &Weak<CameraAdmissionShared>) {
    if let Some(shared) = shared.upgrade() {
        lock_unpoisoned(&shared.queue).active = false;
        shared.available.notify_all();
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupMode {
    NotApplicable,
    Synchronous,
    ReaperHandoff,
    UnresolvedTracked,
    FailedPanicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseCleanupOrder {
    BeforeWrite,
    AfterWrite,
}

trait PanicResponseWriter {
    fn response_write_started(&self) -> bool;
    fn write_response(&mut self, response: &Response) -> Result<()>;
}

struct ConnectionIo {
    stream: UnixStream,
    response_write_started: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
struct PendingPromptRecord {
    username: String,
    target_uid: u32,
    peer_uid: u32,
    connection_id: Option<ConnectionId>,
    transaction_token: Zeroizing<[u8; protocol::PROMPT_TOKEN_BYTES]>,
    client_nonce: Zeroizing<[u8; protocol::PROMPT_NONCE_BYTES]>,
    pam_service: String,
    origin: protocol::PromptOriginV1,
    prompt_timeout_ms: u32,
    commit_response_timeout_ms: u32,
    issue: Option<PendingIssue>,
    claim: Option<CommitClaim>,
}

#[cfg(test)]
impl PartialEq for PendingPromptRecord {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
            && self.target_uid == other.target_uid
            && self.peer_uid == other.peer_uid
            && self.connection_id == other.connection_id
            && self.transaction_token.as_ref() == other.transaction_token.as_ref()
            && self.client_nonce.as_ref() == other.client_nonce.as_ref()
            && self.pam_service == other.pam_service
            && self.origin == other.origin
            && self.prompt_timeout_ms == other.prompt_timeout_ms
            && self.commit_response_timeout_ms == other.commit_response_timeout_ms
    }
}

#[cfg(test)]
impl Eq for PendingPromptRecord {}

#[cfg(test)]
impl Clone for PendingPromptRecord {
    fn clone(&self) -> Self {
        assert!(
            self.issue.is_none(),
            "managed pending prompt records are never cloned"
        );
        Self {
            username: self.username.clone(),
            target_uid: self.target_uid,
            peer_uid: self.peer_uid,
            connection_id: self.connection_id,
            transaction_token: Zeroizing::new(*self.transaction_token),
            client_nonce: Zeroizing::new(*self.client_nonce),
            pam_service: self.pam_service.clone(),
            origin: self.origin,
            prompt_timeout_ms: self.prompt_timeout_ms,
            commit_response_timeout_ms: self.commit_response_timeout_ms,
            issue: None,
            claim: None,
        }
    }
}

impl std::fmt::Debug for PendingPromptRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingPromptRecord")
            .field("username", &self.username)
            .field("target_uid", &self.target_uid)
            .field("peer_uid", &self.peer_uid)
            .field("connection_id", &self.connection_id)
            .field("transaction_token", &"[REDACTED]")
            .field("client_nonce", &"[REDACTED]")
            .field("pam_service", &self.pam_service)
            .field("origin", &self.origin)
            .field("prompt_timeout_ms", &self.prompt_timeout_ms)
            .field(
                "commit_response_timeout_ms",
                &self.commit_response_timeout_ms,
            )
            .finish()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl PendingPromptRecord {
    fn new(
        username: impl Into<String>,
        transaction_token: Zeroizing<[u8; protocol::PROMPT_TOKEN_BYTES]>,
        client_nonce: Zeroizing<[u8; protocol::PROMPT_NONCE_BYTES]>,
        prompt_timeout_ms: u32,
        commit_response_timeout_ms: u32,
    ) -> std::result::Result<Self, protocol::PromptValidationError> {
        let record = Self {
            username: username.into(),
            target_uid: 0,
            peer_uid: 0,
            connection_id: None,
            transaction_token,
            client_nonce,
            pam_service: "sudo".to_string(),
            origin: protocol::PromptOriginV1::Local,
            prompt_timeout_ms,
            commit_response_timeout_ms,
            issue: None,
            claim: None,
        };
        if !(protocol::PROMPT_TIMEOUT_MS_MIN..=protocol::PROMPT_TIMEOUT_MS_MAX)
            .contains(&record.prompt_timeout_ms)
            || !(protocol::COMMIT_RESPONSE_TIMEOUT_MS_MIN
                ..=protocol::COMMIT_RESPONSE_TIMEOUT_MS_MAX)
                .contains(&record.commit_response_timeout_ms)
        {
            return Err(protocol::PromptValidationError::Malformed);
        }
        Ok(record)
    }

    fn managed(
        identity: crate::authorization::CanonicalIdentity,
        peer_uid: u32,
        connection_id: ConnectionId,
        client_nonce: Zeroizing<[u8; protocol::PROMPT_NONCE_BYTES]>,
        pam_service: String,
        origin: protocol::PromptOriginV1,
        prompt_timeout_ms: u32,
        commit_response_timeout_ms: u32,
        issue: PendingIssue,
    ) -> std::result::Result<Self, protocol::PromptValidationError> {
        let mut transaction_token = Zeroizing::new([0u8; protocol::PROMPT_TOKEN_BYTES]);
        transaction_token.copy_from_slice(issue.token());
        let mut record = Self::new(
            identity.username(),
            transaction_token,
            client_nonce,
            prompt_timeout_ms,
            commit_response_timeout_ms,
        )?;
        record.target_uid = identity.uid();
        record.peer_uid = peer_uid;
        record.connection_id = Some(connection_id);
        record.pam_service = pam_service;
        record.origin = origin;
        record.issue = Some(issue);
        Ok(record)
    }

    fn prompt_response(&self) -> SensitivePromptResponse {
        SensitivePromptResponse::prompt_required(
            &self.transaction_token,
            &self.client_nonce,
            self.prompt_timeout_ms,
            self.commit_response_timeout_ms,
        )
    }

    fn client_nonce(&self) -> &[u8; protocol::PROMPT_NONCE_BYTES] {
        &self.client_nonce
    }

    fn activate(
        &mut self,
        shutdown_waker: Option<UnixStream>,
    ) -> std::result::Result<Instant, PromptStateError> {
        match self.issue.as_mut() {
            Some(issue) => issue.activate_with_waker(shutdown_waker),
            None => Instant::now()
                .checked_add(Duration::from_millis(u64::from(self.prompt_timeout_ms)))
                .ok_or(PromptStateError::Unavailable),
        }
    }

    fn claim_commit(
        &mut self,
        token: &[u8; protocol::PROMPT_TOKEN_BYTES],
        nonce: &[u8; protocol::PROMPT_NONCE_BYTES],
    ) -> std::result::Result<(), PromptStateError> {
        let Some(issue) = self.issue.take() else {
            return if constant_time_eq(token, &self.transaction_token)
                && constant_time_eq(nonce, &self.client_nonce)
            {
                Ok(())
            } else {
                Err(PromptStateError::Invalid)
            };
        };
        let claim = issue.claim_commit(token, nonce, self.peer_uid, self.target_uid)?;
        self.claim = Some(claim);
        Ok(())
    }

    fn cancel(
        &mut self,
        token: &[u8; protocol::PROMPT_TOKEN_BYTES],
        nonce: &[u8; protocol::PROMPT_NONCE_BYTES],
    ) -> std::result::Result<(), PromptStateError> {
        let Some(issue) = self.issue.take() else {
            return if constant_time_eq(token, &self.transaction_token)
                && constant_time_eq(nonce, &self.client_nonce)
            {
                Ok(())
            } else {
                Err(PromptStateError::Invalid)
            };
        };
        issue.cancel(token, nonce, self.peer_uid, self.target_uid)
    }

    fn manager_terminated(&self) -> bool {
        self.issue
            .as_ref()
            .is_some_and(PendingIssue::manager_terminated)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
enum PromptConnectionPhase {
    Initial,
    Pending(PendingPromptRecord),
    Committed,
    Closed,
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg_attr(test, derive(PartialEq))]
enum PromptConnectionAction {
    SendPrompt(SensitivePromptResponse),
    StartAuthentication(PendingPromptRecord),
    SendTerminal(SensitivePromptResponse),
    CancelActiveAndSendTerminal(SensitivePromptResponse),
    CancelActiveWithoutResponse,
    CloseWithoutResponse,
}

impl std::fmt::Debug for PromptConnectionAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SendPrompt(_) => "SendPrompt([REDACTED])",
            Self::StartAuthentication(_) => "StartAuthentication([REDACTED])",
            Self::SendTerminal(_) => "SendTerminal([REDACTED])",
            Self::CancelActiveAndSendTerminal(_) => "CancelActiveAndSendTerminal([REDACTED])",
            Self::CancelActiveWithoutResponse => "CancelActiveWithoutResponse",
            Self::CloseWithoutResponse => "CloseWithoutResponse",
        })
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
struct PromptConnectionMachine {
    phase: PromptConnectionPhase,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PromptConnectionMachine {
    fn new() -> Self {
        Self {
            phase: PromptConnectionPhase::Initial,
        }
    }

    fn begin_with(
        &mut self,
        request: &protocol::BeginAuthV1Req,
        issue: impl FnOnce(
            &protocol::BeginAuthV1Req,
        )
            -> std::result::Result<PendingPromptRecord, protocol::PromptErrorCode>,
    ) -> PromptConnectionAction {
        if !matches!(self.phase, PromptConnectionPhase::Initial) {
            return self.terminal_protocol_violation(false);
        }
        if let Err(error) = request.validate() {
            self.phase = PromptConnectionPhase::Closed;
            return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                Response::prompt_error(error.prompt_error()),
            ));
        }
        let pending = match issue(request) {
            Ok(pending) => pending,
            Err(code) => {
                self.phase = PromptConnectionPhase::Closed;
                return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                    Response::prompt_error(code),
                ));
            }
        };
        let mut request_nonce = Zeroizing::new([0u8; protocol::PROMPT_NONCE_BYTES]);
        request_nonce.copy_from_slice(&request.client_nonce);
        let binding_matches = pending.username == request.username
            && constant_time_eq(&pending.client_nonce, &request_nonce);
        if !binding_matches {
            self.phase = PromptConnectionPhase::Closed;
            return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                Response::prompt_error(protocol::PromptErrorCode::TransactionInvalid),
            ));
        }
        let response = pending.prompt_response();
        self.phase = PromptConnectionPhase::Pending(pending);
        PromptConnectionAction::SendPrompt(response)
    }

    fn receive(&mut self, request: &Request) -> PromptConnectionAction {
        let phase = std::mem::replace(&mut self.phase, PromptConnectionPhase::Closed);
        match phase {
            PromptConnectionPhase::Initial => self.terminal_protocol_violation(false),
            PromptConnectionPhase::Pending(mut pending) => match request.cmd.as_ref() {
                Some(Cmd::CommitAuthV1(commit)) => {
                    if let Err(error) = commit.validate() {
                        self.phase = PromptConnectionPhase::Closed;
                        return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                            Response::prompt_error(error.prompt_error()),
                        ));
                    }
                    let token: &[u8; protocol::PROMPT_TOKEN_BYTES] = commit
                        .transaction_token
                        .as_slice()
                        .try_into()
                        .expect("validated prompt token length");
                    let nonce: &[u8; protocol::PROMPT_NONCE_BYTES] = commit
                        .client_nonce
                        .as_slice()
                        .try_into()
                        .expect("validated prompt nonce length");
                    if pending.claim_commit(token, nonce).is_err() {
                        self.phase = PromptConnectionPhase::Closed;
                        return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                            Response::prompt_error(protocol::PromptErrorCode::TransactionInvalid),
                        ));
                    }
                    self.phase = PromptConnectionPhase::Committed;
                    PromptConnectionAction::StartAuthentication(pending)
                }
                Some(Cmd::CancelAuthV1(cancel)) => {
                    if let Err(error) = cancel.validate() {
                        self.phase = PromptConnectionPhase::Closed;
                        return PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                            Response::prompt_error(error.prompt_error()),
                        ));
                    }
                    let token: &[u8; protocol::PROMPT_TOKEN_BYTES] = cancel
                        .transaction_token
                        .as_slice()
                        .try_into()
                        .expect("validated prompt token length");
                    let supplied_nonce: &[u8; protocol::PROMPT_NONCE_BYTES] = cancel
                        .client_nonce
                        .as_slice()
                        .try_into()
                        .expect("validated prompt nonce length");
                    let response = match pending.cancel(token, supplied_nonce) {
                        Ok(()) => {
                            return PromptConnectionAction::SendTerminal(
                                SensitivePromptResponse::auth_cancelled(pending.client_nonce()),
                            );
                        }
                        Err(_) => {
                            Response::prompt_error(protocol::PromptErrorCode::TransactionInvalid)
                        }
                    };
                    PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(response))
                }
                _ => self.terminal_protocol_violation(false),
            },
            PromptConnectionPhase::Committed => self.terminal_protocol_violation(true),
            PromptConnectionPhase::Closed => PromptConnectionAction::CloseWithoutResponse,
        }
    }

    fn prompt_sent(&mut self) -> std::result::Result<Instant, PromptConnectionAction> {
        self.prompt_sent_with_waker(None)
    }

    fn prompt_sent_with_waker(
        &mut self,
        shutdown_waker: Option<UnixStream>,
    ) -> std::result::Result<Instant, PromptConnectionAction> {
        let PromptConnectionPhase::Pending(pending) = &mut self.phase else {
            return Err(self.terminal_protocol_violation(false));
        };
        pending.activate(shutdown_waker).map_err(|_| {
            self.phase = PromptConnectionPhase::Closed;
            PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                Response::prompt_error(protocol::PromptErrorCode::TransactionInvalid),
            ))
        })
    }

    fn pending_manager_terminated(&self) -> bool {
        matches!(&self.phase, PromptConnectionPhase::Pending(pending) if pending.manager_terminated())
    }

    fn finish_authentication(&mut self, response: Response) -> PromptConnectionAction {
        match self.phase {
            PromptConnectionPhase::Committed => {
                self.phase = PromptConnectionPhase::Closed;
                if protocol::is_prompt_auth_terminal_response(&response) {
                    PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(response))
                } else {
                    PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(
                        Response::prompt_error(protocol::PromptErrorCode::Violation),
                    ))
                }
            }
            PromptConnectionPhase::Closed => PromptConnectionAction::CloseWithoutResponse,
            PromptConnectionPhase::Initial | PromptConnectionPhase::Pending(_) => {
                self.terminal_protocol_violation(false)
            }
        }
    }

    fn eof(&mut self) -> PromptConnectionAction {
        match self.phase {
            PromptConnectionPhase::Committed => {
                self.phase = PromptConnectionPhase::Closed;
                PromptConnectionAction::CancelActiveWithoutResponse
            }
            PromptConnectionPhase::Initial | PromptConnectionPhase::Pending(_) => {
                self.phase = PromptConnectionPhase::Closed;
                PromptConnectionAction::CloseWithoutResponse
            }
            PromptConnectionPhase::Closed => PromptConnectionAction::CloseWithoutResponse,
        }
    }

    fn terminal_protocol_violation(&mut self, cancel_active: bool) -> PromptConnectionAction {
        self.phase = PromptConnectionPhase::Closed;
        let response = Response::prompt_error(protocol::PromptErrorCode::Violation);
        if cancel_active {
            PromptConnectionAction::CancelActiveAndSendTerminal(SensitivePromptResponse::new(
                response,
            ))
        } else {
            PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(response))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PromptCoordinatorReport {
    prompt_response_attempts: u8,
    terminal_response_attempts: u8,
    authentication_started: bool,
}

struct PromptWorkerTerminal {
    response: Response,
    cleanup_mode: CleanupMode,
    cache_promotion: Option<Box<dyn AuthenticationCachePromotion>>,
}

struct PromptWorkerCompletion {
    terminal: PromptWorkerTerminal,
    _lease: Option<ActiveLease>,
}

struct PostWriteCachePromotion {
    promotion: Box<dyn AuthenticationCachePromotion>,
    cancellation: ActiveCancellation,
    work_deadline: Instant,
    _lease: Option<ActiveLease>,
}

impl PostWriteCachePromotion {
    fn finish_after_successful_write(self, stream: &UnixStream, shutdown: &ShutdownSignal) {
        let Self {
            promotion,
            cancellation,
            work_deadline,
            _lease,
        } = self;
        let Ok(monitor_stream) = stream.try_clone() else {
            return;
        };
        let monitor_cancellation = cancellation.clone();
        let monitor_shutdown = shutdown.clone();
        let monitor_done = Arc::new(AtomicBool::new(false));
        let monitor_worker_done = Arc::clone(&monitor_done);
        let monitor = std::thread::Builder::new()
            .name("howy-cache-publish-monitor".to_string())
            .spawn(move || {
                while !monitor_worker_done.load(Ordering::Acquire) {
                    if !matches!(
                        inspect_active_socket(&monitor_stream, ACTIVE_SUPERVISOR_POLL),
                        Ok(ActiveSocketEvent::Quiet)
                    ) || monitor_shutdown.is_requested()
                        || Instant::now() >= work_deadline
                    {
                        monitor_cancellation.cancel();
                    }
                }
            });
        let Ok(monitor) = monitor else {
            return;
        };

        // The response is already written, but supervision remains active
        // until the backend evaluates `publish` under its cache lock. HUP after
        // that linearization point is deliberately post-publication.
        let mut publish = || {
            matches!(
                inspect_active_socket(stream, Duration::ZERO),
                Ok(ActiveSocketEvent::Quiet)
            ) && !shutdown.is_requested()
                && Instant::now() < work_deadline
                && !cancellation.is_cancelled()
        };
        let result = promotion.promote_if(&mut publish);
        monitor_done.store(true, Ordering::Release);
        drop(_lease);
        let _ = monitor.join();
        match result {
            Ok(true) => debug!("Published accepted prompt authentication cache load"),
            Ok(false) => debug!("Skipped stale prompt authentication cache promotion"),
            Err(error) => warn!(%error, "Prompt authentication cache promotion failed"),
        }
    }
}

struct SupervisedPromptAction {
    action: PromptConnectionAction,
    post_write_promotion: Option<PostWriteCachePromotion>,
}

impl SupervisedPromptAction {
    fn without_promotion(action: PromptConnectionAction) -> Self {
        Self {
            action,
            post_write_promotion: None,
        }
    }
}

fn response_allows_cache_promotion(response: &Response) -> bool {
    matches!(
        response.result,
        Some(RespResult::Success(_) | RespResult::AuthFailed(_))
    )
}

struct ActivePromptAuthentication {
    cancellation: ActiveCancellation,
    deadline: Instant,
    result_rx: mpsc::Receiver<PromptWorkerCompletion>,
    handle: Option<std::thread::JoinHandle<()>>,
}

enum PromptAuthentication {
    Completed(Response),
    Active(ActivePromptAuthentication),
}

impl From<Response> for PromptAuthentication {
    fn from(response: Response) -> Self {
        Self::Completed(response)
    }
}

#[cfg(test)]
fn spawn_prompt_authentication(
    lease: ActiveLease,
    run: impl FnOnce(&ActiveLease) -> PromptWorkerTerminal + Send + 'static,
) -> PromptAuthentication {
    let cancellation = lease.cancellation();
    let deadline = lease.deadline();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("howy-prompt-auth".to_string())
        .spawn(move || {
            let terminal = catch_unwind(AssertUnwindSafe(|| run(&lease))).unwrap_or_else(|_| {
                PromptWorkerTerminal {
                    response: Response::error("authentication unavailable"),
                    cleanup_mode: CleanupMode::FailedPanicked,
                    cache_promotion: None,
                }
            });
            let _ = result_tx.send(PromptWorkerCompletion {
                terminal,
                _lease: Some(lease),
            });
        });
    match worker {
        Ok(handle) => PromptAuthentication::Active(ActivePromptAuthentication {
            cancellation,
            deadline,
            result_rx,
            handle: Some(handle),
        }),
        Err(error) => {
            cancellation.cancel();
            error!(%error, "Failed to spawn committed prompt authentication worker");
            PromptAuthentication::Completed(Response::error("authentication unavailable"))
        }
    }
}

/// Start supervision from the atomically created Commit claim, before NSS,
/// policy, storage, or camera revalidation can block. The claim's control is
/// sufficient for the connection supervisor to cancel the subordinate worker;
/// only that worker may promote it to an active lease.
fn spawn_prompt_authentication_after_revalidation(
    pending: PendingPromptRecord,
    revalidate: impl FnOnce(PendingPromptRecord) -> std::result::Result<ActiveLease, Response>
    + Send
    + 'static,
    run: impl FnOnce(&ActiveLease) -> PromptWorkerTerminal + Send + 'static,
) -> PromptAuthentication {
    let Some(claim) = pending.claim.as_ref() else {
        return PromptAuthentication::Completed(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    };
    let cancellation = claim.cancellation();
    let deadline = claim.deadline();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let worker_cancellation = cancellation.clone();
    let worker = std::thread::Builder::new()
        .name("howy-prompt-auth".to_string())
        .spawn(move || {
            let (terminal, lease) = catch_unwind(AssertUnwindSafe(|| match revalidate(pending) {
                Ok(lease) => {
                    let terminal = run(&lease);
                    (terminal, Some(lease))
                }
                Err(response) => (
                    prompt_worker_terminal(response, CleanupMode::NotApplicable),
                    None,
                ),
            }))
            .unwrap_or_else(|_| {
                (
                    PromptWorkerTerminal {
                        response: Response::error("authentication unavailable"),
                        cleanup_mode: CleanupMode::FailedPanicked,
                        cache_promotion: None,
                    },
                    None,
                )
            });
            let _ = result_tx.send(PromptWorkerCompletion {
                terminal,
                _lease: lease,
            });
        });
    match worker {
        Ok(handle) => PromptAuthentication::Active(ActivePromptAuthentication {
            cancellation,
            deadline,
            result_rx,
            handle: Some(handle),
        }),
        Err(error) => {
            worker_cancellation.cancel();
            error!(%error, "Failed to spawn committed prompt revalidation worker");
            PromptAuthentication::Completed(Response::error("authentication unavailable"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveSocketEvent {
    Quiet,
    PeerGone,
    UnexpectedData,
    Infrastructure,
}

fn inspect_active_socket(stream: &UnixStream, timeout: Duration) -> io::Result<ActiveSocketEvent> {
    // Floor rather than round up: this poll must never sleep beyond the
    // supervisor's remaining monotonic work budget.
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    // SAFETY: descriptor points to one live pollfd for the duration of poll.
    let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(ActiveSocketEvent::Quiet);
        }
        return Err(error);
    }
    if ready == 0 {
        return Ok(ActiveSocketEvent::Quiet);
    }
    if descriptor.revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Ok(ActiveSocketEvent::PeerGone);
    }
    if descriptor.revents & libc::POLLERR != 0 {
        return Ok(ActiveSocketEvent::Infrastructure);
    }
    if descriptor.revents & libc::POLLIN != 0 {
        let mut byte = [0u8; 1];
        // SAFETY: byte is a live writable one-byte buffer and the socket fd is
        // borrowed for this non-consuming, nonblocking receive.
        let received = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if received > 0 {
            return Ok(ActiveSocketEvent::UnexpectedData);
        }
        if received == 0 {
            return Ok(ActiveSocketEvent::PeerGone);
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(ActiveSocketEvent::Quiet);
        }
        return Ok(ActiveSocketEvent::Infrastructure);
    }
    Ok(ActiveSocketEvent::Quiet)
}

fn active_socket_writable(stream: &UnixStream) -> bool {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLOUT | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    // SAFETY: descriptor points to one live pollfd for the duration of poll.
    let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
    ready > 0
        && descriptor.revents & libc::POLLOUT != 0
        && descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0
}

fn join_completed_active_worker(active: &mut ActivePromptAuthentication) {
    let Some(handle) = active.handle.take() else {
        return;
    };
    if handle.join().is_err() {
        error!("Prompt authentication worker escaped panic containment");
    }
}

fn finish_cancelled_active_worker(
    active: &mut ActivePromptAuthentication,
    cleanup_deadline: Instant,
    shutdown: &ShutdownSignal,
) -> bool {
    let Some(handle) = active.handle.take() else {
        return true;
    };
    while !handle.is_finished() && Instant::now() < cleanup_deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if handle.is_finished() {
        if handle.join().is_err() {
            error!("Prompt authentication worker escaped panic containment");
        }
        true
    } else {
        error!("Prompt authentication cleanup exceeded its bound; failing daemon run");
        shutdown.request_fatal_with_worker(handle);
        false
    }
}

fn active_work_deadline(active_deadline: Instant) -> Instant {
    active_deadline
        .checked_sub(ACTIVE_WORKER_CLEANUP_TIMEOUT)
        .unwrap_or(active_deadline)
}

fn active_poll_timeout(now: Instant, work_deadline: Instant) -> Duration {
    ACTIVE_SUPERVISOR_POLL.min(work_deadline.saturating_duration_since(now))
}

fn active_cleanup_deadline(active_deadline: Instant) -> Instant {
    Instant::now()
        .checked_add(ACTIVE_WORKER_CLEANUP_TIMEOUT)
        .unwrap_or(active_deadline)
        .min(active_deadline)
}

fn supervise_active_authentication(
    stream: &UnixStream,
    shutdown: &ShutdownSignal,
    machine: &mut PromptConnectionMachine,
    mut active: ActivePromptAuthentication,
) -> SupervisedPromptAction {
    enum Winner {
        PeerGone,
        ProtocolViolation,
        Infrastructure,
        Worker(PromptWorkerCompletion),
    }

    let work_deadline = active_work_deadline(active.deadline);
    let winner = loop {
        // Socket state has deterministic precedence over every same-iteration
        // completion. HUP wins over buffered data, then protocol data, daemon
        // shutdown, absolute deadline, and finally the worker result.
        let now = Instant::now();
        match inspect_active_socket(stream, active_poll_timeout(now, work_deadline)) {
            Ok(ActiveSocketEvent::PeerGone) => break Winner::PeerGone,
            Ok(ActiveSocketEvent::UnexpectedData) => break Winner::ProtocolViolation,
            Ok(ActiveSocketEvent::Infrastructure) | Err(_) => break Winner::Infrastructure,
            Ok(ActiveSocketEvent::Quiet) => {}
        }
        if shutdown.is_requested() {
            break Winner::Infrastructure;
        }
        if Instant::now() >= work_deadline {
            break Winner::Infrastructure;
        }
        if active.cancellation.is_cancelled() {
            break Winner::Infrastructure;
        }
        match active.result_rx.try_recv() {
            Ok(terminal) => {
                match inspect_active_socket(stream, Duration::ZERO) {
                    Ok(ActiveSocketEvent::PeerGone) => break Winner::PeerGone,
                    Ok(ActiveSocketEvent::UnexpectedData) => break Winner::ProtocolViolation,
                    Ok(ActiveSocketEvent::Infrastructure) | Err(_) => {
                        break Winner::Infrastructure;
                    }
                    Ok(ActiveSocketEvent::Quiet) => {}
                }
                if shutdown.is_requested()
                    || Instant::now() >= work_deadline
                    || active.cancellation.is_cancelled()
                {
                    break Winner::Infrastructure;
                }
                break Winner::Worker(terminal);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => break Winner::Infrastructure,
        }
    };

    match winner {
        Winner::Worker(completion) => {
            join_completed_active_worker(&mut active);
            let final_socket = inspect_active_socket(stream, Duration::ZERO);
            if matches!(final_socket, Ok(ActiveSocketEvent::PeerGone)) {
                active.cancellation.cancel();
                return SupervisedPromptAction::without_promotion(machine.eof());
            }
            if matches!(final_socket, Ok(ActiveSocketEvent::UnexpectedData)) {
                active.cancellation.cancel();
                let action = if active_socket_writable(stream) {
                    machine.terminal_protocol_violation(true)
                } else {
                    machine.eof()
                };
                return SupervisedPromptAction::without_promotion(action);
            }
            if final_socket.is_err()
                || matches!(final_socket, Ok(ActiveSocketEvent::Infrastructure))
                || shutdown.is_requested()
                || Instant::now() >= work_deadline
                || active.cancellation.is_cancelled()
            {
                active.cancellation.cancel();
                let action = if active_socket_writable(stream) {
                    machine.finish_authentication(Response::error("authentication unavailable"))
                } else {
                    machine.eof()
                };
                return SupervisedPromptAction::without_promotion(action);
            }
            let PromptWorkerCompletion {
                mut terminal,
                _lease,
            } = completion;
            let post_write_promotion = if response_allows_cache_promotion(&terminal.response) {
                terminal
                    .cache_promotion
                    .take()
                    .map(|promotion| PostWriteCachePromotion {
                        promotion,
                        cancellation: active.cancellation.clone(),
                        work_deadline,
                        _lease,
                    })
            } else {
                terminal.cache_promotion.take();
                None
            };
            debug!(
                cleanup_mode = terminal.cleanup_mode.as_str(),
                "Committed prompt worker finished"
            );
            SupervisedPromptAction {
                action: machine.finish_authentication(terminal.response),
                post_write_promotion,
            }
        }
        Winner::PeerGone => {
            active.cancellation.cancel();
            let cleanup_deadline = active_cleanup_deadline(active.deadline);
            if !finish_cancelled_active_worker(&mut active, cleanup_deadline, shutdown) {
                return SupervisedPromptAction::without_promotion(machine.eof());
            }
            SupervisedPromptAction::without_promotion(machine.eof())
        }
        Winner::ProtocolViolation => {
            active.cancellation.cancel();
            let cleanup_deadline = active_cleanup_deadline(active.deadline);
            if !finish_cancelled_active_worker(&mut active, cleanup_deadline, shutdown) {
                return SupervisedPromptAction::without_promotion(machine.eof());
            }
            let action = if active_socket_writable(stream) {
                machine.terminal_protocol_violation(true)
            } else {
                machine.eof()
            };
            SupervisedPromptAction::without_promotion(action)
        }
        Winner::Infrastructure => {
            active.cancellation.cancel();
            let cleanup_deadline = active_cleanup_deadline(active.deadline);
            if !finish_cancelled_active_worker(&mut active, cleanup_deadline, shutdown) {
                return SupervisedPromptAction::without_promotion(machine.eof());
            }
            let action = if active_socket_writable(stream) {
                machine.finish_authentication(Response::error("authentication unavailable"))
            } else {
                machine.eof()
            };
            SupervisedPromptAction::without_promotion(action)
        }
    }
}

#[cfg(test)]
fn coordinate_prompt_connection(
    io: &mut ConnectionIo,
    initial_request: Option<Request>,
    prepare_pending: impl FnOnce(
        &protocol::BeginAuthV1Req,
    )
        -> std::result::Result<PendingPromptRecord, protocol::PromptErrorCode>,
    authenticate: impl FnOnce(PendingPromptRecord) -> Response,
) -> Result<PromptCoordinatorReport> {
    coordinate_prompt_connection_with_shutdown(
        io,
        initial_request,
        prepare_pending,
        authenticate,
        &ShutdownSignal::new(),
    )
}

fn coordinate_prompt_connection_with_shutdown<R>(
    io: &mut ConnectionIo,
    initial_request: Option<Request>,
    prepare_pending: impl FnOnce(
        &protocol::BeginAuthV1Req,
    )
        -> std::result::Result<PendingPromptRecord, protocol::PromptErrorCode>,
    authenticate: impl FnOnce(PendingPromptRecord) -> R,
    shutdown: &ShutdownSignal,
) -> Result<PromptCoordinatorReport>
where
    R: Into<PromptAuthentication>,
{
    let request = SensitivePromptRequest::new(match initial_request {
        Some(request) => request,
        None => ipc::recv_prompt_message(&mut io.stream)?,
    });
    let mut machine = PromptConnectionMachine::new();
    let mut report = PromptCoordinatorReport::default();
    let mut authenticate = Some(authenticate);
    let mut post_write_promotion = None;
    let mut action = match request.as_ref().cmd.as_ref() {
        Some(Cmd::BeginAuthV1(begin)) => machine.begin_with(begin, prepare_pending),
        _ => machine.receive(request.as_ref()),
    };
    drop(request);

    loop {
        action = match action {
            PromptConnectionAction::SendPrompt(response) => {
                report.prompt_response_attempts = report.prompt_response_attempts.saturating_add(1);
                let write = io.write_response(&response.0);
                if let Err(error) = write {
                    let _ = machine.eof();
                    return Err(error);
                }
                let shutdown_waker = match io.stream.try_clone() {
                    Ok(stream) => Some(stream),
                    Err(error) => {
                        let _ = machine.eof();
                        return Err(error.into());
                    }
                };
                match machine.prompt_sent_with_waker(shutdown_waker) {
                    Err(action) => action,
                    Ok(deadline) => {
                        match ipc::recv_prompt_message_until(&mut io.stream, deadline, || {
                            machine.pending_manager_terminated()
                        }) {
                            Ok(request) => {
                                let request = SensitivePromptRequest::new(request);
                                let action = machine.receive(request.as_ref());
                                action
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                                machine.terminal_protocol_violation(false)
                            }
                            Err(_) => {
                                let _ = machine.eof();
                                return Ok(report);
                            }
                        }
                    }
                }
            }
            PromptConnectionAction::StartAuthentication(pending) => {
                report.authentication_started = true;
                let run = authenticate
                    .take()
                    .expect("prompt authentication starts at most once");
                match run(pending).into() {
                    PromptAuthentication::Completed(response) => {
                        machine.finish_authentication(response)
                    }
                    PromptAuthentication::Active(active) => {
                        let supervised = supervise_active_authentication(
                            &io.stream,
                            shutdown,
                            &mut machine,
                            active,
                        );
                        post_write_promotion = supervised.post_write_promotion;
                        supervised.action
                    }
                }
            }
            PromptConnectionAction::SendTerminal(response)
            | PromptConnectionAction::CancelActiveAndSendTerminal(response) => {
                report.terminal_response_attempts =
                    report.terminal_response_attempts.saturating_add(1);
                let write = io.write_response(&response.0);
                if write.is_ok() {
                    if let Some(promotion) = post_write_promotion.take() {
                        promotion.finish_after_successful_write(&io.stream, shutdown);
                    }
                }
                write?;
                return Ok(report);
            }
            PromptConnectionAction::CancelActiveWithoutResponse
            | PromptConnectionAction::CloseWithoutResponse => return Ok(report),
        };
    }
}

struct SensitivePromptRequest(Option<Request>);

impl SensitivePromptRequest {
    fn new(request: Request) -> Self {
        Self(Some(request))
    }

    fn as_ref(&self) -> &Request {
        self.0.as_ref().expect("sensitive request remains owned")
    }

    fn take(mut self) -> Request {
        self.0.take().expect("sensitive request remains owned")
    }
}

impl Drop for SensitivePromptRequest {
    fn drop(&mut self) {
        if let Some(request) = self.0.as_mut() {
            zeroize_prompt_request(request);
        }
    }
}

struct SensitivePromptResponse(Response);

impl SensitivePromptResponse {
    fn new(response: Response) -> Self {
        Self(response)
    }

    fn prompt_required(
        transaction_token: &[u8; protocol::PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; protocol::PROMPT_NONCE_BYTES],
        prompt_timeout_ms: u32,
        commit_response_timeout_ms: u32,
    ) -> Self {
        let mut token = Zeroizing::new(transaction_token.to_vec());
        let mut nonce = Zeroizing::new(client_nonce.to_vec());
        Self::new(Response {
            result: Some(RespResult::PromptRequiredV1(protocol::PromptRequiredV1 {
                protocol_version: protocol::PROMPT_PROTOCOL_VERSION,
                transaction_token: std::mem::take(&mut *token),
                client_nonce: std::mem::take(&mut *nonce),
                prompt_timeout_ms,
                commit_response_timeout_ms,
            })),
        })
    }

    fn auth_cancelled(client_nonce: &[u8; protocol::PROMPT_NONCE_BYTES]) -> Self {
        let mut nonce = Zeroizing::new(client_nonce.to_vec());
        Self::new(Response {
            result: Some(RespResult::AuthCancelledV1(protocol::AuthCancelledV1 {
                protocol_version: protocol::PROMPT_PROTOCOL_VERSION,
                client_nonce: std::mem::take(&mut *nonce),
            })),
        })
    }
}

impl PartialEq for SensitivePromptResponse {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SensitivePromptResponse {}

impl Drop for SensitivePromptResponse {
    fn drop(&mut self) {
        zeroize_prompt_response(&mut self.0);
    }
}

fn zeroize_prompt_request(request: &mut Request) {
    match request.cmd.as_mut() {
        Some(Cmd::BeginAuthV1(begin)) => begin.client_nonce.zeroize(),
        Some(Cmd::CommitAuthV1(commit)) => {
            commit.transaction_token.zeroize();
            commit.client_nonce.zeroize();
        }
        Some(Cmd::CancelAuthV1(cancel)) => {
            cancel.transaction_token.zeroize();
            cancel.client_nonce.zeroize();
        }
        _ => {}
    }
}

fn zeroize_prompt_response(response: &mut Response) {
    match response.result.as_mut() {
        Some(RespResult::PromptRequiredV1(prompt)) => {
            prompt.transaction_token.zeroize();
            prompt.client_nonce.zeroize();
        }
        Some(RespResult::AuthCancelledV1(cancelled)) => cancelled.client_nonce.zeroize(),
        _ => {}
    }
}

#[cfg(test)]
fn prompt_request_fields_are_zero(request: &Request) -> bool {
    match request.cmd.as_ref() {
        Some(Cmd::BeginAuthV1(begin)) => begin.client_nonce.iter().all(|byte| *byte == 0),
        Some(Cmd::CommitAuthV1(commit)) => {
            commit.transaction_token.iter().all(|byte| *byte == 0)
                && commit.client_nonce.iter().all(|byte| *byte == 0)
        }
        Some(Cmd::CancelAuthV1(cancel)) => {
            cancel.transaction_token.iter().all(|byte| *byte == 0)
                && cancel.client_nonce.iter().all(|byte| *byte == 0)
        }
        _ => true,
    }
}

#[cfg(test)]
fn prompt_response_fields_are_zero(response: &Response) -> bool {
    match response.result.as_ref() {
        Some(RespResult::PromptRequiredV1(prompt)) => {
            prompt.transaction_token.iter().all(|byte| *byte == 0)
                && prompt.client_nonce.iter().all(|byte| *byte == 0)
        }
        Some(RespResult::AuthCancelledV1(cancelled)) => {
            cancelled.client_nonce.iter().all(|byte| *byte == 0)
        }
        _ => true,
    }
}

fn authorize_prompt_begin(
    peer_uid: u32,
    confirmation_required: bool,
    request: &protocol::BeginAuthV1Req,
) -> std::result::Result<crate::authorization::CanonicalIdentity, protocol::PromptErrorCode> {
    authorize_and_then(
        &SystemIdentityResolver,
        Operation::BeginAuth {
            target: &request.username,
        },
        &AuthorizationContext::initial(peer_uid, confirmation_required),
        |authorization| {
            authorization
                .canonical_target()
                .expect("prompt begin authorization resolves a target")
                .clone()
        },
    )
    .map_err(|_| protocol::PromptErrorCode::Unavailable)
}

pub fn prompt_active_timeout(config: &HowyConfig) -> Duration {
    prompt_active_timeout_checked(config)
        .expect("validated prompt machine budgets fit monotonic Duration")
}

fn prompt_active_timeout_checked(config: &HowyConfig) -> Option<Duration> {
    // Commit revalidation, lazy profile acquisition, camera admission/start,
    // and the first successful frame all consume the one advertised
    // commit-to-camera interval. Storage load begins only after camera start,
    // so retain its separate bounded allowance before the scan interval.
    Duration::from_millis(config.presence.commit_to_camera_ms)
        .checked_add(PROMPT_STORAGE_TIMEOUT)?
        .checked_add(Duration::from_millis(config.presence.scan_timeout_ms))?
        .checked_add(ACTIVE_WORKER_CLEANUP_TIMEOUT)
}

fn prompt_commit_response_timeout(config: &HowyConfig) -> Option<Duration> {
    prompt_active_timeout_checked(config)
}

pub const fn prompt_active_capacity() -> usize {
    PROMPT_ACTIVE_LIMIT_FROM_CAMERA_ADMISSION
}

fn prepare_prompt_pending(
    peer_uid: u32,
    connection_id: ConnectionId,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
    manager: &PromptTransactionManager,
    begin: &protocol::BeginAuthV1Req,
) -> std::result::Result<PendingPromptRecord, protocol::PromptErrorCode> {
    let identity = authorize_prompt_begin(peer_uid, true, begin)?;
    validate_prompt_begin_policy(config, begin)?;
    let reservation = manager
        .reserve_begin(connection_id, peer_uid, identity.clone())
        .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    let canonical = CanonicalUsername::new(identity.username().to_owned())
        .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    let storage_snapshot = storage
        .prompt_snapshot(&canonical)
        .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    if storage_snapshot.health() != BackendHealth::Ready
        || !matches!(
            storage_snapshot.candidate(),
            CandidatePresence::Candidate { .. }
        )
    {
        return Err(protocol::PromptErrorCode::Unavailable);
    }
    let policy = begin
        .policy
        .as_ref()
        .ok_or(protocol::PromptErrorCode::Violation)?;
    let origin = protocol::PromptOriginV1::try_from(policy.origin)
        .map_err(|_| protocol::PromptErrorCode::Violation)?;
    let mut client_nonce = Zeroizing::new([0u8; protocol::PROMPT_NONCE_BYTES]);
    client_nonce.copy_from_slice(&begin.client_nonce);
    let mut binding_nonce = Zeroizing::new([0u8; protocol::PROMPT_NONCE_BYTES]);
    binding_nonce.copy_from_slice(&client_nonce[..]);
    let snapshot = SecuritySnapshot::capture(config, storage_snapshot);
    let issue = reservation
        .issue(PendingBinding {
            connection: connection_id,
            peer_uid,
            target: identity.clone(),
            client_nonce: binding_nonce,
            pam_service: policy.pam_service.clone(),
            origin,
            snapshot,
        })
        .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    let prompt_timeout_ms = u32::try_from(config.presence.prompt_timeout_ms)
        .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    let commit_response_timeout_ms = u32::try_from(
        prompt_commit_response_timeout(config)
            .ok_or(protocol::PromptErrorCode::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| protocol::PromptErrorCode::Unavailable)?;
    PendingPromptRecord::managed(
        identity,
        peer_uid,
        connection_id,
        client_nonce,
        policy.pam_service.clone(),
        origin,
        prompt_timeout_ms,
        commit_response_timeout_ms,
        issue,
    )
    .map_err(|_| protocol::PromptErrorCode::Unavailable)
}

#[cfg(test)]
fn finish_prompt_commit_unavailable(
    pending: PendingPromptRecord,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
) -> Response {
    finish_prompt_commit_with(pending, config, storage, |lease| {
        drop(lease);
        Response::prompt_error(protocol::PromptErrorCode::Unavailable)
    })
}

#[cfg(test)]
fn finish_prompt_commit_with(
    pending: PendingPromptRecord,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
    handoff: impl FnOnce(ActiveLease) -> Response,
) -> Response {
    match claim_prompt_commit(pending, config, storage) {
        Ok(lease) => handoff(lease),
        Err(response) => response,
    }
}

fn claim_prompt_commit(
    pending: PendingPromptRecord,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
) -> std::result::Result<ActiveLease, Response> {
    claim_prompt_commit_with_resolver(pending, config, storage, &SystemIdentityResolver)
}

fn claim_prompt_commit_with_resolver<R: crate::authorization::IdentityResolver>(
    mut pending: PendingPromptRecord,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
    resolver: &R,
) -> std::result::Result<ActiveLease, Response> {
    let Some(connection_id) = pending.connection_id else {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    };
    let Some(claim) = pending.claim.take() else {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    };
    let cancellation = claim.cancellation();
    if cancellation.is_cancelled() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    let original_target = claim.target().clone();
    let context = AuthorizationContext {
        peer_uid: claim.peer_uid(),
        confirmation_required: true,
        connection_phase: ConnectionPhase::PendingAuth {
            peer_uid: claim.peer_uid(),
            target: original_target,
        },
    };
    let current_target =
        match authorize_and_then(resolver, Operation::CommitAuth, &context, |authorization| {
            authorization
                .canonical_target()
                .expect("prompt commit authorization resolves a target")
                .clone()
        }) {
            Ok(target) => target,
            Err(_) => {
                return Err(Response::prompt_error(
                    protocol::PromptErrorCode::TransactionInvalid,
                ));
            }
        };
    if cancellation.is_cancelled() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    if validate_current_prompt_policy(config, claim.pam_service(), claim.origin()).is_err() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    let canonical = match CanonicalUsername::new(current_target.username().to_owned()) {
        Ok(canonical) => canonical,
        Err(_) => {
            return Err(Response::prompt_error(
                protocol::PromptErrorCode::TransactionInvalid,
            ));
        }
    };
    if cancellation.is_cancelled() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    let storage_snapshot = match storage.prompt_snapshot(&canonical) {
        Ok(snapshot)
            if snapshot.health() == BackendHealth::Ready
                && matches!(snapshot.candidate(), CandidatePresence::Candidate { .. }) =>
        {
            snapshot
        }
        Ok(_) | Err(_) => {
            return Err(Response::prompt_error(
                protocol::PromptErrorCode::TransactionInvalid,
            ));
        }
    };
    if cancellation.is_cancelled() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    // The backend snapshot call is the storage linearization point. Mutations
    // after it returns are logically post-commit and do not invalidate this claim.
    let snapshot = SecuritySnapshot::capture(config, storage_snapshot);
    if cancellation.is_cancelled() {
        return Err(Response::prompt_error(
            protocol::PromptErrorCode::TransactionInvalid,
        ));
    }
    let lease = claim.promote(CommitBinding {
        connection: connection_id,
        peer_uid: pending.peer_uid,
        target: current_target,
        pam_service: pending.pam_service.clone(),
        origin: pending.origin,
        snapshot,
    });
    let lease: ActiveLease = match lease {
        Ok(lease) => lease,
        Err(PromptStateError::Invalid) => {
            return Err(Response::prompt_error(
                protocol::PromptErrorCode::TransactionInvalid,
            ));
        }
        Err(PromptStateError::Unavailable) => {
            return Err(Response::prompt_error(
                protocol::PromptErrorCode::Unavailable,
            ));
        }
    };
    Ok(lease)
}

struct PhaseCancellation {
    active: ActiveCancellation,
    deadline: Instant,
}

struct BranchCancellation {
    active: ActiveCancellation,
    local: Arc<AtomicBool>,
    deadline: Instant,
}

impl CancellationSignal for BranchCancellation {
    fn is_cancelled(&self) -> bool {
        self.local.load(Ordering::Acquire)
            || self.active.is_cancelled()
            || Instant::now() >= self.deadline
    }
}

impl CancellationSignal for PhaseCancellation {
    fn is_cancelled(&self) -> bool {
        self.active.is_cancelled() || Instant::now() >= self.deadline
    }
}

fn phase_deadline(active: &ActiveCancellation, budget: Duration) -> Instant {
    Instant::now()
        .checked_add(budget)
        .unwrap_or(active.deadline())
        .min(active.deadline())
}

fn prompt_worker_terminal(response: Response, cleanup_mode: CleanupMode) -> PromptWorkerTerminal {
    PromptWorkerTerminal {
        response,
        cleanup_mode,
        cache_promotion: None,
    }
}

fn prompt_worker_terminal_with_load(
    response: Response,
    cleanup_mode: CleanupMode,
    load: &mut AuthenticationLoad,
) -> PromptWorkerTerminal {
    let cache_promotion = if response_allows_cache_promotion(&response) {
        load.take_promotion()
    } else {
        // Infrastructure errors must never make a cold load globally visible.
        drop(load.take_promotion());
        None
    };
    PromptWorkerTerminal {
        response,
        cleanup_mode,
        cache_promotion,
    }
}

fn finish_prompt_camera(cleanup: CameraCleanup) -> CleanupMode {
    finish_prompt_camera_with_invalidation(cleanup, None)
}

fn finish_prompt_camera_with_invalidation(
    mut cleanup: CameraCleanup,
    invalidation: Option<ProfileInvalidation>,
) -> CleanupMode {
    let outcome = cleanup.camera.stop();
    let lease = cleanup
        .lease
        .take()
        .expect("prompt camera cleanup lease is present");
    let mode = match outcome {
        CameraStopOutcome::Released => CleanupMode::Synchronous,
        CameraStopOutcome::FailedPanicked => CleanupMode::FailedPanicked,
        CameraStopOutcome::Pending(mut pending) => loop {
            match pending.try_complete() {
                Some(WorkerExit::Released) => break CleanupMode::Synchronous,
                Some(WorkerExit::FailedPanicked) => break CleanupMode::FailedPanicked,
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        },
    };
    if let Some(invalidation) = invalidation {
        invalidation.apply();
    }
    drop(lease);
    mode
}

fn run_committed_prompt_authentication(
    lease: &ActiveLease,
    engine: &dyn ServerInference,
    storage: &dyn StorageBackend,
    config: &HowyConfig,
    camera: LazyCameraHandle,
    username: &str,
) -> PromptWorkerTerminal {
    let active = lease.cancellation();
    let camera_ready_deadline = lease.camera_ready_deadline();
    if active.is_cancelled() || Instant::now() >= camera_ready_deadline {
        return prompt_worker_terminal(
            Response::error("authentication unavailable"),
            CleanupMode::NotApplicable,
        );
    }
    let canonical = match CanonicalUsername::new(username.to_owned()) {
        Ok(username) => username,
        Err(_) => {
            return prompt_worker_terminal(
                Response::error("authentication unavailable"),
                CleanupMode::NotApplicable,
            );
        }
    };

    // Mode 1 must reserve/decrypt a cold record before camera admission. Warm
    // hits remain Arc-only, while a failed/cancelled cold load cannot acquire
    // the camera or publish its provisional cache entry. Mode 0 retains its
    // established first-frame/storage overlap, and Mode 2 will define its own
    // overlap transaction after the separate feasibility gate.
    let preloaded_authentication =
        if config.security.embedding_mode == EmbeddingSecurityMode::AeadCached {
            let storage_phase = PhaseCancellation {
                active: active.clone(),
                deadline: phase_deadline(&active, PROMPT_STORAGE_TIMEOUT),
            };
            match storage.authenticate_active(&canonical, &storage_phase) {
                Ok(load) => Some(load),
                Err(StorageBackendError::Absent) => {
                    return prompt_worker_terminal(
                        Response::auth_failed(0.0, 0, "no face models enrolled"),
                        CleanupMode::NotApplicable,
                    );
                }
                Err(error) => {
                    return prompt_worker_terminal(
                        storage_error_response(error),
                        CleanupMode::NotApplicable,
                    );
                }
            }
        } else {
            None
        };
    if active.is_cancelled() || Instant::now() >= camera_ready_deadline {
        return prompt_worker_terminal(
            Response::error("authentication unavailable"),
            CleanupMode::NotApplicable,
        );
    }

    let profile = match camera.resolve_profile_active(&active, camera_ready_deadline) {
        Ok(profile) => profile,
        Err(error) => {
            warn!(%error, "Committed prompt camera profile acquisition failed");
            return prompt_worker_terminal(
                Response::error("authentication unavailable"),
                CleanupMode::NotApplicable,
            );
        }
    };
    let admission_budget = camera_ready_deadline.saturating_duration_since(Instant::now());
    if admission_budget.is_zero() {
        return prompt_worker_terminal(
            Response::error("authentication unavailable"),
            CleanupMode::NotApplicable,
        );
    }
    let camera_lease = match camera.admission.acquire_cancellable(admission_budget, || {
        active.is_cancelled() || Instant::now() >= camera_ready_deadline
    }) {
        Ok(lease) => lease,
        Err(_) => {
            return prompt_worker_terminal(
                Response::error("authentication unavailable"),
                CleanupMode::NotApplicable,
            );
        }
    };
    let camera_phase = PhaseCancellation {
        active: active.clone(),
        deadline: camera_ready_deadline,
    };
    if camera_phase.is_cancelled() {
        drop(camera_lease);
        return prompt_worker_terminal(
            Response::error("authentication unavailable"),
            CleanupMode::NotApplicable,
        );
    }
    let mut capture = camera.factory.create(&profile);
    if let Some(resource) = capture.active_resource_cancellation() {
        active.register_resource(resource);
    }
    if let Err(error) = capture.start_cancellable(&camera_phase) {
        let invalidation =
            profile_invalidation_for_failure(&camera.profile, profile.token, error.kind());
        let cleanup = CameraCleanup {
            camera: capture,
            lease: Some(camera_lease),
            admission: camera.admission.clone(),
        };
        let mode = finish_prompt_camera_with_invalidation(cleanup, invalidation);
        return prompt_worker_terminal(Response::error("authentication unavailable"), mode);
    }
    let mut cleanup = CameraCleanup {
        camera: capture,
        lease: Some(camera_lease),
        admission: camera.admission.clone(),
    };
    if camera_phase.is_cancelled() {
        let mode = finish_prompt_camera(cleanup);
        return prompt_worker_terminal(Response::error("authentication unavailable"), mode);
    }

    let local_cancellation = Arc::new(AtomicBool::new(false));
    let storage_cancellation = BranchCancellation {
        active: active.clone(),
        local: Arc::clone(&local_cancellation),
        deadline: phase_deadline(&active, PROMPT_STORAGE_TIMEOUT),
    };
    let camera_cancellation = BranchCancellation {
        active: active.clone(),
        local: Arc::clone(&local_cancellation),
        deadline: camera_phase.deadline,
    };
    let (first_frame, authentication_load) = if let Some(load) = preloaded_authentication {
        let frame = cleanup
            .camera
            .capture_frame_cancellable(&camera_cancellation);
        if frame.is_err() {
            local_cancellation.store(true, Ordering::Release);
        }
        (frame, Ok(load))
    } else {
        std::thread::scope(|scope| {
            let local = Arc::clone(&local_cancellation);
            let storage_worker = scope.spawn(move || {
                let result = storage.authenticate_active(&canonical, &storage_cancellation);
                if result.is_err() {
                    local.store(true, Ordering::Release);
                }
                result
            });
            let frame = cleanup
                .camera
                .capture_frame_cancellable(&camera_cancellation);
            if frame.is_err() {
                local_cancellation.store(true, Ordering::Release);
            }
            let storage = storage_worker
                .join()
                .unwrap_or(Err(StorageBackendError::Unavailable));
            (frame, storage)
        })
    };
    let mut authentication_load = match authentication_load {
        Ok(lease) => lease,
        Err(StorageBackendError::Absent) => {
            let mode = finish_prompt_camera(cleanup);
            return prompt_worker_terminal(
                Response::auth_failed(0.0, 0, "no face models enrolled"),
                mode,
            );
        }
        Err(error) => {
            let mode = finish_prompt_camera(cleanup);
            return prompt_worker_terminal(storage_error_response(error), mode);
        }
    };
    // `capture_frame_cancellable` sampled the camera deadline and active/local
    // cancellation immediately after the capture call returned. Preserve that
    // boundary result while the concurrent storage branch finishes under its
    // own allowance. Active HUP/shutdown/overall cancellation that happened
    // after the frame completed still wins here.
    if active.is_cancelled() {
        let mode = finish_prompt_camera(cleanup);
        return prompt_worker_terminal_with_load(
            Response::error("authentication unavailable"),
            mode,
            &mut authentication_load,
        );
    }
    let first_frame = match first_frame {
        Ok(frame) => frame,
        Err(error) => {
            let invalidation =
                profile_invalidation_for_failure(&camera.profile, profile.token, error.kind());
            let mode = finish_prompt_camera_with_invalidation(cleanup, invalidation);
            return prompt_worker_terminal_with_load(
                Response::error("authentication unavailable"),
                mode,
                &mut authentication_load,
            );
        }
    };
    let scan_deadline = phase_deadline(
        &active,
        Duration::from_millis(config.presence.scan_timeout_ms),
    );
    let scan_phase = PhaseCancellation {
        active: active.clone(),
        deadline: scan_deadline,
    };
    let threshold = config.ml.recognition_threshold;
    let started = Instant::now();
    let mut next_frame = Some(first_frame);
    let mut frames_processed = 0u32;
    let mut dark_frames = 0u32;
    let mut best_score = 0.0f32;

    while !scan_phase.is_cancelled() {
        let frame = match next_frame.take() {
            Some(frame) => frame,
            None => match cleanup.camera.capture_frame_cancellable(&scan_phase) {
                Ok(frame) => frame,
                Err(error) if error.kind() == CameraFailureKind::Cancelled => break,
                Err(error) => {
                    let invalidation = profile_invalidation_for_failure(
                        &camera.profile,
                        profile.token,
                        error.kind(),
                    );
                    let mode = finish_prompt_camera_with_invalidation(cleanup, invalidation);
                    return prompt_worker_terminal_with_load(
                        Response::error("authentication unavailable"),
                        mode,
                        &mut authentication_load,
                    );
                }
            },
        };
        frames_processed = frames_processed.saturating_add(1);
        if is_dark_frame(&frame, config.video.dark_threshold) {
            dark_frames = dark_frames.saturating_add(1);
            if config.video.max_dark_frames > 0 && dark_frames >= config.video.max_dark_frames {
                let mode = finish_prompt_camera(cleanup);
                return prompt_worker_terminal_with_load(
                    Response::auth_failed(best_score, frames_processed, "too many dark frames"),
                    mode,
                    &mut authentication_load,
                );
            }
            continue;
        }
        dark_frames = 0;
        let is_gray = frame.format == FrameFormat::Gray;
        let faces = match engine.analyze(&frame.data, frame.width, frame.height, is_gray) {
            Ok(faces) => faces,
            Err(_) => continue,
        };
        if scan_phase.is_cancelled() {
            break;
        }
        for face_result in &faces {
            let Some(embedding) = face_result.embedding.as_ref() else {
                continue;
            };
            if embedding.len() != face::FACE_EMBEDDING_DIM
                || embedding.iter().any(|value| !value.is_finite())
            {
                continue;
            }
            let (matched_index, score) = face::find_best_match_flat(
                embedding,
                authentication_load.flat_embeddings(),
                authentication_load.entry_count(),
                threshold,
            );
            best_score = best_score.max(score);
            if let Some(index) = matched_index {
                let label = authentication_load
                    .labels()
                    .nth(index)
                    .expect("matching index remains inside committed model lease")
                    .to_owned();
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                let mode = finish_prompt_camera(cleanup);
                return prompt_worker_terminal_with_load(
                    Response::success(index as u32, &label, score, elapsed_ms),
                    mode,
                    &mut authentication_load,
                );
            }
        }
    }

    let mode = finish_prompt_camera(cleanup);
    if active.is_cancelled() {
        prompt_worker_terminal(Response::error("authentication unavailable"), mode)
    } else {
        prompt_worker_terminal_with_load(
            Response::auth_failed(best_score, frames_processed, "face scan timed out"),
            mode,
            &mut authentication_load,
        )
    }
}

impl PanicResponseWriter for ConnectionIo {
    fn response_write_started(&self) -> bool {
        self.response_write_started
    }

    fn write_response(&mut self, response: &Response) -> Result<()> {
        self.response_write_started = true;
        if matches!(
            response.result,
            Some(RespResult::PromptRequiredV1(_) | RespResult::AuthCancelledV1(_))
        ) {
            Ok(ipc::send_prompt_message(&mut self.stream, response)?)
        } else {
            Ok(ipc::send_message(&mut self.stream, response)?)
        }
    }
}

fn dispatch_with_panic_boundary<W>(
    writer: &mut W,
    dispatch: impl FnOnce(&mut W) -> Result<()>,
) -> Result<()>
where
    W: PanicResponseWriter,
{
    match catch_unwind(AssertUnwindSafe(|| dispatch(writer))) {
        Ok(result) => result,
        Err(_) => {
            if !writer.response_write_started() {
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    writer.write_response(&Response::error("internal server error"))
                }));
            }
            Err(anyhow::anyhow!("connection handler panicked"))
        }
    }
}

fn handle_root_shutdown<W>(writer: &mut W, shutdown: &ShutdownSignal) -> Result<()>
where
    W: PanicResponseWriter,
{
    let write_result = writer.write_response(&Response::pong());
    shutdown.request();
    write_result
}

fn successful_response_cleanup_order(defer_camera_stop: bool) -> ResponseCleanupOrder {
    if defer_camera_stop {
        ResponseCleanupOrder::AfterWrite
    } else {
        ResponseCleanupOrder::BeforeWrite
    }
}

impl CleanupMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Synchronous => "synchronous",
            Self::ReaperHandoff => "reaper_handoff",
            Self::UnresolvedTracked => "unresolved_tracked",
            Self::FailedPanicked => "failed_panicked",
        }
    }
}

pub struct StartupPerfTrace {
    pub async_main_entered: Instant,
    pub requested_provider: String,
    pub registered_preferred_provider: String,
    pub explicit_cpu_retry: bool,
    pub provider_initialization_attempt_count: u32,
    pub discarded_provider_initialization_count: u32,
    pub initialization_and_self_test: Duration,
    pub detector_warmup: Duration,
    pub recognizer_warmup_enabled: bool,
    pub recognizer_warmup: Duration,
    pub defer_camera_stop_enabled: bool,
}

impl StartupPerfTrace {
    pub fn emit_ready(&self, phase: &'static str, camera_profile_probe: Option<Duration>) {
        warn!(
            target: PERF_TRACE_TARGET,
            event_kind = "opt_in_performance_trace",
            outcome = "success",
            phase,
            requested_provider = %self.requested_provider,
            registered_preferred_provider = %self.registered_preferred_provider,
            explicit_cpu_retry = self.explicit_cpu_retry,
            provider_initialization_attempt_count = self.provider_initialization_attempt_count,
            discarded_provider_initialization_count = self.discarded_provider_initialization_count,
            provider_session_initialization_self_test_total_ms =
                duration_ms(self.initialization_and_self_test),
            detector_warmup_ms = duration_ms(self.detector_warmup),
            recognizer_warmup_enabled = self.recognizer_warmup_enabled,
            recognizer_warmup_ms = duration_ms(self.recognizer_warmup),
            defer_camera_stop_enabled = self.defer_camera_stop_enabled,
            camera_profile_probe_ms = ?camera_profile_probe.map(duration_ms),
            async_main_entry_to_ready_ms = duration_ms(self.async_main_entered.elapsed()),
            "opt-in performance trace: startup"
        );
    }
}

pub fn emit_startup_outcome(
    async_main_entered: Instant,
    outcome: &'static str,
    phase: &'static str,
    requested_provider: Option<&str>,
    defer_camera_stop_enabled: bool,
) {
    warn!(
        target: PERF_TRACE_TARGET,
        event_kind = "opt_in_performance_trace",
        outcome,
        phase,
        requested_provider = ?requested_provider,
        defer_camera_stop_enabled,
        async_main_entry_to_outcome_ms = duration_ms(async_main_entered.elapsed()),
        "opt-in performance trace: startup"
    );
}

struct AuthPerfTrace {
    server_accepted: Instant,
    model_load_cache: Duration,
    camera_admission_wait: Duration,
    camera_start_to_first_frame: Option<Duration>,
    analyze_inference: Duration,
    matching: Duration,
    camera_stop_call: Duration,
    response_write: Duration,
    response_write_complete: Option<Duration>,
    cleanup_boundary: Option<Duration>,
    cleanup_mode: CleanupMode,
    defer_camera_stop_enabled: bool,
    accepted_frames: u32,
}

impl AuthPerfTrace {
    fn new(server_accepted: Instant, defer_camera_stop_enabled: bool) -> Self {
        Self {
            server_accepted,
            model_load_cache: Duration::ZERO,
            camera_admission_wait: Duration::ZERO,
            camera_start_to_first_frame: None,
            analyze_inference: Duration::ZERO,
            matching: Duration::ZERO,
            camera_stop_call: Duration::ZERO,
            response_write: Duration::ZERO,
            response_write_complete: None,
            cleanup_boundary: None,
            cleanup_mode: CleanupMode::NotApplicable,
            defer_camera_stop_enabled,
            accepted_frames: 0,
        }
    }

    fn emit(&self, response: &Response, write_succeeded: bool) {
        warn!(
            target: PERF_TRACE_TARGET,
            event_kind = "opt_in_performance_trace",
            outcome = auth_outcome(response),
            response_write_succeeded = write_succeeded,
            model_load_cache_ms = duration_ms(self.model_load_cache),
            camera_admission_wait_ms = duration_ms(self.camera_admission_wait),
            camera_start_to_first_frame_ms = ?self.camera_start_to_first_frame.map(duration_ms),
            analyze_inference_ms = duration_ms(self.analyze_inference),
            matching_ms = duration_ms(self.matching),
            camera_stop_call_ms = duration_ms(self.camera_stop_call),
            response_write_ms = duration_ms(self.response_write),
            server_accept_to_response_write_complete_ms =
                ?self.response_write_complete.map(duration_ms),
            accepted_frame_count = self.accepted_frames,
            server_accept_to_cleanup_handoff_or_complete_ms =
                ?self.cleanup_boundary.map(duration_ms),
            defer_camera_stop_enabled = self.defer_camera_stop_enabled,
            cleanup_mode = self.cleanup_mode.as_str(),
            "opt-in performance trace: authentication"
        );
    }
}

fn auth_outcome(response: &Response) -> &'static str {
    match response.result.as_ref() {
        Some(RespResult::Success(_)) => "success",
        Some(RespResult::AuthFailed(_)) => "auth_failed",
        Some(RespResult::CredentialValid(_)) => "credential_valid",
        Some(RespResult::Error(_)) => "error",
        _ => "unexpected_response",
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Run the daemon server.
pub async fn run(
    engine: Arc<InferenceEngine>,
    storage: Arc<dyn StorageBackend>,
    prompt_manager: Arc<PromptTransactionManager>,
    config: HowyConfig,
    perf_trace: bool,
    defer_camera_stop: bool,
    startup_trace: Option<StartupPerfTrace>,
    shutdown: ShutdownSignal,
    child_policy: Arc<DaemonChildPolicy>,
    runtime_identity: DaemonRuntimeIdentity,
) -> Result<()> {
    let mut server_hooks = ServerRunHooks::default();
    server_hooks.runtime_identity = Some(Arc::new(runtime_identity));
    run_with_camera_and_server_hooks(
        engine,
        storage,
        prompt_manager,
        config,
        perf_trace,
        defer_camera_stop,
        startup_trace,
        shutdown,
        CameraHooks::production(child_policy),
        server_hooks,
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
async fn run_with_camera_hooks<E: ServerInference + 'static>(
    engine: Arc<E>,
    storage: Arc<dyn StorageBackend>,
    prompt_manager: Arc<PromptTransactionManager>,
    config: HowyConfig,
    perf_trace: bool,
    defer_camera_stop: bool,
    startup_trace: Option<StartupPerfTrace>,
    shutdown: ShutdownSignal,
    camera_hooks: CameraHooks,
) -> Result<()> {
    run_with_camera_and_server_hooks(
        engine,
        storage,
        prompt_manager,
        config,
        perf_trace,
        defer_camera_stop,
        startup_trace,
        shutdown,
        camera_hooks,
        ServerRunHooks::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_with_camera_and_server_hooks<E: ServerInference + 'static>(
    engine: Arc<E>,
    storage: Arc<dyn StorageBackend>,
    prompt_manager: Arc<PromptTransactionManager>,
    config: HowyConfig,
    perf_trace: bool,
    defer_camera_stop: bool,
    startup_trace: Option<StartupPerfTrace>,
    shutdown: ShutdownSignal,
    camera_hooks: CameraHooks,
    server_hooks: ServerRunHooks,
) -> Result<()> {
    let runtime_identity = match server_hooks.runtime_identity.clone() {
        Some(identity) => identity,
        None => {
            #[cfg(test)]
            {
                Arc::new(DaemonRuntimeIdentity::harness_placeholder())
            }
            #[cfg(not(test))]
            {
                bail!("daemon runtime identity is required before server startup")
            }
        }
    };
    let start = Instant::now();
    let (camera_admission, mut camera_reaper) = CameraReaper::new()?;
    if let Some(observe) = server_hooks.camera_admission.as_ref() {
        observe(camera_admission.clone());
    }

    if shutdown.is_requested() {
        prompt_manager.shutdown();
        finish_daemon_shutdown(&mut camera_reaper, &mut Vec::new(), &shutdown);
        return Ok(());
    }

    // Prompt-off preserves eager one-time discovery. Confirmation mode creates
    // only a cold resolver; socket readiness and all pending prompt phases are
    // therefore physically incapable of starting the provider.
    let camera_probe_started = perf_trace.then(Instant::now);
    let camera_profile = Arc::new(CameraProfileCache::new(
        Arc::clone(&camera_hooks.profile_provider),
        camera_profile_request(&config),
    ));
    let camera_profile_probe = if initialize_camera_profile_for_presence(
        config.presence.mode,
        Arc::clone(&camera_profile),
        &camera_admission,
        &camera_reaper,
    )? {
        camera_probe_started.map(|started| started.elapsed())
    } else {
        None
    };
    if shutdown.is_requested() {
        camera_profile.shutdown();
        prompt_manager.shutdown();
        finish_daemon_shutdown(&mut camera_reaper, &mut Vec::new(), &shutdown);
        return Ok(());
    }

    if config.credentials.enable_cache {
        warn!(
            "Credential caching is configured but disabled at runtime until PAM session-scoped cache keys are implemented"
        );
    }

    // Try systemd socket activation first.
    let listener_result = (|| -> Result<UnixListener> {
        let listener = match try_systemd_socket() {
            Some(listener) => {
                info!("Using systemd socket activation");
                listener
            }
            None => {
                // Manual socket creation — honors HOWY_SOCKET override.
                let socket_path = paths::socket_path();

                // Ensure parent directory exists
                if let Some(parent) = Path::new(&socket_path).parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)
                            .context("failed to create runtime directory")?;
                    }
                }

                // Remove stale socket
                if Path::new(&socket_path).exists() {
                    std::fs::remove_file(&socket_path)?;
                }

                let listener =
                    UnixListener::bind(&socket_path).context("failed to bind Unix socket")?;

                // Allow all users to connect (PAM runs as various users)
                set_socket_permissions(&socket_path)?;

                info!("Listening on {socket_path}");
                listener
            }
        };
        set_fd_cloexec(listener.as_raw_fd())?;
        listener.set_nonblocking(true)?;
        Ok(listener)
    })();
    let listener = match listener_result {
        Ok(listener) => listener,
        Err(error) => {
            camera_profile.shutdown();
            if let Some(startup_trace) = startup_trace.as_ref() {
                emit_startup_outcome(
                    startup_trace.async_main_entered,
                    "error",
                    "listener",
                    Some(&startup_trace.requested_provider),
                    startup_trace.defer_camera_stop_enabled,
                );
            }
            return Err(error);
        }
    };

    // Handle connections
    info!("Daemon ready, accepting connections");
    if let Some(startup_trace) = startup_trace {
        startup_trace.emit_ready("ready", camera_profile_probe);
    }

    let mut connection_workers = Vec::<std::thread::JoinHandle<()>>::new();
    let connection_accounting = Arc::new(Mutex::new(ConnectionAccounting::default()));
    while !shutdown.is_requested() {
        reap_finished_connection_workers(&mut connection_workers);

        match listener.accept() {
            Ok((stream, _address)) => {
                if let Err(error) = set_fd_cloexec(stream.as_raw_fd()) {
                    warn!(%error, "Rejecting local connection whose descriptor could not be sealed");
                    continue;
                }
                if let Some(after_accept) = server_hooks.after_accept.as_ref() {
                    after_accept();
                }
                // `while` can observe a healthy state immediately before a
                // queued/socket-activated accept races fatal shutdown. Reject
                // that stream before peer lookup, accounting, or prompt IDs.
                if shutdown.is_requested() {
                    drop(stream);
                    continue;
                }
                let Some(peer_uid) = get_peer_uid(&stream) else {
                    warn!("Rejecting local connection without peer credentials");
                    continue;
                };
                let Some(connection_permit) =
                    ConnectionAccounting::try_acquire(&connection_accounting, peer_uid)
                else {
                    warn!(peer_uid, "Rejecting local connection at UID/total capacity");
                    continue;
                };
                let connection_id = match prompt_manager.new_connection() {
                    Ok(connection_id) => connection_id,
                    Err(_) => continue,
                };
                let server_accepted = perf_trace.then(Instant::now);
                let engine = Arc::clone(&engine);
                let config = config.clone();
                let camera_admission = camera_admission.clone();
                let storage = Arc::clone(&storage);
                let camera_profile = Arc::clone(&camera_profile);
                let camera_factory = Arc::clone(&camera_hooks.factory);
                let worker_shutdown = shutdown.clone();
                let prompt_manager = Arc::clone(&prompt_manager);
                let before_handle = server_hooks.before_handle.clone();
                let runtime_identity = Arc::clone(&runtime_identity);
                let uptime = start.elapsed().as_secs();

                // Handle in a thread (we're I/O bound on camera, not CPU)
                // The permit is captured by the closure before spawn: std drops
                // that closure on spawn failure, and the worker drops it after
                // normal return, timeout/error, or panic containment.
                let connection_worker = with_connection_permit(connection_permit, move || {
                    let mut io = ConnectionIo {
                        stream,
                        response_write_started: false,
                    };
                    let result = dispatch_with_panic_boundary(&mut io, |io| {
                        if let Some(before_handle) = before_handle.as_ref() {
                            before_handle();
                        }
                        // A fatal transition can race worker spawn. This is the
                        // final gate before parsing, authorization, or hooks.
                        if worker_shutdown.is_requested() {
                            return Ok(());
                        }
                        handle_connection(
                            io,
                            Arc::clone(&engine),
                            &config,
                            &camera_admission,
                            Arc::clone(&storage),
                            &camera_profile,
                            camera_factory,
                            uptime,
                            server_accepted,
                            defer_camera_stop,
                            &worker_shutdown,
                            &prompt_manager,
                            connection_id,
                            &runtime_identity,
                        )
                    });
                    if let Err(e) = result {
                        error!("Connection error: {e}");
                    }
                });
                let spawn_result = std::thread::Builder::new()
                    .name("howy-connection".to_string())
                    .spawn(connection_worker);
                match spawn_result {
                    Ok(handle) => connection_workers.push(handle),
                    Err(error) => error!(%error, "Failed to spawn connection handler"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                shutdown.wait_for_activity(ACCEPT_POLL_INTERVAL);
            }
            Err(error) => error!(%error, "Accept error"),
        }
    }

    drop(listener);
    camera_profile.shutdown();
    prompt_manager.shutdown();
    finish_daemon_shutdown(&mut camera_reaper, &mut connection_workers, &shutdown);
    if shutdown.is_fatal() {
        bail!("daemon fail-stop: active authentication cleanup exceeded its bound");
    }
    Ok(())
}

fn finish_daemon_shutdown(
    camera_reaper: &mut CameraReaper,
    connection_workers: &mut Vec<std::thread::JoinHandle<()>>,
    shutdown: &ShutdownSignal,
) {
    let connection_workers = shutdown_connection_workers(connection_workers);
    let reaper = camera_reaper.shutdown_bounded();
    let remainder = DaemonShutdownRemainder {
        reaper,
        connection_workers,
        retained_camera_workers: take_retained_camera_workers(),
        fatal_active_workers: shutdown.take_fatal_active_workers(),
    };
    if !remainder.is_empty() {
        let unresolved = remainder.unresolved_count();
        error!(
            unresolved,
            "Daemon shutdown retained unresolved in-process ownership for OS reclamation"
        );
        // `run` is the outermost daemon lifecycle boundary. Main returns
        // immediately after this function, so intentionally retain every
        // unresolved handle/task until process termination lets the OS reclaim
        // the in-process resources without detaching them earlier.
        std::mem::forget(remainder);
    }
}

fn camera_profile_request(config: &HowyConfig) -> CameraProfileRequest {
    CameraProfileRequest::new(
        config.video.device_path.clone(),
        config.video.frame_width,
        config.video.frame_height,
        config.video.device_fps,
        config.video.exposure,
    )
}

/// Returns whether eager discovery was requested. Confirmation mode must leave
/// the cache idle; prompt-off preserves the existing eager startup profile.
fn initialize_camera_profile_for_presence(
    mode: PresenceMode,
    camera_profile: Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
    camera_reaper: &CameraReaper,
) -> Result<bool> {
    if mode == PresenceMode::Confirm {
        return Ok(false);
    }
    start_initial_camera_profile_probe(camera_profile, camera_admission, camera_reaper)?;
    Ok(true)
}

fn start_initial_camera_profile_probe(
    camera_profile: Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
    camera_reaper: &CameraReaper,
) -> Result<()> {
    if let ProbeClaim::Start(generation) = camera_profile.claim(Instant::now()) {
        let handle = match spawn_camera_profile_probe(
            camera_profile.clone(),
            camera_admission.clone(),
            generation,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                camera_profile.complete_probe(
                    generation,
                    Err("failed to spawn camera profile probe".to_string()),
                    Instant::now(),
                );
                return Err(error);
            }
        };
        camera_reaper.track_unleased(PendingCameraCleanup::from_thread_handle(handle));
    }
    let deadline = Instant::now() + CAMERA_PROFILE_PROBE_TIMEOUT;
    while !camera_profile.initial_attempt_finished() && Instant::now() < deadline {
        camera_profile.wait_for_change(deadline);
    }
    if camera_profile.ready_profile().is_none() {
        warn!("Camera profile is not ready; first camera use will retry within a bounded deadline");
    }
    Ok(())
}

fn spawn_camera_profile_probe(
    camera_profile: Arc<CameraProfileCache>,
    camera_admission: CameraAdmission,
    generation: u64,
) -> Result<std::thread::JoinHandle<()>> {
    spawn_camera_profile_probe_cancellable(camera_profile, camera_admission, generation, None)
}

fn spawn_camera_profile_probe_cancellable(
    camera_profile: Arc<CameraProfileCache>,
    camera_admission: CameraAdmission,
    generation: u64,
    active: Option<ActiveCancellation>,
) -> Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("howy-camera-profile-probe".to_string())
        .spawn(move || {
            // The outer boundary ensures no worker panic is resumed through
            // JoinHandle ownership. The completion guard transitions Probing
            // even if code outside the provider catch unexpectedly unwinds.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let completion =
                    ProfileProbeCompletion::new(Arc::clone(&camera_profile), generation);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let cancelled = || {
                        camera_profile.is_shutdown()
                            || active
                                .as_ref()
                                .is_some_and(ActiveCancellation::is_cancelled)
                    };
                    let _probe_lease = camera_admission
                        .acquire_cancellable(CAMERA_LOCK_TIMEOUT, cancelled)
                        .map_err(|error| match error {
                            CameraAdmissionError::Busy => {
                                "camera profile probe timed out waiting for admission".to_string()
                            }
                            CameraAdmissionError::Cancelled => {
                                "camera profile probe cancelled during shutdown".to_string()
                            }
                        })?;
                    if camera_profile.is_shutdown()
                        || active
                            .as_ref()
                            .is_some_and(ActiveCancellation::is_cancelled)
                    {
                        return Err("camera profile probe cancelled during shutdown".to_string());
                    }
                    let provider = camera_profile.provider();
                    let request = camera_profile.request();
                    provider.probe(&request).map_err(|error| error.to_string())
                }));
                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err("camera profile probe panicked".to_string()),
                };
                completion.complete(result);
            }));
        })
        .context("failed to spawn camera profile probe")
}

fn resolve_camera_profile_active(
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
    active: &ActiveCancellation,
    deadline: Instant,
) -> Result<ResolvedCameraProfile> {
    loop {
        if active.is_cancelled() || Instant::now() >= deadline {
            bail!("camera profile acquisition cancelled");
        }
        if let Some(profile) = camera_profile.ready_profile() {
            return Ok(profile);
        }
        match camera_profile.claim(Instant::now()) {
            ProbeClaim::Ready => continue,
            ProbeClaim::Wait => camera_profile.wait_for_change(deadline),
            ProbeClaim::Start(generation) => {
                // Active profile I/O stays on the supervised auth worker. If a
                // provider call ignores cancellation, that worker retains the
                // admission lease and the supervisor fail-stops the daemon at
                // the cleanup bound instead of orphaning a nested probe worker.
                let completion =
                    ProfileProbeCompletion::new(Arc::clone(camera_profile), generation);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let _probe_lease = camera_admission
                        .acquire_cancellable(
                            deadline.saturating_duration_since(Instant::now()),
                            || active.is_cancelled() || Instant::now() >= deadline,
                        )
                        .map_err(|error| match error {
                            CameraAdmissionError::Busy => {
                                "camera profile probe timed out waiting for admission".to_string()
                            }
                            CameraAdmissionError::Cancelled => {
                                "camera profile probe cancelled during shutdown".to_string()
                            }
                        })?;
                    if active.is_cancelled()
                        || Instant::now() >= deadline
                        || camera_profile.is_shutdown()
                    {
                        return Err("camera profile probe cancelled during shutdown".to_string());
                    }
                    camera_profile
                        .provider()
                        .probe(&camera_profile.request())
                        .map_err(|error| error.to_string())
                }));
                completion.complete(match result {
                    Ok(result) => result,
                    Err(_) => Err("camera profile probe panicked".to_string()),
                });
            }
            ProbeClaim::Shutdown => bail!("camera profile provider is shutting down"),
        }
        if Instant::now() >= deadline {
            bail!("camera profile probe exceeded its absolute active deadline");
        }
    }
}

fn resolve_camera_profile(
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
    mut cancelled: impl FnMut() -> bool,
) -> Result<ResolvedCameraProfile> {
    let deadline = Instant::now() + CAMERA_PROFILE_PROBE_TIMEOUT;
    loop {
        if cancelled() {
            bail!("camera profile acquisition cancelled");
        }
        if let Some(profile) = camera_profile.ready_profile() {
            return Ok(profile);
        }
        match camera_profile.claim(Instant::now()) {
            ProbeClaim::Ready => continue,
            ProbeClaim::Wait => camera_profile.wait_for_change(deadline),
            ProbeClaim::Start(generation) => {
                match spawn_camera_profile_probe(
                    Arc::clone(camera_profile),
                    camera_admission.clone(),
                    generation,
                ) {
                    Ok(handle) => {
                        camera_admission
                            .track_unleased(PendingCameraCleanup::from_thread_handle(handle));
                    }
                    Err(error) => {
                        camera_profile.complete_probe(
                            generation,
                            Err("failed to spawn camera profile probe".to_string()),
                            Instant::now(),
                        );
                        return Err(error);
                    }
                }
            }
            ProbeClaim::Shutdown => bail!("camera profile provider is shutting down"),
        }
        if Instant::now() >= deadline {
            bail!(
                "camera profile probe did not become ready within the bounded first-use deadline"
            );
        }
    }
}

fn resolve_camera_profile_already_admitted(
    camera_profile: &Arc<CameraProfileCache>,
    _held: &CameraAdmissionHeld<'_>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<ResolvedCameraProfile> {
    let deadline = Instant::now() + CAMERA_PROFILE_PROBE_TIMEOUT;
    loop {
        if cancelled() {
            bail!("camera profile acquisition cancelled");
        }
        if let Some(profile) = camera_profile.ready_profile() {
            return Ok(profile);
        }
        match camera_profile.claim(Instant::now()) {
            ProbeClaim::Ready => continue,
            ProbeClaim::Start(generation) => {
                let completion =
                    ProfileProbeCompletion::new(Arc::clone(camera_profile), generation);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let provider = camera_profile.provider();
                    let request = camera_profile.request();
                    provider.probe(&request).map_err(|error| error.to_string())
                }));
                completion.complete(match result {
                    Ok(result) => result,
                    Err(_) => Err("camera profile probe panicked".to_string()),
                });
            }
            // A normal probe leader may be queued behind this caller's lease.
            // Waiting here would invert admission -> profile ordering.
            ProbeClaim::Wait => {
                bail!("camera profile probe is pending behind active camera admission")
            }
            ProbeClaim::Shutdown => bail!("camera profile provider is shutting down"),
        }
        if Instant::now() >= deadline {
            bail!("camera profile probe did not become ready within the bounded deadline");
        }
    }
}

#[cfg(test)]
fn finish_or_track_unleased_worker(
    handle: std::thread::JoinHandle<()>,
    camera_reaper: &CameraReaper,
    timeout: Duration,
) -> CleanupMode {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if handle.is_finished() {
        if handle.join().is_err() {
            error!("Camera profile probe worker panicked");
            CleanupMode::FailedPanicked
        } else {
            CleanupMode::Synchronous
        }
    } else {
        camera_reaper.track_unleased(PendingCameraCleanup::from_thread_handle(handle))
    }
}

fn reap_finished_connection_workers(workers: &mut Vec<std::thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let handle = workers.swap_remove(index);
            if handle.join().is_err() {
                error!("Connection worker panicked after dispatch containment");
            }
        } else {
            index += 1;
        }
    }
}

fn shutdown_connection_workers(
    workers: &mut Vec<std::thread::JoinHandle<()>>,
) -> Vec<std::thread::JoinHandle<()>> {
    shutdown_connection_workers_with_timeout(workers, CONNECTION_SHUTDOWN_TIMEOUT)
}

fn shutdown_connection_workers_with_timeout(
    workers: &mut Vec<std::thread::JoinHandle<()>>,
    timeout: Duration,
) -> Vec<std::thread::JoinHandle<()>> {
    let deadline = Instant::now() + timeout;
    while !workers.is_empty() && Instant::now() < deadline {
        reap_finished_connection_workers(workers);
        if !workers.is_empty() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    reap_finished_connection_workers(workers);
    std::mem::take(workers)
}

fn current_operation(request: &Request) -> Operation<'_> {
    match request.cmd.as_ref() {
        Some(Cmd::Authenticate(request)) => Operation::Authenticate {
            target: &request.username,
        },
        Some(Cmd::AuthenticateV1(request)) => Operation::Authenticate {
            target: &request.username,
        },
        Some(Cmd::BeginAuthV1(request)) => Operation::BeginAuth {
            target: &request.username,
        },
        Some(Cmd::CommitAuthV1(_)) => Operation::CommitAuth,
        Some(Cmd::CancelAuthV1(_)) => Operation::CancelAuth,
        Some(Cmd::Enroll(request)) => Operation::Enroll {
            target: &request.username,
        },
        Some(Cmd::EnrollV1(request)) => Operation::Enroll {
            target: &request.username,
        },
        Some(Cmd::EnrollBatch(request)) => Operation::EnrollBatch {
            target: &request.username,
        },
        Some(Cmd::EnrollBatchV1(request)) => Operation::EnrollBatch {
            target: &request.username,
        },
        Some(Cmd::EnrollmentPresence(request)) => Operation::EnrollmentPresence {
            target: &request.username,
        },
        Some(Cmd::ListEnrollments(request)) => Operation::ListEnrollments {
            target: &request.username,
        },
        Some(Cmd::RemoveEnrollment(request)) => Operation::RemoveEnrollment {
            target: &request.username,
        },
        Some(Cmd::ClearEnrollments(request)) => Operation::ClearEnrollments {
            target: &request.username,
        },
        Some(Cmd::ReloadStorage(_)) => Operation::Reload,
        Some(Cmd::SecurityInfo(_)) => Operation::SecurityInfo,
        Some(Cmd::Detect(_)) => Operation::Detect,
        Some(Cmd::Ping(_)) => Operation::Ping,
        Some(Cmd::Info(_)) => Operation::PublicInfo,
        Some(Cmd::Shutdown(_)) => Operation::Shutdown,
        Some(Cmd::CheckCredential(request)) => Operation::CheckCredential {
            target: &request.username,
        },
        Some(Cmd::RevokeCredential(request)) => Operation::RevokeCredential {
            target: &request.username,
        },
        None => Operation::Unknown,
    }
}

fn initial_prompt_protocol_response(
    request: &Request,
    confirmation_required: bool,
) -> Option<Response> {
    match request.cmd.as_ref() {
        Some(Cmd::Authenticate(_)) if confirmation_required => Some(Response::prompt_error(
            protocol::PromptErrorCode::Incompatible,
        )),
        Some(Cmd::AuthenticateV1(request)) => match request.validate() {
            Err(error) => Some(Response::prompt_error(error.prompt_error())),
            Ok(()) if confirmation_required => Some(Response::prompt_error(
                protocol::PromptErrorCode::Incompatible,
            )),
            Ok(()) => None,
        },
        Some(Cmd::BeginAuthV1(begin)) => {
            if let Err(error) = begin.validate() {
                return Some(Response::prompt_error(error.prompt_error()));
            }
            if confirmation_required {
                None
            } else {
                Some(Response::prompt_error(
                    protocol::PromptErrorCode::Incompatible,
                ))
            }
        }
        Some(Cmd::CommitAuthV1(commit)) => Some(match commit.validate() {
            Ok(()) => Response::prompt_error(protocol::PromptErrorCode::Violation),
            Err(error) => Response::prompt_error(error.prompt_error()),
        }),
        Some(Cmd::CancelAuthV1(cancel)) => Some(match cancel.validate() {
            Ok(()) => Response::prompt_error(protocol::PromptErrorCode::Violation),
            Err(error) => Response::prompt_error(error.prompt_error()),
        }),
        _ => None,
    }
}

fn dispatch_authenticate_v1_with(
    request: &protocol::AuthenticateV1Req,
    confirmation_required: impl FnOnce() -> bool,
    authenticate: impl FnOnce(&protocol::AuthenticateV1Req) -> Response,
) -> Response {
    if let Err(error) = request.validate() {
        return Response::prompt_error(error.prompt_error());
    }
    if confirmation_required() {
        return Response::prompt_error(protocol::PromptErrorCode::Incompatible);
    }
    authenticate(request)
}

fn validate_prompt_begin_policy(
    config: &HowyConfig,
    request: &protocol::BeginAuthV1Req,
) -> std::result::Result<(), protocol::PromptErrorCode> {
    if let Err(error) = request.validate() {
        return Err(error.prompt_error());
    }
    let Some(policy) = request.policy.as_ref() else {
        return Err(protocol::PromptErrorCode::Violation);
    };
    let origin = protocol::PromptOriginV1::try_from(policy.origin)
        .expect("validated prompt origin is known and specified");
    validate_current_prompt_policy(config, &policy.pam_service, origin)
}

fn validate_current_prompt_policy(
    config: &HowyConfig,
    pam_service: &str,
    origin: protocol::PromptOriginV1,
) -> std::result::Result<(), protocol::PromptErrorCode> {
    // PAM service is client-supplied policy context, not an attested caller
    // identity. Peer-UID authorization constrains the target account, but a
    // malicious same-UID client can still claim an allowlisted service name.
    let origin_supported = matches!(
        origin,
        protocol::PromptOriginV1::Local | protocol::PromptOriginV1::Remote
    );
    let policy_allowed = config
        .presence
        .allowed_pam_services
        .iter()
        .any(|service| service == pam_service)
        && origin_supported
        && !(origin == protocol::PromptOriginV1::Remote && config.presence.local_only);
    if !policy_allowed {
        return Err(protocol::PromptErrorCode::Unavailable);
    }

    Ok(())
}

fn dispatch_authorized_enrollment(
    command: Option<&Cmd>,
    authorized_username: &str,
    live: impl FnOnce(&protocol::EnrollV1Req, &str) -> Response,
    batch: impl FnOnce(&protocol::EnrollBatchV1Req, &str) -> Response,
) -> Option<Response> {
    match command {
        Some(Cmd::Enroll(_)) | Some(Cmd::EnrollBatch(_)) => Some(Response::error_code(
            protocol::ENROLLMENT_PROTOCOL_ERROR,
            "enrollment requires a compatible daemon-owned storage operation",
        )),
        Some(Cmd::EnrollV1(request)) => Some(live(request, authorized_username)),
        Some(Cmd::EnrollBatchV1(request)) => Some(batch(request, authorized_username)),
        _ => None,
    }
}

fn active_storage_ready(storage: &dyn StorageBackend) -> bool {
    storage.health() == BackendHealth::Ready
}

fn authorized_username<'a>(authorization: &'a Authorization, operation: &str) -> &'a str {
    authorization
        .canonical_target()
        .unwrap_or_else(|| panic!("{operation} authorization resolves a target"))
        .username()
}

fn storage_error_response(error: StorageBackendError) -> Response {
    match error {
        StorageBackendError::Absent => {
            Response::error_code(protocol::STORAGE_ABSENT_ERROR, "no enrollments found")
        }
        StorageBackendError::Conflict { .. } => Response::error_code(
            protocol::STORAGE_CONFLICT_ERROR,
            "enrollment data changed; relist and retry",
        ),
        StorageBackendError::Corrupt | StorageBackendError::AuthenticationFailed => {
            Response::error_code(
                protocol::STORAGE_CORRUPT_ERROR,
                "enrollment storage is corrupt",
            )
        }
        StorageBackendError::ModelMismatch => Response::error_code(
            protocol::STORAGE_MODEL_MISMATCH_ERROR,
            "enrollments were created for a different recognizer model",
        ),
        StorageBackendError::InvalidInput(_) => Response::error_code(
            protocol::STORAGE_INVALID_REQUEST_ERROR,
            "invalid storage request",
        ),
        StorageBackendError::ModeMismatch
        | StorageBackendError::KeyMismatch
        | StorageBackendError::GenerationOverflow
        | StorageBackendError::Unavailable
        | StorageBackendError::MemoryBudgetExceeded { .. }
        | StorageBackendError::Io(_) => Response::error_code(
            protocol::STORAGE_UNAVAILABLE_ERROR,
            "enrollment storage is unavailable",
        ),
    }
}

fn current_storage_state(
    storage: &dyn StorageBackend,
    username: &CanonicalUsername,
) -> std::result::Result<(u64, usize), Response> {
    match storage.list_metadata(username) {
        Ok(list) => Ok((list.generation(), list.entries().len())),
        Err(StorageBackendError::Absent) => Ok((ABSENT_GENERATION, 0)),
        Err(error) => Err(storage_error_response(error)),
    }
}

fn with_enrollment_admission(
    storage: &dyn StorageBackend,
    username: &str,
    label: &str,
    plaintext_bytes: usize,
    append_shape: AppendAdmissionShape,
    execute: impl FnOnce(CanonicalUsername, (u64, usize), BudgetPermit, BudgetPermit) -> Response,
) -> Response {
    if label.as_bytes().len() > howy_common::storage::MAX_LABEL_BYTES {
        return Response::error_code(
            protocol::STORAGE_INVALID_REQUEST_ERROR,
            "enrollment label is too long",
        );
    }
    let canonical = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    let initial = match current_storage_state(storage, &canonical) {
        Ok(initial) => initial,
        Err(response) => return response,
    };
    let admission = match storage.admit_enrollment(&canonical, plaintext_bytes, append_shape) {
        Ok(admission) => admission,
        Err(error) => return storage_error_response(error),
    };
    let (operation, input) = admission.into_parts();
    execute(canonical, initial, operation, input)
}

fn new_enrollment_id<R: RandomSource>(
    random: &mut R,
    existing: &HashSet<EnrollmentId>,
) -> std::result::Result<EnrollmentId, Response> {
    for _ in 0..16 {
        if let Ok(id) = generate_enrollment_id(random, existing) {
            return Ok(id);
        }
    }
    Err(storage_error_response(StorageBackendError::Unavailable))
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn handle_enrollment_presence(storage: &dyn StorageBackend, username: &str) -> Response {
    let username = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    match storage.candidate_presence(&username) {
        Ok(CandidatePresence::Absent) => Response::enrollment_presence(false),
        Ok(CandidatePresence::Candidate { .. }) => Response::enrollment_presence(true),
        Err(_) => Response::error_code(
            protocol::STORAGE_UNAVAILABLE_ERROR,
            "enrollment presence is unavailable",
        ),
    }
}

fn metadata_response(list: MetadataList) -> Response {
    let entries = list
        .entries()
        .iter()
        .map(|entry| protocol::EnrollmentMetadataEntry {
            enrollment_id: entry.enrollment_id().into_bytes().to_vec(),
            label: entry.label().to_owned(),
            created_unix_seconds: entry.created_unix_seconds(),
        })
        .collect();
    Response::list_enrollments(list.generation(), entries)
}

fn handle_list_enrollments(storage: &dyn StorageBackend, username: &str) -> Response {
    let username = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    match storage.list_metadata(&username) {
        Ok(list) => metadata_response(list),
        Err(StorageBackendError::Absent) => {
            Response::list_enrollments(ABSENT_GENERATION, Vec::new())
        }
        Err(error) => storage_error_response(error),
    }
}

fn handle_remove_enrollment(
    storage: &dyn StorageBackend,
    username: &str,
    enrollment_id: &[u8],
    expected_generation: u64,
) -> Response {
    if expected_generation == ABSENT_GENERATION || enrollment_id.len() != 16 {
        return storage_error_response(StorageBackendError::InvalidInput("remove request"));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(enrollment_id);
    let id = match EnrollmentId::new(id) {
        Ok(id) => id,
        Err(_) => {
            return storage_error_response(StorageBackendError::InvalidInput("enrollment ID"));
        }
    };
    let username = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    let request = RemoveRequest::new(&username, expected_generation, id)
        .expect("validated remove request is valid");
    match storage.remove(request) {
        Ok(result) => {
            Response::remove_enrollment(result.generation(), result.enrollment_id().into_bytes())
        }
        Err(error) => storage_error_response(error),
    }
}

fn handle_clear_enrollments(
    storage: &dyn StorageBackend,
    username: &str,
    expected_generation: u64,
) -> Response {
    if expected_generation == ABSENT_GENERATION {
        return storage_error_response(StorageBackendError::InvalidInput("clear generation"));
    }
    let username = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    let request = ClearRequest::new(&username, expected_generation)
        .expect("validated clear request is valid");
    match storage.clear(request) {
        Ok(result) => match u32::try_from(result.removed()) {
            Ok(removed) => Response::clear_enrollments(result.generation(), removed),
            Err(_) => storage_error_response(StorageBackendError::InvalidInput("count")),
        },
        Err(error) => storage_error_response(error),
    }
}

fn handle_reload_storage(storage: &dyn StorageBackend) -> Response {
    match storage.reload() {
        Ok(result) => {
            let mut candidate = 0u32;
            let mut mode_mismatch = 0u32;
            let mut key_mismatch = 0u32;
            let mut model_mismatch = 0u32;
            let mut corrupt = 0u32;
            for record in result.records() {
                let counter = match record.classification() {
                    OuterRecordClassification::Candidate { .. } => &mut candidate,
                    OuterRecordClassification::ModeMismatch => &mut mode_mismatch,
                    OuterRecordClassification::KeyMismatch => &mut key_mismatch,
                    OuterRecordClassification::ModelMismatch => &mut model_mismatch,
                    OuterRecordClassification::Corrupt => &mut corrupt,
                };
                *counter = counter.saturating_add(1);
            }
            Response::reload_storage(protocol::ReloadStorageResult {
                storage_ready: result.health() == BackendHealth::Ready,
                candidate_records: candidate,
                mode_mismatch_records: mode_mismatch,
                key_mismatch_records: key_mismatch,
                model_mismatch_records: model_mismatch,
                corrupt_records: corrupt,
            })
        }
        Err(error) => storage_error_response(error),
    }
}

fn handle_security_info(
    engine: &impl ServerInference,
    config: &HowyConfig,
    storage: &dyn StorageBackend,
    runtime_identity: &DaemonRuntimeIdentity,
) -> Response {
    let active_mode = config.security.embedding_mode as u32;
    let namespaces = [
        RecordNamespace::Plaintext,
        RecordNamespace::AeadCached,
        RecordNamespace::AeadEphemeral,
    ]
    .into_iter()
    .map(|namespace| protocol::NamespaceDiagnostic {
        mode: u32::from(namespace.identifier()),
        path: namespace.directory().display().to_string(),
        active: u32::from(namespace.identifier()) == active_mode,
        implemented: matches!(
            namespace,
            RecordNamespace::Plaintext | RecordNamespace::AeadCached
        ),
    })
    .collect();
    let health = storage.health();
    let backend_state = match health {
        BackendHealth::Ready => protocol::SecurityBackendStateV1::Ready,
        BackendHealth::Unavailable(_) => protocol::SecurityBackendStateV1::Unavailable,
    };
    let readiness_state = match health {
        BackendHealth::Ready => protocol::SecurityReadinessStateV1::Ready,
        BackendHealth::Unavailable(_) => protocol::SecurityReadinessStateV1::Unavailable,
    };
    let poison_state = if config.security.embedding_mode == EmbeddingSecurityMode::AeadCached
        && health == BackendHealth::Unavailable(BackendUnavailable::Integrity)
    {
        protocol::SecurityPoisonStateV1::Poisoned
    } else {
        protocol::SecurityPoisonStateV1::NotPoisoned
    };
    let result = protocol::SecurityInfoResult {
        detector_model: engine.detector_model_path(),
        recognizer_model: engine.recognizer_model_path(),
        active_security_mode: active_mode,
        key_epoch: config.security.key_epoch,
        storage_ready: health == BackendHealth::Ready,
        prompt_required: config.presence.mode == PresenceMode::Confirm,
        namespaces,
        config_sha256: runtime_identity.config_sha256.clone(),
        credential_name: runtime_identity.credential_name.clone().unwrap_or_default(),
        configured_credential_source: runtime_identity
            .configured_credential_source
            .clone()
            .unwrap_or_default(),
        backend_state: backend_state as i32,
        readiness_state: readiness_state as i32,
        poison_state: poison_state as i32,
        daemon_invocation_id: runtime_identity.invocation_id.clone(),
        daemon_version: runtime_identity.daemon_version.clone(),
        build_identity: runtime_identity.build_identity.clone(),
        binary_absolute_path: runtime_identity.binary_absolute_path.clone(),
        binary_sha256: runtime_identity.binary_sha256.clone(),
    };
    if result.validate_strict().is_err() {
        return Response::error("security status unavailable");
    }
    Response::security_info(result)
}

/// Handle a single client connection.
fn handle_connection<E: ServerInference + 'static>(
    io: &mut ConnectionIo,
    engine: Arc<E>,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    storage: Arc<dyn StorageBackend>,
    camera_profile: &Arc<CameraProfileCache>,
    camera_factory: Arc<dyn CameraFactory>,
    uptime: u64,
    server_accepted: Option<Instant>,
    defer_camera_stop: bool,
    shutdown: &ShutdownSignal,
    prompt_manager: &PromptTransactionManager,
    connection_id: ConnectionId,
    runtime_identity: &DaemonRuntimeIdentity,
) -> Result<()> {
    configure_initial_io_deadlines(&io.stream)?;

    // The first frame may be prompt-bearing; use zeroizing encoded ownership.
    // Prefix and body share one monotonic deadline, so byte trickle cannot
    // renew a per-read socket timeout. Shutdown/fail-stop is polled while the
    // initial frame is incomplete; no response is required in that state.
    let initial_deadline = Instant::now()
        .checked_add(INITIAL_REQUEST_READ_TIMEOUT)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "initial request deadline")
        })?;
    let request: Request =
        ipc::recv_prompt_message_until(&mut io.stream, initial_deadline, || {
            shutdown.is_requested()
        })?;
    let request = SensitivePromptRequest::new(request);
    let peer_uid = get_peer_uid(&io.stream);
    debug!(
        "Received request: {:?}",
        request
            .as_ref()
            .cmd
            .as_ref()
            .map(|cmd| std::mem::discriminant(cmd))
    );

    if let Some(response) = initial_prompt_protocol_response(
        request.as_ref(),
        config.presence.mode == PresenceMode::Confirm,
    ) {
        io.write_response(&response)?;
        return Ok(());
    }

    if matches!(request.as_ref().cmd.as_ref(), Some(Cmd::BeginAuthV1(_))) {
        let lazy_camera = LazyCameraHandle {
            profile: Arc::clone(camera_profile),
            admission: camera_admission.clone(),
            factory: Arc::clone(&camera_factory),
        };
        let worker_engine = Arc::clone(&engine);
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        coordinate_prompt_connection_with_shutdown(
            io,
            Some(request.take()),
            |begin| {
                let peer_uid = peer_uid.ok_or(protocol::PromptErrorCode::Unavailable)?;
                prepare_prompt_pending(
                    peer_uid,
                    connection_id,
                    config,
                    storage.as_ref(),
                    prompt_manager,
                    begin,
                )
            },
            |pending| {
                let username = pending.username.clone();
                let revalidation_config = worker_config.clone();
                let revalidation_storage = Arc::clone(&worker_storage);
                spawn_prompt_authentication_after_revalidation(
                    pending,
                    move |pending| {
                        claim_prompt_commit(
                            pending,
                            &revalidation_config,
                            revalidation_storage.as_ref(),
                        )
                    },
                    move |lease| {
                        run_committed_prompt_authentication(
                            lease,
                            worker_engine.as_ref(),
                            worker_storage.as_ref(),
                            &worker_config,
                            lazy_camera,
                            &username,
                        )
                    },
                )
            },
            shutdown,
        )?;
        return Ok(());
    }

    // Prompt-bearing initial forms returned above. General dispatch now owns a
    // non-prompt request without retaining the cleanup wrapper.
    let request = request.take();

    let mut auth_perf = matches!(
        request.cmd.as_ref(),
        Some(Cmd::Authenticate(_) | Cmd::AuthenticateV1(_))
    )
    .then(|| server_accepted.map(|accepted| AuthPerfTrace::new(accepted, defer_camera_stop)))
    .flatten();
    let mut deferred_cleanup = None;
    let operation = current_operation(&request);
    let response = match peer_uid {
        Some(peer_uid) => match authorize_and_then(
            &SystemIdentityResolver,
            operation,
            &AuthorizationContext::initial(
                peer_uid,
                config.presence.mode == PresenceMode::Confirm
                    && !matches!(request.cmd.as_ref(), Some(Cmd::AuthenticateV1(_))),
            ),
            |authorization| -> Result<Option<Response>> {
                if matches!(
                    request.cmd.as_ref(),
                    Some(
                        Cmd::Enroll(_)
                            | Cmd::EnrollV1(_)
                            | Cmd::EnrollBatch(_)
                            | Cmd::EnrollBatchV1(_)
                    )
                ) {
                    let username = authorization
                        .canonical_target()
                        .expect("enrollment authorization resolves a target")
                        .username();
                    let response = dispatch_authorized_enrollment(
                        request.cmd.as_ref(),
                        username,
                        |request, username| {
                            handle_enroll(
                                engine.as_ref(),
                                config,
                                camera_admission,
                                storage.as_ref(),
                                camera_profile,
                                camera_factory.as_ref(),
                                username,
                                &request.label,
                            )
                        },
                        |request, username| {
                            handle_enroll_batch(
                                engine.as_ref(),
                                storage.as_ref(),
                                username,
                                &request.session_dir,
                                &request.label,
                            )
                        },
                    )
                    .expect("enrollment commands are handled at the compatibility boundary");
                    return Ok(Some(response));
                }
                let response = match request.cmd.as_ref() {
                    Some(Cmd::Authenticate(req)) => {
                        let username = authorization
                            .canonical_target()
                            .expect("authenticate authorization resolves a target")
                            .username();
                        let result = handle_authenticate(
                            engine.as_ref(),
                            config,
                            camera_admission,
                            storage.as_ref(),
                            camera_profile,
                            camera_factory.as_ref(),
                            username,
                            req.timeout,
                            auth_perf.as_mut(),
                        );
                        deferred_cleanup = result.deferred_cleanup;
                        result.response
                    }
                    Some(Cmd::AuthenticateV1(req)) => {
                        let username = authorization
                            .canonical_target()
                            .expect("versioned authenticate authorization resolves a target")
                            .username();
                        dispatch_authenticate_v1_with(
                            req,
                            || config.presence.mode == PresenceMode::Confirm,
                            |req| {
                                let result = handle_authenticate(
                                    engine.as_ref(),
                                    config,
                                    camera_admission,
                                    storage.as_ref(),
                                    camera_profile,
                                    camera_factory.as_ref(),
                                    username,
                                    req.timeout,
                                    auth_perf.as_mut(),
                                );
                                deferred_cleanup = result.deferred_cleanup;
                                result.response
                            },
                        )
                    }
                    Some(Cmd::BeginAuthV1(_)) => {
                        unreachable!("prompt begin is owned by the connection coordinator")
                    }
                    Some(Cmd::CommitAuthV1(_) | Cmd::CancelAuthV1(_)) => {
                        unreachable!("initial prompt phase gate rejects commit and cancel")
                    }
                    Some(
                        Cmd::Enroll(_)
                        | Cmd::EnrollV1(_)
                        | Cmd::EnrollBatch(_)
                        | Cmd::EnrollBatchV1(_),
                    ) => unreachable!("enrollment commands are dispatched before general handlers"),
                    Some(Cmd::Detect(req)) => {
                        handle_detect(engine.as_ref(), &req.frame, req.height, req.width)
                    }
                    Some(Cmd::Ping(_)) => Response::pong(),
                    Some(Cmd::Info(_)) => Response::daemon_info(
                        engine.registered_preferred_provider(),
                        face::FACE_EMBEDDING_DIM as u32,
                        uptime,
                        config.security.embedding_mode as u32,
                        config.presence.mode == PresenceMode::Confirm,
                        active_storage_ready(storage.as_ref()),
                    ),
                    Some(Cmd::EnrollmentPresence(_)) => {
                        let username = authorized_username(&authorization, "presence");
                        handle_enrollment_presence(storage.as_ref(), username)
                    }
                    Some(Cmd::ListEnrollments(_)) => {
                        let username = authorized_username(&authorization, "list");
                        handle_list_enrollments(storage.as_ref(), username)
                    }
                    Some(Cmd::RemoveEnrollment(req)) => {
                        let username = authorized_username(&authorization, "remove");
                        handle_remove_enrollment(
                            storage.as_ref(),
                            username,
                            &req.enrollment_id,
                            req.expected_generation,
                        )
                    }
                    Some(Cmd::ClearEnrollments(req)) => {
                        let username = authorized_username(&authorization, "clear");
                        handle_clear_enrollments(
                            storage.as_ref(),
                            username,
                            req.expected_generation,
                        )
                    }
                    Some(Cmd::ReloadStorage(_)) => handle_reload_storage(storage.as_ref()),
                    Some(Cmd::SecurityInfo(_)) => handle_security_info(
                        engine.as_ref(),
                        config,
                        storage.as_ref(),
                        runtime_identity,
                    ),
                    Some(Cmd::Shutdown(_)) => {
                        info!("Shutdown requested");
                        handle_root_shutdown(io, shutdown)?;
                        return Ok(None);
                    }
                    Some(Cmd::CheckCredential(_)) => {
                        let username = authorization
                            .canonical_target()
                            .expect("credential check authorization resolves a target")
                            .username();
                        handle_check_credential(config, username)
                    }
                    Some(Cmd::RevokeCredential(req)) => {
                        let username = authorization
                            .canonical_target()
                            .expect("credential revocation authorization resolves a target")
                            .username();
                        handle_revoke_credential(config, username, &req.session_id)
                    }
                    None => unreachable!("unknown operations are denied before dispatch"),
                };
                Ok(Some(response))
            },
        ) {
            Ok(dispatch) => match dispatch? {
                Some(response) => response,
                None => return Ok(()),
            },
            Err(_) if matches!(request.cmd.as_ref(), Some(Cmd::BeginAuthV1(_))) => {
                Response::prompt_error(protocol::PromptErrorCode::Unavailable)
            }
            Err(_) => Response::error("permission denied"),
        },
        None => Response::error("permission denied"),
    };

    let coordinated = coordinate_response_cleanup(
        successful_response_cleanup_order(defer_camera_stop),
        deferred_cleanup.take(),
        || io.write_response(&response),
        |cleanup, wait_for_reaper| cleanup.finish(camera_admission, wait_for_reaper),
    );
    if let Some(perf) = auth_perf.as_mut() {
        perf.response_write = coordinated.write_duration;
        perf.response_write_complete = Some(
            coordinated
                .write_completed_at
                .saturating_duration_since(perf.server_accepted),
        );
        if let Some(report) = coordinated.cleanup_report.as_ref() {
            perf.camera_stop_call += report.stop_duration;
            perf.cleanup_mode = report.mode;
        }
        perf.cleanup_boundary = coordinated
            .cleanup_boundary_at
            .map(|boundary| boundary.saturating_duration_since(perf.server_accepted));
    }
    if let Some(perf) = auth_perf.as_ref() {
        perf.emit(&response, coordinated.write_result.is_ok());
    }
    coordinated.write_result?;
    Ok(())
}

fn configure_initial_io_deadlines(stream: &UnixStream) -> std::io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(10)))
}

/// Open a camera from the cached profile and start it, invalidating and
/// re-probing the profile once if startup fails.
struct CameraStartFailure {
    error: anyhow::Error,
    pending_cleanup: Option<PendingCameraCleanup>,
    pending_invalidation: Option<ProfileInvalidation>,
}

struct StartedCamera {
    camera: Box<dyn CameraCapture>,
    profile_token: CameraProfileToken,
}

impl std::fmt::Debug for CameraStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CameraStartFailure")
            .field("error", &self.error)
            .field("pending_cleanup", &self.pending_cleanup.is_some())
            .field("pending_invalidation", &self.pending_invalidation.is_some())
            .finish()
    }
}

impl std::fmt::Display for CameraStartFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for CameraStartFailure {}

fn open_started_camera_from_profile_cache(
    camera_profile: &Arc<CameraProfileCache>,
    held: &CameraAdmissionHeld<'_>,
    camera_factory: &dyn CameraFactory,
) -> std::result::Result<StartedCamera, CameraStartFailure> {
    let mut first_error = None;
    for attempt in 0..2 {
        let profile = resolve_camera_profile_already_admitted(camera_profile, held, || false)
            .map_err(|error| CameraStartFailure {
                error,
                pending_cleanup: None,
                pending_invalidation: None,
            })?;
        let mut camera = camera_factory.create(&profile);
        match camera.start() {
            Ok(()) => {
                return Ok(StartedCamera {
                    camera,
                    profile_token: profile.token,
                });
            }
            Err(error) if attempt == 0 => {
                let invalidation =
                    profile_invalidation_for_failure(camera_profile, profile.token, error.kind());
                first_error = Some(anyhow::Error::new(error));
                match camera.stop() {
                    CameraStopOutcome::Pending(pending_cleanup) => {
                        return Err(CameraStartFailure {
                            error: first_error.take().unwrap(),
                            pending_cleanup: Some(pending_cleanup),
                            pending_invalidation: invalidation,
                        });
                    }
                    CameraStopOutcome::FailedPanicked => {
                        error!("Camera worker panicked after startup failure");
                    }
                    CameraStopOutcome::Released => {}
                }
                if let Some(invalidation) = invalidation {
                    invalidation.apply();
                }
            }
            Err(error) => {
                let invalidation =
                    profile_invalidation_for_failure(camera_profile, profile.token, error.kind());
                let error = anyhow::Error::new(error)
                    .context("failed to start camera capture worker after reprobe");
                let pending_cleanup = match camera.stop() {
                    CameraStopOutcome::Pending(pending) => Some(pending),
                    CameraStopOutcome::FailedPanicked => {
                        error!("Camera worker panicked after reprobe startup failure");
                        None
                    }
                    CameraStopOutcome::Released => None,
                };
                let pending_invalidation = if pending_cleanup.is_some() {
                    invalidation
                } else {
                    if let Some(invalidation) = invalidation {
                        invalidation.apply();
                    }
                    None
                };
                return Err(CameraStartFailure {
                    error,
                    pending_cleanup,
                    pending_invalidation,
                });
            }
        }
    }
    Err(CameraStartFailure {
        error: first_error
            .unwrap()
            .context("failed to start camera capture worker"),
        pending_cleanup: None,
        pending_invalidation: None,
    })
}

fn profile_invalidation_for_failure(
    camera_profile: &Arc<CameraProfileCache>,
    token: CameraProfileToken,
    kind: CameraFailureKind,
) -> Option<ProfileInvalidation> {
    (kind == CameraFailureKind::StaleProfile).then(|| ProfileInvalidation {
        cache: Arc::clone(camera_profile),
        token,
    })
}

/// Capture a frame, releasing the old worker/device before one bounded reprobe.
fn capture_frame_bounded(
    camera: &mut Box<dyn CameraCapture>,
    profile_token: &mut CameraProfileToken,
    camera_profile: &Arc<CameraProfileCache>,
    held: &CameraAdmissionHeld<'_>,
    camera_factory: &dyn CameraFactory,
    mut perf: Option<&mut AuthPerfTrace>,
) -> Result<Frame> {
    match camera.capture_frame() {
        Ok(frame) => Ok(frame),
        Err(first_err) => {
            let first_invalidation =
                profile_invalidation_for_failure(camera_profile, *profile_token, first_err.kind());
            warn!(error = %first_err, "Camera capture failed; releasing ownership before one bounded reprobe");
            if let Err(stop_error) = stop_camera_for_restart(camera, perf.as_deref_mut()) {
                // The admission lease remains held by the pending cleanup, so
                // invalidation cannot trigger a reprobe until ownership exits.
                if let Some(invalidation) = first_invalidation {
                    invalidation.apply();
                }
                return Err(stop_error).context("camera capture failed with cleanup pending");
            }
            if let Some(invalidation) = first_invalidation {
                invalidation.apply();
            }
            let mut retry = match open_started_camera_from_profile_cache(
                camera_profile,
                held,
                camera_factory,
            ) {
                Ok(retry) => retry,
                Err(mut failure) => {
                    if let Some(pending) = failure.pending_cleanup.take() {
                        if let Some(invalidation) = failure.pending_invalidation.take() {
                            invalidation.apply();
                        }
                        camera.retain_pending_cleanup(pending);
                    }
                    return Err(failure.error)
                        .context("camera reprobe after capture failure failed");
                }
            };
            match retry.camera.capture_frame() {
                Ok(frame) => {
                    *profile_token = retry.profile_token;
                    *camera = retry.camera;
                    Ok(frame)
                }
                Err(retry_error) => {
                    let retry_invalidation = profile_invalidation_for_failure(
                        camera_profile,
                        retry.profile_token,
                        retry_error.kind(),
                    );
                    let stop_started = perf.as_ref().map(|_| Instant::now());
                    let retry_stop = retry.camera.stop();
                    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), stop_started) {
                        perf.camera_stop_call += started.elapsed();
                    }
                    match retry_stop {
                        CameraStopOutcome::Pending(pending) => {
                            // Preserve the request's admission lease until the
                            // retry worker is handed to the normal cleanup reaper.
                            if let Some(invalidation) = retry_invalidation {
                                invalidation.apply();
                            }
                            camera.retain_pending_cleanup(pending);
                        }
                        CameraStopOutcome::FailedPanicked => {
                            if let Some(invalidation) = retry_invalidation {
                                invalidation.apply();
                            }
                            error!("Retried camera worker panicked while stopping");
                        }
                        CameraStopOutcome::Released => {
                            if let Some(invalidation) = retry_invalidation {
                                invalidation.apply();
                            }
                        }
                    }
                    Err(retry_error).context(format!(
                        "camera capture failed after one reprobe; first failure: {first_err}"
                    ))
                }
            }
        }
    }
}

fn stop_camera_for_restart(
    camera: &mut Box<dyn CameraCapture>,
    perf: Option<&mut AuthPerfTrace>,
) -> Result<()> {
    let started = perf.as_ref().map(|_| Instant::now());
    let outcome = camera.stop();
    if let (Some(perf), Some(started)) = (perf, started) {
        perf.camera_stop_call += started.elapsed();
    }
    match outcome {
        CameraStopOutcome::Pending(cleanup) => {
            camera.retain_pending_cleanup(cleanup);
            bail!("camera worker cleanup pending; reprobe deferred");
        }
        CameraStopOutcome::FailedPanicked => {
            error!("Camera worker panicked while stopping for reprobe");
        }
        CameraStopOutcome::Released => {}
    }
    Ok(())
}

struct CameraCleanup {
    camera: Box<dyn CameraCapture>,
    lease: Option<CameraLease>,
    admission: CameraAdmission,
}

struct CleanupReport {
    mode: CleanupMode,
    stop_duration: Duration,
}

impl CameraCleanup {
    fn finish(mut self, _admission: &CameraAdmission, _wait_for_reaper: bool) -> CleanupReport {
        self.finish_inner(None)
    }

    fn finish_with_invalidation(
        mut self,
        invalidation: Option<ProfileInvalidation>,
    ) -> CleanupReport {
        self.finish_inner(invalidation)
    }

    fn finish_inner(&mut self, invalidation: Option<ProfileInvalidation>) -> CleanupReport {
        let stop_started = Instant::now();
        let outcome = self.camera.stop();
        let stop_duration = stop_started.elapsed();
        let lease = self.lease.take().expect("camera cleanup lease is present");

        let mode = match outcome {
            CameraStopOutcome::Released => {
                if let Some(invalidation) = invalidation {
                    invalidation.apply();
                }
                drop(lease);
                CleanupMode::Synchronous
            }
            CameraStopOutcome::FailedPanicked => {
                if let Some(invalidation) = invalidation {
                    invalidation.apply();
                }
                drop(lease);
                CleanupMode::FailedPanicked
            }
            CameraStopOutcome::Pending(pending) => {
                self.admission
                    .handoff_with_invalidation(pending, lease, invalidation)
            }
        };
        CleanupReport {
            mode,
            stop_duration,
        }
    }
}

impl Drop for CameraCleanup {
    fn drop(&mut self) {
        if self.lease.is_some() {
            let report = self.finish_inner(None);
            if matches!(
                report.mode,
                CleanupMode::UnresolvedTracked | CleanupMode::FailedPanicked
            ) {
                error!(
                    cleanup_mode = report.mode.as_str(),
                    "Camera cleanup during unwind was exceptional"
                );
            }
        }
    }
}

struct CoordinatedResponse<E> {
    write_result: std::result::Result<(), E>,
    write_duration: Duration,
    write_completed_at: Instant,
    cleanup_report: Option<CleanupReport>,
    cleanup_boundary_at: Option<Instant>,
}

fn coordinate_response_cleanup<C, E>(
    order: ResponseCleanupOrder,
    mut cleanup: Option<C>,
    mut write: impl FnMut() -> std::result::Result<(), E>,
    mut finish: impl FnMut(C, bool) -> CleanupReport,
) -> CoordinatedResponse<E> {
    // Gate-off performs the bounded stop call before writing. If that call
    // yields pending ownership, `finish` hands it to tracked reaper state and
    // returns immediately; the exceptional response may then proceed while
    // admission remains unavailable until confirmed worker release.
    let mut cleanup_report = None;
    let mut cleanup_boundary_at = None;
    if order == ResponseCleanupOrder::BeforeWrite {
        if let Some(cleanup) = cleanup.take() {
            cleanup_report = Some(finish(cleanup, true));
            cleanup_boundary_at = Some(Instant::now());
        }
    }

    let write_started = Instant::now();
    let write_result = write();
    let write_duration = write_started.elapsed();
    let write_completed_at = Instant::now();

    if let Some(cleanup) = cleanup.take() {
        cleanup_report = Some(finish(cleanup, false));
        cleanup_boundary_at = Some(Instant::now());
    }

    CoordinatedResponse {
        write_result,
        write_duration,
        write_completed_at,
        cleanup_report,
        cleanup_boundary_at,
    }
}

fn finish_camera_cleanup_before_response(
    cleanup: CameraCleanup,
    admission: &CameraAdmission,
    perf: Option<&mut AuthPerfTrace>,
) {
    let report = cleanup.finish(admission, true);
    if let Some(perf) = perf {
        perf.camera_stop_call += report.stop_duration;
        perf.cleanup_mode = report.mode;
        perf.cleanup_boundary = Some(perf.server_accepted.elapsed());
    }
}

struct AuthenticationResult {
    response: Response,
    deferred_cleanup: Option<CameraCleanup>,
}

impl AuthenticationResult {
    fn immediate(response: Response) -> Self {
        Self {
            response,
            deferred_cleanup: None,
        }
    }
}

/// Handle an authentication request.
fn handle_authenticate(
    engine: &impl ServerInference,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    storage: &dyn StorageBackend,
    camera_profile: &Arc<CameraProfileCache>,
    camera_factory: &dyn CameraFactory,
    username: &str,
    timeout_override: u32,
    mut perf: Option<&mut AuthPerfTrace>,
) -> AuthenticationResult {
    let start = Instant::now();

    // Credential caching is intentionally disabled in the current deployment
    // until PAM session scoping is wired end-to-end.
    if credential_cache_runtime_enabled(config) {
        match credential::check_credential(
            username,
            "",
            config.credentials.cache_ttl_secs as u64,
            &config.credentials,
        ) {
            Ok(true) => {
                debug!("Cached credential valid for {username}");
                return AuthenticationResult::immediate(Response::credential_valid());
            }
            Ok(false) => debug!("No valid cached credential for {username}"),
            Err(e) => debug!("Credential check failed: {e}"),
        }
    }

    let model_load_started = perf.as_ref().map(|_| Instant::now());
    let canonical = CanonicalUsername::new(username.to_owned())
        .expect("authorized NSS username is canonical storage input");
    let model_lease = storage.authenticate(&canonical);
    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), model_load_started) {
        perf.model_load_cache = started.elapsed();
    }
    let model_lease = match model_lease {
        Ok(lease) => lease,
        Err(StorageBackendError::Absent) => {
            return AuthenticationResult::immediate(Response::auth_failed(
                0.0,
                0,
                "no face models enrolled",
            ));
        }
        Err(error) => return AuthenticationResult::immediate(storage_error_response(error)),
    };

    let threshold = config.ml.recognition_threshold;
    let timeout = if timeout_override > 0 {
        timeout_override.min(30)
    } else {
        config.video.timeout.min(30)
    };

    let camera_admission_started = perf.as_ref().map(|_| Instant::now());
    let camera_lease_result = camera_admission.acquire(CAMERA_LOCK_TIMEOUT);
    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), camera_admission_started) {
        perf.camera_admission_wait = started.elapsed();
    }
    let camera_lease = match camera_lease_result {
        Ok(guard) => guard,
        Err(response) => {
            warn!(
                username,
                "Authentication infrastructure failure: camera busy"
            );
            return AuthenticationResult::immediate(response);
        }
    };

    let mut camera_start_started = perf.as_ref().map(|_| Instant::now());
    let camera = match open_started_camera_from_profile_cache(
        camera_profile,
        &CameraAdmissionHeld::new(&camera_lease),
        camera_factory,
    ) {
        Ok(camera) => camera,
        Err(mut e) => {
            warn!(username, error = %e, "Authentication infrastructure failure opening/starting camera");
            if let Some(pending) = e.pending_cleanup.take() {
                let _ = camera_admission.handoff_with_invalidation(
                    pending,
                    camera_lease,
                    e.pending_invalidation.take(),
                );
            }
            return AuthenticationResult::immediate(Response::error(&format!("Camera error: {e}")));
        }
    };
    let mut cleanup = CameraCleanup {
        camera: camera.camera,
        lease: Some(camera_lease),
        admission: camera_admission.clone(),
    };
    let mut profile_token = camera.profile_token;

    let deadline = Duration::from_secs(timeout as u64);
    let mut frames_processed = 0u32;
    let mut best_score = 0.0f32;
    let mut dark_frames = 0u32;

    // Main recognition loop
    while start.elapsed() < deadline {
        // Capture frame
        let frame = match capture_frame_bounded(
            &mut cleanup.camera,
            &mut profile_token,
            camera_profile,
            &CameraAdmissionHeld::new(
                cleanup
                    .lease
                    .as_ref()
                    .expect("active camera cleanup retains admission lease"),
            ),
            camera_factory,
            perf.as_deref_mut(),
        ) {
            Ok(frame) => frame,
            Err(e) => {
                warn!(username, error = %e, "Authentication infrastructure failure capturing frame");
                finish_camera_cleanup_before_response(
                    cleanup,
                    camera_admission,
                    perf.as_deref_mut(),
                );
                return AuthenticationResult::immediate(Response::error(&format!(
                    "Camera capture failed: {e}"
                )));
            }
        };
        if let (Some(perf), Some(started)) = (perf.as_deref_mut(), camera_start_started.take()) {
            perf.camera_start_to_first_frame = Some(started.elapsed());
        }

        frames_processed += 1;

        // Check for dark/black frames
        if is_dark_frame(&frame, config.video.dark_threshold) {
            dark_frames += 1;
            if config.video.max_dark_frames > 0 && dark_frames >= config.video.max_dark_frames {
                info!(
                    username,
                    dark_frames, "Exceeded max consecutive dark frames — camera may be covered"
                );
                finish_camera_cleanup_before_response(
                    cleanup,
                    camera_admission,
                    perf.as_deref_mut(),
                );
                return AuthenticationResult::immediate(Response::auth_failed(
                    0.0,
                    frames_processed,
                    &format!(
                        "Too many dark frames ({dark_frames}) — camera may be covered or IR emitter not working"
                    ),
                ));
            }
            continue;
        }
        // Reset dark frame counter on a good frame
        dark_frames = 0;
        if let Some(perf) = perf.as_deref_mut() {
            perf.accepted_frames += 1;
        }

        // Detect and encode faces
        let is_gray = frame.format == FrameFormat::Gray;
        let analyze_started = perf.as_ref().map(|_| Instant::now());
        let faces = engine.analyze(&frame.data, frame.width, frame.height, is_gray);
        if let (Some(perf), Some(started)) = (perf.as_deref_mut(), analyze_started) {
            perf.analyze_inference += started.elapsed();
        }
        let faces = match faces {
            Ok(f) => f,
            Err(e) => {
                debug!("Detection error: {e}");
                continue;
            }
        };

        // Match against enrolled faces
        let matching_started = perf.as_ref().map(|_| Instant::now());
        for face_result in &faces {
            if let Some(ref embedding) = face_result.embedding {
                if embedding.len() != face::FACE_EMBEDDING_DIM {
                    debug!(
                        expected = face::FACE_EMBEDDING_DIM,
                        actual = embedding.len(),
                        "Face matching error: invalid query embedding length"
                    );
                    continue;
                }

                if embedding.iter().any(|value| !value.is_finite()) {
                    debug!("Face matching error: query embedding contains NaN/Inf");
                    continue;
                }

                let (matched_index, score) = face::find_best_match_flat(
                    embedding,
                    model_lease.flat_embeddings(),
                    model_lease.entry_count(),
                    threshold,
                );

                if score > best_score {
                    best_score = score;
                }

                if let Some(match_idx) = matched_index {
                    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), matching_started) {
                        perf.matching += started.elapsed();
                    }
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

                    let model_label = model_lease
                        .labels()
                        .nth(match_idx)
                        .expect("matching index is within the leased model");
                    info!(
                        username,
                        model_index = match_idx,
                        model_label,
                        score,
                        elapsed_ms,
                        frames = frames_processed,
                        "Authentication successful"
                    );

                    // Credential caching remains intentionally disabled until
                    // PAM session scoping is implemented.
                    if credential_cache_runtime_enabled(config) {
                        if let Err(e) = credential::store_credential(
                            username,
                            "",
                            config.credentials.cache_ttl_secs,
                            &config.credentials,
                        ) {
                            warn!("Failed to cache credential: {e}");
                        }
                    }

                    let response =
                        Response::success(match_idx as u32, model_label, score, elapsed_ms);
                    return AuthenticationResult {
                        response,
                        deferred_cleanup: Some(cleanup),
                    };
                }
            }
        }
        if let (Some(perf), Some(started)) = (perf.as_deref_mut(), matching_started) {
            perf.matching += started.elapsed();
        }
    }

    // Timeout
    let reason = if dark_frames == frames_processed && frames_processed > 0 {
        "All frames too dark — check camera/IR emitter".into()
    } else {
        format!(
            "Timeout after {frames_processed} frames ({dark_frames} dark), best score: {best_score:.3}"
        )
    };

    info!(
        username,
        frames = frames_processed,
        best_score,
        "Authentication failed due to no match/timeout: {reason}"
    );

    finish_camera_cleanup_before_response(cleanup, camera_admission, perf.as_deref_mut());
    AuthenticationResult::immediate(Response::auth_failed(best_score, frames_processed, &reason))
}

/// Handle a face enrollment request.
fn handle_enroll(
    engine: &impl ServerInference,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    storage: &dyn StorageBackend,
    camera_profile: &Arc<CameraProfileCache>,
    camera_factory: &dyn CameraFactory,
    username: &str,
    label: &str,
) -> Response {
    let inference_scratch = match engine.plaintext_scratch_bytes() {
        Ok(bytes) => bytes,
        Err(error) => return Response::error(&format!("Inference accounting error: {error}")),
    };
    // Live enrollment is root-authorized independently of prompt policy. It
    // explicitly resolves one bounded profile and never consumes PAM prompt
    // state or transaction tokens.
    let profile = match resolve_live_enrollment_profile(camera_profile, camera_admission) {
        Ok(profile) => profile,
        Err(_) => return storage_error_response(StorageBackendError::Unavailable),
    };
    let pipeline_bytes = match profile.live_pipeline_bytes(inference_scratch) {
        Ok(bytes) => bytes,
        Err(_) => {
            return storage_error_response(StorageBackendError::InvalidInput(
                "live camera profile memory",
            ));
        }
    };
    handle_live_enrollment_with(
        storage,
        username,
        label,
        pipeline_bytes,
        |canonical, initial, operation_permit, input_permit| {
            execute_live_enrollment(
                engine,
                config,
                camera_admission,
                storage,
                camera_profile,
                &profile,
                camera_factory,
                username,
                label,
                canonical,
                initial.0,
                operation_permit,
                input_permit,
            )
        },
    )
}

fn resolve_live_enrollment_profile(
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
) -> Result<ResolvedCameraProfile> {
    resolve_camera_profile(camera_profile, camera_admission, || false)
}

fn handle_live_enrollment_with(
    storage: &dyn StorageBackend,
    username: &str,
    label: &str,
    pipeline_bytes: usize,
    execute: impl FnOnce(CanonicalUsername, (u64, usize), BudgetPermit, BudgetPermit) -> Response,
) -> Response {
    let live_plaintext_bytes = match live_enrollment_plaintext_bytes(label.len(), pipeline_bytes) {
        Ok(bytes) => bytes,
        Err(error) => return storage_error_response(error),
    };
    let append_shape = match AppendAdmissionShape::new(1, label.len()) {
        Ok(shape) => shape,
        Err(error) => return storage_error_response(error),
    };
    with_enrollment_admission(
        storage,
        username,
        label,
        live_plaintext_bytes,
        append_shape,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_live_enrollment(
    engine: &impl ServerInference,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    storage: &dyn StorageBackend,
    camera_profile: &Arc<CameraProfileCache>,
    admitted_profile: &ResolvedCameraProfile,
    camera_factory: &dyn CameraFactory,
    username: &str,
    label: &str,
    canonical: CanonicalUsername,
    expected_generation: u64,
    operation_permit: BudgetPermit,
    _input_permit: BudgetPermit,
) -> Response {
    let camera_lease = match camera_admission.acquire(CAMERA_LOCK_TIMEOUT) {
        Ok(guard) => guard,
        Err(response) => return response,
    };

    // Use exactly the profile whose phase peak was admitted. Enrollment never
    // reprobes or falls back to FFmpeg because neither would be covered by this
    // request's reserved V4L2 envelope.
    let mut camera = camera_factory.create(admitted_profile);
    match camera.start_enrollment() {
        Ok(()) => {}
        Err(e) => {
            warn!(username, error = %e, "Enrollment infrastructure failure opening/starting camera");
            return finish_live_enrollment_camera_failure(
                CameraCleanup {
                    camera,
                    lease: Some(camera_lease),
                    admission: camera_admission.clone(),
                },
                camera_profile,
                admitted_profile.token,
                e,
                "Camera error",
            );
        }
    }
    let mut cleanup = CameraCleanup {
        camera,
        lease: Some(camera_lease),
        admission: camera_admission.clone(),
    };

    // Capture several frames and pick the best face
    let mut best_face: Option<(Zeroizing<Vec<f32>>, f32)> = None;
    let deadline = Duration::from_secs(5);
    let start = Instant::now();

    while start.elapsed() < deadline {
        let frame = match cleanup.camera.capture_frame() {
            Ok(frame) => frame,
            Err(e) => {
                warn!(username, error = %e, "Enrollment infrastructure failure capturing frame");
                return finish_live_enrollment_camera_failure(
                    cleanup,
                    camera_profile,
                    admitted_profile.token,
                    e,
                    "Camera capture failed",
                );
            }
        };

        if frame.data.len() > crate::camera::MAX_NORMALIZED_FRAME_BYTES {
            finish_camera_cleanup_before_response(cleanup, camera_admission, None);
            return storage_error_response(StorageBackendError::InvalidInput(
                "live enrollment frame bytes",
            ));
        }

        if is_dark_frame(&frame, config.video.dark_threshold) {
            continue;
        }

        let is_gray = frame.format == FrameFormat::Gray;
        match engine.detect(&frame.data, frame.width, frame.height, is_gray) {
            Ok(faces) => {
                if faces.len() > MAX_LIVE_FACES_PER_FRAME {
                    continue;
                }
                for face_result in faces {
                    let Ok(embedding) = engine.encode(
                        &frame.data,
                        frame.width,
                        frame.height,
                        &face_result,
                        is_gray,
                    ) else {
                        continue;
                    };
                    let embedding = Zeroizing::new(embedding);
                    let det_score = face_result.score;
                    if best_face.is_none() || det_score > best_face.as_ref().unwrap().1 {
                        best_face = Some((embedding, det_score));
                    }
                }
                // If we have a good detection, take it
                if let Some((_, score)) = &best_face {
                    if *score > 0.8 {
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("Enrollment detection error: {e}");
                continue;
            }
        }
    }

    finish_camera_cleanup_before_response(cleanup, camera_admission, None);
    let Some((mut embedding, det_score)) = best_face else {
        return Response::error("No face detected during enrollment");
    };
    let enrollment_id = match new_enrollment_id(&mut OsRandomSource, &HashSet::new()) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let entry = match EnrollmentEntry::try_from_embedding_vec(
        enrollment_id,
        unix_timestamp_now(),
        label.to_owned(),
        std::mem::take(&mut *embedding),
    ) {
        Ok(entry) => entry,
        Err(_) => return storage_error_response(StorageBackendError::InvalidInput("entry")),
    };
    let request = AppendRequest::new(
        &canonical,
        expected_generation,
        std::slice::from_ref(&entry),
    )
    .expect("single enrollment append is nonempty");
    match storage.append_admitted(request, operation_permit) {
        Ok(result) => {
            info!(username, label, det_score, "Face enrollment committed");
            let total_count = match u32::try_from(result.total_entries()) {
                Ok(value) => value,
                Err(_) => {
                    return storage_error_response(StorageBackendError::InvalidInput("count"));
                }
            };
            Response::enrolled(
                enrollment_id.into_bytes(),
                result.generation(),
                total_count,
                det_score,
            )
        }
        Err(error) => storage_error_response(error),
    }
}

fn finish_live_enrollment_camera_failure(
    cleanup: CameraCleanup,
    camera_profile: &Arc<CameraProfileCache>,
    profile_token: CameraProfileToken,
    error: CameraCaptureError,
    response_context: &'static str,
) -> Response {
    let kind = error.kind();
    let invalidation = profile_invalidation_for_failure(camera_profile, profile_token, kind);
    cleanup.finish_with_invalidation(invalidation);
    Response::error(&format!("{response_context}: {error}"))
}

/// Handle a batch enrollment request.
///
/// For each image in the session directory:
/// 1. Load image and decode to BGR
/// 2. Run SCRFD face detection
/// 3. If exactly one face with score > 0.5: compute embedding, append to user models
/// 4. If no face or multiple faces: record rejection
/// 5. Save updated models to disk
fn handle_enroll_batch(
    engine: &impl ServerInference,
    storage: &dyn StorageBackend,
    username: &str,
    session_dir: &str,
    label: &str,
) -> Response {
    handle_batch_enrollment_with(
        storage,
        username,
        label,
        |canonical, initial, operation_permit, input_permit| {
            execute_batch_enrollment(
                engine,
                storage,
                username,
                session_dir,
                label,
                canonical,
                initial,
                operation_permit,
                input_permit,
            )
        },
    )
}

fn handle_batch_enrollment_with(
    storage: &dyn StorageBackend,
    username: &str,
    label: &str,
    execute: impl FnOnce(CanonicalUsername, (u64, usize), BudgetPermit, BudgetPermit) -> Response,
) -> Response {
    let batch_plaintext_bytes = match batch_enrollment_plaintext_bytes(label.len()) {
        Ok(bytes) => bytes,
        Err(error) => return storage_error_response(error),
    };
    let maximum_label_bytes = match label.len().checked_mul(MAX_BATCH_FILES) {
        Some(bytes) => bytes,
        None => return storage_error_response(StorageBackendError::InvalidInput("label bytes")),
    };
    let append_shape = match AppendAdmissionShape::new(MAX_BATCH_FILES, maximum_label_bytes) {
        Ok(shape) => shape,
        Err(error) => return storage_error_response(error),
    };
    with_enrollment_admission(
        storage,
        username,
        label,
        batch_plaintext_bytes,
        append_shape,
        execute,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_batch_enrollment(
    engine: &impl ServerInference,
    storage: &dyn StorageBackend,
    username: &str,
    session_dir: &str,
    label: &str,
    canonical: CanonicalUsername,
    initial: (u64, usize),
    operation_permit: BudgetPermit,
    _input_permit: BudgetPermit,
) -> Response {
    let start = std::time::Instant::now();
    let mut image_files = match open_batch_images(Path::new(session_dir)) {
        Ok(images) => images,
        Err(message) => return Response::error(message),
    };
    let frames_found = u32::try_from(image_files.len()).expect("batch file limit fits u32");
    if frames_found == 0 {
        return Response::error("no image files found in session directory");
    }

    let mut admitted_images = Vec::new();
    if admitted_images
        .try_reserve_exact(image_files.len())
        .is_err()
    {
        return storage_error_response(StorageBackendError::Unavailable);
    }
    let mut aggregate_decoded_bytes = 0u64;
    for image in &mut image_files {
        let admitted = match image.read_and_inspect() {
            Ok(image) => image,
            Err(message) => return Response::error(&format!("{}: {message}", image.display_name)),
        };
        aggregate_decoded_bytes = match aggregate_decoded_bytes.checked_add(admitted.decoded_bytes)
        {
            Some(total) if total <= MAX_BATCH_AGGREGATE_DECODED_BYTES => total,
            _ => return Response::error("batch decoded byte total exceeds the limit"),
        };
        admitted_images.push(admitted);
    }

    let mut frames_accepted = 0u32;
    let mut frames_rejected = 0u32;
    let mut rejection_details: Vec<String> = Vec::new();
    let mut accepted_entries = Vec::new();
    if accepted_entries
        .try_reserve_exact(admitted_images.len())
        .is_err()
    {
        return storage_error_response(StorageBackendError::Unavailable);
    }
    let mut accepted_ids = HashSet::new();
    let mut random = OsRandomSource;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for image in &admitted_images {
        let file_name = &image.display_name;
        let bgr_result = decode_image_as_bgr(image);
        let (bgr_data, width, height) = match bgr_result {
            Ok(data) => data,
            Err(e) => {
                frames_rejected += 1;
                rejection_details.push(format!("{file_name}: failed to load: {e}"));
                continue;
            }
        };

        // Detect faces
        let faces = match engine.detect(&bgr_data, width, height, false) {
            Ok(f) => f,
            Err(e) => {
                frames_rejected += 1;
                rejection_details.push(format!("{file_name}: detection error: {e}"));
                continue;
            }
        };

        if faces.is_empty() {
            frames_rejected += 1;
            rejection_details.push(format!("{file_name}: no face detected"));
            continue;
        }

        if faces.len() > 1 {
            frames_rejected += 1;
            rejection_details.push(format!(
                "{file_name}: multiple faces detected ({})",
                faces.len()
            ));
            continue;
        }

        let face = faces.into_iter().next().expect("one face was checked");
        if face.score < 0.5 {
            frames_rejected += 1;
            rejection_details.push(format!(
                "{file_name}: detection score too low ({:.2})",
                face.score
            ));
            continue;
        }

        match engine.encode(&bgr_data, width, height, &face, false) {
            Ok(embedding) => {
                let mut embedding = Zeroizing::new(embedding);
                // Validate embedding dimension and values
                if embedding.len() != face::FACE_EMBEDDING_DIM {
                    frames_rejected += 1;
                    rejection_details.push(format!(
                        "{file_name}: wrong embedding dim ({}, expected {})",
                        embedding.len(),
                        face::FACE_EMBEDDING_DIM
                    ));
                    continue;
                }
                if embedding.iter().any(|v| !v.is_finite()) {
                    frames_rejected += 1;
                    rejection_details.push(format!("{file_name}: embedding contains NaN/Inf"));
                    continue;
                }

                let enrollment_id = match new_enrollment_id(&mut random, &accepted_ids) {
                    Ok(id) => id,
                    Err(response) => return response,
                };
                let entry = match EnrollmentEntry::try_from_embedding_vec(
                    enrollment_id,
                    now,
                    label.to_owned(),
                    std::mem::take(&mut *embedding),
                ) {
                    Ok(entry) => entry,
                    Err(_) => {
                        return storage_error_response(StorageBackendError::InvalidInput("entry"));
                    }
                };
                accepted_ids.insert(enrollment_id);
                accepted_entries.push(entry);
                frames_accepted += 1;
                info!(
                    username,
                    file = %file_name,
                    det_score = face.score,
                    "Enrolled frame"
                );
            }
            Err(_) => {
                frames_rejected += 1;
                rejection_details.push(format!("{file_name}: no embedding computed"));
            }
        }
    }

    let (generation, total_count) = if accepted_entries.is_empty() {
        (initial.0, initial.1)
    } else {
        let request = AppendRequest::new(&canonical, initial.0, &accepted_entries)
            .expect("accepted batch append is nonempty");
        match storage.append_admitted(request, operation_permit) {
            Ok(result) => (result.generation(), result.total_entries()),
            Err(error) => return storage_error_response(error),
        }
    };

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Response::enroll_batch_done(
        frames_found,
        frames_accepted,
        frames_rejected,
        elapsed_ms,
        rejection_details,
        generation,
        match u32::try_from(total_count) {
            Ok(value) => value,
            Err(_) => return storage_error_response(StorageBackendError::InvalidInput("count")),
        },
    )
}

/// Handle a detection-only request (for testing/preview).
fn handle_detect(engine: &impl ServerInference, frame: &[u8], height: u32, width: u32) -> Response {
    let start = Instant::now();

    match engine.detect(frame, width, height, false) {
        Ok(faces) => detected_response(faces, start.elapsed().as_secs_f64() * 1000.0),
        Err(e) => Response::error(&format!("Detection error: {e}")),
    }
}

fn detected_response(faces: Vec<face::Face>, elapsed_ms: f64) -> Response {
    Response::detected(
        faces
            .into_iter()
            .map(|face| protocol::DetectedFace::detection(face.bbox, face.landmarks, face.score))
            .collect(),
        elapsed_ms,
    )
}

/// Handle credential check request.
fn handle_check_credential(config: &HowyConfig, username: &str) -> Response {
    if !credential_cache_runtime_enabled(config) {
        return Response::credential_invalid();
    }

    match credential::check_credential(
        username,
        "",
        config.credentials.cache_ttl_secs as u64,
        &config.credentials,
    ) {
        Ok(true) => Response::credential_valid(),
        _ => Response::credential_invalid(),
    }
}

fn handle_revoke_credential(config: &HowyConfig, username: &str, session_id: &str) -> Response {
    if !credential_cache_runtime_enabled(config) {
        let _ = (config, session_id);
        return Response::pong();
    }

    match credential::revoke_credential(username, session_id, &config.credentials) {
        Ok(()) => Response::pong(),
        Err(_) => Response::error("failed to revoke credential"),
    }
}

/// Runtime credential caching is intentionally disabled for the first PAM
/// deployment. This prevents empty or synthetic session IDs from creating
/// reusable auth success across unrelated PAM calls.
fn credential_cache_runtime_enabled(_config: &HowyConfig) -> bool {
    false
}

/// Check if a frame is too dark for face detection.
fn is_dark_frame(frame: &Frame, threshold: f32) -> bool {
    if frame.data.is_empty() {
        return true;
    }

    let mut dark_count = 0u32;
    let mut total = 0u32;

    match frame.format {
        FrameFormat::Gray => {
            for &g in frame.data.iter().step_by(16) {
                if g < 30 {
                    dark_count += 1;
                }
                total += 1;
            }
        }
        FrameFormat::Bgr => {
            for i in (0..frame.data.len()).step_by(48) {
                if i + 2 < frame.data.len() {
                    let brightness = (frame.data[i] as u32
                        + frame.data[i + 1] as u32
                        + frame.data[i + 2] as u32)
                        / 3;
                    if brightness < 30 {
                        dark_count += 1;
                    }
                    total += 1;
                }
            }
        }
    }

    if total == 0 {
        return true;
    }

    (dark_count as f32 / total as f32) * 100.0 > threshold
}

fn enrollment_plaintext_bytes(
    entry_capacity: usize,
    label_bytes: usize,
    transient_embeddings: usize,
) -> std::result::Result<usize, StorageBackendError> {
    let retained = entry_capacity
        .checked_mul(size_of::<EnrollmentEntry>().saturating_add(label_bytes))
        .ok_or(StorageBackendError::InvalidInput(
            "enrollment plaintext bytes",
        ))?;
    let transient = transient_embeddings
        .checked_mul(face::FACE_EMBEDDING_DIM)
        .and_then(|values| values.checked_mul(size_of::<f32>()))
        .ok_or(StorageBackendError::InvalidInput(
            "enrollment plaintext bytes",
        ))?;
    retained
        .checked_add(transient)
        .ok_or(StorageBackendError::InvalidInput(
            "enrollment plaintext bytes",
        ))
}

fn live_enrollment_plaintext_bytes(
    label_bytes: usize,
    pipeline_bytes: usize,
) -> std::result::Result<usize, StorageBackendError> {
    enrollment_plaintext_bytes(1, label_bytes, 2).and_then(|bytes| {
        bytes
            .checked_add(pipeline_bytes)
            .ok_or(StorageBackendError::InvalidInput(
                "live enrollment reservation",
            ))
    })
}

fn batch_enrollment_plaintext_bytes(
    label_bytes: usize,
) -> std::result::Result<usize, StorageBackendError> {
    enrollment_plaintext_bytes(MAX_BATCH_FILES, label_bytes, 1).and_then(|bytes| {
        bytes
            .checked_add(MAX_BATCH_TOTAL_ENCODED_BYTES as usize)
            .and_then(|bytes| bytes.checked_add(MAX_BATCH_DECODED_BYTES_PER_FILE))
            .ok_or(StorageBackendError::InvalidInput("batch reservation"))
    })
}

struct BatchImageFile {
    display_name: String,
    file: File,
    encoded_len: usize,
}

struct AdmittedBatchImage {
    display_name: String,
    encoded: Zeroizing<Vec<u8>>,
    bmp: BmpMetadata,
    decoded_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BmpMetadata {
    width: u32,
    height: u32,
    pixel_offset: usize,
    row_stride: usize,
}

impl BatchImageFile {
    fn read_and_inspect(&mut self) -> std::result::Result<AdmittedBatchImage, &'static str> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| "failed to seek validated image")?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(self.encoded_len)
            .map_err(|_| "failed to allocate bounded encoded image")?;
        self.file
            .by_ref()
            .take(MAX_BATCH_ENCODED_BYTES_PER_FILE.saturating_add(1))
            .read_to_end(&mut encoded)
            .map_err(|_| "failed to read validated image")?;
        if encoded.len() != self.encoded_len
            || u64::try_from(encoded.len()).ok() > Some(MAX_BATCH_ENCODED_BYTES_PER_FILE)
        {
            return Err("image changed size while being admitted");
        }

        let (bmp, decoded_bytes) = inspect_strict_bmp(&encoded)?;
        Ok(AdmittedBatchImage {
            display_name: self.display_name.clone(),
            encoded,
            bmp,
            decoded_bytes,
        })
    }
}

fn open_batch_images(path: &Path) -> std::result::Result<Vec<BatchImageFile>, &'static str> {
    let directory = open_absolute_directory_nofollow(path)?;
    if !directory
        .metadata()
        .map_err(|_| "cannot inspect session directory")?
        .is_dir()
    {
        return Err("session path is not a directory");
    }

    let names = read_directory_names(&directory)?;
    let mut image_names: Vec<OsString> = names
        .into_iter()
        .filter(|name| is_normalized_bmp_name(name))
        .collect();
    image_names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if image_names.len() > MAX_BATCH_FILES {
        return Err("session directory contains too many image files");
    }

    let mut images = Vec::new();
    images
        .try_reserve_exact(image_names.len())
        .map_err(|_| "failed to allocate bounded image list")?;
    let mut total_encoded = 0u64;
    for name in image_names {
        let c_name = CString::new(name.as_bytes()).map_err(|_| "invalid image filename")?;
        // O_NONBLOCK prevents a replaced FIFO/device from blocking before the
        // descriptor's regular-file metadata can be validated.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("session image is unavailable or unsafe");
        }
        // SAFETY: openat returned a new owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect session image")?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_BATCH_ENCODED_BYTES_PER_FILE
        {
            return Err("session image is not a bounded regular file");
        }
        total_encoded = total_encoded
            .checked_add(metadata.len())
            .filter(|total| *total <= MAX_BATCH_TOTAL_ENCODED_BYTES)
            .ok_or("batch encoded byte total exceeds the limit")?;
        let encoded_len = usize::try_from(metadata.len()).map_err(|_| "image is too large")?;
        images.push(BatchImageFile {
            display_name: name.to_string_lossy().into_owned(),
            file,
            encoded_len,
        });
    }
    Ok(images)
}

fn open_absolute_directory_nofollow(path: &Path) -> std::result::Result<File, &'static str> {
    let path = path.as_os_str().as_bytes();
    if path.is_empty() || path.len() > MAX_BATCH_SESSION_PATH_BYTES {
        return Err("session path length exceeds the limit");
    }
    if path.first() != Some(&b'/') {
        return Err("session path must be absolute");
    }
    if path == b"/" {
        return Err("filesystem root is not a session directory");
    }
    let components = path[1..].split(|byte| *byte == b'/');
    let root = CString::new("/").expect("static root path contains no NUL");
    // SAFETY: root is a static NUL-terminated path and the returned descriptor
    // is uniquely owned on success.
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err("cannot open filesystem root for session traversal");
    }
    // SAFETY: open returned a new owned descriptor.
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    for component in components {
        if component.is_empty() {
            return Err("session path must not contain repeated or trailing separators");
        }
        if component == b"." || component == b".." {
            return Err("session path must not contain dot components");
        }
        let component = CString::new(component).map_err(|_| "invalid session path component")?;
        // SAFETY: directory is a live descriptor, component is a single
        // NUL-terminated relative name, and ownership transfers to File.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("session path component is unavailable or unsafe");
        }
        // SAFETY: openat returned a new owned descriptor.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

fn read_directory_names(directory: &File) -> std::result::Result<Vec<OsString>, &'static str> {
    // Duplicate because fdopendir takes ownership of its descriptor.
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err("cannot duplicate session directory descriptor");
    }
    // SAFETY: duplicate is a live directory descriptor transferred to fdopendir.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(duplicate) };
        return Err("cannot enumerate session directory");
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the live DIR pointer.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        // SAFETY: this daemon is Linux-only; clearing thread-local errno lets
        // us distinguish end-of-directory from a readdir failure.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: stream remains live and readdir's pointer is consumed before
        // the next call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            // SAFETY: Linux thread-local errno is valid for the current thread.
            if unsafe { *libc::__errno_location() } != 0 {
                return Err("failed while enumerating session directory");
            }
            break;
        }
        // SAFETY: d_name is NUL-terminated for the lifetime of this entry.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= MAX_BATCH_DIRECTORY_ENTRIES {
            return Err("session directory contains too many entries");
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    Ok(names)
}

fn is_normalized_bmp_name(name: &OsStr) -> bool {
    Path::new(name)
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("bmp"))
}

fn decode_image_as_bgr(
    image: &AdmittedBatchImage,
) -> anyhow::Result<(Zeroizing<Vec<u8>>, u32, u32)> {
    decode_bmp_as_bgr(image, image.bmp)
}

fn decode_bmp_as_bgr(
    image: &AdmittedBatchImage,
    bmp: BmpMetadata,
) -> anyhow::Result<(Zeroizing<Vec<u8>>, u32, u32)> {
    let decoded_len = usize::try_from(image.decoded_bytes)
        .context("decoded image byte length does not fit this platform")?;
    let mut bgr = zeroizing_buffer(image.decoded_bytes)?;
    debug_assert_eq!(bgr.len(), decoded_len);
    let active_row_bytes = usize::try_from(bmp.width)
        .ok()
        .and_then(|width| width.checked_mul(3))
        .context("BMP active row size overflowed")?;
    let height = usize::try_from(bmp.height).context("BMP height does not fit usize")?;
    for output_row in 0..height {
        let source_row = height - 1 - output_row;
        let source_start = bmp
            .pixel_offset
            .checked_add(
                source_row
                    .checked_mul(bmp.row_stride)
                    .context("BMP source row offset overflowed")?,
            )
            .context("BMP source offset overflowed")?;
        let source_end = source_start
            .checked_add(active_row_bytes)
            .context("BMP source row end overflowed")?;
        let destination_start = output_row
            .checked_mul(active_row_bytes)
            .context("BMP destination row offset overflowed")?;
        let destination_end = destination_start
            .checked_add(active_row_bytes)
            .context("BMP destination row end overflowed")?;
        bgr[destination_start..destination_end]
            .copy_from_slice(&image.encoded[source_start..source_end]);
    }
    Ok((bgr, bmp.width, bmp.height))
}

fn zeroizing_buffer(bytes: u64) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let len = usize::try_from(bytes).context("decoded image byte length does not fit usize")?;
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(len)
        .context("failed to allocate bounded decoded image")?;
    buffer.resize(len, 0);
    Ok(buffer)
}

fn inspect_strict_bmp(bytes: &[u8]) -> std::result::Result<(BmpMetadata, u64), &'static str> {
    if bytes.len() < 54 || bytes.get(..2) != Some(b"BM") {
        return Err("invalid BMP header");
    }
    let file_size = usize::try_from(read_u32_le(bytes, 2)?).map_err(|_| "BMP size overflowed")?;
    if file_size != bytes.len() || bytes.get(6..10) != Some(&[0, 0, 0, 0]) {
        return Err("BMP file size or reserved fields are invalid");
    }
    let pixel_offset =
        usize::try_from(read_u32_le(bytes, 10)?).map_err(|_| "BMP pixel offset overflowed")?;
    if read_u32_le(bytes, 14)? != 40 || pixel_offset != 54 {
        return Err("only BITMAPINFOHEADER BMP files are supported");
    }
    let width_signed = read_i32_le(bytes, 18)?;
    let height_signed = read_i32_le(bytes, 22)?;
    if width_signed <= 0 || height_signed <= 0 {
        return Err("BMP dimensions are invalid");
    }
    let width = u32::try_from(width_signed).map_err(|_| "BMP width is invalid")?;
    let height = u32::try_from(height_signed).map_err(|_| "BMP height is invalid")?;
    if width > MAX_BATCH_IMAGE_WIDTH || height > MAX_BATCH_IMAGE_HEIGHT {
        return Err("image dimensions exceed the limit");
    }
    if read_u16_le(bytes, 26)? != 1 || read_u16_le(bytes, 28)? != 24 || read_u32_le(bytes, 30)? != 0
    {
        return Err("only uncompressed 24-bit BMP files are supported");
    }
    if bytes.get(38..54) != Some(&[0; 16]) {
        return Err("BMP canonical header fields are invalid");
    }
    let decoded_bytes = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or("decoded image size overflowed")?;
    if decoded_bytes == 0 || decoded_bytes > MAX_BATCH_DECODED_BYTES_PER_FILE as u64 {
        return Err("decoded image bytes exceed the limit");
    }
    let active_row_bytes = usize::try_from(width)
        .ok()
        .and_then(|width| width.checked_mul(3))
        .ok_or("BMP row size overflowed")?;
    let row_stride = active_row_bytes
        .checked_add(3)
        .map(|bytes| bytes & !3)
        .ok_or("BMP row stride overflowed")?;
    let pixel_bytes = row_stride
        .checked_mul(usize::try_from(height).map_err(|_| "BMP height overflowed")?)
        .ok_or("BMP pixel data size overflowed")?;
    let end = pixel_offset
        .checked_add(pixel_bytes)
        .ok_or("BMP pixel data end overflowed")?;
    if end != bytes.len() {
        return Err("BMP pixel data length is invalid");
    }
    for row in 0..usize::try_from(height).map_err(|_| "BMP height overflowed")? {
        let padding_start = pixel_offset
            .checked_add(
                row.checked_mul(row_stride)
                    .and_then(|offset| offset.checked_add(active_row_bytes))
                    .ok_or("BMP padding offset overflowed")?,
            )
            .ok_or("BMP padding offset overflowed")?;
        let padding_end = pixel_offset
            .checked_add(
                row.checked_add(1)
                    .and_then(|row| row.checked_mul(row_stride))
                    .ok_or("BMP padding end overflowed")?,
            )
            .ok_or("BMP padding end overflowed")?;
        if bytes
            .get(padding_start..padding_end)
            .ok_or("BMP padding is truncated")?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err("BMP row padding is not canonical");
        }
    }
    let declared_image_bytes = read_u32_le(bytes, 34)?;
    if declared_image_bytes == 0 || usize::try_from(declared_image_bytes).ok() != Some(pixel_bytes)
    {
        return Err("BMP declared image size is invalid");
    }
    Ok((
        BmpMetadata {
            width,
            height,
            pixel_offset,
            row_stride,
        },
        decoded_bytes,
    ))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> std::result::Result<u16, &'static str> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .ok_or("truncated BMP header")?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> std::result::Result<u32, &'static str> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or("truncated BMP header")?;
    Ok(u32::from_le_bytes(value))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> std::result::Result<i32, &'static str> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or("truncated BMP header")?;
    Ok(i32::from_le_bytes(value))
}

/// Try to get a listener from systemd socket activation.
/// Returns None if not running under socket activation.
fn try_systemd_socket() -> Option<UnixListener> {
    let listen_pid = std::env::var("LISTEN_PID").ok()?.parse::<u32>().ok()?;
    if listen_pid != std::process::id() {
        return None;
    }

    // systemd passes LISTEN_FDS=1 and the fd is 3
    let listen_fds = std::env::var("LISTEN_FDS").ok()?.parse::<i32>().ok()?;

    if listen_fds < 1 {
        return None;
    }

    for descriptor in 3..3_i32.checked_add(listen_fds)? {
        if set_fd_cloexec(descriptor).is_err() {
            return None;
        }
    }
    if listen_fds != 1 {
        return None;
    }

    // fd 3 is the first passed socket
    use std::os::unix::io::FromRawFd;
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    Some(listener)
}

fn set_fd_cloexec(fd: i32) -> io::Result<()> {
    // SAFETY: fcntl operates on the supplied live descriptor and has no
    // pointer arguments for F_GETFD/F_SETFD.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set socket permissions for owner/group access.
fn set_socket_permissions(path: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

fn get_peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret == 0 { Some(cred.uid) } else { None }
}

#[cfg(test)]
mod tests {
    use super::{
        CameraAdmissionHeld, CameraCleanup, CameraHooks, CameraProfileCache, CameraReaper,
        CleanupMode, CleanupReport, CleanupTask, ConnectionAccounting, ConnectionIo,
        DaemonRuntimeIdentity, LazyCameraHandle, MAX_CONNECTION_WORKERS, PanicResponseWriter,
        PendingPromptRecord, PromptAuthentication, PromptConnectionAction, PromptConnectionMachine,
        PromptConnectionPhase, PromptCoordinatorReport, PromptWorkerTerminal, ResponseCleanupOrder,
        SensitivePromptRequest, SensitivePromptResponse, ServerInference, ServerRunHooks,
        ShutdownSignal, active_storage_ready, auth_outcome, authorize_prompt_begin,
        batch_enrollment_plaintext_bytes, claim_prompt_commit, claim_prompt_commit_with_resolver,
        configure_initial_io_deadlines, coordinate_prompt_connection,
        coordinate_prompt_connection_with_shutdown, coordinate_response_cleanup, current_operation,
        decode_image_as_bgr, detected_response, dispatch_authenticate_v1_with,
        dispatch_authorized_enrollment, dispatch_with_panic_boundary, enqueue_cleanup_task,
        finish_live_enrollment_camera_failure, finish_or_track_unleased_worker,
        finish_prompt_commit_unavailable, finish_prompt_commit_with, handle_batch_enrollment_with,
        handle_clear_enrollments, handle_enroll, handle_enrollment_presence,
        handle_live_enrollment_with, handle_remove_enrollment, handle_root_shutdown,
        handle_security_info, initial_prompt_protocol_response,
        initialize_camera_profile_for_presence, live_enrollment_plaintext_bytes, lock_unpoisoned,
        open_absolute_directory_nofollow, open_batch_images,
        open_started_camera_from_profile_cache, prepare_prompt_pending,
        profile_invalidation_for_failure, prompt_active_capacity, prompt_active_timeout,
        prompt_request_fields_are_zero, prompt_response_fields_are_zero,
        reap_finished_connection_workers, release_camera_admission, resolve_camera_profile,
        resolve_camera_profile_already_admitted, resolve_live_enrollment_profile,
        run_with_camera_and_server_hooks, run_with_camera_hooks, set_fd_cloexec,
        shutdown_connection_workers_with_timeout, spawn_prompt_authentication,
        spawn_prompt_authentication_after_revalidation, start_initial_camera_profile_probe,
        storage_error_response, successful_response_cleanup_order, validate_current_prompt_policy,
        validate_prompt_begin_policy, with_connection_permit, zeroize_prompt_request,
        zeroize_prompt_response,
    };
    use crate::authorization::{
        CanonicalIdentity, IdentityLookupError, IdentityResolver, Operation, SystemIdentityResolver,
    };
    use crate::camera::{
        CameraCapture, CameraCaptureError, CameraFactory, CameraFailureKind, CameraLifecycleEvent,
        CameraProfile, CameraProfileProvider, CameraProfileRequest, CameraStopOutcome, Frame,
        FrameFormat, PendingCameraCleanup, WorkerExit,
    };
    use crate::mode1_key::Mode1KeyContext;
    use crate::prompt_state::{ActiveResourceCancellation, PromptTransactionManager};
    use crate::storage::{
        Mode1BackendOptions, Mode1StorageBackend, Mode1StorageLimits, ModelCacheLimits,
        PlaintextBackendOptions, PlaintextStorageBackend, PlaintextStorageLimits,
    };
    use howy_common::config::{EmbeddingSecurityMode, PresenceMode};
    use howy_common::protocol::{
        self, Cmd, DetectReq, ENROLLMENT_PROTOCOL_ERROR, EnrollBatchReq, EnrollReq,
        PROMPT_NONCE_BYTES, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, PROMPT_PROTOCOL_VIOLATION_ERROR,
        PROMPT_TOKEN_BYTES, PROMPT_TRANSACTION_INVALID_ERROR, PROMPT_UNAVAILABLE_ERROR,
        PromptOriginV1, Request, RespResult, Response, STORAGE_CORRUPT_ERROR,
        STORAGE_INVALID_REQUEST_ERROR, STORAGE_MODEL_MISMATCH_ERROR, STORAGE_UNAVAILABLE_ERROR,
    };
    use howy_common::storage::{
        AppendAdmissionShape, AppendRequest, AppendResult, AuthModel, AuthenticationCachePromotion,
        AuthenticationLoad, BackendHealth, BackendUnavailable, BudgetPermit, CancellationSignal,
        CandidatePresence, CanonicalUsername, ClearRequest, ClearResult, EnrollmentAdmission,
        EnrollmentEntry, EnrollmentId, MetadataList, ModelDigest, ModelLease,
        PlaintextAllocationEstimate, PlaintextBudget, PromptOpaqueIdentity, PromptStorageSnapshot,
        ReloadResult, RemoveRequest, RemoveResult, StorageBackend, StorageBackendError,
    };
    use std::collections::VecDeque;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, Weak, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use zeroize::{Zeroize, Zeroizing};

    struct FixedProfileProvider;

    #[test]
    fn listener_and_accepted_descriptor_sealing_sets_cloexec() {
        let (left, right) = UnixStream::pair().unwrap();
        for stream in [&left, &right] {
            assert_eq!(
                unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, 0) },
                0
            );
            set_fd_cloexec(stream.as_raw_fd()).unwrap();
            let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    impl CameraProfileProvider for FixedProfileProvider {
        fn probe(&self, _request: &CameraProfileRequest) -> anyhow::Result<CameraProfile> {
            Ok(CameraProfile::test_profile("fixed"))
        }
    }

    fn idle_profile_cache() -> CameraProfileCache {
        CameraProfileCache::new(
            Arc::new(FixedProfileProvider),
            CameraProfileRequest::new(String::new(), 640, 480, 30, -1),
        )
    }

    fn probing_profile_cache() -> CameraProfileCache {
        let cache = idle_profile_cache();
        assert_eq!(
            cache.claim(std::time::Instant::now()),
            super::ProbeClaim::Start(0)
        );
        cache
    }

    #[derive(Clone, Default)]
    struct LifecycleEvents(Arc<Mutex<Vec<CameraLifecycleEvent>>>);

    impl LifecycleEvents {
        fn push(&self, event: CameraLifecycleEvent) {
            self.0.lock().unwrap().push(event);
        }

        fn snapshot(&self) -> Vec<CameraLifecycleEvent> {
            self.0.lock().unwrap().clone()
        }

        fn assert_empty(&self) {
            assert!(self.snapshot().is_empty());
        }
    }

    struct ScriptedProfileProvider {
        events: LifecycleEvents,
        outcomes: Mutex<VecDeque<std::result::Result<(), &'static str>>>,
        calls: AtomicUsize,
        block: Option<Arc<(Mutex<bool>, Condvar)>>,
        entered: Option<mpsc::Sender<()>>,
    }

    impl ScriptedProfileProvider {
        fn succeeding(events: LifecycleEvents) -> Self {
            Self {
                events,
                outcomes: Mutex::new(VecDeque::from([Ok(())])),
                calls: AtomicUsize::new(0),
                block: None,
                entered: None,
            }
        }

        fn scripted(
            events: LifecycleEvents,
            outcomes: impl IntoIterator<Item = std::result::Result<(), &'static str>>,
        ) -> Self {
            Self {
                events,
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                calls: AtomicUsize::new(0),
                block: None,
                entered: None,
            }
        }

        fn blocking(
            events: LifecycleEvents,
            block: Arc<(Mutex<bool>, Condvar)>,
            entered: mpsc::Sender<()>,
        ) -> Self {
            Self {
                events,
                outcomes: Mutex::new(VecDeque::from([Ok(())])),
                calls: AtomicUsize::new(0),
                block: Some(block),
                entered: Some(entered),
            }
        }
    }

    impl CameraProfileProvider for ScriptedProfileProvider {
        fn probe(&self, _request: &CameraProfileRequest) -> anyhow::Result<CameraProfile> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.events.push(CameraLifecycleEvent::ProfileProbe);
            if let Some(entered) = &self.entered {
                let _ = entered.send(());
            }
            if let Some(block) = &self.block {
                let mut released = block.0.lock().unwrap();
                while !*released {
                    released = block.1.wait(released).unwrap();
                }
            }
            match self.outcomes.lock().unwrap().pop_front().unwrap_or(Ok(())) {
                Ok(()) => Ok(CameraProfile::test_profile("injected")),
                Err(message) => Err(anyhow::anyhow!(message)),
            }
        }
    }

    struct PanicThenSuccessProvider {
        events: LifecycleEvents,
        calls: AtomicUsize,
    }

    impl CameraProfileProvider for PanicThenSuccessProvider {
        fn probe(&self, _request: &CameraProfileRequest) -> anyhow::Result<CameraProfile> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.events.push(CameraLifecycleEvent::ProfileProbe);
            if call == 0 {
                panic!("injected first profile probe panic");
            }
            Ok(CameraProfile::test_profile("panic-recovered"))
        }
    }

    struct RecordingCameraFactory {
        events: LifecycleEvents,
    }

    impl CameraFactory for RecordingCameraFactory {
        fn create(&self, _profile: &CameraProfile) -> Box<dyn CameraCapture> {
            Box::new(RecordingCamera {
                events: self.events.clone(),
                started: false,
            })
        }
    }

    struct RecordingCamera {
        events: LifecycleEvents,
        started: bool,
    }

    struct StaleReadPendingCamera {
        pending: Option<PendingCameraCleanup>,
    }

    struct StaleReadSynchronousCamera;

    impl CameraCapture for StaleReadSynchronousCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            Err(CameraCaptureError::stale_profile(anyhow::anyhow!(
                "injected synchronous stale profile"
            )))
        }

        fn stop(&mut self) -> CameraStopOutcome {
            CameraStopOutcome::Released
        }

        fn retain_pending_cleanup(&mut self, _pending: PendingCameraCleanup) {
            panic!("synchronous camera cannot retain pending cleanup");
        }
    }

    impl CameraCapture for StaleReadPendingCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            Err(CameraCaptureError::stale_profile(anyhow::anyhow!(
                "injected exact-profile mismatch"
            )))
        }

        fn stop(&mut self) -> CameraStopOutcome {
            CameraStopOutcome::Pending(
                self.pending
                    .take()
                    .expect("stale camera cleanup is returned exactly once"),
            )
        }

        fn retain_pending_cleanup(&mut self, pending: PendingCameraCleanup) {
            self.pending = Some(pending);
        }
    }

    struct SequenceProfileProvider {
        profiles: Mutex<VecDeque<CameraProfile>>,
        calls: AtomicUsize,
    }

    impl CameraProfileProvider for SequenceProfileProvider {
        fn probe(&self, _request: &CameraProfileRequest) -> anyhow::Result<CameraProfile> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.profiles
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no injected profile remains"))
        }
    }

    impl CameraCapture for RecordingCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            self.events.push(CameraLifecycleEvent::DeviceOpen);
            self.events.push(CameraLifecycleEvent::ConfigureProfile);
            self.events.push(CameraLifecycleEvent::StreamStart);
            self.started = true;
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            self.start()
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            assert!(self.started);
            self.events.push(CameraLifecycleEvent::FrameRead);
            Ok(Frame {
                data: vec![64],
                width: 1,
                height: 1,
                format: FrameFormat::Gray,
            })
        }

        fn stop(&mut self) -> CameraStopOutcome {
            if self.started {
                self.events.push(CameraLifecycleEvent::StopCleanup);
                self.started = false;
            }
            CameraStopOutcome::Released
        }

        fn retain_pending_cleanup(&mut self, _pending: PendingCameraCleanup) {
            panic!("recording camera never returns pending cleanup");
        }
    }

    struct BoundaryGate {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        released: Mutex<bool>,
        changed: Condvar,
    }

    impl BoundaryGate {
        fn new(entered: mpsc::Sender<()>) -> Self {
            Self {
                entered: Mutex::new(Some(entered)),
                released: Mutex::new(false),
                changed: Condvar::new(),
            }
        }

        fn wait(&self) {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.changed.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    struct CancellableBoundaryGate {
        entered: Mutex<Option<mpsc::Sender<()>>>,
        released: Mutex<bool>,
        changed: Condvar,
    }

    impl CancellableBoundaryGate {
        fn new(entered: mpsc::Sender<()>) -> Self {
            Self {
                entered: Mutex::new(Some(entered)),
                released: Mutex::new(false),
                changed: Condvar::new(),
            }
        }

        fn wait(&self, cancellation: &dyn CancellationSignal) -> bool {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let mut released = self.released.lock().unwrap();
            while !*released {
                if cancellation.is_cancelled() {
                    return false;
                }
                let waited = self
                    .changed
                    .wait_timeout(released, Duration::from_millis(5))
                    .unwrap();
                released = waited.0;
            }
            true
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    struct BlockingProfileProvider(Arc<BoundaryGate>);

    impl CameraProfileProvider for BlockingProfileProvider {
        fn probe(&self, _request: &CameraProfileRequest) -> anyhow::Result<CameraProfile> {
            self.0.wait();
            Ok(CameraProfile::test_profile("released-profile"))
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BlockingCameraPhase {
        Start,
        Frame,
        Cleanup,
    }

    struct BoundaryCamera {
        phase: BlockingCameraPhase,
        gate: Arc<BoundaryGate>,
        control: Arc<BlockingCameraControl>,
        cleanup_returned: bool,
    }

    impl CameraCapture for BoundaryCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            if self.phase == BlockingCameraPhase::Start {
                self.gate.wait();
            }
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            self.start()
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            if self.phase == BlockingCameraPhase::Frame {
                self.gate.wait();
            }
            Ok(Frame {
                data: vec![64],
                width: 1,
                height: 1,
                format: FrameFormat::Gray,
            })
        }

        fn stop(&mut self) -> CameraStopOutcome {
            if self.phase == BlockingCameraPhase::Cleanup && !self.cleanup_returned {
                self.cleanup_returned = true;
                let gate = Arc::clone(&self.gate);
                CameraStopOutcome::Pending(PendingCameraCleanup::from_thread_handle(thread::spawn(
                    move || gate.wait(),
                )))
            } else {
                CameraStopOutcome::Released
            }
        }

        fn retain_pending_cleanup(&mut self, _pending: PendingCameraCleanup) {
            panic!("boundary camera cleanup remains owned by the prompt worker");
        }

        fn active_resource_cancellation(&self) -> Option<Arc<dyn ActiveResourceCancellation>> {
            Some(self.control.clone())
        }
    }

    struct BoundaryCameraFactory {
        phase: BlockingCameraPhase,
        gate: Arc<BoundaryGate>,
        control: Arc<BlockingCameraControl>,
    }

    impl CameraFactory for BoundaryCameraFactory {
        fn create(&self, _profile: &CameraProfile) -> Box<dyn CameraCapture> {
            Box::new(BoundaryCamera {
                phase: self.phase,
                gate: Arc::clone(&self.gate),
                control: Arc::clone(&self.control),
                cleanup_returned: false,
            })
        }
    }

    struct TimedFrameCamera {
        gate: Arc<BoundaryGate>,
        completed: Option<mpsc::Sender<bool>>,
    }

    impl CameraCapture for TimedFrameCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            self.start()
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            self.gate.wait();
            Ok(Frame {
                data: vec![64],
                width: 1,
                height: 1,
                format: FrameFormat::Gray,
            })
        }

        fn capture_frame_cancellable(
            &mut self,
            cancellation: &dyn CancellationSignal,
        ) -> std::result::Result<Frame, CameraCaptureError> {
            if cancellation.is_cancelled() {
                return Err(CameraCaptureError::cancelled(anyhow::anyhow!(
                    "timed frame cancelled before capture"
                )));
            }
            let frame = self.capture_frame();
            let timely = frame.is_ok() && !cancellation.is_cancelled();
            if let Some(completed) = self.completed.take() {
                let _ = completed.send(timely);
            }
            if timely {
                frame
            } else {
                Err(CameraCaptureError::cancelled(anyhow::anyhow!(
                    "timed frame cancelled at capture boundary"
                )))
            }
        }

        fn stop(&mut self) -> CameraStopOutcome {
            CameraStopOutcome::Released
        }

        fn retain_pending_cleanup(&mut self, _pending: PendingCameraCleanup) {
            panic!("timed camera has no pending cleanup");
        }
    }

    struct TimedFrameCameraFactory {
        gate: Arc<BoundaryGate>,
        completed: Mutex<Option<mpsc::Sender<bool>>>,
    }

    impl CameraFactory for TimedFrameCameraFactory {
        fn create(&self, _profile: &CameraProfile) -> Box<dyn CameraCapture> {
            Box::new(TimedFrameCamera {
                gate: Arc::clone(&self.gate),
                completed: self.completed.lock().unwrap().take(),
            })
        }
    }

    struct BlockingCameraControl {
        cancelled: AtomicBool,
        release_on_cancel: bool,
        state: Mutex<bool>,
        changed: Condvar,
    }

    impl BlockingCameraControl {
        fn new(release_on_cancel: bool) -> Self {
            Self {
                cancelled: AtomicBool::new(false),
                release_on_cancel,
                state: Mutex::new(false),
                changed: Condvar::new(),
            }
        }

        fn release(&self) {
            *self.state.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }

    impl ActiveResourceCancellation for BlockingCameraControl {
        fn cancel_resource(&self) {
            self.cancelled.store(true, Ordering::Release);
            if self.release_on_cancel {
                self.release();
            }
        }
    }

    struct BlockingActiveCamera {
        control: Arc<BlockingCameraControl>,
        entered: Option<mpsc::Sender<()>>,
    }

    impl CameraCapture for BlockingActiveCamera {
        fn start(&mut self) -> std::result::Result<(), CameraCaptureError> {
            Ok(())
        }

        fn start_enrollment(&mut self) -> std::result::Result<(), CameraCaptureError> {
            self.start()
        }

        fn capture_frame(&mut self) -> std::result::Result<Frame, CameraCaptureError> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            let mut released = self.control.state.lock().unwrap();
            while !*released {
                released = self.control.changed.wait(released).unwrap();
            }
            Err(CameraCaptureError::cancelled(anyhow::anyhow!(
                "injected blocking camera released"
            )))
        }

        fn stop(&mut self) -> CameraStopOutcome {
            CameraStopOutcome::Released
        }

        fn retain_pending_cleanup(&mut self, _pending: PendingCameraCleanup) {
            panic!("blocking test camera never returns pending cleanup");
        }

        fn active_resource_cancellation(&self) -> Option<Arc<dyn ActiveResourceCancellation>> {
            Some(self.control.clone())
        }
    }

    struct BlockingActiveCameraFactory {
        control: Arc<BlockingCameraControl>,
        entered: Mutex<Option<mpsc::Sender<()>>>,
    }

    struct CountingPromotion(Arc<AtomicUsize>);

    impl AuthenticationCachePromotion for CountingPromotion {
        fn promote_if(
            self: Box<Self>,
            publish: &mut dyn FnMut() -> bool,
        ) -> Result<bool, StorageBackendError> {
            if !publish() {
                return Ok(false);
            }
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    struct BarrierPromotion {
        inner: Box<dyn AuthenticationCachePromotion>,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }

    impl AuthenticationCachePromotion for BarrierPromotion {
        fn promote_if(
            self: Box<Self>,
            publish: &mut dyn FnMut() -> bool,
        ) -> Result<bool, StorageBackendError> {
            let Self {
                inner,
                entered,
                release,
            } = *self;
            entered
                .send(())
                .map_err(|_| StorageBackendError::Unavailable)?;
            release
                .recv()
                .map_err(|_| StorageBackendError::Unavailable)?;
            inner.promote_if(publish)
        }
    }

    impl CameraFactory for BlockingActiveCameraFactory {
        fn create(&self, _profile: &CameraProfile) -> Box<dyn CameraCapture> {
            Box::new(BlockingActiveCamera {
                control: Arc::clone(&self.control),
                entered: self.entered.lock().unwrap().take(),
            })
        }
    }

    fn injected_profile_cache(provider: Arc<dyn CameraProfileProvider>) -> Arc<CameraProfileCache> {
        Arc::new(CameraProfileCache::new(
            provider,
            CameraProfileRequest::new(String::new(), 640, 480, 30, -1),
        ))
    }

    struct RunnerInference;

    impl RunnerInference {
        fn embedding() -> Vec<f32> {
            let value = 1.0 / (howy_common::face::FACE_EMBEDDING_DIM as f32).sqrt();
            vec![value; howy_common::face::FACE_EMBEDDING_DIM]
        }

        fn face(with_embedding: bool) -> howy_common::face::Face {
            howy_common::face::Face {
                bbox: [0, 0, 1, 1],
                landmarks: [0.0; 10],
                score: 0.99,
                embedding: with_embedding.then(Self::embedding),
            }
        }
    }

    impl ServerInference for RunnerInference {
        fn registered_preferred_provider(&self) -> &str {
            "test"
        }

        fn detector_model_path(&self) -> String {
            "/test/test-detector".to_string()
        }

        fn recognizer_model_path(&self) -> String {
            "/test/test-recognizer".to_string()
        }

        fn plaintext_scratch_bytes(&self) -> anyhow::Result<usize> {
            Ok(1024)
        }

        fn detect(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<howy_common::face::Face>> {
            Ok(vec![Self::face(false)])
        }

        fn encode(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _detected_face: &howy_common::face::Face,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<f32>> {
            Ok(Self::embedding())
        }

        fn analyze(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<howy_common::face::Face>> {
            Ok(vec![Self::face(true)])
        }
    }

    struct BlockingInference(Option<Arc<BoundaryGate>>);

    impl ServerInference for BlockingInference {
        fn registered_preferred_provider(&self) -> &str {
            "test"
        }

        fn detector_model_path(&self) -> String {
            "/test/test-detector".to_string()
        }

        fn recognizer_model_path(&self) -> String {
            "/test/test-recognizer".to_string()
        }

        fn plaintext_scratch_bytes(&self) -> anyhow::Result<usize> {
            Ok(1024)
        }

        fn detect(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<howy_common::face::Face>> {
            Ok(vec![RunnerInference::face(false)])
        }

        fn encode(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _detected_face: &howy_common::face::Face,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<f32>> {
            Ok(RunnerInference::embedding())
        }

        fn analyze(
            &self,
            _data: &[u8],
            _width: u32,
            _height: u32,
            _is_gray: bool,
        ) -> anyhow::Result<Vec<howy_common::face::Face>> {
            if let Some(gate) = &self.0 {
                gate.wait();
            }
            Ok(vec![RunnerInference::face(true)])
        }
    }

    struct RunnerStorage {
        budget: PlaintextBudget,
        snapshot_gate: Option<Arc<BoundaryGate>>,
        auth_gate: Option<Arc<BoundaryGate>>,
        cancellable_auth_gate: Option<Arc<CancellableBoundaryGate>>,
        snapshot_calls: AtomicUsize,
        auth_calls: AtomicUsize,
        promotion_calls: Arc<AtomicUsize>,
    }

    impl RunnerStorage {
        fn new() -> Self {
            Self {
                budget: PlaintextBudget::new(256 * 1024 * 1024).unwrap(),
                snapshot_gate: None,
                auth_gate: None,
                cancellable_auth_gate: None,
                snapshot_calls: AtomicUsize::new(0),
                auth_calls: AtomicUsize::new(0),
                promotion_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn blocking(gate: Arc<BoundaryGate>) -> Self {
            Self {
                budget: PlaintextBudget::new(256 * 1024 * 1024).unwrap(),
                snapshot_gate: None,
                auth_gate: Some(gate),
                cancellable_auth_gate: None,
                snapshot_calls: AtomicUsize::new(0),
                auth_calls: AtomicUsize::new(0),
                promotion_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn blocking_snapshot(gate: Arc<BoundaryGate>) -> Self {
            Self {
                budget: PlaintextBudget::new(256 * 1024 * 1024).unwrap(),
                snapshot_gate: Some(gate),
                auth_gate: None,
                cancellable_auth_gate: None,
                snapshot_calls: AtomicUsize::new(0),
                auth_calls: AtomicUsize::new(0),
                promotion_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn cancellable(gate: Arc<CancellableBoundaryGate>) -> Self {
            Self {
                budget: PlaintextBudget::new(256 * 1024 * 1024).unwrap(),
                snapshot_gate: None,
                auth_gate: None,
                cancellable_auth_gate: Some(gate),
                snapshot_calls: AtomicUsize::new(0),
                auth_calls: AtomicUsize::new(0),
                promotion_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl StorageBackend for RunnerStorage {
        fn prompt_snapshot(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<PromptStorageSnapshot, StorageBackendError> {
            let prior = self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            if prior != 0
                && let Some(gate) = &self.snapshot_gate
            {
                gate.wait();
            }
            Ok(PromptStorageSnapshot::new(
                BackendHealth::Ready,
                CandidatePresence::Candidate { generation: 1 },
                PromptOpaqueIdentity::new([0x31; 32]),
                PromptOpaqueIdentity::new([0x32; 32]),
            ))
        }

        fn candidate_presence(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<CandidatePresence, StorageBackendError> {
            Ok(CandidatePresence::Candidate { generation: 1 })
        }

        fn authenticate(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<ModelLease, StorageBackendError> {
            self.auth_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.auth_gate {
                gate.wait();
            }
            let model = AuthModel::new(
                1,
                ModelDigest::new([0x42; 32]),
                howy_common::face::FACE_EMBEDDING_DIM,
                vec![EnrollmentId::new([1; 16]).unwrap()],
                vec!["runner".to_string()],
                RunnerInference::embedding(),
            )?;
            let permit = self.budget.reserve(model.plaintext_bytes())?;
            ModelLease::ephemeral(model, permit)
        }

        fn authenticate_active(
            &self,
            username: &CanonicalUsername,
            cancellation: &dyn CancellationSignal,
        ) -> Result<AuthenticationLoad, StorageBackendError> {
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            if self
                .cancellable_auth_gate
                .as_ref()
                .is_some_and(|gate| !gate.wait(cancellation))
            {
                return Err(StorageBackendError::Unavailable);
            }
            let lease = self.authenticate(username)?;
            if cancellation.is_cancelled() {
                return Err(StorageBackendError::Unavailable);
            }
            Ok(AuthenticationLoad::provisional(
                lease,
                Box::new(CountingPromotion(Arc::clone(&self.promotion_calls))),
            ))
        }

        fn list_metadata(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            Err(StorageBackendError::Absent)
        }

        fn append(&self, _request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn admit_enrollment(
            &self,
            _username: &CanonicalUsername,
            plaintext_bytes: usize,
            _append_shape: AppendAdmissionShape,
        ) -> Result<EnrollmentAdmission, StorageBackendError> {
            self.budget.reserve_enrollment(1024, plaintext_bytes)
        }

        fn append_admitted(
            &self,
            _request: AppendRequest<'_>,
            _operation: BudgetPermit,
        ) -> Result<AppendResult, StorageBackendError> {
            Ok(AppendResult::new(1, 1, 1))
        }

        fn remove(&self, _request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn clear(&self, _request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn health(&self) -> BackendHealth {
            BackendHealth::Ready
        }

        fn verify_record(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }
    }

    fn temp_directory(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "howy-server-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    static SOCKET_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct SocketEnvGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl SocketEnvGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os("HOWY_SOCKET");
            // SAFETY: runner tests serialize this process-global override with
            // SOCKET_ENV_LOCK and restore it before releasing that lock.
            unsafe { std::env::set_var("HOWY_SOCKET", path) };
            Self { previous }
        }
    }

    impl Drop for SocketEnvGuard {
        fn drop(&mut self) {
            // SAFETY: the matching test still owns SOCKET_ENV_LOCK.
            unsafe {
                match self.previous.take() {
                    Some(previous) => std::env::set_var("HOWY_SOCKET", previous),
                    None => std::env::remove_var("HOWY_SOCKET"),
                }
            }
        }
    }

    fn current_peer_username() -> String {
        let username = std::env::var("USER").expect("runner test requires USER");
        let identity = SystemIdentityResolver
            .resolve(&username)
            .unwrap()
            .expect("USER must resolve through NSS");
        assert_eq!(identity.uid(), unsafe { libc::geteuid() });
        username
    }

    fn connect_and_send(socket: &std::path::Path, request: &Request) -> Response {
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        howy_common::ipc::send_message(&mut stream, request).unwrap();
        howy_common::ipc::recv_message(&mut stream).unwrap()
    }

    async fn wait_for_socket(socket: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "runner socket was not created");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[test]
    fn queued_second_connection_is_silent_at_accept_and_worker_fatal_gates() {
        #[derive(Clone, Copy, Debug)]
        enum Gate {
            AfterAccept,
            BeforeHandle,
        }

        #[derive(Clone, Copy, Debug)]
        enum RequestKind {
            Ping,
            Status,
            Auth,
        }

        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("fatal-queued-connection");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let username = current_peer_username();
            for gate_kind in [Gate::AfterAccept, Gate::BeforeHandle] {
                for request_kind in [RequestKind::Ping, RequestKind::Status, RequestKind::Auth] {
                    let socket = directory.join(format!("{gate_kind:?}-{request_kind:?}.sock"));
                    let _socket_environment = SocketEnvGuard::set(&socket);
                    let (entered_tx, entered_rx) = mpsc::channel();
                    let gate = Arc::new(BoundaryGate::new(entered_tx));
                    let calls = Arc::new(AtomicUsize::new(0));
                    let blocking_hook: Arc<dyn Fn() + Send + Sync> = {
                        let gate = Arc::clone(&gate);
                        let calls = Arc::clone(&calls);
                        Arc::new(move || {
                            if calls.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                                gate.wait();
                            }
                        })
                    };
                    let server_hooks = match gate_kind {
                        Gate::AfterAccept => ServerRunHooks {
                            after_accept: Some(blocking_hook),
                            before_handle: None,
                            camera_admission: None,
                            runtime_identity: None,
                        },
                        Gate::BeforeHandle => ServerRunHooks {
                            after_accept: None,
                            before_handle: Some(blocking_hook),
                            camera_admission: None,
                            runtime_identity: None,
                        },
                    };
                    let storage = Arc::new(RunnerStorage::new());
                    let events = LifecycleEvents::default();
                    let mut config = howy_common::config::HowyConfig::default();
                    config.presence.mode = PresenceMode::Confirm;
                    let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                        &config,
                        prompt_active_timeout(&config),
                        prompt_active_capacity(),
                    ));
                    let shutdown = ShutdownSignal::new();
                    let server = tokio::spawn(run_with_camera_and_server_hooks(
                        Arc::new(RunnerInference),
                        storage.clone(),
                        Arc::clone(&manager),
                        config,
                        false,
                        false,
                        None,
                        shutdown.clone(),
                        CameraHooks {
                            profile_provider: Arc::new(FixedProfileProvider),
                            factory: Arc::new(RecordingCameraFactory {
                                events: events.clone(),
                            }),
                        },
                        server_hooks,
                    ));
                    wait_for_socket(&socket).await;

                    let initial = connect_and_send(&socket, &Request::ping());
                    assert!(matches!(initial.result, Some(RespResult::Pong(_))));
                    let snapshot_calls = storage.snapshot_calls.load(Ordering::SeqCst);
                    let auth_calls = storage.auth_calls.load(Ordering::SeqCst);

                    let request = match request_kind {
                        RequestKind::Ping => Request::ping(),
                        RequestKind::Status => Request::info(),
                        RequestKind::Auth => Request::begin_auth_v1(
                            &username,
                            [0x11; PROMPT_NONCE_BYTES],
                            "sudo",
                            PromptOriginV1::Local,
                        ),
                    };
                    let mut queued = UnixStream::connect(&socket).unwrap();
                    queued
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    howy_common::ipc::send_message(&mut queued, &request).unwrap();
                    entered_rx
                        .recv_timeout(Duration::from_secs(1))
                        .expect("second connection must reach the injected gate");
                    assert_eq!(
                        manager.next_connection_for_test(),
                        match gate_kind {
                            Gate::AfterAccept => 2,
                            Gate::BeforeHandle => 3,
                        },
                        "{gate_kind:?} must bracket connection-ID allocation"
                    );

                    shutdown.request_fatal_with_worker(thread::spawn(|| {}));
                    gate.release();
                    let response: std::io::Result<Response> =
                        howy_common::ipc::recv_message(&mut queued);
                    assert!(response.is_err(), "{gate_kind:?} {request_kind:?}");
                    let run_error = server.await.unwrap().expect_err("fatal run must return");
                    assert!(run_error.to_string().contains("fail-stop"));
                    assert_eq!(
                        storage.snapshot_calls.load(Ordering::SeqCst),
                        snapshot_calls,
                        "{gate_kind:?} {request_kind:?}"
                    );
                    assert_eq!(
                        storage.auth_calls.load(Ordering::SeqCst),
                        auth_calls,
                        "{gate_kind:?} {request_kind:?}"
                    );
                    assert_eq!(storage.budget.used(), 0);
                    events.assert_empty();
                    assert_eq!(manager.counts(), (0, 0, 0));
                }
            }
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn one_pixel_bmp() -> Vec<u8> {
        let mut bmp = vec![0; 58];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&58u32.to_le_bytes());
        bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
        bmp[18..22].copy_from_slice(&1i32.to_le_bytes());
        bmp[22..26].copy_from_slice(&1i32.to_le_bytes());
        bmp[26..28].copy_from_slice(&1u16.to_le_bytes());
        bmp[28..30].copy_from_slice(&24u16.to_le_bytes());
        bmp[34..38].copy_from_slice(&4u32.to_le_bytes());
        bmp[54..58].copy_from_slice(&[0xff, 0x00, 0x00, 0x00]);
        bmp
    }

    fn prompt_begin() -> howy_common::protocol::BeginAuthV1Req {
        let Some(Cmd::BeginAuthV1(begin)) = Request::begin_auth_v1(
            "alice",
            [0x11; PROMPT_NONCE_BYTES],
            "sudo",
            PromptOriginV1::Local,
        )
        .cmd
        else {
            unreachable!()
        };
        begin
    }

    fn pending_prompt() -> PendingPromptRecord {
        PendingPromptRecord::new(
            "alice",
            Zeroizing::new([0x22; PROMPT_TOKEN_BYTES]),
            Zeroizing::new([0x11; PROMPT_NONCE_BYTES]),
            30_000,
            10_000,
        )
        .unwrap()
    }

    fn root_prompt_begin_request() -> Request {
        Request::begin_auth_v1(
            "root",
            [0x11; PROMPT_NONCE_BYTES],
            "sudo",
            PromptOriginV1::Local,
        )
    }

    fn root_pending_prompt() -> PendingPromptRecord {
        PendingPromptRecord::new(
            "root",
            Zeroizing::new([0x22; PROMPT_TOKEN_BYTES]),
            Zeroizing::new([0x11; PROMPT_NONCE_BYTES]),
            30_000,
            10_000,
        )
        .unwrap()
    }

    #[derive(Default)]
    struct PromptAuthEffects {
        auth_load: AtomicUsize,
        inference: AtomicUsize,
        camera: AtomicUsize,
    }

    impl PromptAuthEffects {
        fn assert_zero(&self) {
            assert_eq!(self.auth_load.load(Ordering::Relaxed), 0);
            assert_eq!(self.inference.load(Ordering::Relaxed), 0);
            assert_eq!(self.camera.load(Ordering::Relaxed), 0);
        }

        fn run(&self) -> Response {
            self.auth_load.fetch_add(1, Ordering::Relaxed);
            self.inference.fetch_add(1, Ordering::Relaxed);
            self.camera.fetch_add(1, Ordering::Relaxed);
            Response::success(0, "test", 0.9, 1.0)
        }
    }

    struct BlockingIdentityResolver {
        gate: Arc<BoundaryGate>,
    }

    impl IdentityResolver for BlockingIdentityResolver {
        fn resolve(
            &self,
            requested_username: &str,
        ) -> std::result::Result<Option<CanonicalIdentity>, IdentityLookupError> {
            self.gate.wait();
            Ok(Some(CanonicalIdentity::new(requested_username, 0)))
        }
    }

    struct PromptCandidateBackend {
        candidate_calls: AtomicUsize,
        auth_loads: AtomicUsize,
        snapshot_entered: Option<Arc<std::sync::Barrier>>,
        snapshot_release: Option<Arc<std::sync::Barrier>>,
        block_on_snapshot_call: usize,
    }

    impl PromptCandidateBackend {
        fn new() -> Self {
            Self {
                candidate_calls: AtomicUsize::new(0),
                auth_loads: AtomicUsize::new(0),
                snapshot_entered: None,
                snapshot_release: None,
                block_on_snapshot_call: usize::MAX,
            }
        }

        fn blocking(entered: Arc<std::sync::Barrier>, release: Arc<std::sync::Barrier>) -> Self {
            Self {
                candidate_calls: AtomicUsize::new(0),
                auth_loads: AtomicUsize::new(0),
                snapshot_entered: Some(entered),
                snapshot_release: Some(release),
                block_on_snapshot_call: 1,
            }
        }

        fn blocking_on_commit(
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
        ) -> Self {
            Self {
                candidate_calls: AtomicUsize::new(0),
                auth_loads: AtomicUsize::new(0),
                snapshot_entered: Some(entered),
                snapshot_release: Some(release),
                block_on_snapshot_call: 2,
            }
        }
    }

    impl StorageBackend for PromptCandidateBackend {
        fn prompt_snapshot(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<PromptStorageSnapshot, StorageBackendError> {
            let call = self.candidate_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if call == self.block_on_snapshot_call {
                if let Some(entered) = &self.snapshot_entered {
                    entered.wait();
                }
                if let Some(release) = &self.snapshot_release {
                    release.wait();
                }
            }
            Ok(PromptStorageSnapshot::new(
                BackendHealth::Ready,
                CandidatePresence::Candidate { generation: 7 },
                PromptOpaqueIdentity::new([0x41; 32]),
                PromptOpaqueIdentity::new([0x42; 32]),
            ))
        }

        fn candidate_presence(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<CandidatePresence, StorageBackendError> {
            self.candidate_calls.fetch_add(1, Ordering::Relaxed);
            Ok(CandidatePresence::Candidate { generation: 7 })
        }

        fn authenticate(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<ModelLease, StorageBackendError> {
            self.auth_loads.fetch_add(1, Ordering::Relaxed);
            Err(StorageBackendError::Unavailable)
        }

        fn list_metadata(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn append(&self, _request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn admit_enrollment(
            &self,
            _username: &CanonicalUsername,
            _plaintext_bytes: usize,
            _append_shape: AppendAdmissionShape,
        ) -> Result<EnrollmentAdmission, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn append_admitted(
            &self,
            _request: AppendRequest<'_>,
            _operation: BudgetPermit,
        ) -> Result<AppendResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn remove(&self, _request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn clear(&self, _request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn health(&self) -> BackendHealth {
            BackendHealth::Ready
        }

        fn verify_record(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }
    }

    fn action_error_code(action: PromptConnectionAction) -> Option<String> {
        let response = match action {
            PromptConnectionAction::SendTerminal(response)
            | PromptConnectionAction::CancelActiveAndSendTerminal(response) => response,
            _ => return None,
        };
        let Some(RespResult::Error(error)) = response.0.result.as_ref() else {
            return None;
        };
        Some(error.code.clone())
    }

    #[test]
    fn production_prompt_coordinator_frames_authorizes_and_starts_only_after_matching_commit() {
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let effects = Arc::new(PromptAuthEffects::default());
        let server_effects = Arc::clone(&effects);
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    authorize_prompt_begin(0, true, begin)?;
                    Ok(root_pending_prompt())
                },
                |_| server_effects.run(),
            )
            .unwrap()
        });

        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        assert!(matches!(
            prompt.result,
            Some(RespResult::PromptRequiredV1(_))
        ));
        effects.assert_zero();

        howy_common::ipc::send_message(
            &mut client,
            &Request::commit_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]),
        )
        .unwrap();
        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        assert!(matches!(response.result, Some(RespResult::Success(_))));
        let report = worker.join().unwrap();
        assert_eq!(
            report,
            PromptCoordinatorReport {
                prompt_response_attempts: 1,
                terminal_response_attempts: 1,
                authentication_started: true,
            }
        );
        assert_eq!(effects.auth_load.load(Ordering::Relaxed), 1);
        assert_eq!(effects.inference.load(Ordering::Relaxed), 1);
        assert_eq!(effects.camera.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn active_supervisor_owns_race_precedence_cancellation_and_one_terminal_attempt() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Success,
            AuthFailed,
            Infrastructure,
            Hup,
            Eof,
            PartialData,
            CancelFrame,
            Shutdown,
            ManagerShutdown,
            Deadline,
            Panic,
        }

        for case in [
            Case::Success,
            Case::AuthFailed,
            Case::Infrastructure,
            Case::Hup,
            Case::Eof,
            Case::PartialData,
            Case::CancelFrame,
            Case::Shutdown,
            Case::ManagerShutdown,
            Case::Deadline,
            Case::Panic,
        ] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                if matches!(case, Case::Deadline) {
                    Duration::from_millis(30)
                } else {
                    prompt_active_timeout(&config)
                },
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let storage = Arc::new(PromptCandidateBackend::new());
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_storage = Arc::clone(&storage);
            let worker_config = config.clone();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (mut client, server) = UnixStream::pair().unwrap();
            let promotions = Arc::new(AtomicUsize::new(0));
            let worker_promotions = Arc::clone(&promotions);

            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_storage.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| -> PromptAuthentication {
                        let lease = match claim_prompt_commit(
                            pending,
                            &worker_config,
                            worker_storage.as_ref(),
                        ) {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                        spawn_prompt_authentication(lease, move |lease| {
                            entered_tx.send(()).unwrap();
                            if matches!(case, Case::Panic) {
                                panic!("injected committed worker panic");
                            }
                            if !matches!(
                                case,
                                Case::Success | Case::AuthFailed | Case::Infrastructure
                            ) {
                                let cancellation = lease.cancellation();
                                while !cancellation.is_cancelled() {
                                    thread::sleep(Duration::from_millis(2));
                                }
                            }
                            PromptWorkerTerminal {
                                response: match case {
                                    Case::AuthFailed => Response::auth_failed(0.1, 2, "no match"),
                                    Case::Infrastructure => Response::error("injected unavailable"),
                                    _ => Response::success(0, "test", 0.9, 1.0),
                                },
                                cleanup_mode: CleanupMode::Synchronous,
                                cache_promotion: Some(Box::new(CountingPromotion(Arc::clone(
                                    &worker_promotions,
                                )))),
                            }
                        })
                    },
                    &worker_shutdown,
                )
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            let commit = Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            );
            howy_common::ipc::send_message(&mut client, &commit).unwrap();
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

            let expected_attempts = match case {
                Case::Success | Case::AuthFailed | Case::Infrastructure | Case::Panic => {
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    match case {
                        Case::Success => {
                            assert!(matches!(response.result, Some(RespResult::Success(_))))
                        }
                        Case::AuthFailed => {
                            assert!(matches!(response.result, Some(RespResult::AuthFailed(_))))
                        }
                        Case::Infrastructure | Case::Panic => {
                            assert!(matches!(response.result, Some(RespResult::Error(_))))
                        }
                        _ => unreachable!(),
                    }
                    1
                }
                Case::Hup => {
                    client.shutdown(std::net::Shutdown::Both).unwrap();
                    drop(client);
                    0
                }
                Case::Eof => {
                    client.shutdown(std::net::Shutdown::Write).unwrap();
                    let eof: std::io::Result<Response> =
                        howy_common::ipc::recv_message(&mut client);
                    assert!(eof.is_err());
                    0
                }
                Case::PartialData => {
                    client.write_all(&[0]).unwrap();
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    let Some(RespResult::Error(error)) = response.result else {
                        panic!("partial data must produce protocol violation")
                    };
                    assert_eq!(error.code, PROMPT_PROTOCOL_VIOLATION_ERROR);
                    1
                }
                Case::CancelFrame => {
                    howy_common::ipc::send_message(
                        &mut client,
                        &Request::cancel_auth_v1([0x22; 32], [0x11; 32]),
                    )
                    .unwrap();
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    let Some(RespResult::Error(error)) = response.result else {
                        panic!("post-commit CancelAuth must produce protocol violation")
                    };
                    assert_eq!(error.code, PROMPT_PROTOCOL_VIOLATION_ERROR);
                    1
                }
                Case::Shutdown => {
                    shutdown.request();
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    assert!(matches!(response.result, Some(RespResult::Error(_))));
                    1
                }
                Case::ManagerShutdown => {
                    manager.shutdown();
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    assert!(matches!(response.result, Some(RespResult::Error(_))));
                    1
                }
                Case::Deadline => {
                    let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                    assert!(matches!(response.result, Some(RespResult::Error(_))));
                    1
                }
            };

            let report = coordinator.join().unwrap().unwrap();
            assert_eq!(
                report.terminal_response_attempts, expected_attempts,
                "{case:?}"
            );
            assert_eq!(report.authentication_started, true, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            assert_eq!(
                promotions.load(Ordering::SeqCst),
                usize::from(matches!(case, Case::Success | Case::AuthFailed)),
                "cache promotion acceptance mismatch for {case:?}"
            );
        }
    }

    #[test]
    fn blocked_commit_snapshot_is_supervised_before_promotion_or_auth_work() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Hup,
            Eof,
            Data,
            Shutdown,
            Deadline,
        }

        for case in [
            Case::Hup,
            Case::Eof,
            Case::Data,
            Case::Shutdown,
            Case::Deadline,
        ] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            let active_timeout = if matches!(case, Case::Deadline) {
                Duration::from_millis(400)
            } else {
                Duration::from_secs(2)
            };
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                active_timeout,
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let (entered_tx, entered_rx) = mpsc::channel();
            let gate = Arc::new(BoundaryGate::new(entered_tx));
            let storage = Arc::new(RunnerStorage::blocking_snapshot(Arc::clone(&gate)));
            let effects = Arc::new(PromptAuthEffects::default());
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_storage = Arc::clone(&storage);
            let worker_config = config.clone();
            let worker_effects = Arc::clone(&effects);
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_storage.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| {
                        let revalidation_config = worker_config.clone();
                        let revalidation_storage = Arc::clone(&worker_storage);
                        spawn_prompt_authentication_after_revalidation(
                            pending,
                            move |pending| {
                                claim_prompt_commit(
                                    pending,
                                    &revalidation_config,
                                    revalidation_storage.as_ref(),
                                )
                            },
                            move |_| PromptWorkerTerminal {
                                response: worker_effects.run(),
                                cleanup_mode: CleanupMode::NotApplicable,
                                cache_promotion: None,
                            },
                        )
                    },
                    &worker_shutdown,
                )
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            match case {
                Case::Hup => {
                    client.shutdown(std::net::Shutdown::Both).unwrap();
                }
                Case::Eof => {
                    client.shutdown(std::net::Shutdown::Write).unwrap();
                }
                Case::Data => client.write_all(&[0]).unwrap(),
                Case::Shutdown => shutdown.request(),
                Case::Deadline => thread::sleep(Duration::from_millis(175)),
            }
            if !matches!(case, Case::Deadline) {
                thread::sleep(Duration::from_millis(30));
            }
            gate.release();

            let response: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
            let expected_attempts = match case {
                Case::Hup | Case::Eof => {
                    assert!(response.is_err(), "{case:?}");
                    0
                }
                Case::Data | Case::Shutdown | Case::Deadline => {
                    assert!(matches!(
                        response.unwrap().result,
                        Some(RespResult::Error(_))
                    ));
                    1
                }
            };
            let report = coordinator.join().unwrap().unwrap();
            assert_eq!(
                report.terminal_response_attempts, expected_attempts,
                "{case:?}"
            );
            effects.assert_zero();
            assert_eq!(storage.auth_calls.load(Ordering::SeqCst), 0, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            assert!(!shutdown.is_fatal(), "{case:?}");
        }
    }

    #[test]
    fn blocked_commit_nss_is_supervised_before_promotion_for_every_cancellation_source() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Hup,
            Eof,
            Data,
            Shutdown,
            Deadline,
        }

        for case in [
            Case::Hup,
            Case::Eof,
            Case::Data,
            Case::Shutdown,
            Case::Deadline,
        ] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                if matches!(case, Case::Deadline) {
                    Duration::from_millis(400)
                } else {
                    Duration::from_secs(2)
                },
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let storage = Arc::new(RunnerStorage::new());
            let effects = Arc::new(PromptAuthEffects::default());
            let (entered_tx, entered_rx) = mpsc::channel();
            let gate = Arc::new(BoundaryGate::new(entered_tx));
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_storage = Arc::clone(&storage);
            let worker_config = config.clone();
            let worker_effects = Arc::clone(&effects);
            let worker_gate = Arc::clone(&gate);
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_storage.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| {
                        let revalidation_config = worker_config.clone();
                        let revalidation_storage = Arc::clone(&worker_storage);
                        spawn_prompt_authentication_after_revalidation(
                            pending,
                            move |pending| {
                                claim_prompt_commit_with_resolver(
                                    pending,
                                    &revalidation_config,
                                    revalidation_storage.as_ref(),
                                    &BlockingIdentityResolver { gate: worker_gate },
                                )
                            },
                            move |_| PromptWorkerTerminal {
                                response: worker_effects.run(),
                                cleanup_mode: CleanupMode::NotApplicable,
                                cache_promotion: None,
                            },
                        )
                    },
                    &worker_shutdown,
                )
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            match case {
                Case::Hup => client.shutdown(std::net::Shutdown::Both).unwrap(),
                Case::Eof => client.shutdown(std::net::Shutdown::Write).unwrap(),
                Case::Data => client.write_all(&[0]).unwrap(),
                Case::Shutdown => shutdown.request(),
                Case::Deadline => thread::sleep(Duration::from_millis(175)),
            }
            if !matches!(case, Case::Deadline) {
                thread::sleep(Duration::from_millis(30));
            }
            gate.release();

            let response: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
            let expected_attempts = if matches!(case, Case::Hup | Case::Eof) {
                assert!(response.is_err(), "{case:?}");
                0
            } else {
                assert!(matches!(
                    response.unwrap().result,
                    Some(RespResult::Error(_))
                ));
                1
            };
            let report = coordinator.join().unwrap().unwrap();
            assert_eq!(
                report.terminal_response_attempts, expected_attempts,
                "{case:?}"
            );
            effects.assert_zero();
            assert_eq!(storage.snapshot_calls.load(Ordering::SeqCst), 1, "{case:?}");
            assert_eq!(storage.auth_calls.load(Ordering::SeqCst), 0, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            assert!(!shutdown.is_fatal(), "{case:?}");
        }
    }

    #[test]
    fn commit_revalidation_consumes_original_camera_deadline_without_refresh() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        config.presence.commit_to_camera_ms = 40;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            Duration::from_secs(2),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let gate = Arc::new(BoundaryGate::new(entered_tx));
        let storage = Arc::new(RunnerStorage::blocking_snapshot(Arc::clone(&gate)));
        let events = LifecycleEvents::default();
        let profile = injected_profile_cache(Arc::new(FixedProfileProvider));
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let camera = LazyCameraHandle {
            profile,
            admission,
            factory: Arc::new(RecordingCameraFactory {
                events: events.clone(),
            }),
        };
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        let auth_config = config.clone();
        let engine = Arc::new(RunnerInference);
        let (mut client, server) = UnixStream::pair().unwrap();
        let coordinator = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection_with_shutdown(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &worker_config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |pending| {
                    let revalidation_config = worker_config.clone();
                    let revalidation_storage = Arc::clone(&worker_storage);
                    let auth_storage = Arc::clone(&worker_storage);
                    spawn_prompt_authentication_after_revalidation(
                        pending,
                        move |pending| {
                            claim_prompt_commit(
                                pending,
                                &revalidation_config,
                                revalidation_storage.as_ref(),
                            )
                        },
                        move |lease| {
                            super::run_committed_prompt_authentication(
                                lease,
                                engine.as_ref(),
                                auth_storage.as_ref(),
                                &auth_config,
                                camera,
                                "root",
                            )
                        },
                    )
                },
                &worker_shutdown,
            )
        });

        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
            panic!("expected prompt")
        };
        howy_common::ipc::send_message(
            &mut client,
            &Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            ),
        )
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        thread::sleep(Duration::from_millis(70));
        gate.release();
        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        assert!(matches!(response.result, Some(RespResult::Error(_))));
        let report = coordinator.join().unwrap().unwrap();
        assert_eq!(report.terminal_response_attempts, 1);
        assert_eq!(storage.auth_calls.load(Ordering::SeqCst), 0);
        events.assert_empty();
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn mode1_prompt_cold_load_completes_before_any_camera_admission_or_io() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        config.security.embedding_mode = howy_common::config::EmbeddingSecurityMode::AeadCached;
        config.presence.commit_to_camera_ms = 1_000;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let (storage_entered_tx, storage_entered_rx) = mpsc::channel();
        let storage_gate = Arc::new(CancellableBoundaryGate::new(storage_entered_tx));
        let storage = Arc::new(RunnerStorage::cancellable(Arc::clone(&storage_gate)));
        let events = LifecycleEvents::default();
        let profile = injected_profile_cache(Arc::new(FixedProfileProvider));
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let camera = LazyCameraHandle {
            profile,
            admission,
            factory: Arc::new(RecordingCameraFactory {
                events: events.clone(),
            }),
        };
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        let auth_config = config.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let coordinator = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection_with_shutdown(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &worker_config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |pending| {
                    let revalidation_config = worker_config.clone();
                    let revalidation_storage = Arc::clone(&worker_storage);
                    let auth_storage = Arc::clone(&worker_storage);
                    spawn_prompt_authentication_after_revalidation(
                        pending,
                        move |pending| {
                            claim_prompt_commit(
                                pending,
                                &revalidation_config,
                                revalidation_storage.as_ref(),
                            )
                        },
                        move |lease| {
                            super::run_committed_prompt_authentication(
                                lease,
                                &RunnerInference,
                                auth_storage.as_ref(),
                                &auth_config,
                                camera,
                                "root",
                            )
                        },
                    )
                },
                &worker_shutdown,
            )
        });

        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
            panic!("expected prompt")
        };
        howy_common::ipc::send_message(
            &mut client,
            &Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            ),
        )
        .unwrap();
        storage_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        events.assert_empty();
        storage_gate.release();

        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        assert!(matches!(response.result, Some(RespResult::Success(_))));
        let report = coordinator.join().unwrap().unwrap();
        assert_eq!(report.terminal_response_attempts, 1);
        assert_eq!(storage.auth_calls.load(Ordering::SeqCst), 1);
        assert_eq!(storage.promotion_calls.load(Ordering::SeqCst), 1);
        assert_eq!(storage.budget.used(), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
        assert!(!shutdown.is_fatal());
    }

    #[test]
    fn first_frame_timeliness_is_fixed_at_capture_boundary_while_storage_joins() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            TimelyFrameSlowStorage,
            LateFrame,
            StorageTimeout,
        }

        for case in [
            Case::TimelyFrameSlowStorage,
            Case::LateFrame,
            Case::StorageTimeout,
        ] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            config.presence.commit_to_camera_ms = 600;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let (storage_entered_tx, storage_entered_rx) = mpsc::channel();
            let storage_gate = Arc::new(CancellableBoundaryGate::new(storage_entered_tx));
            let storage = Arc::new(RunnerStorage::cancellable(Arc::clone(&storage_gate)));
            let (frame_entered_tx, frame_entered_rx) = mpsc::channel();
            let frame_gate = Arc::new(BoundaryGate::new(frame_entered_tx));
            let (frame_completed_tx, frame_completed_rx) = mpsc::channel();
            let profile = Arc::new(probing_profile_cache());
            profile.complete_probe(
                0,
                Ok(CameraProfile::test_profile("capture-boundary-timing")),
                Instant::now(),
            );
            let (admission, _reaper) = CameraReaper::new().unwrap();
            let camera = LazyCameraHandle {
                profile,
                admission,
                factory: Arc::new(TimedFrameCameraFactory {
                    gate: Arc::clone(&frame_gate),
                    completed: Mutex::new(Some(frame_completed_tx)),
                }),
            };
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_storage = Arc::clone(&storage);
            let worker_config = config.clone();
            let (camera_deadline_tx, camera_deadline_rx) = mpsc::channel();
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_storage.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| -> PromptAuthentication {
                        let lease = match claim_prompt_commit(
                            pending,
                            &worker_config,
                            worker_storage.as_ref(),
                        ) {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                        let storage = Arc::clone(&worker_storage);
                        let config = worker_config.clone();
                        spawn_prompt_authentication(lease, move |lease| {
                            camera_deadline_tx
                                .send(lease.camera_ready_deadline())
                                .unwrap();
                            super::run_committed_prompt_authentication(
                                lease,
                                &RunnerInference,
                                storage.as_ref(),
                                &config,
                                camera,
                                "root",
                            )
                        })
                    },
                    &worker_shutdown,
                )
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            frame_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            storage_entered_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            let camera_deadline = camera_deadline_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();

            match case {
                Case::TimelyFrameSlowStorage => {
                    thread::sleep(
                        camera_deadline
                            .checked_sub(Duration::from_millis(100))
                            .unwrap()
                            .saturating_duration_since(Instant::now()),
                    );
                    frame_gate.release();
                    assert!(
                        frame_completed_rx
                            .recv_timeout(Duration::from_secs(1))
                            .unwrap()
                    );
                    thread::sleep(
                        camera_deadline
                            .checked_add(Duration::from_millis(50))
                            .unwrap()
                            .saturating_duration_since(Instant::now()),
                    );
                    storage_gate.release();
                }
                Case::LateFrame => {
                    storage_gate.release();
                    thread::sleep(
                        camera_deadline
                            .checked_add(Duration::from_millis(50))
                            .unwrap()
                            .saturating_duration_since(Instant::now()),
                    );
                    frame_gate.release();
                    assert!(
                        !frame_completed_rx
                            .recv_timeout(Duration::from_secs(1))
                            .unwrap()
                    );
                }
                Case::StorageTimeout => {
                    frame_gate.release();
                    assert!(
                        frame_completed_rx
                            .recv_timeout(Duration::from_secs(1))
                            .unwrap()
                    );
                }
            }

            let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            if matches!(case, Case::TimelyFrameSlowStorage) {
                assert!(matches!(response.result, Some(RespResult::Success(_))));
            } else {
                assert!(matches!(response.result, Some(RespResult::Error(_))));
            }
            let report = coordinator.join().unwrap().unwrap();
            assert_eq!(report.terminal_response_attempts, 1, "{case:?}");
            assert_eq!(
                storage.promotion_calls.load(Ordering::SeqCst),
                usize::from(matches!(case, Case::TimelyFrameSlowStorage)),
                "{case:?}"
            );
            assert_eq!(storage.budget.used(), 0, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            assert!(!shutdown.is_fatal(), "{case:?}");
        }
    }

    #[test]
    fn real_coordinator_hup_directly_cancels_blocked_camera_boundary() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(RunnerStorage::new());
        let engine = Arc::new(RunnerInference);
        let profile = Arc::new(probing_profile_cache());
        profile.complete_probe(
            0,
            Ok(CameraProfile::test_profile("direct-cancel")),
            Instant::now(),
        );
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let control = Arc::new(BlockingCameraControl::new(true));
        let (entered_tx, entered_rx) = mpsc::channel();
        let factory: Arc<dyn CameraFactory> = Arc::new(BlockingActiveCameraFactory {
            control: Arc::clone(&control),
            entered: Mutex::new(Some(entered_tx)),
        });
        let camera = LazyCameraHandle {
            profile,
            admission,
            factory,
        };
        let shutdown = ShutdownSignal::new();
        let worker_shutdown = shutdown.clone();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        let (mut client, server) = UnixStream::pair().unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let coordinator = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            let result = coordinate_prompt_connection_with_shutdown(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &worker_config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |pending| -> PromptAuthentication {
                    let lease =
                        match claim_prompt_commit(pending, &worker_config, worker_storage.as_ref())
                        {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                    let engine = Arc::clone(&engine);
                    let storage = Arc::clone(&worker_storage);
                    let config = worker_config.clone();
                    spawn_prompt_authentication(lease, move |lease| {
                        super::run_committed_prompt_authentication(
                            lease,
                            engine.as_ref(),
                            storage.as_ref(),
                            &config,
                            camera,
                            "root",
                        )
                    })
                },
                &worker_shutdown,
            );
            done_tx.send(result).unwrap();
        });

        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
            panic!("expected prompt")
        };
        howy_common::ipc::send_message(
            &mut client,
            &Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            ),
        )
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
        drop(client);

        let report = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("direct camera cancellation must unblock the production auth worker")
            .unwrap();
        coordinator.join().unwrap();
        assert!(control.cancelled.load(Ordering::Acquire));
        assert!(!shutdown.is_fatal());
        assert_eq!(report.terminal_response_attempts, 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn real_committed_worker_result_barrier_preserves_supervisor_precedence() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Result,
            Hup,
            Eof,
            FullData,
            PartialData,
            CancelAuth,
            Deadline,
            ManagerShutdown,
            DaemonShutdown,
            Panic,
        }

        for case in [
            Case::Result,
            Case::Hup,
            Case::Eof,
            Case::FullData,
            Case::PartialData,
            Case::CancelAuth,
            Case::Deadline,
            Case::ManagerShutdown,
            Case::DaemonShutdown,
            Case::Panic,
        ] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            let active_timeout = if matches!(case, Case::Deadline) {
                Duration::from_millis(400)
            } else {
                Duration::from_secs(2)
            };
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                active_timeout,
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let storage = Arc::new(RunnerStorage::new());
            let engine = Arc::new(RunnerInference);
            let profile = Arc::new(probing_profile_cache());
            profile.complete_probe(
                0,
                Ok(CameraProfile::test_profile("result-race")),
                Instant::now(),
            );
            let (admission, _reaper) = CameraReaper::new().unwrap();
            let camera = LazyCameraHandle {
                profile,
                admission,
                factory: Arc::new(RecordingCameraFactory {
                    events: LifecycleEvents::default(),
                }),
            };
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_storage = Arc::clone(&storage);
            let worker_config = config.clone();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                let result = coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_storage.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| -> PromptAuthentication {
                        let lease = match claim_prompt_commit(
                            pending,
                            &worker_config,
                            worker_storage.as_ref(),
                        ) {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                        let engine = Arc::clone(&engine);
                        let storage = Arc::clone(&worker_storage);
                        let config = worker_config.clone();
                        spawn_prompt_authentication(lease, move |lease| {
                            let terminal = super::run_committed_prompt_authentication(
                                lease,
                                engine.as_ref(),
                                storage.as_ref(),
                                &config,
                                camera,
                                "root",
                            );
                            ready_tx.send(()).unwrap();
                            release_rx.recv().unwrap();
                            if matches!(case, Case::Panic) {
                                panic!("injected panic after real committed result");
                            }
                            terminal
                        })
                    },
                    &worker_shutdown,
                );
                done_tx.send(result).unwrap();
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();

            let mut expect_response = true;
            match case {
                Case::Result | Case::Panic => {}
                Case::Hup => {
                    client.shutdown(std::net::Shutdown::Both).unwrap();
                    expect_response = false;
                }
                Case::Eof => {
                    client.shutdown(std::net::Shutdown::Write).unwrap();
                    expect_response = false;
                }
                Case::FullData => {
                    howy_common::ipc::send_message(&mut client, &Request::ping()).unwrap();
                }
                Case::PartialData => client.write_all(&[0]).unwrap(),
                Case::CancelAuth => {
                    howy_common::ipc::send_message(
                        &mut client,
                        &Request::cancel_auth_v1([0x22; 32], [0x11; 32]),
                    )
                    .unwrap();
                }
                Case::Deadline => thread::sleep(Duration::from_millis(180)),
                Case::ManagerShutdown => manager.shutdown(),
                Case::DaemonShutdown => shutdown.request(),
            }
            release_tx.send(()).unwrap();

            if expect_response {
                let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                match case {
                    Case::Result => {
                        assert!(matches!(response.result, Some(RespResult::Success(_))))
                    }
                    Case::FullData | Case::PartialData | Case::CancelAuth => {
                        let Some(RespResult::Error(error)) = response.result else {
                            panic!("expected protocol error for {case:?}")
                        };
                        assert_eq!(error.code, PROMPT_PROTOCOL_VIOLATION_ERROR);
                    }
                    Case::Deadline | Case::ManagerShutdown | Case::DaemonShutdown | Case::Panic => {
                        assert!(matches!(response.result, Some(RespResult::Error(_))))
                    }
                    Case::Hup | Case::Eof => unreachable!(),
                }
            } else if matches!(case, Case::Eof) {
                let closed: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
                assert!(closed.is_err());
            }

            let report = done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap();
            coordinator.join().unwrap();
            assert_eq!(
                report.terminal_response_attempts,
                u8::from(expect_response),
                "{case:?}"
            );
            assert!(!shutdown.is_fatal(), "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            assert_eq!(storage.budget.used(), 0, "{case:?}");
        }
    }

    #[test]
    fn real_framed_mode0_provisional_promotion_races_publish_conditionally() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Hup,
            Deadline,
            Protocol,
            Panic,
            Result,
            ConcurrentReader,
            Reload,
        }

        for case in [
            Case::Hup,
            Case::Deadline,
            Case::Protocol,
            Case::Panic,
            Case::Result,
            Case::ConcurrentReader,
            Case::Reload,
        ] {
            let directory = temp_directory(&format!("mode0-promotion-{case:?}"));
            let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
            let backend = Arc::new(
                PlaintextStorageBackend::new(
                    PlaintextBackendOptions::path_override(&directory),
                    ModelDigest::new([0x42; 32]),
                    PlaintextStorageLimits::new(8, 64 * 1024).unwrap(),
                    ModelCacheLimits::new(8, 4 * 1024 * 1024).unwrap(),
                    budget.clone(),
                )
                .unwrap(),
            );
            let root = CanonicalUsername::new("root").unwrap();
            let embedding: [f32; howy_common::face::FACE_EMBEDDING_DIM] =
                RunnerInference::embedding().try_into().unwrap();
            let entry = EnrollmentEntry::new(
                EnrollmentId::new([1; 16]).unwrap(),
                1_700_000_001,
                "runner",
                embedding,
            )
            .unwrap();
            backend
                .append(AppendRequest::new(&root, 0, &[entry]).unwrap())
                .unwrap();
            backend.reload().unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert_eq!(budget.used(), 0);
            let baseline_loads = backend.load_count_for_test();

            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            let active_timeout = if matches!(case, Case::Deadline) {
                Duration::from_millis(400)
            } else {
                Duration::from_secs(2)
            };
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                active_timeout,
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let profile = Arc::new(probing_profile_cache());
            profile.complete_probe(
                0,
                Ok(CameraProfile::test_profile("mode0-promotion")),
                Instant::now(),
            );
            let (admission, _reaper) = CameraReaper::new().unwrap();
            let camera = LazyCameraHandle {
                profile,
                admission,
                factory: Arc::new(RecordingCameraFactory {
                    events: LifecycleEvents::default(),
                }),
            };
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_backend = Arc::clone(&backend);
            let worker_config = config.clone();
            let (result_ready_tx, result_ready_rx) = mpsc::channel();
            let (result_release_tx, result_release_rx) = mpsc::channel();
            let (promotion_entered_tx, promotion_entered_rx) = mpsc::channel();
            let (promotion_release_tx, promotion_release_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                let result = coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_backend.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| -> PromptAuthentication {
                        let lease = match claim_prompt_commit(
                            pending,
                            &worker_config,
                            worker_backend.as_ref(),
                        ) {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                        let backend = Arc::clone(&worker_backend);
                        let config = worker_config.clone();
                        spawn_prompt_authentication(lease, move |lease| {
                            let mut terminal = super::run_committed_prompt_authentication(
                                lease,
                                &RunnerInference,
                                backend.as_ref(),
                                &config,
                                camera,
                                "root",
                            );
                            let promotion = terminal
                                .cache_promotion
                                .take()
                                .expect("cold Mode 0 load must remain provisional");
                            terminal.cache_promotion = Some(Box::new(BarrierPromotion {
                                inner: promotion,
                                entered: promotion_entered_tx,
                                release: promotion_release_rx,
                            }));
                            result_ready_tx.send(()).unwrap();
                            result_release_rx.recv().unwrap();
                            if matches!(case, Case::Panic) {
                                panic!("injected panic while owning provisional Mode 0 load");
                            }
                            terminal
                        })
                    },
                    &worker_shutdown,
                );
                done_tx.send(result).unwrap();
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            result_ready_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert!(budget.used() > 0);

            match case {
                Case::Hup => client.shutdown(std::net::Shutdown::Both).unwrap(),
                Case::Deadline => thread::sleep(Duration::from_millis(180)),
                Case::Protocol => client.write_all(&[0]).unwrap(),
                Case::Panic | Case::Result | Case::ConcurrentReader | Case::Reload => {}
            }
            result_release_tx.send(()).unwrap();

            if matches!(case, Case::Result | Case::ConcurrentReader | Case::Reload) {
                promotion_entered_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("accepted result must reach promotion barrier");
                match case {
                    Case::ConcurrentReader => {
                        let lease = backend.authenticate(&root).unwrap();
                        assert_eq!(lease.generation(), 1);
                        drop(lease);
                        assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    }
                    Case::Reload => {
                        backend.reload().unwrap();
                        assert_eq!(backend.cached_generation_for_test(&root), None);
                    }
                    Case::Result => {}
                    _ => unreachable!(),
                }
                promotion_release_tx.send(()).unwrap();
            }

            if !matches!(case, Case::Hup) {
                let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                match case {
                    Case::Result | Case::ConcurrentReader | Case::Reload => {
                        assert!(matches!(response.result, Some(RespResult::Success(_))))
                    }
                    Case::Protocol => {
                        let Some(RespResult::Error(error)) = response.result else {
                            panic!("expected protocol error")
                        };
                        assert_eq!(error.code, PROMPT_PROTOCOL_VIOLATION_ERROR);
                    }
                    Case::Deadline | Case::Panic => {
                        assert!(matches!(response.result, Some(RespResult::Error(_))))
                    }
                    Case::Hup => unreachable!(),
                }
            }

            let report = done_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap();
            coordinator.join().unwrap();
            assert_eq!(
                report.terminal_response_attempts,
                u8::from(!matches!(case, Case::Hup)),
                "{case:?}"
            );
            assert!(!shutdown.is_fatal(), "{case:?}");
            match case {
                Case::Result => assert_eq!(backend.cached_generation_for_test(&root), Some(1)),
                Case::ConcurrentReader => {
                    assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    assert_eq!(backend.load_count_for_test(), baseline_loads + 2);
                }
                Case::Reload => {
                    assert_eq!(backend.cached_generation_for_test(&root), None);
                    let lease = backend.authenticate(&root).unwrap();
                    assert_eq!(lease.generation(), 1);
                    drop(lease);
                    assert_eq!(backend.load_count_for_test(), baseline_loads + 3);
                }
                Case::Hup | Case::Deadline | Case::Protocol | Case::Panic => {
                    assert_eq!(backend.cached_generation_for_test(&root), None);
                    assert!(matches!(
                        promotion_entered_rx.try_recv(),
                        Err(mpsc::TryRecvError::Disconnected)
                    ));
                }
            }
            backend.reload().unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert_eq!(budget.used(), 0, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn real_framed_mode1_provisional_promotion_requires_accepted_written_terminal() {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            Success,
            AuthFailed,
            Infrastructure,
            Hup,
            PostWriteHup,
            PostWriteHupWithNewerReader,
            PostWriteDeadline,
            PostWriteDeadlineWithNewerReader,
            PostWriteShutdown,
            PostWriteShutdownWithNewerReader,
            Deadline,
            Protocol,
            WriteFailure,
            ConcurrentReader,
            Reload,
        }

        for case in [
            Case::Success,
            Case::AuthFailed,
            Case::Infrastructure,
            Case::Hup,
            Case::PostWriteHup,
            Case::PostWriteHupWithNewerReader,
            Case::PostWriteDeadline,
            Case::PostWriteDeadlineWithNewerReader,
            Case::PostWriteShutdown,
            Case::PostWriteShutdownWithNewerReader,
            Case::Deadline,
            Case::Protocol,
            Case::WriteFailure,
            Case::ConcurrentReader,
            Case::Reload,
        ] {
            let directory = temp_directory(&format!("mode1-promotion-{case:?}"));
            let budget = PlaintextBudget::new(4 * 1024 * 1024).unwrap();
            let backend = Arc::new(
                Mode1StorageBackend::new(
                    Mode1BackendOptions::path_override(&directory),
                    Mode1KeyContext::from_test_key([0x31; 32]),
                    ModelDigest::new([0x42; 32]),
                    1,
                    Mode1StorageLimits::new(8, 64 * 1024).unwrap(),
                    ModelCacheLimits::new(8, 4 * 1024 * 1024).unwrap(),
                    budget.clone(),
                )
                .unwrap(),
            );
            let root = CanonicalUsername::new("root").unwrap();
            let embedding: [f32; howy_common::face::FACE_EMBEDDING_DIM] =
                if matches!(case, Case::AuthFailed) {
                    let mut embedding = [0.0; howy_common::face::FACE_EMBEDDING_DIM];
                    embedding[0] = 1.0;
                    embedding
                } else {
                    RunnerInference::embedding().try_into().unwrap()
                };
            let entry = EnrollmentEntry::new(
                EnrollmentId::new([1; 16]).unwrap(),
                1_700_000_001,
                "runner",
                embedding,
            )
            .unwrap();
            backend
                .append(AppendRequest::new(&root, 0, &[entry]).unwrap())
                .unwrap();
            backend.reload().unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert_eq!(budget.used(), 0);

            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
            config.presence.scan_timeout_ms = 100;
            let active_timeout = if matches!(
                case,
                Case::Deadline | Case::PostWriteDeadline | Case::PostWriteDeadlineWithNewerReader
            ) {
                Duration::from_millis(400)
            } else {
                Duration::from_secs(2)
            };
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                active_timeout,
                prompt_active_capacity(),
            ));
            let connection_id = manager.new_connection().unwrap();
            let profile = Arc::new(probing_profile_cache());
            profile.complete_probe(
                0,
                Ok(CameraProfile::test_profile("mode1-promotion")),
                Instant::now(),
            );
            let (admission, _reaper) = CameraReaper::new().unwrap();
            let camera = LazyCameraHandle {
                profile,
                admission,
                factory: Arc::new(RecordingCameraFactory {
                    events: LifecycleEvents::default(),
                }),
            };
            let shutdown = ShutdownSignal::new();
            let worker_shutdown = shutdown.clone();
            let worker_manager = Arc::clone(&manager);
            let worker_backend = Arc::clone(&backend);
            let worker_config = config.clone();
            let (result_ready_tx, result_ready_rx) = mpsc::channel();
            let (result_release_tx, result_release_rx) = mpsc::channel();
            let (promotion_entered_tx, promotion_entered_rx) = mpsc::channel();
            let (promotion_release_tx, promotion_release_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let (mut client, server) = UnixStream::pair().unwrap();
            let server_write_control = server.try_clone().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let coordinator = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                let result = coordinate_prompt_connection_with_shutdown(
                    &mut io,
                    None,
                    |begin| {
                        prepare_prompt_pending(
                            0,
                            connection_id,
                            &worker_config,
                            worker_backend.as_ref(),
                            &worker_manager,
                            begin,
                        )
                    },
                    |pending| -> PromptAuthentication {
                        let lease = match claim_prompt_commit(
                            pending,
                            &worker_config,
                            worker_backend.as_ref(),
                        ) {
                            Ok(lease) => lease,
                            Err(response) => return PromptAuthentication::Completed(response),
                        };
                        let backend = Arc::clone(&worker_backend);
                        let config = worker_config.clone();
                        spawn_prompt_authentication(lease, move |lease| {
                            let mut terminal = super::run_committed_prompt_authentication(
                                lease,
                                &RunnerInference,
                                backend.as_ref(),
                                &config,
                                camera,
                                "root",
                            );
                            let promotion = terminal.cache_promotion.take().unwrap_or_else(|| {
                                panic!(
                                    "cold Mode 1 load must remain provisional, got {:?}",
                                    terminal.response.result
                                )
                            });
                            terminal.cache_promotion = Some(Box::new(BarrierPromotion {
                                inner: promotion,
                                entered: promotion_entered_tx,
                                release: promotion_release_rx,
                            }));
                            if matches!(case, Case::Infrastructure) {
                                terminal.response = Response::error("authentication unavailable");
                            }
                            result_ready_tx.send(()).unwrap();
                            result_release_rx.recv().unwrap();
                            terminal
                        })
                    },
                    &worker_shutdown,
                );
                done_tx.send(result).unwrap();
            });

            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt for {case:?}")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            result_ready_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert!(budget.used() > 0);

            match case {
                Case::Hup => client.shutdown(std::net::Shutdown::Both).unwrap(),
                Case::Deadline => thread::sleep(Duration::from_millis(180)),
                Case::Protocol => client.write_all(&[0]).unwrap(),
                Case::WriteFailure => server_write_control
                    .shutdown(std::net::Shutdown::Write)
                    .unwrap(),
                Case::Success
                | Case::AuthFailed
                | Case::Infrastructure
                | Case::PostWriteHup
                | Case::PostWriteHupWithNewerReader
                | Case::PostWriteDeadline
                | Case::PostWriteDeadlineWithNewerReader
                | Case::PostWriteShutdown
                | Case::PostWriteShutdownWithNewerReader
                | Case::ConcurrentReader
                | Case::Reload => {}
            }
            result_release_tx.send(()).unwrap();

            let mut retained_reader_bytes = None;
            if matches!(
                case,
                Case::Success
                    | Case::AuthFailed
                    | Case::PostWriteHup
                    | Case::PostWriteHupWithNewerReader
                    | Case::PostWriteDeadline
                    | Case::PostWriteDeadlineWithNewerReader
                    | Case::PostWriteShutdown
                    | Case::PostWriteShutdownWithNewerReader
                    | Case::ConcurrentReader
                    | Case::Reload
            ) {
                promotion_entered_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("accepted written terminal must reach promotion barrier");
                match case {
                    Case::ConcurrentReader => {
                        let lease = backend.authenticate(&root).unwrap();
                        assert_eq!(lease.generation(), 1);
                        drop(lease);
                        assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    }
                    Case::Reload => {
                        backend.reload().unwrap();
                        assert_eq!(backend.cached_generation_for_test(&root), None);
                    }
                    Case::PostWriteHup => {
                        // The terminal frame is already in the socket and the
                        // cache promotion is blocked before insertion. HUP must
                        // still cancel publication before the cache-lock
                        // predicate is evaluated.
                        client.shutdown(std::net::Shutdown::Both).unwrap();
                    }
                    Case::PostWriteHupWithNewerReader => {
                        let lease = backend.authenticate(&root).unwrap();
                        retained_reader_bytes = Some(lease.plaintext_bytes());
                        drop(lease);
                        assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                        client.shutdown(std::net::Shutdown::Both).unwrap();
                    }
                    Case::PostWriteDeadline => {
                        thread::sleep(active_timeout + Duration::from_millis(50));
                    }
                    Case::PostWriteDeadlineWithNewerReader => {
                        let lease = backend.authenticate(&root).unwrap();
                        retained_reader_bytes = Some(lease.plaintext_bytes());
                        drop(lease);
                        assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                        thread::sleep(active_timeout + Duration::from_millis(50));
                    }
                    Case::PostWriteShutdown => {
                        manager.shutdown();
                        shutdown.request();
                    }
                    Case::PostWriteShutdownWithNewerReader => {
                        let lease = backend.authenticate(&root).unwrap();
                        retained_reader_bytes = Some(lease.plaintext_bytes());
                        drop(lease);
                        assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                        manager.shutdown();
                        shutdown.request();
                    }
                    Case::Success | Case::AuthFailed => {}
                    _ => unreachable!(),
                }
                promotion_release_tx.send(()).unwrap();
            }

            if !matches!(
                case,
                Case::Hup
                    | Case::PostWriteHup
                    | Case::PostWriteHupWithNewerReader
                    | Case::WriteFailure
            ) {
                let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                match case {
                    Case::Success | Case::ConcurrentReader | Case::Reload => {
                        assert!(matches!(response.result, Some(RespResult::Success(_))))
                    }
                    Case::AuthFailed => {
                        assert!(matches!(response.result, Some(RespResult::AuthFailed(_))))
                    }
                    Case::Infrastructure | Case::Deadline => {
                        assert!(matches!(response.result, Some(RespResult::Error(_))))
                    }
                    Case::Protocol => {
                        let Some(RespResult::Error(error)) = response.result else {
                            panic!("expected protocol error")
                        };
                        assert_eq!(error.code, PROMPT_PROTOCOL_VIOLATION_ERROR);
                    }
                    Case::Hup
                    | Case::PostWriteHup
                    | Case::PostWriteHupWithNewerReader
                    | Case::WriteFailure => unreachable!(),
                    Case::PostWriteDeadline
                    | Case::PostWriteDeadlineWithNewerReader
                    | Case::PostWriteShutdown
                    | Case::PostWriteShutdownWithNewerReader => {
                        assert!(matches!(response.result, Some(RespResult::Success(_))))
                    }
                }
            } else if matches!(case, Case::WriteFailure) {
                let closed: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
                assert!(closed.is_err());
            }

            let coordinate_result = done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            coordinator.join().unwrap();
            if matches!(case, Case::WriteFailure) {
                assert!(coordinate_result.is_err());
            } else {
                let report = coordinate_result.unwrap();
                assert_eq!(
                    report.terminal_response_attempts,
                    u8::from(!matches!(case, Case::Hup)),
                    "{case:?}"
                );
            }
            assert!(!shutdown.is_fatal(), "{case:?}");
            match case {
                Case::Success | Case::AuthFailed | Case::ConcurrentReader => {
                    assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    assert!(budget.used() > 0);
                }
                Case::PostWriteHupWithNewerReader => {
                    assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    assert_eq!(budget.used(), retained_reader_bytes.unwrap());
                }
                Case::PostWriteDeadlineWithNewerReader | Case::PostWriteShutdownWithNewerReader => {
                    assert_eq!(backend.cached_generation_for_test(&root), Some(1));
                    assert_eq!(budget.used(), retained_reader_bytes.unwrap());
                }
                Case::Infrastructure
                | Case::Hup
                | Case::PostWriteHup
                | Case::PostWriteDeadline
                | Case::PostWriteShutdown
                | Case::Deadline
                | Case::Protocol
                | Case::WriteFailure
                | Case::Reload => {
                    assert_eq!(backend.cached_generation_for_test(&root), None);
                    assert_eq!(budget.used(), 0, "{case:?}");
                    assert!(matches!(
                        promotion_entered_rx.try_recv(),
                        Err(mpsc::TryRecvError::Disconnected)
                    ));
                }
            }
            backend.reload().unwrap();
            assert_eq!(backend.cached_generation_for_test(&root), None);
            assert_eq!(budget.used(), 0, "{case:?}");
            assert_eq!(manager.counts(), (0, 0, 0), "{case:?}");
            drop(backend);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn production_runner_fail_stops_when_blocked_camera_ignores_direct_cancel() {
        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("active-fail-stop");
        let socket = directory.join("howy.sock");
        let _socket_environment = SocketEnvGuard::set(&socket);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let username = current_peer_username();
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            config.presence.prompt_timeout_ms = 1_000;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                Duration::from_millis(400),
                prompt_active_capacity(),
            ));
            let shutdown = ShutdownSignal::new();
            let control = Arc::new(BlockingCameraControl::new(false));
            let (entered_tx, entered_rx) = mpsc::channel();
            let server = tokio::spawn(run_with_camera_hooks(
                Arc::new(RunnerInference),
                Arc::new(RunnerStorage::new()),
                Arc::clone(&manager),
                config,
                false,
                false,
                None,
                shutdown.clone(),
                CameraHooks {
                    profile_provider: Arc::new(FixedProfileProvider),
                    factory: Arc::new(BlockingActiveCameraFactory {
                        control: Arc::clone(&control),
                        entered: Mutex::new(Some(entered_tx)),
                    }),
                },
            ));
            wait_for_socket(&socket).await;

            let mut client = UnixStream::connect(&socket).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let begin = Request::begin_auth_v1(
                &username,
                [0x11; PROMPT_NONCE_BYTES],
                "sudo",
                PromptOriginV1::Local,
            );
            howy_common::ipc::send_message(&mut client, &begin).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt")
            };
            howy_common::ipc::send_message(
                &mut client,
                &Request::commit_auth_v1_ref(
                    prompt.transaction_token.as_slice().try_into().unwrap(),
                    prompt.client_nonce.as_slice().try_into().unwrap(),
                ),
            )
            .unwrap();
            entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

            let closed: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
            assert!(closed.is_err());
            let run_error = server
                .await
                .unwrap()
                .expect_err("resource cleanup overrun must fail the daemon run");
            assert!(run_error.to_string().contains("fail-stop"));
            assert!(shutdown.is_fatal());
            assert!(control.cancelled.load(Ordering::Acquire));

            // Release the injected non-returning boundary after observing the
            // fail-stop. Production relies on process exit for this remainder.
            control.release();
            let deadline = Instant::now() + Duration::from_secs(1);
            while manager.counts() != (0, 0, 0) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(manager.counts(), (0, 0, 0));
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn production_runner_fail_stops_across_resource_owning_auth_boundaries() {
        #[derive(Clone, Copy, Debug)]
        enum Boundary {
            Snapshot,
            Probe,
            Start,
            Frame,
            Storage,
            Inference,
            Cleanup,
        }

        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("active-boundary-fail-stop");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let username = current_peer_username();
            for boundary in [
                Boundary::Snapshot,
                Boundary::Probe,
                Boundary::Start,
                Boundary::Frame,
                Boundary::Storage,
                Boundary::Inference,
                Boundary::Cleanup,
            ] {
                let socket = directory.join(format!("{boundary:?}.sock"));
                let _socket_environment = SocketEnvGuard::set(&socket);
                let (entered_tx, entered_rx) = mpsc::channel();
                let gate = Arc::new(BoundaryGate::new(entered_tx));
                let control = Arc::new(BlockingCameraControl::new(false));
                let provider: Arc<dyn CameraProfileProvider> =
                    if matches!(boundary, Boundary::Probe) {
                        Arc::new(BlockingProfileProvider(Arc::clone(&gate)))
                    } else {
                        Arc::new(FixedProfileProvider)
                    };
                let factory: Arc<dyn CameraFactory> = match boundary {
                    Boundary::Start => Arc::new(BoundaryCameraFactory {
                        phase: BlockingCameraPhase::Start,
                        gate: Arc::clone(&gate),
                        control: Arc::clone(&control),
                    }),
                    Boundary::Frame => Arc::new(BoundaryCameraFactory {
                        phase: BlockingCameraPhase::Frame,
                        gate: Arc::clone(&gate),
                        control: Arc::clone(&control),
                    }),
                    Boundary::Cleanup => Arc::new(BoundaryCameraFactory {
                        phase: BlockingCameraPhase::Cleanup,
                        gate: Arc::clone(&gate),
                        control: Arc::clone(&control),
                    }),
                    Boundary::Snapshot
                    | Boundary::Probe
                    | Boundary::Storage
                    | Boundary::Inference => Arc::new(RecordingCameraFactory {
                        events: LifecycleEvents::default(),
                    }),
                };
                let storage = if matches!(boundary, Boundary::Snapshot) {
                    Arc::new(RunnerStorage::blocking_snapshot(Arc::clone(&gate)))
                } else if matches!(boundary, Boundary::Storage) {
                    Arc::new(RunnerStorage::blocking(Arc::clone(&gate)))
                } else {
                    Arc::new(RunnerStorage::new())
                };
                let storage_backend: Arc<dyn StorageBackend> = storage.clone();
                let engine = Arc::new(BlockingInference(
                    matches!(boundary, Boundary::Inference).then(|| Arc::clone(&gate)),
                ));
                let mut config = howy_common::config::HowyConfig::default();
                config.presence.mode = PresenceMode::Confirm;
                config.presence.prompt_timeout_ms = 1_000;
                let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                    &config,
                    Duration::from_millis(400),
                    prompt_active_capacity(),
                ));
                let shutdown = ShutdownSignal::new();
                let (admission_tx, admission_rx) = mpsc::channel();
                let server = tokio::spawn(run_with_camera_and_server_hooks(
                    engine,
                    storage_backend,
                    Arc::clone(&manager),
                    config,
                    false,
                    false,
                    None,
                    shutdown.clone(),
                    CameraHooks {
                        profile_provider: provider,
                        factory,
                    },
                    ServerRunHooks {
                        after_accept: None,
                        before_handle: None,
                        camera_admission: Some(Arc::new(move |admission| {
                            admission_tx.send(admission).unwrap();
                        })),
                        runtime_identity: None,
                    },
                ));
                let admission = admission_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                wait_for_socket(&socket).await;

                let mut client = UnixStream::connect(&socket).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                howy_common::ipc::send_message(
                    &mut client,
                    &Request::begin_auth_v1(
                        &username,
                        [0x11; PROMPT_NONCE_BYTES],
                        "sudo",
                        PromptOriginV1::Local,
                    ),
                )
                .unwrap();
                let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
                let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                    panic!("expected prompt at {boundary:?}")
                };
                howy_common::ipc::send_message(
                    &mut client,
                    &Request::commit_auth_v1_ref(
                        prompt.transaction_token.as_slice().try_into().unwrap(),
                        prompt.client_nonce.as_slice().try_into().unwrap(),
                    ),
                )
                .unwrap();
                entered_rx
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap_or_else(|_| panic!("{boundary:?} boundary was not reached"));

                let fatal_deadline = Instant::now() + Duration::from_secs(1);
                while !shutdown.is_fatal() && Instant::now() < fatal_deadline {
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(shutdown.is_fatal(), "{boundary:?}");
                let (_, _, active) = manager.counts();
                assert!(active <= prompt_active_capacity(), "{boundary:?}");

                // A request queued at the fatal transition is either refused by
                // connect or silently dropped by the post-accept/worker gates.
                if let Ok(mut queued) = UnixStream::connect(&socket) {
                    queued
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let _ = howy_common::ipc::send_message(&mut queued, &Request::ping());
                    let response: std::io::Result<Response> =
                        howy_common::ipc::recv_message(&mut queued);
                    assert!(response.is_err(), "{boundary:?}");
                }
                let closed: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
                assert!(closed.is_err(), "{boundary:?}");
                let run_error = tokio::time::timeout(Duration::from_secs(1), server)
                    .await
                    .expect("fatal server run must not join the retained worker")
                    .unwrap()
                    .expect_err(&format!("{boundary:?} must fail-stop the daemon run"));
                assert!(run_error.to_string().contains("fail-stop"), "{boundary:?}");
                assert!(shutdown.is_fatal(), "{boundary:?}");
                assert_eq!(manager.counts(), (0, 0, 0), "{boundary:?}");
                assert_eq!(storage.promotion_calls.load(Ordering::SeqCst), 0);
                assert!(storage.budget.used() <= 64 * 1024, "{boundary:?}");
                assert_eq!(
                    admission.state_for_test(),
                    if matches!(boundary, Boundary::Snapshot) {
                        (false, 0)
                    } else {
                        (true, 0)
                    },
                    "{boundary:?}"
                );
                if matches!(
                    boundary,
                    Boundary::Start | Boundary::Frame | Boundary::Cleanup
                ) {
                    assert!(control.cancelled.load(Ordering::Acquire), "{boundary:?}");
                }
                gate.release();
                let release_deadline = Instant::now() + Duration::from_secs(1);
                while (admission.state_for_test() != (false, 0) || storage.budget.used() != 0)
                    && Instant::now() < release_deadline
                {
                    thread::sleep(Duration::from_millis(2));
                }
                assert_eq!(admission.state_for_test(), (false, 0), "{boundary:?}");
                assert_eq!(storage.budget.used(), 0, "{boundary:?}");
                assert_eq!(storage.promotion_calls.load(Ordering::SeqCst), 0);
            }
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn advertised_commit_timeout_is_exact_machine_ceiling_without_client_margin() {
        for (commit_to_camera_ms, scan_timeout_ms) in [(1_000, 2_000), (10_000, 30_000)] {
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            config.presence.commit_to_camera_ms = commit_to_camera_ms;
            config.presence.scan_timeout_ms = scan_timeout_ms;
            let manager = PromptTransactionManager::deterministic_for_test(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            );
            let connection = manager.new_connection().unwrap();
            let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
                unreachable!()
            };
            let pending = prepare_prompt_pending(
                0,
                connection,
                &config,
                &PromptCandidateBackend::new(),
                &manager,
                &begin,
            )
            .unwrap();
            let advertised = Duration::from_millis(u64::from(pending.commit_response_timeout_ms));
            assert_eq!(advertised, prompt_active_timeout(&config));
            assert!(
                pending.commit_response_timeout_ms
                    <= howy_common::protocol::COMMIT_RESPONSE_TIMEOUT_MS_MAX
            );
        }
    }

    #[test]
    fn active_poll_uses_strict_remaining_work_budget_and_allows_zero() {
        let now = Instant::now();
        assert_eq!(super::active_poll_timeout(now, now), Duration::ZERO);
        assert_eq!(
            super::active_poll_timeout(now, now + Duration::from_millis(3)),
            Duration::from_millis(3)
        );
        assert_eq!(
            super::active_poll_timeout(now, now + Duration::from_secs(1)),
            super::ACTIVE_SUPERVISOR_POLL
        );
    }

    #[test]
    fn real_coordinator_uses_opaque_tokens_and_activates_without_auth_camera_or_inference() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &worker_config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |pending| {
                    finish_prompt_commit_unavailable(
                        pending,
                        &worker_config,
                        worker_storage.as_ref(),
                    )
                },
            )
            .unwrap()
        });

        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let prompt: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
            panic!("expected prompt response")
        };
        assert_eq!(prompt.transaction_token.len(), PROMPT_TOKEN_BYTES);
        assert!(prompt.transaction_token.iter().any(|byte| *byte != 0));
        let mut token = [0u8; PROMPT_TOKEN_BYTES];
        token.copy_from_slice(&prompt.transaction_token);
        let mut nonce = [0u8; PROMPT_NONCE_BYTES];
        nonce.copy_from_slice(&prompt.client_nonce);
        howy_common::ipc::send_message(&mut client, &Request::commit_auth_v1(token, nonce))
            .unwrap();
        token.zeroize();
        nonce.zeroize();
        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::Error(error)) = response.result else {
            panic!("inactive authentication must return an error")
        };
        assert_eq!(error.code, howy_common::protocol::PROMPT_UNAVAILABLE_ERROR);
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 1);
        assert_eq!(storage.candidate_calls.load(Ordering::Relaxed), 2);
        assert_eq!(storage.auth_loads.load(Ordering::Relaxed), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn failed_prompt_write_immediately_releases_manager_reservation() {
        use std::net::Shutdown;

        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        client.shutdown(Shutdown::Both).unwrap();
        drop(client);

        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let result = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |_| panic!("failed prompt write cannot activate authentication"),
            )
        })
        .join()
        .unwrap();
        assert!(result.is_err());
        assert_eq!(manager.counts(), (0, 0, 0));
        assert_eq!(storage.auth_loads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn production_os_entropy_coordinator_cancel_is_nonzero_and_releases_capacity() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(
            PromptTransactionManager::production(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            )
            .unwrap(),
        );
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |_| panic!("cancel cannot start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let response = SensitivePromptResponse::new(
            howy_common::ipc::recv_prompt_message(&mut client).unwrap(),
        );
        let Some(RespResult::PromptRequiredV1(prompt)) = response.0.result.as_ref() else {
            panic!("expected prompt response")
        };
        assert!(prompt.transaction_token.iter().any(|byte| *byte != 0));
        let token: &[u8; PROMPT_TOKEN_BYTES] =
            prompt.transaction_token.as_slice().try_into().unwrap();
        let nonce: &[u8; PROMPT_NONCE_BYTES] = prompt.client_nonce.as_slice().try_into().unwrap();
        let cancel = SensitivePromptRequest::new(Request::cancel_auth_v1_ref(token, nonce));
        howy_common::ipc::send_prompt_message(&mut client, cancel.as_ref()).unwrap();
        drop(cancel);
        drop(response);
        let response = SensitivePromptResponse::new(
            howy_common::ipc::recv_prompt_message(&mut client).unwrap(),
        );
        assert!(matches!(
            response.0.result.as_ref(),
            Some(RespResult::AuthCancelledV1(_))
        ));
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 1);
        assert_eq!(storage.candidate_calls.load(Ordering::Relaxed), 1);
        assert_eq!(storage.auth_loads.load(Ordering::Relaxed), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn real_coordinator_pending_eof_releases_manager_capacity() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |_| panic!("EOF cannot start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let mut response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        zeroize_prompt_response(&mut response);
        drop(client);
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 0);
        assert_eq!(storage.auth_loads.load(Ordering::Relaxed), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn manager_shutdown_terminates_pending_absolute_deadline_read() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |_| panic!("shutdown cannot start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let mut response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        zeroize_prompt_response(&mut response);
        let activation_deadline = Instant::now() + Duration::from_secs(1);
        while manager.activated_pending_count() != 1 && Instant::now() < activation_deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(manager.activated_pending_count(), 1);
        manager.shutdown();
        let started = std::time::Instant::now();
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 0);
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn pending_absolute_timeout_releases_manager_capacity() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        config.presence.prompt_timeout_ms = 1_000;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let connection_id = manager.new_connection().unwrap();
        let storage = Arc::new(PromptCandidateBackend::new());
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker_manager = Arc::clone(&manager);
        let worker_storage = Arc::clone(&storage);
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    prepare_prompt_pending(
                        0,
                        connection_id,
                        &config,
                        worker_storage.as_ref(),
                        &worker_manager,
                        begin,
                    )
                },
                |_| panic!("timeout cannot start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let mut response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        zeroize_prompt_response(&mut response);
        let started = std::time::Instant::now();
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 0);
        assert!(started.elapsed() < Duration::from_millis(1_500));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn provisional_capacity_precedes_backend_io_and_manager_lock_is_not_held() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        config.presence.max_pending_per_uid = 1;
        config.presence.max_pending_global = 2;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let storage = Arc::new(PromptCandidateBackend::blocking(
            Arc::clone(&entered),
            Arc::clone(&release),
        ));
        let first_connection = manager.new_connection().unwrap();
        let first_manager = Arc::clone(&manager);
        let first_storage = Arc::clone(&storage);
        let first_config = config.clone();
        let Some(Cmd::BeginAuthV1(first_begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let worker = thread::spawn(move || {
            prepare_prompt_pending(
                0,
                first_connection,
                &first_config,
                first_storage.as_ref(),
                &first_manager,
                &first_begin,
            )
        });
        entered.wait();

        // The backend hook is blocked, but the manager mutex is free.
        let second_connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(second_begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        assert_eq!(
            prepare_prompt_pending(
                0,
                second_connection,
                &config,
                storage.as_ref(),
                &manager,
                &second_begin,
            ),
            Err(howy_common::protocol::PromptErrorCode::Unavailable)
        );
        assert_eq!(storage.candidate_calls.load(Ordering::Relaxed), 1);
        release.wait();
        drop(worker.join().unwrap().unwrap());
        assert_eq!(manager.counts(), (0, 0, 0));

        let absent_connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(absent_begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        assert_eq!(
            prepare_prompt_pending(
                0,
                absent_connection,
                &config,
                &HealthBackend(BackendHealth::Ready),
                &manager,
                &absent_begin,
            ),
            Err(howy_common::protocol::PromptErrorCode::Unavailable)
        );
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn expired_commit_is_rejected_before_nss_or_backend_revalidation() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        );
        let storage = PromptCandidateBackend::new();
        let connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let pending =
            prepare_prompt_pending(0, connection, &config, &storage, &manager, &begin).unwrap();
        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let mut machine = PromptConnectionMachine::new();
        assert!(matches!(
            machine.begin_with(&begin, |_| Ok(pending)),
            PromptConnectionAction::SendPrompt(_)
        ));
        machine.prompt_sent().unwrap();
        manager.expire_pending_for_test();
        assert!(matches!(
            machine.receive(&commit),
            PromptConnectionAction::SendTerminal(_)
        ));
        assert_eq!(storage.candidate_calls.load(Ordering::Relaxed), 1);
        assert_eq!(storage.auth_loads.load(Ordering::Relaxed), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn commit_backend_revalidation_runs_without_manager_lock() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        ));
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let storage = Arc::new(PromptCandidateBackend::blocking_on_commit(
            Arc::clone(&entered),
            Arc::clone(&release),
        ));
        let connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let pending =
            prepare_prompt_pending(0, connection, &config, storage.as_ref(), &manager, &begin)
                .unwrap();
        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending));
        machine.prompt_sent().unwrap();
        let PromptConnectionAction::StartAuthentication(pending) = machine.receive(&commit) else {
            panic!("matching commit must create a claim")
        };
        let worker_storage = Arc::clone(&storage);
        let worker_config = config.clone();
        let worker = thread::spawn(move || {
            finish_prompt_commit_unavailable(pending, &worker_config, worker_storage.as_ref())
        });
        entered.wait();

        let other_connection = manager.new_connection().unwrap();
        let reservation = manager
            .reserve_begin(
                other_connection,
                1001,
                crate::authorization::CanonicalIdentity::new("other", 1001),
            )
            .unwrap();
        drop(reservation);
        release.wait();
        let response = worker.join().unwrap();
        assert!(matches!(response.result, Some(RespResult::Error(_))));
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn production_prompt_coordinator_rejects_pending_mismatch_malformed_and_cross_phase() {
        let mut malformed =
            Request::commit_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]);
        let Some(Cmd::CommitAuthV1(commit)) = malformed.cmd.as_mut() else {
            unreachable!()
        };
        commit.client_nonce.pop();

        for (follow_up, expected_code, cancelled) in [
            (
                Request::commit_auth_v1([0x33; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]),
                Some(PROMPT_TRANSACTION_INVALID_ERROR),
                false,
            ),
            (
                Request::cancel_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x33; PROMPT_NONCE_BYTES]),
                Some(PROMPT_TRANSACTION_INVALID_ERROR),
                false,
            ),
            (malformed, Some(PROMPT_PROTOCOL_VIOLATION_ERROR), false),
            (
                Request::ping(),
                Some(PROMPT_PROTOCOL_VIOLATION_ERROR),
                false,
            ),
            (
                Request::cancel_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]),
                None,
                true,
            ),
        ] {
            let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
            let effects = Arc::new(PromptAuthEffects::default());
            let server_effects = Arc::clone(&effects);
            let worker = thread::spawn(move || {
                let mut io = ConnectionIo {
                    stream: server,
                    response_write_started: false,
                };
                coordinate_prompt_connection(
                    &mut io,
                    None,
                    |begin| {
                        authorize_prompt_begin(0, true, begin)?;
                        Ok(root_pending_prompt())
                    },
                    |_| server_effects.run(),
                )
                .unwrap()
            });
            howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
            let _: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            effects.assert_zero();
            howy_common::ipc::send_message(&mut client, &follow_up).unwrap();
            let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
            if cancelled {
                assert!(matches!(
                    response.result,
                    Some(RespResult::AuthCancelledV1(_))
                ));
            } else {
                let Some(RespResult::Error(error)) = response.result else {
                    panic!("expected protocol error")
                };
                assert_eq!(error.code, expected_code.unwrap());
            }
            effects.assert_zero();
            assert_eq!(
                worker.join().unwrap(),
                PromptCoordinatorReport {
                    prompt_response_attempts: 1,
                    terminal_response_attempts: 1,
                    authentication_started: false,
                }
            );
        }
    }

    #[test]
    fn production_prompt_coordinator_pending_eof_and_closed_state_write_no_extra_response() {
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    authorize_prompt_begin(0, true, begin)?;
                    Ok(root_pending_prompt())
                },
                |_| panic!("EOF must not start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let _: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        drop(client);
        assert_eq!(
            worker.join().unwrap(),
            PromptCoordinatorReport {
                prompt_response_attempts: 1,
                terminal_response_attempts: 0,
                authentication_started: false,
            }
        );

        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: server,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |_| Ok(root_pending_prompt()),
                |_| panic!("cancel must not start authentication"),
            )
            .unwrap()
        });
        howy_common::ipc::send_message(&mut client, &root_prompt_begin_request()).unwrap();
        let _: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let cancel =
            Request::cancel_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]);
        howy_common::ipc::send_message(&mut client, &cancel).unwrap();
        let _ = howy_common::ipc::send_message(&mut client, &cancel);
        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        assert!(matches!(
            response.result,
            Some(RespResult::AuthCancelledV1(_))
        ));
        let extra: std::io::Result<Response> = howy_common::ipc::recv_message(&mut client);
        assert!(extra.is_err());
        assert_eq!(worker.join().unwrap().terminal_response_attempts, 1);
    }

    #[test]
    fn prompt_connection_commit_consumes_pending_and_owns_one_final_response() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let mut machine = PromptConnectionMachine::new();
        assert!(matches!(
            machine.begin_with(&begin, |_| Ok(pending.clone())),
            PromptConnectionAction::SendPrompt(SensitivePromptResponse(Response {
                result: Some(RespResult::PromptRequiredV1(_))
            }))
        ));
        assert!(matches!(machine.phase, PromptConnectionPhase::Pending(_)));

        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        assert_eq!(
            machine.receive(&commit),
            PromptConnectionAction::StartAuthentication(pending)
        );
        assert_eq!(machine.phase, PromptConnectionPhase::Committed);

        let final_response = Response::success(0, "desk", 0.9, 12.0);
        assert_eq!(
            machine.finish_authentication(final_response.clone()),
            PromptConnectionAction::SendTerminal(SensitivePromptResponse::new(final_response))
        );
        assert_eq!(machine.phase, PromptConnectionPhase::Closed);
        assert_eq!(
            machine.finish_authentication(Response::auth_failed(0.1, 1, "late")),
            PromptConnectionAction::CloseWithoutResponse
        );
    }

    #[test]
    fn prompt_connection_cancel_is_pending_only_and_terminal() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending.clone()));
        let cancel = Request::cancel_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        assert!(matches!(
            machine.receive(&cancel),
            PromptConnectionAction::SendTerminal(SensitivePromptResponse(Response {
                result: Some(RespResult::AuthCancelledV1(_))
            }))
        ));
        assert_eq!(machine.phase, PromptConnectionPhase::Closed);
        assert_eq!(
            machine.receive(&cancel),
            PromptConnectionAction::CloseWithoutResponse
        );
    }

    #[test]
    fn prompt_connection_wrong_phases_and_duplicate_messages_fail_closed() {
        let begin = prompt_begin();
        let pending = pending_prompt();

        let mut initial = PromptConnectionMachine::new();
        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        assert_eq!(
            action_error_code(initial.receive(&commit)).as_deref(),
            Some(PROMPT_PROTOCOL_VIOLATION_ERROR)
        );

        let mut duplicate_begin = PromptConnectionMachine::new();
        duplicate_begin.begin_with(&begin, |_| Ok(pending.clone()));
        assert_eq!(
            action_error_code(duplicate_begin.begin_with(&begin, |_| Ok(pending.clone())))
                .as_deref(),
            Some(PROMPT_PROTOCOL_VIOLATION_ERROR)
        );

        let mut duplicate_commit = PromptConnectionMachine::new();
        duplicate_commit.begin_with(&begin, |_| Ok(pending.clone()));
        duplicate_commit.receive(&commit);
        assert!(matches!(
            duplicate_commit.receive(&commit),
            PromptConnectionAction::CancelActiveAndSendTerminal(_)
        ));
        assert_eq!(
            duplicate_commit.finish_authentication(Response::success(0, "desk", 0.9, 1.0)),
            PromptConnectionAction::CloseWithoutResponse
        );

        let mut cancel_after_commit = PromptConnectionMachine::new();
        cancel_after_commit.begin_with(&begin, |_| Ok(pending.clone()));
        cancel_after_commit.receive(&commit);
        let cancel = Request::cancel_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        assert!(matches!(
            cancel_after_commit.receive(&cancel),
            PromptConnectionAction::CancelActiveAndSendTerminal(_)
        ));
    }

    #[test]
    fn prompt_connection_malformed_and_mismatched_transactions_use_frozen_codes() {
        let begin = prompt_begin();
        let pending = pending_prompt();

        let mut malformed = PromptConnectionMachine::new();
        malformed.begin_with(&begin, |_| Ok(pending.clone()));
        let mut malformed_commit =
            Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let Some(Cmd::CommitAuthV1(commit)) = malformed_commit.cmd.as_mut() else {
            unreachable!()
        };
        commit.transaction_token.pop();
        assert_eq!(
            action_error_code(malformed.receive(&malformed_commit)).as_deref(),
            Some(PROMPT_PROTOCOL_VIOLATION_ERROR)
        );

        let mut unsupported = PromptConnectionMachine::new();
        unsupported.begin_with(&begin, |_| Ok(pending.clone()));
        let mut unsupported_commit =
            Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let Some(Cmd::CommitAuthV1(commit)) = unsupported_commit.cmd.as_mut() else {
            unreachable!()
        };
        commit.protocol_version += 1;
        assert_eq!(
            action_error_code(unsupported.receive(&unsupported_commit)).as_deref(),
            Some(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR)
        );

        let mut mismatch = PromptConnectionMachine::new();
        mismatch.begin_with(&begin, |_| Ok(pending.clone()));
        let mismatched = Request::commit_auth_v1_ref(&[0x33; 32], &pending.client_nonce);
        assert_eq!(
            action_error_code(mismatch.receive(&mismatched)).as_deref(),
            Some(PROMPT_TRANSACTION_INVALID_ERROR)
        );
    }

    #[test]
    fn prompt_connection_eof_releases_pending_and_cancels_committed_without_response() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let mut pending_machine = PromptConnectionMachine::new();
        pending_machine.begin_with(&begin, |_| Ok(pending.clone()));
        assert_eq!(
            pending_machine.eof(),
            PromptConnectionAction::CloseWithoutResponse
        );
        assert_eq!(pending_machine.phase, PromptConnectionPhase::Closed);

        let mut committed_machine = PromptConnectionMachine::new();
        committed_machine.begin_with(&begin, |_| Ok(pending.clone()));
        committed_machine.receive(&Request::commit_auth_v1_ref(
            &pending.transaction_token,
            &pending.client_nonce,
        ));
        assert_eq!(
            committed_machine.eof(),
            PromptConnectionAction::CancelActiveWithoutResponse
        );
        assert_eq!(committed_machine.phase, PromptConnectionPhase::Closed);
    }

    #[test]
    fn prompt_connection_rejects_extra_post_commit_frame_as_sole_terminal_attempt() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending.clone()));
        machine.receive(&Request::commit_auth_v1_ref(
            &pending.transaction_token,
            &pending.client_nonce,
        ));
        let action = machine.receive(&Request::ping());
        assert_eq!(
            action_error_code(action).as_deref(),
            Some(PROMPT_PROTOCOL_VIOLATION_ERROR)
        );
        assert_eq!(
            machine.finish_authentication(Response::success(0, "desk", 0.9, 1.0)),
            PromptConnectionAction::CloseWithoutResponse
        );
    }

    #[test]
    fn prompt_connection_rejects_nonterminal_commit_response() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending.clone()));
        machine.receive(&Request::commit_auth_v1_ref(
            &pending.transaction_token,
            &pending.client_nonce,
        ));
        assert_eq!(
            action_error_code(machine.finish_authentication(Response::credential_valid()))
                .as_deref(),
            Some(PROMPT_PROTOCOL_VIOLATION_ERROR)
        );
    }

    #[test]
    fn prompt_protocol_gates_preserve_one_shot_off_and_fail_closed_across_versions() {
        let request_triggered_auth_side_effects = AtomicUsize::new(0);
        assert!(
            initial_prompt_protocol_response(&Request::authenticate("alice", 0), false).is_none()
        );
        let old_client_response =
            initial_prompt_protocol_response(&Request::authenticate("alice", 0), true);
        if old_client_response.is_none() {
            request_triggered_auth_side_effects.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(
            action_error_code(PromptConnectionAction::SendTerminal(
                SensitivePromptResponse::new(old_client_response.unwrap()),
            ))
            .as_deref(),
            Some(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR)
        );
        assert_eq!(
            request_triggered_auth_side_effects.load(Ordering::Relaxed),
            0
        );

        let versioned_confirm =
            initial_prompt_protocol_response(&Request::authenticate_v1("alice", 0), true).unwrap();
        let Some(RespResult::Error(error)) = versioned_confirm.result else {
            unreachable!()
        };
        assert_eq!(error.code, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR);
        assert!(
            initial_prompt_protocol_response(&Request::authenticate_v1("alice", 0), false)
                .is_none()
        );

        let begin = Request {
            cmd: Some(Cmd::BeginAuthV1(prompt_begin())),
        };
        assert_eq!(
            action_error_code(PromptConnectionAction::SendTerminal(
                SensitivePromptResponse::new(
                    initial_prompt_protocol_response(&begin, false).unwrap(),
                ),
            ))
            .as_deref(),
            Some(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR)
        );
        assert!(initial_prompt_protocol_response(&begin, true).is_none());
    }

    #[test]
    fn authenticate_v1_rechecks_current_mode_immediately_before_one_shot_side_effects() {
        let Some(Cmd::AuthenticateV1(request)) = Request::authenticate_v1("alice", 7).cmd else {
            unreachable!()
        };
        let events = std::cell::RefCell::new(Vec::new());
        let response = dispatch_authenticate_v1_with(
            &request,
            || {
                events.borrow_mut().push("mode");
                false
            },
            |request| {
                events.borrow_mut().push("auth");
                assert_eq!(request.timeout, 7);
                Response::auth_failed(0.0, 0, "test")
            },
        );
        assert!(matches!(response.result, Some(RespResult::AuthFailed(_))));
        assert_eq!(&*events.borrow(), &["mode", "auth"]);

        let side_effects = AtomicUsize::new(0);
        let preflight_prompt_required = false;
        assert!(!preflight_prompt_required);
        let response = dispatch_authenticate_v1_with(
            &request,
            || true,
            |_| {
                side_effects.fetch_add(1, Ordering::Relaxed);
                Response::error("must not run")
            },
        );
        let Some(RespResult::Error(error)) = response.result else {
            panic!("mode change must fail closed")
        };
        assert_eq!(error.code, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR);
        assert_eq!(side_effects.load(Ordering::Relaxed), 0);

        let mut unsupported = request;
        unsupported.protocol_version += 1;
        let response = initial_prompt_protocol_response(
            &Request {
                cmd: Some(Cmd::AuthenticateV1(unsupported)),
            },
            false,
        )
        .unwrap();
        let Some(RespResult::Error(error)) = response.result else {
            unreachable!()
        };
        assert_eq!(error.code, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR);
    }

    #[test]
    fn prompt_policy_enforces_exact_allowlist_and_locality_matrix() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = howy_common::config::PresenceMode::Confirm;
        config.presence.allowed_pam_services = vec!["sudo".into(), "login".into()];
        let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        assert!(validate_prompt_begin_policy(&config, &begin).is_ok());
        for rejected in ["Sudo", "SUDO", "other"] {
            let mut request = begin.clone();
            request.policy.as_mut().unwrap().pam_service = rejected.into();
            assert_eq!(
                validate_prompt_begin_policy(&config, &request),
                Err(howy_common::protocol::PromptErrorCode::Unavailable)
            );
        }
        let mut malformed_service = begin.clone();
        malformed_service.policy.as_mut().unwrap().pam_service = "sudo ".into();
        assert_eq!(
            validate_prompt_begin_policy(&config, &malformed_service),
            Err(howy_common::protocol::PromptErrorCode::Violation)
        );
        let mut remote = begin.clone();
        remote.policy.as_mut().unwrap().origin = PromptOriginV1::Remote as i32;
        assert_eq!(
            validate_prompt_begin_policy(&config, &remote),
            Err(howy_common::protocol::PromptErrorCode::Unavailable)
        );

        config.presence.local_only = false;
        assert!(validate_prompt_begin_policy(&config, &remote).is_ok());
        remote.policy.as_mut().unwrap().pam_service = "login".into();
        assert!(validate_prompt_begin_policy(&config, &remote).is_ok());
        remote.policy.as_mut().unwrap().pam_service = "sshd".into();
        assert_eq!(
            validate_prompt_begin_policy(&config, &remote),
            Err(howy_common::protocol::PromptErrorCode::Unavailable)
        );
        assert_eq!(
            validate_current_prompt_policy(&config, "sudo", PromptOriginV1::Unspecified),
            Err(howy_common::protocol::PromptErrorCode::Unavailable)
        );
    }

    #[test]
    fn real_framed_remote_policy_rejection_is_terminal_before_auth_handoff() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        config.presence.local_only = true;
        let (mut client, daemon) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut io = ConnectionIo {
                stream: daemon,
                response_write_started: false,
            };
            coordinate_prompt_connection(
                &mut io,
                None,
                |begin| {
                    validate_prompt_begin_policy(&config, begin)?;
                    Ok(pending_prompt())
                },
                |_| panic!("rejected policy must not start auth/camera work"),
            )
            .unwrap()
        });
        let request = Request::begin_auth_v1(
            "alice",
            [0x11; PROMPT_NONCE_BYTES],
            "sudo",
            PromptOriginV1::Remote,
        );
        howy_common::ipc::send_message(&mut client, &request).unwrap();
        let response: Response = howy_common::ipc::recv_message(&mut client).unwrap();
        let Some(RespResult::Error(error)) = response.result else {
            panic!("policy rejection must return a generic prompt error")
        };
        assert_eq!(error.code, PROMPT_UNAVAILABLE_ERROR);
        let report = server.join().unwrap();
        assert!(!report.authentication_started);
        assert_eq!(report.prompt_response_attempts, 0);
        assert_eq!(report.terminal_response_attempts, 1);
    }

    #[test]
    fn service_removal_between_begin_and_commit_fails_before_authentication() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        let manager = PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        );
        let storage = PromptCandidateBackend::new();
        let connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let pending =
            prepare_prompt_pending(0, connection, &config, &storage, &manager, &begin).unwrap();
        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending));
        machine.prompt_sent().unwrap();
        let PromptConnectionAction::StartAuthentication(pending) = machine.receive(&commit) else {
            panic!("valid commit must reach policy revalidation")
        };

        let mut changed = config.clone();
        changed.presence.allowed_pam_services = vec!["login".into()];
        let response = finish_prompt_commit_with(pending, &changed, &storage, |_| {
            panic!("removed service must fail before active auth/camera handoff")
        });
        let Some(RespResult::Error(error)) = response.result else {
            panic!("policy change must return a generic prompt error")
        };
        assert_eq!(error.code, PROMPT_TRANSACTION_INVALID_ERROR);
        assert_eq!(storage.auth_loads.load(Ordering::SeqCst), 0);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn allowlisted_service_is_client_supplied_and_not_same_uid_attestation() {
        let config = howy_common::config::HowyConfig::default();
        // Both a genuine PAM module and a malicious same-UID socket client can
        // supply this identical value. This test intentionally claims only
        // allowlist enforcement; service identity is not daemon-attested.
        assert!(validate_current_prompt_policy(&config, "sudo", PromptOriginV1::Local).is_ok());
    }

    #[test]
    fn every_prompt_request_and_response_shape_has_complete_sensitive_cleanup() {
        let mut requests = vec![
            root_prompt_begin_request(),
            Request::commit_auth_v1([0x22; 32], [0x11; 32]),
            Request::cancel_auth_v1([0x22; 32], [0x11; 32]),
        ];
        for request in &mut requests {
            zeroize_prompt_request(request);
            assert!(prompt_request_fields_are_zero(request));
        }
        let mut responses = vec![
            Response::prompt_required_v1([0x22; 32], [0x11; 32], 30_000, 10_000),
            Response::auth_cancelled_v1([0x11; 32]),
        ];
        for response in &mut responses {
            zeroize_prompt_response(response);
            assert!(prompt_response_fields_are_zero(response));
        }
    }

    #[test]
    fn prompt_state_machine_runs_no_auth_camera_or_inference_hook_before_commit() {
        let begin = prompt_begin();
        let pending = pending_prompt();
        let auth_load = AtomicUsize::new(0);
        let camera = AtomicUsize::new(0);
        let inference = AtomicUsize::new(0);
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending.clone()));
        assert_eq!(auth_load.load(Ordering::Relaxed), 0);
        assert_eq!(camera.load(Ordering::Relaxed), 0);
        assert_eq!(inference.load(Ordering::Relaxed), 0);

        let action = machine.receive(&Request::commit_auth_v1_ref(
            &pending.transaction_token,
            &pending.client_nonce,
        ));
        if matches!(action, PromptConnectionAction::StartAuthentication(_)) {
            auth_load.fetch_add(1, Ordering::Relaxed);
            camera.fetch_add(1, Ordering::Relaxed);
            inference.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(auth_load.load(Ordering::Relaxed), 1);
        assert_eq!(camera.load(Ordering::Relaxed), 1);
        assert_eq!(inference.load(Ordering::Relaxed), 1);
    }

    struct HealthBackend(BackendHealth);

    impl StorageBackend for HealthBackend {
        fn prompt_snapshot(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<PromptStorageSnapshot, StorageBackendError> {
            Ok(PromptStorageSnapshot::new(
                self.0,
                CandidatePresence::Absent,
                PromptOpaqueIdentity::new([0x41; 32]),
                PromptOpaqueIdentity::new([0x42; 32]),
            ))
        }

        fn candidate_presence(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<CandidatePresence, StorageBackendError> {
            Err(match self.0 {
                BackendHealth::Ready => StorageBackendError::Corrupt,
                BackendHealth::Unavailable(_) => StorageBackendError::Unavailable,
            })
        }

        fn authenticate(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<ModelLease, StorageBackendError> {
            unimplemented!()
        }

        fn list_metadata(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            unimplemented!()
        }

        fn append(&self, _request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
            unimplemented!()
        }

        fn admit_enrollment(
            &self,
            _username: &CanonicalUsername,
            _plaintext_bytes: usize,
            _append_shape: AppendAdmissionShape,
        ) -> Result<EnrollmentAdmission, StorageBackendError> {
            unimplemented!()
        }

        fn append_admitted(
            &self,
            _request: AppendRequest<'_>,
            _operation: BudgetPermit,
        ) -> Result<AppendResult, StorageBackendError> {
            unimplemented!()
        }

        fn remove(&self, _request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
            unimplemented!()
        }

        fn clear(&self, _request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
            unimplemented!()
        }

        fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
            unimplemented!()
        }

        fn health(&self) -> BackendHealth {
            self.0
        }

        fn verify_record(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            unimplemented!()
        }
    }

    #[test]
    fn authorization_current_request_mapping_is_exhaustive() {
        let requests = [
            (
                Request::authenticate("alice", 1),
                Operation::Authenticate { target: "alice" },
            ),
            (
                Request::authenticate_v1("alice", 1),
                Operation::Authenticate { target: "alice" },
            ),
            (
                Request {
                    cmd: Some(Cmd::BeginAuthV1(prompt_begin())),
                },
                Operation::BeginAuth { target: "alice" },
            ),
            (
                Request::commit_auth_v1([2; PROMPT_TOKEN_BYTES], [1; PROMPT_NONCE_BYTES]),
                Operation::CommitAuth,
            ),
            (
                Request::cancel_auth_v1([2; PROMPT_TOKEN_BYTES], [1; PROMPT_NONCE_BYTES]),
                Operation::CancelAuth,
            ),
            (
                Request::enroll("alice", "label"),
                Operation::Enroll { target: "alice" },
            ),
            (
                Request::enroll_batch("alice", "/session", "label"),
                Operation::EnrollBatch { target: "alice" },
            ),
            (
                Request::enrollment_presence("alice"),
                Operation::EnrollmentPresence { target: "alice" },
            ),
            (
                Request::list_enrollments("alice"),
                Operation::ListEnrollments { target: "alice" },
            ),
            (
                Request::remove_enrollment("alice", vec![1; 16], 1),
                Operation::RemoveEnrollment { target: "alice" },
            ),
            (
                Request::clear_enrollments("alice", 1),
                Operation::ClearEnrollments { target: "alice" },
            ),
            (Request::reload_storage(), Operation::Reload),
            (Request::security_info(), Operation::SecurityInfo),
            (
                Request {
                    cmd: Some(Cmd::Detect(DetectReq {
                        frame: Vec::new(),
                        height: 0,
                        width: 0,
                    })),
                },
                Operation::Detect,
            ),
            (Request::ping(), Operation::Ping),
            (Request::info(), Operation::PublicInfo),
            (Request::shutdown(), Operation::Shutdown),
            (
                Request::check_credential("alice"),
                Operation::CheckCredential { target: "alice" },
            ),
            (
                Request::revoke_credential("alice", "selector-only"),
                Operation::RevokeCredential { target: "alice" },
            ),
            (Request { cmd: None }, Operation::Unknown),
        ];

        for (request, expected) in requests {
            assert_eq!(current_operation(&request), expected);
        }
    }

    #[test]
    fn public_storage_status_uses_backend_health() {
        assert!(active_storage_ready(&HealthBackend(BackendHealth::Ready)));
        assert!(!active_storage_ready(&HealthBackend(
            BackendHealth::Unavailable(BackendUnavailable::NotInitialized)
        )));
    }

    #[test]
    fn root_security_info_marks_mode1_implemented_and_mode2_unimplemented() {
        let mut config = howy_common::config::HowyConfig::default();
        config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
        let response = handle_security_info(
            &RunnerInference,
            &config,
            &HealthBackend(BackendHealth::Ready),
            &DaemonRuntimeIdentity {
                config_sha256: "1".repeat(64),
                credential_name: Some("howy.storage.mode1.epoch1".to_owned()),
                configured_credential_source: Some(
                    "/etc/credstore.encrypted/howy.storage.mode1.epoch1".to_owned(),
                ),
                invocation_id: "2".repeat(64),
                daemon_version: "0.1.0".to_owned(),
                build_identity: "howy-0.1.0+test".to_owned(),
                binary_absolute_path: "/usr/bin/howyd".to_owned(),
                binary_sha256: "3".repeat(64),
            },
        );
        let Some(RespResult::SecurityInfo(info)) = response.result else {
            panic!("expected root security diagnostics")
        };
        let mode0 = info.namespaces.iter().find(|item| item.mode == 0).unwrap();
        let mode1 = info.namespaces.iter().find(|item| item.mode == 1).unwrap();
        let mode2 = info.namespaces.iter().find(|item| item.mode == 2).unwrap();
        assert!(mode0.implemented);
        assert!(mode1.implemented);
        assert!(mode1.active);
        assert!(!mode2.implemented);
        assert!(!mode2.active);
        assert_eq!(info.config_sha256, "1".repeat(64));
        assert_eq!(info.credential_name, "howy.storage.mode1.epoch1");
        assert_eq!(
            info.configured_credential_source,
            "/etc/credstore.encrypted/howy.storage.mode1.epoch1"
        );
        assert_eq!(
            info.backend_state,
            protocol::SecurityBackendStateV1::Ready as i32
        );
        assert_eq!(
            info.readiness_state,
            protocol::SecurityReadinessStateV1::Ready as i32
        );
        assert_eq!(
            info.poison_state,
            protocol::SecurityPoisonStateV1::NotPoisoned as i32
        );
        assert_eq!(info.daemon_invocation_id, "2".repeat(64));
        assert_eq!(info.binary_sha256, "3".repeat(64));
    }

    #[test]
    fn root_security_info_reports_mode0_without_credential_source_and_live_poison_state() {
        let config = howy_common::config::HowyConfig::default();
        let identity = DaemonRuntimeIdentity::harness_placeholder();
        let response = handle_security_info(
            &RunnerInference,
            &config,
            &HealthBackend(BackendHealth::Ready),
            &identity,
        );
        let Some(RespResult::SecurityInfo(info)) = response.result else {
            panic!("expected root security diagnostics")
        };
        assert!(info.credential_name.is_empty());
        assert!(info.configured_credential_source.is_empty());

        let mut mode1 = config;
        mode1.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
        let identity = DaemonRuntimeIdentity {
            credential_name: Some("howy.storage.mode1.epoch1".to_owned()),
            configured_credential_source: Some(
                "/etc/credstore.encrypted/howy.storage.mode1.epoch1".to_owned(),
            ),
            ..identity
        };
        let response = handle_security_info(
            &RunnerInference,
            &mode1,
            &HealthBackend(BackendHealth::Unavailable(BackendUnavailable::Integrity)),
            &identity,
        );
        let Some(RespResult::SecurityInfo(info)) = response.result else {
            panic!("expected root security diagnostics")
        };
        assert_eq!(
            info.poison_state,
            protocol::SecurityPoisonStateV1::Poisoned as i32
        );
        assert_eq!(
            info.backend_state,
            protocol::SecurityBackendStateV1::Unavailable as i32
        );
    }

    #[test]
    fn malformed_mutations_fail_before_the_backend_is_called() {
        let backend = HealthBackend(BackendHealth::Ready);
        for response in [
            handle_remove_enrollment(&backend, "alice", &[1; 15], 1),
            handle_remove_enrollment(&backend, "alice", &[0; 16], 1),
            handle_remove_enrollment(&backend, "alice", &[1; 16], 0),
            handle_clear_enrollments(&backend, "alice", 0),
        ] {
            let Some(RespResult::Error(error)) = response.result else {
                panic!("expected stable invalid-request error");
            };
            assert_eq!(error.code, STORAGE_INVALID_REQUEST_ERROR);
        }
    }

    #[test]
    fn backend_failures_have_stable_non_sensitive_response_codes() {
        for (backend_error, expected_code) in [
            (StorageBackendError::Corrupt, STORAGE_CORRUPT_ERROR),
            (
                StorageBackendError::ModelMismatch,
                STORAGE_MODEL_MISMATCH_ERROR,
            ),
            (StorageBackendError::Unavailable, STORAGE_UNAVAILABLE_ERROR),
        ] {
            let response = storage_error_response(backend_error);
            let Some(RespResult::Error(error)) = response.result else {
                panic!("expected error response");
            };
            assert_eq!(error.code, expected_code);
            assert!(!error.message.contains("/etc"));
            assert!(!error.message.contains("alice"));
        }
    }

    struct AdmissionRejectingBackend {
        admissions: AtomicUsize,
        mutations: AtomicUsize,
        requested_bytes: AtomicUsize,
    }

    impl AdmissionRejectingBackend {
        fn new() -> Self {
            Self {
                admissions: AtomicUsize::new(0),
                mutations: AtomicUsize::new(0),
                requested_bytes: AtomicUsize::new(0),
            }
        }
    }

    impl StorageBackend for AdmissionRejectingBackend {
        fn prompt_snapshot(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<PromptStorageSnapshot, StorageBackendError> {
            Err(StorageBackendError::Unavailable)
        }

        fn candidate_presence(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<CandidatePresence, StorageBackendError> {
            unimplemented!()
        }

        fn authenticate(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<ModelLease, StorageBackendError> {
            unimplemented!()
        }

        fn list_metadata(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            Err(StorageBackendError::Absent)
        }

        fn append(&self, _request: AppendRequest<'_>) -> Result<AppendResult, StorageBackendError> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err(StorageBackendError::Unavailable)
        }

        fn admit_enrollment(
            &self,
            _username: &CanonicalUsername,
            plaintext_bytes: usize,
            _append_shape: AppendAdmissionShape,
        ) -> Result<EnrollmentAdmission, StorageBackendError> {
            self.admissions.fetch_add(1, Ordering::Relaxed);
            self.requested_bytes
                .store(plaintext_bytes, Ordering::Relaxed);
            Err(StorageBackendError::MemoryBudgetExceeded {
                requested: 1,
                available: 0,
            })
        }

        fn append_admitted(
            &self,
            _request: AppendRequest<'_>,
            _operation: BudgetPermit,
        ) -> Result<AppendResult, StorageBackendError> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err(StorageBackendError::Unavailable)
        }

        fn remove(&self, _request: RemoveRequest<'_>) -> Result<RemoveResult, StorageBackendError> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err(StorageBackendError::Unavailable)
        }

        fn clear(&self, _request: ClearRequest<'_>) -> Result<ClearResult, StorageBackendError> {
            self.mutations.fetch_add(1, Ordering::Relaxed);
            Err(StorageBackendError::Unavailable)
        }

        fn reload(&self) -> Result<ReloadResult, StorageBackendError> {
            unimplemented!()
        }

        fn health(&self) -> BackendHealth {
            BackendHealth::Ready
        }

        fn verify_record(
            &self,
            _username: &CanonicalUsername,
        ) -> Result<MetadataList, StorageBackendError> {
            unimplemented!()
        }
    }

    #[derive(Default)]
    struct EnrollmentEffects {
        camera: AtomicUsize,
        directory: AtomicUsize,
        inference: AtomicUsize,
    }

    impl EnrollmentEffects {
        fn assert_zero(&self) {
            assert_eq!(self.camera.load(Ordering::Relaxed), 0);
            assert_eq!(self.directory.load(Ordering::Relaxed), 0);
            assert_eq!(self.inference.load(Ordering::Relaxed), 0);
        }

        fn mark_all(&self) -> Response {
            self.camera.fetch_add(1, Ordering::Relaxed);
            self.directory.fetch_add(1, Ordering::Relaxed);
            self.inference.fetch_add(1, Ordering::Relaxed);
            Response::error("unexpected enrollment side effect")
        }
    }

    #[test]
    fn dispatch_rejects_legacy_live_and_batch_before_all_side_effects() {
        let backend = AdmissionRejectingBackend::new();
        let effects = EnrollmentEffects::default();
        let legacy_live = Cmd::Enroll(EnrollReq {
            username: "alice".into(),
            label: "desk".into(),
        });
        let response = dispatch_authorized_enrollment(
            Some(&legacy_live),
            "alice",
            |_, _| effects.mark_all(),
            |_, _| effects.mark_all(),
        )
        .unwrap();
        let Some(RespResult::Error(error)) = response.result else {
            panic!("expected protocol error");
        };
        assert_eq!(error.code, ENROLLMENT_PROTOCOL_ERROR);

        let legacy_batch = Cmd::EnrollBatch(EnrollBatchReq {
            username: "alice".into(),
            session_dir: "/session".into(),
            label: "desk".into(),
        });
        let response = dispatch_authorized_enrollment(
            Some(&legacy_batch),
            "alice",
            |_, _| effects.mark_all(),
            |_, _| effects.mark_all(),
        )
        .unwrap();
        let Some(RespResult::Error(error)) = response.result else {
            panic!("expected protocol error");
        };
        assert_eq!(error.code, ENROLLMENT_PROTOCOL_ERROR);
        assert_eq!(backend.admissions.load(Ordering::Relaxed), 0);
        assert_eq!(backend.mutations.load(Ordering::Relaxed), 0);
        effects.assert_zero();
    }

    #[test]
    fn dispatch_failed_admission_stops_live_and_batch_before_downstream_effects() {
        for request in [
            Request::enroll("alice", "desk"),
            Request::enroll_batch("alice", "/must-not-open", "desk"),
        ] {
            let expected_reservation = match request.cmd.as_ref() {
                Some(Cmd::EnrollV1(_)) => live_enrollment_plaintext_bytes(4, 1).unwrap(),
                Some(Cmd::EnrollBatchV1(_)) => batch_enrollment_plaintext_bytes(4).unwrap(),
                _ => unreachable!(),
            };
            let backend = AdmissionRejectingBackend::new();
            let effects = EnrollmentEffects::default();
            let response = dispatch_authorized_enrollment(
                request.cmd.as_ref(),
                "alice",
                |request, username| {
                    handle_live_enrollment_with(
                        &backend,
                        username,
                        &request.label,
                        1,
                        |_, _, _, _| effects.mark_all(),
                    )
                },
                |request, username| {
                    handle_batch_enrollment_with(
                        &backend,
                        username,
                        &request.label,
                        |_, _, _, _| effects.mark_all(),
                    )
                },
            )
            .unwrap();
            let Some(RespResult::Error(error)) = response.result else {
                panic!("expected admission error");
            };
            assert_eq!(error.code, STORAGE_UNAVAILABLE_ERROR);
            assert_eq!(backend.admissions.load(Ordering::Relaxed), 1);
            assert_eq!(
                backend.requested_bytes.load(Ordering::Relaxed),
                expected_reservation
            );
            assert_eq!(backend.mutations.load(Ordering::Relaxed), 0);
            effects.assert_zero();
        }
    }

    #[test]
    fn presence_collapses_record_failures_to_generic_unavailable() {
        let response = handle_enrollment_presence(&HealthBackend(BackendHealth::Ready), "alice");
        let Some(RespResult::Error(error)) = response.result else {
            panic!("expected generic presence error");
        };
        assert_eq!(error.code, STORAGE_UNAVAILABLE_ERROR);
        assert!(!error.message.contains("corrupt"));
    }

    #[test]
    fn batch_images_remain_descriptor_bound_through_bounded_decode() {
        let directory = temp_directory("batch-fd");
        let image_path = directory.join("frame.bmp");
        std::fs::write(&image_path, one_pixel_bmp()).unwrap();
        let mut files = open_batch_images(&directory).unwrap();
        assert_eq!(files.len(), 1);

        std::fs::remove_file(&image_path).unwrap();
        std::fs::write(&image_path, b"replacement").unwrap();
        let admitted = files[0].read_and_inspect().unwrap();
        let (bgr, width, height) = decode_image_as_bgr(&admitted).unwrap();
        assert_eq!((width, height), (1, 1));
        assert_eq!(bgr.len(), 3);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn batch_directory_and_image_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = temp_directory("batch-links");
        let linked_directory = directory.with_extension("link");
        symlink(&directory, &linked_directory).unwrap();
        assert!(open_batch_images(&linked_directory).is_err());

        let target = directory.join("target.bmp");
        std::fs::write(&target, one_pixel_bmp()).unwrap();
        symlink(&target, directory.join("frame.bmp")).unwrap();
        assert!(open_batch_images(&directory).is_err());

        std::fs::remove_file(linked_directory).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn batch_session_path_policy_rejects_ambiguous_components_and_all_symlinks() {
        use std::os::unix::fs::symlink;

        let parent = temp_directory("batch-walk");
        let real = parent.join("real");
        let session = real.join("session");
        std::fs::create_dir_all(&session).unwrap();
        assert!(open_absolute_directory_nofollow(&session).is_ok());

        assert!(
            open_absolute_directory_nofollow(std::path::Path::new("relative/session")).is_err()
        );
        assert!(open_absolute_directory_nofollow(std::path::Path::new("/")).is_err());
        assert!(open_absolute_directory_nofollow(&real.join("./session")).is_err());
        assert!(open_absolute_directory_nofollow(&session.join("../session")).is_err());

        let repeated = format!("{}//session", real.display());
        assert!(open_absolute_directory_nofollow(std::path::Path::new(&repeated)).is_err());
        let trailing = format!("{}/", session.display());
        assert!(open_absolute_directory_nofollow(std::path::Path::new(&trailing)).is_err());

        let intermediate = parent.join("linked");
        symlink(&real, &intermediate).unwrap();
        assert!(open_absolute_directory_nofollow(&intermediate.join("session")).is_err());
        let final_link = real.join("linked-session");
        symlink(&session, &final_link).unwrap();
        assert!(open_absolute_directory_nofollow(&final_link).is_err());

        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn batch_encoded_and_dimension_limits_fail_before_decode() {
        let directory = temp_directory("batch-limits");
        let oversized = directory.join("oversized.bmp");
        let file = std::fs::File::create(&oversized).unwrap();
        file.set_len(super::MAX_BATCH_ENCODED_BYTES_PER_FILE + 1)
            .unwrap();
        assert!(open_batch_images(&directory).is_err());
        std::fs::remove_file(oversized).unwrap();

        let mut bmp = one_pixel_bmp();
        bmp[18..22].copy_from_slice(&(super::MAX_BATCH_IMAGE_WIDTH + 1).to_le_bytes());
        std::fs::write(directory.join("wide.bmp"), bmp).unwrap();
        let mut files = open_batch_images(&directory).unwrap();
        assert!(files[0].read_and_inspect().is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn batch_decode_is_single_pre_admitted_zeroizing_bgr_allocation() {
        let directory = temp_directory("batch-accounting");
        std::fs::write(directory.join("frame.bmp"), one_pixel_bmp()).unwrap();
        let mut files = open_batch_images(&directory).unwrap();
        let admitted = files[0].read_and_inspect().unwrap();
        assert_eq!(admitted.decoded_bytes, 3);
        let (pixels, width, height) = decode_image_as_bgr(&admitted).unwrap();
        assert_eq!((width, height), (1, 1));
        assert_eq!(&pixels[..], &[0xff, 0x00, 0x00]);

        std::fs::write(directory.join("ignored.png"), b"compressed input").unwrap();
        assert_eq!(open_batch_images(&directory).unwrap().len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn daemon_accepts_only_canonical_importer_bmp_representation() {
        let canonical = one_pixel_bmp();
        assert!(super::inspect_strict_bmp(&canonical).is_ok());

        let mut top_down = canonical.clone();
        top_down[22..26].copy_from_slice(&(-1i32).to_le_bytes());
        assert!(super::inspect_strict_bmp(&top_down).is_err());

        let mut offset_gap = canonical.clone();
        offset_gap[10..14].copy_from_slice(&55u32.to_le_bytes());
        assert!(super::inspect_strict_bmp(&offset_gap).is_err());

        let mut zero_image_size = canonical.clone();
        zero_image_size[34..38].copy_from_slice(&0u32.to_le_bytes());
        assert!(super::inspect_strict_bmp(&zero_image_size).is_err());

        let mut wrong_image_size = canonical.clone();
        wrong_image_size[34..38].copy_from_slice(&3u32.to_le_bytes());
        assert!(super::inspect_strict_bmp(&wrong_image_size).is_err());

        let mut nonzero_padding = canonical.clone();
        nonzero_padding[57] = 1;
        assert!(super::inspect_strict_bmp(&nonzero_padding).is_err());

        for offset in [6usize, 38, 42, 46, 50] {
            let mut malformed = canonical.clone();
            malformed[offset] = 1;
            assert!(super::inspect_strict_bmp(&malformed).is_err());
        }

        let mut trailing = canonical;
        trailing.push(0);
        let trailing_len = trailing.len() as u32;
        trailing[2..6].copy_from_slice(&trailing_len.to_le_bytes());
        assert!(super::inspect_strict_bmp(&trailing).is_err());
    }

    #[test]
    fn enrollment_peak_reservations_cover_camera_and_batch_sensitive_ownership() {
        let scratch = crate::inference::inference_plaintext_scratch_bytes(640, 640).unwrap();
        let pipeline = CameraProfile::test_profile("normal")
            .live_pipeline_bytes(scratch)
            .unwrap();
        let live = live_enrollment_plaintext_bytes(4, pipeline).unwrap();
        assert!(live >= pipeline);

        let batch = batch_enrollment_plaintext_bytes(4).unwrap();
        assert!(batch >= super::MAX_BATCH_TOTAL_ENCODED_BYTES as usize);
        assert!(batch >= super::MAX_BATCH_DECODED_BYTES_PER_FILE);
        assert!(
            batch
                >= super::MAX_BATCH_TOTAL_ENCODED_BYTES as usize
                    + super::MAX_BATCH_DECODED_BYTES_PER_FILE
        );

        let mut oversized = one_pixel_bmp();
        oversized[18..22].copy_from_slice(&super::MAX_BATCH_IMAGE_WIDTH.to_le_bytes());
        oversized[22..26].copy_from_slice(&super::MAX_BATCH_IMAGE_HEIGHT.to_le_bytes());
        assert!(
            super::inspect_strict_bmp(&oversized)
                .unwrap_err()
                .contains("decoded image bytes")
        );
    }

    #[test]
    fn default_and_explicit_128_mib_budgets_admit_normal_live_and_batch_peaks() {
        let config = howy_common::config::HowyConfig::default();
        assert_eq!(config.security.max_plaintext_bytes, 128 * 1024 * 1024);
        let operation = PlaintextAllocationEstimate::for_plaintext_limits(
            usize::try_from(config.security.max_record_bytes).unwrap(),
            usize::try_from(config.security.max_embeddings_per_user).unwrap(),
        )
        .unwrap()
        .peak_bytes();
        let scratch = crate::inference::inference_plaintext_scratch_bytes(
            config.ml.det_width,
            config.ml.det_height,
        )
        .unwrap();
        let live_profiles = [
            CameraProfile::test_grey_profile(4094, 2732),
            CameraProfile::test_yuyv_profile(4094, 2732),
            CameraProfile::test_mjpeg_profile(1920, 1080, 16 * 1024 * 1024),
        ];
        let live = live_profiles
            .iter()
            .map(|profile| {
                live_enrollment_plaintext_bytes(
                    howy_common::storage::MAX_LABEL_BYTES,
                    profile.live_pipeline_bytes(scratch).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let batch =
            batch_enrollment_plaintext_bytes(howy_common::storage::MAX_LABEL_BYTES).unwrap();
        assert_eq!(scratch, 9_047_328);
        assert_eq!(operation, 10_501_760);
        assert_eq!(live, [53_793_000, 120_901_848, 98_783_816]);
        assert_eq!(
            live.iter().map(|live| operation + live).collect::<Vec<_>>(),
            [64_294_760, 131_403_608, 109_285_576]
        );
        assert_eq!(operation + batch, 111_767_168);
        for limit in [config.security.max_plaintext_bytes, 128 * 1024 * 1024] {
            let budget = PlaintextBudget::new(usize::try_from(limit).unwrap()).unwrap();
            for live in &live {
                drop(budget.reserve_enrollment(operation, *live).unwrap());
            }
            drop(budget.reserve_enrollment(operation, batch).unwrap());
        }
        assert!(
            live.iter()
                .all(|live| operation + live <= 128 * 1024 * 1024)
        );
        assert!(operation + batch <= 128 * 1024 * 1024);

        assert!(
            CameraProfile::test_yuyv_profile(4097, 4096)
                .live_pipeline_bytes(scratch)
                .is_err()
        );
        assert!(
            CameraProfile::test_mjpeg_profile(4096, 2160, 2 * 1024 * 1024)
                .live_pipeline_bytes(scratch)
                .is_err()
        );
    }

    #[test]
    fn detect_response_preserves_metadata_and_has_no_embedding_field() {
        let response = detected_response(
            vec![howy_common::face::Face {
                bbox: [7, 9, 27, 39],
                landmarks: [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],
                score: 0.75,
                embedding: Some(vec![0.25; howy_common::face::FACE_EMBEDDING_DIM]),
            }],
            6.5,
        );
        let Some(RespResult::Detected(result)) = response.result else {
            panic!("expected detect response");
        };
        assert_eq!(result.elapsed_ms, 6.5);
        assert_eq!(result.faces.len(), 1);
        let face = &result.faces[0];
        assert_eq!((face.x1, face.y1, face.x2, face.y2), (7, 9, 27, 39));
        assert_eq!(
            face.landmarks,
            vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]
        );
        assert_eq!(face.score, 0.75);
    }

    #[test]
    fn injected_lifecycle_distinguishes_probe_open_configure_stream_read_and_stop() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let factory = RecordingCameraFactory {
            events: events.clone(),
        };
        let (admission, _reaper) = CameraReaper::new().unwrap();

        let lease = admission.acquire(Duration::from_secs(1)).unwrap();
        let held = CameraAdmissionHeld::new(&lease);
        let mut camera = open_started_camera_from_profile_cache(&cache, &held, &factory)
            .expect("injected camera should start");
        let _frame = camera.camera.capture_frame().unwrap();
        assert!(matches!(camera.camera.stop(), CameraStopOutcome::Released));

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            events.snapshot(),
            [
                CameraLifecycleEvent::ProfileProbe,
                CameraLifecycleEvent::DeviceOpen,
                CameraLifecycleEvent::ConfigureProfile,
                CameraLifecycleEvent::StreamStart,
                CameraLifecycleEvent::FrameRead,
                CameraLifecycleEvent::StopCleanup,
            ]
        );
    }

    #[test]
    fn production_runner_confirm_is_cold_until_commit_then_runs_real_authentication() {
        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("confirm-runner");
        let socket = directory.join("howy.sock");
        let _socket_environment = SocketEnvGuard::set(&socket);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let username = current_peer_username();
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Confirm;
            config.presence.prompt_timeout_ms = 1_000;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            ));
            let storage = Arc::new(RunnerStorage::new());
            let events = LifecycleEvents::default();
            let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
            let hooks = CameraHooks {
                profile_provider: provider.clone(),
                factory: Arc::new(RecordingCameraFactory {
                    events: events.clone(),
                }),
            };
            let shutdown = ShutdownSignal::new();
            let server = tokio::spawn(run_with_camera_hooks(
                Arc::new(RunnerInference),
                storage,
                Arc::clone(&manager),
                config.clone(),
                false,
                false,
                None,
                shutdown.clone(),
                hooks,
            ));
            wait_for_socket(&socket).await;

            let info = connect_and_send(&socket, &Request::info());
            assert!(matches!(info.result, Some(RespResult::Info(_))));
            events.assert_empty();

            // Malformed commit after PromptRequired.
            let mut malformed_stream = UnixStream::connect(&socket).unwrap();
            let begin = Request::begin_auth_v1(
                &username,
                [0x11; PROMPT_NONCE_BYTES],
                "sudo",
                PromptOriginV1::Local,
            );
            howy_common::ipc::send_message(&mut malformed_stream, &begin).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut malformed_stream).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt")
            };
            let mut malformed = Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            );
            let Some(Cmd::CommitAuthV1(commit)) = malformed.cmd.as_mut() else {
                unreachable!()
            };
            commit.client_nonce.clear();
            howy_common::ipc::send_message(&mut malformed_stream, &malformed).unwrap();
            let _: Response = howy_common::ipc::recv_message(&mut malformed_stream).unwrap();
            events.assert_empty();

            // Explicit pending cancellation.
            let mut cancel_stream = UnixStream::connect(&socket).unwrap();
            howy_common::ipc::send_message(&mut cancel_stream, &begin).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut cancel_stream).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt")
            };
            let cancel = Request::cancel_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            );
            howy_common::ipc::send_message(&mut cancel_stream, &cancel).unwrap();
            let cancelled: Response = howy_common::ipc::recv_message(&mut cancel_stream).unwrap();
            assert!(matches!(
                cancelled.result,
                Some(RespResult::AuthCancelledV1(_))
            ));
            events.assert_empty();

            // Pending HUP/EOF.
            let mut eof_stream = UnixStream::connect(&socket).unwrap();
            howy_common::ipc::send_message(&mut eof_stream, &begin).unwrap();
            let _: Response = howy_common::ipc::recv_message(&mut eof_stream).unwrap();
            drop(eof_stream);

            // Expiry rejects the matching commit before handoff.
            let mut expiry_stream = UnixStream::connect(&socket).unwrap();
            howy_common::ipc::send_message(&mut expiry_stream, &begin).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut expiry_stream).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt")
            };
            manager.expire_pending_for_test();
            let commit = Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            );
            howy_common::ipc::send_message(&mut expiry_stream, &commit).unwrap();
            let _: Response = howy_common::ipc::recv_message(&mut expiry_stream).unwrap();
            events.assert_empty();

            // A valid commit promotes active state, resolves the cold camera,
            // and returns the real authentication result through the supervisor.
            let mut commit_stream = UnixStream::connect(&socket).unwrap();
            howy_common::ipc::send_message(&mut commit_stream, &begin).unwrap();
            let prompt: Response = howy_common::ipc::recv_message(&mut commit_stream).unwrap();
            let Some(RespResult::PromptRequiredV1(prompt)) = prompt.result else {
                panic!("expected prompt")
            };
            let commit = Request::commit_auth_v1_ref(
                prompt.transaction_token.as_slice().try_into().unwrap(),
                prompt.client_nonce.as_slice().try_into().unwrap(),
            );
            howy_common::ipc::send_message(&mut commit_stream, &commit).unwrap();
            let committed: Response = howy_common::ipc::recv_message(&mut commit_stream).unwrap();
            assert!(
                matches!(committed.result, Some(RespResult::Success(_))),
                "unexpected committed response: {committed:?}"
            );
            assert_eq!(
                events.snapshot(),
                [
                    CameraLifecycleEvent::ProfileProbe,
                    CameraLifecycleEvent::DeviceOpen,
                    CameraLifecycleEvent::ConfigureProfile,
                    CameraLifecycleEvent::StreamStart,
                    CameraLifecycleEvent::FrameRead,
                    CameraLifecycleEvent::StopCleanup,
                ]
            );
            let publication_deadline = Instant::now() + Duration::from_secs(1);
            while manager.counts() != (0, 0, 0) && Instant::now() < publication_deadline {
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(manager.counts(), (0, 0, 0));
            let committed_events = events.snapshot();

            // Manager shutdown wakes a real pending connection without camera
            // activity, then daemon shutdown joins the production workers.
            let mut shutdown_stream = UnixStream::connect(&socket).unwrap();
            shutdown_stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            howy_common::ipc::send_message(&mut shutdown_stream, &begin).unwrap();
            let _: Response = howy_common::ipc::recv_message(&mut shutdown_stream).unwrap();
            manager.shutdown();
            let closed: std::io::Result<Response> =
                howy_common::ipc::recv_message(&mut shutdown_stream);
            assert!(closed.is_err());
            shutdown.request();
            server.await.unwrap().unwrap();
            assert_eq!(events.snapshot(), committed_events);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

            // A fresh daemon instance remains cold through bind, status, and
            // shutdown as well.
            std::fs::remove_file(&socket).unwrap();
            let restart_manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            ));
            let restart_shutdown = ShutdownSignal::new();
            let restart = tokio::spawn(run_with_camera_hooks(
                Arc::new(RunnerInference),
                Arc::new(RunnerStorage::new()),
                restart_manager,
                config,
                false,
                false,
                None,
                restart_shutdown.clone(),
                CameraHooks {
                    profile_provider: provider.clone(),
                    factory: Arc::new(RecordingCameraFactory {
                        events: events.clone(),
                    }),
                },
            ));
            wait_for_socket(&socket).await;
            let _: Response = connect_and_send(&socket, &Request::info());
            restart_shutdown.request();
            restart.await.unwrap().unwrap();
            assert_eq!(events.snapshot(), committed_events);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn production_runner_prompt_off_eager_probe_is_reused_by_one_shot_auth() {
        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("prompt-off-runner");
        let socket = directory.join("howy.sock");
        let _socket_environment = SocketEnvGuard::set(&socket);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let username = current_peer_username();
            let mut config = howy_common::config::HowyConfig::default();
            config.presence.mode = PresenceMode::Off;
            let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                &config,
                prompt_active_timeout(&config),
                prompt_active_capacity(),
            ));
            let events = LifecycleEvents::default();
            let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
            let shutdown = ShutdownSignal::new();
            let server = tokio::spawn(run_with_camera_hooks(
                Arc::new(RunnerInference),
                Arc::new(RunnerStorage::new()),
                manager,
                config,
                false,
                false,
                None,
                shutdown.clone(),
                CameraHooks {
                    profile_provider: provider.clone(),
                    factory: Arc::new(RecordingCameraFactory {
                        events: events.clone(),
                    }),
                },
            ));
            wait_for_socket(&socket).await;
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                events
                    .snapshot()
                    .iter()
                    .filter(|event| **event == CameraLifecycleEvent::ProfileProbe)
                    .count(),
                1
            );

            let response = connect_and_send(&socket, &Request::authenticate_v1(&username, 1));
            assert!(matches!(response.result, Some(RespResult::Success(_))));
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                events
                    .snapshot()
                    .iter()
                    .filter(|event| **event == CameraLifecycleEvent::ProfileProbe)
                    .count(),
                1
            );

            shutdown.request();
            server.await.unwrap().unwrap();
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn confirm_startup_socket_pending_cancel_expiry_hup_shutdown_and_restart_stay_cold() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let factory: Arc<dyn CameraFactory> = Arc::new(RecordingCameraFactory {
            events: events.clone(),
        });
        let (admission, _reaper) = CameraReaper::new().unwrap();
        assert!(
            !initialize_camera_profile_for_presence(
                PresenceMode::Confirm,
                Arc::clone(&cache),
                &admission,
                &_reaper,
            )
            .unwrap()
        );

        // Socket construction/accept and public readiness are deliberately
        // outside the provider boundary.
        let socket_directory = temp_directory("lazy-camera-socket");
        let socket_path = socket_directory.join("howy.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop((client, server, listener));
        std::fs::remove_dir_all(socket_directory).unwrap();
        assert!(active_storage_ready(&HealthBackend(BackendHealth::Ready)));

        let lazy = LazyCameraHandle {
            profile: Arc::clone(&cache),
            admission: admission.clone(),
            factory,
        };
        let mut machine = PromptConnectionMachine::new();
        let begin = prompt_begin();
        let pending = pending_prompt();
        assert!(matches!(
            machine.begin_with(&begin, |_| Ok(pending.clone())),
            PromptConnectionAction::SendPrompt(_)
        ));
        machine.prompt_sent().unwrap();
        let cancel = Request::cancel_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        assert!(matches!(
            machine.receive(&cancel),
            PromptConnectionAction::SendTerminal(_)
        ));
        drop(lazy);
        events.assert_empty();

        // Malformed commit, pending expiry, HUP/EOF, shutdown, and a fresh
        // daemon instance all remain cold because none reaches the handoff.
        let mut malformed =
            Request::commit_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]);
        let Some(Cmd::CommitAuthV1(commit)) = malformed.cmd.as_mut() else {
            unreachable!()
        };
        commit.client_nonce.clear();
        let mut malformed_machine = PromptConnectionMachine::new();
        malformed_machine.begin_with(&begin, |_| Ok(pending_prompt()));
        assert!(matches!(
            malformed_machine.receive(&malformed),
            PromptConnectionAction::SendTerminal(_)
        ));
        let mut eof_machine = PromptConnectionMachine::new();
        eof_machine.begin_with(&begin, |_| Ok(pending_prompt()));
        assert_eq!(
            eof_machine.eof(),
            PromptConnectionAction::CloseWithoutResponse
        );

        let mut expiry_config = howy_common::config::HowyConfig::default();
        expiry_config.presence.mode = PresenceMode::Confirm;
        let expiry_manager = PromptTransactionManager::deterministic_for_test(
            &expiry_config,
            prompt_active_timeout(&expiry_config),
            prompt_active_capacity(),
        );
        let expiry_storage = PromptCandidateBackend::new();
        let expiry_connection = expiry_manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(expiry_begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let expiry_pending = prepare_prompt_pending(
            0,
            expiry_connection,
            &expiry_config,
            &expiry_storage,
            &expiry_manager,
            &expiry_begin,
        )
        .unwrap();
        let expiry_commit = Request::commit_auth_v1_ref(
            &expiry_pending.transaction_token,
            &expiry_pending.client_nonce,
        );
        let mut expiry_machine = PromptConnectionMachine::new();
        expiry_machine.begin_with(&expiry_begin, |_| Ok(expiry_pending));
        expiry_machine.prompt_sent().unwrap();
        expiry_manager.expire_pending_for_test();
        assert!(matches!(
            expiry_machine.receive(&expiry_commit),
            PromptConnectionAction::SendTerminal(_)
        ));
        expiry_manager.shutdown();
        events.assert_empty();

        cache.shutdown();
        events.assert_empty();
        let restarted = injected_profile_cache(provider.clone());
        let (restart_admission, restart_reaper) = CameraReaper::new().unwrap();
        assert!(
            !initialize_camera_profile_for_presence(
                PresenceMode::Confirm,
                Arc::clone(&restarted),
                &restart_admission,
                &restart_reaper,
            )
            .unwrap()
        );
        restarted.shutdown();
        events.assert_empty();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_commit_handoff_is_the_first_allowed_profile_acquisition() {
        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Confirm;
        let manager = PromptTransactionManager::deterministic_for_test(
            &config,
            prompt_active_timeout(&config),
            prompt_active_capacity(),
        );
        let storage = PromptCandidateBackend::new();
        let connection = manager.new_connection().unwrap();
        let Some(Cmd::BeginAuthV1(begin)) = root_prompt_begin_request().cmd else {
            unreachable!()
        };
        let pending =
            prepare_prompt_pending(0, connection, &config, &storage, &manager, &begin).unwrap();
        let commit = Request::commit_auth_v1_ref(&pending.transaction_token, &pending.client_nonce);
        let mut machine = PromptConnectionMachine::new();
        machine.begin_with(&begin, |_| Ok(pending));
        machine.prompt_sent().unwrap();

        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lazy = LazyCameraHandle {
            profile: cache,
            admission,
            factory: Arc::new(RecordingCameraFactory {
                events: events.clone(),
            }),
        };
        events.assert_empty();

        let PromptConnectionAction::StartAuthentication(pending) = machine.receive(&commit) else {
            panic!("matching commit must reach committed handoff")
        };
        let response = finish_prompt_commit_with(pending, &config, &storage, |lease| {
            events.assert_empty();
            let _profile = lazy
                .resolve_profile(|| lease.check_deadline())
                .expect("committed lazy acquisition should resolve");
            assert_eq!(events.snapshot(), [CameraLifecycleEvent::ProfileProbe]);
            drop(lease);
            Response::prompt_error(howy_common::protocol::PromptErrorCode::Unavailable)
        });
        assert!(matches!(response.result, Some(RespResult::Error(_))));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(manager.counts(), (0, 0, 0));
    }

    #[test]
    fn concurrent_first_allowed_profile_acquisitions_coalesce() {
        let events = LifecycleEvents::default();
        let block = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let provider = Arc::new(ScriptedProfileProvider::blocking(
            events,
            Arc::clone(&block),
            entered_tx,
        ));
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let workers = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let admission = admission.clone();
                thread::spawn(move || resolve_camera_profile(&cache, &admission, || false))
            })
            .collect::<Vec<_>>();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        *block.0.lock().unwrap() = true;
        block.1.notify_all();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn first_probe_panic_wakes_concurrent_waiters_and_later_probe_succeeds() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(PanicThenSuccessProvider {
            events,
            calls: AtomicUsize::new(0),
        });
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let waiters = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let admission = admission.clone();
                thread::spawn(move || resolve_camera_profile(&cache, &admission, || false))
            })
            .collect::<Vec<_>>();
        for waiter in waiters {
            waiter.join().unwrap().unwrap();
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.state_name(), "ready");
    }

    #[test]
    fn profile_probe_waits_for_real_camera_admission_before_provider_io() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let active = admission.acquire(Duration::from_secs(1)).unwrap();
        let waiter_cache = Arc::clone(&cache);
        let waiter_admission = admission.clone();
        let waiter = thread::spawn(move || {
            resolve_camera_profile(&waiter_cache, &waiter_admission, || false)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while admission.queued_waiters() == 0 {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        events.assert_empty();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        drop(active);
        waiter.join().unwrap().unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_capture_cleanup_blocks_reprobe_until_reaper_releases_admission() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_secs(1)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );

        let waiter_cache = Arc::clone(&cache);
        let waiter_admission = admission.clone();
        let waiter = thread::spawn(move || {
            resolve_camera_profile(&waiter_cache, &waiter_admission, || false)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while admission.queued_waiters() == 0 {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        events.assert_empty();
        release_tx.send(()).unwrap();
        waiter.join().unwrap().unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn synchronous_cleanup_invalidates_before_admission_release_exposes_profile() {
        let provider = Arc::new(SequenceProfileProvider {
            profiles: Mutex::new(VecDeque::from([CameraProfile::test_grey_profile(800, 600)])),
            calls: AtomicUsize::new(0),
        });
        let cache = injected_profile_cache(provider.clone());
        assert_eq!(cache.claim(Instant::now()), super::ProbeClaim::Start(0));
        cache.complete_probe(
            0,
            Ok(CameraProfile::test_grey_profile(640, 480)),
            Instant::now(),
        );
        let stale = cache.ready_profile().unwrap();
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_secs(1)).unwrap();

        let contender_cache = Arc::clone(&cache);
        let contender_admission = admission.clone();
        let contender = thread::spawn(move || {
            let lease = contender_admission.acquire(Duration::from_secs(1)).unwrap();
            resolve_camera_profile_already_admitted(
                &contender_cache,
                &CameraAdmissionHeld::new(&lease),
                || false,
            )
            .unwrap()
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while admission.queued_waiters() == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }

        let mut camera: Box<dyn CameraCapture> = Box::new(StaleReadSynchronousCamera);
        let error = match camera.capture_frame() {
            Ok(_) => panic!("injected stale read must fail"),
            Err(error) => error,
        };
        finish_live_enrollment_camera_failure(
            CameraCleanup {
                camera,
                lease: Some(lease),
                admission: admission.clone(),
            },
            &cache,
            stale.token,
            error,
            "Camera capture failed",
        );

        let refreshed = contender.join().unwrap();
        assert_ne!(refreshed.token, stale.token);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn old_profile_failure_cannot_evict_refreshed_ready_generation() {
        let cache = Arc::new(probing_profile_cache());
        cache.complete_probe(
            0,
            Ok(CameraProfile::test_profile("profile-a")),
            Instant::now(),
        );
        let profile_a = cache.ready_profile().unwrap();
        assert!(cache.invalidate_if_current(profile_a.token));
        let super::ProbeClaim::Start(generation_b) = cache.claim(Instant::now()) else {
            panic!("profile B probe must start")
        };
        cache.complete_probe(
            generation_b,
            Ok(CameraProfile::test_profile("profile-b")),
            Instant::now(),
        );
        let profile_b = cache.ready_profile().unwrap();
        assert_ne!(profile_a.token, profile_b.token);
        assert!(!cache.invalidate_if_current(profile_a.token));
        assert_eq!(cache.ready_profile().unwrap().token, profile_b.token);
    }

    #[test]
    fn pending_cleanup_conditionally_invalidates_before_release_and_blocks_reprobe() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        assert_eq!(cache.claim(Instant::now()), super::ProbeClaim::Start(0));
        cache.complete_probe(0, Ok(CameraProfile::test_profile("stale")), Instant::now());
        let stale_token = cache.ready_profile().unwrap().token;
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_secs(1)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        let mut camera: Box<dyn CameraCapture> = Box::new(StaleReadPendingCamera {
            pending: Some(pending),
        });
        let error = match camera.capture_frame() {
            Ok(_) => panic!("injected exact-profile mismatch must fail"),
            Err(error) => error,
        };
        let response = finish_live_enrollment_camera_failure(
            CameraCleanup {
                camera,
                lease: Some(lease),
                admission: admission.clone(),
            },
            &cache,
            stale_token,
            error,
            "Camera capture failed",
        );
        assert!(matches!(response.result, Some(RespResult::Error(_))));
        assert_eq!(cache.state_name(), "failed");

        let waiter_cache = Arc::clone(&cache);
        let waiter_admission = admission.clone();
        let waiter = thread::spawn(move || {
            resolve_camera_profile(&waiter_cache, &waiter_admission, || false)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while admission.queued_waiters() == 0 {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        events.assert_empty();
        release_tx.send(()).unwrap();
        waiter.join().unwrap().unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.state_name(), "ready");
    }

    #[test]
    fn next_request_reprobes_once_and_recomputes_profile_admission() {
        let provider = Arc::new(SequenceProfileProvider {
            profiles: Mutex::new(VecDeque::from([
                CameraProfile::test_grey_profile(640, 480),
                CameraProfile::test_grey_profile(1280, 720),
            ])),
            calls: AtomicUsize::new(0),
        });
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let first = resolve_camera_profile(&cache, &admission, || false).unwrap();
        let first_admission = first.live_pipeline_bytes(1024).unwrap();
        assert!(cache.invalidate_if_current(first.token));
        let second = resolve_camera_profile(&cache, &admission, || false).unwrap();
        let second_admission = second.live_pipeline_bytes(1024).unwrap();
        assert_ne!(first.token, second.token);
        assert_ne!(first_admission, second_admission);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.ready_profile().unwrap().token, second.token);
    }

    #[test]
    fn enrollment_non_stale_failures_do_not_invalidate_profile() {
        for kind in [CameraFailureKind::Cancelled, CameraFailureKind::Other] {
            let cache = Arc::new(probing_profile_cache());
            cache.complete_probe(
                0,
                Ok(CameraProfile::test_profile("retained")),
                Instant::now(),
            );
            let token = cache.ready_profile().unwrap().token;
            assert!(profile_invalidation_for_failure(&cache, token, kind).is_none());
            assert_eq!(cache.state_name(), "ready");
        }
    }

    #[test]
    fn transient_profile_failure_allows_a_later_retry() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::scripted(
            events,
            [Err("transient"), Ok(())],
        ));
        let cache = injected_profile_cache(provider.clone());
        let (admission, reaper) = CameraReaper::new().unwrap();
        start_initial_camera_profile_probe(Arc::clone(&cache), &admission, &reaper).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        thread::sleep(super::CAMERA_PROFILE_RETRY_BACKOFF + Duration::from_millis(5));
        resolve_camera_profile(&cache, &admission, || false).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert!(cache.ready_profile().is_some());
    }

    #[test]
    fn cancelled_profile_waiter_does_not_poison_provider() {
        let events = LifecycleEvents::default();
        let block = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let provider = Arc::new(ScriptedProfileProvider::blocking(
            events,
            Arc::clone(&block),
            entered_tx,
        ));
        let cache = injected_profile_cache(provider.clone());
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let waiter_cancelled = Arc::clone(&cancelled);
        let waiter_cache = Arc::clone(&cache);
        let waiter_admission = admission.clone();
        let waiter = thread::spawn(move || {
            resolve_camera_profile(&waiter_cache, &waiter_admission, || {
                waiter_cancelled.load(Ordering::Acquire)
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(waiter.join().unwrap().is_err());
        *block.0.lock().unwrap() = true;
        block.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while cache.ready_profile().is_none() {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        resolve_camera_profile(&cache, &admission, || false).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn profile_shutdown_wakes_waiters_without_poisoning_cleanup() {
        let events = LifecycleEvents::default();
        let block = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let provider = Arc::new(ScriptedProfileProvider::blocking(
            events,
            Arc::clone(&block),
            entered_tx,
        ));
        let cache = injected_profile_cache(provider);
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let waiter_cache = Arc::clone(&cache);
        let waiter =
            thread::spawn(move || resolve_camera_profile(&waiter_cache, &admission, || false));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = std::time::Instant::now();
        cache.shutdown();
        assert!(waiter.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
        *block.0.lock().unwrap() = true;
        block.1.notify_all();
    }

    #[test]
    fn prompt_off_eager_profile_is_cached_for_auth_and_enrollment_paths() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let factory = RecordingCameraFactory { events };
        let (admission, reaper) = CameraReaper::new().unwrap();
        assert!(
            initialize_camera_profile_for_presence(
                PresenceMode::Off,
                Arc::clone(&cache),
                &admission,
                &reaper,
            )
            .unwrap()
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

        let lease = admission.acquire(Duration::from_secs(1)).unwrap();
        let held = CameraAdmissionHeld::new(&lease);
        let mut auth_camera =
            open_started_camera_from_profile_cache(&cache, &held, &factory).unwrap();
        let _ = auth_camera.camera.capture_frame().unwrap();
        let _ = auth_camera.camera.stop();
        drop(auth_camera);
        drop(held);
        drop(lease);

        let mut config = howy_common::config::HowyConfig::default();
        config.presence.mode = PresenceMode::Off;
        let enrolled = handle_enroll(
            &RunnerInference,
            &config,
            &admission,
            &RunnerStorage::new(),
            &cache,
            &factory,
            "root",
            "runner",
        );
        assert!(matches!(enrolled.result, Some(RespResult::Enrolled(_))));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn confirm_policy_root_live_enrollment_resolves_explicitly_without_prompt_state() {
        let events = LifecycleEvents::default();
        let provider = Arc::new(ScriptedProfileProvider::succeeding(events.clone()));
        let cache = injected_profile_cache(provider.clone());
        let (admission, reaper) = CameraReaper::new().unwrap();
        assert!(
            !initialize_camera_profile_for_presence(
                PresenceMode::Confirm,
                Arc::clone(&cache),
                &admission,
                &reaper,
            )
            .unwrap()
        );
        events.assert_empty();
        resolve_live_enrollment_profile(&cache, &admission).unwrap();
        assert_eq!(events.snapshot(), [CameraLifecycleEvent::ProfileProbe]);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn camera_profile_busy_at_start_enters_retryable_failure() {
        let cache = probing_profile_cache();
        cache.complete_probe(0, Err("device busy".into()), std::time::Instant::now());
        assert_eq!(cache.state_name(), "failed");
        assert!(cache.ready_profile().is_none());
    }

    #[test]
    fn slow_camera_profile_success_becomes_usable_after_initial_bound() {
        let cache = Arc::new(probing_profile_cache());
        let worker_cache = Arc::clone(&cache);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            worker_cache.complete_probe(
                0,
                Ok(CameraProfile::test_profile("slow")),
                std::time::Instant::now(),
            );
        });
        assert_eq!(cache.state_name(), "probing");
        worker.join().unwrap();
        assert_eq!(cache.state_name(), "ready");
        assert!(cache.ready_profile().is_some());
    }

    #[test]
    fn failed_camera_profile_allows_bounded_retry() {
        let cache = probing_profile_cache();
        cache.complete_probe(0, Err("disconnected".into()), std::time::Instant::now());
        assert_eq!(
            cache.claim(std::time::Instant::now()),
            super::ProbeClaim::Wait
        );
        thread::sleep(super::CAMERA_PROFILE_RETRY_BACKOFF + Duration::from_millis(5));
        let super::ProbeClaim::Start(generation) = cache.claim(std::time::Instant::now()) else {
            panic!("retry was not claimed");
        };
        assert_eq!(cache.state_name(), "probing");
        cache.complete_probe(
            generation,
            Ok(CameraProfile::test_profile("reconnected")),
            std::time::Instant::now(),
        );
        assert_eq!(cache.state_name(), "ready");
    }

    #[test]
    fn camera_profile_invalidation_permits_one_reprobe() {
        let cache = probing_profile_cache();
        cache.complete_probe(
            0,
            Ok(CameraProfile::test_profile("stale")),
            std::time::Instant::now(),
        );
        let token = cache.ready_profile().unwrap().token;
        assert!(cache.invalidate_if_current(token));
        assert_eq!(cache.state_name(), "failed");
        assert!(matches!(
            cache.claim(std::time::Instant::now()),
            super::ProbeClaim::Start(_)
        ));
        assert_eq!(cache.state_name(), "probing");
    }

    #[test]
    fn disconnect_then_reconnect_transitions_failed_retrying_ready() {
        let cache = probing_profile_cache();
        cache.complete_probe(0, Err("disconnect".into()), std::time::Instant::now());
        thread::sleep(super::CAMERA_PROFILE_RETRY_BACKOFF + Duration::from_millis(5));
        let super::ProbeClaim::Start(generation) = cache.claim(std::time::Instant::now()) else {
            panic!("reconnect probe was not started");
        };
        cache.complete_probe(
            generation,
            Ok(CameraProfile::test_profile("reconnect")),
            std::time::Instant::now(),
        );
        assert!(cache.ready_profile().is_some());
    }

    #[test]
    fn concurrent_camera_profile_retry_is_suppressed() {
        let cache = Arc::new(probing_profile_cache());
        cache.complete_probe(0, Err("busy".into()), std::time::Instant::now());
        thread::sleep(super::CAMERA_PROFILE_RETRY_BACKOFF + Duration::from_millis(5));
        let claims = (0..16)
            .map(|_| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || cache.claim(std::time::Instant::now()))
            })
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, super::ProbeClaim::Start(_)))
                .count(),
            1
        );
        assert_eq!(cache.state_name(), "probing");
    }

    #[test]
    fn authentication_outcome_is_reduced_to_non_sensitive_categories() {
        assert_eq!(
            auth_outcome(&Response::success(0, "secret-label", 0.9, 1.0)),
            "success"
        );
        assert_eq!(
            auth_outcome(&Response::auth_failed(0.1, 2, "secret-reason")),
            "auth_failed"
        );
        assert_eq!(auth_outcome(&Response::error("secret-error")), "error");
        assert_eq!(
            auth_outcome(&Response::credential_valid()),
            "credential_valid"
        );
        assert_eq!(auth_outcome(&Response::pong()), "unexpected_response");
    }

    #[test]
    fn camera_admission_is_unavailable_while_lease_is_held() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        assert!(admission.acquire(Duration::from_millis(10)).is_err());
        drop(lease);
        drop(admission.acquire(Duration::from_millis(10)).unwrap());
    }

    #[test]
    fn pending_worker_handoff_blocks_admission_until_reaper_finishes() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let exited = Arc::new(AtomicBool::new(false));
        let worker_exited = Arc::clone(&exited);
        let handle = thread::spawn(move || {
            let _ = release_rx.recv();
            worker_exited.store(true, Ordering::Release);
        });
        let pending = PendingCameraCleanup::from_thread_handle(handle);

        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );
        assert!(admission.acquire(Duration::from_millis(20)).is_err());
        let competing_admission = admission.clone();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let competing_request = thread::spawn(move || {
            let lease = competing_admission.acquire(Duration::from_secs(1)).unwrap();
            acquired_tx.send(()).unwrap();
            drop(lease);
        });
        assert!(matches!(
            acquired_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        competing_request.join().unwrap();
        assert!(exited.load(Ordering::Acquire));
        drop(admission); // Joins the tracked reaper thread.
    }

    #[test]
    fn exceptional_cleanup_before_write_hands_off_without_waiting_for_release() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let pending = PendingCameraCleanup::from_thread_handle(handle);
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            release_tx.send(()).unwrap();
        });

        let started = std::time::Instant::now();
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );
        assert!(started.elapsed() < Duration::from_millis(25));
        assert!(admission.acquire(Duration::from_millis(5)).is_err());
        release.join().unwrap();
        drop(admission.acquire(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn concurrent_auth_and_enrollment_contenders_are_fifo() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let active = admission.acquire(Duration::from_millis(10)).unwrap();
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut contenders = Vec::new();
        for id in 1..=3 {
            let contender_admission = admission.clone();
            let contender_order = Arc::clone(&order);
            contenders.push(thread::spawn(move || {
                let lease = contender_admission.acquire(Duration::from_secs(1)).unwrap();
                contender_order.lock().unwrap().push(id);
                thread::sleep(Duration::from_millis(5));
                drop(lease);
            }));
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while admission.queued_waiters() < id {
                assert!(std::time::Instant::now() < deadline);
                thread::sleep(Duration::from_millis(1));
            }
        }
        drop(active);
        for contender in contenders {
            contender.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), [1, 2, 3]);
    }

    #[test]
    fn timed_out_fifo_waiter_is_removed_and_next_waiter_progresses() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let active = admission.acquire(Duration::from_millis(10)).unwrap();
        let timed_admission = admission.clone();
        let timed = thread::spawn(move || timed_admission.acquire(Duration::from_millis(30)));
        while admission.queued_waiters() < 1 {
            thread::sleep(Duration::from_millis(1));
        }
        let next_admission = admission.clone();
        let (progress_tx, progress_rx) = mpsc::channel();
        let next = thread::spawn(move || {
            let lease = next_admission.acquire(Duration::from_secs(1)).unwrap();
            progress_tx.send(()).unwrap();
            drop(lease);
        });
        while admission.queued_waiters() < 2 {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(timed.join().unwrap().is_err());
        drop(active);
        progress_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        next.join().unwrap();
    }

    #[test]
    fn dropping_external_reaper_owner_during_release_never_self_joins() {
        let (admission, reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let pending = PendingCameraCleanup::from_thread_handle(worker);
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            release_tx.send(()).unwrap();
        });
        release.join().unwrap();
        drop(admission.acquire(Duration::from_secs(1)).unwrap());
        drop(admission);
        drop(reaper);
    }

    #[test]
    fn reaper_shutdown_is_bounded_and_retains_unresolved_ownership() {
        let (admission, mut reaper) = CameraReaper::new().unwrap();
        let lifecycle = Arc::clone(&reaper.lifecycle);
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );

        let started = std::time::Instant::now();
        let remainder = reaper.shutdown_bounded();
        assert!(remainder.unresolved_count() >= 1);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(admission.acquire(Duration::from_millis(5)).is_err());

        release_tx.send(()).unwrap();
        let mut lifecycle = lock_unpoisoned(&lifecycle);
        let unresolved = &mut lifecycle.unresolved;
        let task = unresolved.first_mut().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !task.pending.is_finished() {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(task.pending.try_complete(), Some(WorkerExit::Released));
        release_camera_admission(&task.admission);
        unresolved.clear();
        drop(admission.acquire(Duration::from_millis(10)).unwrap());
    }

    #[test]
    fn enqueue_crossing_shutdown_keeps_task_and_admission_owned() {
        let (admission, mut reaper) = CameraReaper::new().unwrap();
        let lifecycle = Arc::clone(&reaper.lifecycle);
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (worker_release_tx, worker_release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = worker_release_rx.recv();
        }));

        let (enqueue_locked_tx, enqueue_locked_rx) = mpsc::channel();
        let (enqueue_continue_tx, enqueue_continue_rx) = mpsc::channel();
        let enqueue_admission = admission.clone();
        let enqueue = thread::spawn(move || {
            enqueue_admission.handoff_with_lifecycle_hook(pending, lease, || {
                enqueue_locked_tx.send(()).unwrap();
                enqueue_continue_rx.recv().unwrap();
            })
        });
        enqueue_locked_rx.recv().unwrap();

        let (shutdown_entered_tx, shutdown_entered_rx) = mpsc::channel();
        let shutdown = thread::spawn(move || {
            reaper.shutdown_bounded_with_hook(|| shutdown_entered_tx.send(()).unwrap())
        });
        shutdown_entered_rx.recv().unwrap();
        enqueue_continue_tx.send(()).unwrap();

        assert_eq!(enqueue.join().unwrap(), CleanupMode::ReaperHandoff);
        let remainder = shutdown.join().unwrap();
        assert!(remainder.unresolved_count() >= 1);
        assert!(admission.acquire(Duration::from_millis(5)).is_err());

        let (late_release_tx, late_release_rx) = mpsc::channel();
        let late_pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = late_release_rx.recv();
        }));
        assert_eq!(
            enqueue_cleanup_task(
                &lifecycle,
                CleanupTask {
                    pending: late_pending,
                    admission: Weak::new(),
                },
            ),
            CleanupMode::UnresolvedTracked
        );

        worker_release_tx.send(()).unwrap();
        late_release_tx.send(()).unwrap();
        let mut lifecycle = lock_unpoisoned(&lifecycle);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        for task in &mut lifecycle.unresolved {
            while !task.pending.is_finished() {
                assert!(std::time::Instant::now() < deadline);
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(task.pending.try_complete(), Some(WorkerExit::Released));
            release_camera_admission(&task.admission);
        }
        lifecycle.unresolved.clear();
        drop(admission.acquire(Duration::from_millis(10)).unwrap());
    }

    #[test]
    fn blocked_construction_worker_is_handed_off_after_bound() {
        let (_admission, mut reaper) = CameraReaper::new().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let _ = release_rx.recv();
        });
        let started = std::time::Instant::now();
        assert_eq!(
            finish_or_track_unleased_worker(handle, &reaper, Duration::from_millis(20)),
            CleanupMode::ReaperHandoff
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        release_tx.send(()).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(reaper.shutdown_bounded().is_empty());
    }

    #[test]
    fn reaper_releases_admission_after_panicked_worker_finishes() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(|| {
            panic!("mock cleanup panic");
        }));
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );
        drop(admission.acquire(Duration::from_secs(1)).unwrap());
    }

    fn coordinated_success_order(defer: bool, write_succeeds: bool) -> (Vec<&'static str>, bool) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let write_events = Arc::clone(&events);
        let cleanup_events = Arc::clone(&events);
        let coordinated = coordinate_response_cleanup(
            successful_response_cleanup_order(defer),
            Some(()),
            move || {
                write_events.lock().unwrap().push("write");
                if write_succeeds { Ok(()) } else { Err(()) }
            },
            move |(), _| {
                cleanup_events.lock().unwrap().push("stop");
                CleanupReport {
                    mode: CleanupMode::Synchronous,
                    stop_duration: Duration::ZERO,
                }
            },
        );
        (
            Arc::try_unwrap(events).unwrap().into_inner().unwrap(),
            coordinated.write_result.is_ok(),
        )
    }

    #[test]
    fn successful_deferred_order_writes_before_stop() {
        assert_eq!(coordinated_success_order(true, true).0, ["write", "stop"]);
    }

    #[test]
    fn deferred_write_failure_still_stops_after_write_attempt() {
        let (events, write_succeeded) = coordinated_success_order(true, false);
        assert!(!write_succeeded);
        assert_eq!(events, ["write", "stop"]);
    }

    #[test]
    fn disabled_gate_stops_before_response_write() {
        assert_eq!(coordinated_success_order(false, true).0, ["stop", "write"]);
    }

    #[derive(Default)]
    struct MockWriter {
        started: bool,
        outcomes: Vec<&'static str>,
        fail_writes: bool,
    }

    impl PanicResponseWriter for MockWriter {
        fn response_write_started(&self) -> bool {
            self.started
        }

        fn write_response(&mut self, response: &Response) -> anyhow::Result<()> {
            self.started = true;
            self.outcomes.push(auth_outcome(response));
            if self.fail_writes {
                return Err(anyhow::anyhow!("mock write failure"));
            }
            Ok(())
        }
    }

    #[test]
    fn root_shutdown_writes_exactly_one_pong_and_sets_signal() {
        let shutdown = ShutdownSignal::new();
        let mut writer = MockWriter::default();
        handle_root_shutdown(&mut writer, &shutdown).unwrap();
        assert_eq!(writer.outcomes, ["unexpected_response"]);
        assert!(shutdown.is_requested());
    }

    #[test]
    fn root_shutdown_signals_after_single_failed_pong_attempt() {
        let shutdown = ShutdownSignal::new();
        let mut writer = MockWriter {
            fail_writes: true,
            ..MockWriter::default()
        };
        assert!(handle_root_shutdown(&mut writer, &shutdown).is_err());
        assert_eq!(writer.outcomes, ["unexpected_response"]);
        assert!(shutdown.is_requested());
    }

    #[test]
    fn graceful_signal_wakes_idle_wait() {
        let shutdown = ShutdownSignal::new();
        let waiter_shutdown = shutdown.clone();
        let started = std::time::Instant::now();
        let waiter = thread::spawn(move || {
            waiter_shutdown.wait_for_activity(Duration::from_secs(1));
            waiter_shutdown.is_requested()
        });
        thread::sleep(Duration::from_millis(10));
        shutdown.request();
        assert!(waiter.join().unwrap());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn graceful_signal_preserves_pending_cleanup_remainder() {
        let shutdown = ShutdownSignal::new();
        let (admission, mut reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        assert_eq!(
            admission.handoff(pending, lease),
            CleanupMode::ReaperHandoff
        );
        shutdown.request();
        assert!(shutdown.is_requested());
        let mut remainder = reaper.shutdown_bounded();
        assert!(remainder.unresolved_count() >= 1);
        release_tx.send(()).unwrap();
        if let Some(handle) = remainder.handle.take() {
            handle.join().unwrap();
        }
        if let Some(lifecycle) = remainder.lifecycle.take() {
            let mut lifecycle = lock_unpoisoned(&lifecycle);
            for task in &mut lifecycle.unresolved {
                while !task.pending.is_finished() {
                    thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(task.pending.try_complete(), Some(WorkerExit::Released));
                release_camera_admission(&task.admission);
            }
            lifecycle.unresolved.clear();
        }
    }

    #[test]
    fn connection_cap_and_bounded_worker_tracking_are_enforced() {
        let accounting = Arc::new(std::sync::Mutex::new(ConnectionAccounting::default()));
        let permits = (0..super::MAX_CONNECTIONS_PER_UID)
            .map(|_| ConnectionAccounting::try_acquire(&accounting, 1000).unwrap())
            .collect::<Vec<_>>();
        assert!(ConnectionAccounting::try_acquire(&accounting, 1000).is_none());
        assert!(ConnectionAccounting::try_acquire(&accounting, 1001).is_some());
        drop(permits);
        assert_eq!(lock_unpoisoned(&accounting).total, 0);

        let unprivileged = (0..(MAX_CONNECTION_WORKERS - super::RESERVED_CONNECTIONS))
            .map(|uid| ConnectionAccounting::try_acquire(&accounting, uid as u32 + 10).unwrap())
            .collect::<Vec<_>>();
        assert!(ConnectionAccounting::try_acquire(&accounting, 50_000).is_none());
        let root_permit = ConnectionAccounting::try_acquire(&accounting, 0).unwrap();
        drop(root_permit);
        drop(unprivileged);
        assert_eq!(lock_unpoisoned(&accounting).total, 0);

        let spawn_failure_permit = ConnectionAccounting::try_acquire(&accounting, 3000).unwrap();
        let dropped_before_spawn = with_connection_permit(spawn_failure_permit, || {});
        drop(dropped_before_spawn);
        assert_eq!(lock_unpoisoned(&accounting).total, 0);

        let panic_accounting = Arc::clone(&accounting);
        let panicked = thread::spawn(move || {
            let _permit = ConnectionAccounting::try_acquire(&panic_accounting, 2000).unwrap();
            panic!("simulated connection panic");
        });
        assert!(panicked.join().is_err());
        assert_eq!(lock_unpoisoned(&accounting).total, 0);

        let mut workers = vec![thread::spawn(|| {})];
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !workers[0].is_finished() {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        reap_finished_connection_workers(&mut workers);
        assert!(workers.is_empty());

        let (release_tx, release_rx) = mpsc::channel();
        workers.push(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        let started = std::time::Instant::now();
        let unresolved =
            shutdown_connection_workers_with_timeout(&mut workers, Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(workers.is_empty());
        assert_eq!(unresolved.len(), 1);
        release_tx.send(()).unwrap();
        for handle in unresolved {
            handle.join().unwrap();
        }
    }

    #[test]
    fn initial_local_request_deadline_is_short_and_explicit() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        configure_initial_io_deadlines(&stream).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(super::INITIAL_REQUEST_READ_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn production_listener_initial_prefix_and_body_trickle_release_uid_capacity() {
        let _environment = SOCKET_ENV_LOCK.lock().unwrap();
        let directory = temp_directory("initial-trickle");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for body_trickle in [false, true] {
                let socket = directory.join(format!("{body_trickle}.sock"));
                let _socket_environment = SocketEnvGuard::set(&socket);
                let mut config = howy_common::config::HowyConfig::default();
                config.presence.mode = PresenceMode::Confirm;
                let manager = Arc::new(PromptTransactionManager::deterministic_for_test(
                    &config,
                    prompt_active_timeout(&config),
                    prompt_active_capacity(),
                ));
                let shutdown = ShutdownSignal::new();
                let server = tokio::spawn(run_with_camera_hooks(
                    Arc::new(RunnerInference),
                    Arc::new(RunnerStorage::new()),
                    Arc::clone(&manager),
                    config,
                    false,
                    false,
                    None,
                    shutdown.clone(),
                    CameraHooks {
                        profile_provider: Arc::new(FixedProfileProvider),
                        factory: Arc::new(RecordingCameraFactory {
                            events: LifecycleEvents::default(),
                        }),
                    },
                ));
                wait_for_socket(&socket).await;

                let mut framed = Vec::new();
                howy_common::ipc::send_message(&mut framed, &Request::ping()).unwrap();
                let prefix: [u8; 4] = framed[..4].try_into().unwrap();
                let payload = framed[4..].to_vec();
                let mut writers = Vec::new();
                for _ in 0..super::MAX_CONNECTIONS_PER_UID {
                    let mut stream = UnixStream::connect(&socket).unwrap();
                    let payload = payload.clone();
                    writers.push(thread::spawn(move || {
                        if body_trickle {
                            if stream.write_all(&prefix).is_ok() {
                                for byte in payload {
                                    thread::sleep(Duration::from_millis(1_100));
                                    if stream.write_all(&[byte]).is_err() {
                                        break;
                                    }
                                }
                            }
                        } else {
                            for byte in prefix {
                                if stream.write_all(&[byte]).is_err() {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(700));
                            }
                        }
                    }));
                }
                for writer in writers {
                    writer.join().unwrap();
                }

                // A fresh same-UID connection succeeds only after all timed-out
                // incomplete-frame workers have dropped their permits.
                let response = connect_and_send(&socket, &Request::ping());
                assert!(matches!(response.result, Some(RespResult::Pong(_))));
                shutdown.request();
                server.await.unwrap().unwrap();
                assert_eq!(manager.counts(), (0, 0, 0));
            }
        });
        std::fs::remove_dir_all(directory).unwrap();
    }

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn panic_before_write_runs_raii_cleanup_and_sends_one_generic_error() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let dispatch_cleaned = Arc::clone(&cleaned);
        let mut writer = MockWriter::default();
        let result = dispatch_with_panic_boundary(&mut writer, move |_| {
            let _probe = DropProbe(dispatch_cleaned);
            panic!("secret panic text");
        });
        assert!(result.is_err());
        assert!(cleaned.load(Ordering::Acquire));
        assert_eq!(writer.outcomes, ["error"]);
    }

    #[test]
    fn panic_after_write_closes_without_second_response() {
        let mut writer = MockWriter::default();
        let result = dispatch_with_panic_boundary(&mut writer, |writer| {
            writer.write_response(&Response::pong())?;
            panic!("must not become a second response");
        });
        assert!(result.is_err());
        assert_eq!(writer.outcomes, ["unexpected_response"]);
    }

    #[test]
    fn production_coordinator_hands_pending_cleanup_to_reaper_after_write() {
        let (admission, _reaper) = CameraReaper::new().unwrap();
        let lease = admission.acquire(Duration::from_millis(10)).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let pending = PendingCameraCleanup::from_thread_handle(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        let finish_admission = admission.clone();
        let coordinated = coordinate_response_cleanup(
            ResponseCleanupOrder::AfterWrite,
            Some((pending, lease)),
            || Ok::<(), ()>(()),
            move |(pending, lease), _wait| CleanupReport {
                mode: finish_admission.handoff(pending, lease),
                stop_duration: Duration::ZERO,
            },
        );
        assert!(coordinated.write_result.is_ok());
        assert_eq!(
            coordinated.cleanup_report.unwrap().mode,
            CleanupMode::ReaperHandoff
        );
        assert!(admission.acquire(Duration::from_millis(20)).is_err());
        release_tx.send(()).unwrap();
        drop(admission.acquire(Duration::from_secs(1)).unwrap());
    }
}
