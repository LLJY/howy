//! Unix socket server for the howy daemon.
//!
//! Handles IPC requests from the PAM module and CLI tools.
//! Supports systemd socket activation via `LISTEN_FDS`.

use std::collections::{HashMap, VecDeque};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tracing::{debug, error, info, warn};

use howy_common::config::HowyConfig;
use howy_common::credential;
use howy_common::face::{self, UserModels};
use howy_common::ipc;
use howy_common::paths;
use howy_common::protocol::{self, Cmd, Request, RespResult, Response};

use crate::camera::{
    Camera, CameraProfile, CameraStopOutcome, Frame, FrameFormat, PendingCameraCleanup, WorkerExit,
    take_retained_camera_workers,
};
use crate::inference::InferenceEngine;

/// Serialize passwd lookups because getpwnam is not thread-safe.
static PASSWD_LOOKUP_LOCK: Mutex<()> = Mutex::new(());

const CAMERA_LOCK_TIMEOUT: Duration = Duration::from_secs(3);
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const REAPER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const CONNECTION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const CAMERA_PROFILE_PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const CAMERA_PROFILE_RETRY_BACKOFF: Duration = Duration::from_millis(100);
/// Local peers must send their first framed request promptly.
const INITIAL_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CONNECTION_WORKERS: usize = 64;
const RESERVED_CONNECTIONS: usize = 8;
const MAX_CONNECTIONS_PER_UID: usize = 8;
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
}

struct CameraProfileCache {
    state: Mutex<CameraProfileState>,
    changed: Condvar,
}

enum CameraProfileState {
    Pending { generation: u64 },
    Ready(CameraProfile),
    Failed { retry_at: Instant, generation: u64 },
    Retrying { generation: u64 },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeClaim {
    Ready,
    Wait,
    Start(u64),
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
    wake: Arc<(Mutex<()>, Condvar)>,
}

impl DaemonShutdownRemainder {
    fn is_empty(&self) -> bool {
        self.reaper.is_empty()
            && self.connection_workers.is_empty()
            && self.retained_camera_workers.is_empty()
    }

    fn unresolved_count(&self) -> usize {
        self.reaper.unresolved_count()
            + self.connection_workers.len()
            + self.retained_camera_workers.len()
    }
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            requested: Arc::new(AtomicBool::new(false)),
            wake: Arc::new((Mutex::new(()), Condvar::new())),
        }
    }

    pub fn request(&self) {
        self.requested.store(true, Ordering::Release);
        self.wake.1.notify_all();
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
    fn new_pending() -> Self {
        Self {
            state: Mutex::new(CameraProfileState::Pending { generation: 0 }),
            changed: Condvar::new(),
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
            CameraProfileState::Pending { generation }
            | CameraProfileState::Retrying { generation } => *generation,
            CameraProfileState::Ready(_) | CameraProfileState::Failed { .. } => return,
        };
        if active_generation != generation {
            return;
        }
        *state = match result {
            Ok(profile) => CameraProfileState::Ready(profile),
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
            CameraProfileState::Ready(_) => ProbeClaim::Ready,
            CameraProfileState::Pending { .. } | CameraProfileState::Retrying { .. } => {
                ProbeClaim::Wait
            }
            CameraProfileState::Failed {
                retry_at,
                generation,
            } if now >= *retry_at => {
                let generation = generation.wrapping_add(1);
                *state = CameraProfileState::Retrying { generation };
                ProbeClaim::Start(generation)
            }
            CameraProfileState::Failed { .. } => ProbeClaim::Wait,
        }
    }

    fn ready_profile(&self) -> Option<CameraProfile> {
        let state = lock_unpoisoned(&self.state);
        match &*state {
            CameraProfileState::Ready(profile) => Some(profile.clone()),
            _ => None,
        }
    }

    fn initial_attempt_finished(&self) -> bool {
        matches!(
            &*lock_unpoisoned(&self.state),
            CameraProfileState::Ready(_) | CameraProfileState::Failed { .. }
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
            _ => remaining,
        };
        if wait.is_zero() {
            return;
        }
        let _state = self
            .changed
            .wait_timeout(state, wait)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }

    fn invalidate(&self) {
        let mut state = lock_unpoisoned(&self.state);
        let generation = match &*state {
            CameraProfileState::Pending { generation }
            | CameraProfileState::Retrying { generation }
            | CameraProfileState::Failed { generation, .. } => *generation,
            CameraProfileState::Ready(_) => 0,
        };
        *state = CameraProfileState::Failed {
            retry_at: Instant::now(),
            generation,
        };
        self.changed.notify_all();
    }

    #[cfg(test)]
    fn state_name(&self) -> &'static str {
        match &*lock_unpoisoned(&self.state) {
            CameraProfileState::Pending { .. } => "pending",
            CameraProfileState::Ready(_) => "ready",
            CameraProfileState::Failed { .. } => "failed",
            CameraProfileState::Retrying { .. } => "retrying",
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
        let deadline = Instant::now() + timeout;
        let mut queue = lock_unpoisoned(&self.shared.queue);
        let ticket = queue.next_ticket;
        queue.next_ticket = queue.next_ticket.wrapping_add(1);
        queue.waiters.push_back(ticket);

        loop {
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
                return Err(Response::error("camera busy"));
            }
            let waited = self.shared.available.wait_timeout(queue, remaining);
            let (next_queue, timeout_result) = match waited {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            queue = next_queue;
            if timeout_result.timed_out()
                && (queue.active || queue.waiters.front() != Some(&ticket))
            {
                remove_waiter(&mut queue.waiters, ticket);
                self.shared.available.notify_all();
                warn!(
                    timeout_secs = timeout.as_secs(),
                    "Timed out waiting for camera admission"
                );
                return Err(Response::error("camera busy"));
            }
        }
    }

    fn handoff(&self, pending: PendingCameraCleanup, mut lease: CameraLease) -> CleanupMode {
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

impl PanicResponseWriter for ConnectionIo {
    fn response_write_started(&self) -> bool {
        self.response_write_started
    }

    fn write_response(&mut self, response: &Response) -> Result<()> {
        self.response_write_started = true;
        Ok(ipc::send_message(&mut self.stream, response)?)
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
        info!(
            target: PERF_TRACE_TARGET,
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
            "howy_perf startup"
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
    info!(
        target: PERF_TRACE_TARGET,
        outcome,
        phase,
        requested_provider = ?requested_provider,
        defer_camera_stop_enabled,
        async_main_entry_to_outcome_ms = duration_ms(async_main_entered.elapsed()),
        "howy_perf startup"
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
        info!(
            target: PERF_TRACE_TARGET,
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
            "howy_perf authentication"
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

/// Cached user face models with pre-validated flat embeddings.
#[derive(Debug, Clone)]
struct ModelSourceState {
    bin_exists: bool,
    bin_mtime: Option<std::time::SystemTime>,
    json_exists: bool,
    json_mtime: Option<std::time::SystemTime>,
}

struct CachedModels {
    models: UserModels,
    labels: Vec<String>,
    /// Pre-extracted embedding slices for fast matching (no per-auth allocation).
    /// Stored as a flat Vec of 512-float chunks for cache locality.
    flat_embeddings: Arc<Vec<f32>>,
    /// Number of embeddings (flat_embeddings.len() / 512).
    num_embeddings: usize,
    /// Snapshot of both candidate model sources when loaded.
    source_state: ModelSourceState,
}

/// In-memory cache for user face models.
struct ModelCache {
    entries: HashMap<String, CachedModels>,
}

impl ModelCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get cached models for a user. Loads from disk on first access.
    /// Re-loads if model source state changed externally (CLI add/remove/clear).
    fn get_or_load(&mut self, username: &str) -> std::result::Result<&CachedModels, String> {
        // Check if cached entry is stale (preferred source created/updated/deleted externally)
        let stale = if let Some(cached) = self.entries.get(username) {
            is_cache_stale(username, cached)
        } else {
            true // not cached at all
        };

        if stale {
            self.entries.remove(username);

            let (user_models, source_state) = load_user_models_with_state(username)?;
            if user_models.models.is_empty() {
                return Err("no face models enrolled".to_string());
            }

            let cached = build_cached_models(user_models, source_state)?;
            self.entries.insert(username.to_string(), cached);
        }

        Ok(self.entries.get(username).unwrap())
    }

    /// Invalidate cache for a user (call after enrollment/removal).
    fn invalidate(&mut self, username: &str) {
        self.entries.remove(username);
    }
}

fn current_model_source_state(username: &str) -> std::result::Result<ModelSourceState, String> {
    let bin_path =
        paths::user_model_path(username).ok_or_else(|| "invalid username".to_string())?;
    let json_path =
        paths::user_model_path_legacy(username).ok_or_else(|| "invalid username".to_string())?;

    let bin_exists = bin_path.exists();
    let bin_mtime = if bin_exists {
        std::fs::metadata(&bin_path)
            .ok()
            .and_then(|m| m.modified().ok())
    } else {
        None
    };

    let json_exists = json_path.exists();
    let json_mtime = if json_exists {
        std::fs::metadata(&json_path)
            .ok()
            .and_then(|m| m.modified().ok())
    } else {
        None
    };

    Ok(ModelSourceState {
        bin_exists,
        bin_mtime,
        json_exists,
        json_mtime,
    })
}

/// Check if a cached entry is stale by comparing both model source candidates.
fn is_cache_stale(username: &str, cached: &CachedModels) -> bool {
    match current_model_source_state(username) {
        Ok(current) => {
            current.bin_exists != cached.source_state.bin_exists
                || current.bin_mtime != cached.source_state.bin_mtime
                || current.json_exists != cached.source_state.json_exists
                || current.json_mtime != cached.source_state.json_mtime
        }
        Err(_) => true,
    }
}

/// Load user models from disk along with model source state for cache validation.
fn load_user_models_with_state(
    username: &str,
) -> std::result::Result<(UserModels, ModelSourceState), String> {
    let state = current_model_source_state(username)?;

    if state.bin_exists {
        let model_path =
            paths::user_model_path(username).ok_or_else(|| "invalid username".to_string())?;
        let models =
            UserModels::load(&model_path).map_err(|e| format!("failed to load models: {e}"))?;
        return Ok((models, state));
    }

    if state.json_exists {
        let legacy = paths::user_model_path_legacy(username)
            .ok_or_else(|| "invalid username".to_string())?;
        let models =
            UserModels::load(&legacy).map_err(|e| format!("failed to load legacy models: {e}"))?;
        return Ok((models, state));
    }

    Err("no face models enrolled".to_string())
}

fn build_cached_models(
    user_models: UserModels,
    source_state: ModelSourceState,
) -> std::result::Result<CachedModels, String> {
    let mut labels = Vec::with_capacity(user_models.models.len());
    let mut flat = Vec::with_capacity(user_models.models.len() * face::FACE_EMBEDDING_DIM);

    for (idx, model) in user_models.models.iter().enumerate() {
        if model.embedding.len() != face::FACE_EMBEDDING_DIM {
            return Err(format!(
                "model {idx} has wrong embedding dim ({}, expected {})",
                model.embedding.len(),
                face::FACE_EMBEDDING_DIM
            ));
        }

        if model.embedding.iter().any(|value| !value.is_finite()) {
            return Err(format!("model {idx} embedding contains NaN/Inf"));
        }

        labels.push(model.label.clone());
        flat.extend_from_slice(&model.embedding);
    }

    let num_embeddings = user_models.models.len();

    Ok(CachedModels {
        models: user_models,
        labels,
        flat_embeddings: Arc::new(flat),
        num_embeddings,
        source_state,
    })
}

/// Run the daemon server.
pub async fn run(
    engine: Arc<InferenceEngine>,
    config: HowyConfig,
    perf_trace: bool,
    defer_camera_stop: bool,
    startup_trace: Option<StartupPerfTrace>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let start = Instant::now();
    let (camera_admission, mut camera_reaper) = CameraReaper::new()?;
    let model_cache = Arc::new(Mutex::new(ModelCache::new()));

    if shutdown.is_requested() {
        finish_daemon_shutdown(&mut camera_reaper, &mut Vec::new());
        return Ok(());
    }

    // Probe camera in an isolated worker. Kernel open/ioctl calls are not
    // userspace-interruptible, so readiness waits only to a bounded deadline
    // and transfers unresolved ownership to the tracked reaper.
    let camera_probe_started = perf_trace.then(Instant::now);
    let camera_profile = Arc::new(CameraProfileCache::new_pending());
    start_initial_camera_profile_probe(&config, Arc::clone(&camera_profile), &camera_reaper)?;
    let camera_profile_probe = camera_probe_started.map(|started| started.elapsed());
    if shutdown.is_requested() {
        finish_daemon_shutdown(&mut camera_reaper, &mut Vec::new());
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
        listener.set_nonblocking(true)?;
        Ok(listener)
    })();
    let listener = match listener_result {
        Ok(listener) => listener,
        Err(error) => {
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
                let server_accepted = perf_trace.then(Instant::now);
                let engine = Arc::clone(&engine);
                let config = config.clone();
                let camera_admission = camera_admission.clone();
                let model_cache = Arc::clone(&model_cache);
                let camera_profile = Arc::clone(&camera_profile);
                let worker_shutdown = shutdown.clone();
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
                        handle_connection(
                            io,
                            &engine,
                            &config,
                            &camera_admission,
                            &model_cache,
                            &camera_profile,
                            uptime,
                            server_accepted,
                            defer_camera_stop,
                            &worker_shutdown,
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
    finish_daemon_shutdown(&mut camera_reaper, &mut connection_workers);
    Ok(())
}

fn finish_daemon_shutdown(
    camera_reaper: &mut CameraReaper,
    connection_workers: &mut Vec<std::thread::JoinHandle<()>>,
) {
    let connection_workers = shutdown_connection_workers(connection_workers);
    let reaper = camera_reaper.shutdown_bounded();
    let remainder = DaemonShutdownRemainder {
        reaper,
        connection_workers,
        retained_camera_workers: take_retained_camera_workers(),
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

fn start_initial_camera_profile_probe(
    config: &HowyConfig,
    camera_profile: Arc<CameraProfileCache>,
    camera_reaper: &CameraReaper,
) -> Result<()> {
    let handle = spawn_camera_profile_probe(config, camera_profile.clone(), 0)?;
    camera_reaper.track_unleased(PendingCameraCleanup::from_thread_handle(handle));
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
    config: &HowyConfig,
    camera_profile: Arc<CameraProfileCache>,
    generation: u64,
) -> Result<std::thread::JoinHandle<()>> {
    let device_path = config.video.device_path.clone();
    let width = config.video.frame_width;
    let height = config.video.frame_height;
    let fps = config.video.device_fps;
    let exposure = config.video.exposure;
    std::thread::Builder::new()
        .name("howy-camera-profile-probe".to_string())
        .spawn(move || {
            let result = CameraProfile::probe(&device_path, width, height, fps, exposure)
                .map_err(|error| error.to_string());
            camera_profile.complete_probe(generation, result, Instant::now());
        })
        .context("failed to spawn camera profile probe")
}

fn resolve_camera_profile(
    config: &HowyConfig,
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
) -> Result<CameraProfile> {
    let deadline = Instant::now() + CAMERA_PROFILE_PROBE_TIMEOUT;
    loop {
        if let Some(profile) = camera_profile.ready_profile() {
            return Ok(profile);
        }
        match camera_profile.claim(Instant::now()) {
            ProbeClaim::Ready => continue,
            ProbeClaim::Wait => camera_profile.wait_for_change(deadline),
            ProbeClaim::Start(generation) => {
                match spawn_camera_profile_probe(config, Arc::clone(camera_profile), generation) {
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
        }
        if Instant::now() >= deadline {
            bail!(
                "camera profile probe did not become ready within the bounded first-use deadline"
            );
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

/// Handle a single client connection.
fn handle_connection(
    io: &mut ConnectionIo,
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    model_cache: &Mutex<ModelCache>,
    camera_profile: &Arc<CameraProfileCache>,
    uptime: u64,
    server_accepted: Option<Instant>,
    defer_camera_stop: bool,
    shutdown: &ShutdownSignal,
) -> Result<()> {
    configure_initial_io_deadlines(&io.stream)?;

    let request: Request = ipc::recv_message(&mut io.stream)?;
    let peer_uid = get_peer_uid(&io.stream);
    debug!(
        "Received request: {:?}",
        request.cmd.as_ref().map(|cmd| std::mem::discriminant(cmd))
    );

    let mut auth_perf = None;
    let mut deferred_cleanup = None;
    let response = match request.cmd {
        Some(Cmd::Authenticate(req)) => {
            let mut perf =
                server_accepted.map(|accepted| AuthPerfTrace::new(accepted, defer_camera_stop));
            if !is_valid_username(&req.username) {
                auth_perf = perf;
                Response::error("invalid username")
            } else if !can_access_username(peer_uid, &req.username) {
                auth_perf = perf;
                Response::error("permission denied")
            } else {
                let result = handle_authenticate(
                    engine,
                    config,
                    camera_admission,
                    model_cache,
                    camera_profile,
                    &req.username,
                    req.timeout,
                    perf.as_mut(),
                );
                deferred_cleanup = result.deferred_cleanup;
                auth_perf = perf;
                result.response
            }
        }
        Some(Cmd::Enroll(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                handle_enroll(
                    engine,
                    config,
                    camera_admission,
                    model_cache,
                    camera_profile,
                    &req.username,
                    &req.label,
                )
            }
        }
        Some(Cmd::EnrollBatch(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                handle_enroll_batch(
                    engine,
                    model_cache,
                    &req.username,
                    &req.session_dir,
                    &req.label,
                )
            }
        }
        Some(Cmd::Detect(req)) => {
            if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                handle_detect(engine, &req.frame, req.height, req.width)
            }
        }
        Some(Cmd::Ping(_)) => Response::pong(),
        Some(Cmd::Info(_)) => {
            let provider = engine.registered_preferred_provider().to_string();
            let detector_model = engine.detector_model_path();
            let recognizer_model = engine.recognizer_model_path();
            Response::daemon_info(&provider, &detector_model, &recognizer_model, 512, uptime)
        }
        Some(Cmd::Shutdown(_)) => {
            if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                info!("Shutdown requested");
                handle_root_shutdown(io, shutdown)?;
                return Ok(());
            }
        }
        Some(Cmd::CheckCredential(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if !can_access_username(peer_uid, &req.username) {
                Response::error("permission denied")
            } else {
                handle_check_credential(config, &req.username)
            }
        }
        Some(Cmd::RevokeCredential(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if !can_access_username(peer_uid, &req.username) {
                Response::error("permission denied")
            } else {
                handle_revoke_credential(config, &req.username, &req.session_id)
            }
        }
        None => Response::error("empty request"),
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
    stream.set_read_timeout(Some(INITIAL_REQUEST_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))
}

/// Open a camera from the cached profile, probing lazily if needed.
fn open_camera_from_profile_cache(
    config: &HowyConfig,
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
) -> Result<Camera> {
    let profile = resolve_camera_profile(config, camera_profile, camera_admission)?;
    Ok(Camera::from_profile(&profile))
}

/// Open a camera from the cached profile and start it, invalidating and
/// re-probing the profile once if startup fails.
fn open_started_camera_from_profile_cache(
    config: &HowyConfig,
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
) -> Result<Camera> {
    let mut first_error = None;
    for attempt in 0..2 {
        let mut camera = open_camera_from_profile_cache(config, camera_profile, camera_admission)?;
        match camera.start() {
            Ok(()) => return Ok(camera),
            Err(error) if attempt == 0 => {
                first_error = Some(error);
                let _ = camera.stop();
                drop(camera);
                camera_profile.invalidate();
            }
            Err(error) => {
                return Err(error).context("failed to start camera capture worker after reprobe");
            }
        }
    }
    Err(first_error.unwrap()).context("failed to start camera capture worker")
}

/// Capture a frame, releasing the old worker/device before one bounded reprobe.
fn capture_frame_bounded(
    camera: &mut Camera,
    config: &HowyConfig,
    camera_profile: &Arc<CameraProfileCache>,
    camera_admission: &CameraAdmission,
    mut perf: Option<&mut AuthPerfTrace>,
) -> Result<Frame> {
    match camera.capture_frame() {
        Ok(frame) => Ok(frame),
        Err(first_err) => {
            warn!(error = %first_err, "Camera capture failed; releasing ownership before one bounded reprobe");
            if let Err(stop_error) = stop_camera_for_restart(camera, perf.as_deref_mut()) {
                // The admission lease remains held by the pending cleanup, so
                // invalidation cannot trigger a reprobe until ownership exits.
                camera_profile.invalidate();
                return Err(stop_error).context("camera capture failed with cleanup pending");
            }
            camera_profile.invalidate();
            let mut retry =
                open_started_camera_from_profile_cache(config, camera_profile, camera_admission)
                    .context("camera reprobe after capture failure failed")?;
            match retry.capture_frame() {
                Ok(frame) => {
                    *camera = retry;
                    Ok(frame)
                }
                Err(retry_error) => {
                    let stop_started = perf.as_ref().map(|_| Instant::now());
                    let retry_stop = retry.stop();
                    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), stop_started) {
                        perf.camera_stop_call += started.elapsed();
                    }
                    match retry_stop {
                        CameraStopOutcome::Pending(pending) => {
                            // Preserve the request's admission lease until the
                            // retry worker is handed to the normal cleanup reaper.
                            camera.retain_pending_cleanup(pending);
                        }
                        CameraStopOutcome::FailedPanicked => {
                            error!("Retried camera worker panicked while stopping");
                        }
                        CameraStopOutcome::Released => {}
                    }
                    Err(retry_error).context(format!(
                        "camera capture failed after one reprobe; first failure: {first_err}"
                    ))
                }
            }
        }
    }
}

fn stop_camera_for_restart(camera: &mut Camera, perf: Option<&mut AuthPerfTrace>) -> Result<()> {
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
    camera: Camera,
    lease: Option<CameraLease>,
    admission: CameraAdmission,
}

struct CleanupReport {
    mode: CleanupMode,
    stop_duration: Duration,
}

impl CameraCleanup {
    fn finish(mut self, _admission: &CameraAdmission, _wait_for_reaper: bool) -> CleanupReport {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> CleanupReport {
        let stop_started = Instant::now();
        let outcome = self.camera.stop();
        let stop_duration = stop_started.elapsed();
        let lease = self.lease.take().expect("camera cleanup lease is present");

        let mode = match outcome {
            CameraStopOutcome::Released => {
                drop(lease);
                CleanupMode::Synchronous
            }
            CameraStopOutcome::FailedPanicked => {
                drop(lease);
                CleanupMode::FailedPanicked
            }
            CameraStopOutcome::Pending(pending) => self.admission.handoff(pending, lease),
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
            let report = self.finish_inner();
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
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    model_cache: &Mutex<ModelCache>,
    camera_profile: &Arc<CameraProfileCache>,
    username: &str,
    timeout_override: u32,
    mut perf: Option<&mut AuthPerfTrace>,
) -> AuthenticationResult {
    if !is_valid_username(username) {
        return AuthenticationResult::immediate(Response::error("invalid username"));
    }

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
    let cached_models = {
        let mut cache = lock_model_cache(model_cache);
        cache.get_or_load(username).map(|cached| {
            (
                cached.labels.clone(),
                Arc::clone(&cached.flat_embeddings),
                cached.num_embeddings,
            )
        })
    };
    if let (Some(perf), Some(started)) = (perf.as_deref_mut(), model_load_started) {
        perf.model_load_cache = started.elapsed();
    }
    let (labels, flat_embeddings, num_embeddings) = match cached_models {
        Ok(cached) => cached,
        Err(msg) => return AuthenticationResult::immediate(Response::auth_failed(0.0, 0, &msg)),
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
        config,
        camera_profile,
        camera_admission,
    ) {
        Ok(camera) => camera,
        Err(e) => {
            warn!(username, error = %e, "Authentication infrastructure failure opening/starting camera");
            return AuthenticationResult::immediate(Response::error(&format!("Camera error: {e}")));
        }
    };
    let mut cleanup = CameraCleanup {
        camera,
        lease: Some(camera_lease),
        admission: camera_admission.clone(),
    };

    let deadline = Duration::from_secs(timeout as u64);
    let mut frames_processed = 0u32;
    let mut best_score = 0.0f32;
    let mut dark_frames = 0u32;

    // Main recognition loop
    while start.elapsed() < deadline {
        // Capture frame
        let frame = match capture_frame_bounded(
            &mut cleanup.camera,
            config,
            camera_profile,
            camera_admission,
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
                    &flat_embeddings,
                    num_embeddings,
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

                    info!(
                        username,
                        model_index = match_idx,
                        model_label = %labels[match_idx],
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
                        Response::success(match_idx as u32, &labels[match_idx], score, elapsed_ms);
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
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_admission: &CameraAdmission,
    model_cache: &Mutex<ModelCache>,
    camera_profile: &Arc<CameraProfileCache>,
    username: &str,
    label: &str,
) -> Response {
    if !is_valid_username(username) {
        return Response::error("invalid username");
    }

    let camera_lease = match camera_admission.acquire(CAMERA_LOCK_TIMEOUT) {
        Ok(guard) => guard,
        Err(response) => return response,
    };

    let camera = match open_started_camera_from_profile_cache(
        config,
        camera_profile,
        camera_admission,
    ) {
        Ok(camera) => camera,
        Err(e) => {
            warn!(username, error = %e, "Enrollment infrastructure failure opening/starting camera");
            return Response::error(&format!("Camera error: {e}"));
        }
    };
    let mut cleanup = CameraCleanup {
        camera,
        lease: Some(camera_lease),
        admission: camera_admission.clone(),
    };

    // Capture several frames and pick the best face
    let mut best_face: Option<(Vec<f32>, f32)> = None;
    let deadline = Duration::from_secs(5);
    let start = Instant::now();

    while start.elapsed() < deadline {
        let frame = match capture_frame_bounded(
            &mut cleanup.camera,
            config,
            camera_profile,
            camera_admission,
            None,
        ) {
            Ok(frame) => frame,
            Err(e) => {
                warn!(username, error = %e, "Enrollment infrastructure failure capturing frame");
                finish_camera_cleanup_before_response(cleanup, camera_admission, None);
                return Response::error(&format!("Camera capture failed: {e}"));
            }
        };

        if is_dark_frame(&frame, config.video.dark_threshold) {
            continue;
        }

        let is_gray = frame.format == FrameFormat::Gray;
        match engine.analyze(&frame.data, frame.width, frame.height, is_gray) {
            Ok(faces) => {
                for face_result in &faces {
                    if let Some(ref emb) = face_result.embedding {
                        let det_score = face_result.score;
                        if best_face.is_none() || det_score > best_face.as_ref().unwrap().1 {
                            best_face = Some((emb.clone(), det_score));
                        }
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

    let response = match best_face {
        Some((embedding, det_score)) => {
            let mut cache = lock_model_cache(model_cache);
            cache.invalidate(username);
            info!(username, label, det_score, "Face enrolled");
            Response::enrolled(embedding, det_score)
        }
        None => Response::error("No face detected during enrollment"),
    };
    finish_camera_cleanup_before_response(cleanup, camera_admission, None);
    response
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
    engine: &InferenceEngine,
    model_cache: &Mutex<ModelCache>,
    username: &str,
    session_dir: &str,
    label: &str,
) -> Response {
    if !is_valid_username(username) {
        return Response::error("invalid username");
    }

    let dir = std::path::Path::new(session_dir);
    if !dir.is_dir() {
        return Response::error(&format!("session directory not found: {session_dir}"));
    }

    let start = std::time::Instant::now();

    // Collect image files, sorted by name
    let mut image_files: Vec<std::path::PathBuf> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    match ext.to_ascii_lowercase().as_str() {
                        "png" | "jpg" | "jpeg" | "bmp" => image_files.push(path),
                        _ => {}
                    }
                }
            }
        }
        Err(e) => {
            return Response::error(&format!("failed to read session directory: {e}"));
        }
    }
    image_files.sort();

    let frames_found = image_files.len() as u32;
    if frames_found == 0 {
        return Response::error("no image files found in session directory");
    }

    // Reject symlinks and non-regular files in the session directory
    for image_path in &image_files {
        match std::fs::symlink_metadata(image_path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
                let name = image_path.file_name().unwrap_or_default().to_string_lossy();
                return Response::error(&format!(
                    "session directory contains non-regular file: {name}"
                ));
            }
            Err(e) => {
                let name = image_path.file_name().unwrap_or_default().to_string_lossy();
                return Response::error(&format!("cannot stat {name}: {e}"));
            }
            _ => {}
        }
    }

    // Load or create user models — fail hard on corrupt files to avoid
    // silently overwriting existing enrollments.
    let model_path = match paths::user_model_path(username) {
        Some(p) => p,
        None => return Response::error("invalid username"),
    };
    let mut user_models = {
        let cache = lock_model_cache(model_cache);

        if let Some(cached) = cache.entries.get(username) {
            if !is_cache_stale(username, cached) {
                cached.models.clone()
            } else {
                let existing_source_state = match current_model_source_state(username) {
                    Ok(state) => state,
                    Err(e) => return Response::error(&e),
                };

                if existing_source_state.bin_exists || existing_source_state.json_exists {
                    match load_user_models_with_state(username) {
                        Ok((models, _)) => models,
                        Err(e) => {
                            return Response::error(&format!(
                                "{e} (refusing to overwrite existing enrollments)"
                            ));
                        }
                    }
                } else {
                    UserModels::new(username)
                }
            }
        } else {
            let existing_source_state = match current_model_source_state(username) {
                Ok(state) => state,
                Err(e) => return Response::error(&e),
            };

            if existing_source_state.bin_exists || existing_source_state.json_exists {
                match load_user_models_with_state(username) {
                    Ok((models, _)) => models,
                    Err(e) => {
                        return Response::error(&format!(
                            "{e} (refusing to overwrite existing enrollments)"
                        ));
                    }
                }
            } else {
                UserModels::new(username)
            }
        }
    };

    let mut frames_accepted = 0u32;
    let mut frames_rejected = 0u32;
    let mut rejection_details: Vec<String> = Vec::new();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for image_path in &image_files {
        let file_name = image_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Load and decode image to BGR
        let bgr_result = load_image_as_bgr(image_path);
        let (bgr_data, width, height) = match bgr_result {
            Ok(data) => data,
            Err(e) => {
                frames_rejected += 1;
                rejection_details.push(format!("{file_name}: failed to load: {e}"));
                continue;
            }
        };

        // Detect faces
        let faces = match engine.analyze(&bgr_data, width, height, false) {
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

        let face = &faces[0];
        if face.score < 0.5 {
            frames_rejected += 1;
            rejection_details.push(format!(
                "{file_name}: detection score too low ({:.2})",
                face.score
            ));
            continue;
        }

        match &face.embedding {
            Some(embedding) => {
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

                user_models.models.push(face::FaceModel {
                    label: label.to_string(),
                    created: now,
                    embedding: embedding.clone(),
                });
                frames_accepted += 1;
                info!(
                    username,
                    file = %file_name,
                    det_score = face.score,
                    "Enrolled frame"
                );
            }
            None => {
                frames_rejected += 1;
                rejection_details.push(format!("{file_name}: no embedding computed"));
            }
        }
    }

    // Save models to disk
    if frames_accepted > 0 {
        if let Some(parent) = model_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Response::error(&format!("failed to create models directory: {e}"));
            }
        }
        if let Err(e) = user_models.save(&model_path) {
            return Response::error(&format!("failed to save models: {e}"));
        }

        let mut cache = lock_model_cache(model_cache);
        cache.invalidate(username);

        info!(
            username,
            label,
            frames_accepted,
            total_models = user_models.models.len(),
            "Batch enrollment complete"
        );
    }

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    Response::enroll_batch_done(
        frames_found,
        frames_accepted,
        frames_rejected,
        elapsed_ms,
        rejection_details,
    )
}

/// Handle a detection-only request (for testing).
fn handle_detect(engine: &InferenceEngine, frame: &[u8], height: u32, width: u32) -> Response {
    let start = Instant::now();

    match engine.analyze(frame, width, height, false) {
        Ok(faces) => Response {
            result: Some(RespResult::Detected(protocol::DetectResult {
                faces: faces
                    .into_iter()
                    .map(|face| protocol::DetectedFace {
                        x1: face.bbox[0],
                        y1: face.bbox[1],
                        x2: face.bbox[2],
                        y2: face.bbox[3],
                        landmarks: face.landmarks.to_vec(),
                        score: face.score,
                        embedding: face.embedding.unwrap_or_default(),
                    })
                    .collect(),
                elapsed_ms: start.elapsed().as_secs_f64() * 1000.0,
            })),
        },
        Err(e) => Response::error(&format!("Detection error: {e}")),
    }
}

/// Handle credential check request.
fn handle_check_credential(config: &HowyConfig, username: &str) -> Response {
    if !is_valid_username(username) {
        return Response::error("invalid username");
    }

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
    if !is_valid_username(username) {
        return Response::error("invalid username");
    }

    if !credential_cache_runtime_enabled(config) {
        let _ = (config, session_id);
        return Response::pong();
    }

    match credential::revoke_credential(username, session_id, &config.credentials) {
        Ok(()) => Response::pong(),
        Err(e) => Response::error(&format!("Failed to revoke credential: {e}")),
    }
}

/// Runtime credential caching is intentionally disabled for the first PAM
/// deployment. This prevents empty or synthetic session IDs from creating
/// reusable auth success across unrelated PAM calls.
fn credential_cache_runtime_enabled(_config: &HowyConfig) -> bool {
    false
}

fn lock_model_cache<'a>(model_cache: &'a Mutex<ModelCache>) -> MutexGuard<'a, ModelCache> {
    match model_cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("model cache poisoned; proceeding anyway");
            poisoned.into_inner()
        }
    }
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

/// Load an image file from disk and convert to BGR pixel data.
fn load_image_as_bgr(path: &std::path::Path) -> anyhow::Result<(Vec<u8>, u32, u32)> {
    let img =
        image::open(path).with_context(|| format!("failed to open image: {}", path.display()))?;
    let rgb = img.to_rgb8();
    let width = rgb.width();
    let height = rgb.height();

    // Convert RGB to BGR
    let mut bgr = Vec::with_capacity((width * height * 3) as usize);
    for pixel in rgb.pixels() {
        bgr.push(pixel[2]);
        bgr.push(pixel[1]);
        bgr.push(pixel[0]);
    }

    Ok((bgr, width, height))
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

    // fd 3 is the first passed socket
    use std::os::unix::io::FromRawFd;
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    Some(listener)
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

fn is_valid_username(username: &str) -> bool {
    paths::validate_username(username)
}

fn can_access_username(peer_uid: Option<u32>, username: &str) -> bool {
    let peer_uid = match peer_uid {
        Some(uid) => uid,
        None => return false,
    };

    if peer_uid == 0 {
        return true;
    }

    lookup_username_uid(username) == Some(peer_uid)
}

fn lookup_username_uid(username: &str) -> Option<u32> {
    let c_username = std::ffi::CString::new(username).ok()?;
    let _guard = match PASSWD_LOOKUP_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    let passwd = unsafe { libc::getpwnam(c_username.as_ptr()) };
    if passwd.is_null() {
        None
    } else {
        Some(unsafe { (*passwd).pw_uid as u32 })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CameraProfileCache, CameraReaper, CleanupMode, CleanupReport, CleanupTask,
        ConnectionAccounting, MAX_CONNECTION_WORKERS, PanicResponseWriter, ResponseCleanupOrder,
        ShutdownSignal, auth_outcome, configure_initial_io_deadlines, coordinate_response_cleanup,
        dispatch_with_panic_boundary, enqueue_cleanup_task, finish_or_track_unleased_worker,
        handle_root_shutdown, lock_unpoisoned, reap_finished_connection_workers,
        release_camera_admission, shutdown_connection_workers_with_timeout,
        successful_response_cleanup_order, with_connection_permit,
    };
    use crate::camera::{CameraProfile, PendingCameraCleanup, WorkerExit};
    use howy_common::protocol::Response;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Weak, mpsc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn camera_profile_busy_at_start_enters_retryable_failure() {
        let cache = CameraProfileCache::new_pending();
        cache.complete_probe(0, Err("device busy".into()), std::time::Instant::now());
        assert_eq!(cache.state_name(), "failed");
        assert!(cache.ready_profile().is_none());
    }

    #[test]
    fn slow_camera_profile_success_becomes_usable_after_initial_bound() {
        let cache = Arc::new(CameraProfileCache::new_pending());
        let worker_cache = Arc::clone(&cache);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            worker_cache.complete_probe(
                0,
                Ok(CameraProfile::test_profile("slow")),
                std::time::Instant::now(),
            );
        });
        assert_eq!(cache.state_name(), "pending");
        worker.join().unwrap();
        assert_eq!(cache.state_name(), "ready");
        assert!(cache.ready_profile().is_some());
    }

    #[test]
    fn failed_camera_profile_allows_bounded_retry() {
        let cache = CameraProfileCache::new_pending();
        cache.complete_probe(0, Err("disconnected".into()), std::time::Instant::now());
        assert_eq!(
            cache.claim(std::time::Instant::now()),
            super::ProbeClaim::Wait
        );
        thread::sleep(super::CAMERA_PROFILE_RETRY_BACKOFF + Duration::from_millis(5));
        let super::ProbeClaim::Start(generation) = cache.claim(std::time::Instant::now()) else {
            panic!("retry was not claimed");
        };
        assert_eq!(cache.state_name(), "retrying");
        cache.complete_probe(
            generation,
            Ok(CameraProfile::test_profile("reconnected")),
            std::time::Instant::now(),
        );
        assert_eq!(cache.state_name(), "ready");
    }

    #[test]
    fn camera_profile_invalidation_permits_one_reprobe() {
        let cache = CameraProfileCache::new_pending();
        cache.complete_probe(
            0,
            Ok(CameraProfile::test_profile("stale")),
            std::time::Instant::now(),
        );
        cache.invalidate();
        assert_eq!(cache.state_name(), "failed");
        assert!(matches!(
            cache.claim(std::time::Instant::now()),
            super::ProbeClaim::Start(_)
        ));
        assert_eq!(cache.state_name(), "retrying");
    }

    #[test]
    fn disconnect_then_reconnect_transitions_failed_retrying_ready() {
        let cache = CameraProfileCache::new_pending();
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
        let cache = Arc::new(CameraProfileCache::new_pending());
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
        assert_eq!(cache.state_name(), "retrying");
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
        assert_eq!(
            stream.read_timeout().unwrap(),
            Some(super::INITIAL_REQUEST_READ_TIMEOUT)
        );
        assert_eq!(super::INITIAL_REQUEST_READ_TIMEOUT, Duration::from_secs(2));
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
