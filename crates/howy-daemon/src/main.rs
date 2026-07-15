//! howyd — the howy face authentication daemon.
//!
//! Preloads SCRFD (detection) and ArcFace (recognition) ONNX models at startup,
//! warms them with a dummy inference pass, then listens on a Unix domain socket
//! for authentication requests from the PAM module and CLI. A dedicated
//! `--prewarm-only` mode is also available for install-time MIGraphX cache priming.
//!
//! Supports systemd socket activation and credential loading.

use std::cell::Cell;
use std::env;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
use howy_common::env::parse_strict_bool;
use howy_common::paths::CONFIG_FILE;
use howy_common::provisioning::{
    MODE1_CREDENTIAL_NAME, RecognizerIdentity, Sha256Digest, VerifierResultV1,
};
use howy_common::storage::{CancellationSignal, PlaintextBudget, StorageBackend};
use howy_daemon::storage::{
    Mode1StorageBackend, Mode1StorageLimits, ModelCacheLimits, PlaintextStorageBackend,
    PlaintextStorageLimits,
    readiness::{
        OpenedConfig, OpenedDaemonBinary, ReadinessDeadline, StrongRecognizerBinding,
        new_invocation_id_cancellable, open_daemon_binary_identity_cancellable,
        open_daemon_config_cancellable, verify_mode1_namespace,
    },
};
use howy_daemon::{
    child_spawn::{self, DaemonChildPolicy},
    inference,
    mode1_key::{
        StartupKeyContext, load_readiness_key_context, load_startup_key_context,
        probe_model_credential_guard,
    },
    prompt_state::PromptTransactionManager,
    server,
};

const PREWARM_MARKER_PATH: &str = "/var/cache/howy/prewarm-status.txt";
const MAX_DAEMON_ERROR_BYTES: usize = 4_096;
const MAX_VERIFIER_OUTPUT_BYTES: usize = 4_096;
const DAEMON_ERROR_PREFIX: &str = "howyd: ";
const VERIFIER_PANIC_LINE: &[u8] = b"howyd: strong-readiness/panic: verifier panic contained\n";
const VERIFIER_STATE_LINE: &[u8] = b"howyd: strong-readiness/panic: verifier state unavailable\n";
const PANIC_MODE_INACTIVE: u8 = 0;
const PANIC_MODE_ARMED: u8 = 1;
const PANIC_MODE_REPORTED: u8 = 2;
static VERIFIER_PANIC_HOOK: Once = Once::new();
std::thread_local! {
    static VERIFIER_PANIC_MODE: Cell<u8> = const { Cell::new(PANIC_MODE_INACTIVE) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Serve,
    PrewarmOnly,
    StorageReadinessOnly,
    ValidateFfmpegAccount,
}

#[derive(Debug, Eq, PartialEq)]
struct RunOptions {
    mode: RunMode,
    config_path: Option<PathBuf>,
    verify_records: bool,
}

struct InferenceStartup {
    engine: inference::InferenceEngine,
    requested_provider: String,
    registered_preferred_provider: String,
    explicit_cpu_retry: bool,
    provider_initialization_attempt_count: u32,
    discarded_provider_initialization_count: u32,
    detector_warmup: Duration,
    recognizer_warmup: Duration,
}

fn normalize_provider(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn registered_preference_is_cpu(requested_provider: &str, registered_preference: &str) -> bool {
    normalize_provider(requested_provider) != "cpu"
        && normalize_provider(registered_preference) == "cpu"
}

fn should_write_accelerator_prewarm_marker(
    requested_provider: &str,
    registered_preference: &str,
    explicit_cpu_retry: bool,
) -> bool {
    matches!(
        normalize_provider(requested_provider).as_str(),
        "migraphx" | "auto"
    ) && !explicit_cpu_retry
        && normalize_provider(registered_preference) == "migraphx"
}

fn print_usage(program: &str) {
    println!(
        "Usage: {program} [--prewarm-only | --storage-readiness-only [--verify-records --config <absolute-candidate-path>] | --validate-ffmpeg-account]"
    );
}

fn parse_run_options() -> Result<RunOptions> {
    parse_run_options_from(env::args_os())
}

fn parse_run_options_from(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<RunOptions> {
    let mut mode = RunMode::Serve;
    let mut config_path = None;
    let mut verify_records = false;
    let mut help = false;
    let mut run_argument_seen = false;
    let mut args = arguments.into_iter();
    let program = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .unwrap_or_else(|| "howyd".to_string());

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--prewarm-only") if mode == RunMode::Serve => {
                run_argument_seen = true;
                mode = RunMode::PrewarmOnly;
            }
            Some("--storage-readiness-only") if mode == RunMode::Serve => {
                run_argument_seen = true;
                mode = RunMode::StorageReadinessOnly
            }
            Some("--validate-ffmpeg-account") if mode == RunMode::Serve => {
                run_argument_seen = true;
                mode = RunMode::ValidateFfmpegAccount
            }
            Some("--verify-records") if !verify_records => {
                run_argument_seen = true;
                verify_records = true;
            }
            Some("--verify-records") => bail!("--verify-records may be specified only once"),
            Some("--config") if config_path.is_none() => {
                run_argument_seen = true;
                let candidate = args
                    .next()
                    .context("--config requires an absolute candidate path")?;
                let candidate = PathBuf::from(candidate);
                validate_candidate_argument(&candidate)?;
                config_path = Some(candidate);
            }
            Some("--config") => bail!("--config may be specified only once"),
            Some("--prewarm-only" | "--storage-readiness-only" | "--validate-ffmpeg-account") => {
                bail!("only one daemon run mode may be selected")
            }
            Some("-h") | Some("--help") if !help => help = true,
            Some("-h") | Some("--help") => bail!("--help may be specified only once"),
            Some(_) => bail!("unknown daemon argument"),
            None => bail!("howyd does not support non-UTF-8 arguments"),
        }
    }

    if help {
        if run_argument_seen {
            bail!("--help cannot be combined with a daemon run mode");
        }
        print_usage(&program);
        std::process::exit(0);
    }

    let readiness_mode = mode == RunMode::StorageReadinessOnly;
    let has_candidate = config_path.is_some();
    if readiness_mode && has_candidate != verify_records {
        bail!("strong readiness requires --config and --verify-records together");
    }
    if !readiness_mode && (has_candidate || verify_records) {
        bail!("--config and --verify-records require --storage-readiness-only");
    }
    Ok(RunOptions {
        mode,
        config_path,
        verify_records,
    })
}

fn validate_candidate_argument(path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() < 2
        || bytes.len() > howy_common::provisioning::MAX_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.get(1) == Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.windows(2).any(|window| window == b"//")
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("--config requires a canonical absolute candidate path");
    }
    Ok(())
}

fn serialize_strong_readiness_result(verifier: &VerifierResultV1) -> Result<Vec<u8>> {
    let mut output = verifier.deterministic_bytes()?;
    output.push(b'\n');
    // Keep one success object within the protocol cap. Emission separately
    // queries the actual pipe/FIFO PIPE_BUF before its sole nonblocking write.
    if output.len() > MAX_VERIFIER_OUTPUT_BYTES {
        bail!("strong readiness result exceeds the atomic output bound");
    }
    Ok(output)
}

fn bounded_error_message(error: &anyhow::Error) -> String {
    let mut message = format!("{error:#}").replace(['\r', '\n'], " ");
    let maximum = MAX_DAEMON_ERROR_BYTES
        .saturating_sub(DAEMON_ERROR_PREFIX.len())
        .saturating_sub(1);
    if message.len() <= maximum {
        return message;
    }
    let mut end = maximum.saturating_sub(3);
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    message.truncate(end);
    message.push_str("...");
    message
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrongReadinessFailure {
    Deadline,
    Identity,
    Config,
    Credential,
    Verification,
    Output,
}

impl StrongReadinessFailure {
    fn stable_message(self) -> &'static str {
        match self {
            Self::Deadline => "strong-readiness/deadline: operation deadline exceeded",
            Self::Identity => "strong-readiness/identity: verifier identity rejected",
            Self::Config => "strong-readiness/config: candidate configuration rejected",
            Self::Credential => "strong-readiness/credential: credential delivery rejected",
            Self::Verification => "strong-readiness/verification: namespace verification failed",
            Self::Output => "strong-readiness/output: atomic verifier output failed",
        }
    }

    fn stable_line(self) -> &'static [u8] {
        match self {
            Self::Deadline => b"howyd: strong-readiness/deadline: operation deadline exceeded\n",
            Self::Identity => b"howyd: strong-readiness/identity: verifier identity rejected\n",
            Self::Config => b"howyd: strong-readiness/config: candidate configuration rejected\n",
            Self::Credential => {
                b"howyd: strong-readiness/credential: credential delivery rejected\n"
            }
            Self::Verification => {
                b"howyd: strong-readiness/verification: namespace verification failed\n"
            }
            Self::Output => b"howyd: strong-readiness/output: atomic verifier output failed\n",
        }
    }
}

enum DaemonRunFailure {
    General(anyhow::Error),
}

impl From<anyhow::Error> for DaemonRunFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::General(error)
    }
}

fn install_verifier_panic_hook() {
    VERIFIER_PANIC_HOOK.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let mode = VERIFIER_PANIC_MODE
                .try_with(|mode| {
                    let current = mode.get();
                    if current == PANIC_MODE_ARMED {
                        mode.set(PANIC_MODE_REPORTED);
                    }
                    current
                })
                .unwrap_or(PANIC_MODE_INACTIVE);
            match mode {
                PANIC_MODE_ARMED => write_static_stderr(VERIFIER_PANIC_LINE),
                PANIC_MODE_REPORTED => {}
                _ => default_hook(info),
            }
        }));
    });
}

/// Write one bounded static line without formatting, allocation, or panicking.
/// O_NONBLOCK makes a full pipe a bounded best-effort failure rather than a
/// verifier hang. All descriptor errors and partial writes are ignored.
fn write_static_stderr(line: &'static [u8]) {
    let descriptor = libc::STDERR_FILENO;
    // SAFETY: fcntl and write receive a process descriptor and a valid static
    // byte range. No Rust references are created from foreign memory.
    unsafe {
        let flags = libc::fcntl(descriptor, libc::F_GETFL);
        if flags < 0 {
            return;
        }
        let changed = flags & libc::O_NONBLOCK == 0;
        if changed && libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return;
        }
        libc::write(descriptor, line.as_ptr().cast(), line.len());
        if changed {
            libc::fcntl(descriptor, libc::F_SETFL, flags);
        }
    }
}

fn report_strong_failure(failure: StrongReadinessFailure) {
    let claimed = VERIFIER_PANIC_MODE
        .try_with(|mode| {
            if mode.get() == PANIC_MODE_ARMED {
                mode.set(PANIC_MODE_REPORTED);
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if claimed {
        write_static_stderr(failure.stable_line());
    }
}

struct VerifierPanicModeGuard;

impl VerifierPanicModeGuard {
    fn arm() -> Option<Self> {
        VERIFIER_PANIC_MODE
            .try_with(|mode| {
                if mode.get() != PANIC_MODE_INACTIVE {
                    return false;
                }
                mode.set(PANIC_MODE_ARMED);
                true
            })
            .ok()
            .filter(|armed| *armed)
            .map(|_| Self)
    }
}

impl Drop for VerifierPanicModeGuard {
    fn drop(&mut self) {
        let _ = VERIFIER_PANIC_MODE.try_with(|mode| mode.set(PANIC_MODE_INACTIVE));
    }
}

fn readiness_phase<T>(
    result: Result<T>,
    cancellation: &dyn CancellationSignal,
    failure: StrongReadinessFailure,
) -> std::result::Result<T, StrongReadinessFailure> {
    if cancellation.is_cancelled() {
        return Err(StrongReadinessFailure::Deadline);
    }
    match result {
        Ok(value) => Ok(value),
        Err(_) => Err(failure),
    }
}

trait AtomicPipeIo {
    fn is_pipe_or_fifo(&mut self, fd: RawFd) -> io::Result<bool>;
    fn pipe_buf(&mut self, fd: RawFd) -> io::Result<usize>;
    fn get_flags(&mut self, fd: RawFd) -> io::Result<i32>;
    fn set_flags(&mut self, fd: RawFd, flags: i32) -> io::Result<()>;
    fn write_once(&mut self, fd: RawFd, bytes: &[u8]) -> io::Result<usize>;
}

struct SystemAtomicPipeIo;

impl AtomicPipeIo for SystemAtomicPipeIo {
    fn is_pipe_or_fifo(&mut self, fd: RawFd) -> io::Result<bool> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        let result = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(stat.st_mode & libc::S_IFMT == libc::S_IFIFO)
    }

    fn pipe_buf(&mut self, fd: RawFd) -> io::Result<usize> {
        let value = unsafe { libc::fpathconf(fd, libc::_PC_PIPE_BUF) };
        if value <= 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(value).map_err(|_| io::Error::other("invalid pipe atomicity bound"))
    }

    fn get_flags(&mut self, fd: RawFd) -> io::Result<i32> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(flags)
        }
    }

    fn set_flags(&mut self, fd: RawFd, flags: i32) -> io::Result<()> {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn write_once(&mut self, fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
        let mut action = std::mem::MaybeUninit::<libc::sigaction>::zeroed();
        let action_pointer = action.as_mut_ptr();
        unsafe {
            (*action_pointer).sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut (*action_pointer).sa_mask);
            (*action_pointer).sa_flags = 0;
            if libc::sigaction(libc::SIGPIPE, action_pointer, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let result = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(result).map_err(|_| io::Error::other("invalid write result"))
        }
    }
}

fn emit_atomic_pipe_with(
    io: &mut impl AtomicPipeIo,
    fd: RawFd,
    bytes: &[u8],
    cancellation: &dyn CancellationSignal,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_VERIFIER_OUTPUT_BYTES {
        bail!("verifier output is outside the atomic bound");
    }
    if cancellation.is_cancelled() {
        bail!("verifier deadline expired before output");
    }
    if !io.is_pipe_or_fifo(fd)? {
        bail!("verifier output descriptor rejected");
    }
    if cancellation.is_cancelled() {
        bail!("verifier deadline expired before output");
    }
    let pipe_buf = io.pipe_buf(fd)?;
    if cancellation.is_cancelled() {
        bail!("verifier deadline expired before output");
    }
    if bytes.len() > pipe_buf {
        bail!("verifier output exceeds descriptor atomicity bound");
    }
    let flags = io.get_flags(fd)?;
    if cancellation.is_cancelled() {
        bail!("verifier deadline expired before output");
    }
    io.set_flags(fd, flags | libc::O_NONBLOCK)?;
    if cancellation.is_cancelled() {
        bail!("verifier deadline expired before output");
    }
    // Linux guarantees all-or-EAGAIN for nonblocking pipe/FIFO writes no
    // larger than PIPE_BUF. This is the sole verifier stdout write.
    if io.write_once(fd, bytes)? != bytes.len() {
        bail!("atomic verifier write was not complete");
    }
    Ok(())
}

fn emit_atomic_stdout(bytes: &[u8], cancellation: &dyn CancellationSignal) -> Result<()> {
    emit_atomic_pipe_with(
        &mut SystemAtomicPipeIo,
        libc::STDOUT_FILENO,
        bytes,
        cancellation,
    )
}

fn set_private_process_umask() {
    // SAFETY: umask changes process creation policy and has no pointer/lifetime requirements.
    unsafe { libc::umask(0o077) };
}

fn install_signal_forwarder(
    shutdown: server::ShutdownSignal,
) -> Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).context("failed to register SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("failed to register SIGINT")?;
    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = terminate.recv() => info!("SIGTERM received; requesting graceful shutdown"),
            _ = interrupt.recv() => info!("SIGINT received; requesting graceful shutdown"),
        }
        shutdown.request();
    }))
}

fn configure_perf_trace_logging(filter: EnvFilter, enabled: bool) -> EnvFilter {
    // Warning-level is retained by `release_max_level_warn`; the explicit OFF
    // directive prevents synthetic performance samples from looking like
    // runtime warnings unless HOWY_PERF_TRACE was strictly enabled.
    let filter = filter.add_directive(
        "howy_perf=off"
            .parse()
            .expect("static performance tracing directive must be valid"),
    );
    if enabled {
        filter.add_directive(
            "howy_perf=warn"
                .parse()
                .expect("static performance tracing directive must be valid"),
        )
    } else {
        filter
    }
}

fn initialize_inference_engine(
    config: &HowyConfig,
    warm_recognizer: bool,
    models: &inference::ResolvedModels,
) -> Result<InferenceStartup> {
    fn warm_engine(
        engine: &inference::InferenceEngine,
        warm_recognizer: bool,
    ) -> Result<(Duration, Duration)> {
        let detector_started = Instant::now();
        engine.warmup()?;
        let detector_warmup = detector_started.elapsed();

        let recognizer_warmup = if warm_recognizer {
            let recognizer_started = Instant::now();
            engine.warmup_recognizer()?;
            recognizer_started.elapsed()
        } else {
            Duration::ZERO
        };

        Ok((detector_warmup, recognizer_warmup))
    }

    fn initialize_attempt(
        config: &HowyConfig,
        requested_provider: &str,
        warm_recognizer: bool,
        models: &inference::ResolvedModels,
    ) -> Result<InferenceStartup> {
        let engine = inference::InferenceEngine::new_with_resolved_models(config, models);
        engine
            .context("failed to initialize inference engine")
            .and_then(|engine| {
                let (detector_warmup, recognizer_warmup) = warm_engine(&engine, warm_recognizer)?;
                let registered_preferred_provider =
                    engine.registered_preferred_provider().to_string();
                Ok(InferenceStartup {
                    engine,
                    requested_provider: requested_provider.to_string(),
                    registered_preferred_provider,
                    explicit_cpu_retry: false,
                    provider_initialization_attempt_count: 1,
                    discarded_provider_initialization_count: 0,
                    detector_warmup,
                    recognizer_warmup,
                })
            })
    }

    fn initialize_final_path(
        config: &HowyConfig,
        requested_provider: &str,
        warm_recognizer: bool,
        prior_discarded_attempts: u32,
        models: &inference::ResolvedModels,
    ) -> Result<InferenceStartup> {
        match initialize_attempt(config, requested_provider, warm_recognizer, models) {
            Ok(mut startup) => {
                startup.provider_initialization_attempt_count += prior_discarded_attempts;
                startup.discarded_provider_initialization_count = prior_discarded_attempts;
                Ok(startup)
            }
            Err(first_err) if config.ml.provider.trim().eq_ignore_ascii_case("cpu") => {
                Err(first_err)
            }
            Err(first_err) => {
                warn!(
                    provider = %config.ml.provider,
                    error = %first_err,
                    "Configured provider failed self-test, falling back to CPU"
                );
                let mut cpu_config = config.clone();
                cpu_config.ml.provider = "cpu".to_string();
                let mut startup =
                    initialize_attempt(&cpu_config, requested_provider, warm_recognizer, models)
                        .context("failed to initialize CPU retry inference engine")?;
                startup.explicit_cpu_retry = true;
                startup.provider_initialization_attempt_count = prior_discarded_attempts + 2;
                startup.discarded_provider_initialization_count = prior_discarded_attempts + 1;
                Ok(startup)
            }
        }
    }

    let requested_provider = normalize_provider(&config.ml.provider);

    // Auto mode is rediscovered on every process start. Registration+self-test
    // is not graph-placement evidence, so stale provider-selection files are
    // intentionally ignored until profiled placement can justify persistence.
    initialize_final_path(config, &requested_provider, warm_recognizer, 0, models)
}

fn initialize_storage_backend(
    config: &HowyConfig,
    recognizer_model: Option<&inference::ResolvedModel>,
    key_context: StartupKeyContext,
) -> Result<Arc<dyn StorageBackend>> {
    match (config.security.embedding_mode, key_context) {
        (EmbeddingSecurityMode::Plaintext, StartupKeyContext::Mode0) => {
            let recognizer_model =
                recognizer_model.context("plaintext storage requires a pinned recognizer model")?;
            let digest = recognizer_model
                .sha256_digest_bounded(inference::MAX_RECOGNIZER_MODEL_BYTES)
                .with_context(|| {
                    format!(
                        "failed to stream exact recognizer model digest from {}",
                        recognizer_model.display_path().display()
                    )
                })?;
            let limits = PlaintextStorageLimits::new(
                config.security.max_embeddings_per_user,
                config.security.max_record_bytes,
            )
            .context("invalid plaintext storage limits")?;
            let budget_bytes = usize::try_from(config.security.max_plaintext_bytes)
                .context("plaintext storage budget does not fit this platform")?;
            let budget = PlaintextBudget::new(budget_bytes)
                .context("invalid plaintext storage memory budget")?;
            // Until mode 1 is implemented, its dormant cache limits also bound
            // the shared daemon cache used by explicit plaintext mode.
            let cache_limits = ModelCacheLimits::new(
                config.security.cached.max_cached_users,
                config.security.cached.max_cache_bytes,
            )
            .context("invalid shared storage cache limits")?;
            Ok(Arc::new(
                PlaintextStorageBackend::production(digest, limits, cache_limits, budget)
                    .context("failed to initialize plaintext storage backend")?,
            ))
        }
        (EmbeddingSecurityMode::AeadCached, StartupKeyContext::Mode1(mode1_key)) => {
            let recognizer_model =
                recognizer_model.context("mode 1 storage requires a pinned recognizer model")?;
            let digest = recognizer_model
                .sha256_digest_bounded(inference::MAX_RECOGNIZER_MODEL_BYTES)
                .with_context(|| {
                    format!(
                        "failed to stream exact recognizer model digest from {}",
                        recognizer_model.display_path().display()
                    )
                })?;
            let limits = Mode1StorageLimits::new(
                config.security.max_embeddings_per_user,
                config.security.max_record_bytes,
            )
            .context("invalid mode 1 storage limits")?;
            let budget_bytes = usize::try_from(config.security.max_plaintext_bytes)
                .context("mode 1 plaintext budget does not fit this platform")?;
            let budget = PlaintextBudget::new(budget_bytes)
                .context("invalid mode 1 plaintext memory budget")?;
            let cache_limits = ModelCacheLimits::new(
                config.security.cached.max_cached_users,
                config.security.cached.max_cache_bytes,
            )
            .context("invalid mode 1 cache limits")?;
            Ok(Arc::new(
                Mode1StorageBackend::production(
                    mode1_key,
                    digest,
                    config.security.key_epoch,
                    limits,
                    cache_limits,
                    budget,
                )
                .context("failed to initialize mode 1 cached AEAD storage backend")?,
            ))
        }
        (EmbeddingSecurityMode::AeadEphemeral, _) => {
            bail!("embedding storage mode 2 is not implemented in this daemon build")
        }
        (EmbeddingSecurityMode::ReservedFuture, _) => {
            bail!("embedding storage mode 3 is reserved and unavailable")
        }
        _ => bail!("storage startup key context does not match the configured mode"),
    }
}

#[cfg(test)]
enum OrderedStartupError {
    Storage(anyhow::Error),
    Inference(anyhow::Error),
}

#[cfg(test)]
fn initialize_runtime_ordered<K, S, I>(
    key: K,
    storage: impl FnOnce(K) -> Result<S>,
    inference: impl FnOnce() -> Result<I>,
) -> std::result::Result<(S, I), OrderedStartupError> {
    let storage = storage(key).map_err(OrderedStartupError::Storage)?;
    let inference = inference().map_err(OrderedStartupError::Inference)?;
    Ok((storage, inference))
}

fn maybe_write_prewarm_marker(startup: &InferenceStartup) -> Result<()> {
    if !should_write_accelerator_prewarm_marker(
        &startup.requested_provider,
        &startup.registered_preferred_provider,
        startup.explicit_cpu_retry,
    ) {
        return Ok(());
    }

    let marker_path = Path::new(PREWARM_MARKER_PATH);
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create prewarm marker directory {}",
                parent.display()
            )
        })?;
        fs::set_permissions(parent, Permissions::from_mode(0o700))?;
    }

    let contents = prewarm_marker_contents(
        &startup.requested_provider,
        &startup.registered_preferred_provider,
        startup.explicit_cpu_retry,
    );
    write_private_atomic(marker_path, contents.as_bytes())
        .with_context(|| format!("failed to write prewarm marker {}", marker_path.display()))
}

fn prewarm_marker_contents(
    requested_provider: &str,
    registered_preferred_provider: &str,
    explicit_cpu_retry: bool,
) -> String {
    format!(
        "howy accelerator registration+self-test completed\nrequested_provider={}\nregistered_preferred_provider={}\nexplicit_cpu_retry={}\nplacement_verified=false\nprovider_note=registration+self-test is not graph-placement evidence\ncache_note=generated cache files remain placement-unverified; clear cached .mxr files after model, runtime, provider, or GPU changes\n",
        requested_provider, registered_preferred_provider, explicit_cpu_retry,
    )
}

fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("private file path has no parent")?;
    let name = path.file_name().context("private file path has no name")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.tmp.{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        nonce
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

struct NormalProcessSettings {
    perf_trace: bool,
    warm_recognizer: bool,
    defer_camera_stop: bool,
}

struct ServiceRunInput {
    engine: Arc<inference::InferenceEngine>,
    storage: Arc<dyn StorageBackend>,
    prompt_manager: Arc<PromptTransactionManager>,
    config: HowyConfig,
    perf_trace: bool,
    defer_camera_stop: bool,
    startup_trace: Option<server::StartupPerfTrace>,
    shutdown: server::ShutdownSignal,
    child_policy: Arc<DaemonChildPolicy>,
    runtime_identity: server::DaemonRuntimeIdentity,
}

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

trait DaemonRuntime {
    type Deadline: CancellationSignal;
    type Binary;
    type Config;
    type Key;

    fn parse_arguments(&mut self) -> Result<RunOptions>;
    fn create_readiness_deadline(&mut self, started_at: Instant) -> Result<Self::Deadline>;
    fn create_async_runtime(&mut self) -> Result<tokio::runtime::Runtime>;
    fn set_private_umask(&mut self);
    fn invocation_identity(&mut self, cancellation: &dyn CancellationSignal) -> Result<String>;
    fn open_binary(&mut self, cancellation: &dyn CancellationSignal) -> Result<Self::Binary>;
    fn open_config(
        &mut self,
        path: &Path,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Self::Config>;
    fn load_readiness_key(
        &mut self,
        config: &Self::Config,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Self::Key>;
    fn verify(
        &mut self,
        config: &Self::Config,
        key: &Self::Key,
        cancellation: &dyn CancellationSignal,
    ) -> Result<howy_common::provisioning::ReadinessResultV1>;
    fn final_identity(
        &mut self,
        config: &Self::Config,
        binary: &Self::Binary,
        cancellation: &dyn CancellationSignal,
    ) -> Result<(
        Sha256Digest,
        howy_common::provisioning::DaemonVerifierIdentityV1,
    )>;
    fn serialize(
        &mut self,
        verifier: &VerifierResultV1,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Vec<u8>>;
    fn output(&mut self, bytes: &[u8], cancellation: &dyn CancellationSignal) -> Result<()>;
    fn emit_failure(&mut self, failure: &DaemonRunFailure);

    fn config_value<'a>(&self, config: &'a Self::Config) -> &'a HowyConfig;
    fn config_sha256(&self, config: &Self::Config) -> String;
    fn binary_output(
        &self,
        binary: &Self::Binary,
    ) -> howy_common::provisioning::DaemonVerifierIdentityV1;
    fn load_startup_key(&mut self, config: &Self::Config) -> Result<Self::Key>;
    fn configured_credential_source(&self, key: &Self::Key) -> Option<String>;
    fn credential_identity(
        &self,
        key: &Self::Key,
    ) -> Option<howy_daemon::mode1_key::CredentialSourceIdentity>;
    fn initialize_normal_process(&mut self) -> Result<NormalProcessSettings>;
    fn validate_ffmpeg_account(&mut self) -> Result<()>;
    fn install_signal_boundary(
        &mut self,
        shutdown: server::ShutdownSignal,
    ) -> Result<tokio::task::JoinHandle<()>>;
    fn probe_model_credential_boundary(
        &mut self,
    ) -> Result<Option<howy_daemon::mode1_key::CredentialSourceIdentity>>;
    fn resolve_recognizer_boundary(
        &mut self,
        config: &HowyConfig,
        guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
    ) -> Result<inference::ResolvedModel>;
    fn construct_storage_cache_boundary(
        &mut self,
        config: &HowyConfig,
        recognizer: Option<&inference::ResolvedModel>,
        key: Self::Key,
    ) -> Result<Arc<dyn StorageBackend>>;
    fn cleanup_mutation_boundary(&mut self) -> Result<()>;
    fn resolve_inference_models_boundary(
        &mut self,
        config: &HowyConfig,
        guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
        recognizer: inference::ResolvedModel,
    ) -> Result<inference::ResolvedModels>;
    fn initialize_inference_provider_boundary(
        &mut self,
        config: &HowyConfig,
        warm_recognizer: bool,
        models: &inference::ResolvedModels,
    ) -> Result<InferenceStartup>;
    fn prewarm_mutation_boundary(&mut self, startup: &InferenceStartup) -> Result<()>;
    fn camera_profile_creation_boundary(&mut self) -> Result<()>;
    fn listener_socket_boundary(&mut self) -> Result<()>;
    fn human_output(&mut self, line: &str) -> Result<()>;
    fn run_service_boundary<'a>(
        &'a mut self,
        input: ServiceRunInput,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>>;
}

struct ProductionDaemonRuntime;

impl DaemonRuntime for ProductionDaemonRuntime {
    type Deadline = ReadinessDeadline;
    type Binary = OpenedDaemonBinary;
    type Config = OpenedConfig;
    type Key = StartupKeyContext;

    fn parse_arguments(&mut self) -> Result<RunOptions> {
        parse_run_options()
    }

    fn create_readiness_deadline(&mut self, started_at: Instant) -> Result<Self::Deadline> {
        ReadinessDeadline::production_from(started_at)
    }

    fn create_async_runtime(&mut self) -> Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to construct the daemon async runtime")
    }

    fn set_private_umask(&mut self) {
        set_private_process_umask();
    }

    fn invocation_identity(&mut self, cancellation: &dyn CancellationSignal) -> Result<String> {
        new_invocation_id_cancellable(cancellation)
    }

    fn open_binary(&mut self, cancellation: &dyn CancellationSignal) -> Result<Self::Binary> {
        open_daemon_binary_identity_cancellable(cancellation)
    }

    fn open_config(
        &mut self,
        path: &Path,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Self::Config> {
        open_daemon_config_cancellable(path, cancellation)
    }

    fn load_readiness_key(
        &mut self,
        config: &Self::Config,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Self::Key> {
        load_readiness_key_context(config.config(), cancellation).map_err(Into::into)
    }

    fn verify(
        &mut self,
        opened_config: &Self::Config,
        key: &Self::Key,
        cancellation: &dyn CancellationSignal,
    ) -> Result<howy_common::provisioning::ReadinessResultV1> {
        let StartupKeyContext::Mode1(mode1_key) = key else {
            bail!("strong readiness requires Mode 1");
        };
        let loaded_source = key
            .credential_source_identity()
            .context("Mode 1 credential identity is absent")?;
        key.configured_credential_source()
            .context("Mode 1 source companion is absent")?;
        let config = opened_config.config();
        verify_mode1_namespace(config, mode1_key, cancellation, |cancellation| {
            if cancellation.is_cancelled() {
                bail!("readiness deadline expired");
            }
            let credential_guard = probe_model_credential_guard()
                .context("model credential alias guard is unavailable")?;
            if cancellation.is_cancelled() || credential_guard != Some(loaded_source) {
                bail!("Mode 1 credential identity changed");
            }
            let recognizer = inference::resolve_recognizer_model(config, credential_guard)
                .context("readiness recognizer descriptor rejected")?;
            if !recognizer.display_path().is_absolute() {
                bail!("readiness recognizer identity is not absolute");
            }
            let digest = recognizer
                .sha256_digest_bounded_cancellable(inference::MAX_RECOGNIZER_MODEL_BYTES, || {
                    cancellation.is_cancelled()
                })?;
            let absolute_path = recognizer
                .display_path()
                .to_str()
                .context("readiness recognizer identity is not UTF-8")?
                .to_owned();
            if cancellation.is_cancelled() {
                bail!("readiness deadline expired");
            }
            Ok(StrongRecognizerBinding {
                digest,
                identity: RecognizerIdentity {
                    absolute_path,
                    sha256: Sha256Digest::from_array(digest.into_bytes()),
                },
            })
        })
    }

    fn final_identity(
        &mut self,
        config: &Self::Config,
        binary: &Self::Binary,
        cancellation: &dyn CancellationSignal,
    ) -> Result<(
        Sha256Digest,
        howy_common::provisioning::DaemonVerifierIdentityV1,
    )> {
        config.revalidate_cancellable(cancellation)?;
        binary.revalidate_cancellable(cancellation)?;
        Ok((config.raw_sha256().clone(), binary.output().clone()))
    }

    fn serialize(
        &mut self,
        verifier: &VerifierResultV1,
        cancellation: &dyn CancellationSignal,
    ) -> Result<Vec<u8>> {
        if cancellation.is_cancelled() {
            bail!("readiness deadline expired");
        }
        let bytes = serialize_strong_readiness_result(verifier)?;
        if cancellation.is_cancelled() {
            bail!("readiness deadline expired");
        }
        Ok(bytes)
    }

    fn output(&mut self, bytes: &[u8], cancellation: &dyn CancellationSignal) -> Result<()> {
        emit_atomic_stdout(bytes, cancellation)
    }

    fn emit_failure(&mut self, failure: &DaemonRunFailure) {
        match failure {
            DaemonRunFailure::General(error) => {
                eprintln!("{DAEMON_ERROR_PREFIX}{}", bounded_error_message(error));
            }
        }
    }

    fn config_value<'a>(&self, config: &'a Self::Config) -> &'a HowyConfig {
        config.config()
    }

    fn config_sha256(&self, config: &Self::Config) -> String {
        config.raw_sha256().as_str().to_owned()
    }

    fn binary_output(
        &self,
        binary: &Self::Binary,
    ) -> howy_common::provisioning::DaemonVerifierIdentityV1 {
        binary.output().clone()
    }

    fn load_startup_key(&mut self, config: &Self::Config) -> Result<Self::Key> {
        load_startup_key_context(config.config()).map_err(Into::into)
    }

    fn configured_credential_source(&self, key: &Self::Key) -> Option<String> {
        key.configured_credential_source()
            .map(|source| source.as_str().to_owned())
    }

    fn credential_identity(
        &self,
        key: &Self::Key,
    ) -> Option<howy_daemon::mode1_key::CredentialSourceIdentity> {
        key.credential_source_identity()
    }

    fn initialize_normal_process(&mut self) -> Result<NormalProcessSettings> {
        let perf_trace = parse_strict_bool(
            "HOWY_PERF_TRACE",
            env::var_os("HOWY_PERF_TRACE").as_deref(),
            false,
        )?;
        let warm_recognizer = parse_strict_bool(
            "HOWY_WARM_RECOGNIZER",
            env::var_os("HOWY_WARM_RECOGNIZER").as_deref(),
            true,
        )?;
        let defer_camera_stop = parse_strict_bool(
            "HOWY_DEFER_CAMERA_STOP",
            env::var_os("HOWY_DEFER_CAMERA_STOP").as_deref(),
            false,
        )?;
        let log_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let log_filter = configure_perf_trace_logging(log_filter, perf_trace);
        tracing_subscriber::fmt()
            .with_env_filter(log_filter)
            .with_target(false)
            .init();
        Ok(NormalProcessSettings {
            perf_trace,
            warm_recognizer,
            defer_camera_stop,
        })
    }

    fn validate_ffmpeg_account(&mut self) -> Result<()> {
        child_spawn::validate_ffmpeg_account().context("dedicated FFmpeg account validation failed")
    }

    fn install_signal_boundary(
        &mut self,
        shutdown: server::ShutdownSignal,
    ) -> Result<tokio::task::JoinHandle<()>> {
        install_signal_forwarder(shutdown)
    }

    fn probe_model_credential_boundary(
        &mut self,
    ) -> Result<Option<howy_daemon::mode1_key::CredentialSourceIdentity>> {
        probe_model_credential_guard().context("failed to establish model credential alias guard")
    }

    fn resolve_recognizer_boundary(
        &mut self,
        config: &HowyConfig,
        guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
    ) -> Result<inference::ResolvedModel> {
        inference::resolve_recognizer_model(config, guard)
            .context("failed to resolve the storage recognizer model descriptor")
    }

    fn construct_storage_cache_boundary(
        &mut self,
        config: &HowyConfig,
        recognizer: Option<&inference::ResolvedModel>,
        key: Self::Key,
    ) -> Result<Arc<dyn StorageBackend>> {
        initialize_storage_backend(config, recognizer, key)
    }

    fn cleanup_mutation_boundary(&mut self) -> Result<()> {
        Ok(())
    }

    fn resolve_inference_models_boundary(
        &mut self,
        config: &HowyConfig,
        guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
        recognizer: inference::ResolvedModel,
    ) -> Result<inference::ResolvedModels> {
        inference::resolve_models_with_recognizer(config, guard, recognizer)
            .context("failed to resolve startup inference model descriptors")
    }

    fn initialize_inference_provider_boundary(
        &mut self,
        config: &HowyConfig,
        warm_recognizer: bool,
        models: &inference::ResolvedModels,
    ) -> Result<InferenceStartup> {
        initialize_inference_engine(config, warm_recognizer, models)
    }

    fn prewarm_mutation_boundary(&mut self, startup: &InferenceStartup) -> Result<()> {
        maybe_write_prewarm_marker(startup)
    }

    fn camera_profile_creation_boundary(&mut self) -> Result<()> {
        Ok(())
    }

    fn listener_socket_boundary(&mut self) -> Result<()> {
        Ok(())
    }

    fn human_output(&mut self, line: &str) -> Result<()> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(line.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        Ok(())
    }

    fn run_service_boundary<'a>(
        &'a mut self,
        input: ServiceRunInput,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
        Box::pin(server::run(
            input.engine,
            input.storage,
            input.prompt_manager,
            input.config,
            input.perf_trace,
            input.defer_camera_stop,
            input.startup_trace,
            input.shutdown,
            input.child_policy,
            input.runtime_identity,
        ))
    }
}

fn execute_strong_readiness<R: DaemonRuntime>(
    options: &RunOptions,
    cancellation: &dyn CancellationSignal,
    runtime: &mut R,
) -> std::result::Result<(), StrongReadinessFailure> {
    let config_path = options
        .config_path
        .as_deref()
        .filter(|_| options.mode == RunMode::StorageReadinessOnly && options.verify_records)
        .ok_or(StrongReadinessFailure::Config)?;
    if cancellation.is_cancelled() {
        return Err(StrongReadinessFailure::Deadline);
    }
    readiness_phase(
        runtime.invocation_identity(cancellation).map(|_| ()),
        cancellation,
        StrongReadinessFailure::Identity,
    )?;
    let binary = readiness_phase(
        runtime.open_binary(cancellation),
        cancellation,
        StrongReadinessFailure::Identity,
    )?;
    let config = readiness_phase(
        runtime.open_config(config_path, cancellation),
        cancellation,
        StrongReadinessFailure::Config,
    )?;
    let key = readiness_phase(
        runtime.load_readiness_key(&config, cancellation),
        cancellation,
        StrongReadinessFailure::Credential,
    )?;
    let readiness = readiness_phase(
        runtime.verify(&config, &key, cancellation),
        cancellation,
        StrongReadinessFailure::Verification,
    )?;
    // The guarded key and all per-record scratch owned by verification are
    // gone before final serialization or the sole stdout write.
    drop(key);
    let (config_sha256, daemon_identity) = readiness_phase(
        runtime.final_identity(&config, &binary, cancellation),
        cancellation,
        StrongReadinessFailure::Verification,
    )?;
    drop(config);
    drop(binary);
    let verifier = readiness_phase(
        VerifierResultV1::new(config_sha256, daemon_identity, readiness).map_err(Into::into),
        cancellation,
        StrongReadinessFailure::Verification,
    )?;
    let output = readiness_phase(
        runtime.serialize(&verifier, cancellation),
        cancellation,
        StrongReadinessFailure::Output,
    )?;
    match runtime.output(&output, cancellation) {
        Ok(()) => Ok(()),
        Err(_) if cancellation.is_cancelled() => Err(StrongReadinessFailure::Deadline),
        Err(_) => Err(StrongReadinessFailure::Output),
    }
}

fn run_contained_strong_readiness<R: DaemonRuntime>(options: &RunOptions, runtime: &mut R) -> i32 {
    // This timestamp is deliberately the first strong-mode operation. The
    // absolute deadline therefore includes TLS access, any lazy initialization,
    // and every verifier phase through failure reporting.
    let started_at = Instant::now();
    let Some(panic_mode) = VerifierPanicModeGuard::arm() else {
        write_static_stderr(VERIFIER_STATE_LINE);
        return 1;
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = (|| {
            let deadline = runtime
                .create_readiness_deadline(started_at)
                .map_err(|_| StrongReadinessFailure::Deadline)?;
            runtime.set_private_umask();
            execute_strong_readiness(options, &deadline, runtime)
        })();
        match result {
            Ok(()) => 0,
            Err(failure) => {
                report_strong_failure(failure);
                1
            }
        }
    }));
    drop(panic_mode);
    match outcome {
        Ok(exit) => exit,
        Err(payload) => {
            // The static hook already emitted the sole redacted panic line.
            // Avoid running an attacker-controlled panic payload destructor.
            std::mem::forget(payload);
            1
        }
    }
}

fn main() {
    let mut runtime = ProductionDaemonRuntime;
    std::process::exit(daemon_entry(&mut runtime));
}

fn daemon_entry<R: DaemonRuntime>(runtime: &mut R) -> i32 {
    // Install while dormant at process entry, before parsing or constructing
    // Tokio. Only the thread-local strong verifier arm intercepts a panic.
    install_verifier_panic_hook();
    let options = match runtime.parse_arguments() {
        Ok(options) => options,
        Err(error) => {
            runtime.emit_failure(&DaemonRunFailure::General(error));
            return 1;
        }
    };
    if options.verify_records {
        return run_contained_strong_readiness(&options, runtime);
    }

    let async_runtime = match runtime.create_async_runtime() {
        Ok(async_runtime) => async_runtime,
        Err(error) => {
            runtime.emit_failure(&DaemonRunFailure::General(error));
            return 1;
        }
    };
    match async_runtime.block_on(daemon_async_main(options, runtime)) {
        Ok(()) => 0,
        Err(failure) => {
            runtime.emit_failure(&failure);
            1
        }
    }
}

async fn daemon_async_main<R: DaemonRuntime>(
    options: RunOptions,
    runtime: &mut R,
) -> std::result::Result<(), DaemonRunFailure> {
    let async_main_entered = Instant::now();
    let run_mode = options.mode;
    if matches!(
        run_mode,
        RunMode::PrewarmOnly | RunMode::StorageReadinessOnly
    ) {
        runtime.set_private_umask();
    }
    let settings = runtime.initialize_normal_process()?;
    let perf_trace = settings.perf_trace;
    let warm_recognizer = settings.warm_recognizer;
    let defer_camera_stop = settings.defer_camera_stop;

    if run_mode == RunMode::ValidateFfmpegAccount {
        runtime.validate_ffmpeg_account()?;
        runtime.human_output("howy-ffmpeg account policy: conforming")?;
        return Ok(());
    }

    // These identities are generated from live process state once per daemon
    // invocation. Root status and strong readiness share the exact snapshot.
    let invocation_id = runtime.invocation_identity(&NeverCancelled)?;
    let daemon_binary = runtime.open_binary(&NeverCancelled)?;

    // Register before model/provider initialization so service stop requests
    // received during startup are retained and observed by the server boundary.
    let shutdown = server::ShutdownSignal::new();
    let signal_forwarder = if run_mode == RunMode::Serve {
        Some(runtime.install_signal_boundary(shutdown.clone())?)
    } else {
        None
    };

    match run_mode {
        RunMode::Serve => info!("howyd starting up"),
        RunMode::PrewarmOnly => info!("howyd starting up in prewarm-only mode"),
        RunMode::StorageReadinessOnly => {
            info!("howyd starting up in storage-readiness-only mode")
        }
        RunMode::ValidateFfmpegAccount => unreachable!("handled before daemon startup"),
    }

    // Configuration is parsed and validated before the mode-aware key loader.
    // In particular, the key loader performs no credential access for Mode 0;
    // model resolution remains an independent credential-aware mechanism.
    let config_path = options
        .config_path
        .as_deref()
        .unwrap_or_else(|| Path::new(CONFIG_FILE));
    let opened_config =
        match runtime.open_config(config_path, &NeverCancelled).context(
            "failed to load configuration; generate one with `sudo howy config` or select an explicit readiness candidate",
        ) {
            Ok(config) => config,
            Err(error) => {
                if perf_trace {
                    server::emit_startup_outcome(
                        async_main_entered,
                        "error",
                        "config",
                        None,
                        defer_camera_stop,
                    );
                }
                return Err(error.into());
            }
        };
    let config = runtime.config_value(&opened_config).clone();

    // This is the key trust boundary. It must remain immediately after
    // validated configuration and before inference/model initialization,
    // camera profile work, storage reads, listener setup, or disabled-mode
    // handling that could otherwise let an explicit Mode 1 omit its key.
    let key_context = runtime
        .load_startup_key(&opened_config)
        .context("failed to establish storage key context")?;
    let configured_credential_source = runtime.configured_credential_source(&key_context);

    // Preserve explicit/legacy Mode 0 disabled startup: the key loader is a
    // no-op and disabled plaintext mode does not resolve models or touch
    // storage. Encrypted modes still cross their consuming backend boundary.
    if config.core.disabled
        && run_mode == RunMode::Serve
        && config.security.embedding_mode == EmbeddingSecurityMode::Plaintext
    {
        drop(key_context);
        if perf_trace {
            server::emit_startup_outcome(
                async_main_entered,
                "disabled",
                "config",
                Some(&config.ml.provider),
                defer_camera_stop,
            );
        }
        info!("howy is disabled in configuration, exiting");
        return Ok(());
    }

    // Mode 0 performs no key or source-companion access. Mode 1 re-probes both
    // delivered descriptor identities before model resolution to exclude
    // aliases and detect a credential-directory replacement.
    let credential_guard = if let Some(loaded_source) = runtime.credential_identity(&key_context) {
        let credential_guard = runtime.probe_model_credential_boundary()?;
        if credential_guard != Some(loaded_source) {
            return Err(
                anyhow::anyhow!("mode 1 credential changed during startup model binding").into(),
            );
        }
        credential_guard
    } else {
        None
    };
    let recognizer_model = runtime.resolve_recognizer_boundary(&config, credential_guard)?;

    if run_mode == RunMode::StorageReadinessOnly {
        runtime.cleanup_mutation_boundary()?;
        let storage = runtime.construct_storage_cache_boundary(
            &config,
            Some(&recognizer_model),
            key_context,
        )?;
        if storage.health() != howy_common::storage::BackendHealth::Ready {
            return Err(anyhow::anyhow!("storage backend did not report ready").into());
        }
        runtime.human_output(&format!(
            "STORAGE_READINESS_RESULT mode={} ready=true decrypted_records=0 cached_records=0 key_record_compatibility=unproven",
            config.security.embedding_mode as u8
        ))?;
        info!(
            mode = config.security.embedding_mode as u8,
            "Storage readiness validation complete; inference and camera were not initialized"
        );
        return Ok(());
    }

    if config.core.disabled && run_mode == RunMode::Serve {
        runtime.cleanup_mutation_boundary()?;
        let _storage = runtime.construct_storage_cache_boundary(
            &config,
            Some(&recognizer_model),
            key_context,
        )?;
        if perf_trace {
            server::emit_startup_outcome(
                async_main_entered,
                "disabled",
                "config",
                Some(&config.ml.provider),
                defer_camera_stop,
            );
        }
        info!("howy is disabled in configuration, exiting");
        return Ok(());
    }
    if config.core.disabled {
        warn!(
            "howy is disabled in configuration, but continuing because --prewarm-only was requested"
        );
    }

    // Storage readiness has completed against the pinned recognizer. Resolve
    // the detector only now, retaining that exact recognizer descriptor for
    // subsequent ORT construction.
    runtime.cleanup_mutation_boundary()?;
    let storage =
        runtime.construct_storage_cache_boundary(&config, Some(&recognizer_model), key_context)?;
    let resolved_models =
        runtime.resolve_inference_models_boundary(&config, credential_guard, recognizer_model)?;

    let inference_started = Instant::now();
    info!(provider = %config.ml.provider, "Initializing inference engine");
    let startup = match runtime.initialize_inference_provider_boundary(
        &config,
        warm_recognizer,
        &resolved_models,
    ) {
        Ok(startup) => startup,
        Err(error) => {
            if perf_trace {
                server::emit_startup_outcome(
                    async_main_entered,
                    "error",
                    "inference",
                    Some(&config.ml.provider),
                    defer_camera_stop,
                );
            }
            return Err(error.into());
        }
    };
    let initialization_and_self_test = inference_started.elapsed();

    info!(
        requested_provider = %startup.requested_provider,
        registered_preferred_provider = %startup.registered_preferred_provider,
        explicit_cpu_retry = startup.explicit_cpu_retry,
        det_model = %startup.engine.detector_model_path(),
        rec_model = %startup.engine.recognizer_model_path(),
        "Inference engine ready — registered provider preference is not graph-placement evidence"
    );

    if run_mode == RunMode::PrewarmOnly {
        if startup.explicit_cpu_retry
            || registered_preference_is_cpu(
                &startup.requested_provider,
                &startup.registered_preferred_provider,
            )
        {
            warn!(
                requested_provider = %startup.requested_provider,
                registered_preferred_provider = %startup.registered_preferred_provider,
                explicit_cpu_retry = startup.explicit_cpu_retry,
                "Prewarm completed with CPU registered preference"
            );
        }

        if let Err(error) = runtime.prewarm_mutation_boundary(&startup) {
            warn!(error = %error, "Registration+self-test completed but failed to write cache marker");
        }

        runtime.human_output(&format!(
            "PREWARM_RESULT requested_provider={} registered_preferred_provider={} explicit_cpu_retry={} placement_verified=false fallback_to_cpu={}",
            startup.requested_provider,
            startup.registered_preferred_provider,
            startup.explicit_cpu_retry,
            startup.explicit_cpu_retry
                || registered_preference_is_cpu(
                    &startup.requested_provider,
                    &startup.registered_preferred_provider,
                ),
        ))?;
        if perf_trace {
            server::StartupPerfTrace {
                async_main_entered,
                requested_provider: startup.requested_provider.clone(),
                registered_preferred_provider: startup.registered_preferred_provider.clone(),
                explicit_cpu_retry: startup.explicit_cpu_retry,
                provider_initialization_attempt_count: startup
                    .provider_initialization_attempt_count,
                discarded_provider_initialization_count: startup
                    .discarded_provider_initialization_count,
                initialization_and_self_test,
                detector_warmup: startup.detector_warmup,
                recognizer_warmup_enabled: warm_recognizer,
                recognizer_warmup: startup.recognizer_warmup,
                defer_camera_stop_enabled: defer_camera_stop,
            }
            .emit_ready("prewarm_ready", None);
        }
        info!("Prewarm-only mode complete; not starting socket server");
        return Ok(());
    }

    let startup_trace = perf_trace.then(|| server::StartupPerfTrace {
        async_main_entered,
        requested_provider: startup.requested_provider.clone(),
        registered_preferred_provider: startup.registered_preferred_provider.clone(),
        explicit_cpu_retry: startup.explicit_cpu_retry,
        provider_initialization_attempt_count: startup.provider_initialization_attempt_count,
        discarded_provider_initialization_count: startup.discarded_provider_initialization_count,
        initialization_and_self_test,
        detector_warmup: startup.detector_warmup,
        recognizer_warmup_enabled: warm_recognizer,
        recognizer_warmup: startup.recognizer_warmup,
        defer_camera_stop_enabled: defer_camera_stop,
    });
    info!(
        mode = config.security.embedding_mode as u8,
        "Storage backend ready"
    );
    let engine = startup.engine;
    let engine = Arc::new(engine);
    let prompt_manager = Arc::new(PromptTransactionManager::production(
        &config,
        server::prompt_active_timeout(&config),
        server::prompt_active_capacity(),
    )?);
    let child_policy = Arc::new(DaemonChildPolicy::for_mode(config.security.embedding_mode));
    let binary_output = runtime.binary_output(&daemon_binary);
    let runtime_identity = server::DaemonRuntimeIdentity {
        config_sha256: runtime.config_sha256(&opened_config),
        credential_name: (config.security.embedding_mode == EmbeddingSecurityMode::AeadCached)
            .then(|| MODE1_CREDENTIAL_NAME.to_owned()),
        configured_credential_source,
        invocation_id,
        daemon_version: binary_output.version,
        build_identity: binary_output.build_identity,
        binary_absolute_path: binary_output.binary_absolute_path,
        binary_sha256: binary_output.binary_sha256.as_str().to_owned(),
    };

    // Start the socket server. Signals and root IPC share one shutdown flag/wakeup.
    runtime.camera_profile_creation_boundary()?;
    runtime.cleanup_mutation_boundary()?;
    runtime.listener_socket_boundary()?;
    let result = runtime
        .run_service_boundary(ServiceRunInput {
            engine,
            storage,
            prompt_manager,
            config,
            perf_trace,
            defer_camera_stop,
            startup_trace,
            shutdown,
            child_policy,
            runtime_identity,
        })
        .await;
    if let Some(signal_forwarder) = signal_forwarder {
        signal_forwarder.abort();
    }
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{
        AtomicPipeIo, DaemonRunFailure, DaemonRuntime, InferenceStartup, NormalProcessSettings,
        ServiceRunInput, StrongReadinessFailure, bounded_error_message,
        configure_perf_trace_logging, daemon_entry, emit_atomic_pipe_with, emit_atomic_stdout,
        initialize_runtime_ordered, initialize_storage_backend, parse_run_options_from,
        prewarm_marker_contents, registered_preference_is_cpu, serialize_strong_readiness_result,
        should_write_accelerator_prewarm_marker, write_private_atomic,
    };
    use crate::server::PERF_TRACE_TARGET;
    use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
    use howy_common::provisioning::{
        DaemonVerifierIdentityV1, NamespaceFingerprintV1, ReadinessResultV1, RecognizerIdentity,
        Sha256Digest, VerifierResultV1,
    };
    use howy_common::storage::CancellationSignal;
    use howy_daemon::mode1_key::StartupKeyContext;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::MakeWriter;

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "howy-main-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter(Arc::clone(&self.0))
        }
    }

    struct StartupKeyDropProbe(Arc<Mutex<Vec<&'static str>>>);

    impl Drop for StartupKeyDropProbe {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("wipe");
        }
    }

    fn parse(arguments: &[&str]) -> anyhow::Result<super::RunOptions> {
        parse_run_options_from(arguments.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn readiness_arguments_are_strict_and_candidate_only() {
        let parsed = parse(&[
            "howyd",
            "--storage-readiness-only",
            "--verify-records",
            "--config",
            "/etc/howy/candidate.toml",
        ])
        .unwrap();
        assert_eq!(parsed.mode, super::RunMode::StorageReadinessOnly);
        assert!(parsed.verify_records);
        assert_eq!(
            parsed.config_path.as_deref(),
            Some(std::path::Path::new("/etc/howy/candidate.toml"))
        );

        for rejected in [
            vec!["howyd", "--verify-records"],
            vec!["howyd", "--verify-records", "--help"],
            vec!["howyd", "--config", "/etc/howy/candidate.toml"],
            vec![
                "howyd",
                "--verify-records",
                "--config",
                "/etc/howy/candidate.toml",
            ],
            vec!["howyd", "--storage-readiness-only", "--verify-records"],
            vec![
                "howyd",
                "--storage-readiness-only",
                "--config",
                "/etc/howy/candidate.toml",
            ],
            vec!["howyd", "--storage-readiness-only", "--config"],
            vec![
                "howyd",
                "--storage-readiness-only",
                "--config",
                "relative.toml",
            ],
            vec![
                "howyd",
                "--storage-readiness-only",
                "--config",
                "/etc/../tmp/x",
            ],
            vec![
                "howyd",
                "--storage-readiness-only",
                "--config",
                "/etc//howy/x",
            ],
            vec![
                "howyd",
                "--storage-readiness-only",
                "--verify-records",
                "--verify-records",
                "--config",
                "/etc/howy/candidate.toml",
            ],
        ] {
            assert!(parse(&rejected).is_err(), "accepted {rejected:?}");
        }
    }

    #[test]
    fn header_only_readiness_remains_available_without_strong_flag() {
        let parsed = parse(&["howyd", "--storage-readiness-only"]).unwrap();
        assert_eq!(parsed.mode, super::RunMode::StorageReadinessOnly);
        assert!(!parsed.verify_records);
        assert!(parsed.config_path.is_none());
    }

    #[test]
    fn strong_readiness_emits_one_json_object_only_after_complete_validation() {
        let readiness = ReadinessResultV1::new_verified(
            NamespaceFingerprintV1 {
                sha256: Sha256Digest::from_bytes(b"empty-namespace"),
                entry_count: 0,
                ciphertext_bytes: 0,
            },
            None,
        )
        .unwrap();
        let valid = VerifierResultV1::new(
            Sha256Digest::from_bytes(b"config"),
            DaemonVerifierIdentityV1 {
                version: "0.1.0".to_owned(),
                build_identity: "howy-0.1.0+test".to_owned(),
                binary_absolute_path: "/usr/bin/howyd".to_owned(),
                binary_sha256: Sha256Digest::from_bytes(b"binary"),
            },
            readiness,
        )
        .unwrap();
        let stdout = serialize_strong_readiness_result(&valid).unwrap();
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(
            VerifierResultV1::parse(stdout.strip_suffix(b"\n").unwrap()).unwrap(),
            valid
        );

        let mut invalid = valid;
        invalid.readiness.cache_population_count = 1;
        assert!(serialize_strong_readiness_result(&invalid).is_err());
    }

    #[test]
    fn daemon_error_rendering_is_single_line_and_bounded() {
        let error = anyhow::anyhow!(format!("{}\nsecond line", "x".repeat(8_192)));
        let rendered = bounded_error_message(&error);
        assert!(
            super::DAEMON_ERROR_PREFIX.len() + rendered.len() + 1 <= super::MAX_DAEMON_ERROR_BYTES
        );
        assert!(!rendered.contains(['\r', '\n']));
        assert!(rendered.ends_with("..."));
        for failure in [
            StrongReadinessFailure::Deadline,
            StrongReadinessFailure::Identity,
            StrongReadinessFailure::Config,
            StrongReadinessFailure::Credential,
            StrongReadinessFailure::Verification,
            StrongReadinessFailure::Output,
        ] {
            let message = failure.stable_message();
            assert!(!message.contains(['\r', '\n']));
            for forbidden in ["/etc/", ".toml", ".onnx", "alice", ".hye", "tag", "key="] {
                assert!(!message.contains(forbidden));
            }
        }
    }

    struct TestCancellation(std::sync::atomic::AtomicBool);

    impl TestCancellation {
        fn new(cancelled: bool) -> Self {
            Self(std::sync::atomic::AtomicBool::new(cancelled))
        }
    }

    impl CancellationSignal for TestCancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    enum FakeWriteResult {
        Full,
        WouldBlock,
        Error,
    }

    struct FakeAtomicPipeIo {
        pipe: bool,
        pipe_buf: usize,
        flags: i32,
        result: FakeWriteResult,
        writes: usize,
        bytes: Vec<u8>,
    }

    impl FakeAtomicPipeIo {
        fn new(result: FakeWriteResult) -> Self {
            Self {
                pipe: true,
                pipe_buf: 4_096,
                flags: 0,
                result,
                writes: 0,
                bytes: Vec::new(),
            }
        }
    }

    impl AtomicPipeIo for FakeAtomicPipeIo {
        fn is_pipe_or_fifo(&mut self, _fd: std::os::fd::RawFd) -> io::Result<bool> {
            Ok(self.pipe)
        }

        fn pipe_buf(&mut self, _fd: std::os::fd::RawFd) -> io::Result<usize> {
            Ok(self.pipe_buf)
        }

        fn get_flags(&mut self, _fd: std::os::fd::RawFd) -> io::Result<i32> {
            Ok(self.flags)
        }

        fn set_flags(&mut self, _fd: std::os::fd::RawFd, flags: i32) -> io::Result<()> {
            self.flags = flags;
            Ok(())
        }

        fn write_once(&mut self, _fd: std::os::fd::RawFd, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            match self.result {
                FakeWriteResult::Full => {
                    self.bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                FakeWriteResult::WouldBlock => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                FakeWriteResult::Error => Err(io::Error::other("injected write failure")),
            }
        }
    }

    #[test]
    fn atomic_verifier_output_is_one_full_pipe_write_or_zero_bytes() {
        let active = TestCancellation::new(false);
        let payload = b"{\"success\":true}\n";
        let mut full = FakeAtomicPipeIo::new(FakeWriteResult::Full);
        emit_atomic_pipe_with(&mut full, 1, payload, &active).unwrap();
        assert_eq!(full.writes, 1);
        assert_eq!(full.bytes, payload);
        assert_ne!(full.flags & libc::O_NONBLOCK, 0);

        for result in [FakeWriteResult::WouldBlock, FakeWriteResult::Error] {
            let mut failed = FakeAtomicPipeIo::new(result);
            assert!(emit_atomic_pipe_with(&mut failed, 1, payload, &active).is_err());
            assert_eq!(failed.writes, 1);
            assert!(failed.bytes.is_empty());
        }

        let mut regular_file = FakeAtomicPipeIo::new(FakeWriteResult::Full);
        regular_file.pipe = false;
        assert!(emit_atomic_pipe_with(&mut regular_file, 1, payload, &active).is_err());
        assert_eq!(regular_file.writes, 0);
        assert!(regular_file.bytes.is_empty());

        let expired = TestCancellation::new(true);
        let mut deadline = FakeAtomicPipeIo::new(FakeWriteResult::Full);
        assert!(emit_atomic_pipe_with(&mut deadline, 1, payload, &expired).is_err());
        assert_eq!(deadline.writes, 0);
        assert!(deadline.bytes.is_empty());
    }

    #[test]
    fn system_atomic_output_accepts_pipe_rejects_nonpipe_and_preserves_full_pipe() {
        let active = TestCancellation::new(false);
        let payload = b"{\"success\":true}\n";
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let mut reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        emit_atomic_pipe_with(
            &mut super::SystemAtomicPipeIo,
            writer.as_raw_fd(),
            payload,
            &active,
        )
        .unwrap();
        let mut received = vec![0u8; payload.len()];
        reader.read_exact(&mut received).unwrap();
        assert_eq!(received, payload);

        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert!(
            emit_atomic_pipe_with(
                &mut super::SystemAtomicPipeIo,
                null.as_raw_fd(),
                payload,
                &active,
            )
            .is_err()
        );

        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK,) },
            0
        );
        let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        let fill = [0u8; 4_096];
        loop {
            let written =
                unsafe { libc::write(writer.as_raw_fd(), fill.as_ptr().cast(), fill.len()) };
            if written < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                break;
            }
            assert_eq!(written as usize, fill.len());
        }
        let mut before = 0;
        assert_eq!(
            unsafe { libc::ioctl(reader.as_raw_fd(), libc::FIONREAD, &mut before) },
            0
        );
        assert!(
            emit_atomic_pipe_with(
                &mut super::SystemAtomicPipeIo,
                writer.as_raw_fd(),
                payload,
                &active,
            )
            .is_err()
        );
        let mut after = 0;
        assert_eq!(
            unsafe { libc::ioctl(reader.as_raw_fd(), libc::FIONREAD, &mut after) },
            0
        );
        assert_eq!(after, before);

        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        drop(unsafe { std::fs::File::from_raw_fd(descriptors[0]) });
        let writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        assert!(
            emit_atomic_pipe_with(
                &mut super::SystemAtomicPipeIo,
                writer.as_raw_fd(),
                payload,
                &active,
            )
            .is_err()
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FixtureScenario {
        Empty,
        Success,
        VerifyFailure,
        Timeout,
        Panic,
        BackgroundPanic,
        PanicStderrFull,
        PanicStderrClosed,
        OutputFailure,
        NormalAsync,
        ConfigOnly,
        VerifyOnly,
        StrongWithoutMode,
    }

    impl FixtureScenario {
        fn parse(value: &str) -> Self {
            match value {
                "empty" => Self::Empty,
                "success" => Self::Success,
                "verify-failure" => Self::VerifyFailure,
                "timeout" => Self::Timeout,
                "panic" => Self::Panic,
                "background-panic" => Self::BackgroundPanic,
                "panic-stderr-full" => Self::PanicStderrFull,
                "panic-stderr-closed" => Self::PanicStderrClosed,
                "output-failure" => Self::OutputFailure,
                "normal-async" => Self::NormalAsync,
                "config-only" => Self::ConfigOnly,
                "verify-only" => Self::VerifyOnly,
                "strong-without-mode" => Self::StrongWithoutMode,
                _ => panic!("unknown fixture scenario"),
            }
        }

        fn as_str(self) -> &'static str {
            match self {
                Self::Empty => "empty",
                Self::Success => "success",
                Self::VerifyFailure => "verify-failure",
                Self::Timeout => "timeout",
                Self::Panic => "panic",
                Self::BackgroundPanic => "background-panic",
                Self::PanicStderrFull => "panic-stderr-full",
                Self::PanicStderrClosed => "panic-stderr-closed",
                Self::OutputFailure => "output-failure",
                Self::NormalAsync => "normal-async",
                Self::ConfigOnly => "config-only",
                Self::VerifyOnly => "verify-only",
                Self::StrongWithoutMode => "strong-without-mode",
            }
        }

        fn arguments(self) -> Vec<&'static str> {
            match self {
                Self::NormalAsync => vec!["howyd", "--validate-ffmpeg-account"],
                Self::ConfigOnly => vec![
                    "howyd",
                    "--storage-readiness-only",
                    "--config",
                    "/etc/howy/candidate.toml",
                ],
                Self::VerifyOnly => {
                    vec!["howyd", "--storage-readiness-only", "--verify-records"]
                }
                Self::StrongWithoutMode => vec![
                    "howyd",
                    "--verify-records",
                    "--config",
                    "/etc/howy/candidate.toml",
                ],
                _ => vec![
                    "howyd",
                    "--storage-readiness-only",
                    "--verify-records",
                    "--config",
                    "/etc/howy/candidate.toml",
                ],
            }
        }
    }

    struct FixtureConfig(HowyConfig);
    struct FixtureBinary;
    struct FixtureKey(Arc<Mutex<Vec<&'static str>>>);

    impl Drop for FixtureKey {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("key_drop");
        }
    }

    struct FixtureRuntime {
        scenario: FixtureScenario,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FixtureRuntime {
        fn new(scenario: FixtureScenario) -> Self {
            Self {
                scenario,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn call(&self, name: &'static str) {
            self.calls.lock().unwrap().push(name);
        }

        fn readiness(&self) -> anyhow::Result<ReadinessResultV1> {
            match self.scenario {
                FixtureScenario::Empty | FixtureScenario::OutputFailure => {
                    ReadinessResultV1::new_verified(
                        NamespaceFingerprintV1 {
                            sha256: Sha256Digest::from_bytes(b"empty"),
                            entry_count: 0,
                            ciphertext_bytes: 0,
                        },
                        None,
                    )
                    .map_err(Into::into)
                }
                _ => ReadinessResultV1::new_verified(
                    NamespaceFingerprintV1 {
                        sha256: Sha256Digest::from_bytes(b"nonempty"),
                        entry_count: 1,
                        ciphertext_bytes: 64,
                    },
                    Some(RecognizerIdentity {
                        absolute_path: "/models/recognizer.onnx".into(),
                        sha256: Sha256Digest::from_bytes(b"recognizer"),
                    }),
                )
                .map_err(Into::into),
            }
        }
    }

    impl DaemonRuntime for FixtureRuntime {
        type Deadline = TestCancellation;
        type Binary = FixtureBinary;
        type Config = FixtureConfig;
        type Key = FixtureKey;

        fn parse_arguments(&mut self) -> anyhow::Result<super::RunOptions> {
            self.call("parse");
            parse_run_options_from(
                self.scenario
                    .arguments()
                    .into_iter()
                    .map(std::ffi::OsString::from),
            )
        }

        fn create_readiness_deadline(
            &mut self,
            _started_at: std::time::Instant,
        ) -> anyhow::Result<Self::Deadline> {
            self.call("deadline");
            Ok(TestCancellation::new(
                self.scenario == FixtureScenario::Timeout,
            ))
        }

        fn create_async_runtime(&mut self) -> anyhow::Result<tokio::runtime::Runtime> {
            self.call("async_runtime");
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(Into::into)
        }

        fn set_private_umask(&mut self) {
            self.call("umask");
        }

        fn invocation_identity(
            &mut self,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<String> {
            self.call("invocation");
            Ok("23".repeat(32))
        }

        fn open_binary(
            &mut self,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<Self::Binary> {
            self.call("binary");
            Ok(FixtureBinary)
        }

        fn open_config(
            &mut self,
            _path: &std::path::Path,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<Self::Config> {
            self.call("config");
            let mut config = HowyConfig::default();
            config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
            Ok(FixtureConfig(config))
        }

        fn load_readiness_key(
            &mut self,
            _config: &Self::Config,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<Self::Key> {
            self.call("readiness_key");
            Ok(FixtureKey(Arc::clone(&self.calls)))
        }

        fn verify(
            &mut self,
            _config: &Self::Config,
            _key: &Self::Key,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<ReadinessResultV1> {
            self.call("verify");
            match self.scenario {
                FixtureScenario::VerifyFailure => anyhow::bail!("sensitive fixture failure"),
                FixtureScenario::BackgroundPanic => {
                    let panicked = std::thread::spawn(|| {
                        std::panic::catch_unwind(|| {
                            panic!("background panic delegated /record/alice.hye")
                        })
                        .is_err()
                    })
                    .join()
                    .unwrap();
                    assert!(panicked);
                    anyhow::bail!("fail after delegated background panic")
                }
                _ => self.readiness(),
            }
        }

        fn final_identity(
            &mut self,
            _config: &Self::Config,
            _binary: &Self::Binary,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<(Sha256Digest, DaemonVerifierIdentityV1)> {
            self.call("final_identity");
            Ok((
                Sha256Digest::from_bytes(b"config"),
                DaemonVerifierIdentityV1 {
                    version: "0.1.0".into(),
                    build_identity: "howy-test".into(),
                    binary_absolute_path: "/usr/bin/howyd".into(),
                    binary_sha256: Sha256Digest::from_bytes(b"binary"),
                },
            ))
        }

        fn serialize(
            &mut self,
            verifier: &VerifierResultV1,
            _cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<Vec<u8>> {
            self.call("serialize");
            serialize_strong_readiness_result(verifier)
        }

        fn output(
            &mut self,
            bytes: &[u8],
            cancellation: &dyn CancellationSignal,
        ) -> anyhow::Result<()> {
            self.call("output");
            if matches!(
                self.scenario,
                FixtureScenario::Panic
                    | FixtureScenario::PanicStderrFull
                    | FixtureScenario::PanicStderrClosed
            ) {
                panic!("sensitive panic path /record/alice.hye");
            }
            if self.scenario == FixtureScenario::OutputFailure {
                anyhow::bail!("injected output failure");
            }
            emit_atomic_stdout(bytes, cancellation)
        }

        fn emit_failure(&mut self, failure: &DaemonRunFailure) {
            self.call("emit_error");
            match failure {
                DaemonRunFailure::General(error) => eprintln!(
                    "{}{}",
                    super::DAEMON_ERROR_PREFIX,
                    bounded_error_message(error)
                ),
            }
        }

        fn config_value<'a>(&self, config: &'a Self::Config) -> &'a HowyConfig {
            &config.0
        }

        fn config_sha256(&self, _config: &Self::Config) -> String {
            "01".repeat(32)
        }

        fn binary_output(&self, _binary: &Self::Binary) -> DaemonVerifierIdentityV1 {
            unreachable!("normal boundary must not run")
        }

        fn load_startup_key(&mut self, _config: &Self::Config) -> anyhow::Result<Self::Key> {
            self.call("startup_key");
            anyhow::bail!("normal boundary called")
        }

        fn configured_credential_source(&self, _key: &Self::Key) -> Option<String> {
            None
        }

        fn credential_identity(
            &self,
            _key: &Self::Key,
        ) -> Option<howy_daemon::mode1_key::CredentialSourceIdentity> {
            None
        }

        fn initialize_normal_process(&mut self) -> anyhow::Result<NormalProcessSettings> {
            self.call("normal_process");
            if self.scenario == FixtureScenario::NormalAsync {
                return Ok(NormalProcessSettings {
                    perf_trace: false,
                    warm_recognizer: false,
                    defer_camera_stop: false,
                });
            }
            anyhow::bail!("normal boundary called")
        }

        fn validate_ffmpeg_account(&mut self) -> anyhow::Result<()> {
            self.call("ffmpeg");
            if self.scenario == FixtureScenario::NormalAsync {
                Ok(())
            } else {
                anyhow::bail!("normal boundary called")
            }
        }

        fn install_signal_boundary(
            &mut self,
            _shutdown: crate::server::ShutdownSignal,
        ) -> anyhow::Result<tokio::task::JoinHandle<()>> {
            self.call("signal");
            anyhow::bail!("normal boundary called")
        }

        fn probe_model_credential_boundary(
            &mut self,
        ) -> anyhow::Result<Option<howy_daemon::mode1_key::CredentialSourceIdentity>> {
            self.call("model_probe");
            anyhow::bail!("normal boundary called")
        }

        fn resolve_recognizer_boundary(
            &mut self,
            _config: &HowyConfig,
            _guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
        ) -> anyhow::Result<howy_daemon::inference::ResolvedModel> {
            self.call("recognizer");
            anyhow::bail!("normal boundary called")
        }

        fn construct_storage_cache_boundary(
            &mut self,
            _config: &HowyConfig,
            _recognizer: Option<&howy_daemon::inference::ResolvedModel>,
            _key: Self::Key,
        ) -> anyhow::Result<Arc<dyn howy_common::storage::StorageBackend>> {
            self.call("storage_cache");
            anyhow::bail!("normal boundary called")
        }

        fn cleanup_mutation_boundary(&mut self) -> anyhow::Result<()> {
            self.call("cleanup_mutation");
            anyhow::bail!("normal boundary called")
        }

        fn resolve_inference_models_boundary(
            &mut self,
            _config: &HowyConfig,
            _guard: Option<howy_daemon::mode1_key::CredentialSourceIdentity>,
            _recognizer: howy_daemon::inference::ResolvedModel,
        ) -> anyhow::Result<howy_daemon::inference::ResolvedModels> {
            self.call("inference_models");
            anyhow::bail!("normal boundary called")
        }

        fn initialize_inference_provider_boundary(
            &mut self,
            _config: &HowyConfig,
            _warm_recognizer: bool,
            _models: &howy_daemon::inference::ResolvedModels,
        ) -> anyhow::Result<InferenceStartup> {
            self.call("inference_provider");
            anyhow::bail!("normal boundary called")
        }

        fn prewarm_mutation_boundary(&mut self, _startup: &InferenceStartup) -> anyhow::Result<()> {
            self.call("prewarm_mutation");
            anyhow::bail!("normal boundary called")
        }

        fn camera_profile_creation_boundary(&mut self) -> anyhow::Result<()> {
            self.call("camera_profile");
            anyhow::bail!("normal boundary called")
        }

        fn listener_socket_boundary(&mut self) -> anyhow::Result<()> {
            self.call("listener_socket");
            anyhow::bail!("normal boundary called")
        }

        fn human_output(&mut self, _line: &str) -> anyhow::Result<()> {
            self.call("human_output");
            if self.scenario == FixtureScenario::NormalAsync {
                Ok(())
            } else {
                anyhow::bail!("normal boundary called")
            }
        }

        fn run_service_boundary<'a>(
            &'a mut self,
            _input: ServiceRunInput,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + 'a>> {
            self.call("service_run");
            Box::pin(async { anyhow::bail!("normal boundary called") })
        }
    }

    fn inheritable_pipe() -> (std::fs::File, std::fs::File) {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        (reader, writer)
    }

    #[test]
    fn daemon_entry_child_process_helper() {
        let Some(scenario) = std::env::var_os("HOWY_DAEMON_ENTRY_FIXTURE") else {
            return;
        };
        let scenario = FixtureScenario::parse(scenario.to_str().unwrap());
        let stdout_fd: i32 = std::env::var("HOWY_DAEMON_ENTRY_STDOUT_FD")
            .unwrap()
            .parse()
            .unwrap();
        let stderr_fd: i32 = std::env::var("HOWY_DAEMON_ENTRY_STDERR_FD")
            .unwrap()
            .parse()
            .unwrap();
        let report_fd: i32 = std::env::var("HOWY_DAEMON_ENTRY_REPORT_FD")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::dup2(stdout_fd, libc::STDOUT_FILENO) }, 1);
        assert_eq!(unsafe { libc::dup2(stderr_fd, libc::STDERR_FILENO) }, 2);
        if scenario == FixtureScenario::PanicStderrFull {
            let flags = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe {
                    libc::fcntl(libc::STDERR_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK)
                },
                0
            );
            let filler = [b'x'; 4_096];
            loop {
                let written = unsafe {
                    libc::write(libc::STDERR_FILENO, filler.as_ptr().cast(), filler.len())
                };
                if written < 0 {
                    assert_eq!(
                        std::io::Error::last_os_error().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    break;
                }
            }
            assert_eq!(
                unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_SETFL, flags) },
                0
            );
        } else if scenario == FixtureScenario::PanicStderrClosed {
            assert_eq!(unsafe { libc::close(libc::STDERR_FILENO) }, 0);
        }
        let mut runtime = FixtureRuntime::new(scenario);
        let exit = daemon_entry(&mut runtime);
        let report = runtime.calls.lock().unwrap().join(",");
        unsafe {
            libc::write(report_fd, report.as_ptr().cast(), report.len());
        }
        std::process::exit(exit);
    }

    struct ChildEntryResult {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        calls: Vec<String>,
    }

    fn run_entry_child(scenario: FixtureScenario) -> ChildEntryResult {
        let (mut stdout_reader, stdout_writer) = inheritable_pipe();
        let (mut stderr_reader, stderr_writer) = inheritable_pipe();
        let (mut report_reader, report_writer) = inheritable_pipe();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::daemon_entry_child_process_helper",
                "--nocapture",
            ])
            .env("HOWY_DAEMON_ENTRY_FIXTURE", scenario.as_str())
            .env(
                "HOWY_DAEMON_ENTRY_STDOUT_FD",
                stdout_writer.as_raw_fd().to_string(),
            )
            .env(
                "HOWY_DAEMON_ENTRY_STDERR_FD",
                stderr_writer.as_raw_fd().to_string(),
            )
            .env(
                "HOWY_DAEMON_ENTRY_REPORT_FD",
                report_writer.as_raw_fd().to_string(),
            )
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        drop((stdout_writer, stderr_writer, report_writer));
        let status = child.wait().unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut report = String::new();
        stdout_reader.read_to_end(&mut stdout).unwrap();
        stderr_reader.read_to_end(&mut stderr).unwrap();
        report_reader.read_to_string(&mut report).unwrap();
        ChildEntryResult {
            status,
            stdout,
            stderr,
            calls: report
                .split(',')
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }

    fn expected_fixture_stdout(scenario: FixtureScenario) -> Vec<u8> {
        let runtime = FixtureRuntime::new(scenario);
        let verifier = VerifierResultV1::new(
            Sha256Digest::from_bytes(b"config"),
            DaemonVerifierIdentityV1 {
                version: "0.1.0".into(),
                build_identity: "howy-test".into(),
                binary_absolute_path: "/usr/bin/howyd".into(),
                binary_sha256: Sha256Digest::from_bytes(b"binary"),
            },
            runtime.readiness().unwrap(),
        )
        .unwrap();
        serialize_strong_readiness_result(&verifier).unwrap()
    }

    fn assert_zero_forbidden_boundaries(calls: &[String]) {
        for forbidden in [
            "async_runtime",
            "normal_process",
            "ffmpeg",
            "signal",
            "startup_key",
            "model_probe",
            "recognizer",
            "storage_cache",
            "cleanup_mutation",
            "inference_models",
            "inference_provider",
            "prewarm_mutation",
            "camera_profile",
            "listener_socket",
            "service_run",
            "human_output",
        ] {
            assert!(
                !calls.iter().any(|call| call == forbidden),
                "called {forbidden}"
            );
        }
    }

    #[test]
    fn actual_daemon_entry_child_covers_success_failure_timeout_panic_and_output() {
        for scenario in [FixtureScenario::Empty, FixtureScenario::Success] {
            let result = run_entry_child(scenario);
            assert_eq!(result.status.code(), Some(0));
            assert_eq!(result.stdout, expected_fixture_stdout(scenario));
            assert!(result.stderr.is_empty());
            assert_zero_forbidden_boundaries(&result.calls);
            assert_eq!(
                result.calls,
                [
                    "parse",
                    "deadline",
                    "umask",
                    "invocation",
                    "binary",
                    "config",
                    "readiness_key",
                    "verify",
                    "key_drop",
                    "final_identity",
                    "serialize",
                    "output",
                ]
            );
            let key_drop = result
                .calls
                .iter()
                .position(|call| call == "key_drop")
                .unwrap();
            let serialize = result
                .calls
                .iter()
                .position(|call| call == "serialize")
                .unwrap();
            assert!(key_drop < serialize);
        }

        for (scenario, stderr) in [
            (
                FixtureScenario::VerifyFailure,
                "howyd: strong-readiness/verification: namespace verification failed\n",
            ),
            (
                FixtureScenario::Timeout,
                "howyd: strong-readiness/deadline: operation deadline exceeded\n",
            ),
            (
                FixtureScenario::OutputFailure,
                "howyd: strong-readiness/output: atomic verifier output failed\n",
            ),
            (
                FixtureScenario::Panic,
                "howyd: strong-readiness/panic: verifier panic contained\n",
            ),
        ] {
            let result = run_entry_child(scenario);
            assert_eq!(result.status.code(), Some(1));
            assert!(result.stdout.is_empty());
            assert_eq!(result.stderr, stderr.as_bytes());
            assert!(result.stderr.len() <= super::MAX_DAEMON_ERROR_BYTES);
            assert_zero_forbidden_boundaries(&result.calls);
        }
    }

    #[test]
    fn actual_daemon_entry_rejects_partial_flags_before_every_boundary() {
        for (scenario, stderr) in [
            (
                FixtureScenario::ConfigOnly,
                "howyd: strong readiness requires --config and --verify-records together\n",
            ),
            (
                FixtureScenario::VerifyOnly,
                "howyd: strong readiness requires --config and --verify-records together\n",
            ),
            (
                FixtureScenario::StrongWithoutMode,
                "howyd: --config and --verify-records require --storage-readiness-only\n",
            ),
        ] {
            let result = run_entry_child(scenario);
            assert_eq!(result.status.code(), Some(1));
            assert!(result.stdout.is_empty());
            assert_eq!(result.stderr, stderr.as_bytes());
            assert_eq!(result.calls, ["parse", "emit_error"]);
        }
    }

    #[test]
    fn normal_entry_constructs_one_async_runtime_after_parsing() {
        let result = run_entry_child(FixtureScenario::NormalAsync);
        assert_eq!(result.status.code(), Some(0));
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        assert_eq!(
            result.calls,
            [
                "parse",
                "async_runtime",
                "normal_process",
                "ffmpeg",
                "human_output",
            ]
        );
        assert_eq!(
            result
                .calls
                .iter()
                .filter(|call| call.as_str() == "async_runtime")
                .count(),
            1
        );
    }

    #[test]
    fn background_panic_delegates_without_claiming_verifier_failure_report() {
        let result = run_entry_child(FixtureScenario::BackgroundPanic);
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert!(stderr.contains("background panic delegated /record/alice.hye"));
        let strong_line = "howyd: strong-readiness/verification: namespace verification failed\n";
        assert_eq!(stderr.matches(strong_line).count(), 1);
        assert_zero_forbidden_boundaries(&result.calls);
    }

    #[test]
    fn verifier_panic_reporting_is_bounded_when_stderr_is_full_or_closed() {
        let full = run_entry_child(FixtureScenario::PanicStderrFull);
        assert_eq!(full.status.code(), Some(1));
        assert!(full.stdout.is_empty());
        assert!(!full.stderr.is_empty());
        assert!(full.stderr.iter().all(|byte| *byte == b'x'));
        assert_zero_forbidden_boundaries(&full.calls);

        let closed = run_entry_child(FixtureScenario::PanicStderrClosed);
        assert_eq!(closed.status.code(), Some(1));
        assert!(closed.stdout.is_empty());
        assert!(closed.stderr.is_empty());
        assert_zero_forbidden_boundaries(&closed.calls);
    }

    #[test]
    fn production_orchestrator_constructs_storage_before_inference() {
        let events = Arc::new(Mutex::new(vec!["config", "key"]));
        let storage_events = Arc::clone(&events);
        let inference_events = Arc::clone(&events);
        initialize_runtime_ordered(
            (),
            move |()| {
                storage_events.lock().unwrap().push("storage");
                Ok(())
            },
            move || {
                inference_events.lock().unwrap().push("inference");
                Ok(())
            },
        )
        .map_err(|_| ())
        .unwrap();
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["config", "key", "storage", "inference"]
        );
    }

    #[test]
    fn storage_failure_consumes_and_wipes_key_before_skipping_inference() {
        let events = Arc::new(Mutex::new(vec!["key"]));
        let storage_events = Arc::clone(&events);
        let inference_events = Arc::clone(&events);
        let result = initialize_runtime_ordered(
            StartupKeyDropProbe(Arc::clone(&events)),
            move |key| -> anyhow::Result<()> {
                storage_events.lock().unwrap().push("storage");
                drop(key);
                anyhow::bail!("injected backend failure")
            },
            move || -> anyhow::Result<()> {
                inference_events.lock().unwrap().push("inference");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["key", "storage", "wipe"]
        );
    }

    #[test]
    fn registered_cpu_preference_is_labeled_without_claiming_placement() {
        assert!(registered_preference_is_cpu("migraphx", "cpu"));
        assert!(registered_preference_is_cpu("auto", "cpu"));
        assert!(!registered_preference_is_cpu("cpu", "cpu"));
        assert!(!registered_preference_is_cpu("auto", "cuda"));
    }

    #[test]
    fn prewarm_marker_requires_migraphx_preference_without_cpu_retry() {
        assert!(should_write_accelerator_prewarm_marker(
            "migraphx", "migraphx", false
        ));
        assert!(should_write_accelerator_prewarm_marker(
            "auto", "migraphx", false
        ));
        assert!(!should_write_accelerator_prewarm_marker(
            "auto", "cuda", false
        ));
        assert!(!should_write_accelerator_prewarm_marker(
            "auto", "cpu", false
        ));
        assert!(!should_write_accelerator_prewarm_marker(
            "auto", "mixed", false
        ));
        assert!(!should_write_accelerator_prewarm_marker(
            "migraphx", "migraphx", true
        ));
        assert!(!should_write_accelerator_prewarm_marker(
            "cuda", "migraphx", false
        ));
    }

    #[test]
    fn prewarm_marker_is_private_atomic_and_contains_no_model_paths() {
        let directory = temporary_directory("marker");
        let path = directory.join("prewarm-status.txt");
        let contents = prewarm_marker_contents("auto", "migraphx", false);
        write_private_atomic(&path, contents.as_bytes()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let stored = std::fs::read_to_string(&path).unwrap();
        assert_eq!(stored, contents);
        assert!(!stored.contains("detector_model"));
        assert!(!stored.contains("recognizer_model"));
        assert!(!stored.contains(".onnx"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn perf_target_remains_enabled_by_warn_filter() {
        let output = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(configure_perf_trace_logging(EnvFilter::new("warn"), true))
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: PERF_TRACE_TARGET, "perf-visible");
            tracing::info!(target: "normal_target", "normal-hidden");
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("perf-visible"));
        assert!(!output.contains("normal-hidden"));
    }

    #[test]
    fn perf_target_is_silent_without_explicit_opt_in_even_under_info_filter() {
        let output = SharedBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(configure_perf_trace_logging(EnvFilter::new("info"), false))
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: PERF_TRACE_TARGET, "perf-must-be-hidden");
            tracing::warn!(target: "normal_target", "normal-warning-visible");
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("perf-must-be-hidden"));
        assert!(output.contains("normal-warning-visible"));
    }

    #[test]
    fn release_compile_time_filter_keeps_only_warn_and_error_instrumentation() {
        #[cfg(not(debug_assertions))]
        assert_eq!(
            tracing::level_filters::STATIC_MAX_LEVEL,
            tracing::level_filters::LevelFilter::WARN
        );
    }

    #[test]
    fn unimplemented_storage_modes_fail_without_touching_a_model_or_storage_path() {
        for mode in [
            EmbeddingSecurityMode::AeadEphemeral,
            EmbeddingSecurityMode::ReservedFuture,
        ] {
            let mut config = HowyConfig::default();
            config.security.embedding_mode = mode;
            let error = match initialize_storage_backend(&config, None, StartupKeyContext::Mode0) {
                Ok(_) => panic!("unimplemented storage mode unexpectedly initialized"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("mode"));
        }
    }

    #[test]
    fn binary_uses_canonical_library_modules() {
        assert_eq!(
            super::server::PERF_TRACE_TARGET,
            howy_daemon::server::PERF_TRACE_TARGET
        );
        assert!(
            std::any::type_name::<super::inference::InferenceEngine>()
                .starts_with("howy_daemon::inference::")
        );
    }
}
