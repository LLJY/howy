//! howyd — the howy face authentication daemon.
//!
//! Preloads SCRFD (detection) and ArcFace (recognition) ONNX models at startup,
//! warms them with a dummy inference pass, then listens on a Unix domain socket
//! for authentication requests from the PAM module and CLI. A dedicated
//! `--prewarm-only` mode is also available for install-time MIGraphX cache priming.
//!
//! Supports systemd socket activation and credential loading.

use std::env;
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use howy_common::config::HowyConfig;
use howy_common::env::parse_strict_bool;
use howy_daemon::{inference, server};

const PREWARM_MARKER_PATH: &str = "/var/cache/howy/prewarm-status.txt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Serve,
    PrewarmOnly,
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
    println!("Usage: {program} [--prewarm-only]");
}

fn parse_run_mode() -> Result<RunMode> {
    let mut mode = RunMode::Serve;
    let mut args = env::args_os();
    let program = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .unwrap_or_else(|| "howyd".to_string());

    for arg in args {
        match arg.to_str() {
            Some("--prewarm-only") => mode = RunMode::PrewarmOnly,
            Some("-h") | Some("--help") => {
                print_usage(&program);
                std::process::exit(0);
            }
            Some(other) => bail!("unknown argument: {other}"),
            None => bail!("howyd does not support non-UTF-8 arguments"),
        }
    }

    Ok(mode)
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

fn enable_perf_trace_logging(filter: EnvFilter) -> EnvFilter {
    filter.add_directive(
        "howy_perf=info"
            .parse()
            .expect("static performance tracing directive must be valid"),
    )
}

fn initialize_inference_engine(
    config: &HowyConfig,
    warm_recognizer: bool,
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
    ) -> Result<InferenceStartup> {
        let engine = inference::InferenceEngine::new(config);
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
    ) -> Result<InferenceStartup> {
        match initialize_attempt(config, requested_provider, warm_recognizer) {
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
                    initialize_attempt(&cpu_config, requested_provider, warm_recognizer)
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
    initialize_final_path(config, &requested_provider, warm_recognizer, 0)
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

#[tokio::main]
async fn main() -> Result<()> {
    let async_main_entered = Instant::now();
    let run_mode = parse_run_mode()?;
    if run_mode == RunMode::PrewarmOnly {
        set_private_process_umask();
    }
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

    // Initialize logging
    let log_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let log_filter = if perf_trace {
        enable_perf_trace_logging(log_filter)
    } else {
        log_filter
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_target(false)
        .init();

    // Register before model/provider initialization so service stop requests
    // received during startup are retained and observed by the server boundary.
    let shutdown = server::ShutdownSignal::new();
    let signal_forwarder = if run_mode == RunMode::Serve {
        Some(install_signal_forwarder(shutdown.clone())?)
    } else {
        None
    };

    match run_mode {
        RunMode::Serve => info!("howyd starting up"),
        RunMode::PrewarmOnly => info!("howyd starting up in prewarm-only mode"),
    }

    // Load configuration (supports systemd credentials)
    let config = match HowyConfig::load_with_systemd_creds().context("failed to load configuration")
    {
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
            return Err(error);
        }
    };

    if config.core.disabled {
        if run_mode == RunMode::Serve {
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

        warn!(
            "howy is disabled in configuration, but continuing because --prewarm-only was requested"
        );
    }

    info!(provider = %config.ml.provider, "Initializing inference engine");

    let inference_started = Instant::now();
    let startup = match initialize_inference_engine(&config, warm_recognizer) {
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
            return Err(error);
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

        if let Err(error) = maybe_write_prewarm_marker(&startup) {
            warn!(error = %error, "Registration+self-test completed but failed to write cache marker");
        }

        println!(
            "PREWARM_RESULT requested_provider={} registered_preferred_provider={} explicit_cpu_retry={} placement_verified=false fallback_to_cpu={}",
            startup.requested_provider,
            startup.registered_preferred_provider,
            startup.explicit_cpu_retry,
            startup.explicit_cpu_retry
                || registered_preference_is_cpu(
                    &startup.requested_provider,
                    &startup.registered_preferred_provider,
                ),
        );
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
    let engine = startup.engine;
    let engine = Arc::new(engine);

    // Start the socket server. Signals and root IPC share one shutdown flag/wakeup.
    let result = server::run(
        engine,
        config,
        perf_trace,
        defer_camera_stop,
        startup_trace,
        shutdown,
    )
    .await;
    if let Some(signal_forwarder) = signal_forwarder {
        signal_forwarder.abort();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        enable_perf_trace_logging, prewarm_marker_contents, registered_preference_is_cpu,
        should_write_accelerator_prewarm_marker, write_private_atomic,
    };
    use crate::server::PERF_TRACE_TARGET;
    use std::io::{self, Write};
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
            .with_env_filter(enable_perf_trace_logging(EnvFilter::new("warn")))
            .with_writer(output.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: PERF_TRACE_TARGET, "perf-visible");
            tracing::info!(target: "normal_target", "normal-hidden");
        });

        let output = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("perf-visible"));
        assert!(!output.contains("normal-hidden"));
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
