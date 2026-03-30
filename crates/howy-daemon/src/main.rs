//! howyd — the howy face authentication daemon.
//!
//! Preloads SCRFD (detection) and ArcFace (recognition) ONNX models at startup,
//! warms them with a dummy inference pass, then listens on a Unix domain socket
//! for authentication requests from the PAM module and CLI. A dedicated
//! `--prewarm-only` mode is also available for install-time MIGraphX cache priming.
//!
//! Supports systemd socket activation and credential loading.

mod camera;
mod inference;
mod server;

use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use howy_common::config::HowyConfig;

const PREWARM_MARKER_PATH: &str = "/var/cache/howy/prewarm-status.txt";
const PROVIDER_SELECTION_PATH: &str = "/var/cache/howy/provider-selection.txt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Serve,
    PrewarmOnly,
}

struct InferenceStartup {
    engine: inference::InferenceEngine,
    requested_provider: String,
    effective_provider: String,
    fell_back_to_cpu: bool,
}

fn provider_cache_dir() -> &'static Path {
    Path::new("/var/cache/howy")
}

fn normalize_provider(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn read_cached_provider_selection() -> Option<String> {
    let path = Path::new(PROVIDER_SELECTION_PATH);
    let contents = fs::read_to_string(path).ok()?;
    let provider = normalize_provider(contents.lines().next()?.trim());
    match provider.as_str() {
        "cpu" | "cuda" | "tensorrt" | "migraphx" | "openvino" => Some(provider),
        _ => None,
    }
}

fn write_cached_provider_selection(provider: &str) -> Result<()> {
    let provider = normalize_provider(provider);
    if provider.is_empty() || provider == "auto" {
        return Ok(());
    }

    fs::create_dir_all(provider_cache_dir())
        .with_context(|| format!("failed to create {}", provider_cache_dir().display()))?;
    fs::write(PROVIDER_SELECTION_PATH, format!("{provider}\n")).with_context(|| {
        format!(
            "failed to write provider selection cache {}",
            PROVIDER_SELECTION_PATH
        )
    })
}

fn remove_cached_provider_selection() -> Result<()> {
    let path = Path::new(PROVIDER_SELECTION_PATH);
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to remove {}", PROVIDER_SELECTION_PATH))?;
    }
    Ok(())
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

fn initialize_inference_engine(config: &HowyConfig) -> Result<InferenceStartup> {
    fn try_initialize(config: &HowyConfig, requested_provider: &str) -> Result<InferenceStartup> {
        // Initialize the inference engine and self-test the configured provider.
        // If a non-CPU provider fails warmup on this host, fall back to CPU so the
        // live PAM path remains usable.
        match inference::InferenceEngine::new(config)
        .context("failed to initialize inference engine")
        .and_then(|engine| {
            engine.warmup()?;
            let provider = engine.active_provider().to_string();
            Ok(InferenceStartup {
                engine,
                requested_provider: requested_provider.to_string(),
                effective_provider: provider,
                fell_back_to_cpu: false,
            })
        }) {
        Ok(ok) => Ok(ok),
        Err(first_err) if config.ml.provider.trim().eq_ignore_ascii_case("cpu") => Err(first_err),
        Err(first_err) => {
            warn!(
                provider = %config.ml.provider,
                error = %first_err,
                "Configured provider failed self-test, falling back to CPU"
            );
            let mut cpu_config = config.clone();
            cpu_config.ml.provider = "cpu".to_string();
            let engine = inference::InferenceEngine::new(&cpu_config)
                .context("failed to initialize CPU fallback inference engine")?;
            engine.warmup().context("CPU fallback warmup failed")?;
            let provider = engine.active_provider().to_string();
            Ok(InferenceStartup {
                engine,
                requested_provider: requested_provider.to_string(),
                effective_provider: provider,
                fell_back_to_cpu: true,
            })
        }
        }
    }

    let requested_provider = normalize_provider(&config.ml.provider);

    // Sticky provider selection for auto mode:
    // - first successful resolved provider is cached
    // - later boots try that provider first for a leaner hot path
    // - if the cached provider fails, fall back to full auto rediscovery
    if requested_provider == "auto" {
        if let Some(cached_provider) = read_cached_provider_selection() {
            info!(
                cached_provider = %cached_provider,
                "Using cached provider selection for auto mode"
            );
            let mut cached_config = config.clone();
            cached_config.ml.provider = cached_provider.clone();
            match try_initialize(&cached_config, &requested_provider) {
                Ok(startup) if !(startup.fell_back_to_cpu && cached_provider != "cpu") => {
                    return Ok(startup);
                }
                Ok(_) | Err(_) => {
                    warn!(
                        cached_provider = %cached_provider,
                        "Cached provider failed self-test; rediscovering from full auto chain"
                    );
                    let _ = remove_cached_provider_selection();
                }
            }
        }
    }

    try_initialize(config, &requested_provider)
}

fn maybe_write_prewarm_marker(startup: &InferenceStartup) -> Result<()> {
    let requested_provider = startup.requested_provider.trim().to_ascii_lowercase();
    if startup.fell_back_to_cpu || (requested_provider != "migraphx" && requested_provider != "auto") {
        return Ok(());
    }

    let marker_path = Path::new(PREWARM_MARKER_PATH);
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create prewarm marker directory {}", parent.display())
        })?;
    }

    let contents = format!(
        "howy prewarm completed\nrequested_provider={}\neffective_provider={}\nfallback_to_cpu={}\ndetector_model={}\nrecognizer_model={}\ncache_note=clear /var/cache/howy/*.mxr if model, ONNX Runtime, ROCm/MIGraphX, or GPU arch changes\n",
        startup.requested_provider,
        startup.effective_provider,
        startup.fell_back_to_cpu,
        startup.engine.detector_model_path(),
        startup.engine.recognizer_model_path(),
    );
    fs::write(marker_path, contents)
        .with_context(|| format!("failed to write prewarm marker {}", marker_path.display()))
}

fn maybe_update_provider_selection(startup: &InferenceStartup) -> Result<()> {
    if normalize_provider(&startup.requested_provider) == "auto" {
        write_cached_provider_selection(&startup.effective_provider)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let run_mode = parse_run_mode()?;

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match run_mode {
        RunMode::Serve => info!("howyd starting up"),
        RunMode::PrewarmOnly => info!("howyd starting up in prewarm-only mode"),
    }

    // Load configuration (supports systemd credentials)
    let config = HowyConfig::load_with_systemd_creds()
        .context("failed to load configuration")?;

    if config.core.disabled {
        if run_mode == RunMode::Serve {
            info!("howy is disabled in configuration, exiting");
            return Ok(());
        }

        warn!("howy is disabled in configuration, but continuing because --prewarm-only was requested");
    }

    info!(provider = %config.ml.provider, "Initializing inference engine");

    let startup = initialize_inference_engine(&config)?;

    info!(
        provider = %startup.effective_provider,
        requested_provider = %startup.requested_provider,
        fell_back_to_cpu = startup.fell_back_to_cpu,
        det_model = %startup.engine.detector_model_path(),
        rec_model = %startup.engine.recognizer_model_path(),
        "Inference engine ready — models preloaded"
    );

    if let Err(error) = maybe_update_provider_selection(&startup) {
        warn!(error = %error, "Failed to update persistent provider selection cache");
    }

    if run_mode == RunMode::PrewarmOnly {
        if startup.fell_back_to_cpu {
            warn!(
                requested_provider = %startup.requested_provider,
                effective_provider = %startup.effective_provider,
                "Prewarm completed with CPU fallback"
            );
        }

        if let Err(error) = maybe_write_prewarm_marker(&startup) {
            warn!(error = %error, "Prewarm succeeded but failed to write cache marker");
        }

        println!(
            "PREWARM_RESULT requested_provider={} effective_provider={} fallback_to_cpu={}",
            startup.requested_provider,
            startup.effective_provider,
            startup.fell_back_to_cpu,
        );
        info!("Prewarm-only mode complete; not starting socket server");
        return Ok(());
    }

    let engine = startup.engine;
    let engine = Arc::new(engine);

    // Start the socket server
    server::run(engine, config).await
}
