//! howy — CLI tool for managing face models and testing authentication.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use howy_common::config::HowyConfig;
use howy_common::face::{FaceModel, UserModels};
use howy_common::ipc::DaemonClient;
use howy_common::paths;
use howy_common::protocol::{Request, RespResult};

#[derive(Parser)]
#[command(
    name = "howy",
    about = "Face authentication for Linux — manage face models and test authentication",
    version
)]
struct Cli {
    /// Target user (defaults to current user via SUDO_USER or whoami).
    #[arg(short = 'U', long, global = true)]
    user: Option<String>,

    /// Skip confirmation prompts.
    #[arg(short = 'y', long, global = true)]
    yes: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll a new face model.
    Add {
        /// Label for this face model (e.g., "laptop IR", "office webcam").
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Enroll face models from a batch of captured images.
    EnrollBatch {
        /// Path to the session directory containing captured frame images (png/jpg/bmp).
        #[arg(short = 'd', long)]
        session_dir: String,

        /// Label for this enrollment session (e.g., "laptop IR", "default").
        #[arg(short, long)]
        label: Option<String>,

        /// Delete session directory after successful enrollment.
        #[arg(long)]
        delete_on_success: bool,
    },

    /// List enrolled face models.
    List,

    /// Remove a face model by index.
    Remove {
        /// Model index to remove (from `howy list`).
        index: usize,
    },

    /// Remove all face models for the user.
    Clear,

    /// Test face authentication against enrolled models.
    Test,

    /// Show daemon status and provider info.
    Status,

    /// Inspect local deployment state and caches.
    Doctor,

    /// Prewarm inference and persistent MIGraphX cache.
    Prewarm,

    /// Generate default configuration file.
    Config {
        /// Write to stdout instead of /etc/howy/config.toml.
        #[arg(long)]
        stdout: bool,
    },

    /// Print the version.
    Version,
}

fn main() -> Result<()> {
    let Cli { user, yes, command } = Cli::parse();

    match command {
        Commands::Add { label } => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_add(&user, label, yes)
        }
        Commands::EnrollBatch {
            session_dir,
            label,
            delete_on_success,
        } => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_enroll_batch(&user, &session_dir, label, delete_on_success)
        }
        Commands::List => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_list(&user)
        }
        Commands::Remove { index } => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_remove(&user, index, yes)
        }
        Commands::Clear => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_clear(&user, yes)
        }
        Commands::Test => {
            let user = resolve_target_user(user.as_deref())?;
            cmd_test(&user)
        }
        Commands::Status => cmd_status(),
        Commands::Doctor => cmd_doctor(),
        Commands::Prewarm => cmd_prewarm(),
        Commands::Config { stdout } => cmd_config(stdout),
        Commands::Version => {
            println!("howy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn cmd_add(user: &str, label: Option<String>, _skip_confirm: bool) -> Result<()> {
    check_root()?;

    let label = label.unwrap_or_else(|| {
        print!("Enter a label for this face model: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    });

    if label.is_empty() {
        bail!("Label cannot be empty");
    }

    println!("Look directly at the camera...");

    // Connect to daemon and request enrollment
    let mut client = DaemonClient::default_path().with_timeout(std::time::Duration::from_secs(10));

    let response = client.request(&Request::enroll(user, &label))?;

    match response.result {
        Some(RespResult::Enrolled(e)) => {
            // Load or create user models — fail hard on corrupt files
            // to avoid silently overwriting existing enrollments.
            let model_path = model_path_for_user(user)?;
            let mut models = if model_path.exists() {
                UserModels::load(&model_path)?
            } else if has_legacy_models(user) {
                let legacy =
                    paths::user_model_path_legacy(user).expect("has_legacy_models returned true");
                UserModels::load(&legacy)?
            } else {
                UserModels::new(user)
            };

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            models.models.push(FaceModel {
                label: label.clone(),
                created: now,
                embedding: e.embedding,
            });

            // Ensure models directory exists
            if let Some(parent) = model_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            models.save(&model_path)?;

            println!("Face model added successfully:");
            println!("  Label: {label}");
            println!("  Detection score: {:.3}", e.det_score);
            println!("  Total models: {}", models.models.len());
        }
        Some(RespResult::Error(e)) => {
            bail!("Enrollment failed: {}", e.message);
        }
        other => {
            bail!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn cmd_enroll_batch(
    user: &str,
    session_dir: &str,
    label: Option<String>,
    delete_on_success: bool,
) -> Result<()> {
    check_root()?;

    let label = label.unwrap_or_else(|| "default".to_string());

    let dir = Path::new(session_dir);
    if !dir.is_dir() {
        bail!("Session directory not found: {session_dir}");
    }

    // Count image files for user feedback
    let image_count = std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| {
                    matches!(
                        ext.to_ascii_lowercase().as_str(),
                        "png" | "jpg" | "jpeg" | "bmp"
                    )
                })
                .unwrap_or(false)
        })
        .count();

    if image_count == 0 {
        bail!("No image files (png/jpg/bmp) found in {session_dir}");
    }

    println!("Enrolling {image_count} frame(s) for user '{user}' with label '{label}'...");

    let mut client = DaemonClient::default_path().with_timeout(std::time::Duration::from_secs(120));

    let response = client.request(&Request::enroll_batch(user, session_dir, &label))?;

    match response.result {
        Some(RespResult::EnrollBatchDone(r)) => {
            println!("\nEnrollment complete:");
            println!("  Frames found:    {}", r.frames_found);
            println!("  Frames accepted: {}", r.frames_accepted);
            println!("  Frames rejected: {}", r.frames_rejected);
            println!("  Time: {:.1}ms", r.elapsed_ms);

            if !r.rejection_details.is_empty() {
                println!("\nRejected frames:");
                for detail in &r.rejection_details {
                    println!("  - {detail}");
                }
            }

            if r.frames_accepted == 0 {
                bail!("No frames were accepted. Check image quality and try again.");
            }

            if delete_on_success {
                // Safety: only delete directories that look like howy enrollment
                // session dirs (under /tmp with the howy-enroll- prefix) to
                // prevent accidental recursive deletion of arbitrary paths.
                let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
                let safe_prefix = std::path::Path::new("/tmp/howy-enroll-");
                let is_safe = canonical
                    .to_str()
                    .map(|s| s.starts_with(safe_prefix.to_str().unwrap_or("/tmp/howy-enroll-")))
                    .unwrap_or(false);
                if is_safe {
                    match std::fs::remove_dir_all(dir) {
                        Ok(()) => println!("\nSession directory deleted: {session_dir}"),
                        Err(e) => eprintln!("\nWarning: failed to delete session directory: {e}"),
                    }
                } else {
                    eprintln!(
                        "\nWarning: refusing to delete {session_dir} (not under /tmp/howy-enroll-*)"
                    );
                }
            }

            println!(
                "\nSuccessfully enrolled {} embedding(s) for '{user}'.",
                r.frames_accepted
            );
        }
        Some(RespResult::Error(e)) => {
            bail!("Enrollment failed: {}", e.message);
        }
        other => {
            bail!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn cmd_list(user: &str) -> Result<()> {
    let model_path = model_path_for_user(user)?;

    if !model_path.exists() && !has_legacy_models(user) {
        println!("No face models enrolled for user '{user}'");
        return Ok(());
    }

    let models = UserModels::load(&model_path)?;

    if models.models.is_empty() {
        println!("No face models enrolled for user '{user}'");
        return Ok(());
    }

    println!("Face models for '{user}':");
    println!("{:<6} {:<24} {:<24}", "Index", "Label", "Created");
    println!("{}", "-".repeat(54));

    for (i, model) in models.models.iter().enumerate() {
        let created = format_timestamp(model.created);
        println!("{:<6} {:<24} {:<24}", i, model.label, created);
    }

    println!("\nTotal: {} model(s)", models.models.len());
    Ok(())
}

fn cmd_remove(user: &str, index: usize, skip_confirm: bool) -> Result<()> {
    check_root()?;

    let model_path = model_path_for_user(user)?;
    let mut models = UserModels::load(&model_path).context("No face models found")?;

    if models.models.is_empty() {
        bail!("No face models to remove for user '{user}'");
    }

    if index >= models.models.len() {
        bail!(
            "Invalid index {index}. Valid range: 0-{}",
            models.models.len() - 1
        );
    }

    let label = &models.models[index].label;

    if !skip_confirm {
        print!("Remove model '{label}' (index {index})? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let removed = models.models.remove(index);
    models.save(&model_path)?;

    println!("Removed model '{}' (index {index})", removed.label);
    println!("Remaining: {} model(s)", models.models.len());
    Ok(())
}

fn cmd_clear(user: &str, skip_confirm: bool) -> Result<()> {
    check_root()?;

    let model_path = model_path_for_user(user)?;

    if !model_path.exists() && !has_legacy_models(user) {
        println!("No face models to clear for user '{user}'");
        return Ok(());
    }

    if !skip_confirm {
        print!("Remove ALL face models for '{user}'? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Remove both bincode and legacy JSON files.
    let mut removed_any = false;
    if model_path.exists() {
        std::fs::remove_file(&model_path)?;
        removed_any = true;
    }
    if let Some(legacy) = paths::user_model_path_legacy(user) {
        if legacy.exists() {
            std::fs::remove_file(&legacy)?;
            removed_any = true;
        }
    }
    if removed_any {
        println!("All face models removed for '{user}'");
    }
    Ok(())
}

fn cmd_test(user: &str) -> Result<()> {
    println!("Testing face recognition for '{user}'...");

    let mut client = DaemonClient::default_path().with_timeout(std::time::Duration::from_secs(10));

    let response = client.authenticate(user, 0)?;

    match response.result {
        Some(RespResult::Success(s)) => {
            println!("MATCH FOUND:");
            println!("  Model: {} (index {})", s.model_label, s.model_index);
            println!("  Score: {:.4}", s.score);
            println!("  Time: {:.1}ms", s.elapsed_ms);
        }
        Some(RespResult::CredentialValid(_)) => {
            println!("Cached credential is valid (face scan skipped)");
        }
        Some(RespResult::AuthFailed(f)) => {
            println!("NO MATCH:");
            println!("  Reason: {}", f.reason);
            println!("  Best score: {:.4}", f.best_score);
            println!("  Frames: {}", f.frames_processed);
        }
        Some(RespResult::Error(e)) => {
            println!("ERROR: {}", e.message);
        }
        other => {
            println!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn cmd_status() -> Result<()> {
    let mut client = DaemonClient::default_path();

    if !client.ping() {
        println!("Daemon: NOT RUNNING");
        println!("  Start with: sudo systemctl start howy");
        return Ok(());
    }

    let response = client.request(&Request::info())?;

    match response.result {
        Some(RespResult::Info(info)) => {
            println!("Daemon: RUNNING");
            println!("  Provider: {}", info.provider);
            println!("  Detector: {}", info.detector_model);
            println!("  Recognizer: {}", info.recognizer_model);
            println!("  Embedding dim: {}", info.embedding_dim);
            println!("  Uptime: {}s", info.uptime_secs);
        }
        other => {
            println!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn cmd_doctor() -> Result<()> {
    println!("howy doctor");
    println!("  Version: {}", env!("CARGO_PKG_VERSION"));
    println!("  User: {}", whoami());
    println!("  Effective UID: {}", unsafe { libc::geteuid() });

    let config_path = Path::new(howy_common::paths::CONFIG_FILE);
    println!("\nConfig:");
    println!("  Path: {}", config_path.display());
    if config_path.exists() {
        match HowyConfig::load(config_path) {
            Ok(config) => {
                println!("  Requested provider: {}", config.ml.provider);
                println!(
                    "  Camera device: {}",
                    if config.video.device_path.is_empty() {
                        "<auto>"
                    } else {
                        &config.video.device_path
                    }
                );
                println!(
                    "  Detector model: {}",
                    if config.ml.detector_model.is_empty() {
                        "<auto>"
                    } else {
                        &config.ml.detector_model
                    }
                );
                println!(
                    "  Recognizer model: {}",
                    if config.ml.recognizer_model.is_empty() {
                        "<auto>"
                    } else {
                        &config.ml.recognizer_model
                    }
                );
            }
            Err(e) => println!("  Failed to load config: {e}"),
        }
    } else {
        println!("  Missing");
    }

    println!("\nDaemon:");
    println!("  Socket path: {}", howy_common::paths::SOCKET_PATH);
    let mut client = DaemonClient::default_path();
    match client.request(&Request::info()) {
        Ok(response) => match response.result {
            Some(RespResult::Info(info)) => {
                println!("  Reachable: yes");
                println!("  Effective provider: {}", info.provider);
                println!("  Uptime: {}s", info.uptime_secs);
            }
            other => {
                println!("  Reachable: unexpected response: {other:?}");
            }
        },
        Err(e) => {
            println!("  Reachable: no ({e})");
        }
    }

    println!("\nCache:");
    let cache_dir = Path::new("/var/cache/howy");
    println!("  Dir: {}", cache_dir.display());
    if cache_dir.is_dir() {
        let mut mxr_files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("mxr") {
                    mxr_files.push(path);
                }
            }
        }
        println!("  .mxr files: {}", mxr_files.len());
        for path in mxr_files.iter().take(8) {
            if let Ok(meta) = std::fs::metadata(path) {
                println!("    - {} ({} bytes)", path.display(), meta.len());
            } else {
                println!("    - {}", path.display());
            }
        }

        let provider_cache = cache_dir.join("provider-selection.txt");
        if let Ok(contents) = std::fs::read_to_string(&provider_cache) {
            println!("  Cached provider: {}", contents.trim());
        } else {
            println!("  Cached provider: <none>");
        }

        let prewarm_marker = cache_dir.join("prewarm-status.txt");
        println!(
            "  Prewarm marker: {}",
            if prewarm_marker.exists() {
                "present"
            } else {
                "missing"
            }
        );
    } else {
        println!("  Missing");
    }

    Ok(())
}

fn cmd_prewarm() -> Result<()> {
    check_root()?;

    let howyd = find_howyd_binary();
    if !howyd.is_file() {
        bail!("howyd binary not found at {}", howyd.display());
    }

    let config_path = Path::new(howy_common::paths::CONFIG_FILE);
    let provider = if config_path.exists() {
        HowyConfig::load(config_path)
            .map(|c| c.ml.provider)
            .unwrap_or_else(|_| "auto".to_string())
    } else {
        "auto".to_string()
    };

    println!("Running prewarm with provider='{}'...", provider);

    let mut command = Command::new(&howyd);
    command.arg("--prewarm-only");
    command.env("RUST_LOG", "info");

    let provider_norm = provider.trim().to_ascii_lowercase();
    if provider_norm == "migraphx" || provider_norm == "auto" {
        command.env("HSA_OVERRIDE_GFX_VERSION", "11.0.2");
        command.env("ORT_MIGRAPHX_MODEL_CACHE_PATH", "/var/cache/howy");
        command.env("ORT_MIGRAPHX_CACHE_PATH", "/var/cache/howy");
    }

    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to run howyd prewarm")?;

    if !status.success() {
        bail!("prewarm failed with exit status {status}");
    }

    println!("Prewarm completed.");
    Ok(())
}

fn cmd_config(to_stdout: bool) -> Result<()> {
    let config_toml = howy_common::config::HowyConfig::default_toml();

    if to_stdout {
        println!("{config_toml}");
    } else {
        check_root()?;
        let config_path = Path::new(howy_common::paths::CONFIG_FILE);

        if config_path.exists() {
            print!(
                "Config already exists at {}. Overwrite? [y/N] ",
                config_path.display()
            );
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(config_path, &config_toml)?;
        println!("Config written to {}", config_path.display());
    }

    Ok(())
}

// Helpers

fn check_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("This command requires root. Run with: sudo howy ...");
    }
    Ok(())
}

fn resolve_target_user(cli_user: Option<&str>) -> Result<String> {
    let user = cli_user.map(str::to_owned).unwrap_or_else(|| {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("DOAS_USER"))
            .unwrap_or_else(|_| whoami())
    });

    if user.is_empty() || user == "root" {
        bail!("Cannot run howy commands as root. Use --user or run with sudo.");
    }

    Ok(user)
}

fn model_path_for_user(user: &str) -> Result<std::path::PathBuf> {
    match paths::user_model_path(user) {
        Some(path) => Ok(path),
        None => bail!("Invalid username '{user}'"),
    }
}

/// Check if legacy JSON models exist for a user.
fn has_legacy_models(user: &str) -> bool {
    paths::user_model_path_legacy(user)
        .map(|p| p.exists())
        .unwrap_or(false)
}

fn find_howyd_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sibling = parent.join("howyd");
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from("/usr/bin/howyd")
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

fn format_timestamp(ts: u64) -> String {
    // Simple formatting without chrono dependency
    if ts == 0 {
        return "unknown".to_string();
    }
    // Just show the unix timestamp — good enough for a CLI
    format!("{ts}")
}
