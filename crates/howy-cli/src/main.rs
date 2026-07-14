//! howy — CLI tool for managing face models and testing authentication.

use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use howy_common::config::HowyConfig;
use howy_common::env::parse_strict_bool;
use howy_common::ipc::DaemonClient;
use howy_common::protocol::{
    EnrollBatchResult, EnrollSuccess, EnrollmentMetadataEntry, LIVE_ENROLLMENT_PROTOCOL_VERSION,
    ListEnrollmentsResult, Request, RespResult, STORAGE_CONFLICT_ERROR,
};

mod importer;
mod security;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliKeySelection {
    Auto,
    Host,
    Tpm2,
    #[value(name = "host+tpm2")]
    HostAndTpm2,
}

impl From<CliKeySelection> for security::KeySelection {
    fn from(value: CliKeySelection) -> Self {
        match value {
            CliKeySelection::Auto => Self::Auto,
            CliKeySelection::Host => Self::Host,
            CliKeySelection::Tpm2 => Self::Tpm2,
            CliKeySelection::HostAndTpm2 => Self::HostAndTpm2,
        }
    }
}

#[derive(Subcommand)]
enum SecurityCommands {
    /// Provision an explicit storage security mode transactionally.
    Provision {
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2))]
        mode: u8,
        #[arg(long, value_enum, default_value = "auto")]
        with_key: CliKeySelection,
        #[arg(long)]
        adopt_existing: bool,
    },
    /// Activate an exact receipted disabled Mode-1 candidate.
    Enable,
    /// Deterministically recover the durable security transaction journal.
    Recover,
    /// Remove an exact unadopted artifact after reference-safe revalidation.
    CleanupUnadopted {
        #[arg(long)]
        transaction: String,
        #[arg(long)]
        artifact_sha256: String,
    },
}

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
    #[command(name = "__image-import", hide = true)]
    ImageImport {
        #[arg(long)]
        session_dir: String,
    },
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

    /// Provision, activate, recover, or clean up storage security state.
    Security {
        #[command(subcommand)]
        command: SecurityCommands,
    },

    /// Print the version.
    Version,
}

fn main() -> Result<()> {
    let Cli { user, yes, command } = Cli::parse();
    let perf_trace = parse_strict_bool(
        "HOWY_PERF_TRACE",
        std::env::var_os("HOWY_PERF_TRACE").as_deref(),
        false,
    )?;

    match command {
        Commands::ImageImport { session_dir } => importer::run_hidden_importer(&session_dir),
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
            cmd_test(&user, perf_trace)
        }
        Commands::Status => cmd_status(),
        Commands::Doctor => cmd_doctor(),
        Commands::Prewarm => cmd_prewarm(),
        Commands::Config { stdout } => cmd_config(stdout),
        Commands::Security { command } => cmd_security(command, yes),
        Commands::Version => {
            println!("howy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn cmd_security(command: SecurityCommands, assume_yes: bool) -> Result<()> {
    let mut runtime = security::RealSecurityRuntime::new();
    let mut engine = security::SecurityEngine::new(&mut runtime);
    let outcome = match command {
        SecurityCommands::Provision {
            mode,
            with_key,
            adopt_existing,
        } => {
            let mode = match mode {
                0 => security::ProvisionMode::Plaintext,
                1 => security::ProvisionMode::CachedAead,
                2 => security::ProvisionMode::EphemeralAead,
                _ => unreachable!("clap restricts security mode"),
            };
            let confirmed = if assume_yes {
                true
            } else {
                if mode == security::ProvisionMode::Plaintext {
                    eprintln!(
                        "WARNING: Mode 0 stores face embeddings in plaintext. Encrypted artifacts and namespaces will be preserved."
                    );
                }
                prompt_yes("Proceed with the transactional security migration? [y/N] ")?
            };
            engine.provision(security::ProvisionRequest {
                mode,
                with_key: with_key.into(),
                adopt_existing,
                confirmed,
            })
        }
        SecurityCommands::Enable => engine.enable(),
        SecurityCommands::Recover => engine.recover(),
        SecurityCommands::CleanupUnadopted {
            transaction,
            artifact_sha256,
        } => {
            let artifact_sha256 = howy_common::provisioning::Sha256Digest::parse(artifact_sha256)
                .map_err(|error| anyhow::anyhow!(error))?;
            engine.cleanup_unadopted(security::CleanupRequest {
                transaction_id: transaction,
                artifact_sha256,
            })
        }
    }
    .map_err(|error| anyhow::anyhow!(error))?;
    for message in outcome.messages {
        println!("{message}");
    }
    if let Some(command) = outcome.cleanup_command {
        println!("Safe cleanup command: {command}");
    }
    Ok(())
}

fn prompt_yes(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y"))
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
            validate_live_enrollment_result(&e)?;
            println!("Face model added successfully:");
            println!("  Label: {label}");
            println!("  Detection score: {:.3}", e.det_score);
            println!("  Total models: {}", e.total_count);
        }
        Some(RespResult::Error(error)) => return daemon_storage_error("Enrollment failed", error),
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
    let staged = importer::stage_session(dir)?;
    let image_count = staged.image_count();

    println!("Enrolling {image_count} frame(s) for user '{user}' with label '{label}'...");

    let mut client = DaemonClient::default_path().with_timeout(std::time::Duration::from_secs(120));

    let staging_path = staged
        .path()
        .to_str()
        .context("staging path is not valid UTF-8")?;
    let response = client.request(&Request::enroll_batch(user, staging_path, &label))?;

    match response.result {
        Some(RespResult::EnrollBatchDone(r)) => {
            validate_batch_enrollment_result(&r)?;
            println!("\nEnrollment complete:");
            println!("  Frames found:    {}", r.frames_found);
            println!("  Frames accepted: {}", r.frames_accepted);
            println!("  Frames rejected: {}", r.frames_rejected);
            println!("  Total models:    {}", r.total_count);
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
        Some(RespResult::Error(error)) => return daemon_storage_error("Enrollment failed", error),
        other => {
            bail!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn validate_live_enrollment_result(result: &EnrollSuccess) -> Result<()> {
    if result.enrollment_protocol_version != LIVE_ENROLLMENT_PROTOCOL_VERSION {
        bail!(
            "Enrollment failed: daemon does not support compatible daemon-owned storage enrollment"
        );
    }
    if result.enrollment_id.len() != 16
        || result.enrollment_id.iter().all(|byte| *byte == 0)
        || result.generation == 0
        || result.total_count == 0
        || !result.det_score.is_finite()
    {
        bail!("Enrollment failed: daemon returned invalid enrollment metadata");
    }
    Ok(())
}

fn validate_batch_enrollment_result(result: &EnrollBatchResult) -> Result<()> {
    let classified = result
        .frames_accepted
        .checked_add(result.frames_rejected)
        .filter(|classified| *classified == result.frames_found);
    if classified.is_none()
        || !result.elapsed_ms.is_finite()
        || result.elapsed_ms < 0.0
        || (result.generation == 0 && result.total_count != 0)
        || (result.frames_accepted > 0
            && (result.generation == 0 || result.total_count < result.frames_accepted))
    {
        bail!("Enrollment failed: daemon returned legacy or invalid batch metadata");
    }
    Ok(())
}

fn cmd_list(user: &str) -> Result<()> {
    check_root()?;
    let list = fetch_enrollments(user)?;
    if list.entries.is_empty() {
        println!("No face models enrolled for user '{user}'");
        return Ok(());
    }

    println!("Face models for '{user}':");
    println!("{:<6} {:<24} {:<24}", "Index", "Label", "Created");
    println!("{}", "-".repeat(54));

    for (i, model) in list.entries.iter().enumerate() {
        let created = format_timestamp(model.created_unix_seconds);
        println!("{:<6} {:<24} {:<24}", i, model.label, created);
    }

    println!("\nTotal: {} model(s)", list.entries.len());
    Ok(())
}

fn cmd_remove(user: &str, index: usize, skip_confirm: bool) -> Result<()> {
    check_root()?;

    let list = fetch_enrollments(user)?;
    if list.entries.is_empty() {
        bail!("No face models to remove for user '{user}'");
    }
    let selected = select_enrollment(&list, index)?;
    let label = &selected.entry.label;

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

    let mut client = DaemonClient::default_path();
    let response = client.request(&Request::remove_enrollment(
        user,
        selected.entry.enrollment_id.clone(),
        selected.generation,
    ))?;
    match response.result {
        Some(RespResult::RemoveEnrollment(_)) => {
            println!("Removed model '{}' (index {index})", selected.entry.label);
            println!("Remaining: {} model(s)", list.entries.len() - 1);
        }
        Some(RespResult::Error(error)) => return daemon_storage_error("Removal failed", error),
        other => bail!("Unexpected response: {other:?}"),
    }
    Ok(())
}

fn cmd_clear(user: &str, skip_confirm: bool) -> Result<()> {
    check_root()?;

    let list = fetch_enrollments(user)?;
    if list.entries.is_empty() && list.generation == 0 {
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

    let mut client = DaemonClient::default_path();
    let response = client.request(&Request::clear_enrollments(user, list.generation))?;
    match response.result {
        Some(RespResult::ClearEnrollments(_)) => {
            println!("All face models removed for '{user}'");
        }
        Some(RespResult::Error(error)) => return daemon_storage_error("Clear failed", error),
        other => bail!("Unexpected response: {other:?}"),
    }
    Ok(())
}

fn cmd_test(user: &str, perf_trace: bool) -> Result<()> {
    println!("Testing face recognition for '{user}'...");

    let mut client = DaemonClient::default_path().with_timeout(std::time::Duration::from_secs(10));

    let request_started = perf_trace.then(Instant::now);
    let response = client.request(&test_auth_request(user));
    if let Some(started) = request_started {
        println!(
            "Client request wall: {:.1}ms",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    let response = response?;

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

fn test_auth_request(user: &str) -> Request {
    Request::authenticate_v1(user, 0)
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
            println!("  Registered provider preference: {}", info.provider);
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
                println!("  Registered provider preference: {}", info.provider);
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

        println!("  Auto provider cache: disabled (stale selection files are ignored)");

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
    configure_private_umask(&mut command);

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

fn configure_private_umask(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Commands, SecurityCommands, configure_private_umask, select_enrollment,
        test_auth_request, validate_batch_enrollment_result, validate_live_enrollment_result,
    };
    use clap::Parser;
    use howy_common::protocol::{
        Cmd, EnrollBatchResult, EnrollSuccess, EnrollmentMetadataEntry,
        LIVE_ENROLLMENT_PROTOCOL_VERSION, ListEnrollmentsResult, Request,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[test]
    fn prewarm_child_mxr_creation_inherits_private_umask() {
        let directory = std::env::temp_dir().join(format!(
            "howy-cli-umask-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let cache_file = directory.join("mock.mxr");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("touch \"$1\"")
            .arg("sh")
            .arg(&cache_file);
        configure_private_umask(&mut command);
        assert!(command.status().unwrap().success());
        assert_eq!(
            std::fs::metadata(&cache_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn security_command_surface_is_exact_and_numeric_modes_are_bounded() {
        let cli = Cli::try_parse_from([
            "howy",
            "security",
            "provision",
            "--mode",
            "1",
            "--with-key",
            "host+tpm2",
            "--adopt-existing",
        ])
        .unwrap();
        let Commands::Security {
            command:
                SecurityCommands::Provision {
                    mode,
                    adopt_existing,
                    ..
                },
        } = cli.command
        else {
            panic!("expected security provision")
        };
        assert_eq!(mode, 1);
        assert!(adopt_existing);

        assert!(
            Cli::try_parse_from([
                "howy",
                "security",
                "cleanup-unadopted",
                "--transaction",
                "txn-1",
                "--artifact-sha256",
                &"01".repeat(32),
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["howy", "security", "provision", "--mode", "3",]).is_err());
        assert!(
            Cli::try_parse_from(["howy", "security", "provision", "--mode", "1", "--new-key",])
                .is_err()
        );
    }

    #[test]
    fn test_command_uses_only_versioned_authenticate_without_preflight_or_legacy_retry() {
        let request = test_auth_request("alice");
        let Some(Cmd::AuthenticateV1(request)) = request.cmd else {
            panic!("howy test must use only AuthenticateV1")
        };
        assert_eq!(request.username, "alice");
        assert_eq!(request.timeout, 0);
        request.validate().unwrap();
    }

    #[test]
    fn remove_display_index_maps_to_stable_id_and_list_generation() {
        let list = ListEnrollmentsResult {
            generation: 7,
            entries: vec![
                EnrollmentMetadataEntry {
                    enrollment_id: vec![1; 16],
                    label: "first".into(),
                    created_unix_seconds: 1,
                },
                EnrollmentMetadataEntry {
                    enrollment_id: vec![2; 16],
                    label: "second".into(),
                    created_unix_seconds: 2,
                },
            ],
        };
        let selected = select_enrollment(&list, 1).unwrap();
        let request = Request::remove_enrollment(
            "alice",
            selected.entry.enrollment_id.clone(),
            selected.generation,
        );
        let Some(Cmd::RemoveEnrollment(request)) = request.cmd else {
            panic!("expected remove request");
        };
        assert_eq!(request.enrollment_id, vec![2; 16]);
        assert_eq!(request.expected_generation, 7);
    }

    #[test]
    fn remove_index_rejects_invalid_daemon_metadata() {
        let list = ListEnrollmentsResult {
            generation: 0,
            entries: vec![EnrollmentMetadataEntry {
                enrollment_id: vec![1; 16],
                label: "invalid".into(),
                created_unix_seconds: 1,
            }],
        };
        assert!(select_enrollment(&list, 0).is_err());
        assert!(select_enrollment(&list, 1).is_err());
    }

    #[test]
    fn live_enrollment_rejects_legacy_and_invalid_metadata() {
        let valid = EnrollSuccess {
            det_score: 0.9,
            enrollment_id: vec![7; 16],
            generation: 1,
            total_count: 1,
            enrollment_protocol_version: LIVE_ENROLLMENT_PROTOCOL_VERSION,
        };
        assert!(validate_live_enrollment_result(&valid).is_ok());

        let mut legacy = valid.clone();
        legacy.enrollment_protocol_version = 0;
        legacy.enrollment_id.clear();
        legacy.generation = 0;
        legacy.total_count = 0;
        assert!(validate_live_enrollment_result(&legacy).is_err());

        for invalid in [
            EnrollSuccess {
                enrollment_id: vec![0; 16],
                ..valid.clone()
            },
            EnrollSuccess {
                generation: 0,
                ..valid.clone()
            },
            EnrollSuccess {
                total_count: 0,
                ..valid.clone()
            },
            EnrollSuccess {
                det_score: f32::NAN,
                ..valid
            },
        ] {
            assert!(validate_live_enrollment_result(&invalid).is_err());
        }
    }

    #[test]
    fn accepted_batch_rejects_legacy_or_inconsistent_metadata() {
        let valid = EnrollBatchResult {
            frames_found: 2,
            frames_accepted: 2,
            frames_rejected: 0,
            elapsed_ms: 1.0,
            rejection_details: Vec::new(),
            generation: 1,
            total_count: 2,
        };
        assert!(validate_batch_enrollment_result(&valid).is_ok());
        assert!(
            validate_batch_enrollment_result(&EnrollBatchResult {
                generation: 0,
                ..valid.clone()
            })
            .is_err()
        );
        assert!(
            validate_batch_enrollment_result(&EnrollBatchResult {
                total_count: 1,
                ..valid
            })
            .is_err()
        );
    }
}

fn cmd_config(to_stdout: bool) -> Result<()> {
    let config_toml = howy_common::config::HowyConfig::fresh_template_toml();

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

fn fetch_enrollments(user: &str) -> Result<ListEnrollmentsResult> {
    let mut client = DaemonClient::default_path();
    let response = client.request(&Request::list_enrollments(user))?;
    match response.result {
        Some(RespResult::ListEnrollments(list)) => Ok(list),
        Some(RespResult::Error(error)) => daemon_storage_error("List failed", error),
        other => bail!("Unexpected response: {other:?}"),
    }
}

struct SelectedEnrollment<'a> {
    generation: u64,
    entry: &'a EnrollmentMetadataEntry,
}

fn select_enrollment(list: &ListEnrollmentsResult, index: usize) -> Result<SelectedEnrollment<'_>> {
    let entry = list.entries.get(index).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid index {index}. Valid range: 0-{}",
            list.entries.len().saturating_sub(1)
        )
    })?;
    if list.generation == 0 || entry.enrollment_id.len() != 16 {
        bail!("Daemon returned invalid enrollment metadata");
    }
    Ok(SelectedEnrollment {
        generation: list.generation,
        entry,
    })
}

fn daemon_storage_error<T>(context: &str, error: howy_common::protocol::Error) -> Result<T> {
    if error.code == STORAGE_CONFLICT_ERROR {
        bail!("{context}: enrollment data changed; run `howy list` and retry");
    }
    bail!("{context}: {}", error.message)
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
