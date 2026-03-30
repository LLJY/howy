//! Unix socket server for the howy daemon.
//!
//! Handles IPC requests from the PAM module and CLI tools.
//! Supports systemd socket activation via `LISTEN_FDS`.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use howy_common::config::HowyConfig;
use howy_common::credential;
use howy_common::face::{self, UserModels};
use howy_common::ipc;
use howy_common::paths;
use howy_common::protocol::{self, Cmd, Request, RespResult, Response};

use crate::camera::Camera;
use crate::inference::InferenceEngine;

/// Serialize passwd lookups because getpwnam is not thread-safe.
static PASSWD_LOOKUP_LOCK: Mutex<()> = Mutex::new(());

const CAMERA_LOCK_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the daemon server.
pub async fn run(engine: Arc<InferenceEngine>, config: HowyConfig) -> Result<()> {
    let start = Instant::now();
    let camera_lock = Arc::new(Mutex::new(()));

    if config.credentials.enable_cache {
        warn!(
            "Credential caching is configured but disabled at runtime until PAM session-scoped cache keys are implemented"
        );
    }

    // Try systemd socket activation first
    let listener = match try_systemd_socket() {
        Some(listener) => {
            info!("Using systemd socket activation");
            listener
        }
        None => {
            // Manual socket creation
            let socket_path = paths::SOCKET_PATH;

            // Ensure runtime directory exists
            let runtime_dir = Path::new(paths::RUNTIME_DIR);
            if !runtime_dir.exists() {
                std::fs::create_dir_all(runtime_dir)
                    .context("failed to create runtime directory")?;
            }

            // Remove stale socket
            if Path::new(socket_path).exists() {
                std::fs::remove_file(socket_path)?;
            }

            let listener = UnixListener::bind(socket_path)
                .context("failed to bind Unix socket")?;

            // Allow all users to connect (PAM runs as various users)
            set_socket_permissions(socket_path)?;

            info!("Listening on {socket_path}");
            listener
        }
    };

    // Set non-blocking for graceful shutdown
    listener.set_nonblocking(false)?;

    // Handle connections
    info!("Daemon ready, accepting connections");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let engine = Arc::clone(&engine);
                let config = config.clone();
                let camera_lock = Arc::clone(&camera_lock);
                let uptime = start.elapsed().as_secs();

                // Handle in a thread (we're I/O bound on camera, not CPU)
                std::thread::spawn(move || {
                    if let Err(e) =
                        handle_connection(stream, &engine, &config, &camera_lock, uptime)
                    {
                        error!("Connection error: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {e}");
            }
        }
    }

    Ok(())
}

/// Handle a single client connection.
fn handle_connection(
    mut stream: UnixStream,
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_lock: &Mutex<()>,
    uptime: u64,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request: Request = ipc::recv_message(&mut stream)?;
    let peer_uid = get_peer_uid(&stream);
    debug!(
        "Received request: {:?}",
        request.cmd.as_ref().map(|cmd| std::mem::discriminant(cmd))
    );

    let response = match request.cmd {
        Some(Cmd::Authenticate(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if !can_access_username(peer_uid, &req.username) {
                Response::error("permission denied")
            } else {
                handle_authenticate(engine, config, camera_lock, &req.username, req.timeout)
            }
        }
        Some(Cmd::Enroll(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                handle_enroll(engine, config, camera_lock, &req.username, &req.label)
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
            let provider = engine.active_provider().to_string();
            let detector_model = engine.detector_model_path();
            let recognizer_model = engine.recognizer_model_path();
            Response::daemon_info(
                &provider,
                &detector_model,
                &recognizer_model,
                512,
                uptime,
            )
        }
        Some(Cmd::Shutdown(_)) => {
            if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                info!("Shutdown requested");
                ipc::send_message(&mut stream, &Response::pong())?;
                std::process::exit(0);
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

    ipc::send_message(&mut stream, &response)?;
    Ok(())
}

/// Handle an authentication request.
fn handle_authenticate(
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_lock: &Mutex<()>,
    username: &str,
    timeout_override: u32,
) -> Response {
    if !is_valid_username(username) {
        return Response::error("invalid username");
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
                info!("Cached credential valid for {username}");
                return Response::credential_valid();
            }
            Ok(false) => debug!("No valid cached credential for {username}"),
            Err(e) => debug!("Credential check failed: {e}"),
        }
    }

    // Load user face models
    let model_path = match paths::user_model_path(username) {
        Some(path) => path,
        None => {
            return Response::error("invalid username");
        }
    };
    let user_models = match UserModels::load(&model_path) {
        Ok(m) if !m.models.is_empty() => m,
        Ok(_) => {
            return Response::auth_failed(0.0, 0, "No face models enrolled");
        }
        Err(e) => {
            return Response::auth_failed(0.0, 0, &format!("Failed to load face models: {e}"));
        }
    };

    let known_embeddings: Vec<&[f32]> = user_models.embeddings();
    let threshold = config.ml.recognition_threshold;
    let timeout = if timeout_override > 0 {
        timeout_override.min(30)
    } else {
        config.video.timeout.min(30)
    };

    let _camera_guard = match try_acquire_camera_lock(camera_lock, CAMERA_LOCK_TIMEOUT) {
        Ok(guard) => guard,
        Err(response) => {
            warn!(username, "Authentication infrastructure failure: camera busy");
            return response;
        }
    };

    // Open camera
    let mut camera = match Camera::open(
        &config.video.device_path,
        config.video.frame_width,
        config.video.frame_height,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(username, error = %e, "Authentication infrastructure failure opening camera");
            return Response::error(&format!("Camera error: {e}"));
        }
    };

    if let Err(e) = camera.start() {
        warn!(username, error = %e, "Authentication infrastructure failure starting camera");
        return Response::error(&format!("Failed to start camera: {e}"));
    }

    let deadline = Duration::from_secs(timeout as u64);
    let mut frames_processed = 0u32;
    let mut best_score = 0.0f32;
    let mut dark_frames = 0u32;

    // Main recognition loop
    while start.elapsed() < deadline {
        // Capture frame
        let (bgr_data, width, height) = match camera.capture_frame() {
            Ok(f) => f,
            Err(e) => {
                warn!(username, error = %e, "Authentication infrastructure failure capturing frame");
                return Response::error(&format!("Camera capture failed: {e}"));
            }
        };

        frames_processed += 1;

        // Check for dark/black frames
        if is_dark_frame(&bgr_data, config.video.dark_threshold) {
            dark_frames += 1;
            continue;
        }

        // Detect and encode faces
        let faces = match engine.analyze(&bgr_data, width, height) {
            Ok(f) => f,
            Err(e) => {
                debug!("Detection error: {e}");
                continue;
            }
        };

        // Match against enrolled faces
        for face_result in &faces {
            if let Some(ref embedding) = face_result.embedding {
                let (match_idx, score) = match face::find_best_match(
                    embedding,
                    &known_embeddings,
                    threshold,
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        debug!("Face matching error: {e}");
                        continue;
                    }
                };

                if score > best_score {
                    best_score = score;
                }

                if let Some(idx) = match_idx {
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

                    info!(
                        username,
                        model_index = idx,
                        model_label = %user_models.models[idx].label,
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

                    return Response::success(
                        idx as u32,
                        &user_models.models[idx].label,
                        score,
                        elapsed_ms,
                    );
                }
            }
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

    Response::auth_failed(best_score, frames_processed, &reason)
}

/// Handle a face enrollment request.
fn handle_enroll(
    engine: &InferenceEngine,
    config: &HowyConfig,
    camera_lock: &Mutex<()>,
    username: &str,
    label: &str,
) -> Response {
    if !is_valid_username(username) {
        return Response::error("invalid username");
    }

    let _camera_guard = match try_acquire_camera_lock(camera_lock, CAMERA_LOCK_TIMEOUT) {
        Ok(guard) => guard,
        Err(response) => return response,
    };

    // Open camera
    let mut camera = match Camera::open(
        &config.video.device_path,
        config.video.frame_width,
        config.video.frame_height,
    ) {
        Ok(c) => c,
        Err(e) => {
            warn!(username, error = %e, "Enrollment infrastructure failure opening camera");
            return Response::error(&format!("Camera error: {e}"));
        }
    };

    if let Err(e) = camera.start() {
        warn!(username, error = %e, "Enrollment infrastructure failure starting camera");
        return Response::error(&format!("Failed to start camera: {e}"));
    }

    // Capture several frames and pick the best face
    let mut best_face: Option<(Vec<f32>, f32)> = None;
    let deadline = Duration::from_secs(5);
    let start = Instant::now();

    while start.elapsed() < deadline {
        let (bgr_data, width, height) = match camera.capture_frame() {
            Ok(f) => f,
            Err(e) => {
                warn!(username, error = %e, "Enrollment infrastructure failure capturing frame");
                return Response::error(&format!("Camera capture failed: {e}"));
            }
        };

        if is_dark_frame(&bgr_data, config.video.dark_threshold) {
            continue;
        }

        match engine.analyze(&bgr_data, width, height) {
            Ok(faces) => {
                for face_result in &faces {
                    if let Some(ref emb) = face_result.embedding {
                        let det_score = face_result.score;
                        if best_face.is_none()
                            || det_score > best_face.as_ref().unwrap().1
                        {
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

    match best_face {
        Some((embedding, det_score)) => {
            info!(username, label, det_score, "Face enrolled");
            Response::enrolled(embedding, det_score)
        }
        None => Response::error("No face detected during enrollment"),
    }
}

/// Handle a detection-only request (for testing).
fn handle_detect(
    engine: &InferenceEngine,
    frame: &[u8],
    height: u32,
    width: u32,
) -> Response {
    let start = Instant::now();

    match engine.analyze(frame, width, height) {
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

fn handle_revoke_credential(
    config: &HowyConfig,
    username: &str,
    session_id: &str,
) -> Response {
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

fn try_acquire_camera_lock<'a>(
    camera_lock: &'a Mutex<()>,
    timeout: Duration,
) -> std::result::Result<MutexGuard<'a, ()>, Response> {
    let start = Instant::now();

    loop {
        match camera_lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => {
                warn!("camera lock poisoned; proceeding anyway");
                return Ok(poisoned.into_inner());
            }
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() >= timeout {
                    warn!(timeout_secs = timeout.as_secs(), "Timed out waiting for camera lock");
                    return Err(Response::error("camera busy"));
                }

                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Check if a frame is too dark for face detection.
fn is_dark_frame(bgr_data: &[u8], threshold: f32) -> bool {
    if bgr_data.is_empty() {
        return true;
    }

    // Sample every 16th pixel for speed
    let mut dark_count = 0u32;
    let mut total = 0u32;

    for i in (0..bgr_data.len()).step_by(48) {
        // 16 pixels * 3 channels
        if i + 2 < bgr_data.len() {
            let brightness =
                (bgr_data[i] as u32 + bgr_data[i + 1] as u32 + bgr_data[i + 2] as u32) / 3;
            if brightness < 30 {
                dark_count += 1;
            }
            total += 1;
        }
    }

    if total == 0 {
        return true;
    }

    let dark_pct = (dark_count as f32 / total as f32) * 100.0;
    dark_pct > threshold
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

    if ret == 0 {
        Some(cred.uid)
    } else {
        None
    }
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
