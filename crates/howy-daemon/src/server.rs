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

use crate::camera::{Camera, Frame, FrameFormat};
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

            let listener = UnixListener::bind(&socket_path)
                .context("failed to bind Unix socket")?;

            // Allow all users to connect (PAM runs as various users)
            set_socket_permissions(&socket_path)?;

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
        Some(Cmd::EnrollBatch(req)) => {
            if !is_valid_username(&req.username) {
                Response::error("invalid username")
            } else if peer_uid != Some(0) {
                Response::error("permission denied")
            } else {
                handle_enroll_batch(engine, &req.username, &req.session_dir, &req.label)
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
        config.video.device_fps,
        config.video.exposure,
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
        let frame = match camera.capture_frame() {
            Ok(frame) => frame,
            Err(e) => {
                warn!(username, error = %e, "Authentication infrastructure failure capturing frame");
                return Response::error(&format!("Camera capture failed: {e}"));
            }
        };

        frames_processed += 1;

        // Check for dark/black frames
        if is_dark_frame(&frame, config.video.dark_threshold) {
            dark_frames += 1;
            if config.video.max_dark_frames > 0 && dark_frames >= config.video.max_dark_frames {
                info!(
                    username,
                    dark_frames,
                    "Exceeded max consecutive dark frames — camera may be covered"
                );
                return Response::auth_failed(
                    0.0,
                    frames_processed,
                    &format!(
                        "Too many dark frames ({dark_frames}) — camera may be covered or IR emitter not working"
                    ),
                );
            }
            continue;
        }
        // Reset dark frame counter on a good frame
        dark_frames = 0;

        // Detect and encode faces
        let is_gray = frame.format == FrameFormat::Gray;
        let faces = match engine.analyze(&frame.data, frame.width, frame.height, is_gray) {
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
        config.video.device_fps,
        config.video.exposure,
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
        let frame = match camera.capture_frame() {
            Ok(frame) => frame,
            Err(e) => {
                warn!(username, error = %e, "Enrollment infrastructure failure capturing frame");
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
    let mut user_models = if model_path.exists() {
        match UserModels::load(&model_path) {
            Ok(m) => m,
            Err(e) => {
                return Response::error(&format!(
                    "failed to load existing models (refusing to overwrite): {e}"
                ));
            }
        }
    } else {
        // Check legacy JSON path for migration
        match paths::user_model_path_legacy(username) {
            Some(legacy) if legacy.exists() => match UserModels::load(&legacy) {
                Ok(m) => m,
                Err(e) => {
                    return Response::error(&format!(
                        "failed to load legacy models (refusing to overwrite): {e}"
                    ));
                }
            },
            _ => UserModels::new(username),
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
fn handle_detect(
    engine: &InferenceEngine,
    frame: &[u8],
    height: u32,
    width: u32,
) -> Response {
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
                    let brightness =
                        (frame.data[i] as u32 + frame.data[i + 1] as u32 + frame.data[i + 2] as u32) / 3;
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
    let img = image::open(path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
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
