//! Standard filesystem paths for howy.

use std::path::{Path, PathBuf};

/// Runtime directory (created by systemd or manually).
pub const RUNTIME_DIR: &str = "/run/howy";

/// Unix domain socket path for daemon IPC.
pub const SOCKET_PATH: &str = "/run/howy/howy.sock";

/// System configuration directory.
pub const CONFIG_DIR: &str = "/etc/howy";

/// Default configuration file path.
pub const CONFIG_FILE: &str = "/etc/howy/config.toml";

/// System-wide face model storage.
pub const MODELS_DIR: &str = "/etc/howy/models";

/// ONNX model data directory.
pub const ONNX_DATA_DIR: &str = "/usr/share/howy/onnx-data";

/// Log directory.
pub const LOG_DIR: &str = "/var/log/howy";

/// Snapshot directory.
pub const SNAPSHOT_DIR: &str = "/var/log/howy/snapshots";

/// Validate a username for safe filesystem usage.
pub fn validate_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && !username.contains("..")
        && username.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
}

/// User face model file for a given username.
pub fn user_model_path(username: &str) -> Option<PathBuf> {
    validate_username(username).then(|| Path::new(MODELS_DIR).join(format!("{username}.json")))
}

/// Find an ONNX model file, searching standard locations.
pub fn find_model(filename: &str) -> Option<PathBuf> {
    let search_paths = [
        PathBuf::from(ONNX_DATA_DIR).join(filename),
        PathBuf::from("/usr/local/share/howy/onnx-data").join(filename),
        PathBuf::from("/lib/security/howy/onnx-data").join(filename),
        // Development: relative to binary
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("models").join(filename)))
            .unwrap_or_default(),
    ];

    search_paths.into_iter().find(|p| p.is_file())
}
