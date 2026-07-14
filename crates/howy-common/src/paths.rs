//! Standard filesystem paths for howy.

use std::path::{Path, PathBuf};

/// Runtime directory (created by systemd or manually).
pub const RUNTIME_DIR: &str = "/run/howy";

/// Default Unix domain socket path for daemon IPC.
pub const SOCKET_PATH: &str = "/run/howy/howy.sock";

/// Effective socket path: honors `HOWY_SOCKET` env override for development,
/// falls back to the default production path.
pub fn socket_path() -> String {
    std::env::var("HOWY_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string())
}

/// System configuration directory.
pub const CONFIG_DIR: &str = "/etc/howy";

/// Default configuration file path.
pub const CONFIG_FILE: &str = "/etc/howy/config.toml";

/// System-wide face model storage.
pub const MODELS_DIR: &str = "/etc/howy/models";

/// Mode-1 cached-AEAD face model storage.
pub const MODE1_MODELS_DIR: &str = "/etc/howy/models/mode1";

/// Mode-2 ephemeral-AEAD face model storage.
pub const MODE2_MODELS_DIR: &str = "/etc/howy/models/mode2";

/// ONNX model data directory.
pub const ONNX_DATA_DIR: &str = "/usr/share/howy/onnx-data";

/// Log directory.
pub const LOG_DIR: &str = "/var/log/howy";

/// Snapshot directory.
pub const SNAPSHOT_DIR: &str = "/var/log/howy/snapshots";

/// Validate a username for safe filesystem usage.
pub fn validate_username(username: &str) -> bool {
    is_canonical_username(username)
}

/// Shared exact grammar for canonical NSS usernames used by storage paths.
pub(crate) fn is_canonical_username(username: &str) -> bool {
    let bytes = username.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// User face model file for a given username.
pub fn user_model_path(username: &str) -> Option<PathBuf> {
    validate_username(username).then(|| Path::new(MODELS_DIR).join(format!("{username}.bin")))
}

/// Legacy JSON model path (for migration fallback).
pub fn user_model_path_legacy(username: &str) -> Option<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::validate_username;

    #[test]
    fn username_validation_uses_the_canonical_storage_grammar() {
        for valid in ["a", "first..last", "Alice-01_test.name", &"x".repeat(64)] {
            assert!(validate_username(valid), "{valid:?}");
        }
        for invalid in [
            "",
            &"x".repeat(65),
            "root/child",
            "root\\child",
            "has space",
            "josé",
        ] {
            assert!(!validate_username(invalid), "{invalid:?}");
        }
    }
}
