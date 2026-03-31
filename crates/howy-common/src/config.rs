//! Configuration management for howy.
//!
//! Uses TOML format. Supports systemd credential loading for sensitive values.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level howy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HowyConfig {
    pub core: CoreConfig,
    pub ml: MlConfig,
    pub video: VideoConfig,
    pub snapshots: SnapshotConfig,
    pub credentials: CredentialConfig,
    pub debug: DebugConfig,
}

impl Default for HowyConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            ml: MlConfig::default(),
            video: VideoConfig::default(),
            snapshots: SnapshotConfig::default(),
            credentials: CredentialConfig::default(),
            debug: DebugConfig::default(),
        }
    }
}

/// Core behaviour settings.
///
/// Note: the first PAM deployment does not yet load this config directly in
/// `pam_howy`, so several policy-style knobs are still documentary/reserved
/// rather than fully enforced by the PAM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CoreConfig {
    /// Print "Attempting facial authentication" notice.
    pub detection_notice: bool,
    /// Print timeout notice.
    pub timeout_notice: bool,
    /// Suppress confirmation message on success.
    pub no_confirmation: bool,
    /// Fail silently for users without face models.
    pub suppress_unknown: bool,
    /// Disable in SSH sessions.
    /// Intended policy knob; current `pam_howy` still uses its own built-in SSH
    /// heuristic and does not yet honor this value from config.
    pub abort_if_ssh: bool,
    /// Disable if laptop lid is closed.
    /// Intended policy knob; current `pam_howy` still uses its own built-in lid
    /// heuristic and does not yet honor this value from config.
    pub abort_if_lid_closed: bool,
    /// Master kill switch.
    pub disabled: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            detection_notice: false,
            timeout_notice: true,
            no_confirmation: false,
            suppress_unknown: false,
            abort_if_ssh: true,
            abort_if_lid_closed: true,
            disabled: false,
        }
    }
}

/// ML inference settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MlConfig {
    /// Execution provider preference.
    /// "auto", "cuda", "tensorrt", "migraphx", "rocm", "openvino", "cpu"
    /// `auto` is only a broad default; deployment should usually pin the known
    /// good provider for the target machine.
    pub provider: String,
    /// Prefer NPU over GPU when both are available.
    pub prefer_npu: bool,
    /// Face detection confidence threshold (0.0 - 1.0).
    pub det_threshold: f32,
    /// Recognition threshold (cosine similarity, 0.0 - 1.0).
    /// Higher = stricter. 0.4-0.6 recommended.
    pub recognition_threshold: f32,
    /// Path to SCRFD detector model. Empty = auto-find.
    pub detector_model: String,
    /// Path to ArcFace recognizer model. Empty = auto-find.
    pub recognizer_model: String,
    /// Detector input size (width).
    pub det_width: u32,
    /// Detector input size (height).
    pub det_height: u32,
    /// Number of inference threads (0 = auto).
    pub threads: usize,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            provider: "auto".into(),
            prefer_npu: false,
            det_threshold: 0.6,
            recognition_threshold: 0.5,
            detector_model: String::new(),
            recognizer_model: String::new(),
            det_width: 640,
            det_height: 640,
            threads: 0,
        }
    }
}

/// Video capture settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VideoConfig {
    /// Seconds before timeout.
    pub timeout: u32,
    /// V4L2 device path. Empty = auto-detect.
    /// Auto-detect is only a generic fallback and may select the wrong camera
    /// on multi-camera systems, so deployment should usually set this
    /// explicitly.
    pub device_path: String,
    /// Maximum capture height (for downscaling).
    pub max_height: u32,
    /// Dark frame threshold (0-100). Higher = more tolerant of dark frames.
    pub dark_threshold: f32,
    /// Maximum consecutive dark frames before failing auth early.
    /// 0 = no limit (rely on timeout only). Useful for detecting a covered
    /// or broken camera without burning the full timeout.
    pub max_dark_frames: u32,
    /// Requested capture width (-1 = device default).
    pub frame_width: i32,
    /// Requested capture height (-1 = device default).
    pub frame_height: i32,
    /// Frame rotation mode: 0 = landscape only, 1 = both, 2 = portrait only.
    pub rotate: u8,
    /// Requested capture FPS (-1 = device default).
    /// Some IR emitters need a specific frame rate to function properly.
    pub device_fps: i32,
    /// Explicit exposure value (-1 = auto-exposure).
    /// Disables auto-exposure when set. Use qv4l2 to find a good value.
    pub exposure: i32,
}

impl Default for VideoConfig {
    fn default() -> Self {
        Self {
            timeout: 4,
            device_path: String::new(),
            max_height: 320,
            dark_threshold: 60.0,
            max_dark_frames: 15,
            frame_width: -1,
            frame_height: -1,
            rotate: 0,
            device_fps: -1,
            exposure: -1,
        }
    }
}

/// Snapshot settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnapshotConfig {
    /// Save snapshots of failed login attempts.
    pub save_failed: bool,
    /// Save snapshots of successful login attempts.
    pub save_successful: bool,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            save_failed: false,
            save_successful: false,
        }
    }
}

/// Credential caching configuration.
///
/// The keyring cache is experimental and intentionally disabled in the current
/// PAM deployment until the daemon receives a real PAM session identifier for
/// session-scoped entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialConfig {
    /// Request kernel keyring session credential caching.
    /// This remains experimental and is ignored by the current daemon/PAM
    /// deployment until proper PAM session scoping exists.
    pub enable_cache: bool,
    /// Time-to-live for cached credentials (seconds).
    /// Reserved for the future session-scoped cache path.
    pub cache_ttl_secs: u32,
    /// Keyring key description prefix.
    /// Reserved for the future session-scoped cache path.
    pub keyring_prefix: String,
    /// Use systemd encrypted credentials for model storage.
    pub use_systemd_creds: bool,
}

impl Default for CredentialConfig {
    fn default() -> Self {
        Self {
            enable_cache: false,
            cache_ttl_secs: 300,
            keyring_prefix: "howy:auth".into(),
            use_systemd_creds: false,
        }
    }
}

/// Debug settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DebugConfig {
    /// Print timing report after auth.
    pub end_report: bool,
    /// Verbose logging level: "error", "warn", "info", "debug", "trace".
    pub log_level: String,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            end_report: false,
            log_level: "info".into(),
        }
    }
}

impl HowyConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.ml.det_threshold) {
            return Err("ml.det_threshold must be in 0.0..=1.0".to_string());
        }

        if !(0.0..=1.0).contains(&self.ml.recognition_threshold) {
            return Err("ml.recognition_threshold must be in 0.0..=1.0".to_string());
        }

        if self.ml.det_width == 0 {
            return Err("ml.det_width must be > 0".to_string());
        }

        if self.ml.det_height == 0 {
            return Err("ml.det_height must be > 0".to_string());
        }

        if self.credentials.enable_cache && self.credentials.cache_ttl_secs == 0 {
            return Err(
                "credentials.cache_ttl_secs must be > 0 when caching is enabled".to_string(),
            );
        }

        if self.video.timeout == 0 {
            return Err("video.timeout must be > 0".to_string());
        }

        match self.debug.log_level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => Ok(()),
            _ => Err("debug.log_level must be one of: error, warn, info, debug, trace".to_string()),
        }
    }

    /// Load configuration from a TOML file.
    /// Falls back to defaults for missing fields.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let config: HowyConfig = toml::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            config
                .validate()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(config)
        } else {
            tracing::warn!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            let config = Self::default();
            config
                .validate()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            Ok(config)
        }
    }

    /// Load from systemd credentials directory if available,
    /// otherwise fall back to the standard config path.
    pub fn load_with_systemd_creds() -> Result<Self, std::io::Error> {
        // Check for systemd credentials directory
        if let Ok(creds_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
            let cred_path = Path::new(&creds_dir).join("howy.config");
            if cred_path.exists() {
                tracing::info!(
                    "Loading config from systemd credential: {}",
                    cred_path.display()
                );
                return Self::load(&cred_path);
            }
        }

        // Fall back to standard path
        Self::load(Path::new(super::paths::CONFIG_FILE))
    }

    /// Generate a default TOML config string for writing to disk.
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Self::default()).expect("default config serializes")
    }
}
