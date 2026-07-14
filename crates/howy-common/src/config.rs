//! Configuration management for howy.
//!
//! Uses TOML format. Supports systemd credential loading for sensitive values.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where a loaded configuration document came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    File(PathBuf),
    SystemdCredential(PathBuf),
}

/// Whether a setting was present in the source document or filled by legacy defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigValueSource {
    Explicit,
    Defaulted,
}

/// Source and field-level provenance for a loaded configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProvenance {
    source: ConfigSource,
    explicit_fields: BTreeSet<String>,
}

impl ConfigProvenance {
    pub fn source(&self) -> &ConfigSource {
        &self.source
    }

    /// Return whether a dotted setting path, such as `core.disabled`, was explicit.
    pub fn value_source(&self, path: &str) -> ConfigValueSource {
        if self.explicit_fields.contains(path) {
            ConfigValueSource::Explicit
        } else {
            ConfigValueSource::Defaulted
        }
    }
}

/// A validated configuration together with its load provenance.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: HowyConfig,
    pub provenance: ConfigProvenance,
}

impl LoadedConfig {
    pub fn into_config(self) -> HowyConfig {
        self.config
    }
}

/// Top-level howy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HowyConfig {
    pub core: CoreConfig,
    pub ml: MlConfig,
    pub video: VideoConfig,
    pub snapshots: SnapshotConfig,
    pub credentials: CredentialConfig,
    pub security: SecurityConfig,
    pub presence: PresenceConfig,
    pub debug: DebugConfig,
}

impl Default for HowyConfig {
    fn default() -> Self {
        Self::legacy_defaults()
    }
}

impl HowyConfig {
    /// Runtime defaults used for fields absent from an existing configuration.
    ///
    /// Security and presence fields added later must keep legacy-compatible
    /// values here rather than inheriting fresh-install policy.
    pub fn legacy_defaults() -> Self {
        Self {
            core: CoreConfig::default(),
            ml: MlConfig::default(),
            video: VideoConfig::default(),
            snapshots: SnapshotConfig::default(),
            credentials: CredentialConfig::default(),
            security: SecurityConfig::default(),
            presence: PresenceConfig::default(),
            debug: DebugConfig::default(),
        }
    }

    /// Disabled secure configuration for provisioning and readiness checks.
    pub fn secure_bootstrap_template() -> Self {
        let mut config = Self::legacy_defaults();
        config.core.disabled = true;
        config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
        config.presence.mode = PresenceMode::Confirm;
        config
    }

    /// Configuration used when generating a new installation template.
    ///
    /// This is deliberately separate from [`Self::legacy_defaults`]. Until the
    /// secure mode is implemented and qualified, the generated values remain
    /// the same as the legacy-compatible runtime defaults.
    pub fn fresh_template() -> Self {
        Self::legacy_defaults()
    }
}

/// Stable embedding-storage mode identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmbeddingSecurityMode {
    Plaintext = 0,
    AeadCached = 1,
    AeadEphemeral = 2,
    ReservedFuture = 3,
}

impl Default for EmbeddingSecurityMode {
    fn default() -> Self {
        Self::Plaintext
    }
}

impl Serialize for EmbeddingSecurityMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for EmbeddingSecurityMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        match value {
            0 => Ok(Self::Plaintext),
            1 => Ok(Self::AeadCached),
            2 => Ok(Self::AeadEphemeral),
            3 => Ok(Self::ReservedFuture),
            _ => Err(serde::de::Error::custom(format!(
                "unknown embedding security mode {value}; expected numeric 0, 1, 2, or 3"
            ))),
        }
    }
}

/// Embedding storage security settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub embedding_mode: EmbeddingSecurityMode,
    pub key_epoch: u64,
    pub max_embeddings_per_user: u32,
    pub max_record_bytes: u64,
    pub max_plaintext_bytes: u64,
    pub cached: CachedSecurityConfig,
    pub ephemeral: EphemeralSecurityConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            embedding_mode: EmbeddingSecurityMode::Plaintext,
            key_epoch: 1,
            max_embeddings_per_user: 1_000,
            max_record_bytes: 2_621_440,
            max_plaintext_bytes: 134_217_728,
            cached: CachedSecurityConfig::default(),
            ephemeral: EphemeralSecurityConfig::default(),
        }
    }
}

/// Mode-1 cached AEAD settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CachedSecurityConfig {
    pub credential_name: String,
    pub max_cached_users: u32,
    pub max_cache_bytes: u64,
    pub require_mlock: bool,
}

impl Default for CachedSecurityConfig {
    fn default() -> Self {
        Self {
            credential_name: "howy.storage.mode1.epoch1".into(),
            max_cached_users: 64,
            max_cache_bytes: 134_217_728,
            require_mlock: true,
        }
    }
}

/// Mode-2 ephemeral AEAD settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EphemeralSecurityConfig {
    pub sealed_key_blob: String,
    pub key_description: String,
    pub tpm_parent_handle: String,
}

impl Default for EphemeralSecurityConfig {
    fn default() -> Self {
        Self {
            sealed_key_blob: "/var/lib/howy/keys/mode2-epoch1.blob".into(),
            key_description: "howy:storage:mode2:epoch1".into(),
            tpm_parent_handle: "0x81000001".into(),
        }
    }
}

/// Prompt-before-capture policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceMode {
    Off,
    Confirm,
}

impl Default for PresenceMode {
    fn default() -> Self {
        Self::Off
    }
}

/// Prompt confirmation settings independent of embedding storage mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PresenceConfig {
    pub mode: PresenceMode,
    pub local_only: bool,
    pub allowed_pam_services: Vec<String>,
    pub prompt_timeout_ms: u64,
    pub commit_to_camera_ms: u64,
    pub scan_timeout_ms: u64,
    pub max_pending_per_uid: u32,
    pub max_pending_global: u32,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            mode: PresenceMode::Off,
            local_only: true,
            allowed_pam_services: vec!["sudo".into()],
            prompt_timeout_ms: 30_000,
            commit_to_camera_ms: 1_000,
            scan_timeout_ms: 2_000,
            max_pending_per_uid: 2,
            max_pending_global: 32,
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

fn is_safe_ascii_name(value: &str, max_len: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max_len
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_tpm_parent_handle(value: &str) -> bool {
    value.len() == 10
        && value.starts_with("0x")
        && value.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
        && u32::from_str_radix(&value[2..], 16).is_ok_and(|handle| handle != 0)
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

        if self.security.embedding_mode == EmbeddingSecurityMode::ReservedFuture {
            return Err(
                "security.embedding_mode 3 is reserved and unsupported in this release".to_string(),
            );
        }

        if matches!(
            self.security.embedding_mode,
            EmbeddingSecurityMode::AeadCached | EmbeddingSecurityMode::AeadEphemeral
        ) && self.security.key_epoch == 0
        {
            return Err("security.key_epoch must be > 0 for encrypted modes".to_string());
        }

        if !(1..=1_000).contains(&self.security.max_embeddings_per_user) {
            return Err("security.max_embeddings_per_user must be in 1..=1000".to_string());
        }

        if !(4_096..=2_621_440).contains(&self.security.max_record_bytes) {
            return Err("security.max_record_bytes must be in 4096..=2621440".to_string());
        }

        if self.security.max_plaintext_bytes < self.security.max_record_bytes
            || self.security.max_plaintext_bytes > 1_073_741_824
        {
            return Err(
                "security.max_plaintext_bytes must be at least max_record_bytes and no greater than 1073741824"
                    .to_string(),
            );
        }

        match self.security.embedding_mode {
            EmbeddingSecurityMode::AeadCached => {
                if !(1..=4_096).contains(&self.security.cached.max_cached_users) {
                    return Err("security.cached.max_cached_users must be in 1..=4096".to_string());
                }

                if self.security.cached.max_cache_bytes < self.security.max_record_bytes
                    || self.security.cached.max_cache_bytes > self.security.max_plaintext_bytes
                {
                    return Err(
                        "security.cached.max_cache_bytes must be at least max_record_bytes and no greater than max_plaintext_bytes"
                            .to_string(),
                    );
                }

                if !is_safe_ascii_name(&self.security.cached.credential_name, 128) {
                    return Err(
                        "security.cached.credential_name must be 1..=128 ASCII bytes using only A-Z, a-z, 0-9, '.', '_', or '-'"
                            .to_string(),
                    );
                }
            }
            EmbeddingSecurityMode::AeadEphemeral => {
                if !Path::new(&self.security.ephemeral.sealed_key_blob).is_absolute() {
                    return Err(
                        "security.ephemeral.sealed_key_blob must be an absolute path".to_string(),
                    );
                }

                let description = self.security.ephemeral.key_description.as_bytes();
                if description.is_empty()
                    || description.len() > 128
                    || !description.iter().all(|byte| (b' '..=b'~').contains(byte))
                {
                    return Err(
                        "security.ephemeral.key_description must be 1..=128 printable ASCII bytes without NUL or newline"
                            .to_string(),
                    );
                }

                if !validate_tpm_parent_handle(&self.security.ephemeral.tpm_parent_handle) {
                    return Err(
                        "security.ephemeral.tpm_parent_handle must be nonzero and formatted as 0x followed by eight hex digits"
                            .to_string(),
                    );
                }
            }
            EmbeddingSecurityMode::Plaintext | EmbeddingSecurityMode::ReservedFuture => {}
        }

        let mut allowed_services = BTreeSet::new();
        for service in &self.presence.allowed_pam_services {
            if !is_safe_ascii_name(service, 64) {
                return Err(
                    "presence.allowed_pam_services entries must be 1..=64 ASCII bytes using only A-Z, a-z, 0-9, '.', '_', or '-'"
                        .to_string(),
                );
            }
            if !allowed_services.insert(service.as_str()) {
                return Err("presence.allowed_pam_services entries must be unique".to_string());
            }
        }

        if self.presence.mode == PresenceMode::Confirm
            && self.presence.allowed_pam_services.is_empty()
        {
            return Err(
                "presence.allowed_pam_services must not be empty when presence.mode is confirm"
                    .to_string(),
            );
        }

        if !(1_000..=300_000).contains(&self.presence.prompt_timeout_ms) {
            return Err("presence.prompt_timeout_ms must be in 1000..=300000".to_string());
        }

        if !(100..=10_000).contains(&self.presence.commit_to_camera_ms) {
            return Err("presence.commit_to_camera_ms must be in 100..=10000".to_string());
        }

        if !(100..=30_000).contains(&self.presence.scan_timeout_ms) {
            return Err("presence.scan_timeout_ms must be in 100..=30000".to_string());
        }

        if !(1..=16).contains(&self.presence.max_pending_per_uid) {
            return Err("presence.max_pending_per_uid must be in 1..=16".to_string());
        }

        if self.presence.max_pending_global < self.presence.max_pending_per_uid
            || self.presence.max_pending_global > 1_024
        {
            return Err(
                "presence.max_pending_global must be at least max_pending_per_uid and no greater than 1024"
                    .to_string(),
            );
        }

        match self.debug.log_level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => Ok(()),
            _ => Err("debug.log_level must be one of: error, warn, info, debug, trace".to_string()),
        }
    }

    /// Load configuration from a TOML file.
    ///
    /// Missing fields use legacy-compatible defaults. A missing whole file is
    /// an error so daemon startup cannot silently select runtime defaults.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        Self::load_with_provenance(path).map(LoadedConfig::into_config)
    }

    /// Load configuration and retain source and explicit/defaulted field provenance.
    pub fn load_with_provenance(path: &Path) -> Result<LoadedConfig, std::io::Error> {
        Self::load_from_source(path, ConfigSource::File(path.to_path_buf()))
    }

    /// Load from systemd credentials directory if available,
    /// otherwise fall back to the standard config path.
    pub fn load_with_systemd_creds() -> Result<Self, std::io::Error> {
        Self::load_with_systemd_creds_and_provenance().map(LoadedConfig::into_config)
    }

    /// Load configuration with provenance from a systemd credential or the standard path.
    pub fn load_with_systemd_creds_and_provenance() -> Result<LoadedConfig, std::io::Error> {
        // Check for systemd credentials directory
        if let Ok(creds_dir) = std::env::var("CREDENTIALS_DIRECTORY") {
            let cred_path = Path::new(&creds_dir).join("howy.config");
            if cred_path.exists() {
                tracing::info!(
                    "Loading config from systemd credential: {}",
                    cred_path.display()
                );
                return Self::load_from_source(
                    &cred_path,
                    ConfigSource::SystemdCredential(cred_path.clone()),
                );
            }
        }

        // Fall back to standard path
        Self::load_with_provenance(Path::new(super::paths::CONFIG_FILE))
    }

    /// Generate a fresh-install TOML config string for writing to disk.
    pub fn fresh_template_toml() -> String {
        toml::to_string_pretty(&Self::fresh_template()).expect("fresh config template serializes")
    }

    /// Generate the exact disabled Mode-1 candidate used by provisioning.
    pub fn secure_bootstrap_template_toml() -> String {
        toml::to_string_pretty(&Self::secure_bootstrap_template())
            .expect("secure bootstrap config template serializes")
    }

    fn load_from_source(path: &Path, source: ConfigSource) -> Result<LoadedConfig, std::io::Error> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "configuration file not found at {}; generate one with `sudo howy config` or select an explicit configuration",
                        path.display()
                    ),
                )
            } else {
                error
            }
        })?;
        let config: HowyConfig = toml::from_str(&contents)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        config
            .validate()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

        let document: toml::Value = toml::from_str(&contents)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let mut explicit_fields = BTreeSet::new();
        collect_explicit_fields(&document, "", &mut explicit_fields);

        Ok(LoadedConfig {
            config,
            provenance: ConfigProvenance {
                source,
                explicit_fields,
            },
        })
    }
}

fn collect_explicit_fields(value: &toml::Value, prefix: &str, fields: &mut BTreeSet<String>) {
    if let toml::Value::Table(table) = value {
        for (name, value) in table {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            collect_explicit_fields(value, &path, fields);
        }
    } else if !prefix.is_empty() {
        fields.insert(prefix.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigSource, ConfigValueSource, EmbeddingSecurityMode, HowyConfig, PresenceMode};
    use std::path::PathBuf;

    struct TestConfigFile {
        path: PathBuf,
    }

    impl TestConfigFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "howy-config-test-{}-{}.toml",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::write(&path, contents).unwrap();
            Self { path }
        }
    }

    impl Drop for TestConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn assert_validation_error(config: HowyConfig, expected: &str) {
        let error = config.validate().unwrap_err();
        assert!(
            error.contains(expected),
            "expected error containing {expected:?}, got {error:?}"
        );
    }

    #[test]
    fn missing_whole_file_returns_actionable_error() {
        let path = std::env::temp_dir().join(format!(
            "howy-missing-config-test-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let error = HowyConfig::load(&path).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("sudo howy config"));
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn existing_config_preserves_parsing_and_legacy_field_defaults() {
        let file = TestConfigFile::new(
            r#"
[ml]
provider = "cpu"

[video]
timeout = 9
"#,
        );

        let config = HowyConfig::load(&file.path).unwrap();

        assert_eq!(config.ml.provider, "cpu");
        assert_eq!(config.video.timeout, 9);
        assert_eq!(config.video.max_height, 320);
        assert!(!config.core.disabled);
        assert_eq!(
            config.security.embedding_mode,
            EmbeddingSecurityMode::Plaintext
        );
        assert_eq!(config.presence.mode, PresenceMode::Off);
        assert_eq!(config.security.key_epoch, 1);
        assert_eq!(config.security.max_record_bytes, 2_621_440);
        assert_eq!(config.presence.allowed_pam_services, ["sudo"]);
    }

    #[test]
    fn frozen_security_and_presence_defaults_match_schema() {
        let config = HowyConfig::legacy_defaults();

        assert_eq!(
            config.security.embedding_mode,
            EmbeddingSecurityMode::Plaintext
        );
        assert_eq!(config.security.key_epoch, 1);
        assert_eq!(config.security.max_embeddings_per_user, 1_000);
        assert_eq!(config.security.max_record_bytes, 2_621_440);
        assert_eq!(config.security.max_plaintext_bytes, 134_217_728);
        assert_eq!(
            config.security.cached.credential_name,
            "howy.storage.mode1.epoch1"
        );
        assert_eq!(config.security.cached.max_cached_users, 64);
        assert_eq!(config.security.cached.max_cache_bytes, 134_217_728);
        assert!(config.security.cached.require_mlock);
        assert_eq!(
            config.security.ephemeral.sealed_key_blob,
            "/var/lib/howy/keys/mode2-epoch1.blob"
        );
        assert_eq!(
            config.security.ephemeral.key_description,
            "howy:storage:mode2:epoch1"
        );
        assert_eq!(config.security.ephemeral.tpm_parent_handle, "0x81000001");

        assert_eq!(config.presence.mode, PresenceMode::Off);
        assert!(config.presence.local_only);
        assert_eq!(config.presence.allowed_pam_services, ["sudo"]);
        assert_eq!(config.presence.prompt_timeout_ms, 30_000);
        assert_eq!(config.presence.commit_to_camera_ms, 1_000);
        assert_eq!(config.presence.scan_timeout_ms, 2_000);
        assert_eq!(config.presence.max_pending_per_uid, 2);
        assert_eq!(config.presence.max_pending_global, 32);
        config.validate().unwrap();
    }

    #[test]
    fn loaded_config_tracks_explicit_and_defaulted_values() {
        let file = TestConfigFile::new(
            r#"
[core]
disabled = true
"#,
        );

        let loaded = HowyConfig::load_with_provenance(&file.path).unwrap();

        assert_eq!(
            loaded.provenance.source(),
            &ConfigSource::File(file.path.clone())
        );
        assert_eq!(
            loaded.provenance.value_source("core.disabled"),
            ConfigValueSource::Explicit
        );
        assert_eq!(
            loaded.provenance.value_source("core.timeout_notice"),
            ConfigValueSource::Defaulted
        );
        assert_eq!(
            loaded
                .provenance
                .value_source("security.cached.credential_name"),
            ConfigValueSource::Defaulted
        );
        assert!(loaded.config.core.disabled);
        assert!(loaded.config.core.timeout_notice);
    }

    #[test]
    fn loaded_config_tracks_new_explicit_leaf_values() {
        let file = TestConfigFile::new(
            r#"
[security]
embedding_mode = 1

[security.cached]
credential_name = "howy.storage.test"

[presence]
mode = "confirm"
allowed_pam_services = ["sudo", "login"]
"#,
        );

        let loaded = HowyConfig::load_with_provenance(&file.path).unwrap();

        for path in [
            "security.embedding_mode",
            "security.cached.credential_name",
            "presence.mode",
            "presence.allowed_pam_services",
        ] {
            assert_eq!(
                loaded.provenance.value_source(path),
                ConfigValueSource::Explicit,
                "unexpected provenance for {path}"
            );
        }
        assert_eq!(
            loaded.provenance.value_source("security.max_record_bytes"),
            ConfigValueSource::Defaulted
        );
    }

    #[test]
    fn embedding_modes_use_stable_numeric_toml_values() {
        for (mode, identifier) in [
            (EmbeddingSecurityMode::Plaintext, 0),
            (EmbeddingSecurityMode::AeadCached, 1),
            (EmbeddingSecurityMode::AeadEphemeral, 2),
            (EmbeddingSecurityMode::ReservedFuture, 3),
        ] {
            let mut config = HowyConfig::legacy_defaults();
            config.security.embedding_mode = mode;

            let encoded = toml::to_string(&config).unwrap();
            assert!(encoded.contains(&format!("embedding_mode = {identifier}")));

            let decoded: HowyConfig = toml::from_str(&encoded).unwrap();
            assert_eq!(decoded.security.embedding_mode, mode);
        }
    }

    #[test]
    fn unknown_embedding_mode_fails_deserialization_clearly() {
        let error = toml::from_str::<HowyConfig>("[security]\nembedding_mode = 4\n")
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown embedding security mode 4"));
        assert!(error.contains("0, 1, 2, or 3"));
    }

    #[test]
    fn reserved_embedding_mode_parses_but_fails_validation() {
        let config: HowyConfig = toml::from_str("[security]\nembedding_mode = 3\n").unwrap();

        assert_eq!(
            config.security.embedding_mode,
            EmbeddingSecurityMode::ReservedFuture
        );
        assert_validation_error(config, "reserved and unsupported");
    }

    #[test]
    fn supported_embedding_modes_validate_with_frozen_defaults() {
        for mode in [
            EmbeddingSecurityMode::Plaintext,
            EmbeddingSecurityMode::AeadCached,
            EmbeddingSecurityMode::AeadEphemeral,
        ] {
            let mut config = HowyConfig::legacy_defaults();
            config.security.embedding_mode = mode;
            config.validate().unwrap();
        }
    }

    #[test]
    fn presence_mode_uses_lowercase_strings() {
        for (name, expected) in [
            ("off", PresenceMode::Off),
            ("confirm", PresenceMode::Confirm),
        ] {
            let input = format!("[presence]\nmode = \"{name}\"\n");
            let config: HowyConfig = toml::from_str(&input).unwrap();
            assert_eq!(config.presence.mode, expected);

            let encoded = toml::to_string(&config).unwrap();
            assert!(encoded.contains(&format!("mode = \"{name}\"")));
        }

        assert!(toml::from_str::<HowyConfig>("[presence]\nmode = \"Confirm\"\n").is_err());
    }

    #[test]
    fn secure_bootstrap_is_disabled_mode_one_with_confirmation() {
        let secure = HowyConfig::secure_bootstrap_template();

        assert!(secure.core.disabled);
        assert_eq!(
            secure.security.embedding_mode,
            EmbeddingSecurityMode::AeadCached
        );
        assert_eq!(secure.security.key_epoch, 1);
        assert_eq!(secure.presence.mode, PresenceMode::Confirm);
        secure.validate().unwrap();

        let fresh = HowyConfig::fresh_template();
        assert!(!fresh.core.disabled);
        assert_eq!(
            fresh.security.embedding_mode,
            EmbeddingSecurityMode::Plaintext
        );
        assert_eq!(fresh.presence.mode, PresenceMode::Off);
    }

    #[test]
    fn validation_rejects_invalid_security_limits() {
        let mut config = HowyConfig::legacy_defaults();
        config.security.max_embeddings_per_user = 0;
        assert_validation_error(config, "max_embeddings_per_user");

        let mut config = HowyConfig::legacy_defaults();
        config.security.max_embeddings_per_user = 1_001;
        assert_validation_error(config, "max_embeddings_per_user");

        let mut config = HowyConfig::legacy_defaults();
        config.security.max_record_bytes = 4_095;
        assert_validation_error(config, "max_record_bytes");

        let mut config = HowyConfig::legacy_defaults();
        config.security.max_record_bytes = 2_621_441;
        assert_validation_error(config, "max_record_bytes");

        let mut config = HowyConfig::legacy_defaults();
        config.security.max_plaintext_bytes = config.security.max_record_bytes - 1;
        assert_validation_error(config, "max_plaintext_bytes");

        let mut config = HowyConfig::legacy_defaults();
        config.security.max_plaintext_bytes = 1_073_741_825;
        assert_validation_error(config, "max_plaintext_bytes");
    }

    #[test]
    fn validation_applies_only_the_selected_security_mode_table() {
        let mut plaintext = HowyConfig::legacy_defaults();
        plaintext.security.key_epoch = 0;
        plaintext.security.cached.credential_name.clear();
        plaintext.security.ephemeral.sealed_key_blob = "relative".into();
        plaintext.validate().unwrap();

        let mut cached = HowyConfig::legacy_defaults();
        cached.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
        cached.security.key_epoch = 0;
        assert_validation_error(cached, "key_epoch");

        let mut cached = HowyConfig::secure_bootstrap_template();
        cached.security.cached.max_cached_users = 0;
        assert_validation_error(cached, "max_cached_users");

        let mut cached = HowyConfig::secure_bootstrap_template();
        cached.security.cached.max_cached_users = 4_097;
        assert_validation_error(cached, "max_cached_users");

        let mut cached = HowyConfig::secure_bootstrap_template();
        cached.security.cached.max_cache_bytes = cached.security.max_record_bytes - 1;
        assert_validation_error(cached, "max_cache_bytes");

        let mut cached = HowyConfig::secure_bootstrap_template();
        cached.security.cached.max_cache_bytes = cached.security.max_plaintext_bytes + 1;
        assert_validation_error(cached, "max_cache_bytes");

        let mut cached = HowyConfig::secure_bootstrap_template();
        cached.security.cached.credential_name = "invalid/name".into();
        assert_validation_error(cached, "credential_name");

        let mut ephemeral = HowyConfig::legacy_defaults();
        ephemeral.security.embedding_mode = EmbeddingSecurityMode::AeadEphemeral;
        ephemeral.security.ephemeral.sealed_key_blob = "relative".into();
        assert_validation_error(ephemeral, "sealed_key_blob");

        let mut ephemeral = HowyConfig::legacy_defaults();
        ephemeral.security.embedding_mode = EmbeddingSecurityMode::AeadEphemeral;
        ephemeral.security.ephemeral.key_description = "line\nbreak".into();
        assert_validation_error(ephemeral, "key_description");

        let mut ephemeral = HowyConfig::legacy_defaults();
        ephemeral.security.embedding_mode = EmbeddingSecurityMode::AeadEphemeral;
        ephemeral.security.ephemeral.tpm_parent_handle = "0x00000000".into();
        assert_validation_error(ephemeral, "tpm_parent_handle");
    }

    #[test]
    fn validation_rejects_invalid_presence_combinations() {
        let mut config = HowyConfig::legacy_defaults();
        config.presence.mode = PresenceMode::Confirm;
        config.presence.allowed_pam_services.clear();
        assert_validation_error(config, "must not be empty");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.allowed_pam_services = vec!["sudo".into(), "sudo".into()];
        assert_validation_error(config, "must be unique");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.allowed_pam_services = vec!["bad/service".into()];
        assert_validation_error(config, "allowed_pam_services entries");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.prompt_timeout_ms = 999;
        assert_validation_error(config, "prompt_timeout_ms");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.commit_to_camera_ms = 10_001;
        assert_validation_error(config, "commit_to_camera_ms");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.scan_timeout_ms = 99;
        assert_validation_error(config, "scan_timeout_ms");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.max_pending_per_uid = 17;
        assert_validation_error(config, "max_pending_per_uid");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.max_pending_global = config.presence.max_pending_per_uid - 1;
        assert_validation_error(config, "max_pending_global");

        let mut config = HowyConfig::legacy_defaults();
        config.presence.max_pending_global = 1_025;
        assert_validation_error(config, "max_pending_global");
    }

    #[test]
    fn runtime_defaults_and_fresh_template_have_distinct_constructors() {
        let runtime_toml = toml::to_string_pretty(&HowyConfig::legacy_defaults()).unwrap();
        let fresh_toml = HowyConfig::fresh_template_toml();

        assert_eq!(
            fresh_toml,
            toml::to_string_pretty(&HowyConfig::fresh_template()).unwrap()
        );
        assert_eq!(fresh_toml, runtime_toml);
    }
}
