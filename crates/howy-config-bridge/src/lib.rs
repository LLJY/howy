//! Descriptor-safe release-N package configuration bridge.
//!
//! The bridge recognizes only the pinned release-N payload, the pinned disabled
//! bootstrap, and versioned controls that it created itself. Every durable
//! mutation is descriptor-bound. Unknown controls and orphan stages are retained
//! and cause refusal instead of being removed by name or shape.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use howy_common::config::{EmbeddingSecurityMode, HowyConfig, PresenceMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LEGACY_SHA256: &str = "c6ce9bfdf7e79dfa9ec85f3529a4a4400de8855da0d9488809ecbdf9966b1e01";
pub const LEGACY_SIZE: u64 = 3_740;
pub const BOOTSTRAP_SHA256: &str =
    "45d544fb9261da2dc1f6ce1ec546f0889c4934ca19eb39921074513081421ca4";
pub const BOOTSTRAP_SIZE: u64 = 1_381;

pub const CONFIG_PATH: &str = "/etc/howy/config.toml";
pub const BOOTSTRAP_PATH: &str = "/usr/share/howy/config.bootstrap.toml";
pub const LOCK_PATH: &str = "/run/lock/howy-config-bridge.lock";
pub const STATE_DIRECTORY: &str = "/var/lib/howy/config-bridge";
pub const JOURNAL_PATH: &str = "/var/lib/howy/config-bridge/journal-v2.json";
pub const MANIFEST_PATH: &str = "/var/lib/howy/config-bridge/manifest-v2.json";
pub const MARKER_PATH: &str = "/var/lib/howy-package-bootstrap.complete";

const LEGACY_BYTES: &[u8] = include_bytes!("../../../packaging/config-release-n-legacy.toml");
const BOOTSTRAP_BYTES: &[u8] = include_bytes!("../../../packaging/config.bootstrap.toml");
const SCHEMA_VERSION: u16 = 2;
const MARKER_SCHEMA_VERSION: u16 = 1;
const RELEASE_ID: &str = "release-n";
const MAX_CONFIG_BYTES: usize = 1_048_576;
const MAX_CONTROL_BYTES: usize = 262_144;
const MAX_CONSUMED_GENERATIONS: usize = 64;
const LOCK_WAIT: Duration = Duration::from_secs(10);
const CONFIG_STAGE_PREFIX: &str = ".howy-config-bridge-v2-";
const CONTROL_STAGE_PREFIX: &str = ".howy-control-v2-";
const PRIVATE_STAGE_PREFIX: &str = ".howy-private-v2-";
const STASH_PREFIX: &str = "config-release-n.stash.g";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeError(String);

impl BridgeError {
    fn refused(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BridgeError {}

type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Installed,
    RestoredStash,
    VerifiedUpgrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    Created,
    Occupied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StashOutcome {
    Created,
    Refreshed,
    AlreadyExact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMetadata {
    uid: u32,
    gid: u32,
    permissions: u32,
    link_count: u64,
    byte_length: u64,
    access_seconds: i64,
    access_nanoseconds: u32,
    modification_seconds: i64,
    modification_nanoseconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    device: u64,
    inode: u64,
    sha256: String,
    metadata: FileMetadata,
}

#[derive(Debug)]
struct Snapshot {
    bytes: Vec<u8>,
    record: FileRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbsenceRecord {
    parent_device: u64,
    parent_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ConfigState {
    Absent { absence: AbsenceRecord },
    Present { file: FileRecord },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum GenerationState {
    Absent {
        absence: AbsenceRecord,
    },
    PresentStashed {
        source: FileRecord,
        stash_path: String,
        stash_sha256: String,
        stash_size: u64,
    },
    Restored {
        captured: Box<GenerationState>,
        restored_target: ConfigState,
        restore_transaction_id: String,
    },
    ConsumedRefreshable {
        captured: Box<GenerationState>,
        restored_target: ConfigState,
        restore_transaction_id: String,
        consumed_by_transaction_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationRecord {
    generation: u64,
    stash_transaction_id: String,
    state: GenerationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StashManifest {
    schema_version: u16,
    release_id: String,
    config_path: String,
    active: GenerationRecord,
    consumed_generations: Vec<GenerationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapMarker {
    schema_version: u16,
    release_id: String,
    transaction_id: String,
    generation: Option<u64>,
    config: ConfigState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum BridgeJournal {
    BootstrapReleaseN {
        schema_version: u16,
        transaction_id: String,
        legacy: FileRecord,
        config_stage_name: String,
    },
    StashReleaseN {
        schema_version: u16,
        transaction_id: String,
        source: ConfigState,
        previous_manifest: Option<FileRecord>,
        new_manifest: Box<StashManifest>,
        manifest_stage_name: String,
        marker: Option<FileRecord>,
    },
    RestoreReleaseN {
        schema_version: u16,
        transaction_id: String,
        manifest: FileRecord,
        generation: u64,
        config_stage_name: String,
        config_backup_name: String,
        manifest_stage_name: String,
    },
}

impl BridgeJournal {
    fn transaction_id(&self) -> &str {
        match self {
            Self::BootstrapReleaseN { transaction_id, .. }
            | Self::StashReleaseN { transaction_id, .. }
            | Self::RestoreReleaseN { transaction_id, .. } => transaction_id,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::BootstrapReleaseN {
                schema_version,
                transaction_id,
                legacy,
                config_stage_name,
            } => {
                validate_schema_and_transaction(*schema_version, transaction_id)?;
                validate_record(legacy)?;
                validate_stage_name(config_stage_name, transaction_id, "bootstrap")?;
            }
            Self::StashReleaseN {
                schema_version,
                transaction_id,
                source,
                previous_manifest,
                new_manifest,
                manifest_stage_name,
                marker,
            } => {
                validate_schema_and_transaction(*schema_version, transaction_id)?;
                validate_config_state(source)?;
                if let Some(record) = previous_manifest {
                    validate_record(record)?;
                }
                new_manifest.validate()?;
                validate_control_stage_name(manifest_stage_name, transaction_id, "manifest")?;
                if let Some(record) = marker {
                    validate_record(record)?;
                }
            }
            Self::RestoreReleaseN {
                schema_version,
                transaction_id,
                manifest,
                generation,
                config_stage_name,
                config_backup_name,
                manifest_stage_name,
            } => {
                validate_schema_and_transaction(*schema_version, transaction_id)?;
                validate_record(manifest)?;
                if *generation == 0 {
                    return Err(BridgeError::refused(
                        "restore journal generation is invalid",
                    ));
                }
                validate_stage_name(config_stage_name, transaction_id, "restore")?;
                validate_stage_name(config_backup_name, transaction_id, "absent-backup")?;
                validate_control_stage_name(manifest_stage_name, transaction_id, "manifest")?;
            }
        }
        Ok(())
    }
}

impl StashManifest {
    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.release_id != RELEASE_ID
            || self.config_path != CONFIG_PATH
            || self.active.generation == 0
            || self.consumed_generations.len() > MAX_CONSUMED_GENERATIONS
        {
            return Err(BridgeError::refused(
                "release-N stash manifest header is invalid",
            ));
        }
        validate_transaction_id(&self.active.stash_transaction_id)?;
        validate_active_generation(&self.active.state)?;
        let mut prior = 0;
        for generation in &self.consumed_generations {
            if generation.generation == 0
                || generation.generation >= self.active.generation
                || generation.generation <= prior
            {
                return Err(BridgeError::refused(
                    "release-N consumed generation ordering is invalid",
                ));
            }
            validate_transaction_id(&generation.stash_transaction_id)?;
            validate_consumed_generation(&generation.state)?;
            prior = generation.generation;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct BridgePaths {
    root: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    require_euid_root: bool,
}

impl BridgePaths {
    fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
            expected_uid: 0,
            expected_gid: 0,
            require_euid_root: true,
        }
    }

    #[cfg(test)]
    fn rooted(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            expected_uid: unsafe { libc::geteuid() },
            expected_gid: unsafe { libc::getegid() },
            require_euid_root: false,
        }
    }

    fn relative<'a>(&self, production: &'a str) -> Result<&'a Path> {
        let path = Path::new(production);
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(BridgeError::refused("bridge path contract is invalid"));
        }
        path.strip_prefix("/")
            .map_err(|_| BridgeError::refused("bridge path is outside its root"))
    }

    fn open_root(&self) -> Result<OwnedFd> {
        let name = cstring(self.root.as_os_str())?;
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(last_error("bridge root open failed"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        validate_safe_directory(fd.as_raw_fd(), self.expected_uid, self.expected_gid)?;
        Ok(fd)
    }

    fn open_directory(&self, production: &str) -> Result<OwnedFd> {
        let relative = self.relative(production)?;
        let mut current = self.open_root()?;
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(BridgeError::refused("bridge directory path is invalid"));
            };
            let component = cstring(component)?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(last_error("no-follow bridge directory traversal failed"));
            }
            let next = unsafe { OwnedFd::from_raw_fd(fd) };
            validate_safe_directory(next.as_raw_fd(), self.expected_uid, self.expected_gid)?;
            current = next;
        }
        Ok(current)
    }

    fn open_parent(&self, production: &str) -> Result<(OwnedFd, CString)> {
        let path = Path::new(production);
        let parent = path
            .parent()
            .and_then(Path::to_str)
            .ok_or_else(|| BridgeError::refused("bridge path has no safe parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| BridgeError::refused("bridge path has no file name"))?;
        Ok((self.open_directory(parent)?, cstring(name)?))
    }
}

pub struct ConfigBridge {
    paths: BridgePaths,
    lock: Option<File>,
    #[cfg(test)]
    fail_at: Option<String>,
    #[cfg(test)]
    kill_at: Option<String>,
}

impl Default for ConfigBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBridge {
    pub fn new() -> Self {
        Self {
            paths: BridgePaths::production(),
            lock: None,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            kill_at: None,
        }
    }

    #[cfg(test)]
    fn rooted(root: &Path) -> Self {
        Self {
            paths: BridgePaths::rooted(root),
            lock: None,
            fail_at: None,
            kill_at: None,
        }
    }

    #[cfg(test)]
    fn fail_at(mut self, point: &str) -> Self {
        self.fail_at = Some(point.to_owned());
        self
    }

    #[cfg(test)]
    fn kill_at(mut self, point: &str) -> Self {
        self.kill_at = Some(point.to_owned());
        self
    }

    /// Create and verify every package/local sensitive directory without
    /// following symlinks. Existing leaves must already have the exact policy.
    pub fn ensure_layout(&mut self) -> Result<()> {
        self.require_identity()?;
        for (path, mode) in [
            ("/etc/howy", 0o700),
            ("/etc/howy/models", 0o700),
            ("/etc/howy/models/mode1", 0o700),
            ("/etc/credstore.encrypted", 0o700),
            ("/var/lib/howy", 0o700),
            ("/var/lib/howy/security-state", 0o700),
            ("/var/lib/howy/security-state/unadopted", 0o700),
            (STATE_DIRECTORY, 0o700),
            ("/var/cache/howy", 0o700),
            ("/var/log/howy", 0o700),
            ("/etc/systemd/system/howy.service.d", 0o755),
            ("/usr/lib/howy", 0o755),
            ("/usr/lib/security", 0o755),
            ("/usr/lib/sysusers.d", 0o755),
            ("/usr/share/howy", 0o755),
            ("/usr/share/libalpm/hooks", 0o755),
        ] {
            self.ensure_directory(path, mode)?;
        }
        Ok(())
    }

    pub fn bootstrap_release_n(&mut self) -> Result<BootstrapOutcome> {
        self.begin()?;
        self.recover_locked(true)?;
        if let Some((manifest, manifest_snapshot)) = self.read_manifest()? {
            return self.restore_manifest(&manifest, &manifest_snapshot.record);
        }

        let source = self.require_bootstrap_source()?;
        let current = self.read_path(CONFIG_PATH, MAX_CONFIG_BYTES)?;
        if let Some(current) = &current
            && exact_bootstrap(current, self.paths.expected_uid, self.paths.expected_gid).is_ok()
        {
            let state = ConfigState::Present {
                file: current.record.clone(),
            };
            self.ensure_marker(&transaction_id()?, None, &state)?;
            return Ok(BootstrapOutcome::Installed);
        }
        let legacy = current.ok_or_else(|| {
            BridgeError::refused("release-N legacy package payload is absent on fresh install")
        })?;
        require_exact_legacy(
            &legacy,
            self.paths.expected_uid,
            self.paths.expected_gid,
            "release-N legacy package payload",
        )?;

        if self.path_occupied(MARKER_PATH)? {
            return Err(BridgeError::refused(
                "fresh bootstrap marker unexpectedly exists; refusing an ambiguous install",
            ));
        }
        let transaction_id = transaction_id()?;
        let stage_name = format!("{CONFIG_STAGE_PREFIX}{transaction_id}-bootstrap");
        let journal = BridgeJournal::BootstrapReleaseN {
            schema_version: SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            legacy: legacy.record,
            config_stage_name: stage_name,
        };
        self.write_journal(&journal)?;
        self.boundary("bootstrap-journal-published")?;
        self.recover_locked(true)?;

        let installed = self
            .read_path(CONFIG_PATH, MAX_CONFIG_BYTES)?
            .ok_or_else(|| BridgeError::refused("installed bootstrap disappeared"))?;
        exact_bootstrap(&installed, self.paths.expected_uid, self.paths.expected_gid)?;
        let state = ConfigState::Present {
            file: installed.record,
        };
        self.ensure_marker(&transaction_id, None, &state)?;
        drop(source);
        Ok(BootstrapOutcome::Installed)
    }

    /// Upgrade/reinstall completion never performs a fresh legacy→bootstrap
    /// replacement. A release-N manifest is restored exactly; without one the
    /// preserved config state is descriptor-verified before the positive marker.
    pub fn complete_release_n(&mut self) -> Result<BootstrapOutcome> {
        self.begin()?;
        self.recover_locked(true)?;
        if let Some((manifest, snapshot)) = self.read_manifest()? {
            return self.restore_manifest(&manifest, &snapshot.record);
        }
        let state = self.snapshot_config_state()?;
        validate_safe_completion_state(&state, self.paths.expected_uid, self.paths.expected_gid)?;
        self.ensure_marker(&transaction_id()?, None, &state)?;
        Ok(BootstrapOutcome::VerifiedUpgrade)
    }

    pub fn create_if_absent(&mut self) -> Result<CreateOutcome> {
        self.begin()?;
        self.recover_locked(true)?;
        let source = self.require_bootstrap_source()?;
        let transaction_id = transaction_id()?;
        let (parent, target) = self.paths.open_parent(CONFIG_PATH)?;
        if lookup(parent.as_raw_fd(), &target)?.is_some() {
            return Ok(CreateOutcome::Occupied);
        }
        self.boundary("create-private-open")?;
        match self.publish_noreplace_at(
            parent.as_raw_fd(),
            &target,
            &source.bytes,
            self.paths.expected_uid,
            self.paths.expected_gid,
            0o600,
            None,
            &transaction_id,
            "create",
        )? {
            PublishOutcome::Published(snapshot) => {
                self.boundary("create-linked")?;
                sync_directory(parent.as_raw_fd())?;
                exact_bootstrap(&snapshot, self.paths.expected_uid, self.paths.expected_gid)?;
                Ok(CreateOutcome::Created)
            }
            PublishOutcome::Occupied => Ok(CreateOutcome::Occupied),
        }
    }

    pub fn stash_release_n(&mut self) -> Result<StashOutcome> {
        self.begin()?;
        // A restored generation is intentionally allowed to differ here: an
        // administrator may have edited/replaced the config after restore and
        // this PreTransaction snapshot must refresh to that exact current state.
        self.recover_locked(false)?;
        let source = self.snapshot_config_state()?;
        validate_stash_config_state(&source)?;
        let existing = self.read_manifest()?;

        if let Some((manifest, _)) = &existing {
            match &manifest.active.state {
                GenerationState::Absent { .. } | GenerationState::PresentStashed { .. } => {
                    self.validate_active_capture(manifest, &source)?;
                    if self.path_occupied(MARKER_PATH)? {
                        return Err(BridgeError::refused(
                            "active stash generation unexpectedly retained a bootstrap marker",
                        ));
                    }
                    return Ok(StashOutcome::AlreadyExact);
                }
                GenerationState::Restored { .. } => {}
                GenerationState::ConsumedRefreshable { .. } => {
                    return Err(BridgeError::refused(
                        "active stash generation cannot be consumed-only",
                    ));
                }
            }
        }

        let transaction_id = transaction_id()?;
        let generation = existing.as_ref().map_or(1, |(manifest, _)| {
            manifest.active.generation.saturating_add(1)
        });
        if generation == 0 {
            return Err(BridgeError::refused("stash generation overflow"));
        }
        let active_state = match &source {
            ConfigState::Absent { absence } => GenerationState::Absent {
                absence: absence.clone(),
            },
            ConfigState::Present { file } => {
                let stash_path = stash_path(generation);
                GenerationState::PresentStashed {
                    source: file.clone(),
                    stash_path,
                    stash_sha256: file.sha256.clone(),
                    stash_size: file.metadata.byte_length,
                }
            }
        };
        let mut consumed_generations = Vec::new();
        if let Some((manifest, _)) = &existing {
            consumed_generations = manifest.consumed_generations.clone();
            let consumed = consume_restored_generation(&manifest.active, &transaction_id)?;
            if consumed_generations.len() >= MAX_CONSUMED_GENERATIONS {
                return Err(BridgeError::refused(
                    "release-N consumed generation limit reached; explicit review is required",
                ));
            }
            consumed_generations.push(consumed);
        }
        let new_manifest = StashManifest {
            schema_version: SCHEMA_VERSION,
            release_id: RELEASE_ID.to_owned(),
            config_path: CONFIG_PATH.to_owned(),
            active: GenerationRecord {
                generation,
                stash_transaction_id: transaction_id.clone(),
                state: active_state,
            },
            consumed_generations,
        };
        new_manifest.validate()?;
        let marker = self.read_marker_snapshot()?.map(|snapshot| snapshot.record);
        let journal = BridgeJournal::StashReleaseN {
            schema_version: SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            source,
            previous_manifest: existing
                .as_ref()
                .map(|(_, snapshot)| snapshot.record.clone()),
            new_manifest: Box::new(new_manifest),
            manifest_stage_name: format!("{CONTROL_STAGE_PREFIX}{transaction_id}-manifest"),
            marker,
        };
        self.write_journal(&journal)?;
        self.boundary("stash-journal-published")?;
        self.recover_locked(true)?;
        Ok(if existing.is_some() {
            StashOutcome::Refreshed
        } else {
            StashOutcome::Created
        })
    }

    pub fn recover(&mut self) -> Result<()> {
        self.begin()?;
        self.recover_locked(true)
    }

    fn require_identity(&self) -> Result<()> {
        if self.paths.require_euid_root && unsafe { libc::geteuid() } != 0 {
            return Err(BridgeError::refused(
                "howy-config-bridge requires the real root identity",
            ));
        }
        Ok(())
    }

    fn begin(&mut self) -> Result<()> {
        self.require_identity()?;
        self.acquire_lock()
    }

    fn acquire_lock(&mut self) -> Result<()> {
        if self.lock.is_some() {
            return Ok(());
        }
        let (parent, name) = self.paths.open_parent(LOCK_PATH)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(last_error("permanent bridge lock open failed"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = fstat(file.as_raw_fd())?;
        if !is_regular(&metadata)
            || metadata.st_uid != self.paths.expected_uid
            || metadata.st_gid != self.paths.expected_gid
            || permissions(&metadata) != 0o600
            || metadata.st_nlink != 1
        {
            return Err(BridgeError::refused(
                "permanent bridge lock metadata is unsafe",
            ));
        }
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK) || Instant::now() >= deadline {
                return Err(BridgeError::refused(format!(
                    "permanent bridge lock acquisition failed: {error}"
                )));
            }
            thread::sleep(Duration::from_millis(50));
        }
        file.sync_all()
            .map_err(|_| BridgeError::refused("permanent bridge lock fsync failed"))?;
        sync_directory(parent.as_raw_fd())?;
        self.lock = Some(file);
        Ok(())
    }

    fn recover_locked(&mut self, revalidate_restored: bool) -> Result<()> {
        let Some(journal_snapshot) = self.read_path(JOURNAL_PATH, MAX_CONTROL_BYTES)? else {
            self.refuse_orphan_stages(None)?;
            if revalidate_restored
                && let Some((manifest, _)) = self.read_manifest()?
                && matches!(manifest.active.state, GenerationState::Restored { .. })
            {
                let state = self.verify_restored_manifest(&manifest)?;
                let transaction = restored_transaction(&manifest.active.state)?;
                self.ensure_marker(transaction, Some(manifest.active.generation), &state)?;
            }
            return Ok(());
        };
        require_control_file(
            &journal_snapshot,
            self.paths.expected_uid,
            self.paths.expected_gid,
            "bridge journal",
        )?;
        let journal: BridgeJournal = serde_json::from_slice(&journal_snapshot.bytes)
            .map_err(|_| BridgeError::refused("bridge journal is not the strict v2 schema"))?;
        journal.validate()?;
        self.refuse_orphan_stages(Some(journal.transaction_id()))?;

        let post_marker = match &journal {
            BridgeJournal::BootstrapReleaseN {
                transaction_id,
                legacy,
                config_stage_name,
                ..
            } => {
                self.recover_bootstrap(legacy, config_stage_name)?;
                let current = self
                    .read_path(CONFIG_PATH, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| BridgeError::refused("recovered bootstrap disappeared"))?;
                exact_bootstrap(&current, self.paths.expected_uid, self.paths.expected_gid)?;
                Some((
                    transaction_id.clone(),
                    None,
                    ConfigState::Present {
                        file: current.record,
                    },
                ))
            }
            BridgeJournal::StashReleaseN {
                transaction_id,
                source,
                previous_manifest,
                new_manifest,
                manifest_stage_name,
                marker,
                ..
            } => {
                self.recover_stash(
                    transaction_id,
                    source,
                    previous_manifest.as_ref(),
                    new_manifest,
                    manifest_stage_name,
                    marker.as_ref(),
                )?;
                None
            }
            BridgeJournal::RestoreReleaseN {
                transaction_id,
                manifest,
                generation,
                config_stage_name,
                config_backup_name,
                manifest_stage_name,
                ..
            } => {
                let state = self.recover_restore(
                    transaction_id,
                    manifest,
                    *generation,
                    config_stage_name,
                    config_backup_name,
                    manifest_stage_name,
                )?;
                Some((transaction_id.clone(), Some(*generation), state))
            }
        };
        self.remove_journal(&journal_snapshot.record)?;
        self.boundary("journal-removed-and-synced")?;
        if let Some((transaction, generation, state)) = post_marker {
            self.ensure_marker(&transaction, generation, &state)?;
        }
        self.refuse_orphan_stages(None)
    }

    fn recover_bootstrap(&mut self, legacy: &FileRecord, stage_name: &str) -> Result<()> {
        require_pinned_legacy_record(legacy, self.paths.expected_uid, self.paths.expected_gid)?;
        let source = self.require_bootstrap_source()?;
        let (parent, target_name) = self.paths.open_parent(CONFIG_PATH)?;
        let stage_name = cstring(OsStr::new(stage_name))?;
        let mut target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
        let mut stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONFIG_BYTES)?;

        if target
            .as_ref()
            .is_some_and(|value| same_object(&value.record, legacy))
            && stage.is_none()
        {
            self.boundary("bootstrap-stage-before-open")?;
            stage = Some(create_exclusive(
                parent.as_raw_fd(),
                &stage_name,
                &source.bytes,
                self.paths.expected_uid,
                self.paths.expected_gid,
                0o600,
                None,
            )?);
            sync_directory(parent.as_raw_fd())?;
            self.boundary("bootstrap-stage-created-and-synced")?;
        }
        if let (Some(current), Some(staged)) = (&target, &stage)
            && same_object(&current.record, legacy)
            && exact_bootstrap(staged, self.paths.expected_uid, self.paths.expected_gid).is_ok()
        {
            self.boundary("bootstrap-exchange-before")?;
            renameat2(
                parent.as_raw_fd(),
                &stage_name,
                parent.as_raw_fd(),
                &target_name,
                libc::RENAME_EXCHANGE,
            )?;
            sync_directory(parent.as_raw_fd())?;
            self.boundary("bootstrap-exchange-after-directory-fsync")?;
            target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
            stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONFIG_BYTES)?;
        }
        match (target.as_ref(), stage.as_ref()) {
            (Some(target), Some(stage))
                if exact_bootstrap(target, self.paths.expected_uid, self.paths.expected_gid)
                    .is_ok()
                    && same_object(&stage.record, legacy) =>
            {
                self.boundary("bootstrap-backup-before-unlink")?;
                remove_exact(parent.as_raw_fd(), &stage_name, legacy)?;
                sync_directory(parent.as_raw_fd())?;
                self.boundary("bootstrap-backup-after-directory-fsync")?;
            }
            (Some(target), None)
                if exact_bootstrap(target, self.paths.expected_uid, self.paths.expected_gid)
                    .is_ok() =>
            {
                sync_directory(parent.as_raw_fd())?;
            }
            _ => {
                return Err(BridgeError::refused(
                    "bootstrap recovery observed an unknown target or stage; all objects were retained",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_stash(
        &mut self,
        transaction_id: &str,
        source: &ConfigState,
        previous_manifest: Option<&FileRecord>,
        new_manifest: &StashManifest,
        manifest_stage_name: &str,
        marker: Option<&FileRecord>,
    ) -> Result<()> {
        self.verify_config_state_identity(source)?;
        if new_manifest.active.stash_transaction_id != transaction_id {
            return Err(BridgeError::refused(
                "stash journal and active generation transaction differ",
            ));
        }
        if let ConfigState::Present { file } = source {
            let (stash_path, expected_hash, expected_size) =
                active_present(&new_manifest.active.state)?;
            if expected_hash != file.sha256 || expected_size != file.metadata.byte_length {
                return Err(BridgeError::refused(
                    "stash manifest does not bind the captured configuration",
                ));
            }
            let live = self
                .read_path(CONFIG_PATH, MAX_CONFIG_BYTES)?
                .ok_or_else(|| BridgeError::refused("captured config disappeared"))?;
            self.ensure_stash_file(stash_path, &live, transaction_id)?;
        }

        let bytes = serialize_control(new_manifest, "stash manifest")?;
        self.replace_manifest(
            previous_manifest,
            &bytes,
            manifest_stage_name,
            transaction_id,
        )?;
        self.boundary("stash-manifest-committed")?;

        match (marker, self.read_marker_snapshot()?) {
            (Some(expected), Some(current)) if same_object(expected, &current.record) => {
                self.boundary("marker-before-unlink")?;
                let (parent, name) = self.paths.open_parent(MARKER_PATH)?;
                remove_exact(parent.as_raw_fd(), &name, expected)?;
                sync_directory(parent.as_raw_fd())?;
                self.boundary("marker-after-directory-fsync")?;
            }
            (Some(_), None) | (None, None) => {}
            _ => {
                return Err(BridgeError::refused(
                    "bootstrap marker identity changed during stash; it was retained",
                ));
            }
        }
        Ok(())
    }

    fn recover_restore(
        &mut self,
        transaction_id: &str,
        old_manifest_record: &FileRecord,
        generation: u64,
        config_stage_name: &str,
        config_backup_name: &str,
        manifest_stage_name: &str,
    ) -> Result<ConfigState> {
        let (manifest, current_manifest_snapshot) = self
            .read_manifest()?
            .ok_or_else(|| BridgeError::refused("restore lost its durable manifest"))?;
        if manifest.active.generation != generation {
            return Err(BridgeError::refused(
                "restore generation changed unexpectedly",
            ));
        }

        let restored_already = matches!(
            &manifest.active.state,
            GenerationState::Restored {
                restore_transaction_id,
                ..
            } if restore_transaction_id == transaction_id
        );
        if !restored_already && !same_object(&current_manifest_snapshot.record, old_manifest_record)
        {
            return Err(BridgeError::refused(
                "restore manifest identity changed; controls were retained",
            ));
        }
        let captured = if restored_already {
            restored_capture(&manifest.active.state)?.clone()
        } else {
            manifest.active.state.clone()
        };

        let state = self.restore_config_state(
            &captured,
            config_stage_name,
            config_backup_name,
            transaction_id,
        )?;
        if !restored_already {
            let mut restored_manifest = manifest.clone();
            restored_manifest.active.state = GenerationState::Restored {
                captured: Box::new(captured),
                restored_target: state.clone(),
                restore_transaction_id: transaction_id.to_owned(),
            };
            restored_manifest.validate()?;
            let bytes = serialize_control(&restored_manifest, "restored manifest")?;
            self.replace_manifest(
                Some(old_manifest_record),
                &bytes,
                manifest_stage_name,
                transaction_id,
            )?;
        } else {
            // A crash after the manifest exchange but before removing the
            // exact exchanged legacy manifest leaves the old inode at the
            // transaction-bound stage. Finish that identity-checked cleanup.
            let bytes = serialize_control(&manifest, "restored manifest")?;
            self.replace_manifest(
                Some(old_manifest_record),
                &bytes,
                manifest_stage_name,
                transaction_id,
            )?;
        }
        let (final_manifest, _) = self
            .read_manifest()?
            .ok_or_else(|| BridgeError::refused("restored manifest disappeared"))?;
        self.verify_restored_manifest(&final_manifest)
    }

    fn restore_config_state(
        &mut self,
        captured: &GenerationState,
        stage_name: &str,
        backup_name: &str,
        transaction_id: &str,
    ) -> Result<ConfigState> {
        match captured {
            GenerationState::Absent { absence } => {
                let (parent, target_name) = self.paths.open_parent(CONFIG_PATH)?;
                validate_absence_parent(parent.as_raw_fd(), absence)?;
                let backup_name = cstring(OsStr::new(backup_name))?;
                let target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
                let backup = read_regular(parent.as_raw_fd(), &backup_name, MAX_CONFIG_BYTES)?;
                match (target.as_ref(), backup.as_ref()) {
                    (None, None) => {}
                    (Some(target), None)
                        if require_exact_legacy(
                            target,
                            self.paths.expected_uid,
                            self.paths.expected_gid,
                            "variant-installed payload",
                        )
                        .is_ok() =>
                    {
                        self.boundary("absent-restore-backup-before-rename")?;
                        renameat2(
                            parent.as_raw_fd(),
                            &target_name,
                            parent.as_raw_fd(),
                            &backup_name,
                            libc::RENAME_NOREPLACE,
                        )?;
                        sync_directory(parent.as_raw_fd())?;
                        self.boundary("absent-restore-backup-after-directory-fsync")?;
                    }
                    (None, Some(backup))
                        if require_exact_legacy(
                            backup,
                            self.paths.expected_uid,
                            self.paths.expected_gid,
                            "journal-owned absent restore backup",
                        )
                        .is_ok() => {}
                    _ => {
                        return Err(BridgeError::refused(
                            "absent stash accepts only an absent target or exact packaged legacy payload",
                        ));
                    }
                }
                if let Some(backup) =
                    read_regular(parent.as_raw_fd(), &backup_name, MAX_CONFIG_BYTES)?
                {
                    require_exact_legacy(
                        &backup,
                        self.paths.expected_uid,
                        self.paths.expected_gid,
                        "journal-owned absent restore backup",
                    )?;
                    self.boundary("absent-restore-backup-before-unlink")?;
                    remove_exact(parent.as_raw_fd(), &backup_name, &backup.record)?;
                    sync_directory(parent.as_raw_fd())?;
                    self.boundary("absent-restore-backup-after-unlink-fsync")?;
                }
                if lookup(parent.as_raw_fd(), &target_name)?.is_some() {
                    return Err(BridgeError::refused(
                        "absent restore target reappeared after transactional removal",
                    ));
                }
                Ok(ConfigState::Absent {
                    absence: absence.clone(),
                })
            }
            GenerationState::PresentStashed {
                source,
                stash_path,
                stash_sha256,
                stash_size,
            } => {
                let stash = self
                    .read_path(stash_path, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| BridgeError::refused("release-N stash file is absent"))?;
                require_control_file(
                    &stash,
                    self.paths.expected_uid,
                    self.paths.expected_gid,
                    "release-N stash",
                )?;
                if stash.record.sha256 != *stash_sha256
                    || stash.record.metadata.byte_length != *stash_size
                    || stash.bytes.len() as u64 != source.metadata.byte_length
                    || sha256(&stash.bytes) != source.sha256
                {
                    return Err(BridgeError::refused(
                        "release-N stash bytes differ from the exact captured source",
                    ));
                }
                let (parent, target_name) = self.paths.open_parent(CONFIG_PATH)?;
                let stage_name = cstring(OsStr::new(stage_name))?;
                let mut target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
                let mut stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONFIG_BYTES)?;
                if let Some(current_target) = &target {
                    if logically_matches(&current_target.record, source) {
                        if let Some(legacy_stage) = &stage {
                            require_exact_legacy(
                                legacy_stage,
                                self.paths.expected_uid,
                                self.paths.expected_gid,
                                "journal-owned exchanged legacy payload",
                            )?;
                            self.boundary("restore-backup-before-unlink")?;
                            remove_exact(parent.as_raw_fd(), &stage_name, &legacy_stage.record)?;
                            sync_directory(parent.as_raw_fd())?;
                            self.boundary("restore-backup-after-directory-fsync")?;
                        }
                        return Ok(ConfigState::Present {
                            file: current_target.record.clone(),
                        });
                    }
                    require_exact_legacy(
                        current_target,
                        self.paths.expected_uid,
                        self.paths.expected_gid,
                        "variant-installed payload",
                    )?;
                    if stage.is_none() {
                        self.boundary("restore-stage-before-open")?;
                        stage = Some(create_exclusive(
                            parent.as_raw_fd(),
                            &stage_name,
                            &stash.bytes,
                            source.metadata.uid,
                            source.metadata.gid,
                            source.metadata.permissions,
                            Some(&source.metadata),
                        )?);
                        sync_directory(parent.as_raw_fd())?;
                        self.boundary("restore-stage-created-and-synced")?;
                    }
                    let staged = stage.as_ref().ok_or_else(|| {
                        BridgeError::refused("restore stage disappeared after creation")
                    })?;
                    if !logically_matches(&staged.record, source) {
                        return Err(BridgeError::refused(
                            "restore stage does not match captured metadata",
                        ));
                    }
                    self.boundary("restore-exchange-before")?;
                    renameat2(
                        parent.as_raw_fd(),
                        &stage_name,
                        parent.as_raw_fd(),
                        &target_name,
                        libc::RENAME_EXCHANGE,
                    )?;
                    sync_directory(parent.as_raw_fd())?;
                    self.boundary("restore-exchange-after-directory-fsync")?;
                    target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
                    stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONFIG_BYTES)?;
                } else if stage.is_none() {
                    self.boundary("restore-noreplace-before-open")?;
                    match self.publish_noreplace_at(
                        parent.as_raw_fd(),
                        &target_name,
                        &stash.bytes,
                        source.metadata.uid,
                        source.metadata.gid,
                        source.metadata.permissions,
                        Some(&source.metadata),
                        transaction_id,
                        "restore-target",
                    )? {
                        PublishOutcome::Published(_) => {}
                        PublishOutcome::Occupied => {
                            return Err(BridgeError::refused(
                                "restore target became occupied during no-replace publication",
                            ));
                        }
                    }
                    sync_directory(parent.as_raw_fd())?;
                    self.boundary("restore-noreplace-after-directory-fsync")?;
                    target = read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)?;
                }

                if let Some(stage) = &stage {
                    require_exact_legacy(
                        stage,
                        self.paths.expected_uid,
                        self.paths.expected_gid,
                        "journal-owned exchanged legacy payload",
                    )?;
                    self.boundary("restore-backup-before-unlink")?;
                    remove_exact(parent.as_raw_fd(), &stage_name, &stage.record)?;
                    sync_directory(parent.as_raw_fd())?;
                    self.boundary("restore-backup-after-directory-fsync")?;
                }
                let target = target
                    .or_else(|| {
                        read_regular(parent.as_raw_fd(), &target_name, MAX_CONFIG_BYTES)
                            .ok()
                            .flatten()
                    })
                    .ok_or_else(|| BridgeError::refused("restored target is absent"))?;
                if !logically_matches(&target.record, source) {
                    return Err(BridgeError::refused(
                        "present stash target is neither exact stashed bytes nor a safe restore result",
                    ));
                }
                Ok(ConfigState::Present {
                    file: target.record,
                })
            }
            _ => Err(BridgeError::refused(
                "only absent or present-stashed generations can be restored",
            )),
        }
    }

    fn restore_manifest(
        &mut self,
        manifest: &StashManifest,
        manifest_record: &FileRecord,
    ) -> Result<BootstrapOutcome> {
        match &manifest.active.state {
            GenerationState::Restored { .. } => {
                let state = self.verify_restored_manifest(manifest)?;
                self.ensure_marker(
                    restored_transaction(&manifest.active.state)?,
                    Some(manifest.active.generation),
                    &state,
                )?;
                Ok(BootstrapOutcome::RestoredStash)
            }
            GenerationState::Absent { .. } | GenerationState::PresentStashed { .. } => {
                if self.path_occupied(MARKER_PATH)? {
                    return Err(BridgeError::refused(
                        "unrestored generation still has a bootstrap marker; refusing fail-open recovery",
                    ));
                }
                let transaction_id = transaction_id()?;
                let journal = BridgeJournal::RestoreReleaseN {
                    schema_version: SCHEMA_VERSION,
                    transaction_id: transaction_id.clone(),
                    manifest: manifest_record.clone(),
                    generation: manifest.active.generation,
                    config_stage_name: format!("{CONFIG_STAGE_PREFIX}{transaction_id}-restore"),
                    config_backup_name: format!(
                        "{CONFIG_STAGE_PREFIX}{transaction_id}-absent-backup"
                    ),
                    manifest_stage_name: format!("{CONTROL_STAGE_PREFIX}{transaction_id}-manifest"),
                };
                self.write_journal(&journal)?;
                self.boundary("restore-journal-published")?;
                self.recover_locked(true)?;
                Ok(BootstrapOutcome::RestoredStash)
            }
            GenerationState::ConsumedRefreshable { .. } => Err(BridgeError::refused(
                "consumed generation cannot be the active restore generation",
            )),
        }
    }

    fn verify_restored_manifest(&self, manifest: &StashManifest) -> Result<ConfigState> {
        let GenerationState::Restored {
            captured,
            restored_target,
            ..
        } = &manifest.active.state
        else {
            return Err(BridgeError::refused("active generation is not restored"));
        };
        let live = self.snapshot_config_state()?;
        match captured.as_ref() {
            GenerationState::Absent { .. } => {
                if !matches!(live, ConfigState::Absent { .. }) {
                    return Err(BridgeError::refused(
                        "restored absent generation is now occupied",
                    ));
                }
            }
            GenerationState::PresentStashed { source, .. } => match &live {
                ConfigState::Present { file } if logically_matches(file, source) => {}
                _ => {
                    return Err(BridgeError::refused(
                        "restored present generation no longer matches captured config",
                    ));
                }
            },
            _ => {
                return Err(BridgeError::refused(
                    "restored generation has an invalid captured state",
                ));
            }
        }
        if !config_states_logically_match(&live, restored_target) {
            return Err(BridgeError::refused(
                "restored target identity differs from the committed manifest",
            ));
        }
        Ok(live)
    }

    fn validate_active_capture(&self, manifest: &StashManifest, live: &ConfigState) -> Result<()> {
        match (&manifest.active.state, live) {
            (GenerationState::Absent { absence }, ConfigState::Absent { absence: live })
                if absence == live => {}
            (GenerationState::PresentStashed { source, .. }, ConfigState::Present { file })
                if logically_matches(source, file) =>
            {
                self.validate_stash_for_generation(&manifest.active.state)?;
            }
            _ => {
                return Err(BridgeError::refused(
                    "active stash generation conflicts with the current configuration",
                ));
            }
        }
        Ok(())
    }

    fn verify_config_state_identity(&self, expected: &ConfigState) -> Result<()> {
        let live = self.snapshot_config_state()?;
        match (expected, &live) {
            (ConfigState::Absent { absence }, ConfigState::Absent { absence: current })
                if absence == current =>
            {
                Ok(())
            }
            (ConfigState::Present { file }, ConfigState::Present { file: current })
                if same_object(file, current) =>
            {
                Ok(())
            }
            _ => Err(BridgeError::refused(
                "configuration changed while completing the journaled operation",
            )),
        }
    }

    fn ensure_stash_file(
        &mut self,
        stash_path: &str,
        source: &Snapshot,
        transaction_id: &str,
    ) -> Result<()> {
        match self.read_path(stash_path, MAX_CONFIG_BYTES)? {
            Some(existing) => {
                require_control_file(
                    &existing,
                    self.paths.expected_uid,
                    self.paths.expected_gid,
                    "release-N stash",
                )?;
                if existing.bytes != source.bytes {
                    return Err(BridgeError::refused(
                        "generation stash path contains conflicting bytes",
                    ));
                }
            }
            None => {
                let (parent, name) = self.paths.open_parent(stash_path)?;
                self.boundary("stash-control-before-open")?;
                match self.publish_noreplace_at(
                    parent.as_raw_fd(),
                    &name,
                    &source.bytes,
                    self.paths.expected_uid,
                    self.paths.expected_gid,
                    0o600,
                    None,
                    transaction_id,
                    "stash",
                )? {
                    PublishOutcome::Published(_) => {}
                    PublishOutcome::Occupied => {
                        return Err(BridgeError::refused(
                            "generation stash path became occupied",
                        ));
                    }
                }
                sync_directory(parent.as_raw_fd())?;
                self.boundary("stash-control-after-directory-fsync")?;
            }
        }
        Ok(())
    }

    fn validate_stash_for_generation(&self, state: &GenerationState) -> Result<()> {
        let (path, hash, size) = active_present(state)?;
        let stash = self
            .read_path(path, MAX_CONFIG_BYTES)?
            .ok_or_else(|| BridgeError::refused("generation stash is absent"))?;
        require_control_file(
            &stash,
            self.paths.expected_uid,
            self.paths.expected_gid,
            "release-N stash",
        )?;
        if stash.record.sha256 != hash || stash.record.metadata.byte_length != size {
            return Err(BridgeError::refused(
                "generation stash does not match its manifest",
            ));
        }
        Ok(())
    }

    fn replace_manifest(
        &mut self,
        old: Option<&FileRecord>,
        new_bytes: &[u8],
        stage_name: &str,
        transaction_id: &str,
    ) -> Result<()> {
        let (parent, manifest_name) = self.paths.open_parent(MANIFEST_PATH)?;
        let stage_name = cstring(OsStr::new(stage_name))?;
        let mut current = read_regular(parent.as_raw_fd(), &manifest_name, MAX_CONTROL_BYTES)?;
        let mut stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONTROL_BYTES)?;
        let current_is_new = current.as_ref().is_some_and(|value| {
            require_control_file(
                value,
                self.paths.expected_uid,
                self.paths.expected_gid,
                "stash manifest",
            )
            .is_ok()
                && value.bytes == new_bytes
        });
        if old.is_none() {
            match current.as_ref() {
                None => {
                    self.boundary("manifest-control-before-open")?;
                    match self.publish_noreplace_at(
                        parent.as_raw_fd(),
                        &manifest_name,
                        new_bytes,
                        self.paths.expected_uid,
                        self.paths.expected_gid,
                        0o600,
                        None,
                        transaction_id,
                        "manifest",
                    )? {
                        PublishOutcome::Published(_) => {}
                        PublishOutcome::Occupied => {
                            return Err(BridgeError::refused(
                                "manifest appeared during no-replace publication",
                            ));
                        }
                    }
                    sync_directory(parent.as_raw_fd())?;
                    self.boundary("manifest-control-after-directory-fsync")?;
                    return Ok(());
                }
                Some(_) if current_is_new => return Ok(()),
                Some(_) => {
                    return Err(BridgeError::refused(
                        "unexpected existing manifest was retained",
                    ));
                }
            }
        }
        let old = old.expect("checked above");
        if current_is_new {
            if let Some(stage) = &stage {
                if !same_object(&stage.record, old) {
                    return Err(BridgeError::refused(
                        "manifest backup identity is unknown and was retained",
                    ));
                }
                self.boundary("manifest-backup-before-unlink")?;
                remove_exact(parent.as_raw_fd(), &stage_name, old)?;
                sync_directory(parent.as_raw_fd())?;
                self.boundary("manifest-backup-after-directory-fsync")?;
            }
            return Ok(());
        }
        if !current
            .as_ref()
            .is_some_and(|value| same_object(&value.record, old))
        {
            return Err(BridgeError::refused(
                "manifest replacement target identity changed",
            ));
        }
        if stage.is_none() {
            self.boundary("manifest-stage-before-open")?;
            match self.publish_noreplace_at(
                parent.as_raw_fd(),
                &stage_name,
                new_bytes,
                self.paths.expected_uid,
                self.paths.expected_gid,
                0o600,
                None,
                transaction_id,
                "manifest-stage",
            )? {
                PublishOutcome::Published(value) => stage = Some(value),
                PublishOutcome::Occupied => {
                    return Err(BridgeError::refused("manifest stage became occupied"));
                }
            }
            sync_directory(parent.as_raw_fd())?;
            self.boundary("manifest-stage-created-and-synced")?;
        }
        let staged = stage
            .as_ref()
            .ok_or_else(|| BridgeError::refused("manifest stage absent"))?;
        if staged.bytes != new_bytes {
            return Err(BridgeError::refused(
                "manifest stage has unknown bytes and was retained",
            ));
        }
        self.boundary("manifest-exchange-before")?;
        renameat2(
            parent.as_raw_fd(),
            &stage_name,
            parent.as_raw_fd(),
            &manifest_name,
            libc::RENAME_EXCHANGE,
        )?;
        sync_directory(parent.as_raw_fd())?;
        self.boundary("manifest-exchange-after-directory-fsync")?;
        current = read_regular(parent.as_raw_fd(), &manifest_name, MAX_CONTROL_BYTES)?;
        stage = read_regular(parent.as_raw_fd(), &stage_name, MAX_CONTROL_BYTES)?;
        if current
            .as_ref()
            .is_none_or(|value| value.bytes != new_bytes)
            || !stage
                .as_ref()
                .is_some_and(|value| same_object(&value.record, old))
        {
            return Err(BridgeError::refused(
                "manifest exchange did not produce exact recoverable identities",
            ));
        }
        self.boundary("manifest-backup-before-unlink")?;
        remove_exact(parent.as_raw_fd(), &stage_name, old)?;
        sync_directory(parent.as_raw_fd())?;
        self.boundary("manifest-backup-after-directory-fsync")
    }

    fn ensure_marker(
        &mut self,
        transaction_id: &str,
        generation: Option<u64>,
        state: &ConfigState,
    ) -> Result<()> {
        validate_config_state(state)?;
        let marker = BootstrapMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            release_id: RELEASE_ID.to_owned(),
            transaction_id: transaction_id.to_owned(),
            generation,
            config: state.clone(),
        };
        let bytes = serialize_control(&marker, "bootstrap marker")?;
        if let Some(existing) = self.read_marker_snapshot()? {
            let parsed: BootstrapMarker = serde_json::from_slice(&existing.bytes)
                .map_err(|_| BridgeError::refused("unknown bootstrap marker was retained"))?;
            validate_marker(&parsed)?;
            if parsed.generation == generation && config_states_exact_match(&parsed.config, state) {
                return Ok(());
            }
            let (parent, name) = self.paths.open_parent(MARKER_PATH)?;
            self.boundary("marker-reset-before-unlink")?;
            remove_exact(parent.as_raw_fd(), &name, &existing.record)?;
            sync_directory(parent.as_raw_fd())?;
            self.boundary("marker-reset-after-directory-fsync")?;
        }
        let (parent, name) = self.paths.open_parent(MARKER_PATH)?;
        self.boundary("marker-control-before-open")?;
        match self.publish_noreplace_at(
            parent.as_raw_fd(),
            &name,
            &bytes,
            self.paths.expected_uid,
            self.paths.expected_gid,
            0o600,
            None,
            transaction_id,
            "marker",
        )? {
            PublishOutcome::Published(_) => {}
            PublishOutcome::Occupied => {
                return Err(BridgeError::refused(
                    "bootstrap marker became occupied during publication",
                ));
            }
        }
        sync_directory(parent.as_raw_fd())?;
        self.boundary("marker-control-after-directory-fsync")
    }

    fn read_marker_snapshot(&self) -> Result<Option<Snapshot>> {
        let Some(snapshot) = self.read_path(MARKER_PATH, MAX_CONTROL_BYTES)? else {
            return Ok(None);
        };
        require_control_file(
            &snapshot,
            self.paths.expected_uid,
            self.paths.expected_gid,
            "package bootstrap marker",
        )?;
        Ok(Some(snapshot))
    }

    fn require_bootstrap_source(&self) -> Result<Snapshot> {
        let source = self
            .read_path(BOOTSTRAP_PATH, MAX_CONFIG_BYTES)?
            .ok_or_else(|| BridgeError::refused("secure bootstrap source is absent"))?;
        require_exact_file(
            &source,
            self.paths.expected_uid,
            self.paths.expected_gid,
            0o644,
            BOOTSTRAP_SIZE,
            BOOTSTRAP_SHA256,
            "secure bootstrap source",
        )?;
        validate_bootstrap_semantics(&source.bytes)?;
        Ok(source)
    }

    fn snapshot_config_state(&self) -> Result<ConfigState> {
        let (parent, name) = self.paths.open_parent(CONFIG_PATH)?;
        match read_regular(parent.as_raw_fd(), &name, MAX_CONFIG_BYTES)? {
            Some(snapshot) => Ok(ConfigState::Present {
                file: snapshot.record,
            }),
            None => {
                if lookup(parent.as_raw_fd(), &name)?.is_some() {
                    return Err(BridgeError::refused(
                        "configuration path is occupied by an unsupported object",
                    ));
                }
                let stat = fstat(parent.as_raw_fd())?;
                Ok(ConfigState::Absent {
                    absence: AbsenceRecord {
                        parent_device: stat.st_dev,
                        parent_inode: stat.st_ino,
                    },
                })
            }
        }
    }

    fn read_manifest(&self) -> Result<Option<(StashManifest, Snapshot)>> {
        let Some(snapshot) = self.read_path(MANIFEST_PATH, MAX_CONTROL_BYTES)? else {
            return Ok(None);
        };
        require_control_file(
            &snapshot,
            self.paths.expected_uid,
            self.paths.expected_gid,
            "release-N stash manifest",
        )?;
        let manifest: StashManifest = serde_json::from_slice(&snapshot.bytes)
            .map_err(|_| BridgeError::refused("release-N stash manifest is invalid"))?;
        manifest.validate()?;
        match &manifest.active.state {
            GenerationState::PresentStashed { .. } => {
                self.validate_stash_for_generation(&manifest.active.state)?;
            }
            GenerationState::Restored { captured, .. }
                if matches!(captured.as_ref(), GenerationState::PresentStashed { .. }) =>
            {
                self.validate_stash_for_generation(captured)?;
            }
            _ => {}
        }
        Ok(Some((manifest, snapshot)))
    }

    fn write_journal(&mut self, journal: &BridgeJournal) -> Result<()> {
        journal.validate()?;
        if self.path_occupied(JOURNAL_PATH)? {
            return Err(BridgeError::refused(
                "bridge journal appeared after recovery",
            ));
        }
        let bytes = serialize_control(journal, "bridge journal")?;
        let (parent, name) = self.paths.open_parent(JOURNAL_PATH)?;
        self.boundary("journal-control-before-open")?;
        match self.publish_noreplace_at(
            parent.as_raw_fd(),
            &name,
            &bytes,
            self.paths.expected_uid,
            self.paths.expected_gid,
            0o600,
            None,
            journal.transaction_id(),
            "journal",
        )? {
            PublishOutcome::Published(_) => {}
            PublishOutcome::Occupied => {
                return Err(BridgeError::refused("bridge journal became occupied"));
            }
        }
        sync_directory(parent.as_raw_fd())?;
        self.boundary("journal-control-after-directory-fsync")
    }

    fn remove_journal(&mut self, expected: &FileRecord) -> Result<()> {
        let (parent, name) = self.paths.open_parent(JOURNAL_PATH)?;
        self.boundary("journal-before-unlink")?;
        remove_exact(parent.as_raw_fd(), &name, expected)?;
        sync_directory(parent.as_raw_fd())?;
        self.boundary("journal-after-unlink-directory-fsync")
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_noreplace_at(
        &mut self,
        parent: RawFd,
        name: &CStr,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        metadata: Option<&FileMetadata>,
        transaction_id: &str,
        label: &str,
    ) -> Result<PublishOutcome> {
        if lookup(parent, name)?.is_some() {
            return Ok(PublishOutcome::Occupied);
        }
        let dot = cstring(OsStr::new("."))?;
        let mut unnamed = true;
        let mut fd = unsafe {
            libc::openat(
                parent,
                dot.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                mode as libc::mode_t,
            )
        };
        let private_name = cstring(OsStr::new(&format!(
            "{PRIVATE_STAGE_PREFIX}{transaction_id}-{label}"
        )))?;
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) | Some(libc::EISDIR)
            ) {
                unnamed = false;
                fd = unsafe {
                    libc::openat(
                        parent,
                        private_name.as_ptr(),
                        libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        mode as libc::mode_t,
                    )
                };
            }
        }
        if fd < 0 {
            return Err(last_error("private bridge temporary creation failed"));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let mut created_identity = None;
        let result = (|| {
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0
            {
                return Err(last_error("private bridge temporary metadata setup failed"));
            }
            self.boundary("private-control-before-write")?;
            file.write_all(bytes)
                .map_err(|_| BridgeError::refused("private bridge temporary write failed"))?;
            if let Some(metadata) = metadata {
                set_timestamps(file.as_raw_fd(), metadata)?;
            }
            self.boundary("private-control-after-write")?;
            file.sync_all()
                .map_err(|_| BridgeError::refused("private bridge temporary fsync failed"))?;
            self.boundary("private-control-after-fsync")?;
            let created = fstat(file.as_raw_fd())?;
            created_identity = Some((created.st_dev, created.st_ino));
            let publish = if unnamed {
                let empty = cstring(OsStr::new(""))?;
                let mut result = unsafe {
                    libc::linkat(
                        file.as_raw_fd(),
                        empty.as_ptr(),
                        parent,
                        name.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                };
                if result != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                {
                    let proc_path =
                        cstring(OsStr::new(&format!("/proc/self/fd/{}", file.as_raw_fd())))?;
                    result = unsafe {
                        libc::linkat(
                            libc::AT_FDCWD,
                            proc_path.as_ptr(),
                            parent,
                            name.as_ptr(),
                            libc::AT_SYMLINK_FOLLOW,
                        )
                    };
                }
                result
            } else {
                match renameat2(parent, &private_name, parent, name, libc::RENAME_NOREPLACE) {
                    Ok(()) => 0,
                    Err(error) if lookup(parent, name)?.is_some() => {
                        let _ = error;
                        1
                    }
                    Err(error) => return Err(error),
                }
            };
            if publish != 0 {
                if lookup(parent, name)?.is_some() {
                    return Ok(PublishOutcome::Occupied);
                }
                return Err(last_error("private bridge temporary publication failed"));
            }
            self.boundary("private-control-after-link-or-rename")?;
            sync_directory(parent)?;
            self.boundary("private-control-after-directory-fsync")?;
            let published = read_regular(parent, name, bytes.len().max(1))?
                .ok_or_else(|| BridgeError::refused("published bridge file disappeared"))?;
            if published.record.device != created.st_dev
                || published.record.inode != created.st_ino
                || published.bytes != bytes
                || published.record.metadata.uid != uid
                || published.record.metadata.gid != gid
                || published.record.metadata.permissions != mode
            {
                return Err(BridgeError::refused(
                    "published bridge file identity or bytes changed",
                ));
            }
            Ok(PublishOutcome::Published(published))
        })();
        if !unnamed
            && (result.is_err() || matches!(&result, Ok(PublishOutcome::Occupied)))
            && let Some((device, inode)) = created_identity
            && lookup(parent, &private_name)?.is_some()
        {
            self.boundary("private-collision-before-unlink")?;
            unlink_identity(parent, &private_name, device, inode)?;
            sync_directory(parent)?;
            self.boundary("private-collision-after-directory-fsync")?;
        }
        result
    }

    fn ensure_directory(&mut self, production: &str, mode: u32) -> Result<()> {
        let relative = self.paths.relative(production)?;
        let mut current = self.paths.open_root()?;
        let components: Vec<_> = relative.components().collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                return Err(BridgeError::refused("layout path is invalid"));
            };
            let name = cstring(component)?;
            let is_leaf = index + 1 == components.len();
            let existing = lookup(current.as_raw_fd(), &name)?;
            if existing.is_none() {
                if !is_leaf {
                    return Err(BridgeError::refused(format!(
                        "required layout parent is absent: {production}"
                    )));
                }
                self.boundary("layout-before-mkdir")?;
                if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode) } != 0 {
                    return Err(last_error("descriptor-safe layout mkdir failed"));
                }
                sync_directory(current.as_raw_fd())?;
                self.boundary("layout-after-parent-fsync")?;
            }
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(last_error("descriptor-safe layout traversal failed"));
            }
            let next = unsafe { OwnedFd::from_raw_fd(fd) };
            let stat = fstat(next.as_raw_fd())?;
            if is_leaf {
                if stat.st_uid != self.paths.expected_uid
                    || stat.st_gid != self.paths.expected_gid
                    || permissions(&stat) != mode
                    || (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                {
                    return Err(BridgeError::refused(format!(
                        "layout directory has non-exact policy: {production}"
                    )));
                }
                sync_directory(next.as_raw_fd())?;
            } else {
                validate_safe_directory(
                    next.as_raw_fd(),
                    self.paths.expected_uid,
                    self.paths.expected_gid,
                )?;
            }
            current = next;
        }
        Ok(())
    }

    fn refuse_orphan_stages(&self, transaction_id: Option<&str>) -> Result<()> {
        for directory in ["/etc/howy", STATE_DIRECTORY, "/var/lib"] {
            let fd = self.paths.open_directory(directory)?;
            for name in list_directory(fd.as_raw_fd())? {
                let relevant = name.starts_with(CONFIG_STAGE_PREFIX)
                    || name.starts_with(CONTROL_STAGE_PREFIX)
                    || name.starts_with(PRIVATE_STAGE_PREFIX);
                if !relevant {
                    continue;
                }
                let allowed = transaction_id.is_some_and(|transaction| name.contains(transaction));
                if !allowed {
                    return Err(BridgeError::refused(format!(
                        "unknown/orphan bridge stage retained: {directory}/{name}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn path_occupied(&self, path: &str) -> Result<bool> {
        let (parent, name) = self.paths.open_parent(path)?;
        Ok(lookup(parent.as_raw_fd(), &name)?.is_some())
    }

    fn read_path(&self, path: &str, maximum: usize) -> Result<Option<Snapshot>> {
        let (parent, name) = self.paths.open_parent(path)?;
        read_regular(parent.as_raw_fd(), &name, maximum)
    }

    #[cfg(not(test))]
    fn boundary(&mut self, _point: &str) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn boundary(&mut self, point: &str) -> Result<()> {
        if self.kill_at.as_deref() == Some(point) {
            unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            unreachable!("SIGKILL must terminate the bridge test child");
        }
        if self.fail_at.as_deref() == Some(point) {
            self.fail_at = None;
            Err(BridgeError::refused(format!(
                "injected bridge interruption at {point}"
            )))
        } else {
            Ok(())
        }
    }
}

enum PublishOutcome {
    Published(Snapshot),
    Occupied,
}

fn validate_bootstrap_semantics(bytes: &[u8]) -> Result<()> {
    if bytes != BOOTSTRAP_BYTES
        || sha256(bytes) != BOOTSTRAP_SHA256
        || bytes.len() as u64 != BOOTSTRAP_SIZE
    {
        return Err(BridgeError::refused("secure bootstrap hash is not pinned"));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| BridgeError::refused("secure bootstrap is not UTF-8"))?;
    let config: HowyConfig =
        toml::from_str(source).map_err(|_| BridgeError::refused("secure bootstrap is invalid"))?;
    config
        .validate()
        .map_err(|_| BridgeError::refused("secure bootstrap does not validate"))?;
    if !config.core.disabled
        || config.security.embedding_mode != EmbeddingSecurityMode::AeadCached
        || config.security.key_epoch != 1
        || config.presence.mode != PresenceMode::Confirm
    {
        return Err(BridgeError::refused(
            "secure bootstrap semantics are not disabled Mode1 epoch1 with prompt confirmation",
        ));
    }
    if HowyConfig::secure_bootstrap_template_toml().as_bytes() != bytes {
        return Err(BridgeError::refused(
            "secure bootstrap differs from the common generated template",
        ));
    }
    Ok(())
}

fn validate_schema_and_transaction(schema: u16, transaction_id: &str) -> Result<()> {
    if schema != SCHEMA_VERSION {
        return Err(BridgeError::refused("bridge journal schema is unsupported"));
    }
    validate_transaction_id(transaction_id)
}

fn validate_transaction_id(transaction_id: &str) -> Result<()> {
    if transaction_id.len() != 32
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BridgeError::refused(
            "bridge transaction identity is invalid",
        ));
    }
    Ok(())
}

fn validate_stage_name(name: &str, transaction_id: &str, suffix: &str) -> Result<()> {
    if name != format!("{CONFIG_STAGE_PREFIX}{transaction_id}-{suffix}") {
        return Err(BridgeError::refused(
            "config stage name is not transaction-bound",
        ));
    }
    Ok(())
}

fn validate_control_stage_name(name: &str, transaction_id: &str, suffix: &str) -> Result<()> {
    if name != format!("{CONTROL_STAGE_PREFIX}{transaction_id}-{suffix}") {
        return Err(BridgeError::refused(
            "control stage name is not transaction-bound",
        ));
    }
    Ok(())
}

fn validate_active_generation(state: &GenerationState) -> Result<()> {
    match state {
        GenerationState::Absent { absence } => validate_absence_record(absence),
        GenerationState::PresentStashed {
            source,
            stash_path,
            stash_sha256,
            stash_size,
        } => validate_present_capture(source, stash_path, stash_sha256, *stash_size),
        GenerationState::Restored {
            captured,
            restored_target,
            restore_transaction_id,
        } => {
            validate_captured_state(captured)?;
            validate_config_state(restored_target)?;
            validate_transaction_id(restore_transaction_id)
        }
        GenerationState::ConsumedRefreshable { .. } => Err(BridgeError::refused(
            "active generation cannot be consumed-refreshable",
        )),
    }
}

fn validate_consumed_generation(state: &GenerationState) -> Result<()> {
    let GenerationState::ConsumedRefreshable {
        captured,
        restored_target,
        restore_transaction_id,
        consumed_by_transaction_id,
    } = state
    else {
        return Err(BridgeError::refused(
            "history generation is not consumed-refreshable",
        ));
    };
    validate_captured_state(captured)?;
    validate_config_state(restored_target)?;
    validate_transaction_id(restore_transaction_id)?;
    validate_transaction_id(consumed_by_transaction_id)
}

fn validate_captured_state(state: &GenerationState) -> Result<()> {
    match state {
        GenerationState::Absent { absence } => validate_absence_record(absence),
        GenerationState::PresentStashed {
            source,
            stash_path,
            stash_sha256,
            stash_size,
        } => validate_present_capture(source, stash_path, stash_sha256, *stash_size),
        _ => Err(BridgeError::refused("captured generation state is invalid")),
    }
}

fn validate_present_capture(
    source: &FileRecord,
    stash_path: &str,
    stash_sha256: &str,
    stash_size: u64,
) -> Result<()> {
    validate_record(source)?;
    if stash_path != stash_path_from_source(stash_path)?
        || stash_sha256 != source.sha256
        || stash_size != source.metadata.byte_length
    {
        return Err(BridgeError::refused(
            "present stash generation is inconsistent",
        ));
    }
    Ok(())
}

fn stash_path_from_source(path: &str) -> Result<&str> {
    let Some(suffix) = path.strip_prefix(&format!("{STATE_DIRECTORY}/{STASH_PREFIX}")) else {
        return Err(BridgeError::refused(
            "stash path is outside the generation namespace",
        ));
    };
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BridgeError::refused("stash generation path is invalid"));
    }
    Ok(path)
}

fn validate_absence_record(absence: &AbsenceRecord) -> Result<()> {
    if absence.parent_device == 0 || absence.parent_inode == 0 {
        return Err(BridgeError::refused("absent config identity is invalid"));
    }
    Ok(())
}

fn validate_config_state(state: &ConfigState) -> Result<()> {
    match state {
        ConfigState::Absent { absence } => validate_absence_record(absence),
        ConfigState::Present { file } => validate_record(file),
    }
}

fn validate_marker(marker: &BootstrapMarker) -> Result<()> {
    if marker.schema_version != MARKER_SCHEMA_VERSION || marker.release_id != RELEASE_ID {
        return Err(BridgeError::refused("bootstrap marker schema is invalid"));
    }
    validate_transaction_id(&marker.transaction_id)?;
    if marker.generation == Some(0) {
        return Err(BridgeError::refused(
            "bootstrap marker generation is invalid",
        ));
    }
    validate_config_state(&marker.config)
}

fn validate_safe_completion_state(state: &ConfigState, uid: u32, gid: u32) -> Result<()> {
    match state {
        ConfigState::Absent { .. } => Ok(()),
        ConfigState::Present { file }
            if file.metadata.uid == uid
                && file.metadata.gid == gid
                && file.metadata.link_count == 1
                && file.metadata.byte_length <= MAX_CONFIG_BYTES as u64 =>
        {
            Ok(())
        }
        _ => Err(BridgeError::refused(
            "preserved config is not a root-owned single-link bounded regular file",
        )),
    }
}

fn validate_stash_config_state(state: &ConfigState) -> Result<()> {
    match state {
        ConfigState::Absent { .. } => Ok(()),
        ConfigState::Present { file }
            if file.metadata.link_count == 1
                && file.metadata.byte_length <= MAX_CONFIG_BYTES as u64 =>
        {
            Ok(())
        }
        _ => Err(BridgeError::refused(
            "configuration metadata is unsafe for an exact release-N stash",
        )),
    }
}

fn consume_restored_generation(
    active: &GenerationRecord,
    transaction_id: &str,
) -> Result<GenerationRecord> {
    let GenerationState::Restored {
        captured,
        restored_target,
        restore_transaction_id,
    } = &active.state
    else {
        return Err(BridgeError::refused(
            "only a restored generation can be refreshed",
        ));
    };
    Ok(GenerationRecord {
        generation: active.generation,
        stash_transaction_id: active.stash_transaction_id.clone(),
        state: GenerationState::ConsumedRefreshable {
            captured: captured.clone(),
            restored_target: restored_target.clone(),
            restore_transaction_id: restore_transaction_id.clone(),
            consumed_by_transaction_id: transaction_id.to_owned(),
        },
    })
}

fn restored_capture(state: &GenerationState) -> Result<&GenerationState> {
    let GenerationState::Restored { captured, .. } = state else {
        return Err(BridgeError::refused("generation is not restored"));
    };
    Ok(captured)
}

fn restored_transaction(state: &GenerationState) -> Result<&str> {
    let GenerationState::Restored {
        restore_transaction_id,
        ..
    } = state
    else {
        return Err(BridgeError::refused("generation is not restored"));
    };
    Ok(restore_transaction_id)
}

fn active_present(state: &GenerationState) -> Result<(&str, &str, u64)> {
    let GenerationState::PresentStashed {
        stash_path,
        stash_sha256,
        stash_size,
        ..
    } = state
    else {
        return Err(BridgeError::refused("generation is not present-stashed"));
    };
    Ok((stash_path, stash_sha256, *stash_size))
}

fn stash_path(generation: u64) -> String {
    format!("{STATE_DIRECTORY}/{STASH_PREFIX}{generation}")
}

fn config_states_logically_match(left: &ConfigState, right: &ConfigState) -> bool {
    match (left, right) {
        (ConfigState::Absent { absence: left }, ConfigState::Absent { absence: right }) => {
            left == right
        }
        (ConfigState::Present { file: left }, ConfigState::Present { file: right }) => {
            logically_matches(left, right)
        }
        _ => false,
    }
}

fn config_states_exact_match(left: &ConfigState, right: &ConfigState) -> bool {
    match (left, right) {
        (ConfigState::Absent { absence: left }, ConfigState::Absent { absence: right }) => {
            left == right
        }
        (ConfigState::Present { file: left }, ConfigState::Present { file: right }) => {
            same_object(left, right)
        }
        _ => false,
    }
}

fn require_exact_legacy(snapshot: &Snapshot, uid: u32, gid: u32, label: &str) -> Result<()> {
    require_exact_file(snapshot, uid, gid, 0o644, LEGACY_SIZE, LEGACY_SHA256, label)?;
    if snapshot.bytes != LEGACY_BYTES {
        return Err(BridgeError::refused(format!(
            "{label} differs from the compiled release-N fixture"
        )));
    }
    Ok(())
}

fn require_pinned_legacy_record(record: &FileRecord, uid: u32, gid: u32) -> Result<()> {
    validate_record(record)?;
    if record.sha256 != LEGACY_SHA256
        || record.metadata.byte_length != LEGACY_SIZE
        || record.metadata.uid != uid
        || record.metadata.gid != gid
        || record.metadata.permissions != 0o644
    {
        return Err(BridgeError::refused(
            "bootstrap journal does not bind the pinned legacy payload",
        ));
    }
    Ok(())
}

fn exact_bootstrap(snapshot: &Snapshot, uid: u32, gid: u32) -> Result<()> {
    require_exact_file(
        snapshot,
        uid,
        gid,
        0o600,
        BOOTSTRAP_SIZE,
        BOOTSTRAP_SHA256,
        "installed secure bootstrap",
    )?;
    validate_bootstrap_semantics(&snapshot.bytes)
}

fn require_exact_file(
    snapshot: &Snapshot,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    hash: &str,
    label: &str,
) -> Result<()> {
    if snapshot.record.metadata.uid != uid
        || snapshot.record.metadata.gid != gid
        || snapshot.record.metadata.permissions != mode
        || snapshot.record.metadata.link_count != 1
        || snapshot.record.metadata.byte_length != size
        || snapshot.record.sha256 != hash
    {
        return Err(BridgeError::refused(format!(
            "{label} bytes or metadata differ from the exact release-N contract"
        )));
    }
    Ok(())
}

fn require_control_file(snapshot: &Snapshot, uid: u32, gid: u32, label: &str) -> Result<()> {
    if snapshot.record.metadata.uid != uid
        || snapshot.record.metadata.gid != gid
        || snapshot.record.metadata.permissions != 0o600
        || snapshot.record.metadata.link_count != 1
    {
        return Err(BridgeError::refused(format!("{label} metadata is unsafe")));
    }
    Ok(())
}

fn validate_record(record: &FileRecord) -> Result<()> {
    if record.device == 0
        || record.inode == 0
        || record.sha256.len() != 64
        || !record
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || record.metadata.link_count != 1
        || record.metadata.permissions & !0o7777 != 0
        || record.metadata.byte_length > MAX_CONFIG_BYTES as u64
        || record.metadata.access_nanoseconds > 999_999_999
        || record.metadata.modification_nanoseconds > 999_999_999
    {
        return Err(BridgeError::refused("bridge file record is invalid"));
    }
    Ok(())
}

fn serialize_control<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| BridgeError::refused(format!("{label} serialization failed")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(BridgeError::refused(format!(
            "{label} exceeds the control cap"
        )));
    }
    Ok(bytes)
}

fn create_exclusive(
    parent: RawFd,
    name: &CStr,
    bytes: &[u8],
    uid: u32,
    gid: u32,
    mode: u32,
    metadata: Option<&FileMetadata>,
) -> Result<Snapshot> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(last_error(
            "exclusive journaled bridge stage creation failed",
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| {
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
            || unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0
        {
            return Err(last_error("bridge stage metadata setup failed"));
        }
        file.write_all(bytes)
            .map_err(|_| BridgeError::refused("bridge stage write failed"))?;
        if let Some(metadata) = metadata {
            set_timestamps(file.as_raw_fd(), metadata)?;
        }
        file.sync_all()
            .map_err(|_| BridgeError::refused("bridge stage fsync failed"))?;
        let stat = fstat(file.as_raw_fd())?;
        let record = record(bytes, &stat)?;
        if record.metadata.uid != uid
            || record.metadata.gid != gid
            || record.metadata.permissions != mode
            || record.metadata.byte_length != bytes.len() as u64
        {
            return Err(BridgeError::refused(
                "created bridge stage metadata verification failed",
            ));
        }
        Ok(Snapshot {
            bytes: bytes.to_vec(),
            record,
        })
    })();
    // Once a named stage exists, failures retain it for journaled recovery.
    result
}

fn set_timestamps(fd: RawFd, metadata: &FileMetadata) -> Result<()> {
    let timestamps = [
        libc::timespec {
            tv_sec: metadata.access_seconds,
            tv_nsec: i64::from(metadata.access_nanoseconds),
        },
        libc::timespec {
            tv_sec: metadata.modification_seconds,
            tv_nsec: i64::from(metadata.modification_nanoseconds),
        },
    ];
    if unsafe { libc::futimens(fd, timestamps.as_ptr()) } != 0 {
        return Err(last_error("bridge timestamp restoration failed"));
    }
    Ok(())
}

fn read_regular(parent: RawFd, name: &CStr, maximum: usize) -> Result<Option<Snapshot>> {
    let Some(lookup_stat) = lookup(parent, name)? else {
        return Ok(None);
    };
    if !is_regular(&lookup_stat)
        || lookup_stat.st_nlink != 1
        || lookup_stat.st_size < 0
        || usize::try_from(lookup_stat.st_size).map_or(true, |size| size > maximum)
    {
        return Err(BridgeError::refused(
            "bridge path is occupied by a non-regular, hard-linked, or oversized object",
        ));
    }
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | libc::O_NOATIME,
        )
    };
    if fd < 0 {
        return Err(last_error("no-follow bridge file open failed"));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = fstat(file.as_raw_fd())?;
    if identity(&lookup_stat) != identity(&before) {
        return Err(BridgeError::refused(
            "bridge file changed between lookup and descriptor open",
        ));
    }
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| BridgeError::refused("bounded descriptor read failed"))?;
    let after = fstat(file.as_raw_fd())?;
    if identity(&before) != identity(&after) || after.st_size != bytes.len() as i64 {
        return Err(BridgeError::refused(
            "bridge file changed during descriptor read",
        ));
    }
    Ok(Some(Snapshot {
        record: record(&bytes, &after)?,
        bytes,
    }))
}

fn remove_exact(parent: RawFd, name: &CStr, expected: &FileRecord) -> Result<()> {
    let current = read_regular(parent, name, MAX_CONTROL_BYTES.max(MAX_CONFIG_BYTES))?
        .ok_or_else(|| BridgeError::refused("journal-owned bridge file disappeared"))?;
    if !same_object(&current.record, expected) {
        return Err(BridgeError::refused(
            "journal-owned bridge file was replaced; refusing deletion",
        ));
    }
    unlink_identity(parent, name, expected.device, expected.inode)
}

fn unlink_identity(parent: RawFd, name: &CStr, device: u64, inode: u64) -> Result<()> {
    let current = lookup(parent, name)?
        .ok_or_else(|| BridgeError::refused("exact bridge unlink target is absent"))?;
    if current.st_dev != device || current.st_ino != inode || !is_regular(&current) {
        return Err(BridgeError::refused(
            "exact bridge unlink target identity changed",
        ));
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        return Err(last_error("exact bridge unlink failed"));
    }
    Ok(())
}

fn lookup(parent: RawFd, name: &CStr) -> Result<Option<libc::stat>> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(Some(stat));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(BridgeError::refused(format!(
            "bridge path lookup failed: {error}"
        )))
    }
}

fn validate_safe_directory(fd: RawFd, uid: u32, gid: u32) -> Result<()> {
    let stat = fstat(fd)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_nlink == 0
        || permissions(&stat) & 0o022 != 0
    {
        return Err(BridgeError::refused(
            "bridge directory ownership or metadata is unsafe",
        ));
    }
    Ok(())
}

fn validate_absence_parent(fd: RawFd, absence: &AbsenceRecord) -> Result<()> {
    let stat = fstat(fd)?;
    if stat.st_dev != absence.parent_device || stat.st_ino != absence.parent_inode {
        return Err(BridgeError::refused(
            "absent config parent identity changed",
        ));
    }
    Ok(())
}

fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(last_error("bridge descriptor metadata query failed"));
    }
    Ok(stat)
}

fn record(bytes: &[u8], stat: &libc::stat) -> Result<FileRecord> {
    if !is_regular(stat) || stat.st_nlink != 1 || stat.st_size != bytes.len() as i64 {
        return Err(BridgeError::refused("bridge file record is not canonical"));
    }
    let access_nanoseconds = u32::try_from(stat.st_atime_nsec)
        .map_err(|_| BridgeError::refused("bridge access timestamp is invalid"))?;
    let modification_nanoseconds = u32::try_from(stat.st_mtime_nsec)
        .map_err(|_| BridgeError::refused("bridge modification timestamp is invalid"))?;
    let record = FileRecord {
        device: stat.st_dev,
        inode: stat.st_ino,
        sha256: sha256(bytes),
        metadata: FileMetadata {
            uid: stat.st_uid,
            gid: stat.st_gid,
            permissions: permissions(stat),
            link_count: stat.st_nlink,
            byte_length: bytes.len() as u64,
            access_seconds: stat.st_atime,
            access_nanoseconds,
            modification_seconds: stat.st_mtime,
            modification_nanoseconds,
        },
    };
    validate_record(&record)?;
    Ok(record)
}

fn identity(stat: &libc::stat) -> (u64, u64, u32, u32, u32, u64, i64, i64, i64, i64, i64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_gid,
        stat.st_nlink,
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    )
}

fn is_regular(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

fn permissions(stat: &libc::stat) -> u32 {
    stat.st_mode & 0o7777
}

fn logically_matches(left: &FileRecord, right: &FileRecord) -> bool {
    left.sha256 == right.sha256
        && left.metadata.uid == right.metadata.uid
        && left.metadata.gid == right.metadata.gid
        && left.metadata.permissions == right.metadata.permissions
        && left.metadata.link_count == right.metadata.link_count
        && left.metadata.byte_length == right.metadata.byte_length
        && left.metadata.modification_seconds == right.metadata.modification_seconds
        && left.metadata.modification_nanoseconds == right.metadata.modification_nanoseconds
}

fn same_object(left: &FileRecord, right: &FileRecord) -> bool {
    left.device == right.device && left.inode == right.inode && logically_matches(left, right)
}

fn renameat2(
    old_parent: RawFd,
    old: &CStr,
    new_parent: RawFd,
    new: &CStr,
    flags: u32,
) -> Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent,
            old.as_ptr(),
            new_parent,
            new.as_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(last_error("descriptor-bound atomic bridge rename failed"));
    }
    Ok(())
}

fn sync_directory(fd: RawFd) -> Result<()> {
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(last_error("bridge directory fsync failed"));
    }
    Ok(())
}

fn transaction_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    let mut offset = 0;
    while offset < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(BridgeError::refused(format!(
                "bridge transaction randomness failed: {error}"
            )));
        }
        if result == 0 {
            return Err(BridgeError::refused(
                "bridge transaction randomness returned no bytes",
            ));
        }
        offset += result as usize;
    }
    let mut output = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn list_directory(fd: RawFd) -> Result<BTreeSet<String>> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(last_error("bridge directory duplication failed"));
    }
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(last_error("bridge directory stream open failed"));
    }
    let mut names = BTreeSet::new();
    loop {
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = std::str::from_utf8(name.to_bytes())
            .map_err(|_| BridgeError::refused("non-UTF-8 bridge stage was retained"))?;
        names.insert(name.to_owned());
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(last_error("bridge directory stream close failed"));
    }
    Ok(names)
}

fn cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| BridgeError::refused("bridge path contains an interior NUL"))
}

fn last_error(context: &str) -> BridgeError {
    BridgeError::refused(format!("{context}: {}", std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests;
