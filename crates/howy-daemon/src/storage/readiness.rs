//! Read-only provisioning readiness for the cached-AEAD namespace.
//!
//! This path deliberately does not construct a storage backend: it never
//! creates/fixes directories, cleans transaction artifacts, publishes cache
//! state, or resolves a model unless at least one authoritative record exists.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
use howy_common::provisioning::{
    DaemonVerifierIdentityV1, MAX_CONFIG_BYTES, MAX_NAMESPACE_CIPHERTEXT_BYTES,
    MAX_NAMESPACE_ENTRIES, MAX_NAMESPACE_NAME_BYTES, MAX_NAMESPACE_TOTAL_BYTES, MAX_PATH_BYTES,
    MODE1_NAMESPACE_PATH, NamespaceDirectoryMetadata, NamespaceEntryClassification,
    NamespaceFileType, NamespaceFingerprintEntry, NamespaceInventoryV1, ReadinessResultV1,
    RecognizerIdentity, Sha256Digest, classify_mode1_namespace_entry, namespace_fingerprint,
    validate_readiness_inventory,
};
use howy_common::storage::{
    CancellationSignal, CanonicalUsername, ModelDigest, OsRandomSource,
    PlaintextAllocationEstimate, PlaintextBudget, RandomSource, StorageMode, inspect_howyenc1,
    inspect_howyenc1_metadata,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::mode1_key::Mode1KeyContext;

pub const STRONG_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const CONFIG_FILE_MODE_WRITE_MASK: u32 = 0o022;
const CONFIG_FILE_SPECIAL_MODE_MASK: u32 = 0o7000;
const CONFIG_FILE_OWNER_READ: u32 = 0o400;
const BINARY_SIZE_MAX: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl DescriptorIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct OpenedAbsoluteFile {
    file: File,
    parent: File,
    parent_identity: DescriptorIdentity,
    identity: DescriptorIdentity,
    final_name: CString,
}

/// Exact bytes and descriptor identity of the configuration selected at startup.
pub struct OpenedConfig {
    path: PathBuf,
    expected_owner: u32,
    validate_ancestors: bool,
    opened: OpenedAbsoluteFile,
    config: HowyConfig,
    raw_sha256: Sha256Digest,
}

impl OpenedConfig {
    pub fn config(&self) -> &HowyConfig {
        &self.config
    }

    pub fn raw_sha256(&self) -> &Sha256Digest {
        &self.raw_sha256
    }

    /// Reopen the complete path without following symlinks and require the
    /// exact parent and file identity retained at initial parsing.
    pub fn revalidate(&self) -> Result<()> {
        self.revalidate_cancellable(&NeverCancelled)
    }

    pub fn revalidate_cancellable(&self, cancellation: &dyn CancellationSignal) -> Result<()> {
        ensure_not_cancelled(cancellation)?;
        if DescriptorIdentity::from_metadata(&self.opened.parent.metadata()?)
            != self.opened.parent_identity
        {
            bail!("configuration parent descriptor identity changed");
        }
        let relative = open_regular_entry(&self.opened.parent, &self.opened.final_name)
            .context("configuration final path component changed")?;
        if DescriptorIdentity::from_metadata(&relative.metadata()?) != self.opened.identity {
            bail!("configuration final path identity changed");
        }
        let reopened = open_absolute_file_no_follow(
            &self.path,
            self.expected_owner,
            self.validate_ancestors,
            cancellation,
        )
        .context("configuration path identity changed")?;
        if reopened.parent_identity != self.opened.parent_identity
            || reopened.identity != self.opened.identity
            || self
                .opened
                .file
                .metadata()
                .map(|value| DescriptorIdentity::from_metadata(&value))?
                != self.opened.identity
        {
            bail!("configuration descriptor identity changed");
        }
        ensure_not_cancelled(cancellation)?;
        Ok(())
    }
}

/// Open, read, hash, parse, and validate one root-owned configuration without
/// ever following a path component symlink.
pub fn open_daemon_config(path: &Path) -> Result<OpenedConfig> {
    open_daemon_config_cancellable(path, &NeverCancelled)
}

pub fn open_daemon_config_cancellable(
    path: &Path,
    cancellation: &dyn CancellationSignal,
) -> Result<OpenedConfig> {
    open_config_with_policy(path, 0, true, cancellation)
}

fn open_config_with_policy(
    path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    cancellation: &dyn CancellationSignal,
) -> Result<OpenedConfig> {
    ensure_not_cancelled(cancellation)?;
    let opened =
        open_absolute_file_no_follow(path, expected_owner, validate_ancestors, cancellation)
            .context("configuration could not be opened safely")?;
    validate_config_metadata(&opened.file.metadata()?, expected_owner, validate_ancestors)?;
    let length = usize::try_from(opened.identity.length).context("configuration is too large")?;
    if length == 0 || length > MAX_CONFIG_BYTES {
        bail!("configuration size is outside the allowed bound");
    }
    let bytes = read_exact_descriptor(&opened.file, length, Some(cancellation))
        .context("configuration could not be read exactly")?;
    let post_read = DescriptorIdentity::from_metadata(&opened.file.metadata()?);
    if post_read != opened.identity {
        bail!("configuration metadata changed while it was read");
    }
    let source = std::str::from_utf8(&bytes).context("configuration is not valid UTF-8")?;
    ensure_not_cancelled(cancellation)?;
    let config: HowyConfig = toml::from_str(source).context("configuration TOML is invalid")?;
    config
        .validate()
        .map_err(anyhow::Error::msg)
        .context("configuration validation failed")?;
    let raw_sha256 = Sha256Digest::from_bytes(&bytes);
    ensure_not_cancelled(cancellation)?;
    let snapshot = OpenedConfig {
        path: path.to_path_buf(),
        expected_owner,
        validate_ancestors,
        opened,
        config,
        raw_sha256,
    };
    snapshot.revalidate_cancellable(cancellation)?;
    Ok(snapshot)
}

fn validate_config_metadata(
    metadata: &Metadata,
    expected_owner: u32,
    strict_root_group: bool,
) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner
        || (strict_root_group && metadata.gid() != expected_owner)
        || metadata.nlink() != 1
        || mode & CONFIG_FILE_OWNER_READ == 0
        || mode & CONFIG_FILE_MODE_WRITE_MASK != 0
        || mode & CONFIG_FILE_SPECIAL_MODE_MASK != 0
        || mode & 0o111 != 0
    {
        bail!("configuration metadata violates the root-owned secure-file policy");
    }
    Ok(())
}

fn open_absolute_file_no_follow(
    path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    cancellation: &dyn CancellationSignal,
) -> Result<OpenedAbsoluteFile> {
    ensure_not_cancelled(cancellation)?;
    validate_absolute_path(path)?;
    let mut components = path.components().peekable();
    if !matches!(components.next(), Some(Component::RootDir)) {
        bail!("path is not absolute");
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    if validate_ancestors {
        validate_ancestor(&current.metadata()?, expected_owner)?;
    }
    loop {
        ensure_not_cancelled(cancellation)?;
        let Some(component) = components.next() else {
            bail!("path has no final component");
        };
        let Component::Normal(component) = component else {
            bail!("path contains an unsupported component");
        };
        let component = CString::new(component.as_bytes()).context("path contains NUL")?;
        if components.peek().is_none() {
            let parent_identity = DescriptorIdentity::from_metadata(&current.metadata()?);
            let descriptor = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let file = unsafe { File::from_raw_fd(descriptor) };
            let identity = DescriptorIdentity::from_metadata(&file.metadata()?);
            return Ok(OpenedAbsoluteFile {
                file,
                parent: current,
                parent_identity,
                identity,
                final_name: component,
            });
        }
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error().into());
        }
        current = unsafe { File::from_raw_fd(descriptor) };
        if validate_ancestors {
            validate_ancestor(&current.metadata()?, expected_owner)?;
        }
    }
}

fn validate_ancestor(metadata: &Metadata, expected_owner: u32) -> Result<()> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner
        || metadata.nlink() == 0
        || metadata.mode() & 0o022 != 0
    {
        bail!("path ancestor violates the no-follow ownership policy");
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() < 2
        || bytes.len() > MAX_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.get(1) == Some(&b'/')
        || bytes.last() == Some(&b'/')
        || bytes.windows(2).any(|window| window == b"//")
        || bytes.contains(&0)
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("path is not a canonical absolute candidate");
    }
    Ok(())
}

/// Opened and streamed identity of the running verifier executable.
pub struct OpenedDaemonBinary {
    file: File,
    identity: DescriptorIdentity,
    output: DaemonVerifierIdentityV1,
}

impl OpenedDaemonBinary {
    pub fn output(&self) -> &DaemonVerifierIdentityV1 {
        &self.output
    }

    pub fn revalidate(&self) -> Result<()> {
        self.revalidate_cancellable(&NeverCancelled)
    }

    pub fn revalidate_cancellable(&self, cancellation: &dyn CancellationSignal) -> Result<()> {
        ensure_not_cancelled(cancellation)?;
        if DescriptorIdentity::from_metadata(&self.file.metadata()?) != self.identity {
            bail!("daemon binary metadata changed after hashing");
        }
        Ok(())
    }
}

pub fn open_daemon_binary_identity() -> Result<OpenedDaemonBinary> {
    open_daemon_binary_identity_cancellable(&NeverCancelled)
}

pub fn open_daemon_binary_identity_cancellable(
    cancellation: &dyn CancellationSignal,
) -> Result<OpenedDaemonBinary> {
    ensure_not_cancelled(cancellation)?;
    let path = std::env::current_exe().context("daemon executable path is unavailable")?;
    validate_absolute_path(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .context("daemon executable descriptor is unavailable")?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > BINARY_SIZE_MAX {
        bail!("daemon executable identity is outside the allowed bound");
    }
    let identity = DescriptorIdentity::from_metadata(&metadata);
    let digest = stream_descriptor_sha256(&file, identity.length, Some(cancellation))?;
    if DescriptorIdentity::from_metadata(&file.metadata()?) != identity {
        bail!("daemon executable changed while it was hashed");
    }
    let binary_absolute_path = path
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("daemon executable path is not UTF-8"))?;
    let version = env!("CARGO_PKG_VERSION").to_owned();
    let build_identity = option_env!("HOWY_BUILD_ID")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("howy-{version}+cargo"));
    if version.is_empty()
        || version.len() > howy_common::provisioning::MAX_DAEMON_VERSION_BYTES
        || !version.bytes().all(|byte| matches!(byte, b' '..=b'~'))
        || build_identity.is_empty()
        || build_identity.len() > howy_common::provisioning::MAX_BUILD_ID_BYTES
        || !build_identity
            .bytes()
            .all(|byte| matches!(byte, b' '..=b'~'))
    {
        bail!("daemon build identity is outside the allowed bound");
    }
    let output = DaemonVerifierIdentityV1 {
        version,
        build_identity,
        binary_absolute_path,
        binary_sha256: Sha256Digest::from_array(digest),
    };
    ensure_not_cancelled(cancellation)?;
    Ok(OpenedDaemonBinary {
        file,
        identity,
        output,
    })
}

pub fn new_invocation_id() -> Result<String> {
    new_invocation_id_cancellable(&NeverCancelled)
}

pub fn new_invocation_id_cancellable(cancellation: &dyn CancellationSignal) -> Result<String> {
    ensure_not_cancelled(cancellation)?;
    let mut bytes = [0u8; 32];
    OsRandomSource
        .fill_bytes(&mut bytes)
        .map_err(|_| anyhow::anyhow!("daemon invocation identity generation failed"))?;
    ensure_not_cancelled(cancellation)?;
    Ok(hex::encode(bytes))
}

/// Descriptor-bound recognizer evidence supplied only for a nonempty namespace.
pub struct StrongRecognizerBinding {
    pub digest: ModelDigest,
    pub identity: RecognizerIdentity,
}

struct AuthoritativeRecord {
    name: Vec<u8>,
    username: CanonicalUsername,
    file: File,
    identity: DescriptorIdentity,
}

struct StrongInventory {
    physical_path: PathBuf,
    expected_owner: u32,
    validate_ancestors: bool,
    directory: File,
    directory_identity: DescriptorIdentity,
    logical: NamespaceInventoryV1,
    records: Vec<AuthoritativeRecord>,
}

/// Monotonic cancellation source for the daemon's independently bounded
/// readiness process.
pub struct ReadinessDeadline {
    deadline: Instant,
}

impl ReadinessDeadline {
    pub fn production_from(started_at: Instant) -> Result<Self> {
        let deadline = started_at
            .checked_add(STRONG_READINESS_TIMEOUT)
            .context("readiness deadline overflow")?;
        Ok(Self { deadline })
    }

    pub fn ensure_remaining(&self) -> Result<()> {
        ensure_not_cancelled(self)
    }

    #[cfg(test)]
    pub fn expired_for_test() -> Self {
        Self {
            deadline: Instant::now(),
        }
    }
}

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

impl CancellationSignal for ReadinessDeadline {
    fn is_cancelled(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

/// Inventory and authenticate every authoritative Mode 1 record without
/// constructing a cache-bearing backend or mutating the namespace.
pub fn verify_mode1_namespace<F>(
    config: &HowyConfig,
    key: &Mode1KeyContext,
    cancellation: &dyn CancellationSignal,
    resolve_recognizer: F,
) -> Result<ReadinessResultV1>
where
    F: FnOnce(&dyn CancellationSignal) -> Result<StrongRecognizerBinding>,
{
    verify_mode1_namespace_at(
        config,
        key,
        Path::new(MODE1_NAMESPACE_PATH),
        0,
        true,
        cancellation,
        resolve_recognizer,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_mode1_namespace_at<F>(
    config: &HowyConfig,
    key: &Mode1KeyContext,
    physical_path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    cancellation: &dyn CancellationSignal,
    resolve_recognizer: F,
) -> Result<ReadinessResultV1>
where
    F: FnOnce(&dyn CancellationSignal) -> Result<StrongRecognizerBinding>,
{
    if config.security.embedding_mode != EmbeddingSecurityMode::AeadCached
        || config.security.key_epoch != 1
    {
        bail!("strong readiness requires configured Mode 1 epoch 1");
    }
    ensure_not_cancelled(cancellation)?;
    let mut inventory = inventory_mode1_namespace(
        physical_path,
        expected_owner,
        validate_ancestors,
        cancellation,
    )?;
    ensure_not_cancelled(cancellation)?;
    let fingerprint = namespace_fingerprint(&inventory.logical)?;
    validate_readiness_inventory(&inventory.logical)?;
    ensure_not_cancelled(cancellation)?;
    if inventory.records.is_empty() {
        revalidate_inventory_directory(&inventory, cancellation)?;
        return ReadinessResultV1::new_verified(fingerprint, None).map_err(Into::into);
    }

    ensure_not_cancelled(cancellation)?;
    let recognizer = resolve_recognizer(cancellation)?;
    let budget_limit = usize::try_from(config.security.max_plaintext_bytes)
        .context("readiness plaintext budget does not fit this platform")?;
    let budget = PlaintextBudget::new(budget_limit)?;
    for record in &mut inventory.records {
        verify_authoritative_record(
            record,
            &inventory.directory,
            config,
            key,
            recognizer.digest,
            &budget,
            cancellation,
        )?;
        if budget.used() != 0 {
            bail!("readiness plaintext budget was not released between records");
        }
    }
    ensure_not_cancelled(cancellation)?;
    for record in &inventory.records {
        if DescriptorIdentity::from_metadata(&record.file.metadata()?) != record.identity {
            bail!("Mode 1 record metadata changed after authentication");
        }
        revalidate_record_path(
            &inventory.directory,
            &CString::new(record.name.clone())?,
            record.identity,
            cancellation,
        )?;
    }
    revalidate_inventory_directory(&inventory, cancellation)?;
    ReadinessResultV1::new_verified(fingerprint, Some(recognizer.identity)).map_err(Into::into)
}

fn inventory_mode1_namespace(
    physical_path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    cancellation: &dyn CancellationSignal,
) -> Result<StrongInventory> {
    let directory = open_absolute_directory_no_follow(
        physical_path,
        expected_owner,
        validate_ancestors,
        cancellation,
    )?;
    let directory_metadata = directory.metadata()?;
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.uid() != expected_owner
        || (validate_ancestors && directory_metadata.gid() != expected_owner)
        || directory_metadata.mode() & 0o7777 != 0o700
        || directory_metadata.nlink() == 0
    {
        bail!("Mode 1 namespace directory metadata is not canonical");
    }
    let directory_identity = DescriptorIdentity::from_metadata(&directory_metadata);
    let mut entries = Vec::new();
    let mut records = Vec::new();
    let mut total_bytes = 0u64;
    for_each_directory_name(&directory, MAX_NAMESPACE_ENTRIES, |name| {
        ensure_not_cancelled(cancellation)?;
        if name.is_empty() || name.len() > MAX_NAMESPACE_NAME_BYTES {
            bail!("Mode 1 namespace entry name exceeds the bound");
        }
        let name_c = CString::new(name).context("Mode 1 namespace entry contains NUL")?;
        let path_descriptor = open_path_entry(&directory, &name_c)?;
        let path_metadata = path_descriptor.metadata()?;
        let file_type = namespace_file_type(&path_metadata);
        let classification = classify_mode1_namespace_entry(name, file_type, path_metadata.nlink());
        let mut digest = Sha256Digest::from_bytes(&[]);
        if let NamespaceEntryClassification::Authoritative { username } = &classification {
            let file = open_regular_entry(&directory, &name_c)?;
            let metadata = file.metadata()?;
            let identity = DescriptorIdentity::from_metadata(&metadata);
            if identity != DescriptorIdentity::from_metadata(&path_metadata)
                || !metadata.file_type().is_file()
                || metadata.uid() != expected_owner
                || (validate_ancestors && metadata.gid() != expected_owner)
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() == 0
            {
                bail!("authoritative Mode 1 record metadata is not canonical");
            }
            total_bytes = checked_namespace_total(total_bytes, metadata.len())?;
            let streamed = stream_descriptor_sha256(&file, metadata.len(), Some(cancellation))?;
            if DescriptorIdentity::from_metadata(&file.metadata()?) != identity {
                bail!("Mode 1 record metadata changed while hashing");
            }
            revalidate_record_path(&directory, &name_c, identity, cancellation)?;
            digest = Sha256Digest::from_array(streamed);
            records
                .try_reserve(1)
                .map_err(|_| anyhow::anyhow!("Mode 1 inventory allocation failed"))?;
            records.push(AuthoritativeRecord {
                name: name.to_vec(),
                username: CanonicalUsername::new(username.clone())?,
                file,
                identity,
            });
        }
        entries
            .try_reserve(1)
            .map_err(|_| anyhow::anyhow!("Mode 1 inventory allocation failed"))?;
        entries.push(NamespaceFingerprintEntry {
            name: name.to_vec(),
            file_type,
            uid: if validate_ancestors {
                path_metadata.uid()
            } else {
                0
            },
            gid: if validate_ancestors {
                path_metadata.gid()
            } else {
                0
            },
            mode: path_metadata.mode() & 0o7777,
            nlink: path_metadata.nlink(),
            size: path_metadata.len(),
            ciphertext_sha256: digest,
            classification,
        });
        Ok(())
    })?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    records.sort_by(|left, right| left.name.cmp(&right.name));
    revalidate_directory_path(
        physical_path,
        expected_owner,
        validate_ancestors,
        &directory,
        directory_identity,
        cancellation,
    )?;
    Ok(StrongInventory {
        physical_path: physical_path.to_path_buf(),
        expected_owner,
        validate_ancestors,
        directory,
        directory_identity,
        logical: NamespaceInventoryV1 {
            directory: NamespaceDirectoryMetadata {
                path: MODE1_NAMESPACE_PATH.to_owned(),
                uid: if validate_ancestors {
                    directory_metadata.uid()
                } else {
                    0
                },
                gid: if validate_ancestors {
                    directory_metadata.gid()
                } else {
                    0
                },
                mode: directory_metadata.mode() & 0o7777,
                nlink: directory_metadata.nlink(),
            },
            entries,
        },
        records,
    })
}

fn checked_namespace_total(current: u64, record_bytes: u64) -> Result<u64> {
    if record_bytes == 0 || record_bytes > MAX_NAMESPACE_CIPHERTEXT_BYTES {
        bail!("Mode 1 record exceeds the ciphertext byte bound");
    }
    let total = current
        .checked_add(record_bytes)
        .context("Mode 1 namespace byte total overflow")?;
    if total > MAX_NAMESPACE_TOTAL_BYTES {
        bail!("Mode 1 namespace exceeds the total byte bound");
    }
    Ok(total)
}

fn verify_authoritative_record(
    record: &mut AuthoritativeRecord,
    directory: &File,
    config: &HowyConfig,
    key: &Mode1KeyContext,
    recognizer: ModelDigest,
    budget: &PlaintextBudget,
    cancellation: &dyn CancellationSignal,
) -> Result<()> {
    ensure_not_cancelled(cancellation)?;
    revalidate_record_path(
        directory,
        &CString::new(record.name.clone())?,
        record.identity,
        cancellation,
    )?;
    let length = usize::try_from(record.identity.length).context("record length overflow")?;
    let bytes = Zeroizing::new(read_exact_descriptor(
        &record.file,
        length,
        Some(cancellation),
    )?);
    let header = inspect_howyenc1(&bytes)?;
    inspect_howyenc1_metadata(
        &bytes[..header.header_length()],
        bytes.len(),
        StorageMode::AeadCached,
        config.security.key_epoch,
        &record.username,
        recognizer,
        usize::try_from(config.security.max_embeddings_per_user)
            .context("configured record count does not fit this platform")?,
        usize::try_from(config.security.max_record_bytes)
            .context("configured record byte bound does not fit this platform")?,
    )?;
    let estimate = PlaintextAllocationEstimate::for_encrypted_header(&header)?;
    let permit = budget.reserve(estimate.cold_load_peak_bytes())?;
    ensure_not_cancelled(cancellation)?;
    let decoded = key.decrypt_record(
        &bytes,
        config.security.key_epoch,
        &record.username,
        recognizer,
    )?;
    ensure_not_cancelled(cancellation)?;
    drop(decoded);
    drop(permit);
    drop(bytes);
    if DescriptorIdentity::from_metadata(&record.file.metadata()?) != record.identity {
        bail!("Mode 1 record metadata changed during authentication");
    }
    revalidate_record_path(
        directory,
        &CString::new(record.name.clone())?,
        record.identity,
        cancellation,
    )?;
    Ok(())
}

fn open_absolute_directory_no_follow(
    path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    cancellation: &dyn CancellationSignal,
) -> Result<File> {
    ensure_not_cancelled(cancellation)?;
    validate_absolute_path(path)?;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    if validate_ancestors {
        validate_ancestor(&current.metadata()?, expected_owner)?;
    }
    for component in path.components().skip(1) {
        ensure_not_cancelled(cancellation)?;
        let Component::Normal(component) = component else {
            bail!("directory path contains an unsupported component");
        };
        let component = CString::new(component.as_bytes())?;
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error().into());
        }
        current = unsafe { File::from_raw_fd(descriptor) };
        if validate_ancestors {
            validate_ancestor(&current.metadata()?, expected_owner)?;
        }
    }
    Ok(current)
}

fn open_path_entry(directory: &File, name: &CStr) -> Result<File> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn open_regular_entry(directory: &File, name: &CStr) -> Result<File> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn namespace_file_type(metadata: &Metadata) -> NamespaceFileType {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        NamespaceFileType::Regular
    } else if file_type.is_dir() {
        NamespaceFileType::Directory
    } else if file_type.is_symlink() {
        NamespaceFileType::Symlink
    } else {
        NamespaceFileType::Other
    }
}

fn revalidate_record_path(
    directory: &File,
    name: &CStr,
    expected: DescriptorIdentity,
    cancellation: &dyn CancellationSignal,
) -> Result<()> {
    ensure_not_cancelled(cancellation)?;
    let reopened = open_regular_entry(directory, name)?;
    if DescriptorIdentity::from_metadata(&reopened.metadata()?) != expected {
        bail!("Mode 1 record path identity changed");
    }
    ensure_not_cancelled(cancellation)?;
    Ok(())
}

fn revalidate_directory(directory: &File, expected: DescriptorIdentity) -> Result<()> {
    if DescriptorIdentity::from_metadata(&directory.metadata()?) != expected {
        bail!("Mode 1 namespace directory metadata changed");
    }
    Ok(())
}

fn revalidate_directory_path(
    path: &Path,
    expected_owner: u32,
    validate_ancestors: bool,
    directory: &File,
    expected: DescriptorIdentity,
    cancellation: &dyn CancellationSignal,
) -> Result<()> {
    ensure_not_cancelled(cancellation)?;
    revalidate_directory(directory, expected)?;
    let reopened =
        open_absolute_directory_no_follow(path, expected_owner, validate_ancestors, cancellation)?;
    if DescriptorIdentity::from_metadata(&reopened.metadata()?) != expected {
        bail!("Mode 1 namespace path identity changed");
    }
    ensure_not_cancelled(cancellation)?;
    Ok(())
}

fn revalidate_inventory_directory(
    inventory: &StrongInventory,
    cancellation: &dyn CancellationSignal,
) -> Result<()> {
    revalidate_directory_path(
        &inventory.physical_path,
        inventory.expected_owner,
        inventory.validate_ancestors,
        &inventory.directory,
        inventory.directory_identity,
        cancellation,
    )
}

fn for_each_directory_name(
    directory: &File,
    maximum_entries: usize,
    mut visit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(descriptor) };
        return Err(error.into());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut count = 0usize;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        count = count
            .checked_add(1)
            .context("namespace entry count overflow")?;
        if count > maximum_entries {
            bail!("Mode 1 namespace exceeds the entry-count bound");
        }
        visit(name)?;
    }
    Ok(())
}

fn read_exact_descriptor(
    file: &File,
    length: usize,
    cancellation: Option<&dyn CancellationSignal>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| anyhow::anyhow!("bounded descriptor allocation failed"))?;
    bytes.resize(length, 0);
    let mut offset = 0usize;
    while offset < length {
        if cancellation.is_some_and(|signal| signal.is_cancelled()) {
            bail!("readiness deadline expired");
        }
        let amount = (length - offset).min(64 * 1024);
        match file.read_at(&mut bytes[offset..offset + amount], offset as u64) {
            Ok(0) => bail!("descriptor became shorter while it was read"),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut extra = [0u8; 1];
    if file.read_at(&mut extra, length as u64)? != 0 {
        bail!("descriptor became longer while it was read");
    }
    Ok(bytes)
}

fn stream_descriptor_sha256(
    file: &File,
    exact_length: u64,
    cancellation: Option<&dyn CancellationSignal>,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < exact_length {
        if cancellation.is_some_and(|signal| signal.is_cancelled()) {
            bail!("readiness deadline expired");
        }
        let remaining = usize::try_from((exact_length - offset).min(buffer.len() as u64))?;
        match file.read_at(&mut buffer[..remaining], offset) {
            Ok(0) => bail!("descriptor became shorter while hashing"),
            Ok(read) => {
                hasher.update(&buffer[..read]);
                offset = offset
                    .checked_add(read as u64)
                    .context("hash offset overflow")?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut extra = [0u8; 1];
    if file.read_at(&mut extra, exact_length)? != 0 {
        bail!("descriptor became longer while hashing");
    }
    Ok(hasher.finalize().into())
}

fn ensure_not_cancelled(cancellation: &dyn CancellationSignal) -> Result<()> {
    if cancellation.is_cancelled() {
        bail!("readiness deadline expired");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use howy_common::provisioning::KeyRecordCompatibility;
    use howy_common::storage::{
        EnrollmentEntry, EnrollmentId, EnrollmentRecord, NonceGenerator, encode_howyenc1,
    };
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NeverCancelled;
    impl CancellationSignal for NeverCancelled {
        fn is_cancelled(&self) -> bool {
            false
        }
    }

    struct AlwaysCancelled;
    impl CancellationSignal for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    struct TestRandom(u8);
    impl RandomSource for TestRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), String> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "howy-readiness-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn mode1_config() -> HowyConfig {
        let mut config = HowyConfig::default();
        config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
        config.security.key_epoch = 1;
        config
    }

    fn write_record(
        directory: &Path,
        username: &str,
        key: [u8; 32],
        model: ModelDigest,
        generation: u64,
    ) {
        let username = CanonicalUsername::new(username).unwrap();
        let entry = EnrollmentEntry::new(
            EnrollmentId::new([generation as u8; 16]).unwrap(),
            generation,
            "test",
            [0.0; 512],
        )
        .unwrap();
        let record =
            EnrollmentRecord::new(generation, model, username.clone(), vec![entry]).unwrap();
        let mut nonces = NonceGenerator::from_source(TestRandom(generation as u8));
        let bytes =
            encode_howyenc1(&record, StorageMode::AeadCached, 1, &key, &mut nonces).unwrap();
        let path = directory.join(format!("{}.hye", username.as_str()));
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn binding(model: ModelDigest) -> StrongRecognizerBinding {
        StrongRecognizerBinding {
            digest: model,
            identity: RecognizerIdentity {
                absolute_path: "/usr/share/howy/w600k_r50.onnx".to_owned(),
                sha256: Sha256Digest::from_array(model.into_bytes()),
            },
        }
    }

    #[test]
    fn empty_namespace_skips_recognizer_and_reports_not_applicable() {
        let root = temporary_directory("empty");
        let calls = AtomicUsize::new(0);
        let result = verify_mode1_namespace_at(
            &mode1_config(),
            &Mode1KeyContext::from_test_key([0x11; 32]),
            &root,
            unsafe { libc::geteuid() },
            false,
            &NeverCancelled,
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                bail!("must not resolve")
            },
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.record_count, 0);
        assert_eq!(result.verified_record_count, 0);
        assert_eq!(
            result.key_record_compatibility,
            KeyRecordCompatibility::EmptyNotApplicable
        );
        assert!(result.recognizer.is_none());
        assert_eq!(result.cache_population_count, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn all_records_are_verified_and_last_record_failure_fails_whole_result() {
        let root = temporary_directory("all-records");
        let model = ModelDigest::new([0x22; 32]);
        let key = [0x33; 32];
        write_record(&root, "alice", key, model, 1);
        write_record(&root, "bob", key, model, 2);
        let result = verify_mode1_namespace_at(
            &mode1_config(),
            &Mode1KeyContext::from_test_key(key),
            &root,
            unsafe { libc::geteuid() },
            false,
            &NeverCancelled,
            |_| Ok(binding(model)),
        )
        .unwrap();
        assert_eq!(result.record_count, 2);
        assert_eq!(result.verified_record_count, 2);
        assert_eq!(
            result.key_record_compatibility,
            KeyRecordCompatibility::Verified
        );

        let bob = root.join("bob.hye");
        let mut bytes = std::fs::read(&bob).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&bob, bytes).unwrap();
        assert!(
            verify_mode1_namespace_at(
                &mode1_config(),
                &Mode1KeyContext::from_test_key(key),
                &root,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
                |_| Ok(binding(model)),
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_key_model_epoch_and_filename_binding_fail() {
        let model = ModelDigest::new([0x44; 32]);
        for failure in ["key", "model", "epoch", "username"] {
            let root = temporary_directory(failure);
            let key = [0x55; 32];
            write_record(&root, "alice", key, model, 1);
            if failure == "username" {
                std::fs::rename(root.join("alice.hye"), root.join("bob.hye")).unwrap();
            }
            let mut config = mode1_config();
            if failure == "epoch" {
                config.security.key_epoch = 2;
            }
            let supplied_key = if failure == "key" { [0x99; 32] } else { key };
            let supplied_model = if failure == "model" {
                ModelDigest::new([0xaa; 32])
            } else {
                model
            };
            assert!(
                verify_mode1_namespace_at(
                    &config,
                    &Mode1KeyContext::from_test_key(supplied_key),
                    &root,
                    unsafe { libc::geteuid() },
                    false,
                    &NeverCancelled,
                    |_| Ok(binding(supplied_model)),
                )
                .is_err(),
                "{failure} mismatch was accepted"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn strict_entry_matrix_rejects_artifacts_links_directories_and_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let cases: Vec<(&str, Box<dyn Fn(&Path)>)> = vec![
            (
                "temp",
                Box::new(|root| {
                    std::fs::write(
                        root.join(".alice.hye.tmp.00112233445566778899aabbccddeeff"),
                        b"x",
                    )
                    .unwrap()
                }),
            ),
            (
                "staged",
                Box::new(|root| {
                    std::fs::write(
                        root.join(".alice.hye.staged.00112233445566778899aabbccddeeff"),
                        b"x",
                    )
                    .unwrap()
                }),
            ),
            (
                "clear",
                Box::new(|root| {
                    std::fs::write(
                        root.join(".alice.hye.clear.00112233445566778899aabbccddeeff"),
                        b"x",
                    )
                    .unwrap()
                }),
            ),
            (
                "rollback",
                Box::new(|root| {
                    std::fs::write(
                        root.join(".alice.hye.rollback.00112233445566778899aabbccddeeff"),
                        b"x",
                    )
                    .unwrap()
                }),
            ),
            (
                "unknown",
                Box::new(|root| std::fs::write(root.join("unknown.txt"), b"x").unwrap()),
            ),
            (
                "directory",
                Box::new(|root| std::fs::create_dir(root.join("alice.hye")).unwrap()),
            ),
            (
                "symlink",
                Box::new(|root| {
                    std::fs::write(root.join("target"), b"x").unwrap();
                    symlink(root.join("target"), root.join("alice.hye")).unwrap();
                }),
            ),
            (
                "hardlink",
                Box::new(|root| {
                    std::fs::write(root.join("alice.hye"), b"x").unwrap();
                    std::fs::hard_link(root.join("alice.hye"), root.join("other")).unwrap();
                }),
            ),
            (
                "nonutf8",
                Box::new(|root| {
                    std::fs::write(root.join(std::ffi::OsString::from_vec(vec![0xff])), b"x")
                        .unwrap()
                }),
            ),
        ];
        for (name, create) in cases {
            let root = temporary_directory(name);
            create(&root);
            assert!(
                verify_mode1_namespace_at(
                    &mode1_config(),
                    &Mode1KeyContext::from_test_key([1; 32]),
                    &root,
                    unsafe { libc::geteuid() },
                    false,
                    &NeverCancelled,
                    |_| bail!("rejected inventory must not resolve a model"),
                )
                .is_err(),
                "{name} entry was accepted"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn path_replacement_and_cancellation_fail_closed() {
        let root = temporary_directory("swap");
        let model = ModelDigest::new([7; 32]);
        let key = [8; 32];
        write_record(&root, "alice", key, model, 1);
        let inventory =
            inventory_mode1_namespace(&root, unsafe { libc::geteuid() }, false, &NeverCancelled)
                .unwrap();
        let original = root.join("alice.hye");
        let replacement = root.join("replacement");
        std::fs::copy(&original, &replacement).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &original).unwrap();
        assert!(
            revalidate_record_path(
                &inventory.directory,
                c"alice.hye",
                inventory.records[0].identity,
                &NeverCancelled,
            )
            .is_err()
        );
        drop(inventory);
        std::fs::remove_file(&original).unwrap();
        write_record(&root, "alice", key, model, 1);
        assert!(
            verify_mode1_namespace_at(
                &mode1_config(),
                &Mode1KeyContext::from_test_key(key),
                &root,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
                |_| {
                    let raced = root.join("raced");
                    std::fs::copy(&original, &raced).unwrap();
                    std::fs::set_permissions(&raced, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    std::fs::rename(&raced, &original).unwrap();
                    Ok(binding(model))
                },
            )
            .is_err()
        );
        assert!(
            verify_mode1_namespace_at(
                &mode1_config(),
                &Mode1KeyContext::from_test_key(key),
                &root,
                unsafe { libc::geteuid() },
                false,
                &AlwaysCancelled,
                |_| Ok(binding(model)),
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn candidate_config_is_exactly_hashed_and_rejects_swap_symlink_mode_and_link_count() {
        let root = temporary_directory("config");
        let config_path = root.join("candidate.toml");
        let bytes = toml::to_string(&mode1_config()).unwrap();
        std::fs::write(&config_path, &bytes).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let opened = open_config_with_policy(
            &config_path,
            unsafe { libc::geteuid() },
            false,
            &NeverCancelled,
        )
        .unwrap();
        assert_eq!(
            opened.raw_sha256(),
            &Sha256Digest::from_bytes(bytes.as_bytes())
        );
        let replacement = root.join("replacement.toml");
        std::fs::write(&replacement, &bytes).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(&replacement, &config_path).unwrap();
        assert!(opened.revalidate().is_err());
        drop(opened);

        std::fs::remove_file(&config_path).unwrap();
        let real_parent = root.join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let nested = real_parent.join("nested.toml");
        std::fs::write(&nested, &bytes).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o600)).unwrap();
        let linked_parent = root.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(
            open_config_with_policy(
                &linked_parent.join("nested.toml"),
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::remove_file(&linked_parent).unwrap();
        std::fs::remove_dir_all(&real_parent).unwrap();

        symlink(root.join("missing"), &config_path).unwrap();
        assert!(
            open_config_with_policy(
                &config_path,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::remove_file(&config_path).unwrap();
        std::fs::write(&config_path, &bytes).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(
            open_config_with_policy(
                &config_path,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            open_config_with_policy(
                &config_path,
                unsafe { libc::geteuid() }.saturating_add(1),
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::hard_link(&config_path, root.join("linked.toml")).unwrap();
        assert!(
            open_config_with_policy(
                &config_path,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::remove_file(root.join("linked.toml")).unwrap();
        let oversized = OpenOptions::new().write(true).open(&config_path).unwrap();
        oversized.set_len(MAX_CONFIG_BYTES as u64 + 1).unwrap();
        drop(oversized);
        assert!(
            open_config_with_policy(
                &config_path,
                unsafe { libc::geteuid() },
                false,
                &NeverCancelled,
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invocation_ids_are_strongly_generated_and_binary_identity_is_bounded() {
        let first = new_invocation_id().unwrap();
        let second = new_invocation_id().unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert!(first.bytes().all(|value| value.is_ascii_hexdigit()));
        let binary = open_daemon_binary_identity().unwrap();
        binary.revalidate().unwrap();
        assert_eq!(binary.output().version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn ciphertext_file_and_total_bounds_are_checked_before_allocation() {
        assert!(checked_namespace_total(0, 0).is_err());
        assert!(checked_namespace_total(0, MAX_NAMESPACE_CIPHERTEXT_BYTES + 1).is_err());
        assert!(
            checked_namespace_total(
                MAX_NAMESPACE_TOTAL_BYTES,
                MAX_NAMESPACE_CIPHERTEXT_BYTES.min(1),
            )
            .is_err()
        );
        assert_eq!(
            checked_namespace_total(7, MAX_NAMESPACE_CIPHERTEXT_BYTES).unwrap(),
            7 + MAX_NAMESPACE_CIPHERTEXT_BYTES
        );
    }
}
