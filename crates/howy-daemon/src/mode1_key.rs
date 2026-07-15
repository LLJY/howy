//! Mode-aware startup loading for the cached-AEAD storage key.
//!
//! systemd owns encrypted-credential discovery and decryption. The daemon only
//! accepts the resulting exact credential file below `CREDENTIALS_DIRECTORY`.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, compiler_fence};

use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
#[cfg(test)]
use howy_common::provisioning::MODE1_CREDENTIAL_PATH;
use howy_common::provisioning::{
    ConfiguredMode1CredentialSource, MAX_MODE1_CREDENTIAL_SOURCE_BYTES, Mode1CredentialSourcePolicy,
};
pub use howy_common::provisioning::{
    MODE1_CREDENTIAL_NAME, MODE1_CREDENTIAL_SOURCE_COMPANION_NAME,
};
use howy_common::storage::{
    AES_256_KEY_BYTES, Aes256Key, CancellationSignal, CanonicalUsername, EnrollmentRecord,
    ModelDigest, NonceGenerator, OsRandomSource, PromptOpaqueIdentity, RandomSource, StorageError,
    StorageMode, decode_howyenc1, encode_howyenc1,
};
use zeroize::Zeroize;

pub const MODE1_KEY_EPOCH: u64 = 1;

const CREDENTIAL_DIRECTORY_MODE: u32 = 0o500;
const CREDENTIAL_FILE_MODE: u32 = 0o400;

/// Redacted startup error for the Mode 1 credential trust boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupKeyError {
    ContractMismatch,
    UnsupportedMode,
    CredentialUnavailable,
    CredentialRejected,
    GuardedMemoryUnavailable,
    UnsupportedCredentialDelivery,
}

impl fmt::Display for StartupKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContractMismatch => "mode 1 storage-key contract mismatch",
            Self::UnsupportedMode => "configured embedding storage mode is unavailable",
            Self::CredentialUnavailable => "mode 1 storage credential is unavailable",
            Self::CredentialRejected => "mode 1 storage credential was rejected",
            Self::GuardedMemoryUnavailable => {
                "required mode 1 guarded memory could not be established"
            }
            Self::UnsupportedCredentialDelivery => {
                "mode 1 requires root-owned credential delivery without extended ACLs"
            }
        })
    }
}

impl std::error::Error for StartupKeyError {}

/// Mode-aware key state established before inference, camera, storage, or IPC.
pub enum StartupKeyContext {
    Mode0,
    Mode1(Mode1KeyContext),
}

impl StartupKeyContext {
    /// Non-sensitive descriptor identity used to keep model resolution away
    /// from the already-consumed storage credential.
    pub fn credential_source_identity(&self) -> Option<CredentialSourceIdentity> {
        match self {
            Self::Mode0 => None,
            Self::Mode1(context) => Some(context.credential_source),
        }
    }

    pub fn configured_credential_source(&self) -> Option<&ConfiguredMode1CredentialSource> {
        match self {
            Self::Mode0 => None,
            Self::Mode1(context) => Some(&context.configured_source),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorIdentity {
    device: u64,
    inode: u64,
}

/// Non-secret identity of the exact Mode 1 credential source.
///
/// This deliberately retains no descriptor or path to the key bytes. The
/// device/inode pairs and fixed credential name are sufficient to reject model
/// aliases before model bytes are read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialSourceIdentity {
    directory: DescriptorIdentity,
    credential: DescriptorIdentity,
    source_companion: Option<DescriptorIdentity>,
    credential_name: &'static str,
}

impl CredentialSourceIdentity {
    fn from_metadata(
        directory: CredentialMetadata,
        credential: CredentialMetadata,
        source_companion: CredentialMetadata,
    ) -> Self {
        Self {
            directory: DescriptorIdentity {
                device: directory.device,
                inode: directory.inode,
            },
            credential: DescriptorIdentity {
                device: credential.device,
                inode: credential.inode,
            },
            source_companion: Some(DescriptorIdentity {
                device: source_companion.device,
                inode: source_companion.inode,
            }),
            credential_name: MODE1_CREDENTIAL_NAME,
        }
    }

    pub(crate) fn credential_name(self) -> &'static str {
        self.credential_name
    }

    pub(crate) fn matches_credential(self, metadata: &Metadata) -> bool {
        (self.credential.device == metadata.dev() && self.credential.inode == metadata.ino())
            || self.source_companion.is_some_and(|source| {
                source.device == metadata.dev() && source.inode == metadata.ino()
            })
    }

    pub(crate) fn matches_directory(self, metadata: &Metadata) -> bool {
        self.directory.device == metadata.dev() && self.directory.inode == metadata.ino()
    }

    pub(crate) fn from_descriptor_metadata(
        directory: &Metadata,
        credential: &Metadata,
        source_companion: Option<&Metadata>,
    ) -> Self {
        Self {
            directory: DescriptorIdentity {
                device: directory.dev(),
                inode: directory.ino(),
            },
            credential: DescriptorIdentity {
                device: credential.dev(),
                inode: credential.ino(),
            },
            source_companion: source_companion.map(|metadata| DescriptorIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
            credential_name: MODE1_CREDENTIAL_NAME,
        }
    }
}

/// Guarded Mode 1 key plus its non-secret, redacted snapshot identity.
///
/// The type deliberately implements neither `Clone` nor formatting or
/// serialization traits. Key access is borrowed and crate-private so the next
/// storage-backend step can consume it without creating a daemon-lifetime copy.
pub struct Mode1KeyContext {
    allocation: Box<dyn GuardedAllocation>,
    #[allow(dead_code)] // transferred with the guard to the next backend step
    identity: PromptOpaqueIdentity,
    credential_source: CredentialSourceIdentity,
    configured_source: ConfiguredMode1CredentialSource,
}

impl Mode1KeyContext {
    /// Opaque process-instance identity for prompt snapshots. This value is
    /// generated independently and is neither a key digest nor key metadata.
    pub(crate) fn backend_identity(&self) -> PromptOpaqueIdentity {
        self.identity
    }

    /// Encrypt one frozen Mode 1 record while keeping guarded key bytes inside
    /// this ownership boundary. The process-lifetime nonce generator remains
    /// backend-owned and records the nonce before this method returns.
    pub(crate) fn encrypt_record<R: RandomSource>(
        &self,
        record: &EnrollmentRecord,
        key_epoch: u64,
        nonce_generator: &mut NonceGenerator<R>,
    ) -> Result<Vec<u8>, StorageError> {
        encode_howyenc1(
            record,
            StorageMode::AeadCached,
            key_epoch,
            self.allocation.key(),
            nonce_generator,
        )
    }

    /// Authenticate and decode one frozen Mode 1 record without exposing or
    /// copying guarded key bytes. Returned biometric fields own zeroizing
    /// allocations through [`EnrollmentRecord`].
    pub(crate) fn decrypt_record(
        &self,
        bytes: &[u8],
        key_epoch: u64,
        expected_username: &CanonicalUsername,
        expected_model: ModelDigest,
    ) -> Result<EnrollmentRecord, StorageError> {
        decode_howyenc1(
            bytes,
            self.allocation.key(),
            StorageMode::AeadCached,
            key_epoch,
            expected_username,
            expected_model,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_test_key(key: Aes256Key) -> Self {
        Self {
            allocation: Box::new(TestGuardedAllocation {
                key,
                disposed: false,
                drop_probe: None,
            }),
            identity: PromptOpaqueIdentity::new([0x7b; 32]),
            credential_source: CredentialSourceIdentity {
                directory: DescriptorIdentity {
                    device: 1,
                    inode: 2,
                },
                credential: DescriptorIdentity {
                    device: 1,
                    inode: 3,
                },
                source_companion: Some(DescriptorIdentity {
                    device: 1,
                    inode: 4,
                }),
                credential_name: MODE1_CREDENTIAL_NAME,
            },
            configured_source: ConfiguredMode1CredentialSource::production(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_key_with_drop_probe(
        key: Aes256Key,
        drop_probe: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        let mut context = Self::from_test_key(key);
        context.allocation = Box::new(TestGuardedAllocation {
            key,
            disposed: false,
            drop_probe: Some(drop_probe),
        });
        context
    }
}

impl Drop for Mode1KeyContext {
    fn drop(&mut self) {
        self.allocation.dispose();
    }
}

/// Load the mode-aware startup key context from the systemd service boundary.
pub fn load_startup_key_context(config: &HowyConfig) -> Result<StartupKeyContext, StartupKeyError> {
    let mut credentials = SystemCredentialIo;
    let mut memory = MmapGuardedMemoryFactory;
    load_startup_key_context_with(
        config,
        &mut credentials,
        &mut memory,
        Mode1CredentialSourcePolicy::Production,
        &NeverCancelled,
    )
}

pub fn load_readiness_key_context(
    config: &HowyConfig,
    cancellation: &dyn CancellationSignal,
) -> Result<StartupKeyContext, StartupKeyError> {
    let mut credentials = SystemCredentialIo;
    let mut memory = MmapGuardedMemoryFactory;
    load_startup_key_context_with(
        config,
        &mut credentials,
        &mut memory,
        Mode1CredentialSourcePolicy::ReadinessCandidate,
        cancellation,
    )
}

/// Probe only the descriptor identity of the optional Mode 1 credential for
/// model-alias exclusion. This is independent from key loading and never opens
/// the credential for reading.
pub fn probe_model_credential_guard() -> Result<Option<CredentialSourceIdentity>, StartupKeyError> {
    probe_model_credential_guard_from_directory(std::env::var_os("CREDENTIALS_DIRECTORY"))
}

fn probe_model_credential_guard_from_directory(
    directory_path: Option<OsString>,
) -> Result<Option<CredentialSourceIdentity>, StartupKeyError> {
    let Some(directory_path) = directory_path else {
        return Ok(None);
    };
    validate_absolute_directory_path(&directory_path)?;
    let directory = open_absolute_directory_no_follow(&directory_path)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    let name = CStr::from_bytes_with_nul(b"howy.storage.mode1.epoch1\0")
        .expect("static Mode 1 credential name");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(StartupKeyError::CredentialRejected)
        };
    }
    let credential = unsafe { File::from_raw_fd(descriptor) };
    let credential_metadata = credential
        .metadata()
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    if !credential_metadata.file_type().is_file() {
        return Err(StartupKeyError::CredentialRejected);
    }
    let source_name = CStr::from_bytes_with_nul(b"howy.storage.mode1.source\0")
        .expect("static Mode 1 source companion name");
    let source_descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            source_name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let source_companion = if source_descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            None
        } else {
            return Err(StartupKeyError::CredentialRejected);
        }
    } else {
        let source = unsafe { File::from_raw_fd(source_descriptor) };
        let metadata = source
            .metadata()
            .map_err(|_| StartupKeyError::CredentialRejected)?;
        if !metadata.file_type().is_file() {
            return Err(StartupKeyError::CredentialRejected);
        }
        Some(metadata)
    };
    let directory_metadata = directory
        .metadata()
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    Ok(Some(CredentialSourceIdentity::from_descriptor_metadata(
        &directory_metadata,
        &credential_metadata,
        source_companion.as_ref(),
    )))
}

fn load_startup_key_context_with<I, M>(
    config: &HowyConfig,
    credentials: &mut I,
    memory: &mut M,
    source_policy: Mode1CredentialSourcePolicy,
    cancellation: &dyn CancellationSignal,
) -> Result<StartupKeyContext, StartupKeyError>
where
    I: CredentialIo,
    M: GuardedMemoryFactory,
{
    ensure_not_cancelled(cancellation)?;
    match config.security.embedding_mode {
        EmbeddingSecurityMode::Plaintext => return Ok(StartupKeyContext::Mode0),
        EmbeddingSecurityMode::AeadEphemeral | EmbeddingSecurityMode::ReservedFuture => {
            return Err(StartupKeyError::UnsupportedMode);
        }
        EmbeddingSecurityMode::AeadCached => {}
    }

    if config.security.key_epoch != MODE1_KEY_EPOCH
        || config.security.cached.credential_name != MODE1_CREDENTIAL_NAME
    {
        return Err(StartupKeyError::ContractMismatch);
    }
    if !credentials.delivery_supported() {
        return Err(StartupKeyError::UnsupportedCredentialDelivery);
    }

    let directory_path = credentials
        .credential_directory()
        .map_err(|_| StartupKeyError::CredentialUnavailable)?
        .ok_or(StartupKeyError::CredentialUnavailable)?;
    ensure_not_cancelled(cancellation)?;
    validate_absolute_directory_path(&directory_path)?;

    let directory = credentials
        .open_directory_no_follow(&directory_path)
        .map_err(|_| StartupKeyError::CredentialUnavailable)?;
    let directory_metadata = credentials
        .directory_metadata(&directory)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    validate_directory_metadata(directory_metadata, credentials.expected_owner())?;
    if credentials
        .directory_has_acl(&directory)
        .map_err(|_| StartupKeyError::CredentialRejected)?
    {
        return Err(StartupKeyError::UnsupportedCredentialDelivery);
    }

    let source_name = CStr::from_bytes_with_nul(b"howy.storage.mode1.source\0")
        .expect("static Mode 1 source companion name is a C string");
    let mut source_companion = credentials
        .open_credential_no_follow(&directory, source_name)
        .map_err(|_| StartupKeyError::CredentialUnavailable)?;
    let source_metadata = credentials
        .credential_metadata(&source_companion)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    validate_source_metadata(source_metadata, credentials.expected_owner())?;
    if credentials
        .credential_has_acl(&source_companion)
        .map_err(|_| StartupKeyError::CredentialRejected)?
    {
        return Err(StartupKeyError::UnsupportedCredentialDelivery);
    }
    ensure_not_cancelled(cancellation)?;
    let configured_source = read_exact_source_companion(
        &mut source_companion,
        source_metadata.length,
        source_policy,
        cancellation,
    )?;
    let source_post = credentials
        .credential_metadata(&source_companion)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    if source_post != source_metadata {
        return Err(StartupKeyError::CredentialRejected);
    }

    let credential_name = CStr::from_bytes_with_nul(b"howy.storage.mode1.epoch1\0")
        .expect("static Mode 1 credential name is a C string");
    let mut credential = credentials
        .open_credential_no_follow(&directory, credential_name)
        .map_err(|_| StartupKeyError::CredentialUnavailable)?;
    let credential_metadata = credentials
        .credential_metadata(&credential)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    validate_credential_metadata(credential_metadata, credentials.expected_owner())?;
    if credentials
        .credential_has_acl(&credential)
        .map_err(|_| StartupKeyError::CredentialRejected)?
    {
        return Err(StartupKeyError::UnsupportedCredentialDelivery);
    }
    ensure_not_cancelled(cancellation)?;

    let mut allocation = memory
        .allocate()
        .map_err(|_| StartupKeyError::GuardedMemoryUnavailable)?;
    allocation
        .lock()
        .map_err(|_| StartupKeyError::GuardedMemoryUnavailable)?;
    allocation
        .dont_dump()
        .map_err(|_| StartupKeyError::GuardedMemoryUnavailable)?;
    // Defense in depth only: child isolation is enforced independently by the
    // centralized daemon spawn boundary.
    allocation
        .dont_fork()
        .map_err(|_| StartupKeyError::GuardedMemoryUnavailable)?;

    read_exact_binary_key(&mut credential, allocation.key_mut(), cancellation)?;
    let credential_post = credentials
        .credential_metadata(&credential)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    if credential_post != credential_metadata {
        return Err(StartupKeyError::CredentialRejected);
    }
    ensure_not_cancelled(cancellation)?;
    let mut identity = [0_u8; 32];
    OsRandomSource
        .fill_bytes(&mut identity)
        .map_err(|_| StartupKeyError::GuardedMemoryUnavailable)?;

    Ok(StartupKeyContext::Mode1(Mode1KeyContext {
        allocation,
        identity: PromptOpaqueIdentity::new(identity),
        credential_source: CredentialSourceIdentity::from_metadata(
            directory_metadata,
            credential_metadata,
            source_metadata,
        ),
        configured_source,
    }))
}

struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

fn ensure_not_cancelled(cancellation: &dyn CancellationSignal) -> Result<(), StartupKeyError> {
    if cancellation.is_cancelled() {
        Err(StartupKeyError::CredentialUnavailable)
    } else {
        Ok(())
    }
}

fn read_exact_source_companion(
    source: &mut impl Read,
    length: u64,
    policy: Mode1CredentialSourcePolicy,
    cancellation: &dyn CancellationSignal,
) -> Result<ConfiguredMode1CredentialSource, StartupKeyError> {
    let length = usize::try_from(length).map_err(|_| StartupKeyError::CredentialRejected)?;
    if length == 0 || length > MAX_MODE1_CREDENTIAL_SOURCE_BYTES {
        return Err(StartupKeyError::CredentialRejected);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| StartupKeyError::CredentialRejected)?;
    bytes.resize(length, 0);
    let mut offset = 0;
    while offset < bytes.len() {
        ensure_not_cancelled(cancellation)?;
        match source.read(&mut bytes[offset..]) {
            Ok(0) => return Err(StartupKeyError::CredentialRejected),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StartupKeyError::CredentialRejected),
        }
    }
    let mut extra = [0u8; 1];
    let exact = loop {
        ensure_not_cancelled(cancellation)?;
        match source.read(&mut extra) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Ok(0) => break true,
            Ok(_) | Err(_) => break false,
        }
    };
    if !exact {
        return Err(StartupKeyError::CredentialRejected);
    }
    ensure_not_cancelled(cancellation)?;
    ConfiguredMode1CredentialSource::parse(&bytes, policy)
        .map_err(|_| StartupKeyError::CredentialRejected)
}

fn read_exact_binary_key(
    credential: &mut impl Read,
    destination: &mut Aes256Key,
    cancellation: &dyn CancellationSignal,
) -> Result<(), StartupKeyError> {
    let mut filled = 0;
    while filled < destination.len() {
        ensure_not_cancelled(cancellation)?;
        match credential.read(&mut destination[filled..]) {
            Ok(0) => return Err(StartupKeyError::CredentialRejected),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(StartupKeyError::CredentialRejected),
        }
    }

    // A one-byte zeroizing probe rejects a raced or synthetic extra byte
    // without creating an ordinary key-sized temporary allocation.
    let mut extra = [0_u8; 1];
    let extra_result = loop {
        ensure_not_cancelled(cancellation)?;
        match credential.read(&mut extra) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    let exact_eof = matches!(extra_result, Ok(0));
    extra.zeroize();
    if !exact_eof {
        return Err(StartupKeyError::CredentialRejected);
    }
    Ok(())
}

fn validate_absolute_directory_path(path: &OsStr) -> Result<(), StartupKeyError> {
    let bytes = path.as_bytes();
    if bytes.len() < 2
        || bytes[0] != b'/'
        || bytes[1] == b'/'
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(StartupKeyError::CredentialRejected);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetadataKind {
    Directory,
    Regular,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialMetadata {
    kind: MetadataKind,
    owner: u32,
    mode: u32,
    links: u64,
    length: u64,
    device: u64,
    inode: u64,
}

fn validate_directory_metadata(
    metadata: CredentialMetadata,
    expected_owner: u32,
) -> Result<(), StartupKeyError> {
    if metadata.kind != MetadataKind::Directory
        || metadata.owner != expected_owner
        || metadata.mode != CREDENTIAL_DIRECTORY_MODE
    {
        return Err(StartupKeyError::CredentialRejected);
    }
    Ok(())
}

fn validate_credential_metadata(
    metadata: CredentialMetadata,
    expected_owner: u32,
) -> Result<(), StartupKeyError> {
    if metadata.kind != MetadataKind::Regular
        || metadata.owner != expected_owner
        || metadata.mode != CREDENTIAL_FILE_MODE
        || metadata.links != 1
        || metadata.length != AES_256_KEY_BYTES as u64
    {
        return Err(StartupKeyError::CredentialRejected);
    }
    Ok(())
}

fn validate_source_metadata(
    metadata: CredentialMetadata,
    expected_owner: u32,
) -> Result<(), StartupKeyError> {
    if metadata.kind != MetadataKind::Regular
        || metadata.owner != expected_owner
        || metadata.mode != CREDENTIAL_FILE_MODE
        || metadata.links != 1
        || metadata.length == 0
        || metadata.length > MAX_MODE1_CREDENTIAL_SOURCE_BYTES as u64
    {
        return Err(StartupKeyError::CredentialRejected);
    }
    Ok(())
}

trait CredentialIo {
    type Directory;
    type Credential: Read;

    fn credential_directory(&mut self) -> Result<Option<OsString>, ()>;
    fn delivery_supported(&self) -> bool;
    fn expected_owner(&self) -> u32;
    fn open_directory_no_follow(&mut self, path: &OsStr) -> Result<Self::Directory, ()>;
    fn directory_metadata(&mut self, directory: &Self::Directory)
    -> Result<CredentialMetadata, ()>;
    fn open_credential_no_follow(
        &mut self,
        directory: &Self::Directory,
        name: &CStr,
    ) -> Result<Self::Credential, ()>;
    fn credential_metadata(
        &mut self,
        credential: &Self::Credential,
    ) -> Result<CredentialMetadata, ()>;
    fn directory_has_acl(&mut self, directory: &Self::Directory) -> Result<bool, ()>;
    fn credential_has_acl(&mut self, credential: &Self::Credential) -> Result<bool, ()>;
}

struct SystemCredentialIo;

impl CredentialIo for SystemCredentialIo {
    type Directory = File;
    type Credential = File;

    fn credential_directory(&mut self) -> Result<Option<OsString>, ()> {
        Ok(std::env::var_os("CREDENTIALS_DIRECTORY"))
    }

    fn delivery_supported(&self) -> bool {
        // The service unit is root-run. Alternate service users and ACL-based
        // credential delivery require a separately reviewed metadata policy.
        (unsafe { libc::geteuid() }) == 0
    }

    fn expected_owner(&self) -> u32 {
        0
    }

    fn open_directory_no_follow(&mut self, path: &OsStr) -> Result<Self::Directory, ()> {
        open_absolute_directory_no_follow(path).map_err(|_| ())
    }

    fn directory_metadata(
        &mut self,
        directory: &Self::Directory,
    ) -> Result<CredentialMetadata, ()> {
        directory.metadata().map(metadata_from_std).map_err(|_| ())
    }

    fn open_credential_no_follow(
        &mut self,
        directory: &Self::Directory,
        name: &CStr,
    ) -> Result<Self::Credential, ()> {
        // SAFETY: directory is a live descriptor, name is NUL-terminated, and
        // O_NOFOLLOW/O_CLOEXEC make the exact relative open non-following and
        // non-inheritable across exec.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return Err(());
        }
        // SAFETY: openat returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn credential_metadata(
        &mut self,
        credential: &Self::Credential,
    ) -> Result<CredentialMetadata, ()> {
        credential.metadata().map(metadata_from_std).map_err(|_| ())
    }

    fn directory_has_acl(&mut self, directory: &Self::Directory) -> Result<bool, ()> {
        descriptor_has_acl(directory).map_err(|_| ())
    }

    fn credential_has_acl(&mut self, credential: &Self::Credential) -> Result<bool, ()> {
        descriptor_has_acl(credential).map_err(|_| ())
    }
}

fn descriptor_has_acl(file: &File) -> io::Result<bool> {
    let name = CStr::from_bytes_with_nul(b"system.posix_acl_access\0").expect("static ACL name");
    let result =
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if result >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(code) if code == libc::ENODATA || code == libc::ENOTSUP)
    {
        Ok(false)
    } else {
        Err(error)
    }
}

fn open_absolute_directory_no_follow(path: &OsStr) -> io::Result<File> {
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;

    for component in path.as_bytes()[1..].split(|byte| *byte == b'/') {
        let component =
            CString::new(component).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: current is a live directory descriptor and component is a
        // validated single NUL-terminated path component.
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        current = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(current)
}

fn metadata_from_std(metadata: Metadata) -> CredentialMetadata {
    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        MetadataKind::Directory
    } else if file_type.is_file() {
        MetadataKind::Regular
    } else if file_type.is_symlink() {
        MetadataKind::Symlink
    } else {
        MetadataKind::Other
    };
    CredentialMetadata {
        kind,
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
        length: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

trait GuardedMemoryFactory {
    fn allocate(&mut self) -> Result<Box<dyn GuardedAllocation>, ()>;
}

trait GuardedAllocation: Send + Sync {
    fn lock(&mut self) -> Result<(), ()>;
    fn dont_dump(&mut self) -> Result<(), ()>;
    fn dont_fork(&mut self) -> Result<(), ()>;
    fn key(&self) -> &Aes256Key;
    fn key_mut(&mut self) -> &mut Aes256Key;
    fn dispose(&mut self);
}

#[cfg(test)]
struct TestGuardedAllocation {
    key: Aes256Key,
    disposed: bool,
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(test)]
impl GuardedAllocation for TestGuardedAllocation {
    fn lock(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn dont_dump(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn dont_fork(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn key(&self) -> &Aes256Key {
        &self.key
    }

    fn key_mut(&mut self) -> &mut Aes256Key {
        &mut self.key
    }

    fn dispose(&mut self) {
        if !self.disposed {
            self.key.zeroize();
            self.disposed = true;
            if let Some(probe) = &self.drop_probe {
                probe.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

struct MmapGuardedMemoryFactory;

impl GuardedMemoryFactory for MmapGuardedMemoryFactory {
    fn allocate(&mut self) -> Result<Box<dyn GuardedAllocation>, ()> {
        MmapGuardedAllocation::new()
            .map(|allocation| Box::new(allocation) as Box<dyn GuardedAllocation>)
            .map_err(|_| ())
    }
}

#[cfg(test)]
const DISPOSAL_OBSERVED_ZEROIZED: u8 = 1 << 0;
#[cfg(test)]
const DISPOSAL_OBSERVED_MUNLOCK: u8 = 1 << 1;
#[cfg(test)]
const DISPOSAL_OBSERVED_MUNMAP: u8 = 1 << 2;
#[cfg(test)]
const DISPOSAL_OBSERVED_UNMAPPED: u8 = 1 << 3;
#[cfg(test)]
static DISPOSAL_OBSERVER_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static DISPOSAL_OBSERVER_STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
fn observe_zeroized_key_page(key_page: NonNull<u8>) {
    if !DISPOSAL_OBSERVER_ENABLED.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    // SAFETY: this observer runs synchronously inside dispose while the key
    // page is still mapped and before munlock. It only reads the real key.
    let key = unsafe { &*key_page.as_ptr().cast::<Aes256Key>() };
    if key.iter().all(|byte| *byte == 0) {
        DISPOSAL_OBSERVER_STATE.fetch_or(
            DISPOSAL_OBSERVED_ZEROIZED,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

#[cfg(test)]
fn observe_munlock(result: libc::c_int) {
    if DISPOSAL_OBSERVER_ENABLED.load(std::sync::atomic::Ordering::SeqCst) && result == 0 {
        DISPOSAL_OBSERVER_STATE.fetch_or(
            DISPOSAL_OBSERVED_MUNLOCK,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

#[cfg(test)]
fn observe_munmap(key_page: NonNull<u8>, page_length: usize, result: libc::c_int) {
    if !DISPOSAL_OBSERVER_ENABLED.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    if result == 0 {
        DISPOSAL_OBSERVER_STATE.fetch_or(
            DISPOSAL_OBSERVED_MUNMAP,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    let mut vector = 0_u8;
    // SAFETY: mincore is deliberately called on the just-unmapped page to
    // observe ENOMEM. It does not dereference the supplied address.
    let observed = unsafe { libc::mincore(key_page.as_ptr().cast(), page_length, &mut vector) };
    let errno = if observed == -1 {
        // SAFETY: libc exposes this thread's errno location on the Linux target.
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    if observed == -1 && errno == libc::ENOMEM {
        DISPOSAL_OBSERVER_STATE.fetch_or(
            DISPOSAL_OBSERVED_UNMAPPED,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

struct MmapGuardedAllocation {
    mapping: Option<NonNull<u8>>,
    key_page: NonNull<u8>,
    page_length: usize,
    mapping_length: usize,
    locked: bool,
}

// The allocation has unique mutable access while loading and immutable access
// afterward. Its stable mmap address remains valid until synchronized Drop.
unsafe impl Send for MmapGuardedAllocation {}
unsafe impl Sync for MmapGuardedAllocation {}

impl MmapGuardedAllocation {
    fn new() -> io::Result<Self> {
        // SAFETY: sysconf has no pointer arguments.
        let page_length = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_length <= 0 {
            return Err(io::Error::last_os_error());
        }
        let page_length = usize::try_from(page_length)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let mapping_length = page_length
            .checked_mul(3)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        // SAFETY: requesting a fresh anonymous private mapping with no backing
        // descriptor. It is initially inaccessible so adjacent pages guard the
        // one data page.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let mapping = NonNull::new(raw.cast::<u8>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOMEM))?;
        // SAFETY: the second page lies within the three-page mapping.
        let key_page = unsafe { NonNull::new_unchecked(mapping.as_ptr().add(page_length)) };
        // SAFETY: key_page is page-aligned and spans exactly the middle page.
        if unsafe {
            libc::mprotect(
                key_page.as_ptr().cast(),
                page_length,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            // SAFETY: mapping and length are the exact successful mmap range.
            unsafe { libc::munmap(mapping.as_ptr().cast(), mapping_length) };
            return Err(error);
        }
        Ok(Self {
            mapping: Some(mapping),
            key_page,
            page_length,
            mapping_length,
            locked: false,
        })
    }

    fn advise(&mut self, advice: libc::c_int) -> Result<(), ()> {
        let Some(mapping) = self.mapping else {
            return Err(());
        };
        // SAFETY: mapping and mapping_length identify the live complete mmap.
        if unsafe { libc::madvise(mapping.as_ptr().cast(), self.mapping_length, advice) } == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl GuardedAllocation for MmapGuardedAllocation {
    fn lock(&mut self) -> Result<(), ()> {
        // SAFETY: key_page and page_length identify the live writable data page.
        if unsafe { libc::mlock(self.key_page.as_ptr().cast(), self.page_length) } == 0 {
            self.locked = true;
            Ok(())
        } else {
            Err(())
        }
    }

    fn dont_dump(&mut self) -> Result<(), ()> {
        self.advise(libc::MADV_DONTDUMP)
    }

    fn dont_fork(&mut self) -> Result<(), ()> {
        self.advise(libc::MADV_DONTFORK)
    }

    fn key(&self) -> &Aes256Key {
        // SAFETY: shared access is confined to this live allocation. The data
        // page remains mapped and immutable after startup loading.
        unsafe { &*self.key_page.as_ptr().cast::<Aes256Key>() }
    }

    fn key_mut(&mut self) -> &mut Aes256Key {
        // SAFETY: unique &mut self provides unique access to the live key bytes.
        unsafe { &mut *self.key_page.as_ptr().cast::<Aes256Key>() }
    }

    fn dispose(&mut self) {
        let Some(mapping) = self.mapping.take() else {
            return;
        };
        // Zeroization always precedes unlock and unmap. The compiler fence
        // prevents cleanup operations from being reordered ahead of the wipe.
        self.key_mut().zeroize();
        compiler_fence(Ordering::SeqCst);
        #[cfg(test)]
        observe_zeroized_key_page(self.key_page);
        if self.locked {
            // SAFETY: key_page and page_length identify the locked data page.
            let _result = unsafe { libc::munlock(self.key_page.as_ptr().cast(), self.page_length) };
            #[cfg(test)]
            observe_munlock(_result);
            self.locked = false;
        }
        // SAFETY: mapping and mapping_length identify the exact mmap range.
        let _result = unsafe { libc::munmap(mapping.as_ptr().cast(), self.mapping_length) };
        #[cfg(test)]
        observe_munmap(self.key_page, self.page_length, _result);
    }
}

impl Drop for MmapGuardedAllocation {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::{Arc, Mutex};

    const OWNER: u32 = 0;
    static REAL_MEMORY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn mode_config(mode: EmbeddingSecurityMode) -> HowyConfig {
        let mut config = HowyConfig::default();
        config.security.embedding_mode = mode;
        config
    }

    fn valid_directory_metadata() -> CredentialMetadata {
        CredentialMetadata {
            kind: MetadataKind::Directory,
            owner: OWNER,
            mode: CREDENTIAL_DIRECTORY_MODE,
            links: 2,
            length: 0,
            device: 10,
            inode: 20,
        }
    }

    fn valid_file_metadata() -> CredentialMetadata {
        CredentialMetadata {
            kind: MetadataKind::Regular,
            owner: OWNER,
            mode: CREDENTIAL_FILE_MODE,
            links: 1,
            length: AES_256_KEY_BYTES as u64,
            device: 10,
            inode: 21,
        }
    }

    fn valid_source_metadata() -> CredentialMetadata {
        CredentialMetadata {
            length: MODE1_CREDENTIAL_PATH.len() as u64,
            inode: 22,
            ..valid_file_metadata()
        }
    }

    #[derive(Clone, Copy)]
    enum FakeCredentialKind {
        Key,
        Source,
    }

    #[derive(Default)]
    struct FakeCredentialIo {
        calls: Vec<&'static str>,
        directory: Option<OsString>,
        directory_open_fails: bool,
        credential_open_fails: bool,
        source_open_fails: bool,
        directory_metadata: Option<CredentialMetadata>,
        credential_metadata: Option<CredentialMetadata>,
        source_metadata: Option<CredentialMetadata>,
        bytes: Vec<u8>,
        source_bytes: Vec<u8>,
        read_chunks: VecDeque<usize>,
        read_error_after: Option<usize>,
        interrupt_at: VecDeque<usize>,
        directory_acl: bool,
        credential_acl: bool,
    }

    impl FakeCredentialIo {
        fn valid(bytes: Vec<u8>) -> Self {
            Self {
                directory: Some(OsString::from("/run/credentials/howy.service")),
                directory_metadata: Some(valid_directory_metadata()),
                credential_metadata: Some(valid_file_metadata()),
                source_metadata: Some(valid_source_metadata()),
                bytes,
                source_bytes: MODE1_CREDENTIAL_PATH.as_bytes().to_vec(),
                ..Self::default()
            }
        }
    }

    struct FakeReader {
        kind: FakeCredentialKind,
        bytes: Vec<u8>,
        offset: usize,
        chunks: VecDeque<usize>,
        error_after: Option<usize>,
        interrupt_at: VecDeque<usize>,
    }

    impl Read for FakeReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_at.front() == Some(&self.offset) {
                self.interrupt_at.pop_front();
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.error_after == Some(self.offset) {
                self.error_after = None;
                return Err(io::Error::other("injected read failure"));
            }
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let chunk = self.chunks.pop_front().unwrap_or(buffer.len());
            let count = chunk
                .min(buffer.len())
                .min(self.bytes.len().saturating_sub(self.offset));
            buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    impl CredentialIo for FakeCredentialIo {
        type Directory = ();
        type Credential = FakeReader;

        fn credential_directory(&mut self) -> Result<Option<OsString>, ()> {
            self.calls.push("env");
            Ok(self.directory.clone())
        }

        fn delivery_supported(&self) -> bool {
            true
        }

        fn expected_owner(&self) -> u32 {
            OWNER
        }

        fn open_directory_no_follow(&mut self, _path: &OsStr) -> Result<Self::Directory, ()> {
            self.calls.push("open_dir");
            (!self.directory_open_fails).then_some(()).ok_or(())
        }

        fn directory_metadata(
            &mut self,
            _directory: &Self::Directory,
        ) -> Result<CredentialMetadata, ()> {
            self.calls.push("dir_metadata");
            self.directory_metadata.ok_or(())
        }

        fn open_credential_no_follow(
            &mut self,
            _directory: &Self::Directory,
            name: &CStr,
        ) -> Result<Self::Credential, ()> {
            self.calls.push("open_credential");
            let key = name.to_bytes() == MODE1_CREDENTIAL_NAME.as_bytes();
            let source = name.to_bytes() == MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.as_bytes();
            if (!key && !source)
                || (key && self.credential_open_fails)
                || (source && self.source_open_fails)
            {
                return Err(());
            }
            Ok(FakeReader {
                kind: if key {
                    FakeCredentialKind::Key
                } else {
                    FakeCredentialKind::Source
                },
                bytes: if key {
                    self.bytes.clone()
                } else {
                    self.source_bytes.clone()
                },
                offset: 0,
                chunks: if key {
                    self.read_chunks.clone()
                } else {
                    VecDeque::new()
                },
                error_after: key.then_some(self.read_error_after).flatten(),
                interrupt_at: if key {
                    self.interrupt_at.clone()
                } else {
                    VecDeque::new()
                },
            })
        }

        fn credential_metadata(
            &mut self,
            credential: &Self::Credential,
        ) -> Result<CredentialMetadata, ()> {
            self.calls.push("credential_metadata");
            match credential.kind {
                FakeCredentialKind::Key => self.credential_metadata.ok_or(()),
                FakeCredentialKind::Source => self.source_metadata.ok_or(()),
            }
        }

        fn directory_has_acl(&mut self, _directory: &Self::Directory) -> Result<bool, ()> {
            Ok(self.directory_acl)
        }

        fn credential_has_acl(&mut self, credential: &Self::Credential) -> Result<bool, ()> {
            Ok(match credential.kind {
                FakeCredentialKind::Key => self.credential_acl,
                FakeCredentialKind::Source => false,
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MemoryFailure {
        Allocate,
        Lock,
        DontDump,
        DontFork,
    }

    struct FakeMemoryFactory {
        events: Arc<Mutex<Vec<&'static str>>>,
        failure: Option<MemoryFailure>,
    }

    impl FakeMemoryFactory {
        fn succeeding() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                failure: None,
            }
        }
    }

    impl GuardedMemoryFactory for FakeMemoryFactory {
        fn allocate(&mut self) -> Result<Box<dyn GuardedAllocation>, ()> {
            self.events.lock().unwrap().push("allocate");
            if self.failure == Some(MemoryFailure::Allocate) {
                return Err(());
            }
            Ok(Box::new(FakeAllocation {
                bytes: [0; AES_256_KEY_BYTES],
                events: Arc::clone(&self.events),
                failure: self.failure,
                locked: false,
                disposed: false,
            }))
        }
    }

    struct FakeAllocation {
        bytes: Aes256Key,
        events: Arc<Mutex<Vec<&'static str>>>,
        failure: Option<MemoryFailure>,
        locked: bool,
        disposed: bool,
    }

    impl GuardedAllocation for FakeAllocation {
        fn lock(&mut self) -> Result<(), ()> {
            self.events.lock().unwrap().push("mlock");
            if self.failure == Some(MemoryFailure::Lock) {
                return Err(());
            }
            self.locked = true;
            Ok(())
        }

        fn dont_dump(&mut self) -> Result<(), ()> {
            self.events.lock().unwrap().push("dontdump");
            (self.failure != Some(MemoryFailure::DontDump))
                .then_some(())
                .ok_or(())
        }

        fn dont_fork(&mut self) -> Result<(), ()> {
            self.events.lock().unwrap().push("dontfork");
            (self.failure != Some(MemoryFailure::DontFork))
                .then_some(())
                .ok_or(())
        }

        fn key(&self) -> &Aes256Key {
            &self.bytes
        }

        fn key_mut(&mut self) -> &mut Aes256Key {
            &mut self.bytes
        }

        fn dispose(&mut self) {
            if self.disposed {
                return;
            }
            self.bytes.zeroize();
            let mut events = self.events.lock().unwrap();
            events.push("wipe");
            if self.locked {
                events.push("unlock");
                self.locked = false;
            }
            events.push("free");
            self.disposed = true;
        }
    }

    impl Drop for FakeAllocation {
        fn drop(&mut self) {
            self.dispose();
        }
    }

    fn load_fake(
        config: &HowyConfig,
        io: &mut FakeCredentialIo,
        memory: &mut FakeMemoryFactory,
    ) -> Result<StartupKeyContext, StartupKeyError> {
        load_startup_key_context_with(
            config,
            io,
            memory,
            Mode1CredentialSourcePolicy::Production,
            &NeverCancelled,
        )
    }

    #[test]
    fn mode0_performs_no_credential_or_guarded_memory_calls() {
        let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        let mut memory = FakeMemoryFactory::succeeding();
        let context = load_fake(
            &mode_config(EmbeddingSecurityMode::Plaintext),
            &mut io,
            &mut memory,
        )
        .unwrap();
        assert!(matches!(context, StartupKeyContext::Mode0));
        assert!(io.calls.is_empty());
        assert!(memory.events.lock().unwrap().is_empty());
    }

    #[test]
    fn source_companion_is_required_exact_and_policy_specific_before_key_allocation() {
        let config = mode_config(EmbeddingSecurityMode::AeadCached);
        let candidate = "/etc/credstore.encrypted/.howy.storage.mode1.epoch1.candidate";
        let mut candidate_io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        candidate_io.source_bytes = candidate.as_bytes().to_vec();
        candidate_io.source_metadata.as_mut().unwrap().length = candidate.len() as u64;
        let mut memory = FakeMemoryFactory::succeeding();
        let context = load_startup_key_context_with(
            &config,
            &mut candidate_io,
            &mut memory,
            Mode1CredentialSourcePolicy::ReadinessCandidate,
            &NeverCancelled,
        )
        .unwrap();
        assert_eq!(
            context.configured_credential_source().unwrap().as_str(),
            candidate
        );

        let mut production_io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        production_io.source_bytes = candidate.as_bytes().to_vec();
        production_io.source_metadata.as_mut().unwrap().length = candidate.len() as u64;
        let mut memory = FakeMemoryFactory::succeeding();
        assert_eq!(
            load_startup_key_context_with(
                &config,
                &mut production_io,
                &mut memory,
                Mode1CredentialSourcePolicy::Production,
                &NeverCancelled,
            )
            .err(),
            Some(StartupKeyError::CredentialRejected)
        );
        assert!(memory.events.lock().unwrap().is_empty());

        let mut symlink = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        symlink.source_metadata.as_mut().unwrap().kind = MetadataKind::Symlink;
        let mut memory = FakeMemoryFactory::succeeding();
        assert_eq!(
            load_fake(&config, &mut symlink, &mut memory).err(),
            Some(StartupKeyError::CredentialRejected)
        );
        assert!(memory.events.lock().unwrap().is_empty());
    }

    #[test]
    fn source_companion_metadata_length_and_ascii_fail_before_key_allocation() {
        let config = mode_config(EmbeddingSecurityMode::AeadCached);
        for mutate in [
            |metadata: &mut CredentialMetadata| metadata.owner = 1,
            |metadata: &mut CredentialMetadata| metadata.mode = 0o600,
            |metadata: &mut CredentialMetadata| metadata.links = 2,
            |metadata: &mut CredentialMetadata| metadata.length = 0,
            |metadata: &mut CredentialMetadata| {
                metadata.length = MAX_MODE1_CREDENTIAL_SOURCE_BYTES as u64 + 1
            },
        ] {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            mutate(io.source_metadata.as_mut().unwrap());
            let mut memory = FakeMemoryFactory::succeeding();
            assert_eq!(
                load_fake(&config, &mut io, &mut memory).err(),
                Some(StartupKeyError::CredentialRejected)
            );
            assert!(memory.events.lock().unwrap().is_empty());
        }
        for bytes in [
            b"relative".to_vec(),
            b"/etc/credstore.encrypted/name\n".to_vec(),
            vec![0xff],
        ] {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            io.source_metadata.as_mut().unwrap().length = bytes.len() as u64;
            io.source_bytes = bytes;
            let mut memory = FakeMemoryFactory::succeeding();
            assert_eq!(
                load_fake(&config, &mut io, &mut memory).err(),
                Some(StartupKeyError::CredentialRejected)
            );
            assert!(memory.events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn independent_model_guard_probes_metadata_without_key_read_access() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "howy-mode1-model-guard-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        assert_eq!(
            probe_model_credential_guard_from_directory(Some(root.as_os_str().to_owned())).unwrap(),
            None
        );
        let credential_path = root.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&credential_path, [0x7b; AES_256_KEY_BYTES]).unwrap();
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let guard = probe_model_credential_guard_from_directory(Some(root.as_os_str().to_owned()))
            .unwrap()
            .expect("O_PATH metadata probe succeeds without read permission");
        assert!(guard.matches_credential(&credential_path.metadata().unwrap()));

        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&credential_path).unwrap();
        let target = root.join("target");
        std::fs::write(&target, [0x55; AES_256_KEY_BYTES]).unwrap();
        std::os::unix::fs::symlink(&target, &credential_path).unwrap();
        assert_eq!(
            probe_model_credential_guard_from_directory(Some(root.as_os_str().to_owned())).err(),
            Some(StartupKeyError::CredentialRejected)
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disabled_mode1_still_requires_and_loads_the_exact_key() {
        let mut config = mode_config(EmbeddingSecurityMode::AeadCached);
        config.core.disabled = true;
        let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        let mut memory = FakeMemoryFactory::succeeding();
        let context = load_fake(&config, &mut io, &mut memory).unwrap();
        assert!(matches!(context, StartupKeyContext::Mode1(_)));
        assert_eq!(io.calls.first(), Some(&"env"));
    }

    #[test]
    fn valid_key_is_locked_nondumpable_nonforking_and_wiped_before_unlock() {
        let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        let mut memory = FakeMemoryFactory::succeeding();
        let events = Arc::clone(&memory.events);
        let context = load_fake(
            &mode_config(EmbeddingSecurityMode::AeadCached),
            &mut io,
            &mut memory,
        )
        .unwrap();
        let StartupKeyContext::Mode1(mode1) = &context else {
            panic!("expected Mode 1 key context")
        };
        let identity = mode1.backend_identity();
        assert_eq!(format!("{identity:?}"), "PromptOpaqueIdentity([REDACTED])");
        assert_eq!(
            context.credential_source_identity(),
            Some(CredentialSourceIdentity {
                directory: DescriptorIdentity {
                    device: 10,
                    inode: 20,
                },
                credential: DescriptorIdentity {
                    device: 10,
                    inode: 21,
                },
                source_companion: Some(DescriptorIdentity {
                    device: 10,
                    inode: 22,
                }),
                credential_name: MODE1_CREDENTIAL_NAME,
            })
        );
        assert_eq!(
            context
                .configured_credential_source()
                .expect("Mode 1 source companion")
                .as_str(),
            MODE1_CREDENTIAL_PATH
        );
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["allocate", "mlock", "dontdump", "dontfork"]
        );
        drop(context);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            [
                "allocate", "mlock", "dontdump", "dontfork", "wipe", "unlock", "free"
            ]
        );
    }

    #[test]
    fn tpm_and_host_fallback_delivery_have_identical_loading_and_random_instance_identities() {
        let key = [0x5a; AES_256_KEY_BYTES];
        let mut identities = Vec::new();
        for _origin_not_exposed_to_loader in ["tpm+host", "host"] {
            let mut io = FakeCredentialIo::valid(key.to_vec());
            let mut memory = FakeMemoryFactory::succeeding();
            let context = load_fake(
                &mode_config(EmbeddingSecurityMode::AeadCached),
                &mut io,
                &mut memory,
            )
            .unwrap();
            let StartupKeyContext::Mode1(context) = context else {
                panic!("expected Mode 1 key context")
            };
            identities.push(context.backend_identity());
        }
        assert_ne!(identities[0], identities[1]);
    }

    #[test]
    fn missing_and_ambiguous_directory_inputs_fail_before_open_or_memory() {
        for directory in [
            None,
            Some(OsString::from("relative")),
            Some(OsString::from("//run/credentials")),
            Some(OsString::from("/run//credentials")),
            Some(OsString::from("/run/./credentials")),
            Some(OsString::from("/run/../credentials")),
            Some(OsString::from("/run/credentials/")),
        ] {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            io.directory = directory;
            let mut memory = FakeMemoryFactory::succeeding();
            assert!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .is_err()
            );
            assert_eq!(io.calls, ["env"]);
            assert!(memory.events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn missing_file_and_symlink_or_bad_directory_fail_before_memory() {
        let mut cases = Vec::new();

        let mut missing = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        missing.credential_open_fails = true;
        cases.push(missing);

        let mut symlink_dir = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        symlink_dir.directory_metadata.as_mut().unwrap().kind = MetadataKind::Symlink;
        cases.push(symlink_dir);

        let mut wrong_dir_owner = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        wrong_dir_owner.directory_metadata.as_mut().unwrap().owner = OWNER + 1;
        cases.push(wrong_dir_owner);

        let mut wrong_dir_mode = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
        wrong_dir_mode.directory_metadata.as_mut().unwrap().mode = 0o700;
        cases.push(wrong_dir_mode);

        for mut io in cases {
            let mut memory = FakeMemoryFactory::succeeding();
            assert!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .is_err()
            );
            assert!(memory.events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn credential_metadata_violations_fail_before_read_and_memory() {
        let mut metadata_cases = Vec::new();
        for kind in [
            MetadataKind::Directory,
            MetadataKind::Symlink,
            MetadataKind::Other,
        ] {
            let mut metadata = valid_file_metadata();
            metadata.kind = kind;
            metadata_cases.push(metadata);
        }
        let mut wrong_owner = valid_file_metadata();
        wrong_owner.owner += 1;
        metadata_cases.push(wrong_owner);
        let mut wrong_mode = valid_file_metadata();
        wrong_mode.mode = 0o440;
        metadata_cases.push(wrong_mode);
        let mut links = valid_file_metadata();
        links.links = 2;
        metadata_cases.push(links);
        for length in [0, 31, 33] {
            let mut metadata = valid_file_metadata();
            metadata.length = length;
            metadata_cases.push(metadata);
        }

        for metadata in metadata_cases {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            io.credential_metadata = Some(metadata);
            let mut memory = FakeMemoryFactory::succeeding();
            assert_eq!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .err(),
                Some(StartupKeyError::CredentialRejected)
            );
            assert!(memory.events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn short_extra_and_read_error_wipe_partial_guarded_bytes() {
        let mut cases = Vec::new();

        let mut short = FakeCredentialIo::valid(vec![0x41; 31]);
        short.credential_metadata.as_mut().unwrap().length = 32;
        cases.push(short);

        let mut extra = FakeCredentialIo::valid(vec![0x41; 33]);
        extra.credential_metadata.as_mut().unwrap().length = 32;
        cases.push(extra);

        let mut read_error = FakeCredentialIo::valid(vec![0x41; 32]);
        read_error.read_chunks = VecDeque::from([10]);
        read_error.read_error_after = Some(10);
        cases.push(read_error);

        for mut io in cases {
            let mut memory = FakeMemoryFactory::succeeding();
            let events = Arc::clone(&memory.events);
            assert_eq!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .err(),
                Some(StartupKeyError::CredentialRejected)
            );
            assert_eq!(
                events.lock().unwrap().as_slice(),
                [
                    "allocate", "mlock", "dontdump", "dontfork", "wipe", "unlock", "free"
                ]
            );
        }
    }

    #[test]
    fn exact_binary_key_accepts_trailing_newline_and_embedded_nul_but_rejects_33rd_newline() {
        let mut trailing_newline = vec![0x41; 32];
        trailing_newline[31] = b'\n';
        let mut embedded_nul = vec![0x41; 32];
        embedded_nul[7] = 0;
        for bytes in [trailing_newline, embedded_nul] {
            let mut io = FakeCredentialIo::valid(bytes);
            let mut memory = FakeMemoryFactory::succeeding();
            assert!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .is_ok()
            );
        }

        let mut io = FakeCredentialIo::valid(vec![0x41; 32]);
        io.bytes.push(b'\n');
        io.credential_metadata.as_mut().unwrap().length = 32;
        let mut memory = FakeMemoryFactory::succeeding();
        assert_eq!(
            load_fake(
                &mode_config(EmbeddingSecurityMode::AeadCached),
                &mut io,
                &mut memory,
            )
            .err(),
            Some(StartupKeyError::CredentialRejected)
        );
    }

    #[test]
    fn interrupted_reads_retry_before_during_and_after_the_exact_key() {
        for (chunks, interrupts) in [
            (VecDeque::new(), VecDeque::from([0])),
            (VecDeque::from([9]), VecDeque::from([9])),
            (VecDeque::new(), VecDeque::from([32])),
            (VecDeque::from([7, 25]), VecDeque::from([0, 7, 32])),
        ] {
            let mut io = FakeCredentialIo::valid(vec![0x41; 32]);
            io.read_chunks = chunks;
            io.interrupt_at = interrupts;
            let mut memory = FakeMemoryFactory::succeeding();
            assert!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn root_owned_mode_and_acl_contract_is_exact() {
        assert_eq!(CREDENTIAL_DIRECTORY_MODE, 0o500);
        assert_eq!(CREDENTIAL_FILE_MODE, 0o400);
        assert_eq!(valid_directory_metadata().owner, 0);
        assert_eq!(valid_file_metadata().owner, 0);
        for acl_target in [0, 1] {
            let mut io = FakeCredentialIo::valid(vec![0x41; 32]);
            io.directory_acl = acl_target == 0;
            io.credential_acl = acl_target == 1;
            let mut memory = FakeMemoryFactory::succeeding();
            assert_eq!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .err(),
                Some(StartupKeyError::UnsupportedCredentialDelivery)
            );
        }
    }

    #[test]
    fn guarded_memory_failures_wipe_once_and_unlock_only_after_successful_lock() {
        for failure in [
            MemoryFailure::Allocate,
            MemoryFailure::Lock,
            MemoryFailure::DontDump,
            MemoryFailure::DontFork,
        ] {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            let mut memory = FakeMemoryFactory {
                events: Arc::new(Mutex::new(Vec::new())),
                failure: Some(failure),
            };
            let events = Arc::clone(&memory.events);
            assert_eq!(
                load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .err(),
                Some(StartupKeyError::GuardedMemoryUnavailable)
            );
            let events = events.lock().unwrap();
            assert!(events.iter().filter(|event| **event == "wipe").count() <= 1);
            if failure == MemoryFailure::Allocate {
                assert_eq!(events.as_slice(), ["allocate"]);
            } else {
                assert_eq!(events.iter().filter(|event| **event == "wipe").count(), 1);
                let wipe = events.iter().position(|event| *event == "wipe").unwrap();
                if let Some(unlock) = events.iter().position(|event| *event == "unlock") {
                    assert!(wipe < unlock);
                }
            }
        }
    }

    #[test]
    fn panic_and_backend_failure_drop_the_key_exactly_once() {
        for panic_after_load in [false, true] {
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            let mut memory = FakeMemoryFactory::succeeding();
            let events = Arc::clone(&memory.events);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let context = load_fake(
                    &mode_config(EmbeddingSecurityMode::AeadCached),
                    &mut io,
                    &mut memory,
                )
                .unwrap();
                if panic_after_load {
                    panic!("injected post-load initialization panic");
                }
                let backend_result: Result<(), ()> = Err(());
                drop((backend_result, context));
            }));
            assert_eq!(outcome.is_err(), panic_after_load);
            let events = events.lock().unwrap();
            assert_eq!(events.iter().filter(|event| **event == "wipe").count(), 1);
            assert_eq!(events.iter().filter(|event| **event == "unlock").count(), 1);
            assert_eq!(events.iter().filter(|event| **event == "free").count(), 1);
        }
    }

    #[test]
    fn backend_crypto_boundary_round_trips_without_a_raw_key_api() {
        let context = Mode1KeyContext::from_test_key([0x31; AES_256_KEY_BYTES]);
        let username = CanonicalUsername::new("alice").unwrap();
        let model = ModelDigest::new([0x42; 32]);
        let record = EnrollmentRecord::new(1, model, username.clone(), Vec::new()).unwrap();
        let mut nonces = NonceGenerator::new();
        let encrypted = context.encrypt_record(&record, 1, &mut nonces).unwrap();
        let decoded = context
            .decrypt_record(&encrypted, 1, &username, model)
            .unwrap();
        assert_eq!(decoded, record);

        let source = include_str!("mode1_key.rs");
        assert!(!source.contains(concat!("pub fn ", "key(")));
        assert!(!source.contains(concat!("pub(crate) fn ", "key(")));
        assert!(!source.contains(concat!("impl Clone for ", "Mode1KeyContext")));
        assert!(source.contains("pub(crate) fn encrypt_record"));
        assert!(source.contains("pub(crate) fn decrypt_record"));
    }

    #[test]
    fn credential_name_and_epoch_mismatch_fail_before_environment_access() {
        for mutate in [0, 1] {
            let mut config = mode_config(EmbeddingSecurityMode::AeadCached);
            if mutate == 0 {
                config.security.cached.credential_name = "howy.storage.mode1.epoch2".into();
            } else {
                config.security.key_epoch = 2;
            }
            let mut io = FakeCredentialIo::valid(vec![0x41; AES_256_KEY_BYTES]);
            let mut memory = FakeMemoryFactory::succeeding();
            assert_eq!(
                load_fake(&config, &mut io, &mut memory).err(),
                Some(StartupKeyError::ContractMismatch)
            );
            assert!(io.calls.is_empty());
            assert!(memory.events.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn every_bad_credential_fails_before_inference_camera_and_storage_hooks() {
        let mut io = FakeCredentialIo::valid(vec![0x41; 31]);
        io.credential_metadata.as_mut().unwrap().length = 32;
        let mut memory = FakeMemoryFactory::succeeding();
        let hooks = Arc::new(Mutex::new(Vec::new()));
        let result = load_fake(
            &mode_config(EmbeddingSecurityMode::AeadCached),
            &mut io,
            &mut memory,
        );
        if result.is_ok() {
            hooks
                .lock()
                .unwrap()
                .extend(["inference", "camera", "storage", "listener"]);
        }
        assert!(result.is_err());
        assert!(hooks.lock().unwrap().is_empty());
    }

    #[test]
    fn repository_base_unit_has_no_mode1_credential_directive() {
        let unit = include_str!("../../../systemd/howy.service");
        let active = unit
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        let encrypted = active
            .iter()
            .filter(|line| line.starts_with("LoadCredentialEncrypted="))
            .copied()
            .collect::<Vec<_>>();
        assert!(encrypted.is_empty());
        assert!(
            !active
                .iter()
                .any(|line| line.starts_with("LoadCredential="))
        );
        assert!(!active.iter().any(|line| line.starts_with("SetCredential=")));
        assert!(
            !active
                .iter()
                .any(|line| line.starts_with("SetCredentialEncrypted="))
        );
        assert!(!active.iter().any(|line| line.starts_with("ExecStartPre=")));
        assert!(!unit.contains("systemd-creds"));
        assert!(!active.iter().any(|line| {
            line.starts_with("Environment=")
                && (line.contains(MODE1_CREDENTIAL_NAME) || line.contains("CREDENTIALS_DIRECTORY"))
        }));
        assert_ne!(MODE1_CREDENTIAL_NAME, "det_10g.onnx");
        assert_ne!(MODE1_CREDENTIAL_NAME, "w600k_r50.onnx");
    }

    #[test]
    fn real_guard_mapping_has_guard_pages_lock_dontdump_and_dontfork() {
        let _serial = REAL_MEMORY_TEST_LOCK.lock().unwrap();
        let mut allocation = MmapGuardedAllocation::new().unwrap();
        allocation.lock().unwrap();
        allocation.dont_dump().unwrap();
        allocation.dont_fork().unwrap();
        allocation.key_mut().fill(0x5a);

        let base = allocation.mapping.unwrap().as_ptr() as usize;
        let key = allocation.key_page.as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let permissions_for = |address: usize| {
            maps.lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let range = fields.next()?;
                    let permissions = fields.next()?;
                    let (start, end) = range.split_once('-')?;
                    let start = usize::from_str_radix(start, 16).ok()?;
                    let end = usize::from_str_radix(end, 16).ok()?;
                    (start <= address && address < end).then(|| permissions.to_string())
                })
                .unwrap()
        };
        assert_eq!(permissions_for(base), "---p");
        assert_eq!(permissions_for(key), "rw-p");
        assert_eq!(permissions_for(key + allocation.page_length), "---p");

        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_key_mapping = false;
        let mut flags = None;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((start, end)) = range.split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        in_key_mapping = start <= key && key < end;
                    }
                }
            }
            if in_key_mapping && line.starts_with("VmFlags:") {
                flags = Some(line.to_string());
                break;
            }
        }
        let flags = flags.expect("key mapping VmFlags");
        assert!(flags.split_whitespace().any(|flag| flag == "lo"), "{flags}");
        assert!(flags.split_whitespace().any(|flag| flag == "dd"), "{flags}");
        assert!(flags.split_whitespace().any(|flag| flag == "dc"), "{flags}");
        allocation.dispose();
    }

    #[test]
    fn real_dontfork_mapping_is_absent_in_fork_child() {
        let _serial = REAL_MEMORY_TEST_LOCK.lock().unwrap();
        let mut allocation = MmapGuardedAllocation::new().unwrap();
        allocation.lock().unwrap();
        allocation.dont_dump().unwrap();
        allocation.dont_fork().unwrap();
        allocation.key_mut().fill(0xa5);
        let key = allocation.key_page.as_ptr();
        let page_length = allocation.page_length;
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let mut vector = 0_u8;
            let result = unsafe { libc::mincore(key.cast(), page_length, &mut vector) };
            let absent =
                result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM);
            unsafe { libc::_exit(if absent { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        allocation.dispose();
    }

    #[test]
    fn real_partial_guard_failure_still_wipes_unlocks_and_unmaps() {
        let _serial = REAL_MEMORY_TEST_LOCK.lock().unwrap();
        let mut allocation = MmapGuardedAllocation::new().unwrap();
        allocation.lock().unwrap();
        allocation.key_mut().fill(0x7c);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            if allocation.advise(-1).is_ok() {
                unsafe { libc::_exit(2) };
            }
            DISPOSAL_OBSERVER_STATE.store(0, std::sync::atomic::Ordering::SeqCst);
            DISPOSAL_OBSERVER_ENABLED.store(true, std::sync::atomic::Ordering::SeqCst);
            allocation.dispose();
            DISPOSAL_OBSERVER_ENABLED.store(false, std::sync::atomic::Ordering::SeqCst);
            let observed = DISPOSAL_OBSERVER_STATE.load(std::sync::atomic::Ordering::SeqCst);
            unsafe { libc::_exit(libc::c_int::from(observed)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        let observed = u8::try_from(libc::WEXITSTATUS(status)).unwrap();
        assert_ne!(
            observed & DISPOSAL_OBSERVED_ZEROIZED,
            0,
            "production disposal did not wipe the real key before munlock"
        );
        assert_ne!(
            observed & DISPOSAL_OBSERVED_MUNLOCK,
            0,
            "production disposal did not successfully munlock the key page"
        );
        assert_ne!(
            observed & DISPOSAL_OBSERVED_MUNMAP,
            0,
            "production disposal did not successfully munmap the mapping"
        );
        assert_ne!(
            observed & DISPOSAL_OBSERVED_UNMAPPED,
            0,
            "the real key page remained mapped after production disposal"
        );
        allocation.dispose();
    }

    #[test]
    fn real_component_walk_rejects_directory_and_file_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "howy-mode1-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join(MODE1_CREDENTIAL_NAME), [0x41; 32]).unwrap();
        std::os::unix::fs::symlink(&real, root.join("linked")).unwrap();
        assert!(open_absolute_directory_no_follow(root.join("linked").as_os_str()).is_err());
        let directory = open_absolute_directory_no_follow(real.as_os_str()).unwrap();
        std::os::unix::fs::symlink(
            real.join(MODE1_CREDENTIAL_NAME),
            real.join("credential-link"),
        )
        .unwrap();
        let name = CString::new("credential-link").unwrap();
        assert!(
            SystemCredentialIo
                .open_credential_no_follow(&directory, &name)
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn real_file_read_accepts_all_exact_binary_values() {
        let root = std::env::temp_dir().join(format!("howy-mode1-read-{}", std::process::id()));
        let _ = std::fs::remove_file(&root);
        let mut bytes = [0_u8; 32];
        bytes[0] = 0;
        bytes[31] = b'\n';
        std::fs::write(&root, bytes).unwrap();
        let mut file = File::open(&root).unwrap();
        let mut destination = [0_u8; 32];
        read_exact_binary_key(&mut file, &mut destination, &NeverCancelled).unwrap();
        assert_eq!(destination, bytes);
        destination.zeroize();
        std::fs::remove_file(root).unwrap();
    }

    #[test]
    #[ignore = "requires disposable root environment"]
    fn root_service_metadata_fixture_matches_pinned_delivery() {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "qualification must run as root in a disposable environment"
        );
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("howy-mode1-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let credential = root.join(MODE1_CREDENTIAL_NAME);
        std::fs::write(&credential, [0x41; 32]).unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o400)).unwrap();
        let directory = open_absolute_directory_no_follow(root.as_os_str()).unwrap();
        validate_directory_metadata(metadata_from_std(directory.metadata().unwrap()), 0).unwrap();
        assert!(!descriptor_has_acl(&directory).unwrap());
        let name = CString::new(MODE1_CREDENTIAL_NAME).unwrap();
        let file = SystemCredentialIo
            .open_credential_no_follow(&directory, &name)
            .unwrap();
        validate_credential_metadata(metadata_from_std(file.metadata().unwrap()), 0).unwrap();
        assert!(!descriptor_has_acl(&file).unwrap());
        drop((file, directory));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
