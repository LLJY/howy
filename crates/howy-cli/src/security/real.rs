use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use howy_common::config::HowyConfig;
use howy_common::ipc::DaemonClient;
use howy_common::protocol::{DaemonInfo, Request, RespResult, SecurityInfoResult};
use howy_common::provisioning::{
    AtomicExpectedTargetV1, AtomicFileIdentityV1, AtomicWriteKindV1, AtomicWriteObservationV1,
    AtomicWritePlanV1, BASE_SERVICE_UNIT_PATH, BASE_SOCKET_UNIT_PATH, DaemonVerifierIdentityV1,
    DirectoryIdentityV1, EffectiveCredentialLoadV1, EffectiveFileMetadataV1,
    EffectiveSetCredentialV1, EffectiveUnitFileV1, EffectiveUnitObservationV1, FileLinkPolicy,
    FileMetadataSnapshotV1, FileObjectType, FileTimestampV1, MAX_DROPIN_BYTES, MAX_JOURNAL_BYTES,
    MAX_NAMESPACE_CIPHERTEXT_BYTES, MAX_NAMESPACE_ENTRIES, MAX_NAMESPACE_NAME_BYTES,
    MAX_NAMESPACE_TOTAL_BYTES, MODE1_CREDENTIAL_DIRECTORY, MODE1_CREDENTIAL_NAME,
    MODE1_CREDENTIAL_PATH, MODE1_CREDENTIAL_SOURCE_COMPANION_NAME, MODE1_DROPIN_PATH,
    MODE1_NAMESPACE_PATH, NamespaceDirectoryMetadata, NamespaceFileType, NamespaceFingerprintEntry,
    NamespaceInventoryV1, PlaintextProvisioningJournalV1, ProvisioningJournalV1, ReadinessResultV1,
    RecognizerIdentity, RestorableFileTimestampsV1, SECURITY_JOURNAL_PATH, SECURITY_LOCK_PATH,
    SECURITY_STATE_DIRECTORY, SECURITY_TRANSACTION_GUARD_PATH, SECURITY_UNADOPTED_DIRECTORY,
    SecurityDirectoryRecordV1, Sha256Digest, SupervisorJournalV1, SupervisorOperationV1,
    SupervisorPhaseV1, TransactionGuardIdentityV1, TransactionGuardV1, UnitActiveState,
    UnitFileState, UnitKind, UnitLoadState, UnitObservation, UnitSubState, VerifierResultV1,
    classify_mode1_namespace_entry, namespace_fingerprint, package_bootstrap_condition,
    required_service_hardening, required_unit_conditions, transaction_guard_condition,
    validate_journal_transition, validate_plaintext_journal_transition,
    validate_readiness_inventory, validate_supervisor_journal_transition,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::command::{
    self, CommandSpec, KeySelection, effective_unit_show_command, systemctl_command,
    tpm2_probe_command,
};
use super::engine::{
    AtomicTargetObservation, AtomicWriteReconciliation, BASE_SERVICE_UNIT_BYTES,
    BASE_SOCKET_UNIT_BYTES, MODE0_DROPIN_BYTES, MODE1_DROPIN_BYTES, ObservedFile,
    SecretKeyMaterial, SecurityError, SecurityResult, SecurityRuntime,
};

const LOCK_WAIT: Duration = Duration::from_secs(10);
const UNIT_SETTLE_STEP: Duration = Duration::from_millis(100);
const EXECUTABLE_MAX: usize = 1_073_741_824;
const CHILD_REAP_RESERVE: Duration = Duration::from_millis(250);
const TRANSIENT_CLEANUP_RESERVE: Duration = Duration::from_secs(15);
const TRANSIENT_STATE_MAX: usize = 256;
const EFFECTIVE_SHOW_MAX: usize = 16_384;
const UNIT_STATE_MAX: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedJournal {
    Mode1(ProvisioningJournalV1),
    Plaintext(PlaintextProvisioningJournalV1),
    Supervisor(SupervisorJournalV1),
}

impl ParsedJournal {
    fn transaction_id(&self) -> &str {
        match self {
            Self::Mode1(journal) => &journal.transaction_id,
            Self::Plaintext(journal) => &journal.transaction_id,
            Self::Supervisor(journal) => &journal.transaction_id,
        }
    }

    fn staging_path(&self) -> &str {
        match self {
            Self::Mode1(journal) => &journal.journal_staging_path,
            Self::Plaintext(journal) => &journal.journal_staging_path,
            Self::Supervisor(journal) => &journal.journal_staging_path,
        }
    }

    fn generation(&self) -> u64 {
        match self {
            Self::Mode1(journal) => journal.generation,
            Self::Plaintext(journal) => journal.generation,
            Self::Supervisor(journal) => journal.generation,
        }
    }

    fn prior_journal_identity(&self) -> Option<&AtomicFileIdentityV1> {
        match self {
            Self::Mode1(journal) => journal.prior_journal_identity.as_ref(),
            Self::Plaintext(journal) => journal.prior_journal_identity.as_ref(),
            Self::Supervisor(journal) => journal.prior_journal_identity.as_ref(),
        }
    }

    fn valid_next(&self, next: &Self) -> bool {
        if self.transaction_id() != next.transaction_id()
            || self.staging_path() != next.staging_path()
            || self.generation().checked_add(1) != Some(next.generation())
        {
            return false;
        }
        match (self, next) {
            (Self::Mode1(current), Self::Mode1(next)) => {
                validate_journal_transition(current, next).is_ok()
            }
            (Self::Plaintext(current), Self::Plaintext(next)) => {
                validate_plaintext_journal_transition(current, next).is_ok()
            }
            (Self::Supervisor(current), Self::Supervisor(next)) => {
                validate_supervisor_journal_transition(current, next).is_ok()
            }
            (Self::Supervisor(current), Self::Mode1(next)) => {
                matches!(
                    current.operation,
                    SupervisorOperationV1::ProvisionMode1 | SupervisorOperationV1::EnableMode1
                ) && current.phase == SupervisorPhaseV1::DirectoriesReady
                    && next.guard == current.guard
                    && next.security_directories == current.security_directories
                    && next.prior_config == current.prior_config
                    && next.prior_dropin == current.prior_dropin
                    && next.prior_receipt == current.prior_receipt
                    && next.service_unit_state == *current.service_unit_state.as_ref().unwrap()
                    && next.socket_unit_state == *current.socket_unit_state.as_ref().unwrap()
                    && next.prior_daemon_invocation_id == current.prior_daemon_invocation_id
                    && current.prior_effective_units.as_ref() == Some(&next.prior_effective_units)
            }
            (Self::Supervisor(current), Self::Plaintext(next)) => {
                current.operation == SupervisorOperationV1::ProvisionMode0
                    && current.phase == SupervisorPhaseV1::DirectoriesReady
                    && next.guard == current.guard
                    && next.security_directories == current.security_directories
                    && next.prior_config == current.prior_config
                    && next.prior_dropin == current.prior_dropin
                    && next.service_unit_state == *current.service_unit_state.as_ref().unwrap()
                    && next.socket_unit_state == *current.socket_unit_state.as_ref().unwrap()
                    && next.prior_daemon_invocation_id == current.prior_daemon_invocation_id
                    && current.prior_effective_units.as_ref() == Some(&next.prior_effective_units)
            }
            _ => false,
        }
    }
}

fn parsed_journal(bytes: &[u8]) -> SecurityResult<ParsedJournal> {
    if let Ok(journal) = ProvisioningJournalV1::parse(bytes) {
        return Ok(ParsedJournal::Mode1(journal));
    }
    if let Ok(journal) = PlaintextProvisioningJournalV1::parse(bytes) {
        return Ok(ParsedJournal::Plaintext(journal));
    }
    if let Ok(journal) = SupervisorJournalV1::parse(bytes) {
        return Ok(ParsedJournal::Supervisor(journal));
    }
    Err(SecurityError::Uncertain(
        "journal bytes are not a strict transaction schema".into(),
    ))
}

pub struct RealSecurityRuntime {
    lock: Option<File>,
    monotonic_origin: Instant,
    completed_transient_cleanup: Option<String>,
    paths: SecurityPaths,
    #[cfg(test)]
    atomic_pre_rename_hook: Option<Box<dyn FnMut(&AtomicWritePlanV1)>>,
    #[cfg(test)]
    atomic_failure: Option<&'static str>,
    #[cfg(test)]
    force_named_journal_staging: bool,
    #[cfg(test)]
    journal_pre_exchange_hook: Option<Box<dyn FnMut()>>,
}

#[derive(Debug, Clone)]
struct SecurityPaths {
    root: PathBuf,
}

impl SecurityPaths {
    fn production() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    fn rooted(root: &Path) -> SecurityResult<Self> {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(SecurityError::operation("invalid test security root"));
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn resolve(&self, production: &str) -> SecurityResult<PathBuf> {
        let path = Path::new(production);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(SecurityError::operation("unsafe production path"));
        }
        if self.root == Path::new("/") {
            Ok(path.to_owned())
        } else {
            Ok(self.root.join(
                path.strip_prefix("/")
                    .map_err(|_| SecurityError::operation("production path is not rooted"))?,
            ))
        }
    }
}

impl RealSecurityRuntime {
    pub fn new() -> Self {
        Self {
            lock: None,
            monotonic_origin: Instant::now(),
            completed_transient_cleanup: None,
            paths: SecurityPaths::production(),
            #[cfg(test)]
            atomic_pre_rename_hook: None,
            #[cfg(test)]
            atomic_failure: None,
            #[cfg(test)]
            force_named_journal_staging: false,
            #[cfg(test)]
            journal_pre_exchange_hook: None,
        }
    }

    #[cfg(test)]
    fn rooted(root: &Path) -> SecurityResult<Self> {
        let mut runtime = Self::new();
        runtime.paths = SecurityPaths::rooted(root)?;
        Ok(runtime)
    }

    #[cfg(test)]
    fn atomic_fail(&mut self, point: &'static str) -> SecurityResult<()> {
        if self.atomic_failure == Some(point) {
            self.atomic_failure = None;
            Err(SecurityError::operation(format!(
                "injected atomic failure at {point}"
            )))
        } else {
            Ok(())
        }
    }

    #[cfg(not(test))]
    fn atomic_fail(&mut self, _point: &'static str) -> SecurityResult<()> {
        Ok(())
    }

    fn read_exact_file(&self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>> {
        let resolved = self.paths.resolve(path)?;
        let resolved = resolved
            .to_str()
            .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?;
        let (parent, name) = split_absolute(resolved)?;
        let Some(parent_fd) = open_directory_path(&self.paths.root, parent, false, 0o700)? else {
            return Ok(None);
        };
        let parent_stat = fstat(parent_fd.as_raw_fd())?;
        let name = cstring(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | libc::O_NOATIME,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(SecurityError::operation("safe file open failed"));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = fstat(file.as_raw_fd())?;
        if (before.st_mode & libc::S_IFMT) != libc::S_IFREG
            || before.st_nlink != 1
            || before.st_size < 0
            || usize::try_from(before.st_size).map_or(true, |length| length > maximum)
        {
            return Err(SecurityError::operation("unsafe file object"));
        }
        let mut bytes = Vec::with_capacity(before.st_size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| SecurityError::operation("bounded file read failed"))?;
        let after = fstat(file.as_raw_fd())?;
        if file_identity(&before) != file_identity(&after) || after.st_size != bytes.len() as i64 {
            return Err(SecurityError::operation("file changed while read"));
        }
        Ok(Some(observed(bytes, &after, &parent_stat)))
    }

    fn write_control_direct(
        &self,
        path: &str,
        bytes: &[u8],
        permissions: u32,
    ) -> SecurityResult<ObservedFile> {
        let resolved = self.paths.resolve(path)?;
        let (parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?,
        )?;
        let directory_mode = directory_mode_for(
            Path::new(path)
                .parent()
                .ok_or_else(|| SecurityError::operation("control path has no parent"))?,
        );
        let parent_fd = open_directory_path(&self.paths.root, parent, false, directory_mode)?
            .ok_or_else(|| SecurityError::operation("control parent directory is absent"))?;
        validate_root_directory(parent_fd.as_raw_fd(), directory_mode)?;
        let name = cstring(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                permissions as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(SecurityError::operation(
                "exclusive control file creation failed",
            ));
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let created = fstat(file.as_raw_fd())?;
        let result = (|| {
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), permissions as libc::mode_t) } != 0
            {
                return Err(SecurityError::operation(
                    "control file metadata setup failed",
                ));
            }
            file.write_all(bytes)
                .map_err(|_| SecurityError::operation("control file write failed"))?;
            file.sync_all()
                .map_err(|_| SecurityError::operation("control file fsync failed"))?;
            fsync_directory(parent_fd.as_raw_fd())?;
            let production_parent = Path::new(path)
                .parent()
                .ok_or_else(|| SecurityError::operation("control path has no parent"))?;
            let parent_identity =
                directory_identity(production_parent, &fstat(parent_fd.as_raw_fd())?)?;
            let observed =
                observe_atomic_at(parent_fd.as_raw_fd(), &name, bytes.len(), &parent_identity)?
                    .ok_or_else(|| SecurityError::operation("created control file disappeared"))?;
            if observed.device_id != created.st_dev
                || observed.inode != created.st_ino
                || observed.bytes != bytes
            {
                return Err(SecurityError::Uncertain(
                    "created control file identity changed before observation".into(),
                ));
            }
            Ok(observed)
        })();
        if result.is_err() {
            let _ = unlink_created_stage_exact(
                parent_fd.as_raw_fd(),
                &name,
                created.st_dev,
                created.st_ino,
            );
        }
        result
    }

    fn journal_parent(&self) -> SecurityResult<(OwnedFd, DirectoryIdentityV1, CString)> {
        let resolved = self.paths.resolve(SECURITY_JOURNAL_PATH)?;
        let (parent, target_name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted journal path is not UTF-8"))?,
        )?;
        let parent_fd = open_directory_path_bound(parent)?;
        validate_root_directory(
            parent_fd.as_raw_fd(),
            directory_mode_for(Path::new("/var/lib")),
        )?;
        let identity = directory_identity(Path::new("/var/lib"), &fstat(parent_fd.as_raw_fd())?)?;
        Ok((parent_fd, identity, cstring(target_name.as_bytes())?))
    }

    fn journal_stage_name(&self, staging_path: &str) -> SecurityResult<CString> {
        let resolved = self.paths.resolve(staging_path)?;
        let (staging_parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted journal stage is not UTF-8"))?,
        )?;
        let resolved_journal = self.paths.resolve(SECURITY_JOURNAL_PATH)?;
        let (journal_parent, _) = split_absolute(
            resolved_journal
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted journal path is not UTF-8"))?,
        )?;
        if staging_parent != journal_parent || staging_path == SECURITY_JOURNAL_PATH {
            return Err(SecurityError::operation(
                "journal staging path is outside the held parent",
            ));
        }
        cstring(name.as_bytes())
    }

    #[cfg(test)]
    fn use_named_journal_fallback(&self) -> bool {
        self.force_named_journal_staging
    }

    #[cfg(not(test))]
    fn use_named_journal_fallback(&self) -> bool {
        false
    }

    fn create_journal_stage(
        &mut self,
        parent_fd: RawFd,
        parent: &DirectoryIdentityV1,
        stage_name: &CStr,
        bytes: &[u8],
        allow_named_fallback: bool,
    ) -> SecurityResult<ObservedFile> {
        if fstatat_nofollow(parent_fd, stage_name)?.is_some() {
            return Err(SecurityError::Uncertain(
                "journal stage is occupied and was retained".into(),
            ));
        }
        if !allow_named_fallback && self.use_named_journal_fallback() {
            return Err(SecurityError::operation(
                "initial journal requires unnamed staging",
            ));
        }
        let dot = cstring(b".")?;
        let mut unnamed = !self.use_named_journal_fallback();
        let mut fd = if unnamed {
            unsafe {
                libc::openat(
                    parent_fd,
                    dot.as_ptr(),
                    libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC,
                    0o600,
                )
            }
        } else {
            -1
        };
        if fd < 0 && unnamed {
            let error = std::io::Error::last_os_error();
            if allow_named_fallback
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP)
                        | Some(libc::EINVAL)
                        | Some(libc::EISDIR)
                        | Some(libc::ENOENT)
                )
            {
                unnamed = false;
            } else {
                return Err(SecurityError::operation(
                    "unnamed journal stage creation failed",
                ));
            }
        }
        if !unnamed {
            fd = unsafe {
                libc::openat(
                    parent_fd,
                    stage_name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(SecurityError::Uncertain(
                    "named journal stage creation failed and any occupant was retained".into(),
                ));
            }
        }
        let mut stage = unsafe { File::from_raw_fd(fd) };
        let created = fstat(stage.as_raw_fd())?;
        let write_result = (|| {
            if unsafe { libc::fchown(stage.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(stage.as_raw_fd(), 0o600) } != 0
            {
                return Err(SecurityError::operation(
                    "journal stage metadata setup failed",
                ));
            }
            stage
                .write_all(bytes)
                .map_err(|_| SecurityError::operation("journal stage write failed"))?;
            stage
                .sync_all()
                .map_err(|_| SecurityError::operation("journal stage fsync failed"))?;
            if unnamed {
                let empty = cstring(b"")?;
                let linked = unsafe {
                    libc::linkat(
                        stage.as_raw_fd(),
                        empty.as_ptr(),
                        parent_fd,
                        stage_name.as_ptr(),
                        libc::AT_EMPTY_PATH,
                    )
                };
                if linked != 0 {
                    let proc_path =
                        cstring(format!("/proc/self/fd/{}", stage.as_raw_fd()).as_bytes())?;
                    if unsafe {
                        libc::linkat(
                            libc::AT_FDCWD,
                            proc_path.as_ptr(),
                            parent_fd,
                            stage_name.as_ptr(),
                            libc::AT_SYMLINK_FOLLOW,
                        )
                    } != 0
                    {
                        return Err(SecurityError::operation(
                            "unnamed journal stage publication failed",
                        ));
                    }
                }
            }
            fsync_directory(parent_fd).map_err(|_| {
                SecurityError::Uncertain("journal stage directory fsync failed".into())
            })?;
            let observed = observe_atomic_at(parent_fd, stage_name, bytes.len(), parent)?
                .ok_or_else(|| SecurityError::Uncertain("journal stage disappeared".into()))?;
            if observed.device_id != created.st_dev
                || observed.inode != created.st_ino
                || observed.bytes != bytes
                || observed.metadata.uid != 0
                || observed.metadata.gid != 0
                || observed.metadata.permissions != 0o600
            {
                return Err(SecurityError::Uncertain(
                    "journal stage changed before durable observation".into(),
                ));
            }
            Ok(observed)
        })();
        // A named fallback is intentionally retained on every failure. Its
        // created identity was not yet durably bound by a journal generation.
        // An unnamed inode disappears automatically only if it was never linked.
        write_result
    }

    fn unlink_journal_entry_exact(
        &mut self,
        parent_fd: RawFd,
        parent: &DirectoryIdentityV1,
        name: &CStr,
        expected: &ObservedFile,
    ) -> SecurityResult<()> {
        let live =
            observe_atomic_at(parent_fd, name, MAX_JOURNAL_BYTES, parent)?.ok_or_else(|| {
                SecurityError::Uncertain("journal control disappeared before unlink".into())
            })?;
        if !observed_control_matches(&live, expected) {
            return Err(SecurityError::Uncertain(
                "journal control identity or bytes changed before unlink".into(),
            ));
        }
        if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::Uncertain(
                "exact journal control unlink failed".into(),
            ));
        }
        fsync_directory(parent_fd)
            .map_err(|_| SecurityError::Uncertain("journal directory fsync failed".into()))
    }

    fn journal_stage_candidates(
        &self,
        parent_fd: RawFd,
        parent: &DirectoryIdentityV1,
    ) -> SecurityResult<Vec<(CString, ObservedFile)>> {
        let duplicate = unsafe { libc::fcntl(parent_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(SecurityError::operation(
                "journal directory duplication failed",
            ));
        }
        let directory = unsafe { libc::fdopendir(duplicate) };
        if directory.is_null() {
            unsafe { libc::close(duplicate) };
            return Err(SecurityError::operation(
                "journal directory stream open failed",
            ));
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes.starts_with(b".howy-txn-")
                && bytes.ends_with(b"-transaction-v1.json-journal.stage")
            {
                names.push(cstring(bytes)?);
            }
        }
        unsafe { libc::closedir(directory) };
        let mut candidates = Vec::new();
        for name in names {
            let observed = observe_atomic_at(parent_fd, &name, MAX_JOURNAL_BYTES, parent)?
                .ok_or_else(|| {
                    SecurityError::Uncertain("journal stage changed during scan".into())
                })?;
            candidates.push((name, observed));
        }
        Ok(candidates)
    }

    fn atomic_parent_fd(&self, plan: &AtomicWritePlanV1) -> SecurityResult<OwnedFd> {
        plan.validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let resolved_parent = self.paths.resolve(&plan.parent_directory.path)?;
        let fd = open_directory_path_bound(&resolved_parent)?;
        validate_directory_identity(fd.as_raw_fd(), &plan.parent_directory)?;
        validate_absolute_parent_identity(
            &resolved_parent,
            fd.as_raw_fd(),
            &plan.parent_directory,
        )?;
        Ok(fd)
    }

    fn create_atomic_stage_internal(
        &mut self,
        plan: &AtomicWritePlanV1,
        bytes: &[u8],
    ) -> SecurityResult<AtomicFileIdentityV1> {
        plan.validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if bytes.len() as u64 != plan.byte_length
            || Sha256Digest::from_bytes(bytes) != plan.bytes_sha256
        {
            return Err(SecurityError::operation(
                "atomic write bytes do not match journaled plan",
            ));
        }
        let parent_fd = self.atomic_parent_fd(plan)?;
        let (_, stage_name) = split_absolute(&plan.staging_path)?;
        let stage = cstring(stage_name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                stage.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                plan.permissions as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(SecurityError::operation(
                "journaled atomic stage creation failed",
            ));
        }
        let mut stage_file = unsafe { File::from_raw_fd(fd) };
        let created = fstat(stage_file.as_raw_fd())?;
        let result = (|| {
            self.atomic_fail("stage-create")?;
            if unsafe {
                libc::fchown(
                    stage_file.as_raw_fd(),
                    plan.uid as libc::uid_t,
                    plan.gid as libc::gid_t,
                )
            } != 0
                || unsafe { libc::fchmod(stage_file.as_raw_fd(), plan.permissions as libc::mode_t) }
                    != 0
            {
                return Err(SecurityError::operation(
                    "atomic stage metadata setup failed",
                ));
            }
            stage_file
                .write_all(bytes)
                .map_err(|_| SecurityError::operation("atomic stage write failed"))?;
            self.atomic_fail("stage-write")?;
            if let Some(timestamps) = &plan.timestamps {
                let times = [
                    libc::timespec {
                        tv_sec: timestamps.access.seconds,
                        tv_nsec: i64::from(timestamps.access.nanoseconds),
                    },
                    libc::timespec {
                        tv_sec: timestamps.modification.seconds,
                        tv_nsec: i64::from(timestamps.modification.nanoseconds),
                    },
                ];
                if unsafe { libc::futimens(stage_file.as_raw_fd(), times.as_ptr()) } != 0 {
                    return Err(SecurityError::operation(
                        "atomic stage timestamp setup failed",
                    ));
                }
            }
            self.atomic_fail("stage-fsync")?;
            stage_file
                .sync_all()
                .map_err(|_| SecurityError::operation("atomic stage fsync failed"))?;
            self.atomic_fail("stage-fsynced")?;
            let staged_stat = fstat(stage_file.as_raw_fd())?;
            let staged = atomic_identity(bytes, &staged_stat);
            validate_new_atomic_identity(plan, &staged)?;
            fsync_directory(parent_fd.as_raw_fd()).map_err(|_| {
                SecurityError::Uncertain("atomic stage directory fsync failed".into())
            })?;
            let observed = observe_atomic_at(
                parent_fd.as_raw_fd(),
                &stage,
                plan.byte_length as usize,
                &plan.parent_directory,
            )?
            .ok_or_else(|| SecurityError::Uncertain("atomic stage disappeared".into()))?;
            if observed.atomic_identity() != staged {
                return Err(SecurityError::Uncertain(
                    "atomic stage changed before durable identity return".into(),
                ));
            }
            Ok(staged)
        })();
        if result.is_err() {
            if let Err(cleanup) = unlink_created_stage_exact(
                parent_fd.as_raw_fd(),
                &stage,
                created.st_dev,
                created.st_ino,
            ) {
                return Err(SecurityError::Uncertain(format!(
                    "atomic write failed before rename and exact stage cleanup failed: {cleanup}"
                )));
            }
        }
        result
    }

    fn commit_atomic_stage_internal(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: &AtomicFileIdentityV1,
    ) -> SecurityResult<AtomicWriteObservationV1> {
        plan.validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        validate_new_atomic_identity(plan, staged)?;
        let parent_fd = self.atomic_parent_fd(plan)?;
        let (_, target_name) = split_absolute(&plan.target_path)?;
        let (_, stage_name) = split_absolute(&plan.staging_path)?;
        let target = cstring(target_name.as_bytes())?;
        let stage = cstring(stage_name.as_bytes())?;
        validate_absolute_parent_identity(
            &self.paths.resolve(&plan.parent_directory.path)?,
            parent_fd.as_raw_fd(),
            &plan.parent_directory,
        )?;
        let staged_before = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &stage,
            plan.byte_length as usize,
            &plan.parent_directory,
        )?
        .ok_or_else(|| SecurityError::Uncertain("journaled atomic stage disappeared".into()))?;
        if staged_before.atomic_identity() != *staged {
            return Err(SecurityError::Uncertain(
                "journaled atomic stage identity changed before commit".into(),
            ));
        }
        let before = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target,
            plan.byte_length.max(expected_atomic_length(plan)) as usize,
            &plan.parent_directory,
        )?;
        validate_expected_atomic_target(plan, before.as_ref())?;

        #[cfg(test)]
        if let Some(mut hook) = self.atomic_pre_rename_hook.take() {
            hook(plan);
        }

        let flags = match plan.operation {
            AtomicWriteKindV1::NoReplace => libc::RENAME_NOREPLACE,
            AtomicWriteKindV1::Exchange => libc::RENAME_EXCHANGE,
        };
        self.atomic_fail("rename")?;
        if let Err(error) = renameat2(
            parent_fd.as_raw_fd(),
            &stage,
            parent_fd.as_raw_fd(),
            &target,
            flags,
        ) {
            let stage_after = observe_atomic_at(
                parent_fd.as_raw_fd(),
                &stage,
                plan.byte_length as usize,
                &plan.parent_directory,
            );
            let target_after = observe_atomic_at(
                parent_fd.as_raw_fd(),
                &target,
                howy_common::provisioning::MAX_JOURNAL_BYTES,
                &plan.parent_directory,
            );
            let definitely_not_renamed = stage_after.as_ref().is_ok_and(|stage| {
                stage
                    .as_ref()
                    .is_some_and(|stage| stage.atomic_identity() == *staged)
            }) && target_after
                .as_ref()
                .is_ok_and(|target| validate_expected_atomic_target(plan, target.as_ref()).is_ok());
            if definitely_not_renamed {
                return Err(error);
            }
            return Err(SecurityError::Uncertain(
                "atomic rename reported failure with indeterminate post-state".into(),
            ));
        }
        self.atomic_fail("renamed")
            .map_err(|_| SecurityError::Uncertain("injected failure after atomic rename".into()))?;

        validate_absolute_parent_identity(
            &self.paths.resolve(&plan.parent_directory.path)?,
            parent_fd.as_raw_fd(),
            &plan.parent_directory,
        )
        .map_err(|_| {
            SecurityError::Uncertain("absolute parent path changed across atomic rename".into())
        })?;

        let target_observed = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target,
            howy_common::provisioning::MAX_JOURNAL_BYTES,
            &plan.parent_directory,
        )
        .map_err(|_| SecurityError::Uncertain("atomic target was unsafe after rename".into()))?
        .ok_or_else(|| SecurityError::Uncertain("atomic target missing after rename".into()))?;
        let backup_observed = match plan.operation {
            AtomicWriteKindV1::NoReplace => {
                if fstatat_nofollow(parent_fd.as_raw_fd(), &stage)?.is_some() {
                    return Err(SecurityError::Uncertain(
                        "atomic no-replace stage remained after rename".into(),
                    ));
                }
                None
            }
            AtomicWriteKindV1::Exchange => Some(
                observe_atomic_at(
                    parent_fd.as_raw_fd(),
                    &stage,
                    howy_common::provisioning::MAX_JOURNAL_BYTES,
                    &plan.parent_directory,
                )
                .map_err(|_| {
                    SecurityError::Uncertain("atomic backup was unsafe after exchange".into())
                })?
                .ok_or_else(|| SecurityError::Uncertain("atomic exchange backup missing".into()))?,
            ),
        };
        let observation = AtomicWriteObservationV1 {
            target: target_observed.atomic_identity(),
            backup: backup_observed.map(|file| file.atomic_identity()),
        };
        observation.validate_for_plan(plan).map_err(|_| {
            SecurityError::Uncertain("post-rename target or backup identity mismatch".into())
        })?;
        if observation.target != *staged {
            return Err(SecurityError::Uncertain(
                "committed target differs from the durably recorded stage".into(),
            ));
        }
        self.atomic_fail("directory-fsync").map_err(|_| {
            SecurityError::Uncertain("injected atomic directory fsync failure".into())
        })?;
        fsync_directory(parent_fd.as_raw_fd())
            .map_err(|_| SecurityError::Uncertain("atomic rename directory fsync failed".into()))?;
        self.atomic_fail("directory-fsynced").map_err(|_| {
            SecurityError::Uncertain("injected failure after atomic directory fsync".into())
        })?;
        Ok(observation)
    }

    fn run(&self, spec: &CommandSpec, input: &[u8]) -> SecurityResult<ProcessOutput> {
        let deadline = Instant::now()
            .checked_add(spec.deadline)
            .ok_or_else(|| SecurityError::operation("child deadline overflow"))?;
        self.run_until(spec, input, deadline, true, None)
    }

    fn run_allow_failure(&self, spec: &CommandSpec, input: &[u8]) -> SecurityResult<ProcessOutput> {
        let deadline = Instant::now()
            .checked_add(spec.deadline)
            .ok_or_else(|| SecurityError::operation("child deadline overflow"))?;
        self.run_until(spec, input, deadline, false, None)
    }

    fn run_until(
        &self,
        spec: &CommandSpec,
        input: &[u8],
        deadline: Instant,
        require_success: bool,
        transient_cleanup: Option<&str>,
    ) -> SecurityResult<ProcessOutput> {
        validate_executable(&spec.executable)?;
        if input.len() != spec.stdin_bytes {
            return Err(SecurityError::operation("child stdin length mismatch"));
        }
        if Instant::now() >= deadline {
            return Err(SecurityError::operation("child deadline already elapsed"));
        }
        let preferred_reserve = if transient_cleanup.is_some() {
            TRANSIENT_CLEANUP_RESERVE
        } else {
            CHILD_REAP_RESERVE
        };
        let reserve = preferred_reserve.min(spec.deadline / 4);
        let work_deadline = deadline.checked_sub(reserve).unwrap_or(deadline);
        let mut command = Command::new(&spec.executable);
        command.args(&spec.arguments);
        if spec.clear_environment {
            command.env_clear();
        }
        command
            .stdin(if input.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| SecurityError::operation("absolute child spawn failed"))?;
        let process_group = libc::pid_t::try_from(child.id())
            .map_err(|_| SecurityError::operation("child PID overflow"))?;
        if process_group <= 1
            || process_group == unsafe { libc::getpgrp() }
            || unsafe { libc::getpgid(process_group) } != process_group
            || unsafe { libc::getsid(process_group) } != process_group
        {
            let _ = unsafe { libc::kill(process_group, libc::SIGKILL) };
            let _ = reap_until(&mut child, deadline);
            return Err(SecurityError::operation(
                "child did not enter a dedicated process session",
            ));
        }
        let setup = (|| {
            let stdin = child.stdin.take();
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| SecurityError::operation("child stdout pipe missing"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| SecurityError::operation("child stderr pipe missing"))?;
            set_nonblocking(stdout.as_raw_fd())?;
            set_nonblocking(stderr.as_raw_fd())?;
            if let Some(stdin) = stdin.as_ref() {
                set_nonblocking(stdin.as_raw_fd())?;
            }
            Ok((stdin, stdout, stderr))
        })();
        let (mut stdin, mut stdout, mut stderr) = match setup {
            Ok(pipes) => pipes,
            Err(error) => {
                let cleanup_deadline = deadline.checked_sub(CHILD_REAP_RESERVE).unwrap_or(deadline);
                terminate_process_group(process_group);
                drop(child.stdin.take());
                drop(child.stdout.take());
                drop(child.stderr.take());
                if let Some(unit) = transient_cleanup {
                    let _ = self.cleanup_transient_until(unit, cleanup_deadline);
                }
                let _ = reap_until(&mut child, deadline);
                return Err(error);
            }
        };

        let mut input_offset = 0usize;
        let mut stdout_bytes = Zeroizing::new(Vec::new());
        let mut stderr_bytes = Zeroizing::new(Vec::new());
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut status = None;
        let failure = loop {
            if let Some(pipe) = stdin.as_mut() {
                match write_nonblocking(pipe, &input[input_offset..]) {
                    Ok(written) => {
                        input_offset += written;
                        if input_offset == input.len() {
                            stdin = None;
                        }
                    }
                    Err(error) => break Some(error),
                }
            }
            if !stdout_eof {
                match drain_nonblocking(&mut stdout, spec.stdout_cap, &mut stdout_bytes) {
                    Ok(eof) => stdout_eof = eof,
                    Err(error) => break Some(error),
                }
            }
            if !stderr_eof {
                match drain_nonblocking(&mut stderr, spec.stderr_cap, &mut stderr_bytes) {
                    Ok(eof) => stderr_eof = eof,
                    Err(error) => break Some(error),
                }
            }
            if status.is_none() {
                match child_exited_without_reaping(&child) {
                    Ok(true) => {
                        // Keep the exited leader unreaped until the complete
                        // dedicated group has been signalled. Its live PID/PGID
                        // identity prevents a reused process group race.
                        terminate_process_group(process_group);
                        match child.try_wait() {
                            Ok(Some(observed)) => status = Some(observed),
                            Ok(None) | Err(_) => {
                                break Some(SecurityError::operation("child wait failed"));
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(error) => break Some(error),
                }
                if status.is_some() {
                    stdin = None;
                    if require_success
                        && let Some(observed_status) = status
                        && !observed_status.success()
                    {
                        break Some(SecurityError::operation(format!(
                            "child process failed with status {}; stderr was redacted ({} bytes captured)",
                            observed_status,
                            stderr_bytes.len()
                        )));
                    }
                }
            }
            if status.is_some() && stdout_eof && stderr_eof {
                break None;
            }
            if Instant::now() >= work_deadline {
                break Some(SecurityError::operation("child process deadline exceeded"));
            }
            thread::sleep(Duration::from_millis(1));
        };

        if let Some(error) = failure {
            terminate_process_group(process_group);
            drop(stdin.take());
            let cleanup_deadline = deadline.checked_sub(CHILD_REAP_RESERVE).unwrap_or(deadline);
            let cleanup_error = transient_cleanup
                .map(|unit| self.cleanup_transient_until(unit, cleanup_deadline))
                .and_then(Result::err);
            drop(stdout);
            drop(stderr);
            let reaped = reap_until(&mut child, deadline)?;
            let mut message = error.to_string();
            if let Some(cleanup_error) = cleanup_error {
                message.push_str("; readiness transient cleanup failed: ");
                message.push_str(&cleanup_error.to_string());
            }
            if reaped.is_none() {
                let _ = thread::Builder::new()
                    .name("howy-child-reaper".into())
                    .spawn(move || {
                        terminate_process_group(process_group);
                        let _ = child.wait();
                    });
                message.push_str("; child leader reap was deferred after the absolute deadline");
            }
            return Err(SecurityError::operation(message));
        }
        let status = status.ok_or_else(|| SecurityError::operation("child status missing"))?;
        debug_assert!(!require_success || status.success());
        Ok(ProcessOutput {
            stdout: std::mem::take(&mut *stdout_bytes),
            stderr: std::mem::take(&mut *stderr_bytes),
            status,
        })
    }

    fn systemctl(&self, arguments: impl IntoIterator<Item = String>) -> SecurityResult<Vec<u8>> {
        let spec = systemctl_command(arguments);
        self.run(&spec, &[]).map(ProcessOutput::into_stdout)
    }

    fn systemctl_until(
        &self,
        arguments: impl IntoIterator<Item = String>,
        deadline: Instant,
        require_success: bool,
    ) -> SecurityResult<ProcessOutput> {
        let spec = systemctl_command(arguments);
        let command_deadline = Instant::now()
            .checked_add(spec.deadline)
            .map_or(deadline, |maximum| maximum.min(deadline));
        self.run_until(&spec, &[], command_deadline, require_success, None)
    }

    fn cleanup_transient_until(&self, unit: &str, deadline: Instant) -> SecurityResult<()> {
        if !valid_transient_unit_name(unit) {
            return Err(SecurityError::operation(
                "invalid readiness transient unit name",
            ));
        }
        cleanup_transient_with(unit, deadline, |arguments, operation_deadline| {
            self.systemctl_until(arguments, operation_deadline, false)
        })
    }

    fn query_unit(&self, kind: UnitKind) -> SecurityResult<UnitObservation> {
        let unit = unit_name(kind);
        let output = self.systemctl([
            "show".into(),
            unit.into(),
            "--property=LoadState".into(),
            "--property=ActiveState".into(),
            "--property=SubState".into(),
            "--property=UnitFileState".into(),
            "--property=Job".into(),
            "--all".into(),
        ])?;
        parse_unit_observation(kind, &output)
    }

    fn observe_effective_unit(&self, kind: UnitKind) -> SecurityResult<EffectiveUnitObservationV1> {
        let unit = unit_name(kind);
        let spec = effective_unit_show_command(unit);
        let first_output = self.run(&spec, &[])?.into_stdout();
        let first_show = parse_effective_show(kind, &first_output)?;
        let first_files = self.read_effective_files(kind, &first_show)?;

        let second_output = self.run(&spec, &[])?.into_stdout();
        if first_output != second_output {
            return Err(SecurityError::operation(
                "effective unit properties changed during observation",
            ));
        }
        let second_show = parse_effective_show(kind, &second_output)?;
        let second_files = self.read_effective_files(kind, &second_show)?;
        if first_files != second_files {
            return Err(SecurityError::operation(
                "effective unit files changed during observation",
            ));
        }
        build_effective_observation(kind, second_show, second_files)
    }

    fn read_effective_files(
        &self,
        kind: UnitKind,
        show: &EffectiveShow,
    ) -> SecurityResult<Vec<(String, ObservedFile)>> {
        validate_effective_paths(kind, show)?;
        let mut paths = Vec::with_capacity(1 + show.dropin_paths.len());
        paths.push(show.fragment_path.clone());
        paths.extend(show.dropin_paths.iter().cloned());
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let expected_permissions = if path == MODE1_DROPIN_PATH {
                0o600
            } else {
                0o644
            };
            let file = self
                .read_exact_file(&path, MAX_DROPIN_BYTES)?
                .ok_or_else(|| SecurityError::operation("effective unit file disappeared"))?;
            file.validate_regular(0, 0, expected_permissions)?;
            files.push((path, file));
        }
        Ok(files)
    }

    fn inspect_host_secret_metadata(&self) -> SecurityResult<bool> {
        const DIRECTORY: &str = "/var/lib/systemd";
        const NAME: &[u8] = b"credential.secret";
        let resolved_directory = self.paths.resolve(DIRECTORY)?;
        let Some(directory) =
            open_directory_path(&self.paths.root, &resolved_directory, false, 0o755)?
        else {
            return Ok(false);
        };
        validate_root_directory(directory.as_raw_fd(), 0o755)?;
        let name = cstring(NAME)?;
        let Some(path_stat) = fstatat_nofollow(directory.as_raw_fd(), &name)? else {
            return Ok(false);
        };
        let open_once = || -> SecurityResult<libc::stat> {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(SecurityError::operation(
                    "credential host secret changed during inspection",
                ));
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
            fstat(descriptor.as_raw_fd())
        };
        let first = open_once()?;
        let second_path = fstatat_nofollow(directory.as_raw_fd(), &name)?.ok_or_else(|| {
            SecurityError::operation("credential host secret disappeared during inspection")
        })?;
        let second = open_once()?;
        validate_host_secret_observations(Some(&path_stat), &[&first, &second_path, &second])
    }

    fn observe_daemon_identity(&self) -> SecurityResult<DaemonVerifierIdentityV1> {
        validate_executable_path(&self.paths.resolve(command::HOWYD)?)?;
        let binary = self
            .read_exact_file(command::HOWYD, EXECUTABLE_MAX)?
            .ok_or_else(|| SecurityError::operation("howyd is missing"))?;
        binary.validate_regular(0, 0, binary.metadata.permissions)?;
        if binary.metadata.permissions & 0o022 != 0 || binary.metadata.permissions & 0o111 == 0 {
            return Err(SecurityError::operation(
                "howyd executable metadata is unsafe",
            ));
        }
        let version = env!("CARGO_PKG_VERSION").to_owned();
        let build_identity = option_env!("HOWY_BUILD_ID")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("howy-{version}+cargo"));
        Ok(DaemonVerifierIdentityV1 {
            version,
            build_identity,
            binary_absolute_path: command::HOWYD.into(),
            binary_sha256: binary.sha256(),
        })
    }

    fn inventory_mode1(&self) -> SecurityResult<NamespaceInventoryV1> {
        let resolved_namespace = self.paths.resolve(MODE1_NAMESPACE_PATH)?;
        let directory =
            open_directory_path(&self.paths.root, &resolved_namespace, false, 0o700)?
                .ok_or_else(|| SecurityError::operation("Mode 1 namespace directory is missing"))?;
        let directory_stat = fstat(directory.as_raw_fd())?;
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(SecurityError::operation(
                "namespace descriptor duplicate failed",
            ));
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            unsafe { libc::close(duplicate) };
            return Err(SecurityError::operation(
                "namespace descriptor iteration failed",
            ));
        }
        let mut entries = Vec::new();
        let result = (|| {
            loop {
                unsafe { *libc::__errno_location() = 0 };
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    if unsafe { *libc::__errno_location() } != 0 {
                        return Err(SecurityError::operation("namespace iteration failed"));
                    }
                    break;
                }
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                if name.is_empty()
                    || name.len() > MAX_NAMESPACE_NAME_BYTES
                    || entries.len() >= MAX_NAMESPACE_ENTRIES
                {
                    return Err(SecurityError::operation("namespace entry cap exceeded"));
                }
                let name_c = cstring(name)?;
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC
                            | libc::O_NONBLOCK
                            | libc::O_NOATIME,
                    )
                };
                if fd < 0 {
                    return Err(SecurityError::operation("namespace entry open failed"));
                }
                let mut file = unsafe { File::from_raw_fd(fd) };
                let before = fstat(file.as_raw_fd())?;
                let file_type = namespace_type(&before);
                let size = u64::try_from(before.st_size)
                    .map_err(|_| SecurityError::operation("namespace entry size invalid"))?;
                if size > MAX_NAMESPACE_CIPHERTEXT_BYTES {
                    return Err(SecurityError::operation("namespace entry exceeds byte cap"));
                }
                let prior_total = entries
                    .iter()
                    .try_fold(0u64, |total, entry: &NamespaceFingerprintEntry| {
                        total.checked_add(entry.size)
                    });
                if prior_total
                    .and_then(|total| total.checked_add(size))
                    .is_none_or(|total| total > MAX_NAMESPACE_TOTAL_BYTES)
                {
                    return Err(SecurityError::operation("namespace total exceeds byte cap"));
                }
                let mut hasher = Sha256::new();
                let mut read_total = 0u64;
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    let count = file
                        .read(&mut buffer)
                        .map_err(|_| SecurityError::operation("namespace entry read failed"))?;
                    if count == 0 {
                        break;
                    }
                    read_total = read_total
                        .checked_add(count as u64)
                        .ok_or_else(|| SecurityError::operation("namespace byte overflow"))?;
                    hasher.update(&buffer[..count]);
                }
                let after = fstat(file.as_raw_fd())?;
                if file_identity(&before) != file_identity(&after) || read_total != size {
                    return Err(SecurityError::operation(
                        "namespace entry changed while read",
                    ));
                }
                let classification =
                    classify_mode1_namespace_entry(name, file_type, before.st_nlink);
                entries.push(NamespaceFingerprintEntry {
                    name: name.to_vec(),
                    file_type,
                    uid: before.st_uid,
                    gid: before.st_gid,
                    mode: before.st_mode & 0o7777,
                    nlink: before.st_nlink,
                    size,
                    ciphertext_sha256: Sha256Digest::from_array(hasher.finalize().into()),
                    classification,
                });
            }
            Ok(())
        })();
        unsafe { libc::closedir(stream) };
        result?;
        let after_directory = fstat(directory.as_raw_fd())?;
        if file_identity(&directory_stat) != file_identity(&after_directory) {
            return Err(SecurityError::operation("namespace directory changed"));
        }
        Ok(NamespaceInventoryV1 {
            directory: NamespaceDirectoryMetadata {
                path: MODE1_NAMESPACE_PATH.into(),
                uid: directory_stat.st_uid,
                gid: directory_stat.st_gid,
                mode: directory_stat.st_mode & 0o7777,
                nlink: directory_stat.st_nlink,
            },
            entries,
        })
    }

    fn plan_required_directory(
        &self,
        production_path: &str,
        permissions: u32,
    ) -> SecurityResult<SecurityDirectoryRecordV1> {
        let production_parent = Path::new(production_path)
            .parent()
            .ok_or_else(|| SecurityError::operation("required directory has no parent"))?;
        let resolved = self.paths.resolve(production_path)?;
        let (resolved_parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?,
        )?;
        let parent_fd = open_directory_path_bound(resolved_parent)?;
        let parent_stat = fstat(parent_fd.as_raw_fd())?;
        if (parent_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || parent_stat.st_uid != 0
            || parent_stat.st_gid != 0
            || parent_stat.st_mode & 0o022 != 0
            || parent_stat.st_nlink == 0
        {
            return Err(SecurityError::operation(
                "required directory parent metadata is unsafe",
            ));
        }
        let parent_directory = directory_identity(production_parent, &parent_stat)?;
        let name = cstring(name.as_bytes())?;
        let expected_directory = match fstatat_nofollow(parent_fd.as_raw_fd(), &name)? {
            None => None,
            Some(stat) => {
                if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                    || stat.st_uid != 0
                    || stat.st_gid != 0
                    || stat.st_mode & 0o7777 != permissions
                    || stat.st_nlink == 0
                {
                    return Err(SecurityError::operation(
                        "preexisting required directory metadata is unsafe",
                    ));
                }
                Some(directory_identity(Path::new(production_path), &stat)?)
            }
        };
        let intent = SecurityDirectoryRecordV1 {
            path: production_path.to_owned(),
            uid: 0,
            gid: 0,
            permissions,
            parent_directory,
            preexisted: expected_directory.is_some(),
            expected_directory,
            observed_directory: None,
        };
        intent
            .validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        Ok(intent)
    }

    fn realize_required_directory(
        &mut self,
        intent: &SecurityDirectoryRecordV1,
    ) -> SecurityResult<DirectoryIdentityV1> {
        intent
            .validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if intent.observed_directory.is_some() {
            return Err(SecurityError::operation(
                "directory create called after observation was persisted",
            ));
        }
        let resolved = self.paths.resolve(&intent.path)?;
        let (resolved_parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?,
        )?;
        let parent_fd = open_directory_path_bound(resolved_parent)?;
        let parent_stat = fstat(parent_fd.as_raw_fd())?;
        let production_parent = Path::new(&intent.path)
            .parent()
            .ok_or_else(|| SecurityError::operation("required directory has no parent"))?;
        let current_parent = directory_identity(production_parent, &parent_stat)?;
        let name = cstring(name.as_bytes())?;
        let target_before = fstatat_nofollow(parent_fd.as_raw_fd(), &name)?;
        let created_reconciliation = !intent.preexisted && target_before.is_some();
        if !directory_identity_matches(
            &current_parent,
            &intent.parent_directory,
            created_reconciliation,
        ) {
            return Err(SecurityError::Uncertain(
                "required directory parent changed after journaled intent".into(),
            ));
        }

        if let Some(expected) = &intent.expected_directory {
            let stat = target_before.ok_or_else(|| {
                SecurityError::Uncertain("preexisting required directory disappeared".into())
            })?;
            let observed = directory_identity(Path::new(&intent.path), &stat)?;
            if observed != *expected {
                return Err(SecurityError::Uncertain(
                    "preexisting required directory changed after intent".into(),
                ));
            }
            return Ok(observed);
        }

        if target_before.is_none() {
            if unsafe {
                libc::mkdirat(
                    parent_fd.as_raw_fd(),
                    name.as_ptr(),
                    intent.permissions as libc::mode_t,
                )
            } != 0
            {
                return Err(SecurityError::operation(
                    "journaled required directory creation failed",
                ));
            }
            self.atomic_fail("directory-mkdir-before-metadata")?;
        }
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(SecurityError::Uncertain(
                "transaction-created directory could not be reopened".into(),
            ));
        }
        let directory = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fchown(directory.as_raw_fd(), intent.uid, intent.gid) } != 0
            || unsafe { libc::fchmod(directory.as_raw_fd(), intent.permissions as libc::mode_t) }
                != 0
        {
            return Err(SecurityError::Uncertain(
                "transaction-created directory metadata setup failed".into(),
            ));
        }
        fsync_directory(directory.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("transaction-created directory fsync failed".into())
        })?;
        let stat = fstat(directory.as_raw_fd())?;
        let observed = directory_identity(Path::new(&intent.path), &stat)?;
        if observed.object_type != FileObjectType::Directory
            || observed.uid != intent.uid
            || observed.gid != intent.gid
            || observed.permissions != intent.permissions
        {
            return Err(SecurityError::Uncertain(
                "transaction-created directory observation differs from intent".into(),
            ));
        }
        fsync_directory(parent_fd.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("required directory parent fsync failed".into())
        })?;
        Ok(observed)
    }
}

fn directory_identity_matches(
    observed: &DirectoryIdentityV1,
    expected: &DirectoryIdentityV1,
    allow_created_child: bool,
) -> bool {
    observed.path == expected.path
        && observed.object_type == expected.object_type
        && observed.device_id == expected.device_id
        && observed.inode == expected.inode
        && observed.uid == expected.uid
        && observed.gid == expected.gid
        && observed.permissions == expected.permissions
        && (observed.link_count == expected.link_count
            || allow_created_child
                && expected
                    .link_count
                    .checked_add(1)
                    .is_some_and(|links| observed.link_count == links))
}

fn validate_effective_paths(kind: UnitKind, show: &EffectiveShow) -> SecurityResult<()> {
    let expected_fragment = match kind {
        UnitKind::Service => BASE_SERVICE_UNIT_PATH,
        UnitKind::Socket => BASE_SOCKET_UNIT_PATH,
    };
    if show.fragment_path != expected_fragment {
        return Err(SecurityError::operation(
            "effective unit fragment path is noncanonical",
        ));
    }
    match kind {
        UnitKind::Service
            if !show.dropin_paths.is_empty()
                && show.dropin_paths != [MODE1_DROPIN_PATH.to_owned()] =>
        {
            return Err(SecurityError::operation(
                "unknown or later service drop-in can shadow security policy",
            ));
        }
        UnitKind::Socket if !show.dropin_paths.is_empty() => {
            return Err(SecurityError::operation(
                "socket drop-ins are not permitted by the security contract",
            ));
        }
        _ => {}
    }
    Ok(())
}

impl Default for RealSecurityRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityRuntime for RealSecurityRuntime {
    fn require_root(&mut self) -> SecurityResult<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(SecurityError::Refused(
                "This command requires root. Run with: sudo howy security ...".into(),
            ));
        }
        Ok(())
    }

    fn acquire_lock(&mut self) -> SecurityResult<()> {
        if self.lock.is_some() {
            return Ok(());
        }
        let lock_path = self.paths.resolve(SECURITY_LOCK_PATH)?;
        let lock_text = lock_path
            .to_str()
            .ok_or_else(|| SecurityError::operation("rooted lock path is not UTF-8"))?;
        let (lock_parent, lock_name) = split_absolute(lock_text)?;
        let directory = open_directory_path(&self.paths.root, lock_parent, false, 0o755)?
            .ok_or_else(|| SecurityError::operation("security lock directory missing"))?;
        validate_root_directory(directory.as_raw_fd(), 0o755)?;
        let name = cstring(lock_name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(SecurityError::operation("security lock open failed"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let stat = fstat(file.as_raw_fd())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_nlink != 1
            || stat.st_mode & 0o7777 != 0o600
            || Path::new(SECURITY_LOCK_PATH).file_name() != Some(OsStr::new("howy-security.lock"))
        {
            return Err(SecurityError::operation("security lock metadata is unsafe"));
        }
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
                || Instant::now() >= deadline
            {
                return Err(SecurityError::Refused(
                    "another security transaction owns the lock".into(),
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        file.sync_all()
            .map_err(|_| SecurityError::operation("security lock fsync failed"))?;
        fsync_directory(directory.as_raw_fd())?;
        self.lock = Some(file);
        Ok(())
    }

    fn require_systemd_261(&mut self) -> SecurityResult<()> {
        let spec = CommandSpec {
            executable: command::SYSTEMCTL.into(),
            arguments: vec!["--version".into()],
            clear_environment: true,
            stdin_bytes: 0,
            stdout_cap: 4096,
            stderr_cap: 4096,
            deadline: Duration::from_secs(5),
        };
        let output = self.run(&spec, &[])?.into_stdout();
        let text = std::str::from_utf8(&output)
            .map_err(|_| SecurityError::operation("systemd version output is invalid"))?;
        let version = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("systemd "))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| SecurityError::operation("systemd version could not be parsed"))?;
        if version < 261 {
            return Err(SecurityError::Refused(
                "security provisioning requires systemd 261 or newer".into(),
            ));
        }
        for executable in [
            command::SYSTEMD_CREDS,
            command::SYSTEMD_RUN,
            command::SYSTEMCTL,
            command::HOWYD,
        ] {
            validate_executable(executable)?;
        }
        Ok(())
    }

    fn transaction_id(&mut self) -> SecurityResult<String> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| SecurityError::operation("transaction entropy failed"))?;
        Ok(format!("txn-{}", hex(&bytes)))
    }

    fn generate_key(&mut self) -> SecurityResult<Box<dyn SecretKeyMaterial>> {
        GuardedKey::generate().map(|key| Box::new(key) as Box<dyn SecretKeyMaterial>)
    }

    fn read_file(&mut self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>> {
        self.read_exact_file(path, maximum)
    }

    fn observe_atomic_target(
        &mut self,
        path: &str,
        maximum: usize,
    ) -> SecurityResult<AtomicTargetObservation> {
        let production_parent = Path::new(path)
            .parent()
            .ok_or_else(|| SecurityError::operation("atomic path has no parent"))?;
        let resolved = self.paths.resolve(path)?;
        let (parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?,
        )?;
        let parent_fd = open_directory_path_bound(parent)?;
        let parent_stat = fstat(parent_fd.as_raw_fd())?;
        let parent_directory = directory_identity(production_parent, &parent_stat)?;
        let name = cstring(name.as_bytes())?;
        let target = observe_atomic_at(parent_fd.as_raw_fd(), &name, maximum, &parent_directory)?;
        Ok(AtomicTargetObservation {
            parent_directory,
            target,
        })
    }

    fn create_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        bytes: &[u8],
    ) -> SecurityResult<AtomicFileIdentityV1> {
        self.create_atomic_stage_internal(plan, bytes)
    }

    fn commit_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: &AtomicFileIdentityV1,
    ) -> SecurityResult<AtomicWriteObservationV1> {
        self.commit_atomic_stage_internal(plan, staged)
    }

    fn reconcile_atomic_write(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: Option<&AtomicFileIdentityV1>,
    ) -> SecurityResult<AtomicWriteReconciliation> {
        let parent_fd = self.atomic_parent_fd(plan)?;
        let (_, target_name) = split_absolute(&plan.target_path)?;
        let (_, stage_name) = split_absolute(&plan.staging_path)?;
        let target_name = cstring(target_name.as_bytes())?;
        let stage_name = cstring(stage_name.as_bytes())?;
        let target = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            plan.byte_length.max(expected_atomic_length(plan)) as usize,
            &plan.parent_directory,
        )?;
        let stage = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &stage_name,
            plan.byte_length.max(expected_atomic_length(plan)) as usize,
            &plan.parent_directory,
        )?;
        let target_identity = target.as_ref().map(ObservedFile::atomic_identity);
        let stage_identity = stage.as_ref().map(ObservedFile::atomic_identity);
        let target_is_old = match (&plan.expected_target, &target_identity) {
            (AtomicExpectedTargetV1::Absent, None) => true,
            (AtomicExpectedTargetV1::Present(expected), Some(observed)) => expected == observed,
            _ => false,
        };
        let stage_is_old = match (&plan.expected_target, &stage_identity) {
            (AtomicExpectedTargetV1::Present(expected), Some(observed)) => expected == observed,
            _ => false,
        };

        let Some(staged) = staged else {
            if target_is_old && stage.is_none() {
                return Ok(AtomicWriteReconciliation::NotCommitted);
            }
            return Err(SecurityError::Uncertain(
                "atomic recovery retained a stage without a durably recorded identity".into(),
            ));
        };
        validate_new_atomic_identity(plan, staged)?;
        if target_identity.as_ref() == Some(staged) {
            let observation = AtomicWriteObservationV1 {
                target: target_identity.expect("checked present"),
                backup: if plan.operation == AtomicWriteKindV1::Exchange && stage_is_old {
                    stage_identity
                } else if plan.operation == AtomicWriteKindV1::NoReplace && stage.is_none() {
                    None
                } else {
                    return Err(SecurityError::Uncertain(
                        "atomic recovery found an unexpected post-rename stage".into(),
                    ));
                },
            };
            observation.validate_for_plan(plan).map_err(|_| {
                SecurityError::Uncertain("atomic committed observation is inconsistent".into())
            })?;
            return Ok(AtomicWriteReconciliation::Committed(observation));
        }
        if target_is_old && stage_identity.as_ref() == Some(staged) {
            self.remove_file_exact(
                &plan.staging_path,
                &stage_identity.expect("checked present"),
            )?;
            return Ok(AtomicWriteReconciliation::NotCommitted);
        }
        Err(SecurityError::Uncertain(
            "atomic recovery found target/stage identities outside the journaled plan".into(),
        ))
    }

    fn remove_atomic_backup(
        &mut self,
        plan: &AtomicWritePlanV1,
        observation: &AtomicWriteObservationV1,
    ) -> SecurityResult<()> {
        observation
            .validate_for_plan(plan)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let backup = observation.backup.as_ref().ok_or_else(|| {
            SecurityError::operation("atomic observation has no backup to remove")
        })?;
        let parent_fd = self.atomic_parent_fd(plan)?;
        let (_, target_name) = split_absolute(&plan.target_path)?;
        let (_, backup_name) = split_absolute(
            plan.backup_path
                .as_deref()
                .ok_or_else(|| SecurityError::operation("atomic backup path is missing"))?,
        )?;
        let target_name = cstring(target_name.as_bytes())?;
        let backup_name = cstring(backup_name.as_bytes())?;
        let target = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            plan.byte_length as usize,
            &plan.parent_directory,
        )?
        .ok_or_else(|| {
            SecurityError::Uncertain("atomic target disappeared before cleanup".into())
        })?;
        let live_backup = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &backup_name,
            backup.byte_length as usize,
            &plan.parent_directory,
        )?;
        if target.atomic_identity() != observation.target {
            return Err(SecurityError::Uncertain(
                "atomic target changed before cleanup".into(),
            ));
        }
        let Some(live_backup) = live_backup else {
            return fsync_directory(parent_fd.as_raw_fd()).map_err(|_| {
                SecurityError::Uncertain(
                    "absent atomic backup directory fsync failed during recovery".into(),
                )
            });
        };
        if live_backup.atomic_identity() != *backup {
            return Err(SecurityError::Uncertain(
                "atomic backup changed before cleanup".into(),
            ));
        }
        self.atomic_fail("backup-unlink")?;
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), backup_name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::Uncertain(
                "exact atomic backup unlink failed".into(),
            ));
        }
        self.atomic_fail("backup-unlinked").map_err(|_| {
            SecurityError::Uncertain("injected failure after atomic backup unlink".into())
        })?;
        self.atomic_fail("backup-fsync")?;
        fsync_directory(parent_fd.as_raw_fd())
            .map_err(|_| SecurityError::Uncertain("atomic backup directory fsync failed".into()))?;
        self.atomic_fail("backup-fsynced").map_err(|_| {
            SecurityError::Uncertain("injected failure after atomic backup fsync".into())
        })
    }

    fn remove_file_exact(
        &mut self,
        path: &str,
        expected: &AtomicFileIdentityV1,
    ) -> SecurityResult<()> {
        expected
            .validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let production_parent = Path::new(path)
            .parent()
            .ok_or_else(|| SecurityError::operation("exact path has no parent"))?;
        let resolved = self.paths.resolve(path)?;
        let (parent, name) = split_absolute(
            resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?,
        )?;
        let parent_fd = open_directory_path_bound(parent)?;
        let parent_stat = fstat(parent_fd.as_raw_fd())?;
        let parent_identity = directory_identity(production_parent, &parent_stat)?;
        let name = cstring(name.as_bytes())?;
        let live = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &name,
            expected.byte_length as usize,
            &parent_identity,
        )?
        .ok_or_else(|| SecurityError::operation("exact file disappeared before unlink"))?;
        if live.atomic_identity() != *expected {
            return Err(SecurityError::Uncertain(
                "exact file identity changed before unlink".into(),
            ));
        }
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::operation("exact file unlink failed"));
        }
        fsync_directory(parent_fd.as_raw_fd())
    }

    fn plan_security_directory(
        &mut self,
        path: &str,
        permissions: u32,
    ) -> SecurityResult<SecurityDirectoryRecordV1> {
        self.plan_required_directory(path, permissions)
    }

    fn ensure_security_directory(
        &mut self,
        intent: &SecurityDirectoryRecordV1,
    ) -> SecurityResult<DirectoryIdentityV1> {
        self.realize_required_directory(intent)
    }

    fn verify_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        howy_common::provisioning::validate_security_directory_records(directories)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        for expected in directories {
            let resolved = self.paths.resolve(&expected.path)?;
            let directory =
                open_directory_path(&self.paths.root, &resolved, false, expected.permissions)?
                    .ok_or_else(|| {
                        SecurityError::Uncertain("required directory disappeared".into())
                    })?;
            let stat = fstat(directory.as_raw_fd())?;
            let observed = directory_identity(Path::new(&expected.path), &stat)?;
            let journaled = expected.observed_directory.as_ref().ok_or_else(|| {
                SecurityError::Uncertain("required directory observation is missing".into())
            })?;
            if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || stat.st_uid != expected.uid
                || stat.st_gid != expected.gid
                || stat.st_mode & 0o7777 != expected.permissions
                || observed.device_id != journaled.device_id
                || observed.inode != journaled.inode
            {
                return Err(SecurityError::Uncertain(
                    "required directory differs from the journaled identity".into(),
                ));
            }
        }
        Ok(())
    }

    fn rollback_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        howy_common::provisioning::validate_security_directory_records(directories)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        for record in directories.iter().rev().filter(|record| !record.preexisted) {
            let observed = record.observed_directory.as_ref().ok_or_else(|| {
                SecurityError::Uncertain("created directory observation is missing".into())
            })?;
            let resolved = self.paths.resolve(&record.path)?;
            let resolved_text = resolved
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted path is not UTF-8"))?;
            let (parent, name) = split_absolute(resolved_text)?;
            let Some(parent_fd) = open_directory_path(&self.paths.root, parent, false, 0o755)?
            else {
                continue;
            };
            let name = cstring(name.as_bytes())?;
            let Some(stat) = fstatat_nofollow(parent_fd.as_raw_fd(), &name)? else {
                continue;
            };
            if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || stat.st_dev != observed.device_id
                || stat.st_ino != observed.inode
                || stat.st_uid != record.uid
                || stat.st_gid != record.gid
                || stat.st_mode & 0o7777 != record.permissions
            {
                return Err(SecurityError::Uncertain(
                    "transaction-created directory identity changed before rollback".into(),
                ));
            }
            if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
                ) {
                    continue;
                }
                return Err(SecurityError::operation(
                    "transaction-created directory rollback failed",
                ));
            }
            fsync_directory(parent_fd.as_raw_fd())?;
        }
        Ok(())
    }

    fn create_guard(
        &mut self,
        transaction_id: &str,
        expected: Option<&TransactionGuardIdentityV1>,
    ) -> SecurityResult<TransactionGuardIdentityV1> {
        let content = TransactionGuardV1::new(transaction_id)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let bytes = content
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let existing = self.read_exact_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?;
        let recreated = existing.is_none();
        let observed = match existing {
            Some(guard) => guard,
            None => self.write_control_direct(SECURITY_TRANSACTION_GUARD_PATH, &bytes, 0o600)?,
        };
        observed.validate_regular(0, 0, 0o600)?;
        if observed.bytes != bytes {
            return Err(SecurityError::Uncertain(
                "a different transaction guard exists and was retained".into(),
            ));
        }
        let identity = TransactionGuardIdentityV1::new(transaction_id, observed.atomic_identity())
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if !recreated && expected.is_some_and(|expected| expected != &identity) {
            return Err(SecurityError::Uncertain(
                "transaction guard was replaced and was retained".into(),
            ));
        }
        Ok(identity)
    }

    fn remove_guard(
        &mut self,
        transaction_id: &str,
        expected: &TransactionGuardIdentityV1,
    ) -> SecurityResult<()> {
        expected
            .validate(transaction_id)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let live = self
            .read_exact_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?
            .ok_or_else(|| SecurityError::Uncertain("transaction guard disappeared".into()))?;
        let parsed = TransactionGuardV1::parse(&live.bytes)
            .map_err(|_| SecurityError::Uncertain("transaction guard content changed".into()))?;
        let identity =
            TransactionGuardIdentityV1::new(&parsed.transaction_id, live.atomic_identity())
                .map_err(|_| {
                    SecurityError::Uncertain("transaction guard identity is invalid".into())
                })?;
        if &identity != expected {
            return Err(SecurityError::Uncertain(
                "transaction guard was replaced and was retained".into(),
            ));
        }
        self.remove_file_exact(SECURITY_TRANSACTION_GUARD_PATH, &expected.file)
    }

    fn load_journal(&mut self) -> SecurityResult<Option<ObservedFile>> {
        let (parent_fd, parent, target_name) = self.journal_parent()?;
        let target = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            MAX_JOURNAL_BYTES,
            &parent,
        )?;
        let candidates = self.journal_stage_candidates(parent_fd.as_raw_fd(), &parent)?;
        let Some(target) = target else {
            if candidates.is_empty() {
                return Ok(None);
            }
            if candidates.len() != 1 {
                return Err(SecurityError::Uncertain(
                    "multiple orphan journal stages were retained".into(),
                ));
            }
            return Err(SecurityError::Uncertain(
                "orphan journal stage has no durably bound created identity and was retained"
                    .into(),
            ));
        };
        target.validate_regular(0, 0, 0o600)?;
        let target_parsed = parsed_journal(&target.bytes)?;
        if candidates.is_empty() {
            return Ok(Some(target));
        }
        if candidates.len() != 1 {
            return Err(SecurityError::Uncertain(
                "multiple journal stages were retained".into(),
            ));
        }
        let (stage_name, stage) = &candidates[0];
        if self
            .journal_stage_name(target_parsed.staging_path())?
            .as_c_str()
            != stage_name.as_c_str()
        {
            return Err(SecurityError::Uncertain(
                "journal stage belongs to another transaction".into(),
            ));
        }
        stage.validate_regular(0, 0, 0o600)?;
        let stage_parsed = parsed_journal(&stage.bytes)?;
        if target_parsed.valid_next(&stage_parsed) {
            return Err(SecurityError::Uncertain(
                "pre-exchange journal stage identity was not durably bound and was retained".into(),
            ));
        }
        if stage_parsed.valid_next(&target_parsed)
            && target_parsed.prior_journal_identity() == Some(&stage.atomic_identity())
        {
            self.unlink_journal_entry_exact(parent_fd.as_raw_fd(), &parent, stage_name, stage)?;
            return Ok(Some(target));
        }
        Err(SecurityError::Uncertain(
            "journal target and stage are not adjacent owned generations".into(),
        ))
    }

    fn persist_journal(
        &mut self,
        prior: Option<&ObservedFile>,
        bytes: &[u8],
    ) -> SecurityResult<ObservedFile> {
        let incoming = parsed_journal(bytes)?;
        let prior_parsed = prior
            .map(|prior| parsed_journal(&prior.bytes))
            .transpose()?;
        match &prior_parsed {
            None if incoming.generation() != 1 => {
                return Err(SecurityError::Uncertain(
                    "initial journal generation is not one".into(),
                ));
            }
            Some(current) if !current.valid_next(&incoming) => {
                return Err(SecurityError::Uncertain(
                    "journal update is not the exact next owned generation".into(),
                ));
            }
            _ => {}
        }
        if incoming.prior_journal_identity() != prior.map(ObservedFile::atomic_identity).as_ref() {
            return Err(SecurityError::Uncertain(
                "journal generation does not bind the exact prior file identity".into(),
            ));
        }
        let (parent_fd, parent, target_name) = self.journal_parent()?;
        let stage_name = self.journal_stage_name(incoming.staging_path())?;
        let live_target = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            MAX_JOURNAL_BYTES,
            &parent,
        )?;
        match (prior, &live_target) {
            (None, None) => {}
            (Some(expected), Some(live)) if observed_control_matches(expected, live) => {}
            _ => {
                return Err(SecurityError::Uncertain(
                    "journal target differs from the exact prior observation".into(),
                ));
            }
        }
        if prior.is_none() {
            let target = self.create_journal_stage(
                parent_fd.as_raw_fd(),
                &parent,
                &target_name,
                bytes,
                false,
            )?;
            return Ok(target);
        }
        let stage =
            self.create_journal_stage(parent_fd.as_raw_fd(), &parent, &stage_name, bytes, true)?;
        self.atomic_fail("journal-stage-linked")?;
        #[cfg(test)]
        if let Some(mut hook) = self.journal_pre_exchange_hook.take() {
            hook();
        }
        let target_before = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            MAX_JOURNAL_BYTES,
            &parent,
        )?;
        let stage_before = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &stage_name,
            MAX_JOURNAL_BYTES,
            &parent,
        )?;
        if !optional_observed_control_matches(target_before.as_ref(), prior)
            || !stage_before
                .as_ref()
                .is_some_and(|live| observed_control_matches(live, &stage))
        {
            return Err(SecurityError::Uncertain(
                "journal target or stage was replaced before exchange".into(),
            ));
        }
        renameat2(
            parent_fd.as_raw_fd(),
            &stage_name,
            parent_fd.as_raw_fd(),
            &target_name,
            libc::RENAME_EXCHANGE,
        )?;
        fsync_directory(parent_fd.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("journal exchange directory fsync failed".into())
        })?;
        self.atomic_fail("journal-exchanged")?;
        let target_after = observe_atomic_at(
            parent_fd.as_raw_fd(),
            &target_name,
            MAX_JOURNAL_BYTES,
            &parent,
        )?
        .ok_or_else(|| SecurityError::Uncertain("journal target missing after exchange".into()))?;
        if !observed_control_matches(&target_after, &stage) {
            return Err(SecurityError::Uncertain(
                "journal target identity changed after exchange".into(),
            ));
        }
        if let Some(expected_backup) = prior {
            let backup = observe_atomic_at(
                parent_fd.as_raw_fd(),
                &stage_name,
                MAX_JOURNAL_BYTES,
                &parent,
            )?
            .ok_or_else(|| {
                SecurityError::Uncertain("journal backup missing after exchange".into())
            })?;
            if !observed_control_matches(&backup, expected_backup) {
                return Err(SecurityError::Uncertain(
                    "exchanged journal backup differs from the exact prior journal".into(),
                ));
            }
            self.atomic_fail("journal-before-backup-unlink")?;
            self.unlink_journal_entry_exact(parent_fd.as_raw_fd(), &parent, &stage_name, &backup)?;
        }
        Ok(target_after)
    }

    fn remove_journal(
        &mut self,
        transaction_id: &str,
        expected: &ObservedFile,
    ) -> SecurityResult<()> {
        let parsed = parsed_journal(&expected.bytes)?;
        if parsed.transaction_id() != transaction_id {
            return Err(SecurityError::Uncertain(
                "journal removal transaction identity mismatch".into(),
            ));
        }
        let reconciled = self
            .load_journal()?
            .ok_or_else(|| SecurityError::Uncertain("journal disappeared before removal".into()))?;
        if !observed_control_matches(&reconciled, expected) {
            return Err(SecurityError::Uncertain(
                "latest journal identity changed before removal".into(),
            ));
        }
        let (parent_fd, parent, target_name) = self.journal_parent()?;
        self.unlink_journal_entry_exact(parent_fd.as_raw_fd(), &parent, &target_name, expected)
    }

    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation> {
        self.query_unit(unit)
    }

    fn effective_unit_observation(
        &mut self,
        unit: UnitKind,
    ) -> SecurityResult<howy_common::provisioning::EffectiveUnitObservationV1> {
        self.observe_effective_unit(unit)
    }

    fn resolve_key_selection(&mut self, requested: KeySelection) -> SecurityResult<KeySelection> {
        if requested != KeySelection::Auto {
            return Ok(requested);
        }
        let probe = self.run_allow_failure(&tpm2_probe_command(), &[])?;
        if probe.status.success() {
            if !probe.stdout.is_empty() {
                return Err(SecurityError::operation(
                    "quiet TPM2 policy probe emitted unexpected output",
                ));
            }
            return Ok(KeySelection::Tpm2);
        }
        if probe.status.code().is_none() {
            return Err(SecurityError::operation(
                "TPM2 policy probe terminated by signal",
            ));
        }
        if self.inspect_host_secret_metadata()? {
            Ok(KeySelection::Host)
        } else {
            Err(SecurityError::Refused(
                "auto key selection found no complete TPM2 support and no pre-existing host secret"
                    .into(),
            ))
        }
    }

    fn host_secret_preexisting_secure(&mut self) -> SecurityResult<bool> {
        self.inspect_host_secret_metadata()
    }

    fn daemon_verifier_identity(
        &mut self,
    ) -> SecurityResult<howy_common::provisioning::DaemonVerifierIdentityV1> {
        self.observe_daemon_identity()
    }

    fn monotonic_millis(&mut self) -> u64 {
        self.monotonic_origin
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }

    fn settle_step(&mut self) -> SecurityResult<()> {
        thread::sleep(UNIT_SETTLE_STEP);
        Ok(())
    }

    fn stop_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        self.systemctl(["stop".into(), unit_name(unit).into()])?;
        Ok(())
    }

    fn start_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        self.systemctl(["start".into(), unit_name(unit).into()])?;
        Ok(())
    }

    fn daemon_reload(&mut self) -> SecurityResult<()> {
        self.systemctl(["daemon-reload".into()])?;
        Ok(())
    }

    fn transient_exists(&mut self, unit: &str) -> SecurityResult<bool> {
        if !valid_transient_unit_name(unit) {
            return Err(SecurityError::operation(
                "invalid readiness transient unit name",
            ));
        }
        let output = self.systemctl([
            "show".into(),
            unit.into(),
            "--all".into(),
            "--property=LoadState".into(),
            "--property=ActiveState".into(),
            "--property=SubState".into(),
        ])?;
        Ok(parse_transient_state(&output)?.load != TransientLoadState::NotFound)
    }

    fn stop_and_kill_transient(&mut self, unit: &str) -> SecurityResult<()> {
        if self.completed_transient_cleanup.as_deref() == Some(unit) {
            self.completed_transient_cleanup = None;
            return Ok(());
        }
        let deadline = Instant::now()
            .checked_add(command::SYSTEMCTL_DEADLINE)
            .ok_or_else(|| SecurityError::operation("transient cleanup deadline overflow"))?;
        self.cleanup_transient_until(unit, deadline)
    }

    fn encrypt_credential(
        &mut self,
        command: &CommandSpec,
        plaintext: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        self.run(command, plaintext).map(ProcessOutput::into_stdout)
    }

    fn run_readiness(&mut self, command: &CommandSpec) -> SecurityResult<Vec<u8>> {
        self.completed_transient_cleanup = None;
        let unit = readiness_unit_from_command(command)?;
        let deadline = Instant::now()
            .checked_add(command.deadline)
            .ok_or_else(|| SecurityError::operation("readiness deadline overflow"))?;
        match self.run_until(command, &[], deadline, true, Some(&unit)) {
            Ok(output) => Ok(output.into_stdout()),
            Err(error) => {
                // `run_until` has already spent the single readiness deadline on
                // stop/kill/state cleanup. The engine's generic fallback must not
                // silently start a fresh series of fixed per-command deadlines.
                self.completed_transient_cleanup = Some(unit);
                Err(error)
            }
        }
    }

    fn preview_verifier(&mut self, config_bytes: &[u8]) -> SecurityResult<VerifierResultV1> {
        let config: HowyConfig = toml::from_str(
            std::str::from_utf8(config_bytes)
                .map_err(|_| SecurityError::operation("candidate config is not UTF-8"))?,
        )
        .map_err(|_| SecurityError::operation("candidate config is invalid"))?;
        config.validate().map_err(SecurityError::operation)?;
        let inventory = self.inventory_mode1()?;
        validate_readiness_inventory(&inventory)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let fingerprint = namespace_fingerprint(&inventory)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let recognizer = if fingerprint.entry_count == 0 {
            None
        } else {
            let path = if config.ml.recognizer_model.is_empty() {
                howy_common::paths::find_model("w600k_r50.onnx")
                    .ok_or_else(|| SecurityError::operation("recognizer model is missing"))?
            } else {
                Path::new(&config.ml.recognizer_model).to_owned()
            };
            let path = path
                .to_str()
                .ok_or_else(|| SecurityError::operation("recognizer path is not UTF-8"))?;
            let model = self
                .read_exact_file(path, EXECUTABLE_MAX)?
                .ok_or_else(|| SecurityError::operation("recognizer model is missing"))?;
            Some(RecognizerIdentity {
                absolute_path: path.into(),
                sha256: model.sha256(),
            })
        };
        let daemon = self.observe_daemon_identity()?;
        VerifierResultV1::new(
            Sha256Digest::from_bytes(config_bytes),
            daemon,
            ReadinessResultV1::new_verified(fingerprint, recognizer)
                .map_err(|error| SecurityError::operation(error.to_string()))?,
        )
        .map_err(|error| SecurityError::operation(error.to_string()))
    }

    fn namespace_nonempty(&mut self) -> SecurityResult<bool> {
        let inventory = self.inventory_mode1()?;
        validate_readiness_inventory(&inventory)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        Ok(!inventory.entries.is_empty())
    }

    fn security_info(&mut self) -> SecurityResult<Option<SecurityInfoResult>> {
        let mut client = DaemonClient::default_path().with_timeout(Duration::from_secs(10));
        match client.request(&Request::security_info()) {
            Ok(response) => match response.result {
                Some(RespResult::SecurityInfo(info)) => {
                    info.validate_strict()
                        .map_err(|error| SecurityError::operation(error.to_string()))?;
                    Ok(Some(info))
                }
                _ => Err(SecurityError::operation(
                    "daemon returned an invalid root security response",
                )),
            },
            Err(_) => Ok(None),
        }
    }

    fn daemon_info(&mut self) -> SecurityResult<Option<DaemonInfo>> {
        let mut client = DaemonClient::default_path().with_timeout(Duration::from_secs(10));
        match client.request(&Request::info()) {
            Ok(response) => match response.result {
                Some(RespResult::Info(info)) => {
                    info.validate_strict()
                        .map_err(|error| SecurityError::operation(error.to_string()))?;
                    Ok(Some(info))
                }
                _ => Err(SecurityError::operation(
                    "daemon returned an invalid public status response",
                )),
            },
            Err(_) => Ok(None),
        }
    }

    fn quarantine_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        let original = self.paths.resolve(&expected.path)?;
        let quarantine = self.paths.resolve(quarantine_path)?;
        let (parent, original_name) = split_absolute(
            original
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted artifact path is not UTF-8"))?,
        )?;
        let (quarantine_parent, quarantine_name) = split_absolute(
            quarantine
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted quarantine path is not UTF-8"))?,
        )?;
        if parent != quarantine_parent {
            return Err(SecurityError::operation(
                "cleanup quarantine is not in the artifact directory",
            ));
        }
        let directory = open_directory_path(&self.paths.root, parent, false, 0o700)?
            .ok_or_else(|| SecurityError::operation("artifact parent disappeared"))?;
        let parent_stat = fstat(directory.as_raw_fd())?;
        if !descriptor_parent_matches(expected, &parent_stat) {
            return Err(SecurityError::operation("artifact parent identity changed"));
        }
        let current = self
            .read_exact_file(
                &expected.path,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("artifact disappeared"))?;
        if !artifact_exact_matches(expected, &current) {
            return Err(SecurityError::operation(
                "artifact changed immediately before quarantine",
            ));
        }
        let original_name = cstring(original_name.as_bytes())?;
        let quarantine_name = cstring(quarantine_name.as_bytes())?;
        if fstatat_nofollow(directory.as_raw_fd(), &quarantine_name)?.is_some() {
            return Err(SecurityError::operation(
                "cleanup quarantine path is occupied",
            ));
        }
        self.atomic_fail("quarantine-rename")?;
        renameat2(
            directory.as_raw_fd(),
            &original_name,
            directory.as_raw_fd(),
            &quarantine_name,
            libc::RENAME_NOREPLACE,
        )?;
        self.atomic_fail("quarantine-rename-fsync")
            .map_err(|_| SecurityError::Uncertain("cleanup quarantine rename not synced".into()))?;
        fsync_directory(directory.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("cleanup quarantine directory fsync failed".into())
        })?;
        self.atomic_fail("quarantine-rename-fsynced").map_err(|_| {
            SecurityError::Uncertain("cleanup quarantine rename sync outcome is uncertain".into())
        })?;
        let moved = self
            .read_exact_file(
                quarantine_path,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Uncertain("cleanup quarantine missing".into()))?;
        if !artifact_exact_matches(expected, &moved) {
            return Err(SecurityError::Uncertain(
                "cleanup quarantine identity differs after rename".into(),
            ));
        }
        Ok(())
    }

    fn restore_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        let original = self.paths.resolve(&expected.path)?;
        let quarantine = self.paths.resolve(quarantine_path)?;
        let (parent, original_name) = split_absolute(
            original
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted artifact path is not UTF-8"))?,
        )?;
        let (quarantine_parent, quarantine_name) = split_absolute(
            quarantine
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted quarantine path is not UTF-8"))?,
        )?;
        if parent != quarantine_parent {
            return Err(SecurityError::Uncertain(
                "cleanup quarantine parent changed".into(),
            ));
        }
        let directory = open_directory_path(&self.paths.root, parent, false, 0o700)?
            .ok_or_else(|| SecurityError::Uncertain("artifact parent disappeared".into()))?;
        if !descriptor_parent_matches(expected, &fstat(directory.as_raw_fd())?) {
            return Err(SecurityError::Uncertain(
                "cleanup restore parent identity changed".into(),
            ));
        }
        let quarantined = match self.read_exact_file(
            quarantine_path,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )? {
            Some(file) => file,
            None => {
                let restored = self
                    .read_exact_file(
                        &expected.path,
                        howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
                    )?
                    .ok_or_else(|| {
                        SecurityError::Uncertain("cleanup quarantine disappeared".into())
                    })?;
                if !artifact_exact_matches(expected, &restored) {
                    return Err(SecurityError::Uncertain(
                        "cleanup restore paths have unexpected identity".into(),
                    ));
                }
                fsync_directory(directory.as_raw_fd()).map_err(|_| {
                    SecurityError::Uncertain("restored artifact directory fsync failed".into())
                })?;
                return Ok(());
            }
        };
        if !artifact_exact_matches(expected, &quarantined) {
            return Err(SecurityError::Uncertain(
                "cleanup quarantine changed before restore".into(),
            ));
        }
        let original_name = cstring(original_name.as_bytes())?;
        let quarantine_name = cstring(quarantine_name.as_bytes())?;
        if fstatat_nofollow(directory.as_raw_fd(), &original_name)?.is_some() {
            return Err(SecurityError::Uncertain(
                "original artifact path was occupied before quarantine restore".into(),
            ));
        }
        self.atomic_fail("quarantine-restore")?;
        renameat2(
            directory.as_raw_fd(),
            &quarantine_name,
            directory.as_raw_fd(),
            &original_name,
            libc::RENAME_NOREPLACE,
        )?;
        self.atomic_fail("quarantine-restore-fsync").map_err(|_| {
            SecurityError::Uncertain("cleanup quarantine restore not synced".into())
        })?;
        fsync_directory(directory.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("cleanup quarantine restore directory fsync failed".into())
        })?;
        self.atomic_fail("quarantine-restore-fsynced")
            .map_err(|_| {
                SecurityError::Uncertain("cleanup restore sync outcome is uncertain".into())
            })?;
        let restored = self
            .read_exact_file(
                &expected.path,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Uncertain("restored artifact disappeared".into()))?;
        if !artifact_exact_matches(expected, &restored) {
            return Err(SecurityError::Uncertain(
                "restored artifact identity differs".into(),
            ));
        }
        Ok(())
    }

    fn unlink_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        let quarantine = self.paths.resolve(quarantine_path)?;
        let (parent, name) = split_absolute(
            quarantine
                .to_str()
                .ok_or_else(|| SecurityError::operation("rooted quarantine path is not UTF-8"))?,
        )?;
        let directory = open_directory_path(&self.paths.root, parent, false, 0o700)?
            .ok_or_else(|| SecurityError::Uncertain("quarantine parent disappeared".into()))?;
        if !descriptor_parent_matches(expected, &fstat(directory.as_raw_fd())?) {
            return Err(SecurityError::Uncertain(
                "cleanup unlink parent identity changed".into(),
            ));
        }
        let file = match self.read_exact_file(
            quarantine_path,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )? {
            Some(file) => file,
            None => {
                if self
                    .read_exact_file(
                        &expected.path,
                        howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
                    )?
                    .is_some()
                {
                    return Err(SecurityError::Uncertain(
                        "cleanup artifact reappeared while reconciling unlink".into(),
                    ));
                }
                fsync_directory(directory.as_raw_fd()).map_err(|_| {
                    SecurityError::Uncertain("cleanup unlink reconciliation fsync failed".into())
                })?;
                return Ok(());
            }
        };
        if !artifact_exact_matches(expected, &file) {
            return Err(SecurityError::Uncertain(
                "cleanup quarantine changed before unlink".into(),
            ));
        }
        let name = cstring(name.as_bytes())?;
        self.atomic_fail("quarantine-unlink")?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::Uncertain(
                "exact cleanup quarantine unlink failed".into(),
            ));
        }
        self.atomic_fail("quarantine-unlink-fsync")
            .map_err(|_| SecurityError::Uncertain("cleanup quarantine unlink not synced".into()))?;
        fsync_directory(directory.as_raw_fd()).map_err(|_| {
            SecurityError::Uncertain("cleanup quarantine unlink directory fsync failed".into())
        })?;
        self.atomic_fail("quarantine-unlink-fsynced").map_err(|_| {
            SecurityError::Uncertain("cleanup unlink sync outcome is uncertain".into())
        })
    }

    fn boundary(&mut self, _name: &'static str) -> SecurityResult<()> {
        Ok(())
    }
}

struct ProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: ExitStatus,
}

impl ProcessOutput {
    fn into_stdout(mut self) -> Vec<u8> {
        std::mem::take(&mut self.stdout)
    }
}

impl Drop for ProcessOutput {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

struct GuardedKey {
    mapping: *mut libc::c_void,
    mapping_length: usize,
    key: *mut u8,
    key_length: usize,
}

impl GuardedKey {
    fn generate() -> SecurityResult<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(SecurityError::operation("page size unavailable"));
        }
        let page = page as usize;
        let mapping_length = page
            .checked_mul(3)
            .ok_or_else(|| SecurityError::operation("guarded mapping overflow"))?;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(SecurityError::operation("guarded key mapping failed"));
        }
        let key_page = unsafe { mapping.cast::<u8>().add(page) };
        if unsafe { libc::mprotect(key_page.cast(), page, libc::PROT_READ | libc::PROT_WRITE) } != 0
            || unsafe { libc::mlock(key_page.cast(), page) } != 0
            || unsafe { libc::madvise(key_page.cast(), page, libc::MADV_DONTDUMP) } != 0
            || unsafe { libc::madvise(key_page.cast(), page, libc::MADV_DONTFORK) } != 0
        {
            unsafe { libc::munmap(mapping, mapping_length) };
            return Err(SecurityError::operation("guarded key hardening failed"));
        }
        let key = Self {
            mapping,
            mapping_length,
            key: key_page,
            key_length: 32,
        };
        getrandom::fill(unsafe { std::slice::from_raw_parts_mut(key.key, key.key_length) })
            .map_err(|_| SecurityError::operation("OS key generation failed"))?;
        Ok(key)
    }
}

impl SecretKeyMaterial for GuardedKey {
    fn expose(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.key, self.key_length) }
    }
}

impl Drop for GuardedKey {
    fn drop(&mut self) {
        unsafe {
            for index in 0..self.key_length {
                std::ptr::write_volatile(self.key.add(index), 0);
            }
            libc::munlock(self.key.cast(), self.mapping_length / 3);
            libc::munmap(self.mapping, self.mapping_length);
        }
    }
}

fn split_absolute(path: &str) -> SecurityResult<(&Path, &str)> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SecurityError::operation("unsafe absolute path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| SecurityError::operation("path has no parent"))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| SecurityError::operation("path name is not UTF-8"))?;
    Ok((parent, name))
}

fn open_directory_path(
    root: &Path,
    path: &Path,
    create: bool,
    final_mode: u32,
) -> SecurityResult<Option<OwnedFd>> {
    if !root.is_absolute()
        || !path.is_absolute()
        || root
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SecurityError::operation("directory path is not absolute"));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SecurityError::operation("directory path is outside the security root"))?;
    let root = cstring(root.as_os_str().as_bytes())?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(SecurityError::operation("root directory open failed"));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let root_stat = fstat(current.as_raw_fd())?;
    if (root_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || root_stat.st_uid != 0
        || root_stat.st_gid != 0
        || root_stat.st_mode & 0o022 != 0
        || root_stat.st_nlink == 0
    {
        return Err(SecurityError::operation(
            "security root directory metadata is unsafe",
        ));
    }
    let components: Vec<_> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            Component::RootDir => None,
            _ => None,
        })
        .collect();
    for (index, component) in components.iter().enumerate() {
        let component = cstring(component.as_bytes())?;
        let mut fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            if !create {
                return Ok(None);
            }
            let mode = if index + 1 == components.len() {
                final_mode
            } else {
                0o755
            };
            if unsafe {
                libc::mkdirat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    mode as libc::mode_t,
                )
            } != 0
            {
                return Err(SecurityError::operation("directory creation failed"));
            }
            fsync_directory(current.as_raw_fd())?;
            fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            return Err(SecurityError::operation(
                "no-follow directory traversal failed",
            ));
        }
        let stat = fstat(fd)?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o022 != 0
            || stat.st_nlink == 0
        {
            unsafe { libc::close(fd) };
            return Err(SecurityError::operation(
                "directory traversal metadata is unsafe",
            ));
        }
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(Some(current))
}

fn open_directory_path_bound(path: &Path) -> SecurityResult<OwnedFd> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SecurityError::operation("unsafe atomic parent path"));
    }
    let root = cstring(b"/")?;
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(SecurityError::operation(
            "atomic root directory open failed",
        ));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root_fd) };
    for component in path.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        let component = cstring(component.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(SecurityError::operation(
                "atomic no-follow parent traversal failed",
            ));
        }
        let stat = fstat(fd)?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR || stat.st_nlink == 0 {
            unsafe { libc::close(fd) };
            return Err(SecurityError::operation("unsafe atomic parent component"));
        }
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(current)
}

fn directory_identity(path: &Path, stat: &libc::stat) -> SecurityResult<DirectoryIdentityV1> {
    let path = path
        .to_str()
        .ok_or_else(|| SecurityError::operation("atomic parent path is not UTF-8"))?;
    Ok(DirectoryIdentityV1 {
        path: path.to_owned(),
        object_type: object_type(stat.st_mode),
        device_id: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        gid: stat.st_gid,
        permissions: stat.st_mode & 0o7777,
        link_count: stat.st_nlink,
    })
}

fn validate_directory_identity(fd: RawFd, expected: &DirectoryIdentityV1) -> SecurityResult<()> {
    let stat = fstat(fd)?;
    if object_type(stat.st_mode) != expected.object_type
        || stat.st_dev != expected.device_id
        || stat.st_ino != expected.inode
        || stat.st_uid != expected.uid
        || stat.st_gid != expected.gid
        || stat.st_mode & 0o7777 != expected.permissions
        || stat.st_nlink != expected.link_count
    {
        return Err(SecurityError::operation(
            "atomic parent descriptor identity changed",
        ));
    }
    Ok(())
}

fn validate_absolute_parent_identity(
    path: &Path,
    held_fd: RawFd,
    expected: &DirectoryIdentityV1,
) -> SecurityResult<()> {
    validate_directory_identity(held_fd, expected)?;
    let resolved = open_directory_path_bound(path)?;
    validate_directory_identity(resolved.as_raw_fd(), expected).map_err(|_| {
        SecurityError::operation("absolute atomic parent path no longer resolves to held parent")
    })
}

fn observe_atomic_at(
    parent_fd: RawFd,
    name: &CStr,
    maximum: usize,
    parent: &DirectoryIdentityV1,
) -> SecurityResult<Option<ObservedFile>> {
    let Some(entry) = fstatat_nofollow(parent_fd, name)? else {
        return Ok(None);
    };
    if (entry.st_mode & libc::S_IFMT) != libc::S_IFREG
        || entry.st_nlink != 1
        || entry.st_size < 0
        || usize::try_from(entry.st_size).map_or(true, |length| length > maximum)
    {
        return Err(SecurityError::operation("unsafe atomic file object"));
    }
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(SecurityError::operation("atomic file open failed"));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = fstat(file.as_raw_fd())?;
    if file_identity(&before) != file_identity(&entry) {
        return Err(SecurityError::operation(
            "atomic file changed between lookup and open",
        ));
    }
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| SecurityError::operation("atomic bounded read failed"))?;
    let after = fstat(file.as_raw_fd())?;
    if file_identity(&before) != file_identity(&after) || after.st_size != bytes.len() as i64 {
        return Err(SecurityError::operation("atomic file changed while read"));
    }
    let mut parent_stat: libc::stat = unsafe { std::mem::zeroed() };
    parent_stat.st_dev = parent.device_id;
    parent_stat.st_ino = parent.inode;
    parent_stat.st_uid = parent.uid;
    parent_stat.st_gid = parent.gid;
    parent_stat.st_mode = libc::S_IFDIR | parent.permissions;
    parent_stat.st_nlink = parent.link_count;
    Ok(Some(observed(bytes, &after, &parent_stat)))
}

fn atomic_identity(bytes: &[u8], stat: &libc::stat) -> AtomicFileIdentityV1 {
    AtomicFileIdentityV1 {
        device_id: stat.st_dev,
        inode: stat.st_ino,
        object_type: object_type(stat.st_mode),
        uid: stat.st_uid,
        gid: stat.st_gid,
        permissions: stat.st_mode & 0o7777,
        link_count: stat.st_nlink,
        byte_length: bytes.len() as u64,
        sha256: Sha256Digest::from_bytes(bytes),
    }
}

fn expected_atomic_length(plan: &AtomicWritePlanV1) -> u64 {
    match &plan.expected_target {
        AtomicExpectedTargetV1::Absent => 0,
        AtomicExpectedTargetV1::Present(identity) => identity.byte_length,
    }
}

fn new_atomic_identity_matches(plan: &AtomicWritePlanV1, identity: &AtomicFileIdentityV1) -> bool {
    identity.object_type == FileObjectType::RegularFile
        && identity.uid == plan.uid
        && identity.gid == plan.gid
        && identity.permissions == plan.permissions
        && identity.link_count == 1
        && identity.byte_length == plan.byte_length
        && identity.sha256 == plan.bytes_sha256
}

fn validate_new_atomic_identity(
    plan: &AtomicWritePlanV1,
    identity: &AtomicFileIdentityV1,
) -> SecurityResult<()> {
    identity
        .validate()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    if !new_atomic_identity_matches(plan, identity) {
        return Err(SecurityError::operation(
            "atomic stage identity differs from plan",
        ));
    }
    Ok(())
}

fn validate_expected_atomic_target(
    plan: &AtomicWritePlanV1,
    observed: Option<&ObservedFile>,
) -> SecurityResult<()> {
    let matches = match (&plan.expected_target, observed) {
        (AtomicExpectedTargetV1::Absent, None) => true,
        (AtomicExpectedTargetV1::Present(expected), Some(observed)) => {
            observed.atomic_identity() == *expected
        }
        _ => false,
    };
    if !matches {
        return Err(SecurityError::operation(
            "atomic target changed after planning",
        ));
    }
    Ok(())
}

fn unlink_created_stage_exact(
    parent_fd: RawFd,
    name: &CStr,
    device_id: u64,
    inode: u64,
) -> SecurityResult<()> {
    let Some(stat) = fstatat_nofollow(parent_fd, name)? else {
        return Ok(());
    };
    if stat.st_dev != device_id
        || stat.st_ino != inode
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_nlink != 1
    {
        return Err(SecurityError::operation(
            "journaled stage identity changed before cleanup",
        ));
    }
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
        return Err(SecurityError::operation("journaled stage unlink failed"));
    }
    fsync_directory(parent_fd)
}

fn directory_mode_for(parent: &Path) -> u32 {
    let text = parent.to_string_lossy();
    if text == MODE1_CREDENTIAL_DIRECTORY
        || text == SECURITY_STATE_DIRECTORY
        || text == SECURITY_UNADOPTED_DIRECTORY
    {
        0o700
    } else {
        0o755
    }
}

fn validate_root_directory(fd: RawFd, permissions: u32) -> SecurityResult<()> {
    let stat = fstat(fd)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != permissions
        || stat.st_nlink == 0
    {
        return Err(SecurityError::operation("directory metadata is unsafe"));
    }
    Ok(())
}

fn fstat(fd: RawFd) -> SecurityResult<libc::stat> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(SecurityError::operation("descriptor metadata query failed"));
    }
    Ok(stat)
}

fn fstatat_nofollow(fd: RawFd, name: &CStr) -> SecurityResult<Option<libc::stat>> {
    let mut stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(SecurityError::operation("path metadata query failed"));
    }
    Ok(Some(stat))
}

fn fsync_directory(fd: RawFd) -> SecurityResult<()> {
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(SecurityError::operation("directory fsync failed"));
    }
    Ok(())
}

fn renameat2(
    old_fd: RawFd,
    old: &CStr,
    new_fd: RawFd,
    new: &CStr,
    flags: u32,
) -> SecurityResult<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_fd,
            old.as_ptr(),
            new_fd,
            new.as_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(SecurityError::operation("atomic rename failed"));
    }
    Ok(())
}

fn cstring(bytes: &[u8]) -> SecurityResult<CString> {
    CString::new(bytes).map_err(|_| SecurityError::operation("path contains NUL"))
}

fn observed(bytes: Vec<u8>, stat: &libc::stat, parent: &libc::stat) -> ObservedFile {
    ObservedFile {
        metadata: FileMetadataSnapshotV1 {
            schema_version: 1,
            object_type: object_type(stat.st_mode),
            uid: stat.st_uid,
            gid: stat.st_gid,
            permissions: stat.st_mode & 0o7777,
            link_count: stat.st_nlink,
            link_policy: FileLinkPolicy::ExactlyOne,
            byte_length: bytes.len() as u64,
            restorable_timestamps: RestorableFileTimestampsV1 {
                access: FileTimestampV1 {
                    seconds: stat.st_atime,
                    nanoseconds: stat.st_atime_nsec as u32,
                },
                modification: FileTimestampV1 {
                    seconds: stat.st_mtime,
                    nanoseconds: stat.st_mtime_nsec as u32,
                },
            },
        },
        bytes,
        device_id: stat.st_dev,
        inode: stat.st_ino,
        parent_device_id: parent.st_dev,
        parent_inode: parent.st_ino,
        parent_uid: parent.st_uid,
        parent_gid: parent.st_gid,
        parent_permissions: parent.st_mode & 0o7777,
        parent_link_count: parent.st_nlink,
    }
}

fn observed_control_matches(left: &ObservedFile, right: &ObservedFile) -> bool {
    left.bytes == right.bytes
        && left.atomic_identity() == right.atomic_identity()
        && left.parent_device_id == right.parent_device_id
        && left.parent_inode == right.parent_inode
        && left.parent_uid == right.parent_uid
        && left.parent_gid == right.parent_gid
        && left.parent_permissions == right.parent_permissions
}

fn optional_observed_control_matches(
    left: Option<&ObservedFile>,
    right: Option<&ObservedFile>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => observed_control_matches(left, right),
        _ => false,
    }
}

fn artifact_exact_matches(
    expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
    observed: &ObservedFile,
) -> bool {
    observed.device_id == expected.device_id
        && observed.inode == expected.inode
        && observed.sha256() == expected.sha256
        && observed.metadata.object_type == expected.object_type
        && observed.metadata.uid == expected.uid
        && observed.metadata.gid == expected.gid
        && observed.metadata.permissions == expected.permissions
        && observed.metadata.link_count == expected.link_count
        && observed.metadata.byte_length == expected.byte_length
        && observed.parent_device_id == expected.parent_directory.device_id
        && observed.parent_inode == expected.parent_directory.inode
        && observed.parent_uid == expected.parent_directory.uid
        && observed.parent_gid == expected.parent_directory.gid
        && observed.parent_permissions == expected.parent_directory.permissions
        && observed.parent_link_count == expected.parent_directory.link_count
}

fn descriptor_parent_matches(
    expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
    observed: &libc::stat,
) -> bool {
    object_type(observed.st_mode) == FileObjectType::Directory
        && observed.st_dev == expected.parent_directory.device_id
        && observed.st_ino == expected.parent_directory.inode
        && observed.st_uid == expected.parent_directory.uid
        && observed.st_gid == expected.parent_directory.gid
        && observed.st_mode & 0o7777 == expected.parent_directory.permissions
        && observed.st_nlink == expected.parent_directory.link_count
}

fn object_type(mode: libc::mode_t) -> FileObjectType {
    match mode & libc::S_IFMT {
        libc::S_IFREG => FileObjectType::RegularFile,
        libc::S_IFDIR => FileObjectType::Directory,
        libc::S_IFLNK => FileObjectType::Symlink,
        _ => FileObjectType::Other,
    }
}

fn namespace_type(stat: &libc::stat) -> NamespaceFileType {
    match stat.st_mode & libc::S_IFMT {
        libc::S_IFREG => NamespaceFileType::Regular,
        libc::S_IFDIR => NamespaceFileType::Directory,
        libc::S_IFLNK => NamespaceFileType::Symlink,
        _ => NamespaceFileType::Other,
    }
}

fn file_identity(stat: &libc::stat) -> (u64, u64, i64, i64, i64, i64, i64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime,
        stat.st_ctime_nsec,
    )
}

fn validate_host_secret_observations(
    initial: Option<&libc::stat>,
    later: &[&libc::stat],
) -> SecurityResult<bool> {
    const EXACT_SIZE: i64 = 16 + 4096;
    let Some(initial) = initial else {
        if later.is_empty() {
            return Ok(false);
        }
        return Err(SecurityError::operation(
            "credential host secret appeared during inspection",
        ));
    };
    let all = std::iter::once(initial).chain(later.iter().copied());
    for stat in all {
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o7777 != 0o400
            || stat.st_nlink != 1
            || stat.st_size != EXACT_SIZE
        {
            return Err(SecurityError::operation(
                "credential host secret metadata is unsafe",
            ));
        }
        if file_identity(stat) != file_identity(initial) {
            return Err(SecurityError::operation(
                "credential host secret path was replaced during inspection",
            ));
        }
    }
    Ok(true)
}

fn validate_executable(path: &str) -> SecurityResult<()> {
    validate_executable_path(Path::new(path))
}

fn validate_executable_path(path: &Path) -> SecurityResult<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| SecurityError::operation("required absolute executable is missing"))?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(SecurityError::operation(
            "required absolute executable metadata is unsafe",
        ));
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> SecurityResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(SecurityError::operation(
            "child pipe nonblocking setup failed",
        ));
    }
    Ok(())
}

fn write_nonblocking(pipe: &mut ChildStdin, bytes: &[u8]) -> SecurityResult<usize> {
    if bytes.is_empty() {
        return Ok(0);
    }
    loop {
        let written = unsafe {
            libc::write(
                pipe.as_raw_fd(),
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
            )
        };
        if written >= 0 {
            return Ok(written as usize);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(0),
            Some(libc::EPIPE) => {
                return Err(SecurityError::operation("child closed key input early"));
            }
            _ => return Err(SecurityError::operation("bounded child stdin write failed")),
        }
    }
}

trait CapturedPipe: AsRawFd {}
impl CapturedPipe for ChildStdout {}
impl CapturedPipe for ChildStderr {}

fn drain_nonblocking(
    pipe: &mut impl CapturedPipe,
    cap: usize,
    output: &mut Vec<u8>,
) -> SecurityResult<bool> {
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        let count = unsafe {
            libc::read(
                pipe.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if count == 0 {
            return Ok(true);
        }
        if count > 0 {
            let count = count as usize;
            if output.len().saturating_add(count) > cap {
                return Err(SecurityError::operation("child output exceeded hard cap"));
            }
            output.extend_from_slice(&buffer[..count]);
            continue;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(false),
            _ => return Err(SecurityError::operation("child output read failed")),
        }
    }
}

fn terminate_process_group(process_group: libc::pid_t) {
    if process_group > 1 && process_group != unsafe { libc::getpgrp() } {
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
}

fn child_exited_without_reaping(child: &Child) -> SecurityResult<bool> {
    let child_id = libc::id_t::try_from(child.id())
        .map_err(|_| SecurityError::operation("child PID overflow"))?;
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child_id,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            let info = unsafe { info.assume_init() };
            return Ok(unsafe { info.si_pid() } != 0);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(SecurityError::operation("child wait observation failed"));
        }
    }
}

fn reap_until(child: &mut Child, deadline: Instant) -> SecurityResult<Option<ExitStatus>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| SecurityError::operation("child wait failed"))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn valid_transient_unit_name(unit: &str) -> bool {
    const PREFIX: &str = "howy-readiness-txn-";
    const SUFFIX: &str = ".service";
    const HEX_BYTES: usize = 32;

    unit.len() == PREFIX.len() + HEX_BYTES + SUFFIX.len()
        && unit.is_ascii()
        && unit.starts_with(PREFIX)
        && unit.ends_with(SUFFIX)
        && unit[PREFIX.len()..PREFIX.len() + HEX_BYTES]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn readiness_unit_from_command(spec: &CommandSpec) -> SecurityResult<String> {
    if spec.executable != command::SYSTEMD_RUN
        || !spec.clear_environment
        || spec.stdin_bytes != 0
        || spec
            .arguments
            .iter()
            .filter(|value| *value == "--wait")
            .count()
            != 1
        || spec
            .arguments
            .iter()
            .filter(|value| *value == "--collect")
            .count()
            != 1
        || spec
            .arguments
            .iter()
            .filter(|value| *value == "--pipe")
            .count()
            != 1
    {
        return Err(SecurityError::operation(
            "readiness transport command contract is malformed",
        ));
    }
    let mut units = spec
        .arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix("--unit="));
    let unit = units
        .next()
        .filter(|unit| valid_transient_unit_name(unit))
        .ok_or_else(|| SecurityError::operation("readiness command has an invalid unit name"))?;
    if units.next().is_some() {
        return Err(SecurityError::operation(
            "readiness command has duplicate unit names",
        ));
    }
    Ok(unit.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransientLoadState {
    Loaded,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransientActiveState {
    Active,
    Inactive,
    Activating,
    Deactivating,
    Reloading,
    Refreshing,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransientSubState {
    Running,
    Exited,
    Dead,
    Failed,
    Condition,
    StartPre,
    Start,
    StartPost,
    RefreshExtensions,
    RefreshCredentials,
    Reload,
    ReloadSignal,
    ReloadNotify,
    ReloadPost,
    Mounting,
    Stop,
    StopWatchdog,
    StopSigterm,
    StopSigkill,
    StopPost,
    FinalWatchdog,
    FinalSigterm,
    FinalSigkill,
    DeadBeforeAutoRestart,
    FailedBeforeAutoRestart,
    DeadResourcesPinned,
    AutoRestart,
    AutoRestartQueued,
    Cleaning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransientState {
    load: TransientLoadState,
    active: TransientActiveState,
    sub: TransientSubState,
}

impl TransientState {
    fn is_not_found(self) -> bool {
        self == Self {
            load: TransientLoadState::NotFound,
            active: TransientActiveState::Inactive,
            sub: TransientSubState::Dead,
        }
    }

    fn is_settled(self) -> bool {
        matches!(
            self,
            Self {
                load: TransientLoadState::Loaded,
                active: TransientActiveState::Inactive,
                sub: TransientSubState::Dead,
            } | Self {
                load: TransientLoadState::Loaded,
                active: TransientActiveState::Failed,
                sub: TransientSubState::Failed,
            }
        )
    }
}

fn parse_transient_state(output: &[u8]) -> SecurityResult<TransientState> {
    let expected = ["LoadState", "ActiveState", "SubState"];
    let values = parse_exact_properties(
        output,
        &expected,
        TRANSIENT_STATE_MAX,
        32,
        "transient state",
    )?;
    let load = match required(&values, "LoadState")? {
        "loaded" => TransientLoadState::Loaded,
        "not-found" => TransientLoadState::NotFound,
        _ => return Err(SecurityError::operation("unknown transient load state")),
    };
    let active = match required(&values, "ActiveState")? {
        "active" => TransientActiveState::Active,
        "inactive" => TransientActiveState::Inactive,
        "activating" => TransientActiveState::Activating,
        "deactivating" => TransientActiveState::Deactivating,
        "reloading" => TransientActiveState::Reloading,
        "refreshing" => TransientActiveState::Refreshing,
        "failed" => TransientActiveState::Failed,
        "maintenance" => TransientActiveState::Maintenance,
        _ => return Err(SecurityError::operation("unknown transient active state")),
    };
    let sub = match required(&values, "SubState")? {
        "running" => TransientSubState::Running,
        "exited" => TransientSubState::Exited,
        "dead" => TransientSubState::Dead,
        "failed" => TransientSubState::Failed,
        "condition" => TransientSubState::Condition,
        "start-pre" => TransientSubState::StartPre,
        "start" => TransientSubState::Start,
        "start-post" => TransientSubState::StartPost,
        "refresh-extensions" => TransientSubState::RefreshExtensions,
        "refresh-credentials" => TransientSubState::RefreshCredentials,
        "reload" => TransientSubState::Reload,
        "reload-signal" => TransientSubState::ReloadSignal,
        "reload-notify" => TransientSubState::ReloadNotify,
        "reload-post" => TransientSubState::ReloadPost,
        "mounting" => TransientSubState::Mounting,
        "stop" => TransientSubState::Stop,
        "stop-watchdog" => TransientSubState::StopWatchdog,
        "stop-sigterm" => TransientSubState::StopSigterm,
        "stop-sigkill" => TransientSubState::StopSigkill,
        "stop-post" => TransientSubState::StopPost,
        "final-watchdog" => TransientSubState::FinalWatchdog,
        "final-sigterm" => TransientSubState::FinalSigterm,
        "final-sigkill" => TransientSubState::FinalSigkill,
        "dead-before-auto-restart" => TransientSubState::DeadBeforeAutoRestart,
        "failed-before-auto-restart" => TransientSubState::FailedBeforeAutoRestart,
        "dead-resources-pinned" => TransientSubState::DeadResourcesPinned,
        "auto-restart" => TransientSubState::AutoRestart,
        "auto-restart-queued" => TransientSubState::AutoRestartQueued,
        "cleaning" => TransientSubState::Cleaning,
        _ => return Err(SecurityError::operation("unknown transient sub-state")),
    };
    let state = TransientState { load, active, sub };
    if load == TransientLoadState::NotFound && !state.is_not_found() {
        return Err(SecurityError::operation(
            "inconsistent not-found transient state",
        ));
    }
    Ok(state)
}

fn cleanup_transient_with(
    unit: &str,
    deadline: Instant,
    mut run: impl FnMut(Vec<String>, Instant) -> SecurityResult<ProcessOutput>,
) -> SecurityResult<()> {
    if !valid_transient_unit_name(unit) {
        return Err(SecurityError::operation(
            "invalid readiness transient unit name",
        ));
    }
    let mut failures = Vec::new();
    for arguments in [
        vec!["--no-block".into(), "stop".into(), unit.into()],
        vec![
            "kill".into(),
            "--kill-whom=all".into(),
            "--signal=KILL".into(),
            unit.into(),
        ],
        vec!["reset-failed".into(), unit.into()],
    ] {
        if Instant::now() >= deadline {
            return Err(SecurityError::operation(
                "transient cleanup deadline elapsed before all controls ran",
            ));
        }
        match run(arguments, deadline) {
            Ok(output) if output.status.success() => {}
            Ok(output) => failures.push(format!(
                "transient cleanup command failed with {}",
                output.status
            )),
            Err(error) => failures.push(error.to_string()),
        }
    }

    loop {
        if Instant::now() >= deadline {
            return Err(SecurityError::operation(format!(
                "transient state did not settle before the shared deadline{}",
                failure_suffix(&failures)
            )));
        }
        let output = run(
            vec![
                "show".into(),
                unit.into(),
                "--all".into(),
                "--property=LoadState".into(),
                "--property=ActiveState".into(),
                "--property=SubState".into(),
            ],
            deadline,
        )?;
        if !output.status.success() {
            return Err(SecurityError::operation(format!(
                "transient state query failed with {}{}",
                output.status,
                failure_suffix(&failures)
            )));
        }
        let state = parse_transient_state(&output.stdout)?;
        if state.is_not_found() {
            return Ok(());
        }
        if state.is_settled() {
            if failures.is_empty() {
                return Ok(());
            }
            return Err(SecurityError::operation(format!(
                "transient settled only after failed cleanup controls{}",
                failure_suffix(&failures)
            )));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(Duration::from_millis(10).min(remaining));
    }
}

fn failure_suffix(failures: &[String]) -> String {
    if failures.is_empty() {
        String::new()
    } else {
        format!("; {}", failures.join("; "))
    }
}

fn parse_exact_properties<'a>(
    output: &'a [u8],
    expected: &[&str],
    output_maximum: usize,
    value_maximum: usize,
    context: &'static str,
) -> SecurityResult<BTreeMap<&'a str, &'a str>> {
    if output.is_empty() || output.len() > output_maximum {
        return Err(SecurityError::operation(format!(
            "{context} output length is invalid"
        )));
    }
    let text = std::str::from_utf8(output)
        .map_err(|_| SecurityError::operation(format!("{context} output is not UTF-8")))?;
    if !text.ends_with('\n')
        || text
            .bytes()
            .any(|byte| byte != b'\n' && byte.is_ascii_control())
    {
        return Err(SecurityError::operation(format!(
            "{context} output framing is malformed"
        )));
    }
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut values = BTreeMap::new();
    for line in text.split_terminator('\n') {
        if line.is_empty() || line.len() > value_maximum.saturating_add(64) {
            return Err(SecurityError::operation(format!(
                "{context} property framing is malformed"
            )));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SecurityError::operation(format!("malformed {context} property")))?;
        if !expected.contains(key)
            || value.len() > value_maximum
            || values.insert(key, value).is_some()
        {
            return Err(SecurityError::operation(format!(
                "unknown, duplicate, or oversized {context} property"
            )));
        }
    }
    if values.len() != expected.len() {
        return Err(SecurityError::operation(format!(
            "{context} property is missing"
        )));
    }
    Ok(values)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveShow {
    fragment_path: String,
    dropin_paths: Vec<String>,
}

fn parse_effective_show(kind: UnitKind, output: &[u8]) -> SecurityResult<EffectiveShow> {
    let service_properties = [
        ("FragmentPath", None),
        ("DropInPaths", None),
        ("NeedDaemonReload", Some("no")),
        ("LimitCORE", Some("0")),
        ("LimitMEMLOCK", Some("65536")),
        ("LockPersonality", Some("yes")),
        ("MemoryDenyWriteExecute", Some("no")),
        ("NoNewPrivileges", Some("yes")),
        ("PrivateTmp", Some("yes")),
        ("ProtectControlGroups", Some("yes")),
        ("ProtectHome", Some("read-only")),
        ("ProtectKernelModules", Some("yes")),
        ("ProtectKernelTunables", Some("yes")),
        ("ProtectSystem", Some("strict")),
        ("RestrictAddressFamilies", Some("AF_UNIX")),
        ("RestrictNamespaces", Some("yes")),
        ("RestrictRealtime", Some("yes")),
        ("UMask", None),
    ];
    let socket_properties = [
        ("FragmentPath", None),
        ("DropInPaths", None),
        ("NeedDaemonReload", Some("no")),
    ];
    let expected: BTreeMap<&str, Option<&str>> = match kind {
        UnitKind::Service => service_properties.into_iter().collect(),
        UnitKind::Socket => socket_properties.into_iter().collect(),
    };
    let keys = expected.keys().copied().collect::<Vec<_>>();
    let values =
        parse_exact_properties(output, &keys, EFFECTIVE_SHOW_MAX, 4_096, "effective unit")?;
    for (key, exact) in &expected {
        let value = values[key];
        if exact.is_some_and(|exact| value != exact) {
            return Err(SecurityError::operation(
                "effective unit property differs from policy",
            ));
        }
    }
    if kind == UnitKind::Service && !matches!(values["UMask"], "63" | "0077") {
        return Err(SecurityError::operation(
            "effective service UMask differs from policy",
        ));
    }
    let fragment_path = parse_canonical_systemd_path(values["FragmentPath"])?;
    let dropin_paths = if values["DropInPaths"].is_empty() {
        Vec::new()
    } else {
        values["DropInPaths"]
            .split(' ')
            .map(parse_canonical_systemd_path)
            .collect::<SecurityResult<Vec<_>>>()?
    };
    Ok(EffectiveShow {
        fragment_path,
        dropin_paths,
    })
}

fn parse_canonical_systemd_path(value: &str) -> SecurityResult<String> {
    let path = Path::new(value);
    if value.is_empty()
        || contains_forbidden_escape(value)
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.to_str() != Some(value)
    {
        return Err(SecurityError::operation(
            "systemd returned a noncanonical or escaped path",
        ));
    }
    let mut normalized = String::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push('/'),
            Component::Normal(component) => {
                if normalized.len() > 1 {
                    normalized.push('/');
                }
                normalized.push_str(component.to_str().ok_or_else(|| {
                    SecurityError::operation("systemd path is not canonical UTF-8")
                })?);
            }
            _ => {
                return Err(SecurityError::operation(
                    "systemd path contains a noncanonical component",
                ));
            }
        }
    }
    if normalized != value || value.contains("//") || value.ends_with('/') {
        return Err(SecurityError::operation("systemd path is not normalized"));
    }
    Ok(value.to_owned())
}

#[derive(Default)]
struct ParsedEffectivePolicy {
    conditions: Vec<howy_common::provisioning::EffectiveUnitConditionV1>,
    load_credentials: Vec<EffectiveCredentialLoadV1>,
    set_credentials: Vec<EffectiveSetCredentialV1>,
    exec_start: Vec<Vec<String>>,
    hardening: BTreeMap<String, String>,
}

fn build_effective_observation(
    kind: UnitKind,
    show: EffectiveShow,
    files: Vec<(String, ObservedFile)>,
) -> SecurityResult<EffectiveUnitObservationV1> {
    let mut policy = ParsedEffectivePolicy::default();
    for (index, (path, file)) in files.iter().enumerate() {
        if path == MODE1_DROPIN_PATH
            && file.bytes != MODE1_DROPIN_BYTES
            && file.bytes != MODE0_DROPIN_BYTES
        {
            return Err(SecurityError::operation(
                "security drop-in bytes are not an exact reviewed mode",
            ));
        }
        parse_effective_file(kind, index > 0, &file.bytes, &mut policy)?;
    }
    if policy.conditions != required_unit_conditions() {
        return Err(SecurityError::operation(
            "effective unit does not carry the exact ordered transaction guard and package bootstrap marker conditions",
        ));
    }
    match kind {
        UnitKind::Service => {
            if policy.exec_start != [vec![command::HOWYD.to_owned()]]
                || policy.hardening != required_service_hardening()
            {
                return Err(SecurityError::operation(
                    "effective service command or hardening differs from policy",
                ));
            }
        }
        UnitKind::Socket => {
            if !policy.exec_start.is_empty()
                || !policy.load_credentials.is_empty()
                || !policy.set_credentials.is_empty()
                || !policy.hardening.is_empty()
            {
                return Err(SecurityError::operation(
                    "socket unit unexpectedly carries service execution policy",
                ));
            }
        }
    }
    let mut effective_files = files
        .iter()
        .map(|(path, file)| EffectiveUnitFileV1 {
            path: path.clone(),
            sha256: file.sha256(),
            metadata: EffectiveFileMetadataV1 {
                object_type: file.metadata.object_type,
                uid: file.metadata.uid,
                gid: file.metadata.gid,
                permissions: file.metadata.permissions,
                link_count: file.metadata.link_count,
                byte_length: file.metadata.byte_length,
            },
        })
        .collect::<Vec<_>>();
    let fragment = effective_files.remove(0);
    if effective_files.len() != show.dropin_paths.len()
        || effective_files
            .iter()
            .map(|file| file.path.as_str())
            .ne(show.dropin_paths.iter().map(String::as_str))
    {
        return Err(SecurityError::operation(
            "effective drop-in order changed while files were read",
        ));
    }
    Ok(EffectiveUnitObservationV1 {
        unit_kind: kind,
        fragment,
        dropins: effective_files,
        conditions: policy.conditions,
        load_credential_encrypted: policy.load_credentials,
        set_credential: policy.set_credentials,
        exec_start: policy.exec_start,
        hardening: policy.hardening,
    })
}

fn parse_effective_file(
    kind: UnitKind,
    is_dropin: bool,
    bytes: &[u8],
    policy: &mut ParsedEffectivePolicy,
) -> SecurityResult<()> {
    let pinned = match (kind, is_dropin) {
        (UnitKind::Service, false) => bytes == BASE_SERVICE_UNIT_BYTES,
        (UnitKind::Socket, false) => bytes == BASE_SOCKET_UNIT_BYTES,
        (UnitKind::Service, true) => bytes == MODE0_DROPIN_BYTES || bytes == MODE1_DROPIN_BYTES,
        (UnitKind::Socket, true) => false,
    };
    if !pinned {
        return Err(SecurityError::operation(
            "effective unit file bytes are not an exact packaged fragment or reviewed security drop-in",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SecurityError::operation("effective unit file is not UTF-8"))?;
    if !text.ends_with('\n')
        || text
            .bytes()
            .any(|byte| byte != b'\n' && byte.is_ascii_control())
    {
        return Err(SecurityError::operation("effective unit file is malformed"));
    }
    let mut section = "";
    let mut sections = BTreeSet::new();
    let mut reset_load = false;
    let mut reset_set = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.ends_with('\\') || line.contains('\0') || line.contains('\r') {
            return Err(SecurityError::operation(
                "unit continuation or control escaping is not permitted",
            ));
        }
        if line.starts_with('[') {
            if !line.ends_with(']')
                || line[1..line.len() - 1].contains('[')
                || line[1..line.len() - 1].contains(']')
            {
                return Err(SecurityError::operation("malformed unit section"));
            }
            section = &line[1..line.len() - 1];
            if !matches!(section, "Unit" | "Service" | "Socket" | "Install")
                || !sections.insert(section.to_owned())
            {
                return Err(SecurityError::operation(
                    "unknown or duplicate unit section",
                ));
            }
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SecurityError::operation("malformed unit directive"))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(SecurityError::operation("malformed unit directive name"));
        }
        if key.starts_with("Condition") || key.starts_with("Assert") {
            if section != "Unit" || key != "ConditionPathExists" {
                return Err(SecurityError::operation(
                    "unexpected condition or assertion directive",
                ));
            }
            let expected = match policy.conditions.len() {
                0 => transaction_guard_condition(),
                1 => package_bootstrap_condition(),
                _ => {
                    return Err(SecurityError::operation(
                        "effective unit carries extra condition policy",
                    ));
                }
            };
            let expected_value = if expected.negate {
                format!("!{}", expected.parameter)
            } else {
                expected.parameter.clone()
            };
            if value != expected_value {
                return Err(SecurityError::operation(
                    "ordered unit condition differs from policy",
                ));
            }
            policy.conditions.push(expected);
            continue;
        }
        if matches!(
            key,
            "LoadCredential" | "ImportCredential" | "SetCredentialEncrypted"
        ) {
            return Err(SecurityError::operation(
                "unexpected credential directive can shadow policy",
            ));
        }
        if key == "LoadCredentialEncrypted" {
            if section != "Service" || kind != UnitKind::Service {
                return Err(SecurityError::operation(
                    "encrypted credential directive is in the wrong unit section",
                ));
            }
            if value.is_empty() {
                policy.load_credentials.clear();
                reset_load = true;
            } else {
                let (name, source) = value.split_once(':').ok_or_else(|| {
                    SecurityError::operation("pathless encrypted credential is not permitted")
                })?;
                if name != MODE1_CREDENTIAL_NAME
                    || source != MODE1_CREDENTIAL_PATH
                    || contains_forbidden_escape(value)
                {
                    return Err(SecurityError::operation(
                        "encrypted credential directive differs from policy",
                    ));
                }
                policy.load_credentials.push(EffectiveCredentialLoadV1 {
                    name: name.to_owned(),
                    source: source.to_owned(),
                });
            }
            continue;
        }
        if key == "SetCredential" {
            if section != "Service" || kind != UnitKind::Service {
                return Err(SecurityError::operation(
                    "source companion directive is in the wrong unit section",
                ));
            }
            if value.is_empty() {
                policy.set_credentials.clear();
                reset_set = true;
            } else {
                let (name, source) = value.split_once(':').ok_or_else(|| {
                    SecurityError::operation("malformed source companion directive")
                })?;
                if name != MODE1_CREDENTIAL_SOURCE_COMPANION_NAME
                    || source != MODE1_CREDENTIAL_PATH
                    || contains_forbidden_escape(value)
                {
                    return Err(SecurityError::operation(
                        "source companion directive differs from policy",
                    ));
                }
                policy.set_credentials.push(EffectiveSetCredentialV1 {
                    name: name.to_owned(),
                    value: source.to_owned(),
                });
            }
            continue;
        }
        if key == "ExecStart" {
            if section != "Service" || kind != UnitKind::Service {
                return Err(SecurityError::operation("ExecStart is in the wrong unit"));
            }
            if value.is_empty() {
                policy.exec_start.clear();
            } else if value == command::HOWYD {
                policy.exec_start.push(vec![value.to_owned()]);
            } else {
                return Err(SecurityError::operation(
                    "ExecStart contains an unexpected command or escaping",
                ));
            }
            continue;
        }
        if key.starts_with("Exec") {
            return Err(SecurityError::operation(
                "unexpected service execution directive can shadow policy",
            ));
        }
        if let Some(normalized) = normalize_hardening_directive(key, value)? {
            if section != "Service"
                || kind != UnitKind::Service
                || policy
                    .hardening
                    .insert(key.to_owned(), normalized)
                    .is_some()
            {
                return Err(SecurityError::operation(
                    "duplicate or misplaced hardening directive",
                ));
            }
        }
    }
    if is_dropin && (!reset_load || !reset_set) {
        return Err(SecurityError::operation(
            "security drop-in did not clear inherited credential directives first",
        ));
    }
    Ok(())
}

fn normalize_hardening_directive(key: &str, value: &str) -> SecurityResult<Option<String>> {
    if !required_service_hardening().contains_key(key) {
        return Ok(None);
    }
    let normalized = match (key, value) {
        ("LimitCORE", "0") => "0",
        ("LimitMEMLOCK", "64K" | "65536") => "65536",
        ("UMask", "0077") => "0077",
        ("ProtectHome", "read-only") => "read-only",
        ("ProtectSystem", "strict") => "strict",
        ("RestrictAddressFamilies", "AF_UNIX") => "AF_UNIX",
        ("MemoryDenyWriteExecute", "no") => "no",
        (
            "LockPersonality"
            | "NoNewPrivileges"
            | "PrivateTmp"
            | "ProtectControlGroups"
            | "ProtectKernelModules"
            | "ProtectKernelTunables"
            | "RestrictNamespaces"
            | "RestrictRealtime",
            "yes",
        ) => "yes",
        _ => {
            return Err(SecurityError::operation(
                "service hardening directive differs from reviewed policy",
            ));
        }
    };
    Ok(Some(normalized.to_owned()))
}

fn contains_forbidden_escape(value: &str) -> bool {
    value.contains('\\') || value.contains('"') || value.contains('\'')
}

fn unit_name(kind: UnitKind) -> &'static str {
    match kind {
        UnitKind::Service => "howy.service",
        UnitKind::Socket => "howy.socket",
    }
}

fn parse_unit_observation(kind: UnitKind, output: &[u8]) -> SecurityResult<UnitObservation> {
    let values = parse_exact_properties(
        output,
        &[
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "Job",
        ],
        UNIT_STATE_MAX,
        128,
        "unit state",
    )?;
    let load_state = match required(&values, "LoadState")? {
        "loaded" => UnitLoadState::Loaded,
        "not-found" => UnitLoadState::NotFound,
        "error" => UnitLoadState::Error,
        "bad-setting" => UnitLoadState::BadSetting,
        "masked" => UnitLoadState::Masked,
        _ => return Err(SecurityError::operation("unknown unit load state")),
    };
    let active_state = match required(&values, "ActiveState")? {
        "active" => UnitActiveState::Active,
        "inactive" => UnitActiveState::Inactive,
        "activating" => UnitActiveState::Activating,
        "deactivating" => UnitActiveState::Deactivating,
        "reloading" | "refreshing" => UnitActiveState::Reloading,
        "failed" => UnitActiveState::Failed,
        "maintenance" => UnitActiveState::Maintenance,
        _ => return Err(SecurityError::operation("unknown unit active state")),
    };
    let sub_state = match required(&values, "SubState")? {
        "running" => UnitSubState::Running,
        "dead" => UnitSubState::Dead,
        "failed" => UnitSubState::Failed,
        "start-pre" => UnitSubState::StartPre,
        "start" => UnitSubState::Start,
        "start-post" => UnitSubState::StartPost,
        "stop" => UnitSubState::Stop,
        "stop-sigterm" => UnitSubState::StopSigterm,
        "stop-sigkill" => UnitSubState::StopSigkill,
        "stop-post" => UnitSubState::StopPost,
        "reload" => UnitSubState::Reload,
        "auto-restart" => UnitSubState::AutoRestart,
        "listening" => UnitSubState::Listening,
        _ => UnitSubState::Other,
    };
    let unit_file_state = match required(&values, "UnitFileState")? {
        "enabled" => UnitFileState::Enabled,
        "enabled-runtime" => UnitFileState::EnabledRuntime,
        "linked" => UnitFileState::Linked,
        "linked-runtime" => UnitFileState::LinkedRuntime,
        "alias" => UnitFileState::Alias,
        "masked" => UnitFileState::Masked,
        "masked-runtime" => UnitFileState::MaskedRuntime,
        "static" => UnitFileState::Static,
        "disabled" => UnitFileState::Disabled,
        "indirect" => UnitFileState::Indirect,
        "generated" => UnitFileState::Generated,
        "transient" => UnitFileState::Transient,
        "bad" => UnitFileState::Bad,
        _ => return Err(SecurityError::operation("unknown unit file state")),
    };
    let job = required(&values, "Job")?;
    Ok(UnitObservation {
        unit_kind: kind,
        load_state,
        active_state,
        sub_state,
        unit_file_state,
        has_queued_job: !job.is_empty() && job != "0" && job != "n/a",
    })
}

fn required<'a>(
    values: &'a std::collections::BTreeMap<&str, &str>,
    key: &str,
) -> SecurityResult<&'a str> {
    values
        .get(key)
        .copied()
        .ok_or_else(|| SecurityError::operation("unit state property missing"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0xf) as usize] as char);
    }
    output
}

#[cfg(test)]
#[path = "real_tests.rs"]
mod tests;
