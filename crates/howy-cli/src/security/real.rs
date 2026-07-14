use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use howy_common::config::HowyConfig;
use howy_common::ipc::DaemonClient;
use howy_common::protocol::{Request, RespResult, SecurityInfoResult};
use howy_common::provisioning::{
    DaemonVerifierIdentityV1, FileLinkPolicy, FileMetadataSnapshotV1, FileObjectType,
    FileTimestampV1, MAX_NAMESPACE_CIPHERTEXT_BYTES, MAX_NAMESPACE_ENTRIES,
    MAX_NAMESPACE_NAME_BYTES, MAX_NAMESPACE_TOTAL_BYTES, MODE1_CREDENTIAL_DIRECTORY,
    MODE1_NAMESPACE_PATH, NamespaceDirectoryMetadata, NamespaceFileType, NamespaceFingerprintEntry,
    NamespaceInventoryV1, ReadinessResultV1, RecognizerIdentity, RestorableFileTimestampsV1,
    SECURITY_JOURNAL_PATH, SECURITY_LOCK_PATH, SECURITY_STATE_DIRECTORY,
    SECURITY_TRANSACTION_GUARD_PATH, SECURITY_UNADOPTED_DIRECTORY, Sha256Digest, UnitActiveState,
    UnitFileState, UnitKind, UnitLoadState, UnitObservation, UnitSubState, VerifierResultV1,
    classify_mode1_namespace_entry, namespace_fingerprint, validate_readiness_inventory,
};
use sha2::{Digest, Sha256};

use super::command::{self, CommandSpec, systemctl_command};
use super::engine::{
    AtomicWriteMode, ObservedFile, SecretKeyMaterial, SecurityError, SecurityResult,
    SecurityRuntime,
};

const LOCK_WAIT: Duration = Duration::from_secs(10);
const UNIT_SETTLE_STEP: Duration = Duration::from_millis(100);
const EXECUTABLE_MAX: usize = 1_073_741_824;

pub struct RealSecurityRuntime {
    lock: Option<File>,
    temporary_counter: u64,
    monotonic_origin: Instant,
}

impl RealSecurityRuntime {
    pub fn new() -> Self {
        Self {
            lock: None,
            temporary_counter: 0,
            monotonic_origin: Instant::now(),
        }
    }

    fn next_temporary_name(&mut self, target: &str) -> SecurityResult<String> {
        self.temporary_counter = self
            .temporary_counter
            .checked_add(1)
            .ok_or_else(|| SecurityError::operation("temporary name counter overflow"))?;
        Ok(format!(
            ".{target}.howy-tmp-{}-{}",
            std::process::id(),
            self.temporary_counter
        ))
    }

    fn read_exact_file(&self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>> {
        let (parent, name) = split_absolute(path)?;
        let Some(parent_fd) = open_directory_path(parent, false, 0o700)? else {
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

    fn write_atomic_internal(
        &mut self,
        path: &str,
        bytes: &[u8],
        permissions: u32,
        mode: AtomicWriteMode,
        timestamps: Option<&RestorableFileTimestampsV1>,
    ) -> SecurityResult<()> {
        let (parent, target_name) = split_absolute(path)?;
        let directory_mode = directory_mode_for(parent);
        let parent_fd = open_directory_path(parent, true, directory_mode)?
            .ok_or_else(|| SecurityError::operation("parent directory is absent"))?;
        validate_root_directory(parent_fd.as_raw_fd(), directory_mode)?;
        let temporary_name = self.next_temporary_name(target_name)?;
        let temporary = cstring(temporary_name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                permissions as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(SecurityError::operation(
                "exclusive temporary creation failed",
            ));
        }
        let mut temporary_file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            if unsafe { libc::fchown(temporary_file.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(temporary_file.as_raw_fd(), permissions as libc::mode_t) }
                    != 0
            {
                return Err(SecurityError::operation("temporary metadata setup failed"));
            }
            temporary_file
                .write_all(bytes)
                .map_err(|_| SecurityError::operation("temporary write failed"))?;
            if let Some(timestamps) = timestamps {
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
                if unsafe { libc::futimens(temporary_file.as_raw_fd(), times.as_ptr()) } != 0 {
                    return Err(SecurityError::operation(
                        "temporary timestamp restore failed",
                    ));
                }
            }
            temporary_file
                .sync_all()
                .map_err(|_| SecurityError::operation("temporary fsync failed"))?;
            let target = cstring(target_name.as_bytes())?;
            let target_stat = fstatat_nofollow(parent_fd.as_raw_fd(), &target)?;
            if target_stat.as_ref().is_some_and(|stat| {
                (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
                    || stat.st_uid != 0
                    || stat.st_gid != 0
                    || stat.st_nlink != 1
            }) {
                return Err(SecurityError::operation("atomic target object is unsafe"));
            }
            let target_exists = target_stat.is_some();
            let flags = match (mode, target_exists) {
                (AtomicWriteMode::NoReplace, _) => libc::RENAME_NOREPLACE,
                (AtomicWriteMode::ExchangeOrCreate, true) => libc::RENAME_EXCHANGE,
                (AtomicWriteMode::ExchangeOrCreate, false) => libc::RENAME_NOREPLACE,
            };
            renameat2(
                parent_fd.as_raw_fd(),
                &temporary,
                parent_fd.as_raw_fd(),
                &target,
                flags,
            )?;
            fsync_directory(parent_fd.as_raw_fd())?;
            if flags == libc::RENAME_EXCHANGE {
                if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), temporary.as_ptr(), 0) } != 0 {
                    return Err(SecurityError::operation("exchanged backup unlink failed"));
                }
                fsync_directory(parent_fd.as_raw_fd())?;
            }
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(parent_fd.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result
    }

    fn remove_safe(&self, path: &str) -> SecurityResult<()> {
        let (parent, name) = split_absolute(path)?;
        let Some(parent_fd) = open_directory_path(parent, false, 0o700)? else {
            return Ok(());
        };
        let name = cstring(name.as_bytes())?;
        let Some(stat) = fstatat_nofollow(parent_fd.as_raw_fd(), &name)? else {
            return Ok(());
        };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(SecurityError::operation("refusing to unlink unsafe object"));
        }
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::operation("safe unlink failed"));
        }
        fsync_directory(parent_fd.as_raw_fd())
    }

    fn run(
        &self,
        spec: &CommandSpec,
        input: &[u8],
        anonymous_output: bool,
    ) -> SecurityResult<ProcessOutput> {
        validate_executable(spec.executable)?;
        if input.len() != spec.stdin_bytes {
            return Err(SecurityError::operation("child stdin length mismatch"));
        }
        let mut output_file = anonymous_output.then(create_memfd).transpose()?;
        let mut command = Command::new(spec.executable);
        command.args(&spec.arguments);
        if spec.clear_environment {
            command.env_clear();
        }
        let stdout = match &output_file {
            Some(file) => Stdio::from(
                file.try_clone()
                    .map_err(|_| SecurityError::operation("anonymous output clone failed"))?,
            ),
            None => Stdio::piped(),
        };
        command
            .stdin(if input.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(stdout)
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| SecurityError::operation("absolute child spawn failed"))?;
        let process_group = -(child.id() as i32);
        if !input.is_empty() {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| SecurityError::operation("child stdin pipe missing"))?;
            if stdin.write_all(input).is_err() {
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(SecurityError::operation("bounded child stdin write failed"));
            }
            drop(stdin);
        }
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SecurityError::operation("child stderr pipe missing"))?;
        let stdout_cap = spec.stdout_cap;
        let stderr_cap = spec.stderr_cap;
        let stdout_reader = if anonymous_output {
            None
        } else {
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| SecurityError::operation("child stdout pipe missing"))?;
            Some(thread::spawn(move || read_capped(stdout, stdout_cap)))
        };
        let stderr_reader = thread::spawn(move || read_capped(stderr, stderr_cap));
        let deadline = Instant::now()
            .checked_add(spec.deadline)
            .ok_or_else(|| SecurityError::operation("child deadline overflow"))?;
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| SecurityError::operation("child wait failed"))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(process_group, libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                if let Some(reader) = stdout_reader {
                    let _ = reader.join();
                }
                let _ = stderr_reader.join();
                return Err(SecurityError::operation("child process deadline exceeded"));
            }
            thread::sleep(Duration::from_millis(10));
        };
        // The trusted tools are not expected to leave local descendants. Kill
        // any process-group member that retained a capture descriptor so the
        // bounded reader joins cannot outlive the parent deadline.
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
        let stdout = match stdout_reader {
            Some(reader) => reader
                .join()
                .map_err(|_| SecurityError::operation("stdout capture panicked"))??,
            None => Vec::new(),
        };
        let stderr = stderr_reader
            .join()
            .map_err(|_| SecurityError::operation("stderr capture panicked"))??;
        if !status.success() {
            return Err(SecurityError::operation(format!(
                "child process failed with status {}; stderr was redacted ({} bytes)",
                status,
                stderr.len()
            )));
        }
        let anonymous = if let Some(file) = output_file.as_mut() {
            file.seek(SeekFrom::Start(0))
                .map_err(|_| SecurityError::operation("anonymous output seek failed"))?;
            let mut bytes = Vec::new();
            file.take(howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| SecurityError::operation("anonymous output read failed"))?;
            if bytes.len() > howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX {
                return Err(SecurityError::operation("credential output exceeded cap"));
            }
            Some(bytes)
        } else {
            None
        };
        Ok(ProcessOutput { stdout, anonymous })
    }

    fn systemctl(&self, arguments: impl IntoIterator<Item = String>) -> SecurityResult<Vec<u8>> {
        let spec = systemctl_command(arguments);
        self.run(&spec, &[], false).map(|output| output.stdout)
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

    fn inventory_mode1(&self) -> SecurityResult<NamespaceInventoryV1> {
        let directory = open_directory_path(Path::new(MODE1_NAMESPACE_PATH), false, 0o700)?
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
        let directory = open_directory_path(Path::new(SECURITY_STATE_DIRECTORY), true, 0o700)?
            .ok_or_else(|| SecurityError::operation("security state directory missing"))?;
        validate_root_directory(directory.as_raw_fd(), 0o700)?;
        let name = cstring(b"lock")?;
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
            || Path::new(SECURITY_LOCK_PATH).file_name() != Some(OsStr::new("lock"))
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
            executable: command::SYSTEMCTL,
            arguments: vec!["--version".into()],
            clear_environment: true,
            stdin_bytes: 0,
            stdout_cap: 4096,
            stderr_cap: 4096,
            deadline: Duration::from_secs(5),
        };
        let output = self.run(&spec, &[], false)?.stdout;
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

    fn write_file_atomic(
        &mut self,
        path: &str,
        bytes: &[u8],
        permissions: u32,
        mode: AtomicWriteMode,
    ) -> SecurityResult<()> {
        self.write_atomic_internal(path, bytes, permissions, mode, None)
    }

    fn restore_file(
        &mut self,
        path: &str,
        snapshot: Option<&howy_common::provisioning::ExactFileSnapshot>,
    ) -> SecurityResult<()> {
        match snapshot {
            Some(snapshot) => {
                let maximum = match path {
                    howy_common::paths::CONFIG_FILE => howy_common::provisioning::MAX_CONFIG_BYTES,
                    howy_common::provisioning::SECURITY_RECEIPT_PATH => {
                        howy_common::provisioning::MAX_RECEIPT_BYTES
                    }
                    _ => howy_common::provisioning::MAX_DROPIN_BYTES,
                };
                let reconstruction = snapshot
                    .reconstruct(maximum)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                self.write_atomic_internal(
                    path,
                    &reconstruction.bytes,
                    reconstruction.metadata.permissions,
                    AtomicWriteMode::ExchangeOrCreate,
                    Some(&reconstruction.metadata.restorable_timestamps),
                )
            }
            None => self.remove_safe(path),
        }
    }

    fn create_guard(&mut self, transaction_id: &str) -> SecurityResult<()> {
        match self.read_exact_file(SECURITY_TRANSACTION_GUARD_PATH, 256)? {
            Some(guard) if guard.bytes == transaction_id.as_bytes() => Ok(()),
            Some(_) => Err(SecurityError::Uncertain(
                "a different transaction guard exists".into(),
            )),
            None => self.write_atomic_internal(
                SECURITY_TRANSACTION_GUARD_PATH,
                transaction_id.as_bytes(),
                0o600,
                AtomicWriteMode::NoReplace,
                None,
            ),
        }
    }

    fn remove_guard(&mut self) -> SecurityResult<()> {
        self.remove_safe(SECURITY_TRANSACTION_GUARD_PATH)
    }

    fn persist_journal(&mut self, bytes: &[u8]) -> SecurityResult<()> {
        self.write_atomic_internal(
            SECURITY_JOURNAL_PATH,
            bytes,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
            None,
        )
    }

    fn remove_journal(&mut self) -> SecurityResult<()> {
        self.remove_safe(SECURITY_JOURNAL_PATH)
    }

    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation> {
        self.query_unit(unit)
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
        let output = self.systemctl([
            "show".into(),
            unit.into(),
            "--property=LoadState".into(),
            "--value".into(),
        ])?;
        let state = std::str::from_utf8(&output)
            .map_err(|_| SecurityError::operation("transient state output invalid"))?
            .trim();
        Ok(!matches!(state, "not-found" | ""))
    }

    fn stop_and_kill_transient(&mut self, unit: &str) -> SecurityResult<()> {
        let _ = self.systemctl(["stop".into(), unit.into()]);
        let _ = self.systemctl([
            "kill".into(),
            "--kill-whom=all".into(),
            "--signal=KILL".into(),
            unit.into(),
        ]);
        for _ in 0..100 {
            match self.systemctl([
                "show".into(),
                unit.into(),
                "--property=ActiveState".into(),
                "--value".into(),
            ]) {
                Ok(output)
                    if matches!(
                        std::str::from_utf8(&output).unwrap_or_default().trim(),
                        "inactive" | "failed" | ""
                    ) =>
                {
                    return Ok(());
                }
                Err(_) if !self.transient_exists(unit)? => return Ok(()),
                _ => thread::sleep(UNIT_SETTLE_STEP),
            }
        }
        Err(SecurityError::operation(
            "readiness transient did not stop after kill",
        ))
    }

    fn encrypt_credential(
        &mut self,
        command: &CommandSpec,
        plaintext: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        self.run(command, plaintext, true)?
            .anonymous
            .ok_or_else(|| SecurityError::operation("credential output was not captured"))
    }

    fn run_readiness(&mut self, command: &CommandSpec) -> SecurityResult<Vec<u8>> {
        self.run(command, &[], false).map(|output| output.stdout)
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
        let binary = self
            .read_exact_file(command::HOWYD, EXECUTABLE_MAX)?
            .ok_or_else(|| SecurityError::operation("howyd is missing"))?;
        let version = env!("CARGO_PKG_VERSION").to_owned();
        let build_identity = option_env!("HOWY_BUILD_ID")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("howy-{version}+cargo"));
        VerifierResultV1::new(
            Sha256Digest::from_bytes(config_bytes),
            DaemonVerifierIdentityV1 {
                version,
                build_identity,
                binary_absolute_path: command::HOWYD.into(),
                binary_sha256: binary.sha256(),
            },
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

    fn unlink_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
    ) -> SecurityResult<()> {
        let (parent, name) = split_absolute(&expected.path)?;
        let directory = open_directory_path(parent, false, 0o700)?
            .ok_or_else(|| SecurityError::operation("artifact parent disappeared"))?;
        let parent_stat = fstat(directory.as_raw_fd())?;
        if parent_stat.st_dev != expected.parent_directory.device_id
            || parent_stat.st_ino != expected.parent_directory.inode
        {
            return Err(SecurityError::operation("artifact parent identity changed"));
        }
        let name = cstring(name.as_bytes())?;
        let stat = fstatat_nofollow(directory.as_raw_fd(), &name)?
            .ok_or_else(|| SecurityError::operation("artifact disappeared"))?;
        if stat.st_dev != expected.device_id
            || stat.st_ino != expected.inode
            || stat.st_nlink != expected.link_count
            || stat.st_uid != expected.uid
            || stat.st_gid != expected.gid
            || stat.st_mode & 0o7777 != expected.permissions
            || stat.st_size as u64 != expected.byte_length
        {
            return Err(SecurityError::operation("artifact identity changed"));
        }
        let current = self
            .read_exact_file(
                &expected.path,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("artifact disappeared"))?;
        if current.device_id != expected.device_id
            || current.inode != expected.inode
            || current.sha256() != expected.sha256
        {
            return Err(SecurityError::operation(
                "artifact bytes changed immediately before unlink",
            ));
        }
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(SecurityError::operation("artifact unlink failed"));
        }
        fsync_directory(directory.as_raw_fd())
    }

    fn boundary(&mut self, _name: &'static str) -> SecurityResult<()> {
        Ok(())
    }
}

struct ProcessOutput {
    stdout: Vec<u8>,
    anonymous: Option<Vec<u8>>,
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
    path: &Path,
    create: bool,
    final_mode: u32,
) -> SecurityResult<Option<OwnedFd>> {
    if !path.is_absolute() {
        return Err(SecurityError::operation("directory path is not absolute"));
    }
    let root = cstring(b"/")?;
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
    let components: Vec<_> = path
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

fn file_identity(stat: &libc::stat) -> (u64, u64, i64, i64, i64, i64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime,
        stat.st_mtime_nsec,
        stat.st_ctime_nsec,
    )
}

fn validate_executable(path: &str) -> SecurityResult<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| SecurityError::operation("required absolute executable is missing"))?;
    if !Path::new(path).is_absolute()
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

fn create_memfd() -> SecurityResult<File> {
    let name = cstring(b"howy-systemd-credential")?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    } as i32;
    if fd < 0 {
        return Err(SecurityError::operation(
            "anonymous credential output failed",
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_capped(mut reader: impl Read, cap: usize) -> SecurityResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut overflow = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| SecurityError::operation("child output read failed"))?;
        if count == 0 {
            break;
        }
        let remaining = cap.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        overflow |= count > remaining;
    }
    if overflow {
        return Err(SecurityError::operation("child output exceeded hard cap"));
    }
    Ok(output)
}

fn unit_name(kind: UnitKind) -> &'static str {
    match kind {
        UnitKind::Service => "howy.service",
        UnitKind::Socket => "howy.socket",
    }
}

fn parse_unit_observation(kind: UnitKind, output: &[u8]) -> SecurityResult<UnitObservation> {
    let text = std::str::from_utf8(output)
        .map_err(|_| SecurityError::operation("unit state output is not UTF-8"))?;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| SecurityError::operation("malformed unit state output"))?;
        if values.insert(key, value).is_some() {
            return Err(SecurityError::operation("duplicate unit state property"));
        }
    }
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
