use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

const MAGIC: &[u8; 8] = b"HOWYIMP1";
const TRAILER: &[u8; 8] = b"DONEIMP1";
const VERSION: u32 = 1;
const MAX_FILES: usize = 64;
const MAX_DIRECTORY_ENTRIES: usize = 512;
const MAX_PATH_BYTES: usize = 4096;
const MAX_INPUT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WIDTH: u32 = 4096;
const MAX_HEIGHT: u32 = 4096;
const MAX_PIXEL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TOTAL_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const IMPORT_WALL_TIMEOUT: Duration = Duration::from_secs(45);
const IMPORT_CPU_SECONDS: libc::rlim_t = 30;
const IMPORT_ADDRESS_SPACE_BYTES: libc::rlim_t = 512 * 1024 * 1024;
const IMPORT_NOFILE: libc::rlim_t = 96;

pub(crate) struct StagedBatch {
    path: PathBuf,
    image_count: usize,
}

impl StagedBatch {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn image_count(&self) -> usize {
        self.image_count
    }
}

impl Drop for StagedBatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn stage_session(session: &Path) -> Result<StagedBatch> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("batch image staging requires root; run with sudo howy enroll-batch ...");
    }
    let session = validated_absolute_path(session)?;
    let identity = sudo_identity().context(
        "compressed batch import requires a non-root source identity; run `sudo howy enroll-batch ...` from the image-owning user",
    )?;
    let mut staging = create_staging_directory()?;
    let result = import_via_child(&session, identity, &staging.path, IMPORT_WALL_TIMEOUT);
    match result {
        Ok(image_count) => {
            staging.committed = true;
            Ok(StagedBatch {
                path: staging.path.clone(),
                image_count,
            })
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn run_hidden_importer(session_dir: &str) -> Result<()> {
    if std::env::var_os("HOWY_IMAGE_IMPORT_CHILD").as_deref() != Some(OsStr::new("1"))
        || unsafe { libc::geteuid() } == 0
        || unsafe { libc::getegid() } == 0
    {
        bail!("hidden image importer must run as the sandboxed non-root child");
    }
    if unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        bail!("image importer sandbox attributes were not preserved across exec");
    }
    let session = validated_absolute_path(Path::new(session_dir))?;
    let mut images = open_images(&session)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    output.write_all(MAGIC)?;
    output.write_all(&VERSION.to_le_bytes())?;
    output.write_all(&u32::try_from(images.len())?.to_le_bytes())?;
    let mut total_output = 0u64;
    for (index, image) in images.iter_mut().enumerate() {
        let encoded = image.read_bounded()?;
        let rgb = decode_bounded(&encoded, image.format)?;
        let (width, height) = rgb.dimensions();
        let bmp_len = normalized_bmp_len(width, height)?;
        total_output = total_output
            .checked_add(bmp_len)
            .filter(|total| *total <= MAX_TOTAL_OUTPUT_BYTES)
            .context("normalized image output exceeds aggregate limit")?;
        output.write_all(&u32::try_from(index)?.to_le_bytes())?;
        output.write_all(&width.to_le_bytes())?;
        output.write_all(&height.to_le_bytes())?;
        output.write_all(&bmp_len.to_le_bytes())?;
        write_normalized_bmp(&mut output, rgb.as_raw(), width, height)?;
    }
    output.write_all(TRAILER)?;
    output.flush()?;
    Ok(())
}

#[derive(Clone, Copy)]
struct SourceIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn sudo_identity() -> Result<SourceIdentity> {
    let uid = parse_nonzero_id("SUDO_UID", std::env::var_os("SUDO_UID"))?;
    let gid = parse_nonzero_id("SUDO_GID", std::env::var_os("SUDO_GID"))?;
    Ok(SourceIdentity { uid, gid })
}

fn parse_nonzero_id(name: &str, value: Option<OsString>) -> Result<u32> {
    let value = value.with_context(|| format!("{name} is not set"))?;
    let value = value
        .to_str()
        .with_context(|| format!("{name} is not valid UTF-8"))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{name} must be an unsigned decimal identity");
    }
    let id: u32 = value.parse().with_context(|| format!("invalid {name}"))?;
    if id == 0 {
        bail!("{name} must identify a non-root user/group");
    }
    Ok(id)
}

struct StagingGuard {
    path: PathBuf,
    committed: bool,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn create_staging_directory() -> Result<StagingGuard> {
    create_staging_directory_with(|path| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    })
}

fn create_staging_directory_with(
    set_private_permissions: impl Fn(&Path) -> std::io::Result<()>,
) -> Result<StagingGuard> {
    for attempt in 0..64u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/howy-import-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                // Establish cleanup ownership before any fallible permission or
                // verification step can leave a root-owned directory behind.
                let guard = StagingGuard {
                    path,
                    committed: false,
                };
                set_private_permissions(&guard.path)
                    .context("failed to make staging directory private")?;
                return Ok(guard);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).context("failed to create root-owned staging directory");
            }
        }
    }
    bail!("failed to create a unique staging directory")
}

fn import_via_child(
    session: &Path,
    identity: SourceIdentity,
    staging: &Path,
    timeout: Duration,
) -> Result<usize> {
    let executable = std::env::current_exe()
        .context("cannot resolve current howy executable")?
        .canonicalize()
        .context("cannot canonicalize current howy executable")?;
    if !executable.is_absolute() || !executable.is_file() {
        bail!("current howy executable is not a validated absolute file");
    }
    let mut command = Command::new(executable);
    command
        .arg("__image-import")
        .arg("--session-dir")
        .arg(session)
        .env_clear()
        .env("HOWY_IMAGE_IMPORT_CHILD", "1")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(move || sandbox_child(identity));
    }
    let mut child = command
        .spawn()
        .context("failed to launch non-root image importer")?;
    let mut killer = ChildGroupGuard::new(&mut child)?;
    let deadline = Instant::now() + timeout;
    let count = consume_framed_output(killer.child(), staging, deadline)?;
    wait_until_exited_without_reaping(killer.child(), deadline)?;
    killer.terminate_group();
    let status = killer.child().wait()?;
    if !status.success() {
        bail!("image importer failed with status {status}");
    }
    killer.disarm();
    Ok(count)
}

struct ChildGroupGuard<'a> {
    child: &'a mut Child,
    process_group: libc::pid_t,
    group_terminated: bool,
}

impl<'a> ChildGroupGuard<'a> {
    fn new(child: &'a mut Child) -> Result<Self> {
        let process_group = libc::pid_t::try_from(child.id()).context("importer PID overflow")?;
        let parent_group = unsafe { libc::getpgrp() };
        let actual_group = unsafe { libc::getpgid(process_group) };
        let actual_session = unsafe { libc::getsid(process_group) };
        if process_group <= 1
            || process_group == parent_group
            || actual_group != process_group
            || actual_session != process_group
        {
            let _ = child.kill();
            let _ = child.wait();
            bail!("image importer did not enter its dedicated process session");
        }
        Ok(Self {
            child,
            process_group,
            group_terminated: false,
        })
    }

    fn child(&mut self) -> &mut Child {
        self.child
    }

    fn terminate_group(&mut self) {
        if !self.group_terminated
            && self.process_group > 1
            && self.process_group != unsafe { libc::getpgrp() }
        {
            let _ = unsafe { libc::kill(-self.process_group, libc::SIGKILL) };
            self.group_terminated = true;
        }
    }

    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for ChildGroupGuard<'_> {
    fn drop(&mut self) {
        // Until terminate_group runs, the leader has not been reaped, so its PID
        // cannot be reused. setsid made PID == PGID == SID; the negative PID
        // therefore cannot signal the parent's group and includes descendants.
        self.terminate_group();
        let _ = self.child.wait();
    }
}

fn sandbox_child(identity: SourceIdentity) -> std::io::Result<()> {
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_limit(libc::RLIMIT_CORE, 0)?;
    set_limit(libc::RLIMIT_CPU, IMPORT_CPU_SECONDS)?;
    set_limit(libc::RLIMIT_AS, IMPORT_ADDRESS_SPACE_BYTES)?;
    set_limit(libc::RLIMIT_FSIZE, 0)?;
    set_limit(libc::RLIMIT_NOFILE, IMPORT_NOFILE)?;
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::setresgid(identity.gid, identity.gid, identity.gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::setresuid(identity.uid, identity.uid, identity.uid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { libc::umask(0o077) };
    if unsafe { libc::close_range(3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC as i32) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_limit(resource: libc::__rlimit_resource_t, value: libc::rlim_t) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn consume_framed_output(child: &mut Child, staging: &Path, deadline: Instant) -> Result<usize> {
    let mut stdout = child
        .stdout
        .take()
        .context("importer stdout is unavailable")?;
    consume_framed_stream(&mut stdout, staging, deadline)
}

fn consume_framed_stream(
    stdout: &mut (impl Read + AsRawFd),
    staging: &Path,
    deadline: Instant,
) -> Result<usize> {
    let mut fixed = [0u8; 8];
    read_exact_deadline(stdout, &mut fixed, deadline)?;
    if &fixed != MAGIC {
        bail!("image importer emitted an invalid framing magic");
    }
    let version = read_u32(stdout, deadline)?;
    if version != VERSION {
        bail!("unsupported image importer framing version {version}");
    }
    let count = usize::try_from(read_u32(stdout, deadline)?)?;
    if count == 0 || count > MAX_FILES {
        bail!("image importer emitted an invalid image count");
    }
    let mut total = 0u64;
    for expected_index in 0..count {
        let index = read_u32(stdout, deadline)?;
        let width = read_u32(stdout, deadline)?;
        let height = read_u32(stdout, deadline)?;
        let length = read_u64(stdout, deadline)?;
        if usize::try_from(index).ok() != Some(expected_index)
            || width == 0
            || height == 0
            || width > MAX_WIDTH
            || height > MAX_HEIGHT
            || normalized_bmp_len(width, height)? != length
        {
            bail!("image importer emitted invalid frame metadata");
        }
        total = total
            .checked_add(length)
            .filter(|total| *total <= MAX_TOTAL_OUTPUT_BYTES)
            .context("image importer output exceeds aggregate limit")?;
        write_staged_frame(
            staging,
            expected_index,
            width,
            height,
            length,
            stdout,
            deadline,
        )?;
    }
    read_exact_deadline(stdout, &mut fixed, deadline)?;
    if &fixed != TRAILER {
        bail!("image importer did not emit a valid completion trailer");
    }
    expect_eof_deadline(stdout, deadline)?;
    Ok(count)
}

fn expect_eof_deadline(reader: &mut (impl Read + AsRawFd), deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("image importer exceeded its wall-time limit")?;
    let timeout = i32::try_from(remaining.as_millis().max(1).min(i32::MAX as u128))?;
    let mut pollfd = libc::pollfd {
        fd: reader.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
    if result <= 0 {
        bail!("image importer did not terminate within its wall-time limit");
    }
    let mut byte = [0u8; 1];
    if reader.read(&mut byte)? != 0 {
        bail!("image importer emitted trailing bytes after completion");
    }
    Ok(())
}

fn write_staged_frame(
    staging: &Path,
    index: usize,
    width: u32,
    height: u32,
    length: u64,
    input: &mut (impl Read + AsRawFd),
    deadline: Instant,
) -> Result<()> {
    let temporary = staging.join(format!(".frame-{index:04}.part"));
    let final_path = staging.join(format!("frame-{index:04}.bmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let mut header = [0u8; 54];
    read_exact_deadline(input, &mut header, deadline)?;
    validate_normalized_bmp_header(&header, width, height, length)?;
    file.write_all(&header)?;
    let mut remaining = length.checked_sub(54).context("BMP length underflow")?;
    let mut buffer = [0u8; 16 * 1024];
    while remaining != 0 {
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))?;
        read_exact_deadline(input, &mut buffer[..chunk], deadline)?;
        file.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    std::fs::rename(&temporary, &final_path)?;
    Ok(())
}

fn read_exact_deadline<R: Read + AsRawFd>(
    reader: &mut R,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("image importer exceeded its wall-time limit")?;
        let timeout = i32::try_from(remaining.as_millis().max(1).min(i32::MAX as u128))?;
        let mut pollfd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if result == 0 {
            bail!("image importer exceeded its wall-time limit");
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        let read = reader.read(bytes)?;
        if read == 0 {
            bail!("image importer output ended prematurely");
        }
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn wait_until_exited_without_reaping(child: &mut Child, deadline: Instant) -> Result<()> {
    let child_id = libc::id_t::try_from(child.id()).context("importer PID overflow")?;
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
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to observe image importer");
        }
        let info = unsafe { info.assume_init() };
        if unsafe { info.si_pid() } != 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("image importer exceeded its wall-time limit");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn read_u32(input: &mut (impl Read + AsRawFd), deadline: Instant) -> Result<u32> {
    let mut bytes = [0u8; 4];
    read_exact_deadline(input, &mut bytes, deadline)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(input: &mut (impl Read + AsRawFd), deadline: Instant) -> Result<u64> {
    let mut bytes = [0u8; 8];
    read_exact_deadline(input, &mut bytes, deadline)?;
    Ok(u64::from_le_bytes(bytes))
}

#[derive(Clone, Copy)]
enum ImageFormat {
    Png,
    Jpeg,
    Bmp,
}

struct InputImage {
    file: File,
    encoded_len: usize,
    format: ImageFormat,
}

impl InputImage {
    fn read_bounded(&mut self) -> Result<Vec<u8>> {
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(self.encoded_len)?;
        std::io::Read::by_ref(&mut self.file)
            .take(MAX_INPUT_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut encoded)?;
        if encoded.len() != self.encoded_len || u64::try_from(encoded.len())? > MAX_INPUT_FILE_BYTES
        {
            bail!("image changed size during import");
        }
        Ok(encoded)
    }
}

fn open_images(path: &Path) -> Result<Vec<InputImage>> {
    let directory = open_absolute_directory_nofollow(path)?;
    let mut names = read_directory_names(&directory)?
        .into_iter()
        .filter_map(|name| image_format(&name).map(|format| (name, format)))
        .collect::<Vec<_>>();
    names.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if names.is_empty() || names.len() > MAX_FILES {
        bail!("session must contain between 1 and {MAX_FILES} PNG/JPEG/BMP images");
    }
    let mut total = 0u64;
    let mut images = Vec::new();
    images.try_reserve_exact(names.len())?;
    for (name, format) in names {
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("unsafe session image");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_INPUT_FILE_BYTES {
            bail!("session image is not a bounded regular file");
        }
        total = total
            .checked_add(metadata.len())
            .filter(|total| *total <= MAX_TOTAL_INPUT_BYTES)
            .context("session encoded image total exceeds limit")?;
        images.push(InputImage {
            file,
            encoded_len: usize::try_from(metadata.len())?,
            format,
        });
    }
    Ok(images)
}

fn validated_absolute_path(path: &Path) -> Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES || bytes.first() != Some(&b'/') {
        bail!("session path must be a bounded absolute path");
    }
    if bytes == b"/"
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        bail!("session path contains an unsafe component");
    }
    Ok(path.to_path_buf())
}

fn open_absolute_directory_nofollow(path: &Path) -> Result<File> {
    let root = CString::new("/")?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot open filesystem root");
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for component in path.as_os_str().as_bytes()[1..].split(|byte| *byte == b'/') {
        let component = CString::new(component)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("unsafe session path component");
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

fn read_directory_names(directory: &File) -> Result<Vec<OsString>> {
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot duplicate session directory");
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error()).context("cannot enumerate session directory");
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *libc::__errno_location() } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("directory enumeration failed");
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= MAX_DIRECTORY_ENTRIES {
            bail!("session directory contains too many entries");
        }
        names.push(OsString::from_vec(bytes.to_vec()));
    }
    Ok(names)
}

fn image_format(name: &OsStr) -> Option<ImageFormat> {
    let extension = Path::new(name).extension()?.to_str()?;
    if extension.eq_ignore_ascii_case("png") {
        Some(ImageFormat::Png)
    } else if extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg") {
        Some(ImageFormat::Jpeg)
    } else if extension.eq_ignore_ascii_case("bmp") {
        Some(ImageFormat::Bmp)
    } else {
        None
    }
}

fn decode_bounded(encoded: &[u8], format: ImageFormat) -> Result<image::RgbImage> {
    let format = match format {
        ImageFormat::Png => image::ImageFormat::Png,
        ImageFormat::Jpeg => image::ImageFormat::Jpeg,
        ImageFormat::Bmp => image::ImageFormat::Bmp,
    };
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_WIDTH);
    limits.max_image_height = Some(MAX_HEIGHT);
    limits.max_alloc = Some(128 * 1024 * 1024);
    let mut reader = image::ImageReader::with_format(Cursor::new(encoded), format);
    reader.limits(limits);
    let decoded = reader.decode().context("bounded image decode failed")?;
    let bytes = u64::from(decoded.width())
        .checked_mul(u64::from(decoded.height()))
        .and_then(|pixels| pixels.checked_mul(3))
        .context("decoded image size overflow")?;
    if bytes == 0 || bytes > MAX_PIXEL_BYTES {
        bail!("decoded image exceeds pixel limit");
    }
    Ok(decoded.to_rgb8())
}

fn normalized_bmp_len(width: u32, height: u32) -> Result<u64> {
    if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
        bail!("invalid normalized image dimensions");
    }
    let row = u64::from(width)
        .checked_mul(3)
        .context("BMP row overflow")?;
    let stride = row
        .checked_add(3)
        .map(|value| value & !3)
        .context("BMP stride overflow")?;
    let pixels = stride
        .checked_mul(u64::from(height))
        .context("BMP size overflow")?;
    let active_pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(3))
        .context("BMP active pixel size overflow")?;
    if active_pixels > MAX_PIXEL_BYTES {
        bail!("normalized image exceeds pixel limit");
    }
    54u64.checked_add(pixels).context("BMP length overflow")
}

fn write_normalized_bmp(
    output: &mut impl Write,
    rgb: &[u8],
    width: u32,
    height: u32,
) -> Result<()> {
    let length = normalized_bmp_len(width, height)?;
    let row_bytes = usize::try_from(width)?
        .checked_mul(3)
        .context("row overflow")?;
    let stride = row_bytes
        .checked_add(3)
        .map(|value| value & !3)
        .context("stride overflow")?;
    if rgb.len()
        != row_bytes
            .checked_mul(usize::try_from(height)?)
            .context("pixel overflow")?
    {
        bail!("decoded RGB length mismatch");
    }
    let mut header = [0u8; 54];
    header[0..2].copy_from_slice(b"BM");
    header[2..6].copy_from_slice(&u32::try_from(length)?.to_le_bytes());
    header[10..14].copy_from_slice(&54u32.to_le_bytes());
    header[14..18].copy_from_slice(&40u32.to_le_bytes());
    header[18..22].copy_from_slice(&i32::try_from(width)?.to_le_bytes());
    header[22..26].copy_from_slice(&i32::try_from(height)?.to_le_bytes());
    header[26..28].copy_from_slice(&1u16.to_le_bytes());
    header[28..30].copy_from_slice(&24u16.to_le_bytes());
    header[34..38].copy_from_slice(&u32::try_from(length - 54)?.to_le_bytes());
    output.write_all(&header)?;
    let padding = [0u8; 3];
    for row in (0..usize::try_from(height)?).rev() {
        let start = row.checked_mul(row_bytes).context("row offset overflow")?;
        let end = start.checked_add(row_bytes).context("row end overflow")?;
        for pixel in rgb[start..end].chunks_exact(3) {
            output.write_all(&[pixel[2], pixel[1], pixel[0]])?;
        }
        output.write_all(&padding[..stride - row_bytes])?;
    }
    Ok(())
}

fn validate_normalized_bmp_header(
    header: &[u8; 54],
    width: u32,
    height: u32,
    length: u64,
) -> Result<()> {
    if &header[0..2] != b"BM"
        || u64::from(u32::from_le_bytes(header[2..6].try_into()?)) != length
        || header[6..10] != [0, 0, 0, 0]
        || u32::from_le_bytes(header[10..14].try_into()?) != 54
        || u32::from_le_bytes(header[14..18].try_into()?) != 40
        || i32::from_le_bytes(header[18..22].try_into()?) != i32::try_from(width)?
        || i32::from_le_bytes(header[22..26].try_into()?) != i32::try_from(height)?
        || u16::from_le_bytes(header[26..28].try_into()?) != 1
        || u16::from_le_bytes(header[28..30].try_into()?) != 24
        || u32::from_le_bytes(header[30..34].try_into()?) != 0
        || u64::from(u32::from_le_bytes(header[34..38].try_into()?)) != length - 54
        || header[38..54] != [0; 16]
    {
        bail!("image importer emitted an invalid normalized BMP header");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageEncoder;
    use std::os::unix::net::UnixStream;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "howy-importer-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn encoded(format: ImageFormat) -> Vec<u8> {
        let pixels = [10, 20, 30, 40, 50, 60];
        let mut bytes = Vec::new();
        match format {
            ImageFormat::Png => image::codecs::png::PngEncoder::new(&mut bytes)
                .write_image(&pixels, 2, 1, image::ExtendedColorType::Rgb8)
                .unwrap(),
            ImageFormat::Jpeg => image::codecs::jpeg::JpegEncoder::new(&mut bytes)
                .write_image(&pixels, 2, 1, image::ExtendedColorType::Rgb8)
                .unwrap(),
            ImageFormat::Bmp => image::codecs::bmp::BmpEncoder::new(&mut bytes)
                .encode(&pixels, 2, 1, image::ExtendedColorType::Rgb8)
                .unwrap(),
        }
        bytes
    }

    #[test]
    fn png_jpeg_and_bmp_normalize_to_strict_bmp() {
        for format in [ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::Bmp] {
            let rgb = decode_bounded(&encoded(format), format).unwrap();
            let mut bmp = Vec::new();
            write_normalized_bmp(&mut bmp, rgb.as_raw(), 2, 1).unwrap();
            validate_normalized_bmp_header(bmp[..54].try_into().unwrap(), 2, 1, bmp.len() as u64)
                .unwrap();
        }
    }

    #[test]
    fn identity_validation_rejects_missing_root_and_malformed_values() {
        for value in [
            None,
            Some(OsString::from("0")),
            Some(OsString::from("-1")),
            Some(OsString::from("x")),
        ] {
            assert!(parse_nonzero_id("SUDO_UID", value).is_err());
        }
        assert_eq!(
            parse_nonzero_id("SUDO_UID", Some(OsString::from("1000"))).unwrap(),
            1000
        );
    }

    #[test]
    fn symlink_and_ambiguous_paths_fail_closed_without_modifying_sources() {
        use std::os::unix::fs::symlink;
        let directory = temp_dir("links");
        let image = directory.join("frame.png");
        std::fs::write(&image, encoded(ImageFormat::Png)).unwrap();
        symlink(&image, directory.join("linked.png")).unwrap();
        assert!(open_images(&directory).is_err());
        assert!(image.exists());
        assert!(validated_absolute_path(Path::new("relative")).is_err());
        assert!(validated_absolute_path(&directory.join("../other")).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn importer_enforces_file_count_before_opening_inputs() {
        let directory = temp_dir("count");
        for index in 0..=MAX_FILES {
            std::fs::write(directory.join(format!("frame-{index:03}.bmp")), b"x").unwrap();
        }
        assert!(open_images(&directory).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hostile_framing_and_timeout_are_bounded() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"BADMAGIC").unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        let staging = temp_dir("framing");
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(consume_framed_stream(&mut reader, &staging, deadline).is_err());

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(MAGIC).unwrap();
        writer.write_all(&VERSION.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&u64::MAX.to_le_bytes()).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            consume_framed_stream(
                &mut reader,
                &staging,
                Instant::now() + Duration::from_millis(100)
            )
            .is_err()
        );

        let (_writer, mut reader) = UnixStream::pair().unwrap();
        let mut byte = [0u8; 1];
        assert!(
            read_exact_deadline(
                &mut reader,
                &mut byte,
                Instant::now() + Duration::from_millis(10)
            )
            .is_err()
        );
        assert!(staging.exists());
        std::fs::remove_dir_all(staging).unwrap();
        assert!(normalized_bmp_len(MAX_WIDTH, MAX_HEIGHT).is_err());
    }

    #[test]
    fn staging_guard_cleans_partial_output_and_preserves_original() {
        let source = temp_dir("source");
        let original = source.join("frame.jpg");
        let bytes = encoded(ImageFormat::Jpeg);
        std::fs::write(&original, &bytes).unwrap();
        let staging = create_staging_directory().unwrap();
        let staging_path = staging.path.clone();
        assert_eq!(
            std::fs::metadata(&staging_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::write(staging_path.join(".partial"), b"partial").unwrap();
        drop(staging);
        assert!(!staging_path.exists());
        assert_eq!(std::fs::read(&original).unwrap(), bytes);
        std::fs::remove_dir_all(source).unwrap();
    }

    #[test]
    fn staging_guard_exists_before_permission_failure() {
        let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observed_by_setter = std::sync::Arc::clone(&observed);
        let result = create_staging_directory_with(move |path| {
            *observed_by_setter.lock().unwrap() = Some(path.to_path_buf());
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected chmod failure",
            ))
        });
        let Err(error) = result else {
            panic!("injected permission failure unexpectedly succeeded");
        };
        assert!(error.to_string().contains("private"));
        let path = observed.lock().unwrap().clone().unwrap();
        assert!(!path.exists(), "failed staging directory survived cleanup");
    }

    #[test]
    fn parent_streams_valid_frame_to_private_parent_named_staging_file() {
        let mut bmp = Vec::new();
        write_normalized_bmp(&mut bmp, &[10, 20, 30], 1, 1).unwrap();
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(MAGIC).unwrap();
        writer.write_all(&VERSION.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&1u32.to_le_bytes()).unwrap();
        writer.write_all(&(bmp.len() as u64).to_le_bytes()).unwrap();
        writer.write_all(&bmp).unwrap();
        writer.write_all(TRAILER).unwrap();
        writer.shutdown(std::net::Shutdown::Write).unwrap();

        let staging = temp_dir("valid-stream");
        assert_eq!(
            consume_framed_stream(
                &mut reader,
                &staging,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap(),
            1
        );
        let staged = staging.join("frame-0000.bmp");
        assert_eq!(std::fs::read(&staged).unwrap(), bmp);
        assert_eq!(
            std::fs::metadata(staged).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(staging).unwrap();
    }

    #[test]
    fn child_guard_kills_process_group_descendant_retaining_stdout_and_reaps_leader() {
        use std::io::BufRead;

        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 10 & echo $!; exit 1"])
            .stdout(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut descendant = String::new();
        stdout.read_line(&mut descendant).unwrap();
        let descendant: libc::pid_t = descendant.trim().parse().unwrap();
        {
            let _killer = ChildGroupGuard::new(&mut child).unwrap();
            assert!(
                expect_eof_deadline(stdout.get_mut(), Instant::now() + Duration::from_millis(20))
                    .is_err(),
                "descendant must retain stdout until group cleanup"
            );
        }
        assert!(child.try_wait().unwrap().is_some());
        assert!(
            expect_eof_deadline(stdout.get_mut(), Instant::now() + Duration::from_secs(1)).is_ok(),
            "group termination must release the inherited stdout pipe"
        );
        drop(stdout);
        let deadline = Instant::now() + Duration::from_secs(1);
        while unsafe { libc::kill(descendant, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_ne!(unsafe { libc::kill(descendant, 0) }, 0);
    }
}
