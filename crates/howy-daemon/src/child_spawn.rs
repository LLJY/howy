//! Single fail-closed process-spawn boundary for the production daemon.
//!
//! The daemon must not invoke `Command` anywhere else. This boundary pins the
//! executable and camera device by descriptor, clears the environment, marks
//! every non-required descriptor close-on-exec, and drops to the fixed
//! unprivileged `howy-ffmpeg` identity before exec.

#[cfg(test)]
use std::ffi::OsString;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use howy_common::config::EmbeddingSecurityMode;
use zeroize::Zeroizing;

const FFMPEG_PATH: &str = "/usr/bin/ffmpeg";
const DROP_ACCOUNT: &str = "howy-ffmpeg";
const DROP_GECOS: &str = "Howy FFmpeg sandbox";
const DROP_HOME: &str = "/";
const DROP_SHELL: &str = "/usr/bin/nologin";
const SHARED_NOBODY_ID: u32 = 65_534;
const MAX_NSS_BUFFER: usize = 1024 * 1024;
const DEFAULT_NSS_BUFFER: usize = 16 * 1024;
const LOCAL_PASSWD_PATH: &str = "/etc/passwd";
const LOCAL_GROUP_PATH: &str = "/etc/group";
const LOCAL_SHADOW_PATH: &str = "/etc/shadow";

#[derive(Clone, Copy)]
struct DropIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    camera_gid: Option<libc::gid_t>,
    require_irreversible_drop: bool,
}

#[derive(Clone)]
struct CredentialProbe {
    directory: CString,
    credential: CString,
}

struct ValidatedExecutable {
    file: File,
}

/// Immutable child policy prepared before listener readiness or camera use.
pub struct DaemonChildPolicy {
    executable: Option<Arc<ValidatedExecutable>>,
    identity: Option<DropIdentity>,
    credential_probe: Option<CredentialProbe>,
    mode: EmbeddingSecurityMode,
    #[cfg(test)]
    test_environment: Vec<(OsString, OsString)>,
}

pub struct PreparedCameraFd {
    file: File,
    child_path: CString,
    identity: DropIdentity,
}

impl PreparedCameraFd {
    pub fn child_path(&self) -> String {
        self.child_path.to_string_lossy().into_owned()
    }
}

impl DaemonChildPolicy {
    /// Prepare the optional compatibility-child policy without changing the
    /// direct V4L2 path. Mode 0 and Mode 1 both require the packaged dedicated
    /// account for FFmpeg; an unavailable policy disables only that fallback.
    pub fn for_mode(mode: EmbeddingSecurityMode) -> Self {
        let credential_probe = if mode == EmbeddingSecurityMode::AeadCached {
            credential_probe_from_environment().ok()
        } else {
            None
        };
        let identity = resolve_drop_identity().ok();
        let executable = open_validated_executable(Path::new(FFMPEG_PATH))
            .ok()
            .map(Arc::new);
        Self {
            executable,
            identity,
            credential_probe,
            mode,
            #[cfg(test)]
            test_environment: Vec::new(),
        }
    }

    pub fn ffmpeg_available(&self) -> bool {
        self.executable.is_some()
            && self.identity.is_some()
            && (self.mode != EmbeddingSecurityMode::AeadCached || self.credential_probe.is_some())
    }

    /// Open the exact selected V4L2 node without following any path component.
    pub fn open_camera(&self, device: &str) -> Result<PreparedCameraFd> {
        if !self.ffmpeg_available() {
            bail!("isolated FFmpeg fallback is unavailable");
        }
        let file = open_absolute_no_follow(
            OsStr::new(device),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
        .context("selected camera could not be opened for isolated FFmpeg")?;
        let metadata = file
            .metadata()
            .context("selected camera metadata is unavailable")?;
        if !metadata.file_type().is_char_device() {
            bail!("selected camera is not a character device");
        }
        let base_identity = self
            .identity
            .context("isolated FFmpeg identity is unavailable")?;
        let identity = identity_for_camera(base_identity, &metadata)?;
        let child_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .expect("numeric camera descriptor path is a C string");
        Ok(PreparedCameraFd {
            file,
            child_path,
            identity,
        })
    }

    /// Spawn the reviewed FFmpeg executable with only stdio and camera FD.
    pub fn spawn_ffmpeg(&self, camera: PreparedCameraFd, args: &[String]) -> Result<Child> {
        let executable = self
            .executable
            .as_ref()
            .context("isolated FFmpeg executable is unavailable")?;
        if self.mode == EmbeddingSecurityMode::AeadCached && self.credential_probe.is_none() {
            bail!("isolated FFmpeg credential denial probe is unavailable");
        }

        let executable_fd = executable.file.as_raw_fd();
        let camera_fd = camera.file.as_raw_fd();
        let camera_path = camera.child_path.clone();
        let identity = camera.identity;
        let expected_parent = unsafe { libc::getpid() };
        let credential_probe = self.credential_probe.clone();
        let mut command = Command::new(format!("/proc/self/fd/{executable_fd}"));
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(test)]
        for (name, value) in &self.test_environment {
            command.env(name, value);
        }

        // SAFETY: this closure invokes only raw, async-signal-safe syscalls and
        // accesses data fully allocated before fork. Any failed hardening step
        // aborts spawn through Command's exec-error pipe.
        unsafe {
            command.pre_exec(move || {
                child_pre_exec(
                    expected_parent,
                    camera_fd,
                    &camera_path,
                    identity,
                    credential_probe.as_ref(),
                )
            });
        }
        let child = command.spawn().context("isolated FFmpeg spawn failed")?;
        drop(camera);
        Ok(child)
    }
}

fn child_pre_exec(
    expected_parent: libc::pid_t,
    camera_fd: RawFd,
    camera_path: &CStr,
    identity: DropIdentity,
    credential_probe: Option<&CredentialProbe>,
) -> io::Result<()> {
    set_parent_death_signal()?;
    if unsafe { libc::getppid() } != expected_parent {
        fail_closed_after_parent_change();
    }
    syscall_ok(unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    })?;
    syscall_ok(unsafe {
        libc::close_range(
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC as libc::c_int,
        )
    })?;
    syscall_ok(unsafe { libc::fcntl(camera_fd, libc::F_SETFD, 0) })?;

    if identity.require_irreversible_drop {
        let camera_gid = identity.camera_gid.unwrap_or_default();
        let (group_count, group_pointer) = if identity.camera_gid.is_some() {
            (1_usize, &camera_gid as *const libc::gid_t)
        } else {
            (0_usize, std::ptr::null::<libc::gid_t>())
        };
        raw_syscall_ok(unsafe { libc::syscall(libc::SYS_setgroups, group_count, group_pointer) })?;
        raw_syscall_ok(unsafe {
            libc::syscall(
                libc::SYS_setresgid,
                identity.gid,
                identity.gid,
                identity.gid,
            )
        })?;
        raw_syscall_ok(unsafe {
            libc::syscall(
                libc::SYS_setresuid,
                identity.uid,
                identity.uid,
                identity.uid,
            )
        })?;
    }
    verify_child_identity(identity)?;
    verify_camera_reopen(camera_path)?;
    if let Some(probe) = credential_probe {
        verify_inaccessible(&probe.directory, libc::O_RDONLY | libc::O_DIRECTORY)?;
        verify_inaccessible(&probe.credential, libc::O_RDONLY | libc::O_NONBLOCK)?;
    }
    establish_verified_post_drop_parent_death(expected_parent)?;
    Ok(())
}

fn set_parent_death_signal() -> io::Result<()> {
    syscall_ok(unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    })
}

fn establish_verified_post_drop_parent_death(expected_parent: libc::pid_t) -> io::Result<()> {
    set_parent_death_signal()?;
    let mut signal = 0;
    syscall_ok(unsafe {
        libc::prctl(
            libc::PR_GET_PDEATHSIG,
            &mut signal as *mut libc::c_int,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    })?;
    if signal != libc::SIGKILL {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    if unsafe { libc::getppid() } != expected_parent {
        fail_closed_after_parent_change();
    }
    Ok(())
}

fn fail_closed_after_parent_change() -> ! {
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
        libc::_exit(127);
    }
}

fn verify_camera_reopen(path: &CStr) -> io::Result<()> {
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    syscall_ok(unsafe { libc::close(descriptor) })
}

fn verify_child_identity(identity: DropIdentity) -> io::Result<()> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    raw_syscall_ok(unsafe {
        libc::syscall(
            libc::SYS_getresuid,
            &mut real_uid,
            &mut effective_uid,
            &mut saved_uid,
        )
    })?;
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    raw_syscall_ok(unsafe {
        libc::syscall(
            libc::SYS_getresgid,
            &mut real_gid,
            &mut effective_gid,
            &mut saved_gid,
        )
    })?;
    if [real_uid, effective_uid, saved_uid] != [identity.uid; 3]
        || [real_gid, effective_gid, saved_gid] != [identity.gid; 3]
    {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    if identity.require_irreversible_drop {
        let group_count = unsafe {
            libc::syscall(
                libc::SYS_getgroups,
                0_usize,
                std::ptr::null_mut::<libc::gid_t>(),
            )
        };
        let expected_count = if identity.camera_gid.is_some() { 1 } else { 0 };
        if group_count != expected_count {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if let Some(expected_gid) = identity.camera_gid {
            let mut actual_gid = 0;
            if unsafe { libc::syscall(libc::SYS_getgroups, 1_usize, &mut actual_gid) } != 1
                || actual_gid != expected_gid
            {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
        }
    }
    let no_new_privs = unsafe {
        libc::prctl(
            libc::PR_GET_NO_NEW_PRIVS,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if no_new_privs != 1 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    if identity.require_irreversible_drop {
        let regain = unsafe { libc::syscall(libc::SYS_setresuid, 0_u32, 0_u32, 0_u32) };
        if regain != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let regain_gid = unsafe { libc::syscall(libc::SYS_setresgid, 0_u32, 0_u32, 0_u32) };
        if regain_gid != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let regain_groups = unsafe {
            libc::syscall(
                libc::SYS_setgroups,
                1_usize,
                &identity.gid as *const libc::gid_t,
            )
        };
        if regain_groups != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}

fn identity_for_camera(identity: DropIdentity, metadata: &Metadata) -> Result<DropIdentity> {
    identity_for_camera_metadata(identity, metadata.uid(), metadata.gid(), metadata.mode())
}

fn identity_for_camera_metadata(
    mut identity: DropIdentity,
    owner: libc::uid_t,
    group: libc::gid_t,
    raw_mode: u32,
) -> Result<DropIdentity> {
    let mode = raw_mode & 0o777;
    let owner_can_reopen = owner == identity.uid && mode & 0o600 == 0o600;
    let primary_group_can_reopen = group == identity.gid && mode & 0o060 == 0o060;
    let other_can_reopen = mode & 0o006 == 0o006;
    identity.camera_gid = None;
    if owner_can_reopen || primary_group_can_reopen || other_can_reopen {
        return Ok(identity);
    }
    if mode & 0o060 == 0o060 && group != 0 && group != SHARED_NOBODY_ID && group != identity.gid {
        identity.camera_gid = Some(group);
        return Ok(identity);
    }
    bail!("dedicated FFmpeg identity cannot reopen the selected camera read-write")
}

fn verify_inaccessible(path: &CStr, flags: libc::c_int) -> io::Result<()> {
    let descriptor = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if descriptor >= 0 {
        unsafe { libc::close(descriptor) };
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    let error = io::Error::last_os_error();
    if !matches!(error.raw_os_error(), Some(code) if code == libc::EACCES || code == libc::EPERM) {
        return Err(error);
    }
    Ok(())
}

fn syscall_ok(status: libc::c_int) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn raw_syscall_ok(status: libc::c_long) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Validate the complete package-created FFmpeg account contract without
/// spawning a child or changing process credentials.
pub fn validate_ffmpeg_account() -> Result<()> {
    resolve_drop_identity().map(|_| ())
}

struct StdioFile(*mut libc::FILE);

impl Drop for StdioFile {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::fclose(self.0) };
        }
    }
}

fn open_local_database(path: &OsStr, expected_owner: u32) -> Result<StdioFile> {
    let file = open_absolute_no_follow(path, libc::O_RDONLY | libc::O_CLOEXEC)
        .with_context(|| format!("required local account database is unavailable: {:?}", path))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
    {
        bail!("local account database metadata was rejected");
    }
    let descriptor = file.into_raw_fd();
    let mode = CStr::from_bytes_with_nul(b"r\0").expect("static stdio mode");
    let stream = unsafe { libc::fdopen(descriptor, mode.as_ptr()) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(descriptor) };
        return Err(error.into());
    }
    if unsafe { libc::setvbuf(stream, std::ptr::null_mut(), libc::_IONBF, 0) } != 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::fclose(stream) };
        return Err(error.into());
    }
    Ok(StdioFile(stream))
}

fn for_each_local_passwd(
    path: &OsStr,
    expected_owner: u32,
    mut visit: impl FnMut(&libc::passwd) -> Result<()>,
) -> Result<()> {
    let stream = open_local_database(path, expected_owner)?;
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_NSS_BUFFER]);
    loop {
        let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::fgetpwent_r(
                stream.0,
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if result.is_null() {
            if status == 0 || status == libc::ENOENT {
                return Ok(());
            }
            bail!("local passwd database could not be parsed");
        }
        if status != 0 {
            bail!("local passwd database could not be parsed");
        }
        visit(&passwd)?;
    }
}

fn for_each_local_group(
    path: &OsStr,
    expected_owner: u32,
    mut visit: impl FnMut(&libc::group) -> Result<()>,
) -> Result<()> {
    let stream = open_local_database(path, expected_owner)?;
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_NSS_BUFFER]);
    loop {
        let mut group = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::fgetgrent_r(
                stream.0,
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if result.is_null() {
            if status == 0 || status == libc::ENOENT {
                return Ok(());
            }
            bail!("local group database could not be parsed");
        }
        if status != 0 {
            bail!("local group database could not be parsed");
        }
        visit(&group)?;
    }
}

fn for_each_local_shadow(
    path: &OsStr,
    expected_owner: u32,
    mut visit: impl FnMut(&libc::spwd) -> Result<()>,
) -> Result<()> {
    let stream = open_local_database(path, expected_owner)?;
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_NSS_BUFFER]);
    loop {
        let mut shadow = unsafe { std::mem::zeroed::<libc::spwd>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::fgetspent_r(
                stream.0,
                &mut shadow,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if result.is_null() {
            if status == 0 || status == libc::ENOENT {
                return Ok(());
            }
            bail!("local shadow database could not be parsed");
        }
        if status != 0 {
            bail!("local shadow database could not be parsed");
        }
        visit(&shadow)?;
    }
}

fn validate_local_account_files(
    passwd_path: &OsStr,
    group_path: &OsStr,
    shadow_path: &OsStr,
    expected_owner: u32,
) -> Result<(libc::uid_t, libc::gid_t)> {
    let mut identity = None;
    for_each_local_passwd(passwd_path, expected_owner, |passwd| {
        let name = unsafe { CStr::from_ptr(passwd.pw_name) }.to_bytes();
        if name != DROP_ACCOUNT.as_bytes() {
            return Ok(());
        }
        if identity.is_some() {
            bail!("dedicated FFmpeg account is duplicated in local passwd");
        }
        validate_drop_identity_metadata(
            passwd.pw_uid,
            passwd.pw_gid,
            name,
            unsafe { CStr::from_ptr(passwd.pw_gecos) }.to_bytes(),
            unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes(),
            unsafe { CStr::from_ptr(passwd.pw_shell) }.to_bytes(),
            false,
        )?;
        if unsafe { CStr::from_ptr(passwd.pw_passwd) }.to_bytes() != b"x" {
            bail!("dedicated FFmpeg passwd entry does not use shadow");
        }
        identity = Some((passwd.pw_uid, passwd.pw_gid));
        Ok(())
    })?;
    let (uid, gid) = identity.context("dedicated FFmpeg account is absent from local passwd")?;

    for_each_local_passwd(passwd_path, expected_owner, |passwd| {
        let name = unsafe { CStr::from_ptr(passwd.pw_name) }.to_bytes();
        if name != DROP_ACCOUNT.as_bytes() && (passwd.pw_uid == uid || passwd.pw_gid == gid) {
            bail!("dedicated FFmpeg UID or private primary GID is shared locally");
        }
        Ok(())
    })?;

    let mut group_found = false;
    for_each_local_group(group_path, expected_owner, |group| {
        let name = unsafe { CStr::from_ptr(group.gr_name) }.to_bytes();
        if name == DROP_ACCOUNT.as_bytes() {
            if group_found
                || group.gr_gid != gid
                || unsafe { CStr::from_ptr(group.gr_passwd) }.to_bytes() != b"x"
                || (!group.gr_mem.is_null() && !unsafe { *group.gr_mem }.is_null())
            {
                bail!("dedicated FFmpeg local group metadata was rejected");
            }
            group_found = true;
        } else if group.gr_gid == gid {
            bail!("dedicated FFmpeg primary GID is shared by another local group");
        }
        Ok(())
    })?;
    if !group_found {
        bail!("dedicated FFmpeg private primary group is absent locally");
    }

    let mut shadow_found = false;
    for_each_local_shadow(shadow_path, expected_owner, |shadow| {
        let name = unsafe { CStr::from_ptr(shadow.sp_namp) }.to_bytes();
        if name != DROP_ACCOUNT.as_bytes() {
            return Ok(());
        }
        if shadow_found
            || unsafe { CStr::from_ptr(shadow.sp_pwdp) }.to_bytes() != b"!*"
            || shadow.sp_lstchg < 0
            || shadow.sp_min != -1
            || shadow.sp_max != -1
            || shadow.sp_warn != -1
            || shadow.sp_inact != -1
            || shadow.sp_expire != 1
            || shadow.sp_flag != libc::c_ulong::MAX
        {
            bail!("dedicated FFmpeg shadow lock or expiration policy was rejected");
        }
        shadow_found = true;
        Ok(())
    })?;
    if !shadow_found {
        bail!("dedicated FFmpeg shadow entry is absent locally");
    }
    Ok((uid, gid))
}

fn resolve_drop_identity() -> Result<DropIdentity> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("daemon is not privileged enough to create an isolated child");
    }
    let local_identity = validate_local_account_files(
        OsStr::new(LOCAL_PASSWD_PATH),
        OsStr::new(LOCAL_GROUP_PATH),
        OsStr::new(LOCAL_SHADOW_PATH),
        0,
    )?;
    let requested = CString::new(DROP_ACCOUNT).expect("static account name");
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(MAX_NSS_BUFFER)
    } else {
        DEFAULT_NSS_BUFFER
    }
    .clamp(1, MAX_NSS_BUFFER);
    loop {
        let mut buffer = vec![0_u8; size];
        let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwnam_r(
                requested.as_ptr(),
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::EINTR {
            continue;
        }
        if status == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        if status != 0 || result.is_null() {
            bail!("validated unprivileged child identity is unavailable");
        }
        let name = unsafe { CStr::from_ptr(passwd.pw_name) };
        let gecos = unsafe { CStr::from_ptr(passwd.pw_gecos) };
        let home = unsafe { CStr::from_ptr(passwd.pw_dir) };
        let shell = unsafe { CStr::from_ptr(passwd.pw_shell) };
        let group_has_members = validate_drop_group(passwd.pw_gid)?;
        validate_drop_identity_metadata(
            passwd.pw_uid,
            passwd.pw_gid,
            name.to_bytes(),
            gecos.to_bytes(),
            home.to_bytes(),
            shell.to_bytes(),
            group_has_members,
        )?;
        validate_reverse_identity(passwd.pw_uid, passwd.pw_gid)?;
        validate_no_configured_supplementary_groups(passwd.pw_gid)?;
        if (passwd.pw_uid, passwd.pw_gid) != local_identity {
            bail!("dedicated FFmpeg local and NSS identities disagree");
        }
        return Ok(DropIdentity {
            uid: passwd.pw_uid,
            gid: passwd.pw_gid,
            camera_gid: None,
            require_irreversible_drop: true,
        });
    }
}

fn validate_no_configured_supplementary_groups(primary_gid: libc::gid_t) -> Result<()> {
    let account = CString::new(DROP_ACCOUNT).expect("static account name");
    let mut groups = [0 as libc::gid_t; 1];
    let mut group_count = 1;
    let status = unsafe {
        libc::getgrouplist(
            account.as_ptr(),
            primary_gid,
            groups.as_mut_ptr(),
            &mut group_count,
        )
    };
    if status < 0 || group_count != 1 || groups[0] != primary_gid {
        bail!("dedicated FFmpeg account has unexpected configured group memberships");
    }
    Ok(())
}

fn validate_reverse_identity(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(MAX_NSS_BUFFER)
    } else {
        DEFAULT_NSS_BUFFER
    }
    .clamp(1, MAX_NSS_BUFFER);
    loop {
        let mut buffer = vec![0_u8; size];
        let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::EINTR {
            continue;
        }
        if status == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        if status != 0
            || result.is_null()
            || unsafe { CStr::from_ptr(passwd.pw_name) }.to_bytes() != DROP_ACCOUNT.as_bytes()
        {
            bail!("dedicated FFmpeg UID is shared or does not resolve canonically");
        }
        break;
    }

    let suggested = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let mut size = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(MAX_NSS_BUFFER)
    } else {
        DEFAULT_NSS_BUFFER
    }
    .clamp(1, MAX_NSS_BUFFER);
    loop {
        let mut buffer = vec![0_u8; size];
        let mut group = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrgid_r(
                gid,
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::EINTR {
            continue;
        }
        if status == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        if status != 0
            || result.is_null()
            || unsafe { CStr::from_ptr(group.gr_name) }.to_bytes() != DROP_ACCOUNT.as_bytes()
        {
            bail!("dedicated FFmpeg GID is shared or does not resolve canonically");
        }
        return Ok(());
    }
}

fn validate_drop_group(expected_gid: libc::gid_t) -> Result<bool> {
    let requested = CString::new(DROP_ACCOUNT).expect("static group name");
    let suggested = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let mut size = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(MAX_NSS_BUFFER)
    } else {
        DEFAULT_NSS_BUFFER
    }
    .clamp(1, MAX_NSS_BUFFER);
    loop {
        let mut buffer = vec![0_u8; size];
        let mut group = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrnam_r(
                requested.as_ptr(),
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::EINTR {
            continue;
        }
        if status == libc::ERANGE && size < MAX_NSS_BUFFER {
            size = size.saturating_mul(2).min(MAX_NSS_BUFFER);
            continue;
        }
        if status != 0 || result.is_null() || group.gr_gid != expected_gid {
            bail!("dedicated FFmpeg primary group is unavailable");
        }
        let name = unsafe { CStr::from_ptr(group.gr_name) };
        if name.to_bytes() != DROP_ACCOUNT.as_bytes() {
            bail!("dedicated FFmpeg primary group was rejected");
        }
        let has_members = !group.gr_mem.is_null() && !unsafe { *group.gr_mem }.is_null();
        return Ok(has_members);
    }
}

fn validate_drop_identity_metadata(
    uid: libc::uid_t,
    gid: libc::gid_t,
    name: &[u8],
    gecos: &[u8],
    home: &[u8],
    shell: &[u8],
    primary_group_has_members: bool,
) -> Result<()> {
    if uid == 0
        || gid == 0
        || uid == SHARED_NOBODY_ID
        || gid == SHARED_NOBODY_ID
        || name != DROP_ACCOUNT.as_bytes()
        || gecos != DROP_GECOS.as_bytes()
        || home != DROP_HOME.as_bytes()
        || shell != DROP_SHELL.as_bytes()
        || primary_group_has_members
    {
        bail!("dedicated FFmpeg identity metadata was rejected");
    }
    Ok(())
}

fn credential_probe_from_environment() -> Result<CredentialProbe> {
    let directory =
        std::env::var_os("CREDENTIALS_DIRECTORY").context("credential directory is unavailable")?;
    validate_absolute_path(&directory)?;
    let mut credential = directory.as_bytes().to_vec();
    credential.push(b'/');
    credential.extend_from_slice(crate::mode1_key::MODE1_CREDENTIAL_NAME.as_bytes());
    Ok(CredentialProbe {
        directory: CString::new(directory.as_bytes()).context("credential directory is invalid")?,
        credential: CString::new(credential).context("credential path is invalid")?,
    })
}

fn open_validated_executable(path: &Path) -> Result<ValidatedExecutable> {
    if path != Path::new(FFMPEG_PATH) {
        bail!("FFmpeg path is not the reviewed absolute path");
    }
    let file = open_absolute_no_follow(path.as_os_str(), libc::O_PATH | libc::O_CLOEXEC)
        .context("reviewed FFmpeg executable could not be opened")?;
    validate_executable_metadata(&file.metadata()?)?;
    Ok(ValidatedExecutable { file })
}

fn validate_executable_metadata(metadata: &Metadata) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        bail!("reviewed FFmpeg executable metadata was rejected");
    }
    Ok(())
}

fn open_absolute_no_follow(path: &OsStr, final_flags: libc::c_int) -> io::Result<File> {
    validate_absolute_path(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let components = path.as_bytes()[1..]
        .split(|byte| *byte == b'/')
        .collect::<Vec<_>>();
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in &components[..components.len() - 1] {
        let component =
            CString::new(*component).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        current = unsafe { File::from_raw_fd(descriptor) };
    }
    let final_component = CString::new(*components.last().expect("validated non-root path"))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let descriptor = unsafe {
        libc::openat(
            current.as_raw_fd(),
            final_component.as_ptr(),
            final_flags | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn validate_absolute_path(path: &OsStr) -> Result<()> {
    let bytes = path.as_bytes();
    if bytes.len() < 2
        || bytes[0] != b'/'
        || bytes[1] == b'/'
        || bytes.last() == Some(&b'/')
        || bytes.contains(&0)
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        bail!("absolute child path is ambiguous");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn set_inheritable(fd: RawFd) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    }

    fn canary_policy(
        probe: CredentialProbe,
        environment: Vec<(OsString, OsString)>,
    ) -> DaemonChildPolicy {
        let executable = open_absolute_no_follow(
            std::env::current_exe().unwrap().as_os_str(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
        .unwrap();
        let identity = DropIdentity {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            camera_gid: None,
            require_irreversible_drop: false,
        };
        DaemonChildPolicy {
            executable: Some(Arc::new(ValidatedExecutable { file: executable })),
            identity: Some(identity),
            credential_probe: Some(probe),
            mode: EmbeddingSecurityMode::AeadCached,
            test_environment: environment,
        }
    }

    #[test]
    fn executable_metadata_policy_is_root_regular_executable_and_not_writable() {
        let metadata = std::fs::metadata(FFMPEG_PATH).unwrap();
        assert!(validate_executable_metadata(&metadata).is_ok());
    }

    #[test]
    fn no_follow_open_rejects_intermediate_and_final_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "howy-child-path-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let file = real.join("camera");
        std::fs::write(&file, b"x").unwrap();
        std::os::unix::fs::symlink(&real, root.join("dir-link")).unwrap();
        std::os::unix::fs::symlink(&file, real.join("file-link")).unwrap();
        assert!(
            open_absolute_no_follow(
                root.join("dir-link/camera").as_os_str(),
                libc::O_RDONLY | libc::O_CLOEXEC
            )
            .is_err()
        );
        assert!(
            open_absolute_no_follow(
                real.join("file-link").as_os_str(),
                libc::O_RDONLY | libc::O_CLOEXEC
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_clears_environment_and_fails_closed_without_root_drop_capability() {
        let policy = DaemonChildPolicy::for_mode(EmbeddingSecurityMode::Plaintext);
        if unsafe { libc::geteuid() } != 0 {
            assert!(!policy.ffmpeg_available());
        }
        assert!(policy.test_environment.is_empty());
    }

    #[test]
    fn dedicated_identity_policy_rejects_root_shared_login_and_group_metadata() {
        assert!(
            validate_drop_identity_metadata(
                971,
                971,
                b"howy-ffmpeg",
                b"Howy FFmpeg sandbox",
                b"/",
                b"/usr/bin/nologin",
                false,
            )
            .is_ok()
        );
        for rejected in [
            (
                0,
                971,
                b"howy-ffmpeg".as_slice(),
                b"/usr/bin/nologin".as_slice(),
                false,
            ),
            (
                SHARED_NOBODY_ID,
                SHARED_NOBODY_ID,
                b"howy-ffmpeg".as_slice(),
                b"/usr/bin/nologin".as_slice(),
                false,
            ),
            (
                971,
                971,
                b"nobody".as_slice(),
                b"/usr/bin/nologin".as_slice(),
                false,
            ),
            (
                971,
                971,
                b"howy-ffmpeg".as_slice(),
                b"/bin/sh".as_slice(),
                false,
            ),
            (
                971,
                971,
                b"howy-ffmpeg".as_slice(),
                b"/usr/bin/nologin".as_slice(),
                true,
            ),
        ] {
            assert!(
                validate_drop_identity_metadata(
                    rejected.0,
                    rejected.1,
                    rejected.2,
                    b"Howy FFmpeg sandbox",
                    b"/",
                    rejected.3,
                    rejected.4,
                )
                .is_err()
            );
        }
    }

    fn write_local_account_fixture(
        root: &Path,
        passwd: &str,
        group: &str,
        shadow: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let passwd_path = root.join("passwd");
        let group_path = root.join("group");
        let shadow_path = root.join("shadow");
        std::fs::write(&passwd_path, passwd).unwrap();
        std::fs::write(&group_path, group).unwrap();
        std::fs::write(&shadow_path, shadow).unwrap();
        std::fs::set_permissions(&passwd_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&group_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (passwd_path, group_path, shadow_path)
    }

    #[test]
    fn local_account_database_fixture_enforces_shadow_lock_and_private_primary_gid() {
        let root = std::env::temp_dir().join(format!(
            "howy-account-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let owner = unsafe { libc::geteuid() };
        let conforming_passwd = concat!(
            "root:x:0:0:root:/root:/bin/sh\n",
            "howy-ffmpeg:x:971:971:Howy FFmpeg sandbox:/:/usr/bin/nologin\n"
        );
        let conforming_group = "root:x:0:\nhowy-ffmpeg:x:971:\n";
        let conforming_shadow = "root:!*:20000:::::1:\nhowy-ffmpeg:!*:20000:::::1:\n";
        let (passwd, group, shadow) = write_local_account_fixture(
            &root,
            conforming_passwd,
            conforming_group,
            conforming_shadow,
        );
        assert_eq!(
            validate_local_account_files(
                passwd.as_os_str(),
                group.as_os_str(),
                shadow.as_os_str(),
                owner,
            )
            .unwrap(),
            (971, 971)
        );

        let conflicts = [
            (
                concat!(
                    "other:x:971:1001:Other:/nonexistent:/usr/bin/nologin\n",
                    "howy-ffmpeg:x:971:971:Howy FFmpeg sandbox:/:/usr/bin/nologin\n"
                ),
                conforming_group,
                conforming_shadow,
            ),
            (
                "howy-ffmpeg:x:971:971:Howy FFmpeg sandbox:/:/bin/sh\n",
                conforming_group,
                conforming_shadow,
            ),
            (
                concat!(
                    "other:x:1001:971:Other:/nonexistent:/usr/bin/nologin\n",
                    "howy-ffmpeg:x:971:971:Howy FFmpeg sandbox:/:/usr/bin/nologin\n"
                ),
                conforming_group,
                conforming_shadow,
            ),
            (
                conforming_passwd,
                "root:x:0:\nhowy-ffmpeg:x:972:\n",
                conforming_shadow,
            ),
            (
                conforming_passwd,
                "root:x:0:\nhowy-ffmpeg:x:971:other\n",
                conforming_shadow,
            ),
            (
                conforming_passwd,
                conforming_group,
                "howy-ffmpeg:!:20000:::::1:\n",
            ),
            (
                conforming_passwd,
                conforming_group,
                "howy-ffmpeg:!*:20000::::::\n",
            ),
        ];
        for (index, (passwd_contents, group_contents, shadow_contents)) in
            conflicts.into_iter().enumerate()
        {
            let case = root.join(format!("case-{index}"));
            std::fs::create_dir(&case).unwrap();
            let (passwd, group, shadow) = write_local_account_fixture(
                &case,
                passwd_contents,
                group_contents,
                shadow_contents,
            );
            assert!(
                validate_local_account_files(
                    passwd.as_os_str(),
                    group.as_os_str(),
                    shadow.as_os_str(),
                    owner,
                )
                .is_err(),
                "conflicting local account fixture {index} was accepted"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn camera_policy_keeps_only_a_required_nonshared_device_group() {
        let base = DropIdentity {
            uid: 971,
            gid: 971,
            camera_gid: None,
            require_irreversible_drop: true,
        };
        assert_eq!(
            identity_for_camera_metadata(base, 0, 44, 0o660)
                .unwrap()
                .camera_gid,
            Some(44)
        );
        for (owner, group, mode) in [(971, 44, 0o600), (0, 971, 0o660), (0, 44, 0o666)] {
            assert_eq!(
                identity_for_camera_metadata(base, owner, group, mode)
                    .unwrap()
                    .camera_gid,
                None
            );
        }
        for group in [0, SHARED_NOBODY_ID] {
            assert!(identity_for_camera_metadata(base, 0, group, 0o660).is_err());
        }
        assert!(identity_for_camera_metadata(base, 0, 44, 0o640).is_err());
    }

    #[test]
    fn sysusers_definition_is_one_locked_private_account() {
        let active = include_str!("../../../sysusers.d/howy.conf")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();
        assert_eq!(
            active,
            ["u! howy-ffmpeg - \"Howy FFmpeg sandbox\" - /usr/bin/nologin"]
        );
    }

    #[test]
    fn production_daemon_command_creation_has_one_source_boundary() {
        fn before_test_module(source: &str) -> &str {
            source
                .split("\n#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(source)
        }
        for source in [
            include_str!("authorization.rs"),
            include_str!("camera.rs"),
            include_str!("inference.rs"),
            include_str!("lib.rs"),
            include_str!("prompt_state.rs"),
            include_str!("server.rs"),
            include_str!("storage/cache.rs"),
            include_str!("storage/mod.rs"),
            include_str!("storage/plaintext.rs"),
            include_str!("main.rs"),
            include_str!("mode1_key.rs"),
        ] {
            let production = before_test_module(source);
            assert!(!production.contains("Command::new("));
            assert!(!production.contains(".spawn()"));
        }
        let boundary = before_test_module(include_str!("child_spawn.rs"));
        assert_eq!(boundary.matches("Command::new(").count(), 1);
        assert_eq!(boundary.matches(".spawn()").count(), 1);
    }

    #[test]
    fn fixture_permissions_can_model_an_inaccessible_credential_mount() {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "unprivileged credential policy test must run non-root"
        );
        let root = std::env::temp_dir().join(format!("howy-child-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        assert!(verify_inaccessible(&path, libc::O_RDONLY | libc::O_DIRECTORY).is_ok());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn sandbox_child_canary() {
        if std::env::var_os("HOWY_CHILD_CANARY").as_deref() != Some(OsStr::new("1")) {
            return;
        }
        for forbidden in [
            "CREDENTIALS_DIRECTORY",
            "LISTEN_FDS",
            "LISTEN_PID",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "PATH",
            "HOME",
        ] {
            assert!(
                std::env::var_os(forbidden).is_none(),
                "inherited {forbidden}"
            );
        }
        let required_fd: RawFd = std::env::var("HOWY_REQUIRED_FD").unwrap().parse().unwrap();
        assert!(unsafe { libc::fcntl(required_fd, libc::F_GETFD) } >= 0);
        for name in ["HOWY_SENTINEL_FD", "HOWY_LISTENER_FD"] {
            let fd: RawFd = std::env::var(name).unwrap().parse().unwrap();
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
        assert_eq!(
            unsafe {
                libc::prctl(
                    libc::PR_GET_NO_NEW_PRIVS,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            },
            1
        );
        let credential = CString::new(std::env::var("HOWY_DENIED_CREDENTIAL").unwrap()).unwrap();
        assert!(verify_inaccessible(&credential, libc::O_RDONLY).is_ok());
        let expected_uid: u32 = std::env::var("HOWY_EXPECTED_UID").unwrap().parse().unwrap();
        let expected_gid: u32 = std::env::var("HOWY_EXPECTED_GID").unwrap().parse().unwrap();
        assert_eq!(unsafe { libc::getuid() }, expected_uid);
        assert_eq!(unsafe { libc::geteuid() }, expected_uid);
        assert_eq!(unsafe { libc::getgid() }, expected_gid);
        assert_eq!(unsafe { libc::getegid() }, expected_gid);
        if std::env::var_os("HOWY_EXPECT_DROP").as_deref() == Some(OsStr::new("1")) {
            assert_eq!(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, 0);
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_setresuid, 0_u32, 0_u32, 0_u32) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        }
    }

    #[test]
    fn spawned_canary_gets_exact_env_fd_and_identity_policy() {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "unprivileged child canary must run non-root"
        );
        let root = std::env::temp_dir().join(format!(
            "howy-child-canary-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let credential_path = root.join("credential");
        std::fs::write(&credential_path, b"canary").unwrap();
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();

        let sentinel = File::open("/dev/null").unwrap();
        set_inheritable(sentinel.as_raw_fd());
        let socket_path =
            std::env::temp_dir().join(format!("howy-child-listener-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        set_inheritable(listener.as_raw_fd());

        let camera =
            open_absolute_no_follow(OsStr::new("/dev/null"), libc::O_RDWR | libc::O_CLOEXEC)
                .unwrap();
        let required_fd = camera.as_raw_fd();
        let identity = DropIdentity {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            camera_gid: None,
            require_irreversible_drop: false,
        };
        let environment = vec![
            ("HOWY_CHILD_CANARY".into(), "1".into()),
            ("HOWY_REQUIRED_FD".into(), required_fd.to_string().into()),
            (
                "HOWY_SENTINEL_FD".into(),
                sentinel.as_raw_fd().to_string().into(),
            ),
            (
                "HOWY_LISTENER_FD".into(),
                listener.as_raw_fd().to_string().into(),
            ),
            (
                "HOWY_DENIED_CREDENTIAL".into(),
                credential_path.as_os_str().into(),
            ),
            ("HOWY_EXPECTED_UID".into(), identity.uid.to_string().into()),
            ("HOWY_EXPECTED_GID".into(), identity.gid.to_string().into()),
            (
                "HOWY_EXPECT_DROP".into(),
                if identity.require_irreversible_drop {
                    "1"
                } else {
                    "0"
                }
                .into(),
            ),
        ];
        let policy = canary_policy(
            CredentialProbe {
                directory: CString::new(root.as_os_str().as_bytes()).unwrap(),
                credential: CString::new(credential_path.as_os_str().as_bytes()).unwrap(),
            },
            environment,
        );
        let child = policy
            .spawn_ffmpeg(
                PreparedCameraFd {
                    child_path: CString::new(format!("/proc/self/fd/{}", camera.as_raw_fd()))
                        .unwrap(),
                    file: camera,
                    identity,
                },
                &[
                    "--exact".into(),
                    "child_spawn::tests::sandbox_child_canary".into(),
                    "--nocapture".into(),
                ],
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "child stdout: {}\nchild stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        drop((listener, sentinel));
        std::fs::remove_file(socket_path).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    const PARENT_DEATH_EXEC_READY_FD: RawFd = 198;
    const PARENT_DEATH_EXEC_MARKER: libc::pid_t = 0x5044;

    #[test]
    fn parent_death_exec_canary() {
        if !std::env::args().any(|argument| argument == "--exact")
            || unsafe { libc::fcntl(PARENT_DEATH_EXEC_READY_FD, libc::F_GETFD) } < 0
        {
            return;
        }
        let report = [unsafe { libc::getpid() }, PARENT_DEATH_EXEC_MARKER];
        assert_eq!(
            unsafe {
                libc::write(
                    PARENT_DEATH_EXEC_READY_FD,
                    report.as_ptr().cast(),
                    std::mem::size_of_val(&report),
                )
            },
            std::mem::size_of_val(&report) as isize
        );
        loop {
            unsafe { libc::pause() };
        }
    }

    #[test]
    fn post_policy_parent_death_signal_kills_child_when_parent_exits() {
        let mut ready = [-1; 2];
        let mut release_parent = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(release_parent.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let executable = CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes())
            .expect("test executable path is a C string");
        let exact = CStr::from_bytes_with_nul(b"--exact\0").unwrap();
        let canary =
            CStr::from_bytes_with_nul(b"child_spawn::tests::parent_death_exec_canary\0").unwrap();
        let nocapture = CStr::from_bytes_with_nul(b"--nocapture\0").unwrap();
        let exec_arguments = [
            executable.as_ptr(),
            exact.as_ptr(),
            canary.as_ptr(),
            nocapture.as_ptr(),
            std::ptr::null(),
        ];

        let supervisor = unsafe { libc::fork() };
        assert!(supervisor >= 0);
        if supervisor == 0 {
            unsafe {
                libc::close(ready[0]);
                libc::close(release_parent[1]);
            }
            let worker = unsafe { libc::fork() };
            if worker < 0 {
                unsafe { libc::_exit(10) };
            }
            if worker == 0 {
                unsafe { libc::close(release_parent[0]) };
                let expected_parent = unsafe { libc::getppid() };
                if set_parent_death_signal().is_err() {
                    unsafe { libc::_exit(11) };
                }
                // Model the credential changes that clear the early setting.
                if unsafe {
                    libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                } != 0
                    || establish_verified_post_drop_parent_death(expected_parent).is_err()
                {
                    unsafe { libc::_exit(12) };
                }
                let mut signal = 0;
                if unsafe {
                    libc::prctl(
                        libc::PR_GET_PDEATHSIG,
                        &mut signal as *mut libc::c_int,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                } != 0
                {
                    unsafe { libc::_exit(13) };
                }
                let report = [unsafe { libc::getpid() }, signal];
                if unsafe {
                    libc::write(
                        ready[1],
                        report.as_ptr().cast(),
                        std::mem::size_of_val(&report),
                    )
                } != std::mem::size_of_val(&report) as isize
                {
                    unsafe { libc::_exit(14) };
                }
                if unsafe { libc::dup2(ready[1], PARENT_DEATH_EXEC_READY_FD) }
                    != PARENT_DEATH_EXEC_READY_FD
                {
                    unsafe { libc::_exit(15) };
                }
                unsafe {
                    libc::close(ready[1]);
                    libc::execv(executable.as_ptr(), exec_arguments.as_ptr());
                    libc::_exit(16);
                }
            }

            unsafe { libc::close(ready[1]) };
            let mut release = 0_u8;
            if unsafe { libc::read(release_parent[0], (&mut release as *mut u8).cast(), 1) } != 1 {
                unsafe { libc::_exit(17) };
            }
            unsafe { libc::_exit(0) };
        }

        unsafe {
            libc::close(ready[1]);
            libc::close(release_parent[0]);
        }
        let mut report = [0_i32; 2];
        assert_eq!(
            unsafe {
                libc::read(
                    ready[0],
                    report.as_mut_ptr().cast(),
                    std::mem::size_of_val(&report),
                )
            },
            std::mem::size_of_val(&report) as isize
        );
        assert_eq!(report[1], libc::SIGKILL);
        let mut exec_report = [0_i32; 2];
        assert_eq!(
            unsafe {
                libc::read(
                    ready[0],
                    exec_report.as_mut_ptr().cast(),
                    std::mem::size_of_val(&exec_report),
                )
            },
            std::mem::size_of_val(&exec_report) as isize
        );
        assert_eq!(exec_report, [report[0], PARENT_DEATH_EXEC_MARKER]);
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, report[0], 0_u32) } as RawFd;
        assert!(
            pidfd >= 0,
            "pidfd_open failed: {}",
            io::Error::last_os_error()
        );
        let release = [1_u8];
        assert_eq!(
            unsafe { libc::write(release_parent[1], release.as_ptr().cast(), 1) },
            1
        );
        unsafe {
            libc::close(release_parent[1]);
            libc::close(ready[0]);
        }
        let mut supervisor_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(supervisor, &mut supervisor_status, 0) },
            supervisor
        );
        assert!(libc::WIFEXITED(supervisor_status));
        assert_eq!(libc::WEXITSTATUS(supervisor_status), 0);

        let mut poll_descriptor = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_result = unsafe { libc::poll(&mut poll_descriptor, 1, 3_000) };
        if poll_result != 1 {
            unsafe { libc::kill(report[0], libc::SIGKILL) };
        }
        unsafe { libc::close(pidfd) };
        assert_eq!(
            poll_result, 1,
            "post-policy parent death did not kill child"
        );
        assert_ne!(poll_descriptor.revents & libc::POLLIN, 0);
    }

    #[test]
    #[ignore = "requires disposable root environment"]
    fn disposable_root_real_drop_groups_camera_reopen_and_credential_denial() {
        if std::env::var_os("HOWY_ROOT_DROP_CANARY").as_deref() == Some(OsStr::new("1")) {
            let expected_uid: u32 = std::env::var("HOWY_EXPECTED_UID").unwrap().parse().unwrap();
            let expected_gid: u32 = std::env::var("HOWY_EXPECTED_GID").unwrap().parse().unwrap();
            assert_eq!(unsafe { libc::getuid() }, expected_uid);
            assert_eq!(unsafe { libc::geteuid() }, expected_uid);
            assert_eq!(unsafe { libc::getgid() }, expected_gid);
            assert_eq!(unsafe { libc::getegid() }, expected_gid);
            let expected_camera_gid: u32 = std::env::var("HOWY_EXPECTED_CAMERA_GID")
                .unwrap()
                .parse()
                .unwrap();
            let mut actual_camera_gid = 0;
            assert_eq!(unsafe { libc::getgroups(1, &mut actual_camera_gid) }, 1);
            assert_eq!(actual_camera_gid, expected_camera_gid);
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_setresuid, 0_u32, 0_u32, 0_u32) },
                -1
            );
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
            let credential =
                CString::new(std::env::var("HOWY_DENIED_CREDENTIAL").unwrap()).unwrap();
            verify_inaccessible(&credential, libc::O_RDONLY).unwrap();
            return;
        }

        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "qualification must run as root in a disposable environment"
        );
        let identity = resolve_drop_identity().expect("dedicated howy-ffmpeg account is installed");
        let root = std::env::temp_dir().join(format!("howy-child-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let credential_path = root.join("credential");
        std::fs::write(&credential_path, b"canary").unwrap();
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let camera_gid = if identity.gid == 4_242 { 4_243 } else { 4_242 };
        let camera_path = root.join("camera");
        let camera_path_c = CString::new(camera_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mknod(
                    camera_path_c.as_ptr(),
                    libc::S_IFCHR | 0o660,
                    libc::makedev(1, 3),
                )
            },
            0,
            "temporary character-device fixture failed: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::chown(camera_path_c.as_ptr(), 0, camera_gid) },
            0
        );
        std::fs::set_permissions(&camera_path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let executable = open_absolute_no_follow(
            std::env::current_exe().unwrap().as_os_str(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
        .unwrap();
        let environment = vec![
            ("HOWY_ROOT_DROP_CANARY".into(), "1".into()),
            ("HOWY_EXPECTED_UID".into(), identity.uid.to_string().into()),
            ("HOWY_EXPECTED_GID".into(), identity.gid.to_string().into()),
            (
                "HOWY_EXPECTED_CAMERA_GID".into(),
                camera_gid.to_string().into(),
            ),
            (
                "HOWY_DENIED_CREDENTIAL".into(),
                credential_path.as_os_str().into(),
            ),
        ];
        let policy = DaemonChildPolicy {
            executable: Some(Arc::new(ValidatedExecutable { file: executable })),
            identity: Some(identity),
            credential_probe: Some(CredentialProbe {
                directory: CString::new(root.as_os_str().as_bytes()).unwrap(),
                credential: CString::new(credential_path.as_os_str().as_bytes()).unwrap(),
            }),
            mode: EmbeddingSecurityMode::AeadCached,
            test_environment: environment,
        };
        let camera = policy.open_camera(camera_path.to_str().unwrap()).unwrap();
        let mut child = policy
            .spawn_ffmpeg(
                camera,
                &[
                    "--exact".into(),
                    "child_spawn::tests::disposable_root_real_drop_groups_camera_reopen_and_credential_denial"
                        .into(),
                    "--include-ignored".into(),
                    "--nocapture".into(),
                ],
            )
            .unwrap();
        assert!(child.wait().unwrap().success());
        std::fs::remove_dir_all(root).unwrap();
    }
}
