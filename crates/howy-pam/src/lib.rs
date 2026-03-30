//! pam_howy — PAM module for howy face authentication.
//!
//! This is a thin `cdylib` that PAM loads as `/lib/security/pam_howy.so`.
//! It does NO inference, NO camera access, and NO heavy lifting.
//!
//! All it does:
//! 1. Get the username from PAM
//! 2. Check built-in PAM-side heuristics (currently SSH/lid only; not yet
//!    driven by `howy.config`)
//! 3. Connect to the howyd daemon via Unix socket
//! 4. Send an authenticate request
//! 5. Return PAM_SUCCESS or PAM_AUTH_ERR
//!
//! This keeps the PAM module fast (~10ms) and secure (minimal attack surface).
//! The first PAM deployment also does not enable credential caching yet because
//! a session-scoped PAM session identifier is not wired through this path.

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use howy_common::ipc;
use howy_common::paths;
use howy_common::protocol::{Request, RespResult, Response};

// PAM constants
const PAM_SUCCESS: libc::c_int = 0;
const PAM_AUTH_ERR: libc::c_int = 7;
const PAM_AUTHINFO_UNAVAIL: libc::c_int = 9;
const PAM_IGNORE: libc::c_int = 25;
const PAM_SYSTEM_ERR: libc::c_int = 4;
const PAM_USER_UNKNOWN: libc::c_int = 10;

const PAM_TEXT_INFO: libc::c_int = 4;
const PAM_ERROR_MSG: libc::c_int = 3;

// PAM types (raw FFI)
type PamHandle = libc::c_void;

#[repr(C)]
struct PamMessage {
    msg_style: libc::c_int,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: libc::c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *const *const PamMessage,
            *mut *mut PamResponse,
            *mut libc::c_void,
        ) -> libc::c_int,
    >,
    appdata_ptr: *mut libc::c_void,
}

unsafe extern "C" {
    fn pam_get_user(
        pamh: *mut PamHandle,
        user: *mut *const libc::c_char,
        prompt: *const libc::c_char,
    ) -> libc::c_int;

    fn pam_get_item(
        pamh: *mut PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
}

const PAM_CONV: libc::c_int = 5;

/// Send a PAM conversation message to the user.
unsafe fn pam_message(pamh: *mut PamHandle, style: libc::c_int, message: &str) {
    unsafe {
        let mut conv_ptr: *const libc::c_void = std::ptr::null();
        if pam_get_item(pamh, PAM_CONV, &mut conv_ptr) != PAM_SUCCESS || conv_ptr.is_null() {
            return;
        }

        let conv = &*(conv_ptr as *const PamConv);
        if conv.conv.is_none() {
            return;
        }

        if let Ok(c_msg) = CString::new(message) {
            let msg = PamMessage {
                msg_style: style,
                msg: c_msg.as_ptr(),
            };
            let msg_ptr: *const PamMessage = &msg;
            let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

            let _ = (conv.conv.unwrap())(1, &msg_ptr, &mut resp_ptr, conv.appdata_ptr);

            // Free response if allocated
            if !resp_ptr.is_null() {
                if !(*resp_ptr).resp.is_null() {
                    libc::free((*resp_ptr).resp as *mut libc::c_void);
                }
                libc::free(resp_ptr as *mut libc::c_void);
            }
        }
    }
}

/// Send an informational message to the user via PAM conversation.
unsafe fn pam_info(pamh: *mut PamHandle, message: &str) {
    unsafe { pam_message(pamh, PAM_TEXT_INFO, message) }
}

/// Send an error-style message to the user via PAM conversation.
unsafe fn pam_error(pamh: *mut PamHandle, message: &str) {
    unsafe { pam_message(pamh, PAM_ERROR_MSG, message) }
}

/// Core authentication logic.
unsafe fn authenticate_user(pamh: *mut PamHandle) -> libc::c_int {
    unsafe {
        if pamh.is_null() {
            return PAM_SYSTEM_ERR;
        }

        // Get username
        let mut username_ptr: *const libc::c_char = std::ptr::null();
        let res = pam_get_user(pamh, &mut username_ptr, std::ptr::null());
        if res != PAM_SUCCESS {
            return res;
        }
        if username_ptr.is_null() {
            return PAM_USER_UNKNOWN;
        }

        let username = match CStr::from_ptr(username_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return PAM_USER_UNKNOWN,
        };

        if !is_valid_username(&username) {
            return PAM_USER_UNKNOWN;
        }

        // Skip root
        if username == "root" {
            return PAM_AUTHINFO_UNAVAIL;
        }

        // Check pre-conditions
        if check_ssh_session() {
            return PAM_AUTHINFO_UNAVAIL;
        }

        if check_lid_closed() {
            return PAM_AUTHINFO_UNAVAIL;
        }

        // Check if user has face models (.bin or legacy .json)
        let model_path = match howy_common::paths::user_model_path(&username) {
            Some(p) => p,
            None => return PAM_USER_UNKNOWN, // invalid username
        };
        if !model_path.exists() {
            // Also check legacy JSON path
            let has_legacy = howy_common::paths::user_model_path_legacy(&username)
                .map(|p| p.exists())
                .unwrap_or(false);
            if !has_legacy {
                return PAM_AUTHINFO_UNAVAIL;
            }
        }

        // Connect to daemon
        let mut stream = match UnixStream::connect(paths::SOCKET_PATH) {
            Ok(s) => s,
            Err(e) => {
                // Daemon not running — don't block login, just skip
                syslog(&format!("howy: daemon not available: {e}"));
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        // Set timeouts
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        // Send authenticate request
        let request = Request::authenticate(&username, 0);

        if let Err(e) = ipc::send_message(&mut stream, &request) {
            syslog(&format!("howy: failed to send request: {e}"));
            return PAM_AUTHINFO_UNAVAIL;
        }

        // Wait for response
        // Increase read timeout since face recognition can take a few seconds
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));

        let response: Response = match ipc::recv_message(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                syslog(&format!("howy: failed to read response: {e}"));
                return PAM_AUTHINFO_UNAVAIL;
            }
        };

        match response.result {
            Some(RespResult::Success(s)) => {
                pam_info(
                    pamh,
                    &format!(
                        "Identified face as {} ({}, score: {:.2}, {:.0}ms)",
                        username, s.model_label, s.score, s.elapsed_ms
                    ),
                );
                syslog(&format!(
                    "howy: authenticated {} (model: {}, score: {:.3}, time: {:.0}ms)",
                    username, s.model_label, s.score, s.elapsed_ms
                ));
                PAM_SUCCESS
            }
            Some(RespResult::CredentialValid(_)) => {
                pam_info(
                    pamh,
                    &format!("howy: cached credential valid for {username}"),
                );
                syslog(&format!("howy: cached credential valid for {username}"));
                PAM_SUCCESS
            }
            Some(RespResult::AuthFailed(f)) => {
                pam_error(
                    pamh,
                    "Facial authentication failed. Falling back to password.",
                );
                syslog(&format!(
                    "howy: auth failed for {username}: {} (best: {:.3}, frames: {})",
                    f.reason, f.best_score, f.frames_processed
                ));
                PAM_AUTH_ERR
            }
            Some(RespResult::Error(e)) => {
                pam_error(
                    pamh,
                    "Face authentication unavailable. Falling back to password.",
                );
                syslog(&format!("howy: daemon error: {}", e.message));
                PAM_AUTHINFO_UNAVAIL
            }
            _ => {
                pam_error(
                    pamh,
                    "Face authentication unavailable. Falling back to password.",
                );
                syslog("howy: unexpected response from daemon");
                PAM_AUTHINFO_UNAVAIL
            }
        }
    }
}

fn is_valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Check if we're in an SSH session.
///
/// This intentionally uses PAM-visible environment variables as a heuristic.
/// They are not authoritative and can be spoofed in some contexts, but they are
/// still a practical signal for avoiding camera-based auth in common SSH flows.
/// Current `pam_howy` applies this unconditionally; it does not yet read
/// `core.abort_if_ssh` from `howy.config`.
fn check_ssh_session() -> bool {
    std::env::var("SSH_CONNECTION").is_ok()
        || std::env::var("SSH_CLIENT").is_ok()
        || std::env::var("SSH_TTY").is_ok()
}

/// Check if the laptop lid is closed.
/// Current `pam_howy` applies this unconditionally; it does not yet read
/// `core.abort_if_lid_closed` from `howy.config`.
fn check_lid_closed() -> bool {
    let pattern = "/proc/acpi/button/lid/*/state";
    if let Ok(paths) = glob_paths(pattern) {
        for path in paths {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if contents.contains("closed") {
                    return true;
                }
            }
        }
    }
    false
}

/// Simple glob for lid state files.
fn glob_paths(_pattern: &str) -> io::Result<Vec<String>> {
    // We can't use the glob crate in a cdylib easily, so do it manually
    let dir = "/proc/acpi/button/lid";
    let mut result = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path().join("state");
            if path.exists() {
                result.push(path.to_string_lossy().to_string());
            }
        }
    }

    Ok(result)
}

/// Write to syslog.
fn syslog(message: &str) {
    if let Ok(c_msg) = CString::new(message) {
        unsafe {
            libc::openlog(
                b"pam_howy\0".as_ptr() as *const libc::c_char,
                0,
                libc::LOG_AUTHPRIV,
            );
            libc::syslog(
                libc::LOG_INFO,
                b"%s\0".as_ptr() as *const libc::c_char,
                c_msg.as_ptr(),
            );
            libc::closelog();
        }
    }
}

fn catch_pam_panic<F>(f: F) -> libc::c_int
where
    F: FnOnce() -> libc::c_int,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => {
            syslog("howy: PAM module panicked, returning AUTHINFO_UNAVAIL");
            PAM_AUTHINFO_UNAVAIL
        }
    }
}

// ---------------------------------------------------------------------------
// PAM entry points — these are the C symbols that PAM looks for
// ---------------------------------------------------------------------------

/// Called by PAM when authentication is requested (e.g., sudo, login, gdm).
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| unsafe { authenticate_user(pamh) })
}

/// Called by PAM to set credentials after authentication.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| PAM_SUCCESS)
}

/// Called by PAM for account management.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| PAM_IGNORE)
}

/// Called when a session is opened (e.g., su).
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| PAM_IGNORE)
}

/// Called when a session is closed.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| PAM_IGNORE)
}

/// Called by PAM for password changes (not applicable).
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut PamHandle,
    _flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| PAM_IGNORE)
}
