//! pam_howy — PAM module for howy face authentication.
//!
//! This is a thin `cdylib` that PAM loads as `/lib/security/pam_howy.so`.
//! It does NO inference, NO camera access, and NO heavy lifting.
//!
//! All it does:
//! 1. Get the username from PAM
//! 2. Read exact PAM service and locality context
//! 3. Connect to the howyd daemon via Unix socket
//! 4. Use versioned adaptive prompt authentication
//! 5. Return PAM_SUCCESS or a password-fallback-compatible status
//!
//! This keeps the PAM module fast (~10ms) and secure (minimal attack surface).
//! The first PAM deployment also does not enable credential caching yet because
//! a session-scoped PAM session identifier is not wired through this path.

use std::ffi::{CStr, CString};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use howy_common::ipc::{self, PromptAuthClientConnection, PromptBeginOutcome, PromptNonce};
use howy_common::paths;
use howy_common::protocol::{PROMPT_NONCE_BYTES, PromptOriginV1, Request, RespResult, Response};
use howy_common::storage::{OsRandomSource, RandomSource};

// PAM constants
const PAM_SUCCESS: libc::c_int = 0;
const PAM_AUTH_ERR: libc::c_int = 7;
const PAM_AUTHINFO_UNAVAIL: libc::c_int = 9;
const PAM_IGNORE: libc::c_int = 25;
const PAM_SYSTEM_ERR: libc::c_int = 4;
const PAM_USER_UNKNOWN: libc::c_int = 10;

const PAM_PROMPT_ECHO_ON: libc::c_int = 2;
const PAM_SILENT: libc::c_int = 0x8000;
const PAM_MAX_RESP_SIZE: usize = 512;
const PAM_SERVICE: libc::c_int = 1;
const PAM_RHOST: libc::c_int = 4;
const PAM_CONV: libc::c_int = 5;
const PAM_SERVICE_MAX_BYTES: usize = 64;
const PAM_RHOST_MAX_BYTES: usize = 255;
const PAM_AUTH_CEILING: Duration = Duration::from_secs(10);

const CONFIRMATION_PROMPT: &CStr =
    c"Face authentication requested. Press Enter or submit OK to allow one camera scan; cancel to use another method.";

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
        pamh: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
}

type PamGetItem =
    unsafe extern "C" fn(*const PamHandle, libc::c_int, *mut *const libc::c_void) -> libc::c_int;
type PamGetUser = unsafe extern "C" fn(
    *mut PamHandle,
    *mut *const libc::c_char,
    *const libc::c_char,
) -> libc::c_int;
type PamFree = unsafe fn(*mut libc::c_void);

#[derive(Clone, Copy)]
struct PamApi {
    get_user: PamGetUser,
    get_item: PamGetItem,
    free: PamFree,
}

struct PamResponses {
    responses: *mut PamResponse,
    count: usize,
    free: PamFree,
}

impl Drop for PamResponses {
    fn drop(&mut self) {
        unsafe {
            for index in 0..self.count {
                let response = self.responses.add(index);
                if !(*response).resp.is_null() {
                    (self.free)((*response).resp.cast());
                }
            }
            (self.free)(self.responses.cast());
        }
    }
}

unsafe fn libc_free(pointer: *mut libc::c_void) {
    unsafe { libc::free(pointer) }
}

unsafe fn confirmation_response_is_allowed(response: *const libc::c_char) -> bool {
    // Linux-PAM defines `resp` as a NUL-terminated C string. The first NUL is
    // therefore the response boundary; scan no farther than the documented
    // Linux-PAM response cap plus one byte needed to detect an overlong value.
    let length = unsafe { libc::strnlen(response, PAM_MAX_RESP_SIZE + 1) };
    if length > PAM_MAX_RESP_SIZE {
        return false;
    }

    let bytes = unsafe { std::slice::from_raw_parts(response.cast::<u8>(), length) };
    let Ok(response) = std::str::from_utf8(bytes) else {
        return false;
    };

    response.is_empty() || response == "OK"
}

unsafe fn request_confirmation_from_conv(
    conv_ptr: *const PamConv,
    flags: libc::c_int,
    free: PamFree,
) -> libc::c_int {
    if flags & PAM_SILENT != 0 || conv_ptr.is_null() {
        return PAM_AUTHINFO_UNAVAIL;
    }

    let conv = unsafe { &*conv_ptr };
    let Some(callback) = conv.conv else {
        return PAM_AUTHINFO_UNAVAIL;
    };

    // The prompt bytes have static storage, while both the message and its
    // pointer remain live on this stack for the complete callback invocation.
    let message = PamMessage {
        msg_style: PAM_PROMPT_ECHO_ON,
        msg: CONFIRMATION_PROMPT.as_ptr(),
    };
    let message_ptr: *const PamMessage = &message;
    let mut responses: *mut PamResponse = std::ptr::null_mut();
    let callback_status = unsafe { callback(1, &message_ptr, &mut responses, conv.appdata_ptr) };

    // On failure Linux-PAM requires the conversation function to clean any
    // partial allocations and not set `responses`. Do not inspect or free an
    // output that the failed callback does not transfer to this caller.
    if callback_status != PAM_SUCCESS {
        return PAM_AUTHINFO_UNAVAIL;
    }

    if responses.is_null() {
        return PAM_AUTHINFO_UNAVAIL;
    }
    let responses = PamResponses {
        responses,
        count: 1,
        free,
    };

    let response = unsafe { &*responses.responses };
    if response.resp_retcode != 0 || response.resp.is_null() {
        return PAM_AUTHINFO_UNAVAIL;
    }

    if unsafe { confirmation_response_is_allowed(response.resp) } {
        PAM_SUCCESS
    } else {
        PAM_AUTHINFO_UNAVAIL
    }
}

unsafe fn request_confirmation_with_get_item(
    pamh: *mut PamHandle,
    flags: libc::c_int,
    get_item: PamGetItem,
    free: PamFree,
) -> libc::c_int {
    if flags & PAM_SILENT != 0 || pamh.is_null() {
        return PAM_AUTHINFO_UNAVAIL;
    }

    let mut conv_ptr: *const libc::c_void = std::ptr::null();
    if unsafe { get_item(pamh, PAM_CONV, &mut conv_ptr) } != PAM_SUCCESS {
        return PAM_AUTHINFO_UNAVAIL;
    }

    unsafe { request_confirmation_from_conv(conv_ptr.cast(), flags, free) }
}

unsafe fn read_pam_string_item(
    pamh: *mut PamHandle,
    item_type: libc::c_int,
    max_bytes: usize,
    get_item: PamGetItem,
) -> Result<Option<String>, ()> {
    let mut item: *const libc::c_void = std::ptr::null();
    if unsafe { get_item(pamh, item_type, &mut item) } != PAM_SUCCESS {
        return Err(());
    }
    if item.is_null() {
        return Ok(None);
    }
    let value = item.cast::<libc::c_char>();
    let length = unsafe { libc::strnlen(value, max_bytes + 1) };
    if length > max_bytes {
        return Err(());
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), length) };
    std::str::from_utf8(bytes)
        .map(|value| Some(value.to_owned()))
        .map_err(|_| ())
}

fn is_valid_pam_service(service: &str) -> bool {
    (1..=PAM_SERVICE_MAX_BYTES).contains(&service.len())
        && service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_valid_pam_rhost(rhost: &str) -> bool {
    !rhost.is_empty()
        && rhost.len() <= PAM_RHOST_MAX_BYTES
        && rhost.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']' | b'%')
        })
}

unsafe fn read_pam_policy(
    pamh: *mut PamHandle,
    get_item: PamGetItem,
) -> Result<(String, PromptOriginV1), ()> {
    let service =
        unsafe { read_pam_string_item(pamh, PAM_SERVICE, PAM_SERVICE_MAX_BYTES, get_item) }?
            .ok_or(())?;
    if !is_valid_pam_service(&service) {
        return Err(());
    }

    let rhost = unsafe { read_pam_string_item(pamh, PAM_RHOST, PAM_RHOST_MAX_BYTES, get_item) }?;
    let origin = match rhost.as_deref() {
        None | Some("") => PromptOriginV1::Local,
        Some(value) if is_valid_pam_rhost(value) => PromptOriginV1::Remote,
        Some(_) => return Err(()),
    };
    Ok((service, origin))
}

fn map_auth_response(response: Response) -> libc::c_int {
    match response.result {
        Some(RespResult::Success(_)) => PAM_SUCCESS,
        Some(RespResult::AuthFailed(_)) => PAM_AUTH_ERR,
        Some(RespResult::Error(_)) | None => PAM_AUTHINFO_UNAVAIL,
        _ => PAM_AUTHINFO_UNAVAIL,
    }
}

fn configure_stream(stream: &UnixStream) -> Result<(), ()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| ())
}

/// Core authentication logic. Dropping either connection on every early return
/// is also the active/pending HUP cancellation mechanism understood by howyd.
unsafe fn authenticate_user_with(
    pamh: *mut PamHandle,
    flags: libc::c_int,
    api: PamApi,
    mut connect: impl FnMut() -> std::io::Result<UnixStream>,
    auth_ceiling: Duration,
    mut fill_nonce: impl FnMut(&mut [u8; PROMPT_NONCE_BYTES]) -> Result<(), ()>,
) -> libc::c_int {
    if flags & PAM_SILENT != 0 {
        return PAM_AUTHINFO_UNAVAIL;
    }
    if pamh.is_null() {
        return PAM_SYSTEM_ERR;
    }

    let mut username_ptr: *const libc::c_char = std::ptr::null();
    let status = unsafe { (api.get_user)(pamh, &mut username_ptr, std::ptr::null()) };
    if status != PAM_SUCCESS {
        return status;
    }
    if username_ptr.is_null() {
        return PAM_USER_UNKNOWN;
    }
    let username = match unsafe { CStr::from_ptr(username_ptr) }.to_str() {
        Ok(username) if is_valid_username(username) => username.to_owned(),
        _ => return PAM_USER_UNKNOWN,
    };
    if username == "root" {
        return PAM_AUTHINFO_UNAVAIL;
    }

    let (service, origin) = match unsafe { read_pam_policy(pamh, api.get_item) } {
        Ok(policy) => policy,
        Err(()) => return PAM_AUTHINFO_UNAVAIL,
    };
    let mut nonce = PromptNonce::zeroed();
    if fill_nonce(nonce.as_mut_array()).is_err() {
        return PAM_AUTHINFO_UNAVAIL;
    }

    let stream = match connect() {
        Ok(stream) if configure_stream(&stream).is_ok() => stream,
        Ok(_) | Err(_) => return PAM_AUTHINFO_UNAVAIL,
    };
    let mut prompt = PromptAuthClientConnection::new(stream);
    match prompt.begin_adaptive_ref(&username, nonce.as_array(), &service, origin) {
        Ok(PromptBeginOutcome::PromptRequired(_)) => {
            #[cfg(test)]
            panic_after_prompt_if_requested();
            let confirmed =
                unsafe { request_confirmation_with_get_item(pamh, flags, api.get_item, api.free) };
            if confirmed != PAM_SUCCESS {
                let _ = prompt.cancel();
                return PAM_AUTHINFO_UNAVAIL;
            }
            match prompt.commit() {
                Ok(response) => map_auth_response(response),
                Err(_) => PAM_AUTHINFO_UNAVAIL,
            }
        }
        Ok(PromptBeginOutcome::PromptModeOff) => {
            drop(prompt);
            let mut stream = match connect() {
                Ok(stream) if configure_stream(&stream).is_ok() => stream,
                Ok(_) | Err(_) => return PAM_AUTHINFO_UNAVAIL,
            };
            let request = Request::authenticate_v1(&username, 0);
            let Some(deadline) = Instant::now().checked_add(auth_ceiling) else {
                return PAM_AUTHINFO_UNAVAIL;
            };
            match ipc::request_message_until(&mut stream, &request, deadline) {
                Ok(response) if Instant::now() < deadline => map_auth_response(response),
                Err(_) => PAM_AUTHINFO_UNAVAIL,
                Ok(_) => PAM_AUTHINFO_UNAVAIL,
            }
        }
        Err(_) => PAM_AUTHINFO_UNAVAIL,
    }
}

#[cfg(test)]
std::thread_local! {
    static TEST_AUTH_CONNECTIONS: std::cell::RefCell<std::collections::VecDeque<UnixStream>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    static PANIC_AFTER_PROMPT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn connect_daemon() -> std::io::Result<UnixStream> {
    #[cfg(test)]
    if let Some(stream) = TEST_AUTH_CONNECTIONS.with(|streams| streams.borrow_mut().pop_front()) {
        return Ok(stream);
    }
    UnixStream::connect(paths::SOCKET_PATH)
}

#[cfg(test)]
fn request_post_prompt_panic(stream: UnixStream) {
    TEST_AUTH_CONNECTIONS.with(|streams| streams.borrow_mut().push_back(stream));
    PANIC_AFTER_PROMPT.with(|requested| requested.set(true));
}

#[cfg(test)]
fn panic_after_prompt_if_requested() {
    PANIC_AFTER_PROMPT.with(|requested| {
        if requested.replace(false) {
            panic!("mock panic after PromptRequired");
        }
    });
}

unsafe fn authenticate_user(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int {
    unsafe {
        authenticate_user_with(
            pamh,
            flags,
            PamApi {
                get_user: pam_get_user,
                get_item: pam_get_item,
                free: libc_free,
            },
            connect_daemon,
            PAM_AUTH_CEILING,
            |nonce| OsRandomSource.fill_bytes(nonce).map_err(|_| ()),
        )
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

#[cfg(test)]
std::thread_local! {
    static PANIC_AT_NEXT_AUTHENTICATE_ENTRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn request_authenticate_entry_panic() {
    PANIC_AT_NEXT_AUTHENTICATE_ENTRY.with(|requested| requested.set(true));
}

#[cfg(test)]
fn panic_at_authenticate_entry_if_requested() {
    PANIC_AT_NEXT_AUTHENTICATE_ENTRY.with(|requested| {
        if requested.replace(false) {
            panic!("mock panic at exported PAM authenticate entry");
        }
    });
}

// ---------------------------------------------------------------------------
// PAM entry points — these are the C symbols that PAM looks for
// ---------------------------------------------------------------------------

/// Called by PAM when authentication is requested (e.g., sudo, login, gdm).
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: libc::c_int,
    _argc: libc::c_int,
    _argv: *const *const libc::c_char,
) -> libc::c_int {
    catch_pam_panic(|| {
        #[cfg(test)]
        panic_at_authenticate_entry_if_requested();
        unsafe { authenticate_user(pamh, flags) }
    })
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

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, VecDeque};
    use std::ffi::{CStr, CString};
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::ptr;
    use std::time::{Duration, Instant};

    use super::{
        CONFIRMATION_PROMPT, PAM_AUTH_CEILING, PAM_AUTH_ERR, PAM_AUTHINFO_UNAVAIL, PAM_CONV,
        PAM_MAX_RESP_SIZE, PAM_PROMPT_ECHO_ON, PAM_RHOST, PAM_SERVICE, PAM_SILENT, PAM_SUCCESS,
        PAM_SYSTEM_ERR, PamApi, PamConv, PamHandle, PamMessage, PamResponse,
        authenticate_user_with, pam_sm_authenticate, read_pam_policy,
        request_authenticate_entry_panic, request_confirmation_from_conv,
        request_confirmation_with_get_item, request_post_prompt_panic,
    };
    use howy_common::ipc::{recv_message, send_message};
    use howy_common::protocol::{
        Cmd, PROMPT_NONCE_BYTES, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, PromptOriginV1, Request,
        Response,
    };
    const PAM_CONV_ERR: libc::c_int = 19;
    const PAM_CONV_AGAIN: libc::c_int = 30;

    // The production cdylib resolves these symbols from Linux-PAM at load time.
    // Rooting the actual exported authenticate entry point in this unit-test
    // binary requires inert test definitions even though the injected panic
    // occurs before either function can be called.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn pam_get_user(
        pamh: *mut PamHandle,
        user: *mut *const libc::c_char,
        prompt: *const libc::c_char,
    ) -> libc::c_int {
        if pamh.is_null() {
            PAM_SYSTEM_ERR
        } else {
            unsafe { mock_get_user(pamh, user, prompt) }
        }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn pam_get_item(
        pamh: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int {
        if pamh.is_null() {
            PAM_SYSTEM_ERR
        } else {
            unsafe { mock_get_context_item(pamh, item_type, item) }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AllocationKind {
        ResponseArray,
        ResponseString,
    }

    #[derive(Default)]
    struct AllocationTracker {
        outstanding: HashMap<usize, AllocationKind>,
        freed_arrays: usize,
        freed_strings: usize,
    }

    thread_local! {
        static ALLOCATIONS: RefCell<AllocationTracker> = RefCell::new(AllocationTracker::default());
        static GET_ITEM_CALLS: Cell<usize> = const { Cell::new(0) };
        static NULL_APPDATA_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    fn reset_allocations() {
        ALLOCATIONS.with(|allocations| *allocations.borrow_mut() = AllocationTracker::default());
    }

    fn track_allocation(pointer: *mut libc::c_void, kind: AllocationKind) {
        assert!(!pointer.is_null());
        ALLOCATIONS.with(|allocations| {
            let replaced = allocations
                .borrow_mut()
                .outstanding
                .insert(pointer as usize, kind);
            assert!(replaced.is_none());
        });
    }

    unsafe fn tracking_free(pointer: *mut libc::c_void) {
        ALLOCATIONS.with(|allocations| {
            let mut allocations = allocations.borrow_mut();
            match allocations.outstanding.remove(&(pointer as usize)) {
                Some(AllocationKind::ResponseArray) => allocations.freed_arrays += 1,
                Some(AllocationKind::ResponseString) => allocations.freed_strings += 1,
                None => panic!("attempted to free an untracked PAM allocation"),
            }
        });
        unsafe { libc::free(pointer) };
    }

    fn assert_cleanup(arrays: usize, strings: usize) {
        ALLOCATIONS.with(|allocations| {
            let allocations = allocations.borrow();
            assert!(allocations.outstanding.is_empty());
            assert_eq!(allocations.freed_arrays, arrays);
            assert_eq!(allocations.freed_strings, strings);
        });
    }

    enum MockReply {
        NullArray,
        NullString,
        Bytes(Vec<u8>),
    }

    struct MockConversation {
        callback_status: libc::c_int,
        reply: MockReply,
        response_retcode: libc::c_int,
        calls: usize,
        expected_prompt: bool,
    }

    impl MockConversation {
        fn bytes(bytes: &[u8]) -> Self {
            Self {
                callback_status: PAM_SUCCESS,
                reply: MockReply::Bytes(bytes.to_vec()),
                response_retcode: 0,
                calls: 0,
                expected_prompt: false,
            }
        }
    }

    unsafe fn allocate_mock_response(
        bytes: Option<&[u8]>,
        response_retcode: libc::c_int,
    ) -> *mut PamResponse {
        let array = unsafe { libc::calloc(1, size_of::<PamResponse>()) }.cast::<PamResponse>();
        assert!(!array.is_null());
        track_allocation(array.cast(), AllocationKind::ResponseArray);
        unsafe { (*array).resp_retcode = response_retcode };

        if let Some(bytes) = bytes {
            let string = unsafe { libc::malloc(bytes.len() + 1) }.cast::<u8>();
            assert!(!string.is_null());
            track_allocation(string.cast(), AllocationKind::ResponseString);
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), string, bytes.len());
                *string.add(bytes.len()) = 0;
                (*array).resp = string.cast();
            }
        }

        array
    }

    unsafe fn free_mock_response(array: *mut PamResponse) {
        if !unsafe { (*array).resp }.is_null() {
            unsafe { tracking_free((*array).resp.cast()) };
        }
        unsafe { tracking_free(array.cast()) };
    }

    unsafe extern "C" fn mock_conversation(
        num_msg: libc::c_int,
        messages: *const *const PamMessage,
        responses: *mut *mut PamResponse,
        appdata_ptr: *mut libc::c_void,
    ) -> libc::c_int {
        let state = unsafe { &mut *appdata_ptr.cast::<MockConversation>() };
        state.calls += 1;

        assert_eq!(num_msg, 1);
        assert!(!messages.is_null());
        let message = unsafe { &**messages };
        assert_eq!(message.msg_style, PAM_PROMPT_ECHO_ON);
        assert!(!message.msg.is_null());
        state.expected_prompt = unsafe { CStr::from_ptr(message.msg) }.to_bytes_with_nul()
            == CONFIRMATION_PROMPT.to_bytes_with_nul();

        unsafe { *responses = ptr::null_mut() };
        let allocated = match &state.reply {
            MockReply::NullArray => ptr::null_mut(),
            MockReply::NullString => unsafe {
                allocate_mock_response(None, state.response_retcode)
            },
            MockReply::Bytes(bytes) => unsafe {
                allocate_mock_response(Some(bytes), state.response_retcode)
            },
        };

        if state.callback_status != PAM_SUCCESS {
            if !allocated.is_null() {
                unsafe { free_mock_response(allocated) };
            }
            return state.callback_status;
        }

        if !allocated.is_null() {
            unsafe { *responses = allocated };
        }

        state.callback_status
    }

    unsafe extern "C" fn null_appdata_conversation(
        num_msg: libc::c_int,
        _messages: *const *const PamMessage,
        responses: *mut *mut PamResponse,
        appdata_ptr: *mut libc::c_void,
    ) -> libc::c_int {
        assert_eq!(num_msg, 1);
        assert!(appdata_ptr.is_null());
        NULL_APPDATA_CALLS.with(|calls| calls.set(calls.get() + 1));
        unsafe { *responses = allocate_mock_response(Some(b"OK"), 0) };
        PAM_SUCCESS
    }

    fn run_conversation(state: &mut MockConversation, flags: libc::c_int) -> libc::c_int {
        reset_allocations();
        let conv = PamConv {
            conv: Some(mock_conversation),
            appdata_ptr: ptr::from_mut(state).cast(),
        };
        unsafe { request_confirmation_from_conv(&conv, flags, tracking_free) }
    }

    unsafe extern "C" fn failing_get_item(
        _pamh: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int {
        assert_eq!(item_type, PAM_CONV);
        unsafe { *item = ptr::null() };
        PAM_CONV_ERR
    }

    unsafe extern "C" fn null_get_item(
        _pamh: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int {
        assert_eq!(item_type, PAM_CONV);
        unsafe { *item = ptr::null() };
        PAM_SUCCESS
    }

    unsafe extern "C" fn counting_get_item(
        _pamh: *const PamHandle,
        _item_type: libc::c_int,
        _item: *mut *const libc::c_void,
    ) -> libc::c_int {
        GET_ITEM_CALLS.with(|calls| calls.set(calls.get() + 1));
        PAM_CONV_ERR
    }

    struct MockPamItems {
        username: *const libc::c_char,
        service: *const libc::c_void,
        rhost: *const libc::c_void,
        conversation: *const PamConv,
        user_calls: Cell<usize>,
        item_calls: Cell<usize>,
    }

    unsafe extern "C" fn mock_get_user(
        pamh: *mut PamHandle,
        user: *mut *const libc::c_char,
        _prompt: *const libc::c_char,
    ) -> libc::c_int {
        let items = unsafe { &*pamh.cast::<MockPamItems>() };
        items.user_calls.set(items.user_calls.get() + 1);
        unsafe { *user = items.username };
        PAM_SUCCESS
    }

    unsafe extern "C" fn mock_get_context_item(
        pamh: *const PamHandle,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int {
        let items = unsafe { &*pamh.cast::<MockPamItems>() };
        items.item_calls.set(items.item_calls.get() + 1);
        unsafe {
            *item = match item_type {
                PAM_SERVICE => items.service,
                PAM_RHOST => items.rhost,
                PAM_CONV => items.conversation.cast(),
                _ => return PAM_SYSTEM_ERR,
            };
        }
        PAM_SUCCESS
    }

    fn pam_api() -> PamApi {
        PamApi {
            get_user: mock_get_user,
            get_item: mock_get_context_item,
            free: tracking_free,
        }
    }

    fn mock_items(
        username: &CString,
        service: Option<&CString>,
        rhost: Option<&CString>,
        conversation: Option<&PamConv>,
    ) -> MockPamItems {
        MockPamItems {
            username: username.as_ptr(),
            service: service.map_or(ptr::null(), |value| value.as_ptr().cast()),
            rhost: rhost.map_or(ptr::null(), |value| value.as_ptr().cast()),
            conversation: conversation.map_or(ptr::null(), ptr::from_ref),
            user_calls: Cell::new(0),
            item_calls: Cell::new(0),
        }
    }

    fn run_adaptive_auth(
        items: &mut MockPamItems,
        streams: Vec<UnixStream>,
        flags: libc::c_int,
    ) -> libc::c_int {
        run_adaptive_auth_with_ceiling(items, streams, flags, PAM_AUTH_CEILING)
    }

    fn run_adaptive_auth_with_ceiling(
        items: &mut MockPamItems,
        streams: Vec<UnixStream>,
        flags: libc::c_int,
        auth_ceiling: Duration,
    ) -> libc::c_int {
        let mut streams = VecDeque::from(streams);
        unsafe {
            authenticate_user_with(
                ptr::from_mut(items).cast(),
                flags,
                pam_api(),
                || {
                    streams.pop_front().ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::NotConnected, "no mock stream")
                    })
                },
                auth_ceiling,
                |nonce| {
                    nonce.fill(0x11);
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn empty_enter_and_exact_ok_are_accepted_and_freed() {
        for response in [b"".as_slice(), b"OK".as_slice()] {
            let mut state = MockConversation::bytes(response);
            assert_eq!(run_conversation(&mut state, 0), PAM_SUCCESS);
            assert_eq!(state.calls, 1);
            assert!(state.expected_prompt);
            assert_cleanup(1, 1);
        }
    }

    #[test]
    fn confirmation_policy_rejects_case_and_whitespace_variants() {
        for response in [
            b"ok".as_slice(),
            b"Ok".as_slice(),
            b"oK".as_slice(),
            b" OK".as_slice(),
            b"OK ".as_slice(),
            b"OK\n".as_slice(),
            b"yes".as_slice(),
        ] {
            let mut state = MockConversation::bytes(response);
            assert_eq!(run_conversation(&mut state, 0), PAM_AUTHINFO_UNAVAIL);
            assert_cleanup(1, 1);
        }
    }

    #[test]
    fn silent_flag_declines_without_getting_or_invoking_conversation() {
        let fake_pamh = ptr::dangling_mut::<PamHandle>();
        GET_ITEM_CALLS.with(|calls| calls.set(0));
        assert_eq!(
            unsafe {
                request_confirmation_with_get_item(
                    fake_pamh,
                    PAM_SILENT,
                    counting_get_item,
                    tracking_free,
                )
            },
            PAM_AUTHINFO_UNAVAIL
        );
        GET_ITEM_CALLS.with(|calls| assert_eq!(calls.get(), 0));

        let mut state = MockConversation::bytes(b"OK");
        assert_eq!(
            run_conversation(&mut state, PAM_SILENT),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(state.calls, 0);
        assert_cleanup(0, 0);
    }

    #[test]
    fn get_item_failure_and_null_conversation_use_fallback_status() {
        let fake_pamh = ptr::dangling_mut::<PamHandle>();
        for get_item in [failing_get_item, null_get_item] {
            assert_eq!(
                unsafe {
                    request_confirmation_with_get_item(fake_pamh, 0, get_item, tracking_free)
                },
                PAM_AUTHINFO_UNAVAIL
            );
        }
        assert_eq!(
            unsafe {
                request_confirmation_with_get_item(
                    ptr::null_mut(),
                    0,
                    failing_get_item,
                    tracking_free,
                )
            },
            PAM_AUTHINFO_UNAVAIL
        );
    }

    #[test]
    fn null_callback_uses_fallback_status() {
        let conv = PamConv {
            conv: None,
            appdata_ptr: ptr::null_mut(),
        };
        assert_eq!(
            unsafe { request_confirmation_from_conv(&conv, 0, tracking_free) },
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(
            unsafe { request_confirmation_from_conv(ptr::null(), 0, tracking_free) },
            PAM_AUTHINFO_UNAVAIL
        );
    }

    #[test]
    fn failed_callback_owns_partial_cleanup_and_leaves_output_null() {
        for (status, reply) in [
            (PAM_CONV_ERR, MockReply::Bytes(b"OK".to_vec())),
            (PAM_CONV_AGAIN, MockReply::NullString),
        ] {
            let mut state = MockConversation {
                callback_status: status,
                reply,
                response_retcode: 0,
                calls: 0,
                expected_prompt: false,
            };
            assert_eq!(run_conversation(&mut state, 0), PAM_AUTHINFO_UNAVAIL);
            let expected_strings = usize::from(matches!(state.reply, MockReply::Bytes(_)));
            assert_cleanup(1, expected_strings);
        }
    }

    #[test]
    fn null_appdata_is_forwarded_without_special_case() {
        reset_allocations();
        NULL_APPDATA_CALLS.with(|calls| calls.set(0));
        let conv = PamConv {
            conv: Some(null_appdata_conversation),
            appdata_ptr: ptr::null_mut(),
        };
        assert_eq!(
            unsafe { request_confirmation_from_conv(&conv, 0, tracking_free) },
            PAM_SUCCESS
        );
        NULL_APPDATA_CALLS.with(|calls| assert_eq!(calls.get(), 1));
        assert_cleanup(1, 1);
    }

    #[test]
    fn null_response_array_and_eof_response_use_fallback_status() {
        let mut null_array = MockConversation {
            callback_status: PAM_SUCCESS,
            reply: MockReply::NullArray,
            response_retcode: 0,
            calls: 0,
            expected_prompt: false,
        };
        assert_eq!(run_conversation(&mut null_array, 0), PAM_AUTHINFO_UNAVAIL);
        assert_cleanup(0, 0);

        let mut eof = MockConversation {
            callback_status: PAM_SUCCESS,
            reply: MockReply::NullString,
            response_retcode: 0,
            calls: 0,
            expected_prompt: false,
        };
        assert_eq!(run_conversation(&mut eof, 0), PAM_AUTHINFO_UNAVAIL);
        assert_cleanup(1, 0);
    }

    #[test]
    fn overlong_and_non_utf8_responses_are_rejected_and_freed() {
        for response in [vec![b'A'; PAM_MAX_RESP_SIZE + 1], vec![0xff, 0xfe]] {
            let mut state = MockConversation::bytes(&response);
            assert_eq!(run_conversation(&mut state, 0), PAM_AUTHINFO_UNAVAIL);
            assert_cleanup(1, 1);
        }
    }

    #[test]
    fn nonzero_response_retcode_is_rejected_and_freed() {
        let mut state = MockConversation::bytes(b"OK");
        state.response_retcode = 1;
        assert_eq!(run_conversation(&mut state, 0), PAM_AUTHINFO_UNAVAIL);
        assert_cleanup(1, 1);
    }

    #[test]
    fn exported_authenticate_entry_contains_panics() {
        request_authenticate_entry_panic();
        assert_eq!(
            pam_sm_authenticate(ptr::null_mut(), 0, 0, ptr::null()),
            PAM_AUTHINFO_UNAVAIL
        );
    }

    #[test]
    fn exported_post_prompt_panic_cancels_pending_and_falls_back() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let username = CString::new("alice").unwrap();
        let service = CString::new("sudo").unwrap();
        let mut items = mock_items(&username, Some(&service), None, None);
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let pending = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let server_pending = Arc::clone(&pending);
        let server_active = Arc::clone(&active);
        let daemon_thread = std::thread::spawn(move || {
            let request: Request = recv_message(&mut daemon).unwrap();
            let Some(Cmd::BeginAuthV1(begin)) = request.cmd else {
                panic!("exported PAM must begin with BeginAuthV1")
            };
            let nonce: [u8; PROMPT_NONCE_BYTES] = begin.client_nonce.try_into().unwrap();
            server_pending.store(1, Ordering::SeqCst);
            send_message(
                &mut daemon,
                &Response::prompt_required_v1([0x22; 32], nonce, 30_000, 10_000),
            )
            .unwrap();
            let cancel: Request = recv_message(&mut daemon).unwrap();
            assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
            server_pending.store(0, Ordering::SeqCst);
            send_message(&mut daemon, &Response::auth_cancelled_v1(nonce)).unwrap();
            let duplicate: std::io::Result<Request> = recv_message(&mut daemon);
            assert!(duplicate.is_err(), "unwind guard sends at most one cancel");
            assert_eq!(server_active.load(Ordering::SeqCst), 0);
        });

        request_post_prompt_panic(client);
        assert_eq!(
            pam_sm_authenticate(ptr::from_mut(&mut items).cast(), 0, 0, ptr::null()),
            PAM_AUTHINFO_UNAVAIL
        );
        daemon_thread.join().unwrap();
        assert_eq!(pending.load(Ordering::SeqCst), 0);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pam_native_enter_and_ok_commit_on_the_begin_connection() {
        for reply in [b"".as_slice(), b"OK".as_slice()] {
            reset_allocations();
            let username = CString::new("alice").unwrap();
            let service = CString::new("sudo").unwrap();
            let mut conversation_state = MockConversation::bytes(reply);
            let conversation = PamConv {
                conv: Some(mock_conversation),
                appdata_ptr: ptr::from_mut(&mut conversation_state).cast(),
            };
            let mut items = mock_items(&username, Some(&service), None, Some(&conversation));
            let (client, mut daemon) = UnixStream::pair().unwrap();
            let daemon_thread = std::thread::spawn(move || {
                let begin: Request = recv_message(&mut daemon).unwrap();
                let Some(Cmd::BeginAuthV1(begin)) = begin.cmd else {
                    panic!("supported PAM starts with BeginAuthV1")
                };
                assert_eq!(begin.username, "alice");
                assert_eq!(begin.client_nonce, [0x11; PROMPT_NONCE_BYTES]);
                let policy = begin.policy.unwrap();
                assert_eq!(policy.pam_service, "sudo");
                assert_eq!(policy.origin, PromptOriginV1::Local as i32);
                send_message(
                    &mut daemon,
                    &Response::prompt_required_v1(
                        [0x22; 32],
                        [0x11; PROMPT_NONCE_BYTES],
                        30_000,
                        10_000,
                    ),
                )
                .unwrap();
                let commit: Request = recv_message(&mut daemon).unwrap();
                assert!(matches!(commit.cmd, Some(Cmd::CommitAuthV1(_))));
                send_message(&mut daemon, &Response::success(0, "desk", 0.9, 1.0)).unwrap();
            });

            assert_eq!(run_adaptive_auth(&mut items, vec![client], 0), PAM_SUCCESS);
            daemon_thread.join().unwrap();
            assert_eq!(conversation_state.calls, 1);
            assert!(conversation_state.expected_prompt);
            assert_cleanup(1, 1);
        }
    }

    #[test]
    fn pam_silent_performs_no_pam_lookup_prompt_or_ipc() {
        let mut items = MockPamItems {
            username: ptr::null(),
            service: ptr::null(),
            rhost: ptr::null(),
            conversation: ptr::null(),
            user_calls: Cell::new(0),
            item_calls: Cell::new(0),
        };
        assert_eq!(
            run_adaptive_auth(&mut items, Vec::new(), PAM_SILENT),
            PAM_AUTHINFO_UNAVAIL
        );
        assert_eq!(items.user_calls.get(), 0);
        assert_eq!(items.item_calls.get(), 0);
    }

    #[test]
    fn pam_service_and_rhost_are_bounded_validated_and_not_normalized() {
        let username = CString::new("alice").unwrap();
        let valid_service = CString::new("SuDo.service_1").unwrap();
        for (rhost, expected) in [
            (None, PromptOriginV1::Local),
            (Some(CString::new("").unwrap()), PromptOriginV1::Local),
            (
                Some(CString::new("2001:db8::1").unwrap()),
                PromptOriginV1::Remote,
            ),
        ] {
            let mut items = mock_items(&username, Some(&valid_service), rhost.as_ref(), None);
            let (service, origin) =
                unsafe { read_pam_policy(ptr::from_mut(&mut items).cast(), mock_get_context_item) }
                    .unwrap();
            assert_eq!(service, "SuDo.service_1");
            assert_eq!(origin, expected);
        }

        let invalid_services = [
            None,
            Some(CString::new("").unwrap()),
            Some(CString::new("bad/service").unwrap()),
            Some(CString::new("A".repeat(65)).unwrap()),
            Some(CString::new(vec![0xff]).unwrap()),
        ];
        for service in invalid_services {
            let mut items = mock_items(&username, service.as_ref(), None, None);
            assert!(
                unsafe { read_pam_policy(ptr::from_mut(&mut items).cast(), mock_get_context_item) }
                    .is_err()
            );
        }

        let invalid_rhosts = [
            CString::new("remote host").unwrap(),
            CString::new("bad\\host").unwrap(),
            CString::new("bad/host").unwrap(),
            CString::new("A".repeat(256)).unwrap(),
            CString::new(vec![0xff]).unwrap(),
        ];
        for rhost in invalid_rhosts {
            let mut items = mock_items(&username, Some(&valid_service), Some(&rhost), None);
            assert!(
                unsafe { read_pam_policy(ptr::from_mut(&mut items).cast(), mock_get_context_item) }
                    .is_err()
            );
        }
    }

    #[test]
    fn refusal_sends_same_connection_cancel_and_falls_back() {
        reset_allocations();
        let username = CString::new("alice").unwrap();
        let service = CString::new("sudo").unwrap();
        let mut conversation_state = MockConversation::bytes(b"NO");
        let conversation = PamConv {
            conv: Some(mock_conversation),
            appdata_ptr: ptr::from_mut(&mut conversation_state).cast(),
        };
        let mut items = mock_items(&username, Some(&service), None, Some(&conversation));
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = std::thread::spawn(move || {
            let _: Request = recv_message(&mut daemon).unwrap();
            send_message(
                &mut daemon,
                &Response::prompt_required_v1([0x22; 32], [0x11; 32], 30_000, 10_000),
            )
            .unwrap();
            let cancel: Request = recv_message(&mut daemon).unwrap();
            assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
            send_message(&mut daemon, &Response::auth_cancelled_v1([0x11; 32])).unwrap();
        });
        assert_eq!(
            run_adaptive_auth(&mut items, vec![client], 0),
            PAM_AUTHINFO_UNAVAIL
        );
        daemon_thread.join().unwrap();
        assert_cleanup(1, 1);
    }

    #[test]
    fn committed_auth_failed_and_error_preserve_fallback_semantics() {
        for (response, expected) in [
            (Response::auth_failed(0.1, 1, "not matched"), PAM_AUTH_ERR),
            (
                Response::error_code("backend_unavailable", "internal detail"),
                PAM_AUTHINFO_UNAVAIL,
            ),
        ] {
            reset_allocations();
            let username = CString::new("alice").unwrap();
            let service = CString::new("sudo").unwrap();
            let mut conversation_state = MockConversation::bytes(b"OK");
            let conversation = PamConv {
                conv: Some(mock_conversation),
                appdata_ptr: ptr::from_mut(&mut conversation_state).cast(),
            };
            let mut items = mock_items(&username, Some(&service), None, Some(&conversation));
            let (client, mut daemon) = UnixStream::pair().unwrap();
            let daemon_thread = std::thread::spawn(move || {
                let _: Request = recv_message(&mut daemon).unwrap();
                send_message(
                    &mut daemon,
                    &Response::prompt_required_v1([0x22; 32], [0x11; 32], 30_000, 10_000),
                )
                .unwrap();
                let commit: Request = recv_message(&mut daemon).unwrap();
                assert!(matches!(commit.cmd, Some(Cmd::CommitAuthV1(_))));
                send_message(&mut daemon, &response).unwrap();
            });
            assert_eq!(run_adaptive_auth(&mut items, vec![client], 0), expected);
            daemon_thread.join().unwrap();
            assert_cleanup(1, 1);
        }
    }

    #[test]
    fn conversation_error_still_sends_same_connection_cancel() {
        reset_allocations();
        let username = CString::new("alice").unwrap();
        let service = CString::new("sudo").unwrap();
        let mut conversation_state = MockConversation {
            callback_status: PAM_CONV_ERR,
            reply: MockReply::Bytes(b"OK".to_vec()),
            response_retcode: 0,
            calls: 0,
            expected_prompt: false,
        };
        let conversation = PamConv {
            conv: Some(mock_conversation),
            appdata_ptr: ptr::from_mut(&mut conversation_state).cast(),
        };
        let mut items = mock_items(&username, Some(&service), None, Some(&conversation));
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = std::thread::spawn(move || {
            let _: Request = recv_message(&mut daemon).unwrap();
            send_message(
                &mut daemon,
                &Response::prompt_required_v1([0x22; 32], [0x11; 32], 30_000, 10_000),
            )
            .unwrap();
            let cancel: Request = recv_message(&mut daemon).unwrap();
            assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
            send_message(&mut daemon, &Response::auth_cancelled_v1([0x11; 32])).unwrap();
        });
        assert_eq!(
            run_adaptive_auth(&mut items, vec![client], 0),
            PAM_AUTHINFO_UNAVAIL
        );
        daemon_thread.join().unwrap();
        assert_cleanup(1, 1);
    }

    #[test]
    fn exact_prompt_off_response_uses_fresh_tag_21_connection_only() {
        let username = CString::new("alice").unwrap();
        let service = CString::new("sudo").unwrap();
        let mut items = mock_items(&username, Some(&service), None, None);
        let (first_client, mut first_daemon) = UnixStream::pair().unwrap();
        let first = std::thread::spawn(move || {
            let request: Request = recv_message(&mut first_daemon).unwrap();
            assert!(matches!(request.cmd, Some(Cmd::BeginAuthV1(_))));
            send_message(
                &mut first_daemon,
                &Response::error_code(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, "prompt mode is off"),
            )
            .unwrap();
            let retry: std::io::Result<Request> = recv_message(&mut first_daemon);
            assert!(retry.is_err(), "fallback must use a fresh connection");
        });
        let (second_client, mut second_daemon) = UnixStream::pair().unwrap();
        let second = std::thread::spawn(move || {
            let request: Request = recv_message(&mut second_daemon).unwrap();
            assert!(matches!(request.cmd, Some(Cmd::AuthenticateV1(_))));
            assert!(!matches!(request.cmd, Some(Cmd::Authenticate(_))));
            send_message(
                &mut second_daemon,
                &Response::auth_failed(0.1, 1, "not matched"),
            )
            .unwrap();
        });
        assert_eq!(
            run_adaptive_auth(&mut items, vec![first_client, second_client], 0),
            PAM_AUTH_ERR
        );
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn prompt_off_tag21_prefix_and_body_trickle_share_one_absolute_ceiling() {
        use prost::Message;

        for body_trickle in [false, true] {
            let username = CString::new("alice").unwrap();
            let service = CString::new("sudo").unwrap();
            let mut items = mock_items(&username, Some(&service), None, None);
            let (first_client, mut first_daemon) = UnixStream::pair().unwrap();
            let first = std::thread::spawn(move || {
                let _: Request = recv_message(&mut first_daemon).unwrap();
                send_message(
                    &mut first_daemon,
                    &Response::error_code(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, "prompt mode is off"),
                )
                .unwrap();
            });
            let (second_client, mut second_daemon) = UnixStream::pair().unwrap();
            let second = std::thread::spawn(move || {
                let request: Request = recv_message(&mut second_daemon).unwrap();
                assert!(matches!(request.cmd, Some(Cmd::AuthenticateV1(_))));
                let payload = Response::auth_failed(0.1, 1, "not matched").encode_to_vec();
                let prefix = (payload.len() as u32).to_be_bytes();
                if body_trickle {
                    if second_daemon.write_all(&prefix).is_ok() {
                        for byte in payload {
                            if second_daemon.write_all(&[byte]).is_err() {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(30));
                        }
                    }
                } else {
                    for byte in prefix {
                        if second_daemon.write_all(&[byte]).is_err() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(30));
                    }
                }
            });
            let started = Instant::now();
            assert_eq!(
                run_adaptive_auth_with_ceiling(
                    &mut items,
                    vec![first_client, second_client],
                    0,
                    Duration::from_millis(70),
                ),
                PAM_AUTHINFO_UNAVAIL
            );
            assert!(started.elapsed() < Duration::from_millis(500));
            first.join().unwrap();
            second.join().unwrap();
        }
    }

    #[test]
    fn unknown_begin_response_falls_back_without_any_one_shot_retry() {
        let username = CString::new("alice").unwrap();
        let service = CString::new("sudo").unwrap();
        let mut items = mock_items(&username, Some(&service), None, None);
        let (client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = std::thread::spawn(move || {
            let request: Request = recv_message(&mut daemon).unwrap();
            assert!(matches!(request.cmd, Some(Cmd::BeginAuthV1(_))));
            send_message(&mut daemon, &Response::error("unknown request")).unwrap();
            let retry: std::io::Result<Request> = recv_message(&mut daemon);
            assert!(retry.is_err());
        });
        assert_eq!(
            run_adaptive_auth(&mut items, vec![client], 0),
            PAM_AUTHINFO_UNAVAIL
        );
        daemon_thread.join().unwrap();
    }
}
