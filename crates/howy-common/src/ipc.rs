//! IPC client/server helpers for Unix socket communication.
//!
//! Wire format: 4-byte big-endian length prefix + protobuf payload.
//! Uses prost for zero-copy protobuf serialization.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use prost::Message;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::{
    BeginAuthV1Req, COMMIT_RESPONSE_TIMEOUT_MS_MAX, COMMIT_RESPONSE_TIMEOUT_MS_MIN, Cmd,
    PROMPT_NONCE_BYTES, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, PROMPT_TOKEN_BYTES, PromptOriginV1,
    Request, RespResult, Response, is_prompt_auth_terminal_response,
};

/// Maximum message size: 4 MiB.
/// An auth request is ~50 bytes; a 512-dim embedding response is ~2 KiB.
/// 4 MiB is generous but prevents allocation bombs.
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const PROMPT_READ_CANCEL_POLL: Duration = Duration::from_millis(20);
pub const PROMPT_BEGIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROMPT_CANCEL_RESPONSE_TIMEOUT: Duration = Duration::from_millis(250);
pub const PROMPT_TRANSPORT_MARGIN_MS: u64 = 250;

/// Client nonce storage that zeroizes its bytes on every exit path.
pub struct PromptNonce(Zeroizing<[u8; PROMPT_NONCE_BYTES]>);

impl PromptNonce {
    pub fn zeroed() -> Self {
        Self(Zeroizing::new([0u8; PROMPT_NONCE_BYTES]))
    }

    pub fn as_array(&self) -> &[u8; PROMPT_NONCE_BYTES] {
        &self.0
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; PROMPT_NONCE_BYTES] {
        &mut self.0
    }
}

/// Send a protobuf message over a stream with length-prefix framing.
pub fn send_message<W: Write, M: Message>(writer: &mut W, msg: &M) -> io::Result<()> {
    let len = msg.encoded_len();
    let len_bytes = (len as u32).to_be_bytes();

    // Write length prefix + payload in a single write where possible.
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_bytes);
    msg.encode(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

/// Send a prompt-bearing frame with zeroizing encoded-buffer ownership.
pub fn send_prompt_message<W: Write, M: Message>(writer: &mut W, msg: &M) -> io::Result<()> {
    let len = msg.encoded_len();
    let mut buffer = Zeroizing::new(Vec::with_capacity(4 + len));
    buffer.extend_from_slice(&(len as u32).to_be_bytes());
    msg.encode(&mut *buffer)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(&buffer)?;
    writer.flush()
}

/// Send a protobuf message, reusing the provided buffer to avoid allocation.
fn send_message_reuse<W: Write, M: Message>(
    buf: &mut Vec<u8>,
    writer: &mut W,
    msg: &M,
) -> io::Result<()> {
    buf.clear();
    let len = msg.encoded_len();
    let len_bytes = (len as u32).to_be_bytes();
    buf.reserve(4 + len);
    buf.extend_from_slice(&len_bytes);
    msg.encode(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    writer.write_all(buf)?;
    writer.flush()?;
    Ok(())
}

/// Receive a protobuf message from a stream with length-prefix framing.
pub fn recv_message<R: Read, M: Message + Default>(reader: &mut R) -> io::Result<M> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    M::decode(&buf[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Decode a prompt-bearing frame while zeroizing its encoded payload buffer.
pub fn recv_prompt_message<R: Read, M: Message + Default>(reader: &mut R) -> io::Result<M> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let len = u32::from_be_bytes(length) as usize;
    length.zeroize();
    validate_message_size(len)?;
    let mut buffer = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut buffer)?;
    M::decode(&buffer[..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Read one prompt frame against one absolute monotonic deadline.
///
/// Prefix and payload reads repeatedly use only the remaining duration. Short
/// partial reads therefore cannot renew the timeout. `cancelled` is polled at a
/// small bounded interval so daemon shutdown/manager poison terminates a pending
/// read without waiting for the human prompt deadline.
pub fn recv_prompt_message_until<M: Message + Default>(
    stream: &mut UnixStream,
    deadline: Instant,
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<M> {
    let mut length = [0u8; 4];
    read_exact_until(stream, &mut length, deadline, &mut cancelled)?;
    let len = u32::from_be_bytes(length) as usize;
    length.zeroize();
    validate_message_size(len)?;
    let mut buffer = Zeroizing::new(vec![0u8; len]);
    read_exact_until(stream, &mut buffer, deadline, &mut cancelled)?;
    M::decode(&buffer[..]).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Send one framed message against one absolute monotonic deadline.
/// Encoding ownership is zeroizing because prompt/tag-21 requests can contain
/// authentication transaction material.
pub fn send_message_until<M: Message>(
    stream: &mut UnixStream,
    message: &M,
    deadline: Instant,
) -> io::Result<()> {
    let len = message.encoded_len();
    validate_message_size(len)?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(4 + len));
    buffer.extend_from_slice(&(len as u32).to_be_bytes());
    message
        .encode(&mut *buffer)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_all_until(stream, &buffer, deadline)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "IPC transaction expired",
        ));
    }
    stream.set_write_timeout(Some(remaining))?;
    stream.flush()
}

/// Complete one request/response exchange under a single absolute deadline.
pub fn request_message_until<M: Message + Default>(
    stream: &mut UnixStream,
    request: &Request,
    deadline: Instant,
) -> io::Result<M> {
    send_message_until(stream, request, deadline)?;
    recv_prompt_message_until(stream, deadline, || false)
}

fn validate_message_size(len: usize) -> io::Result<()> {
    if len > MAX_MESSAGE_SIZE {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ))
    } else {
        Ok(())
    }
}

fn read_exact_until(
    stream: &mut UnixStream,
    destination: &mut [u8],
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < destination.len() {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "prompt transaction terminated",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "prompt transaction expired",
            ));
        }
        stream.set_read_timeout(Some(remaining.min(PROMPT_READ_CANCEL_POLL)))?;
        match stream.read(&mut destination[offset..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_until(stream: &mut UnixStream, source: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < source.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "IPC transaction expired",
            ));
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&source[offset..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reusable framed IPC over one already-connected stream.
///
/// Unlike [`DaemonClient`], this type never opens another connection and is
/// therefore suitable for protocols whose messages must share one peer-bound
/// Unix socket connection.
pub struct FramedConnection<S> {
    stream: S,
    tx_buf: Zeroizing<Vec<u8>>,
}

impl<S> FramedConnection<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            tx_buf: Zeroizing::new(Vec::with_capacity(256)),
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> FramedConnection<S> {
    pub fn send_request(&mut self, request: &Request) -> io::Result<()> {
        let result = send_message_reuse(&mut self.tx_buf, &mut self.stream, request);
        self.tx_buf.zeroize();
        result
    }
}

impl FramedConnection<UnixStream> {
    fn receive_response_until(&mut self, deadline: Instant) -> io::Result<Response> {
        recv_prompt_message_until(&mut self.stream, deadline, || false)
    }

    fn send_request_until(&mut self, request: &Request, deadline: Instant) -> io::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "prompt transaction expired",
            ));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        self.send_request(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromptClientPhase {
    Initial,
    Pending,
    Finished,
}

/// Same-connection prompt-auth client sequence.
///
/// The supported PAM client uses this adapter. Any I/O, validation, version,
/// or response-shape failure makes the sequence terminal; only the exact
/// prompt-off incompatibility result permits a fresh tag-21 connection.
pub struct PromptAuthClientConnection {
    connection: Option<FramedConnection<UnixStream>>,
    phase: PromptClientPhase,
    pending: PendingTransactionGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromptMetadata {
    pub prompt_timeout_ms: u32,
    pub commit_response_timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptBeginOutcome {
    PromptRequired(PromptMetadata),
    PromptModeOff,
}

struct PendingClientPrompt {
    transaction_token: Zeroizing<[u8; PROMPT_TOKEN_BYTES]>,
    client_nonce: Zeroizing<[u8; PROMPT_NONCE_BYTES]>,
    commit_response_timeout_ms: u32,
}

#[derive(Default)]
struct PendingTransactionGuard {
    pending: Option<PendingClientPrompt>,
}

impl PendingTransactionGuard {
    fn arm(&mut self, pending: PendingClientPrompt) {
        debug_assert!(self.pending.is_none());
        self.pending = Some(pending);
    }

    fn disarm(&mut self) -> io::Result<PendingClientPrompt> {
        self.pending
            .take()
            .ok_or_else(|| prompt_sequence_error("prompt transaction is not pending"))
    }

    fn is_armed(&self) -> bool {
        self.pending.is_some()
    }
}

struct SensitivePromptRequest(Request);

impl SensitivePromptRequest {
    fn new(request: Request) -> Self {
        Self(request)
    }

    fn commit(
        transaction_token: &[u8; PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        let mut token = Zeroizing::new(transaction_token.to_vec());
        let mut nonce = Zeroizing::new(client_nonce.to_vec());
        Self::new(Request {
            cmd: Some(Cmd::CommitAuthV1(crate::protocol::CommitAuthV1Req {
                protocol_version: crate::protocol::PROMPT_PROTOCOL_VERSION,
                transaction_token: std::mem::take(&mut *token),
                client_nonce: std::mem::take(&mut *nonce),
            })),
        })
    }

    fn cancel(
        transaction_token: &[u8; PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        let mut token = Zeroizing::new(transaction_token.to_vec());
        let mut nonce = Zeroizing::new(client_nonce.to_vec());
        Self::new(Request {
            cmd: Some(Cmd::CancelAuthV1(crate::protocol::CancelAuthV1Req {
                protocol_version: crate::protocol::PROMPT_PROTOCOL_VERSION,
                transaction_token: std::mem::take(&mut *token),
                client_nonce: std::mem::take(&mut *nonce),
            })),
        })
    }
}

impl Drop for SensitivePromptRequest {
    fn drop(&mut self) {
        zeroize_prompt_request_fields(&mut self.0);
    }
}

struct SensitivePromptResponse(Option<Response>);

impl SensitivePromptResponse {
    fn new(response: Response) -> Self {
        Self(Some(response))
    }

    fn as_ref(&self) -> &Response {
        self.0.as_ref().expect("sensitive response remains owned")
    }

    fn into_sanitized(mut self) -> Response {
        self.0.take().expect("sensitive response remains owned")
    }
}

impl Drop for SensitivePromptResponse {
    fn drop(&mut self) {
        if let Some(response) = self.0.as_mut() {
            zeroize_prompt_response_fields(response);
        }
    }
}

impl PromptAuthClientConnection {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            connection: Some(FramedConnection::new(stream)),
            phase: PromptClientPhase::Initial,
            pending: PendingTransactionGuard::default(),
        }
    }

    pub fn into_inner(mut self) -> UnixStream {
        if self.pending.is_armed() {
            let _ = self.cancel();
        }
        self.phase = PromptClientPhase::Finished;
        self.connection
            .take()
            .expect("prompt connection remains owned")
            .into_inner()
    }

    pub fn begin(&mut self, begin: BeginAuthV1Req) -> io::Result<PromptMetadata> {
        match self.begin_adaptive(begin)? {
            PromptBeginOutcome::PromptRequired(metadata) => Ok(metadata),
            PromptBeginOutcome::PromptModeOff => Err(prompt_sequence_error(
                "daemon prompt mode is incompatible with prompt authentication",
            )),
        }
    }

    /// Start supported-client authentication and distinguish only the exact
    /// current-daemon prompt-off compatibility response. Every other response
    /// shape is terminal and must not trigger a one-shot downgrade.
    pub fn begin_adaptive(&mut self, begin: BeginAuthV1Req) -> io::Result<PromptBeginOutcome> {
        self.begin_adaptive_request(SensitivePromptRequest::new(Request {
            cmd: Some(Cmd::BeginAuthV1(begin)),
        }))
    }

    /// Start BeginAuthV1 while borrowing nonce bytes from a zeroizing caller.
    pub fn begin_adaptive_ref(
        &mut self,
        username: &str,
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
        pam_service: &str,
        origin: PromptOriginV1,
    ) -> io::Result<PromptBeginOutcome> {
        self.begin_adaptive_request(SensitivePromptRequest::new(Request::begin_auth_v1_ref(
            username,
            client_nonce,
            pam_service,
            origin,
        )))
    }

    fn begin_adaptive_request(
        &mut self,
        request: SensitivePromptRequest,
    ) -> io::Result<PromptBeginOutcome> {
        let deadline = prompt_deadline(PROMPT_BEGIN_RESPONSE_TIMEOUT)?;
        self.begin_adaptive_request_until(request, deadline)
    }

    #[cfg(test)]
    fn begin_adaptive_with_timeout_for_test(
        &mut self,
        begin: BeginAuthV1Req,
        timeout: Duration,
    ) -> io::Result<PromptBeginOutcome> {
        let request = SensitivePromptRequest::new(Request {
            cmd: Some(Cmd::BeginAuthV1(begin)),
        });
        self.begin_adaptive_request_until(request, prompt_deadline(timeout)?)
    }

    fn begin_adaptive_request_until(
        &mut self,
        request: SensitivePromptRequest,
        deadline: Instant,
    ) -> io::Result<PromptBeginOutcome> {
        let Some(Cmd::BeginAuthV1(begin)) = request.0.cmd.as_ref() else {
            unreachable!("prompt request wrapper preserves BeginAuthV1")
        };
        if self.phase != PromptClientPhase::Initial {
            return Err(prompt_sequence_error("begin is not valid in this phase"));
        }
        if begin.validate().is_err() {
            self.phase = PromptClientPhase::Finished;
            return Err(prompt_sequence_error("invalid prompt begin request"));
        }
        let expected_nonce = zeroizing_exact_array::<PROMPT_NONCE_BYTES>(&begin.client_nonce)?;
        let send = self.connection_mut().send_request(&request.0);
        if let Err(error) = send {
            self.phase = PromptClientPhase::Finished;
            return Err(error);
        }
        let response = match self.connection_mut().receive_response_until(deadline) {
            Ok(response) => SensitivePromptResponse::new(response),
            Err(error) => {
                self.phase = PromptClientPhase::Finished;
                return Err(error);
            }
        };
        let prompt = match response.as_ref().result.as_ref() {
            Some(RespResult::PromptRequiredV1(prompt)) => prompt,
            Some(RespResult::Error(error)) if error.code == PROMPT_PROTOCOL_INCOMPATIBLE_ERROR => {
                self.phase = PromptClientPhase::Finished;
                return Ok(PromptBeginOutcome::PromptModeOff);
            }
            _ => {
                self.phase = PromptClientPhase::Finished;
                return Err(prompt_sequence_error("unexpected prompt begin response"));
            }
        };
        if prompt.validate().is_err()
            || !constant_time_slice_eq(&prompt.client_nonce, &expected_nonce[..])
        {
            self.phase = PromptClientPhase::Finished;
            return Err(prompt_sequence_error("invalid prompt begin response"));
        }
        let transaction_token =
            zeroizing_exact_array::<PROMPT_TOKEN_BYTES>(&prompt.transaction_token)?;
        let metadata = PromptMetadata {
            prompt_timeout_ms: prompt.prompt_timeout_ms,
            commit_response_timeout_ms: prompt.commit_response_timeout_ms,
        };
        self.pending.arm(PendingClientPrompt {
            transaction_token,
            client_nonce: expected_nonce,
            commit_response_timeout_ms: metadata.commit_response_timeout_ms,
        });
        self.phase = PromptClientPhase::Pending;
        Ok(PromptBeginOutcome::PromptRequired(metadata))
    }

    pub fn commit(&mut self) -> io::Result<Response> {
        let pending = self.take_pending()?;
        let timeout = prompt_commit_read_timeout(pending.commit_response_timeout_ms)?;
        let deadline = prompt_deadline(timeout)?;
        self.commit_pending_until(pending, deadline)
    }

    fn commit_pending_until(
        &mut self,
        pending: PendingClientPrompt,
        deadline: Instant,
    ) -> io::Result<Response> {
        let request =
            SensitivePromptRequest::commit(&pending.transaction_token, &pending.client_nonce);
        self.connection_mut().send_request(&request.0)?;
        let response =
            SensitivePromptResponse::new(self.connection_mut().receive_response_until(deadline)?);
        if !is_prompt_auth_terminal_response(response.as_ref()) {
            return Err(prompt_sequence_error("unexpected prompt commit response"));
        }
        Ok(response.into_sanitized())
    }

    #[cfg(test)]
    fn commit_with_timeout_for_test(&mut self, timeout: Duration) -> io::Result<Response> {
        let pending = self.take_pending()?;
        self.commit_pending_until(pending, prompt_deadline(timeout)?)
    }

    pub fn cancel(&mut self) -> io::Result<()> {
        let pending = self.take_pending()?;
        let deadline = prompt_deadline(PROMPT_CANCEL_RESPONSE_TIMEOUT)?;
        self.cancel_pending_until(pending, deadline)
    }

    fn cancel_pending_until(
        &mut self,
        pending: PendingClientPrompt,
        deadline: Instant,
    ) -> io::Result<()> {
        let request =
            SensitivePromptRequest::cancel(&pending.transaction_token, &pending.client_nonce);
        self.connection_mut()
            .send_request_until(&request.0, deadline)?;
        let response =
            SensitivePromptResponse::new(self.connection_mut().receive_response_until(deadline)?);
        let Some(RespResult::AuthCancelledV1(cancelled)) = response.as_ref().result.as_ref() else {
            return Err(prompt_sequence_error("unexpected prompt cancel response"));
        };
        let cancelled_valid = cancelled.validate().is_ok()
            && constant_time_slice_eq(&cancelled.client_nonce, &pending.client_nonce[..]);
        if !cancelled_valid {
            return Err(prompt_sequence_error("invalid prompt cancel response"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn cancel_with_timeout_for_test(&mut self, timeout: Duration) -> io::Result<()> {
        let pending = self.take_pending()?;
        self.cancel_pending_until(pending, prompt_deadline(timeout)?)
    }

    fn take_pending(&mut self) -> io::Result<PendingClientPrompt> {
        if self.phase != PromptClientPhase::Pending {
            return Err(prompt_sequence_error("prompt transaction is not pending"));
        }
        self.phase = PromptClientPhase::Finished;
        self.pending.disarm()
    }

    fn connection_mut(&mut self) -> &mut FramedConnection<UnixStream> {
        self.connection
            .as_mut()
            .expect("prompt connection remains owned")
    }
}

impl Drop for PromptAuthClientConnection {
    fn drop(&mut self) {
        if self.phase != PromptClientPhase::Pending || !self.pending.is_armed() {
            return;
        }
        let Ok(pending) = self.take_pending() else {
            return;
        };
        let Ok(deadline) = prompt_deadline(PROMPT_CANCEL_RESPONSE_TIMEOUT) else {
            return;
        };
        let _ = self.cancel_pending_until(pending, deadline);
    }
}

fn zeroize_prompt_request_fields(request: &mut Request) {
    match request.cmd.as_mut() {
        Some(Cmd::BeginAuthV1(begin)) => begin.client_nonce.zeroize(),
        Some(Cmd::CommitAuthV1(commit)) => {
            commit.transaction_token.zeroize();
            commit.client_nonce.zeroize();
        }
        Some(Cmd::CancelAuthV1(cancel)) => {
            cancel.transaction_token.zeroize();
            cancel.client_nonce.zeroize();
        }
        _ => {}
    }
}

fn zeroize_prompt_response_fields(response: &mut Response) {
    match response.result.as_mut() {
        Some(RespResult::PromptRequiredV1(prompt)) => {
            prompt.transaction_token.zeroize();
            prompt.client_nonce.zeroize();
        }
        Some(RespResult::AuthCancelledV1(cancelled)) => cancelled.client_nonce.zeroize(),
        _ => {}
    }
}

fn constant_time_slice_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

pub fn prompt_commit_read_timeout(commit_response_timeout_ms: u32) -> io::Result<Duration> {
    if !(COMMIT_RESPONSE_TIMEOUT_MS_MIN..=COMMIT_RESPONSE_TIMEOUT_MS_MAX)
        .contains(&commit_response_timeout_ms)
    {
        return Err(prompt_sequence_error(
            "invalid prompt commit response timeout",
        ));
    }
    Duration::from_millis(u64::from(commit_response_timeout_ms))
        .checked_add(Duration::from_millis(PROMPT_TRANSPORT_MARGIN_MS))
        .ok_or_else(|| prompt_sequence_error("prompt commit response timeout overflow"))
}

fn prompt_deadline(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| prompt_sequence_error("prompt response deadline overflow"))
}

fn zeroizing_exact_array<const N: usize>(value: &[u8]) -> io::Result<Zeroizing<[u8; N]>> {
    if value.len() != N {
        return Err(prompt_sequence_error("invalid prompt transaction data"));
    }
    let mut owned = Zeroizing::new([0u8; N]);
    owned.copy_from_slice(value);
    Ok(owned)
}

fn prompt_sequence_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A client that connects to the howy daemon over Unix socket.
///
/// Each request opens a fresh connection because the daemon handles one
/// request per connection. The send buffer is reused across calls to
/// avoid repeated heap allocation.
pub struct DaemonClient {
    socket_path: String,
    timeout: Duration,
    tx_buf: Vec<u8>,
}

impl DaemonClient {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            timeout: Duration::from_secs(10),
            tx_buf: Vec::with_capacity(256),
        }
    }

    /// Create a client with the effective socket path.
    /// Honors `HOWY_SOCKET` env override for development.
    pub fn default_path() -> Self {
        Self::new(&crate::paths::socket_path())
    }

    /// Set the timeout for read/write operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send a request and receive a response.
    /// Opens a fresh connection per request (daemon is one-shot per connection).
    pub fn request(&mut self, req: &Request) -> io::Result<Response> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        send_message_reuse(&mut self.tx_buf, &mut stream, req)?;
        recv_message(&mut stream)
    }

    /// Open one reusable connection for the versioned prompt-auth sequence.
    pub fn connect_prompt_auth(&self) -> io::Result<PromptAuthClientConnection> {
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(PromptAuthClientConnection::new(stream))
    }

    /// Quick health check.
    pub fn ping(&mut self) -> bool {
        matches!(
            self.request(&Request::ping()),
            Ok(Response {
                result: Some(crate::protocol::RespResult::Pong(_)),
                ..
            })
        )
    }

    /// Authenticate a user.
    pub fn authenticate(&mut self, username: &str, timeout: u32) -> io::Result<Response> {
        self.request(&Request::authenticate(username, timeout))
    }

    /// Authenticate with the versioned one-shot request (wire tag 21).
    pub fn authenticate_v1(&mut self, username: &str, timeout: u32) -> io::Result<Response> {
        self.request(&Request::authenticate_v1(username, timeout))
    }

    /// Check cached credential.
    pub fn check_credential(&mut self, username: &str) -> io::Result<Response> {
        self.request(&Request::check_credential(username))
    }

    /// Revoke a cached credential.
    pub fn revoke_credential(&mut self, username: &str, session_id: &str) -> io::Result<Response> {
        self.request(&Request::revoke_credential(username, session_id))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PROMPT_CANCEL_RESPONSE_TIMEOUT, PromptAuthClientConnection, PromptBeginOutcome,
        prompt_commit_read_timeout, recv_message, recv_prompt_message_until, send_message,
        zeroize_prompt_request_fields, zeroize_prompt_response_fields,
    };
    use crate::protocol::{
        Cmd, PROMPT_NONCE_BYTES, PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, PROMPT_TOKEN_BYTES,
        PromptOriginV1, Request, RespResult, Response,
    };
    use prost::Message;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn begin_message() -> crate::protocol::BeginAuthV1Req {
        let Some(Cmd::BeginAuthV1(begin)) = Request::begin_auth_v1(
            "alice",
            [0x11; PROMPT_NONCE_BYTES],
            "sudo",
            PromptOriginV1::Local,
        )
        .cmd
        else {
            unreachable!()
        };
        begin
    }

    fn send_slow_frame(
        stream: &mut UnixStream,
        response: &Response,
        slow_body: bool,
        delay: Duration,
    ) {
        let payload = response.encode_to_vec();
        let length = (payload.len() as u32).to_be_bytes();
        if slow_body {
            stream.write_all(&length).unwrap();
            stream.write_all(&payload[..1]).unwrap();
            std::thread::sleep(delay);
            let _ = stream.write_all(&payload[1..]);
        } else {
            stream.write_all(&length[..1]).unwrap();
            std::thread::sleep(delay);
            let _ = stream.write_all(&length[1..]);
            let _ = stream.write_all(&payload);
        }
    }

    #[test]
    fn prompt_client_uses_one_connection_for_begin_and_commit() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let begin: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(begin.cmd, Some(Cmd::BeginAuthV1(_))));
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x11; PROMPT_NONCE_BYTES],
                    30_000,
                    10_000,
                ),
            )
            .unwrap();
            let commit: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(commit.cmd, Some(Cmd::CommitAuthV1(_))));
            send_message(&mut server_stream, &Response::success(0, "desk", 0.9, 12.0)).unwrap();
        });

        let mut client = PromptAuthClientConnection::new(client_stream);
        let metadata = client.begin(begin_message()).unwrap();
        assert_eq!(metadata.prompt_timeout_ms, 30_000);
        assert_eq!(metadata.commit_response_timeout_ms, 10_000);
        assert!(matches!(
            client.commit().unwrap().result,
            Some(RespResult::Success(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn prompt_client_uses_one_connection_for_pending_cancel() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x11; PROMPT_NONCE_BYTES],
                    30_000,
                    10_000,
                ),
            )
            .unwrap();
            let cancel: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
            send_message(
                &mut server_stream,
                &Response::auth_cancelled_v1([0x11; PROMPT_NONCE_BYTES]),
            )
            .unwrap();
        });

        let mut client = PromptAuthClientConnection::new(client_stream);
        client.begin(begin_message()).unwrap();
        client.cancel().unwrap();
        assert!(client.cancel().is_err());
        server.join().unwrap();
    }

    #[test]
    fn new_client_rejects_old_daemon_response_without_one_shot_downgrade() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let first: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(first.cmd, Some(Cmd::BeginAuthV1(_))));
            send_message(&mut server_stream, &Response::error("unknown request")).unwrap();
            let second: std::io::Result<Request> = recv_message(&mut server_stream);
            assert!(
                second.is_err(),
                "client must close instead of retrying Authenticate"
            );
        });

        let mut client = PromptAuthClientConnection::new(client_stream);
        assert!(client.begin(begin_message()).is_err());
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn new_client_treats_old_daemon_eof_as_terminal_without_downgrade() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let first: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(first.cmd, Some(Cmd::BeginAuthV1(_))));
        });

        let mut client = PromptAuthClientConnection::new(client_stream);
        assert!(client.begin(begin_message()).is_err());
        assert!(client.begin(begin_message()).is_err());
        server.join().unwrap();
    }

    #[test]
    fn adaptive_begin_distinguishes_only_exact_prompt_off_code() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::error_code(PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, "prompt mode is off"),
            )
            .unwrap();
        });
        let mut client = PromptAuthClientConnection::new(client_stream);
        assert_eq!(
            client.begin_adaptive(begin_message()).unwrap(),
            PromptBeginOutcome::PromptModeOff
        );
        server.join().unwrap();

        for response in [
            Response::error_code("Prompt_Protocol_Incompatible", "wrong case"),
            Response::error("unknown request"),
            Response::pong(),
        ] {
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let _: Request = recv_message(&mut server_stream).unwrap();
                send_message(&mut server_stream, &response).unwrap();
            });
            let mut client = PromptAuthClientConnection::new(client_stream);
            assert!(client.begin_adaptive(begin_message()).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn prompt_client_rejects_nonce_mismatch_and_invalid_final_forms() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x33; PROMPT_NONCE_BYTES],
                    30_000,
                    10_000,
                ),
            )
            .unwrap();
        });
        let mut client = PromptAuthClientConnection::new(client_stream);
        assert!(client.begin(begin_message()).is_err());
        server.join().unwrap();

        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x11; PROMPT_NONCE_BYTES],
                    30_000,
                    10_000,
                ),
            )
            .unwrap();
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(&mut server_stream, &Response::credential_valid()).unwrap();
        });
        let mut client = PromptAuthClientConnection::new(client_stream);
        client.begin(begin_message()).unwrap();
        assert!(client.commit().is_err());
        server.join().unwrap();
    }

    #[test]
    fn committed_prompt_applies_advertised_timeout_plus_exact_transport_margin() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x11; PROMPT_NONCE_BYTES],
                    30_000,
                    120_000,
                ),
            )
            .unwrap();
            let commit: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(commit.cmd, Some(Cmd::CommitAuthV1(_))));
            send_message(&mut server_stream, &Response::auth_failed(0.0, 0, "test")).unwrap();
        });

        let mut client = PromptAuthClientConnection::new(client_stream);
        client.begin(begin_message()).unwrap();
        let started = Instant::now();
        client.commit().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();

        assert_eq!(
            prompt_commit_read_timeout(1_000).unwrap(),
            Duration::from_millis(1_250)
        );
        assert!(prompt_commit_read_timeout(999).is_err());
        assert!(prompt_commit_read_timeout(120_001).is_err());
    }

    #[test]
    fn begin_commit_and_cancel_use_one_deadline_across_prefix_and_body() {
        const CLIENT_LIMIT: Duration = Duration::from_millis(60);
        const SERVER_DELAY: Duration = Duration::from_millis(120);

        for slow_body in [false, true] {
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let _: Request = recv_message(&mut server_stream).unwrap();
                send_slow_frame(
                    &mut server_stream,
                    &Response::prompt_required_v1(
                        [0x22; PROMPT_TOKEN_BYTES],
                        [0x11; PROMPT_NONCE_BYTES],
                        30_000,
                        10_000,
                    ),
                    slow_body,
                    SERVER_DELAY,
                );
            });
            let mut client = PromptAuthClientConnection::new(client_stream);
            let started = Instant::now();
            let error = client
                .begin_adaptive_with_timeout_for_test(begin_message(), CLIENT_LIMIT)
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() < SERVER_DELAY);
            drop(client);
            server.join().unwrap();

            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let _: Request = recv_message(&mut server_stream).unwrap();
                send_message(
                    &mut server_stream,
                    &Response::prompt_required_v1(
                        [0x22; PROMPT_TOKEN_BYTES],
                        [0x11; PROMPT_NONCE_BYTES],
                        30_000,
                        10_000,
                    ),
                )
                .unwrap();
                let commit: Request = recv_message(&mut server_stream).unwrap();
                assert!(matches!(commit.cmd, Some(Cmd::CommitAuthV1(_))));
                send_slow_frame(
                    &mut server_stream,
                    &Response::auth_failed(0.0, 0, "test"),
                    slow_body,
                    SERVER_DELAY,
                );
            });
            let mut client = PromptAuthClientConnection::new(client_stream);
            client.begin(begin_message()).unwrap();
            let started = Instant::now();
            let error = client
                .commit_with_timeout_for_test(CLIENT_LIMIT)
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() < SERVER_DELAY);
            drop(client);
            server.join().unwrap();

            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                let _: Request = recv_message(&mut server_stream).unwrap();
                send_message(
                    &mut server_stream,
                    &Response::prompt_required_v1(
                        [0x22; PROMPT_TOKEN_BYTES],
                        [0x11; PROMPT_NONCE_BYTES],
                        30_000,
                        10_000,
                    ),
                )
                .unwrap();
                let cancel: Request = recv_message(&mut server_stream).unwrap();
                assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
                send_slow_frame(
                    &mut server_stream,
                    &Response::auth_cancelled_v1([0x11; PROMPT_NONCE_BYTES]),
                    slow_body,
                    SERVER_DELAY,
                );
            });
            let mut client = PromptAuthClientConnection::new(client_stream);
            client.begin(begin_message()).unwrap();
            let started = Instant::now();
            let error = client
                .cancel_with_timeout_for_test(CLIENT_LIMIT)
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() < SERVER_DELAY);
            drop(client);
            server.join().unwrap();
        }
    }

    #[test]
    fn armed_pending_guard_drop_sends_one_bounded_cancel_then_closes() {
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let _: Request = recv_message(&mut server_stream).unwrap();
            send_message(
                &mut server_stream,
                &Response::prompt_required_v1(
                    [0x22; PROMPT_TOKEN_BYTES],
                    [0x11; PROMPT_NONCE_BYTES],
                    30_000,
                    10_000,
                ),
            )
            .unwrap();
            let cancel: Request = recv_message(&mut server_stream).unwrap();
            assert!(matches!(cancel.cmd, Some(Cmd::CancelAuthV1(_))));
            let duplicate: std::io::Result<Request> = recv_message(&mut server_stream);
            assert!(duplicate.is_err());
        });
        let mut client = PromptAuthClientConnection::new(client_stream);
        client.begin(begin_message()).unwrap();
        let started = Instant::now();
        drop(client);
        assert!(started.elapsed() < PROMPT_CANCEL_RESPONSE_TIMEOUT + Duration::from_millis(150));
        server.join().unwrap();
    }

    #[test]
    fn slow_prefix_and_body_trickle_cannot_extend_absolute_prompt_deadline() {
        let request =
            Request::commit_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]);
        let payload = request.encode_to_vec();
        let length = (payload.len() as u32).to_be_bytes();

        for body_phase in [false, true] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            let payload = payload.clone();
            let writer_thread = std::thread::spawn(move || {
                if body_phase {
                    writer.write_all(&length).unwrap();
                    writer.write_all(&payload[..1]).unwrap();
                } else {
                    writer.write_all(&length[..1]).unwrap();
                }
                std::thread::sleep(Duration::from_millis(180));
                let _ = writer.write_all(if body_phase {
                    &payload[1..]
                } else {
                    &length[1..]
                });
            });
            let started = Instant::now();
            let result: std::io::Result<Request> = recv_prompt_message_until(
                &mut reader,
                Instant::now() + Duration::from_millis(60),
                || false,
            );
            assert!(matches!(
                result.as_ref().map_err(std::io::Error::kind),
                Err(std::io::ErrorKind::TimedOut)
            ));
            assert!(started.elapsed() < Duration::from_millis(150));
            drop(reader);
            writer_thread.join().unwrap();
        }
    }

    #[test]
    fn prompt_generated_fields_have_complete_early_error_cleanup() {
        let mut requests = vec![
            Request::begin_auth_v1(
                "alice",
                [0x11; PROMPT_NONCE_BYTES],
                "sudo",
                PromptOriginV1::Local,
            ),
            Request::commit_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]),
            Request::cancel_auth_v1([0x22; PROMPT_TOKEN_BYTES], [0x11; PROMPT_NONCE_BYTES]),
        ];
        for request in &mut requests {
            zeroize_prompt_request_fields(request);
            match request.cmd.as_ref().unwrap() {
                Cmd::BeginAuthV1(begin) => {
                    assert!(begin.client_nonce.iter().all(|byte| *byte == 0))
                }
                Cmd::CommitAuthV1(commit) => {
                    assert!(commit.transaction_token.iter().all(|byte| *byte == 0));
                    assert!(commit.client_nonce.iter().all(|byte| *byte == 0));
                }
                Cmd::CancelAuthV1(cancel) => {
                    assert!(cancel.transaction_token.iter().all(|byte| *byte == 0));
                    assert!(cancel.client_nonce.iter().all(|byte| *byte == 0));
                }
                _ => unreachable!(),
            }
        }

        let mut response = Response::prompt_required_v1(
            [0x22; PROMPT_TOKEN_BYTES],
            [0x11; PROMPT_NONCE_BYTES],
            30_000,
            10_000,
        );
        zeroize_prompt_response_fields(&mut response);
        let Some(RespResult::PromptRequiredV1(prompt)) = response.result else {
            unreachable!()
        };
        assert!(prompt.transaction_token.iter().all(|byte| *byte == 0));
        assert!(prompt.client_nonce.iter().all(|byte| *byte == 0));
    }
}
