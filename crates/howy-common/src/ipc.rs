//! IPC client/server helpers for Unix socket communication.
//!
//! Wire format: 4-byte big-endian length prefix + protobuf payload.
//! Uses prost for zero-copy protobuf serialization.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use prost::Message;

use crate::protocol::{Request, Response};

/// Maximum message size: 4 MiB.
/// An auth request is ~50 bytes; a 512-dim embedding response is ~2 KiB.
/// 4 MiB is generous but prevents allocation bombs.
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

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

    /// Check cached credential.
    pub fn check_credential(&mut self, username: &str) -> io::Result<Response> {
        self.request(&Request::check_credential(username))
    }

    /// Revoke a cached credential.
    pub fn revoke_credential(&mut self, username: &str, session_id: &str) -> io::Result<Response> {
        self.request(&Request::revoke_credential(username, session_id))
    }
}
