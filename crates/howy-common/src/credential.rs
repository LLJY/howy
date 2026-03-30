//! Credential caching via the Linux kernel keyring.
//!
//! This module still contains the experimental keyring helpers, but the
//! current PAM deployment intentionally does not use them at runtime until a
//! real PAM session identifier is wired through the daemon path.
//!
//! Callers must provide a non-empty, session-scoped `session_id`. Empty
//! session IDs are rejected or treated as cache misses so they cannot create a
//! reusable auth success across unrelated PAM calls.

use crate::config::CredentialConfig;
use std::time::{SystemTime, UNIX_EPOCH};

const INITIAL_KEY_READ_CAPACITY: usize = 512;

/// Credential token stored in the keyring.
#[derive(Debug)]
pub struct AuthCredential {
    pub username: String,
    pub timestamp: u64,
    pub nonce: u64,
}

impl AuthCredential {
    /// Create a new credential for the current time.
    pub fn new(username: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = timestamp ^ (std::process::id() as u64);
        Self {
            username: username.to_string(),
            timestamp,
            nonce,
        }
    }

    /// Encode to a storable string.
    pub fn encode(&self) -> String {
        format!("howy:1:{}:{}:{}", self.username, self.timestamp, self.nonce)
    }

    /// Decode from a stored string.
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 5 || parts[0] != "howy" || parts[1] != "1" {
            return None;
        }
        Some(Self {
            username: parts[2].to_string(),
            timestamp: parts[3].parse().ok()?,
            nonce: parts[4].parse().ok()?,
        })
    }

    /// Check if the credential is still valid (within TTL).
    pub fn is_valid(&self, username: &str, ttl_secs: u64) -> bool {
        if self.username != username {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.timestamp > now {
            return false;
        }

        now.saturating_sub(self.timestamp) < ttl_secs
    }
}

fn credential_description(keyring_prefix: &str, username: &str, session_id: &str) -> String {
    format!("{keyring_prefix}:{username}:{session_id}")
}

fn has_session_scope(session_id: &str) -> bool {
    !session_id.trim().is_empty()
}

fn read_key_payload(key: linux_keyutils::Key) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; INITIAL_KEY_READ_CAPACITY];

    loop {
        match key.read(&mut buf) {
            Ok(n) if n <= buf.len() => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(n) => buf.resize(n, 0),
            Err(e) => return Err(format!("failed to read key payload: {e}")),
        }
    }
}

/// Store an auth credential in the kernel session keyring.
pub fn store_credential(
    username: &str,
    session_id: &str,
    ttl_secs: u32,
    config: &CredentialConfig,
) -> Result<(), String> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    if !has_session_scope(session_id) {
        return Err("credential caching requires a non-empty session_id".to_string());
    }

    let cred = AuthCredential::new(username);
    let payload = cred.encode();
    let description = credential_description(&config.keyring_prefix, username, session_id);

    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| format!("failed to open session keyring: {e}"))?;

    let key = ring
        .add_key(&description, payload.as_bytes())
        .map_err(|e| format!("failed to add key to keyring: {e}"))?;

    key.set_timeout(ttl_secs as usize)
        .map_err(|e| format!("failed to set key timeout: {e}"))?;

    tracing::debug!(
        "Stored auth credential for {username} (session: {session_id}, TTL: {ttl_secs}s)"
    );
    Ok(())
}

/// Check if a valid auth credential exists in the kernel session keyring.
pub fn check_credential(
    username: &str,
    session_id: &str,
    ttl_secs: u64,
    config: &CredentialConfig,
) -> Result<bool, String> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    if !has_session_scope(session_id) {
        return Ok(false);
    }

    let description = credential_description(&config.keyring_prefix, username, session_id);

    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| format!("failed to open session keyring: {e}"))?;

    match ring.search(&description) {
        Ok(key) => match read_key_payload(key) {
            Ok(payload) => {
                let payload = String::from_utf8_lossy(&payload);
                Ok(AuthCredential::decode(&payload)
                    .map(|cred| cred.is_valid(username, ttl_secs))
                    .unwrap_or(false))
            }
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    }
}

/// Invalidate (revoke) any cached credential for a user.
pub fn revoke_credential(
    username: &str,
    session_id: &str,
    config: &CredentialConfig,
) -> Result<(), String> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    if !has_session_scope(session_id) {
        return Err("credential caching requires a non-empty session_id".to_string());
    }

    let description = credential_description(&config.keyring_prefix, username, session_id);

    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| format!("failed to open session keyring: {e}"))?;

    if let Ok(key) = ring.search(&description) {
        key.invalidate()
            .map_err(|e| format!("failed to invalidate key: {e}"))?;
        tracing::debug!("Revoked auth credential for {username} (session: {session_id})");
    }

    Ok(())
}
