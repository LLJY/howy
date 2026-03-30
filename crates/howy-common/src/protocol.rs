//! IPC protocol definitions between PAM module, CLI, and daemon.
//!
//! Wire format: 4-byte big-endian length prefix + protobuf payload.
//! See `proto/howy.proto` for the canonical schema.
//!
//! This module re-exports the prost-generated types and adds
//! convenience constructors.

/// Generated protobuf types from `proto/howy.proto`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/howy.rs"));
}

// Re-export top-level types for convenience.
pub use pb::request::Cmd;
pub use pb::response::Result as RespResult;
pub use pb::Request;
pub use pb::Response;

// Re-export all message types.
pub use pb::{
    AuthFailed, AuthSuccess, AuthenticateReq, CheckCredentialReq, CredentialInvalid,
    CredentialValid, DaemonInfo, DetectReq, DetectResult, DetectedFace, EnrollBatchReq,
    EnrollBatchResult, EnrollReq, EnrollSuccess, Error, InfoReq, PingReq, Pong,
    RevokeCredentialReq, ShutdownReq,
};

/// PAM exit codes (matching howdy conventions for backward compatibility).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Authentication succeeded.
    Success = 0,
    /// General failure.
    Failure = 1,
    /// No face model enrolled for user.
    NoFaceModel = 10,
    /// Timeout reached, no match found.
    Timeout = 11,
    /// General abort.
    Abort = 12,
    /// Image too dark.
    TooDark = 13,
    /// Camera device not found.
    InvalidDevice = 14,
}

// ---- Convenience constructors ----

impl Request {
    pub fn authenticate(username: &str, timeout: u32) -> Self {
        Self {
            cmd: Some(Cmd::Authenticate(AuthenticateReq {
                username: username.to_string(),
                timeout,
            })),
        }
    }

    pub fn enroll(username: &str, label: &str) -> Self {
        Self {
            cmd: Some(Cmd::Enroll(EnrollReq {
                username: username.to_string(),
                label: label.to_string(),
            })),
        }
    }

    pub fn ping() -> Self {
        Self {
            cmd: Some(Cmd::Ping(PingReq {})),
        }
    }

    pub fn info() -> Self {
        Self {
            cmd: Some(Cmd::Info(InfoReq {})),
        }
    }

    pub fn shutdown() -> Self {
        Self {
            cmd: Some(Cmd::Shutdown(ShutdownReq {})),
        }
    }

    pub fn check_credential(username: &str) -> Self {
        Self {
            cmd: Some(Cmd::CheckCredential(CheckCredentialReq {
                username: username.to_string(),
            })),
        }
    }

    pub fn revoke_credential(username: &str, session_id: &str) -> Self {
        Self {
            cmd: Some(Cmd::RevokeCredential(RevokeCredentialReq {
                username: username.to_string(),
                session_id: session_id.to_string(),
            })),
        }
    }

    pub fn enroll_batch(username: &str, session_dir: &str, label: &str) -> Self {
        Self {
            cmd: Some(Cmd::EnrollBatch(EnrollBatchReq {
                username: username.to_string(),
                session_dir: session_dir.to_string(),
                label: label.to_string(),
            })),
        }
    }
}

impl Response {
    pub fn success(model_index: u32, model_label: &str, score: f32, elapsed_ms: f64) -> Self {
        Self {
            result: Some(RespResult::Success(AuthSuccess {
                model_index,
                model_label: model_label.to_string(),
                score,
                elapsed_ms,
            })),
        }
    }

    pub fn auth_failed(best_score: f32, frames_processed: u32, reason: &str) -> Self {
        Self {
            result: Some(RespResult::AuthFailed(AuthFailed {
                best_score,
                frames_processed,
                reason: reason.to_string(),
            })),
        }
    }

    pub fn enrolled(embedding: Vec<f32>, det_score: f32) -> Self {
        Self {
            result: Some(RespResult::Enrolled(EnrollSuccess {
                embedding,
                det_score,
            })),
        }
    }

    pub fn pong() -> Self {
        Self {
            result: Some(RespResult::Pong(Pong {})),
        }
    }

    pub fn daemon_info(
        provider: &str,
        detector_model: &str,
        recognizer_model: &str,
        embedding_dim: u32,
        uptime_secs: u64,
    ) -> Self {
        Self {
            result: Some(RespResult::Info(DaemonInfo {
                provider: provider.to_string(),
                detector_model: detector_model.to_string(),
                recognizer_model: recognizer_model.to_string(),
                embedding_dim,
                uptime_secs,
            })),
        }
    }

    pub fn credential_valid() -> Self {
        Self {
            result: Some(RespResult::CredentialValid(CredentialValid {})),
        }
    }

    pub fn credential_invalid() -> Self {
        Self {
            result: Some(RespResult::CredentialInvalid(CredentialInvalid {})),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            result: Some(RespResult::Error(Error {
                message: message.to_string(),
            })),
        }
    }

    pub fn enroll_batch_done(
        frames_found: u32,
        frames_accepted: u32,
        frames_rejected: u32,
        elapsed_ms: f64,
        rejection_details: Vec<String>,
    ) -> Self {
        Self {
            result: Some(RespResult::EnrollBatchDone(EnrollBatchResult {
                frames_found,
                frames_accepted,
                frames_rejected,
                elapsed_ms,
                rejection_details,
            })),
        }
    }
}
