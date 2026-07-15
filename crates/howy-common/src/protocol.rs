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
pub use pb::Request;
pub use pb::Response;
pub use pb::request::Cmd;
pub use pb::response::Result as RespResult;

// Re-export all message types.
pub use pb::{
    AuthCancelledV1, AuthFailed, AuthSuccess, AuthenticateReq, AuthenticateV1Req, BeginAuthV1Req,
    CancelAuthV1Req, CheckCredentialReq, ClearEnrollmentsReq, ClearEnrollmentsResult,
    CommitAuthV1Req, CredentialInvalid, CredentialValid, DaemonInfo, DetectReq, DetectResult,
    DetectedFace, EnrollBatchReq, EnrollBatchResult, EnrollBatchV1Req, EnrollReq, EnrollSuccess,
    EnrollV1Req, EnrollmentMetadataEntry, EnrollmentPresenceReq, EnrollmentPresenceResult, Error,
    InfoReq, ListEnrollmentsReq, ListEnrollmentsResult, NamespaceDiagnostic, PingReq, Pong,
    PromptOriginV1, PromptPolicyContextV1, PromptRequiredV1, ReloadStorageReq, ReloadStorageResult,
    RemoveEnrollmentReq, RemoveEnrollmentResult, RevokeCredentialReq, SecurityBackendStateV1,
    SecurityInfoReq, SecurityInfoResult, SecurityPoisonStateV1, SecurityReadinessStateV1,
    ShutdownReq,
};

pub const STORAGE_CONFLICT_ERROR: &str = "storage_conflict";
pub const STORAGE_ABSENT_ERROR: &str = "storage_absent";
pub const STORAGE_CORRUPT_ERROR: &str = "storage_corrupt";
pub const STORAGE_MODEL_MISMATCH_ERROR: &str = "storage_model_mismatch";
pub const STORAGE_UNAVAILABLE_ERROR: &str = "storage_unavailable";
pub const STORAGE_INVALID_REQUEST_ERROR: &str = "storage_invalid_request";
pub const ENROLLMENT_PROTOCOL_ERROR: &str = "enrollment_protocol_incompatible";
pub const LIVE_ENROLLMENT_PROTOCOL_VERSION: u32 = 1;
pub const PROMPT_PROTOCOL_VERSION: u32 = 1;
pub const PROMPT_NONCE_BYTES: usize = 32;
pub const PROMPT_TOKEN_BYTES: usize = 32;
pub const PROMPT_IDENTITY_MAX_BYTES: usize = 64;
pub const PROMPT_TIMEOUT_MS_MIN: u32 = 1_000;
pub const PROMPT_TIMEOUT_MS_MAX: u32 = 300_000;
pub const COMMIT_RESPONSE_TIMEOUT_MS_MIN: u32 = 1_000;
pub const COMMIT_RESPONSE_TIMEOUT_MS_MAX: u32 = 120_000;
pub const PROMPT_PROTOCOL_INCOMPATIBLE_ERROR: &str = "prompt_protocol_incompatible";
pub const PROMPT_PROTOCOL_VIOLATION_ERROR: &str = "prompt_protocol_violation";
pub const PROMPT_UNAVAILABLE_ERROR: &str = "prompt_unavailable";
pub const PROMPT_TRANSACTION_INVALID_ERROR: &str = "prompt_transaction_invalid";
pub const PUBLIC_PROVIDER_MAX_BYTES: usize = 128;
pub const PUBLIC_EMBEDDING_DIM_MAX: u32 = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonInfoValidationError {
    InvalidField,
    InconsistentState,
    UnexpectedAvailability,
}

impl std::fmt::Display for DaemonInfoValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidField => "public daemon status contains an invalid bounded field",
            Self::InconsistentState => "public daemon status fields are inconsistent",
            Self::UnexpectedAvailability => {
                "public daemon status availability contradicts disabled policy"
            }
        })
    }
}

impl std::error::Error for DaemonInfoValidationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonInfoExpectation {
    pub active_security_mode: u32,
    pub prompt_required: bool,
    pub storage_ready: bool,
    pub disabled: bool,
}

pub fn validate_daemon_info_for_activation(
    info: Option<&DaemonInfo>,
    expected: DaemonInfoExpectation,
) -> Result<(), DaemonInfoValidationError> {
    use crate::config::EmbeddingSecurityMode;

    if !matches!(
        expected.active_security_mode,
        value if value == EmbeddingSecurityMode::Plaintext as u32
            || value == EmbeddingSecurityMode::AeadCached as u32
    ) || (expected.disabled && expected.storage_ready)
    {
        return Err(DaemonInfoValidationError::InconsistentState);
    }
    if expected.disabled {
        return if info.is_none() {
            Ok(())
        } else {
            Err(DaemonInfoValidationError::UnexpectedAvailability)
        };
    }
    let info = info.ok_or(DaemonInfoValidationError::UnexpectedAvailability)?;
    info.validate_strict()?;
    if info.active_security_mode != expected.active_security_mode
        || info.prompt_required != expected.prompt_required
        || info.storage_ready != expected.storage_ready
    {
        return Err(DaemonInfoValidationError::InconsistentState);
    }
    Ok(())
}

impl DaemonInfo {
    pub fn validate_strict(&self) -> Result<(), DaemonInfoValidationError> {
        use crate::config::EmbeddingSecurityMode;

        if self.provider.is_empty()
            || self.provider.len() > PUBLIC_PROVIDER_MAX_BYTES
            || !self
                .provider
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            || !self.detector_model.is_empty()
            || !self.recognizer_model.is_empty()
            || self.embedding_dim == 0
            || self.embedding_dim > PUBLIC_EMBEDDING_DIM_MAX
        {
            return Err(DaemonInfoValidationError::InvalidField);
        }
        if !matches!(
            self.active_security_mode,
            value if value == EmbeddingSecurityMode::Plaintext as u32
                || value == EmbeddingSecurityMode::AeadCached as u32
        ) {
            return Err(DaemonInfoValidationError::InconsistentState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedSecurityInfoStates {
    pub backend: SecurityBackendStateV1,
    pub readiness: SecurityReadinessStateV1,
    pub poison: SecurityPoisonStateV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityInfoValidationError {
    UnknownEnum,
    InvalidField,
    InconsistentState,
}

impl std::fmt::Display for SecurityInfoValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnknownEnum => "security status contains an unknown enum value",
            Self::InvalidField => "security status contains an invalid bounded field",
            Self::InconsistentState => "security status fields are inconsistent",
        })
    }
}

impl std::error::Error for SecurityInfoValidationError {}

impl SecurityInfoResult {
    pub fn validate_strict(
        &self,
    ) -> Result<ValidatedSecurityInfoStates, SecurityInfoValidationError> {
        use crate::config::EmbeddingSecurityMode;
        use crate::provisioning::{
            ConfiguredMode1CredentialSource, MAX_BUILD_ID_BYTES, MAX_DAEMON_VERSION_BYTES,
            MAX_PATH_BYTES, MODE1_CREDENTIAL_NAME, Mode1CredentialSourcePolicy,
        };
        use crate::storage::ALL_RECORD_NAMESPACES;

        let backend = SecurityBackendStateV1::try_from(self.backend_state)
            .map_err(|_| SecurityInfoValidationError::UnknownEnum)?;
        let readiness = SecurityReadinessStateV1::try_from(self.readiness_state)
            .map_err(|_| SecurityInfoValidationError::UnknownEnum)?;
        let poison = SecurityPoisonStateV1::try_from(self.poison_state)
            .map_err(|_| SecurityInfoValidationError::UnknownEnum)?;
        if matches!(backend, SecurityBackendStateV1::Unspecified)
            || matches!(readiness, SecurityReadinessStateV1::Unspecified)
            || matches!(poison, SecurityPoisonStateV1::Unspecified)
        {
            return Err(SecurityInfoValidationError::UnknownEnum);
        }
        let mode = match self.active_security_mode {
            value if value == EmbeddingSecurityMode::Plaintext as u32 => {
                EmbeddingSecurityMode::Plaintext
            }
            value if value == EmbeddingSecurityMode::AeadCached as u32 => {
                EmbeddingSecurityMode::AeadCached
            }
            _ => return Err(SecurityInfoValidationError::InconsistentState),
        };
        if !security_hash_is_valid(&self.config_sha256)
            || !security_hash_is_valid(&self.binary_sha256)
            || !security_hash_is_valid(&self.daemon_invocation_id)
            || !security_printable_is_valid(&self.daemon_version, MAX_DAEMON_VERSION_BYTES, false)
            || !security_printable_is_valid(&self.build_identity, MAX_BUILD_ID_BYTES, false)
            || !security_absolute_path_is_valid(&self.binary_absolute_path, MAX_PATH_BYTES)
            || !security_absolute_path_is_valid(&self.detector_model, MAX_PATH_BYTES)
            || !security_absolute_path_is_valid(&self.recognizer_model, MAX_PATH_BYTES)
        {
            return Err(SecurityInfoValidationError::InvalidField);
        }
        match mode {
            EmbeddingSecurityMode::Plaintext => {
                if !self.credential_name.is_empty()
                    || !self.configured_credential_source.is_empty()
                    || poison == SecurityPoisonStateV1::Poisoned
                {
                    return Err(SecurityInfoValidationError::InconsistentState);
                }
            }
            EmbeddingSecurityMode::AeadCached => {
                if self.credential_name != MODE1_CREDENTIAL_NAME
                    || self.key_epoch != 1
                    || ConfiguredMode1CredentialSource::parse(
                        self.configured_credential_source.as_bytes(),
                        Mode1CredentialSourcePolicy::Production,
                    )
                    .is_err()
                {
                    return Err(SecurityInfoValidationError::InconsistentState);
                }
            }
            _ => return Err(SecurityInfoValidationError::InconsistentState),
        }
        let ready = backend == SecurityBackendStateV1::Ready
            && readiness == SecurityReadinessStateV1::Ready
            && self.storage_ready;
        let unavailable = backend == SecurityBackendStateV1::Unavailable
            && readiness == SecurityReadinessStateV1::Unavailable
            && !self.storage_ready;
        if !ready && !unavailable {
            return Err(SecurityInfoValidationError::InconsistentState);
        }
        if poison == SecurityPoisonStateV1::Poisoned
            && (mode != EmbeddingSecurityMode::AeadCached || !unavailable)
        {
            return Err(SecurityInfoValidationError::InconsistentState);
        }
        if self.namespaces.len() != ALL_RECORD_NAMESPACES.len() {
            return Err(SecurityInfoValidationError::InconsistentState);
        }
        for (actual, expected) in self.namespaces.iter().zip(ALL_RECORD_NAMESPACES) {
            let expected_mode = u32::from(expected.identifier());
            if actual.mode != expected_mode
                || actual.path != expected.directory().to_string_lossy()
                || actual.active != (expected_mode == self.active_security_mode)
                || actual.implemented != matches!(expected_mode, 0 | 1)
                || !security_absolute_path_is_valid(&actual.path, MAX_PATH_BYTES)
            {
                return Err(SecurityInfoValidationError::InconsistentState);
            }
        }
        Ok(ValidatedSecurityInfoStates {
            backend,
            readiness,
            poison,
        })
    }
}

fn security_hash_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn security_printable_is_valid(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= maximum
        && value.bytes().all(|byte| matches!(byte, b' '..=b'~'))
}

fn security_absolute_path_is_valid(value: &str, maximum: usize) -> bool {
    use std::path::Component;
    let path = std::path::Path::new(value);
    !value.is_empty()
        && value.len() <= maximum
        && value.as_bytes().first() == Some(&b'/')
        && !value.ends_with('/')
        && !value.contains("//")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptErrorCode {
    Incompatible,
    Violation,
    Unavailable,
    TransactionInvalid,
}

impl PromptErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incompatible => PROMPT_PROTOCOL_INCOMPATIBLE_ERROR,
            Self::Violation => PROMPT_PROTOCOL_VIOLATION_ERROR,
            Self::Unavailable => PROMPT_UNAVAILABLE_ERROR,
            Self::TransactionInvalid => PROMPT_TRANSACTION_INVALID_ERROR,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptValidationError {
    UnsupportedVersion,
    Malformed,
}

impl PromptValidationError {
    pub const fn prompt_error(self) -> PromptErrorCode {
        match self {
            Self::UnsupportedVersion => PromptErrorCode::Incompatible,
            Self::Malformed => PromptErrorCode::Violation,
        }
    }
}

fn validate_prompt_version(version: u32) -> Result<(), PromptValidationError> {
    if version == PROMPT_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(PromptValidationError::UnsupportedVersion)
    }
}

fn validate_prompt_identity(value: &str) -> Result<(), PromptValidationError> {
    if (1..=PROMPT_IDENTITY_MAX_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(PromptValidationError::Malformed)
    }
}

fn validate_exact_bytes(value: &[u8], expected: usize) -> Result<(), PromptValidationError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(PromptValidationError::Malformed)
    }
}

pub fn prompt_origin_from_pam_rhost(rhost: Option<&str>) -> PromptOriginV1 {
    if rhost.map_or(true, str::is_empty) {
        PromptOriginV1::Local
    } else {
        PromptOriginV1::Remote
    }
}

impl BeginAuthV1Req {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_prompt_identity(&self.username)?;
        validate_exact_bytes(&self.client_nonce, PROMPT_NONCE_BYTES)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(PromptValidationError::Malformed)?;
        validate_prompt_identity(&policy.pam_service)?;
        match PromptOriginV1::try_from(policy.origin) {
            Ok(PromptOriginV1::Local | PromptOriginV1::Remote) => Ok(()),
            Ok(PromptOriginV1::Unspecified) | Err(_) => Err(PromptValidationError::Malformed),
        }
    }
}

impl AuthenticateV1Req {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_prompt_identity(&self.username)
    }
}

impl PromptRequiredV1 {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_exact_bytes(&self.transaction_token, PROMPT_TOKEN_BYTES)?;
        validate_exact_bytes(&self.client_nonce, PROMPT_NONCE_BYTES)?;
        if !(PROMPT_TIMEOUT_MS_MIN..=PROMPT_TIMEOUT_MS_MAX).contains(&self.prompt_timeout_ms)
            || !(COMMIT_RESPONSE_TIMEOUT_MS_MIN..=COMMIT_RESPONSE_TIMEOUT_MS_MAX)
                .contains(&self.commit_response_timeout_ms)
        {
            return Err(PromptValidationError::Malformed);
        }
        Ok(())
    }
}

impl CommitAuthV1Req {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_exact_bytes(&self.transaction_token, PROMPT_TOKEN_BYTES)?;
        validate_exact_bytes(&self.client_nonce, PROMPT_NONCE_BYTES)
    }
}

impl CancelAuthV1Req {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_exact_bytes(&self.transaction_token, PROMPT_TOKEN_BYTES)?;
        validate_exact_bytes(&self.client_nonce, PROMPT_NONCE_BYTES)
    }
}

impl AuthCancelledV1 {
    pub fn validate(&self) -> Result<(), PromptValidationError> {
        validate_prompt_version(self.protocol_version)?;
        validate_exact_bytes(&self.client_nonce, PROMPT_NONCE_BYTES)
    }
}

pub fn is_prompt_auth_terminal_response(response: &Response) -> bool {
    matches!(
        response.result,
        Some(RespResult::Success(_) | RespResult::AuthFailed(_) | RespResult::Error(_))
    )
}

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

    pub fn authenticate_v1(username: &str, timeout: u32) -> Self {
        Self {
            cmd: Some(Cmd::AuthenticateV1(AuthenticateV1Req {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                username: username.to_string(),
                timeout,
            })),
        }
    }

    pub fn begin_auth_v1(
        username: &str,
        client_nonce: [u8; PROMPT_NONCE_BYTES],
        pam_service: &str,
        origin: PromptOriginV1,
    ) -> Self {
        Self::begin_auth_v1_ref(username, &client_nonce, pam_service, origin)
    }

    /// Construct BeginAuthV1 from borrowed nonce storage so callers can retain
    /// the source in a zeroizing owner rather than creating another by-value
    /// nonce array.
    pub fn begin_auth_v1_ref(
        username: &str,
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
        pam_service: &str,
        origin: PromptOriginV1,
    ) -> Self {
        Self {
            cmd: Some(Cmd::BeginAuthV1(BeginAuthV1Req {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                username: username.to_string(),
                client_nonce: client_nonce.to_vec(),
                policy: Some(PromptPolicyContextV1 {
                    pam_service: pam_service.to_string(),
                    origin: origin as i32,
                }),
            })),
        }
    }

    pub fn commit_auth_v1(
        transaction_token: [u8; PROMPT_TOKEN_BYTES],
        client_nonce: [u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        Self::commit_auth_v1_ref(&transaction_token, &client_nonce)
    }

    pub fn commit_auth_v1_ref(
        transaction_token: &[u8; PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        Self {
            cmd: Some(Cmd::CommitAuthV1(CommitAuthV1Req {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                transaction_token: transaction_token.to_vec(),
                client_nonce: client_nonce.to_vec(),
            })),
        }
    }

    pub fn cancel_auth_v1(
        transaction_token: [u8; PROMPT_TOKEN_BYTES],
        client_nonce: [u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        Self::cancel_auth_v1_ref(&transaction_token, &client_nonce)
    }

    pub fn cancel_auth_v1_ref(
        transaction_token: &[u8; PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
    ) -> Self {
        Self {
            cmd: Some(Cmd::CancelAuthV1(CancelAuthV1Req {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                transaction_token: transaction_token.to_vec(),
                client_nonce: client_nonce.to_vec(),
            })),
        }
    }

    pub fn enroll(username: &str, label: &str) -> Self {
        Self {
            cmd: Some(Cmd::EnrollV1(EnrollV1Req {
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
            cmd: Some(Cmd::EnrollBatchV1(EnrollBatchV1Req {
                username: username.to_string(),
                session_dir: session_dir.to_string(),
                label: label.to_string(),
            })),
        }
    }

    pub fn enrollment_presence(username: &str) -> Self {
        Self {
            cmd: Some(Cmd::EnrollmentPresence(EnrollmentPresenceReq {
                username: username.to_string(),
            })),
        }
    }

    pub fn list_enrollments(username: &str) -> Self {
        Self {
            cmd: Some(Cmd::ListEnrollments(ListEnrollmentsReq {
                username: username.to_string(),
            })),
        }
    }

    pub fn remove_enrollment(
        username: &str,
        enrollment_id: Vec<u8>,
        expected_generation: u64,
    ) -> Self {
        Self {
            cmd: Some(Cmd::RemoveEnrollment(RemoveEnrollmentReq {
                username: username.to_string(),
                enrollment_id,
                expected_generation,
            })),
        }
    }

    pub fn clear_enrollments(username: &str, expected_generation: u64) -> Self {
        Self {
            cmd: Some(Cmd::ClearEnrollments(ClearEnrollmentsReq {
                username: username.to_string(),
                expected_generation,
            })),
        }
    }

    pub fn reload_storage() -> Self {
        Self {
            cmd: Some(Cmd::ReloadStorage(ReloadStorageReq {})),
        }
    }

    pub fn security_info() -> Self {
        Self {
            cmd: Some(Cmd::SecurityInfo(SecurityInfoReq {})),
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

    pub fn prompt_required_v1(
        transaction_token: [u8; PROMPT_TOKEN_BYTES],
        client_nonce: [u8; PROMPT_NONCE_BYTES],
        prompt_timeout_ms: u32,
        commit_response_timeout_ms: u32,
    ) -> Self {
        Self::prompt_required_v1_ref(
            &transaction_token,
            &client_nonce,
            prompt_timeout_ms,
            commit_response_timeout_ms,
        )
    }

    pub fn prompt_required_v1_ref(
        transaction_token: &[u8; PROMPT_TOKEN_BYTES],
        client_nonce: &[u8; PROMPT_NONCE_BYTES],
        prompt_timeout_ms: u32,
        commit_response_timeout_ms: u32,
    ) -> Self {
        Self {
            result: Some(RespResult::PromptRequiredV1(PromptRequiredV1 {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                transaction_token: transaction_token.to_vec(),
                client_nonce: client_nonce.to_vec(),
                prompt_timeout_ms,
                commit_response_timeout_ms,
            })),
        }
    }

    pub fn auth_cancelled_v1(client_nonce: [u8; PROMPT_NONCE_BYTES]) -> Self {
        Self::auth_cancelled_v1_ref(&client_nonce)
    }

    pub fn auth_cancelled_v1_ref(client_nonce: &[u8; PROMPT_NONCE_BYTES]) -> Self {
        Self {
            result: Some(RespResult::AuthCancelledV1(AuthCancelledV1 {
                protocol_version: PROMPT_PROTOCOL_VERSION,
                client_nonce: client_nonce.to_vec(),
            })),
        }
    }

    pub fn prompt_error(code: PromptErrorCode) -> Self {
        let message = match code {
            PromptErrorCode::Incompatible => "prompt protocol is incompatible",
            PromptErrorCode::Violation => "prompt protocol violation",
            PromptErrorCode::Unavailable => "prompt authentication is unavailable",
            PromptErrorCode::TransactionInvalid => "prompt transaction is invalid",
        };
        Self::error_code(code.as_str(), message)
    }

    pub fn enrolled(
        enrollment_id: [u8; 16],
        generation: u64,
        total_count: u32,
        det_score: f32,
    ) -> Self {
        Self {
            result: Some(RespResult::Enrolled(EnrollSuccess {
                det_score,
                enrollment_id: enrollment_id.to_vec(),
                generation,
                total_count,
                enrollment_protocol_version: LIVE_ENROLLMENT_PROTOCOL_VERSION,
            })),
        }
    }

    pub fn detected(faces: Vec<DetectedFace>, elapsed_ms: f64) -> Self {
        Self {
            result: Some(RespResult::Detected(DetectResult { faces, elapsed_ms })),
        }
    }

    pub fn pong() -> Self {
        Self {
            result: Some(RespResult::Pong(Pong {})),
        }
    }

    pub fn daemon_info(
        provider: &str,
        embedding_dim: u32,
        uptime_secs: u64,
        active_security_mode: u32,
        prompt_required: bool,
        storage_ready: bool,
    ) -> Self {
        Self {
            result: Some(RespResult::Info(DaemonInfo {
                provider: provider.to_string(),
                detector_model: String::new(),
                recognizer_model: String::new(),
                embedding_dim,
                uptime_secs,
                active_security_mode,
                prompt_required,
                storage_ready,
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
                code: String::new(),
            })),
        }
    }

    pub fn error_code(code: &str, message: &str) -> Self {
        Self {
            result: Some(RespResult::Error(Error {
                message: message.to_string(),
                code: code.to_string(),
            })),
        }
    }

    pub fn enroll_batch_done(
        frames_found: u32,
        frames_accepted: u32,
        frames_rejected: u32,
        elapsed_ms: f64,
        rejection_details: Vec<String>,
        generation: u64,
        total_count: u32,
    ) -> Self {
        Self {
            result: Some(RespResult::EnrollBatchDone(EnrollBatchResult {
                frames_found,
                frames_accepted,
                frames_rejected,
                elapsed_ms,
                rejection_details,
                generation,
                total_count,
            })),
        }
    }

    pub fn enrollment_presence(candidate: bool) -> Self {
        Self {
            result: Some(RespResult::EnrollmentPresence(EnrollmentPresenceResult {
                candidate,
            })),
        }
    }

    pub fn list_enrollments(generation: u64, entries: Vec<EnrollmentMetadataEntry>) -> Self {
        Self {
            result: Some(RespResult::ListEnrollments(ListEnrollmentsResult {
                generation,
                entries,
            })),
        }
    }

    pub fn remove_enrollment(generation: u64, removed_enrollment_id: [u8; 16]) -> Self {
        Self {
            result: Some(RespResult::RemoveEnrollment(RemoveEnrollmentResult {
                generation,
                removed_enrollment_id: removed_enrollment_id.to_vec(),
            })),
        }
    }

    pub fn clear_enrollments(generation: u64, removed_count: u32) -> Self {
        Self {
            result: Some(RespResult::ClearEnrollments(ClearEnrollmentsResult {
                generation,
                removed_count,
            })),
        }
    }

    pub fn reload_storage(result: ReloadStorageResult) -> Self {
        Self {
            result: Some(RespResult::ReloadStorage(result)),
        }
    }

    pub fn security_info(result: SecurityInfoResult) -> Self {
        Self {
            result: Some(RespResult::SecurityInfo(result)),
        }
    }
}

impl DetectedFace {
    pub fn detection(bbox: [i32; 4], landmarks: [f32; 10], score: f32) -> Self {
        Self {
            x1: bbox[0],
            y1: bbox[1],
            x2: bbox[2],
            y2: bbox[3],
            landmarks: landmarks.to_vec(),
            score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMMIT_RESPONSE_TIMEOUT_MS_MAX, COMMIT_RESPONSE_TIMEOUT_MS_MIN, Cmd, PROMPT_NONCE_BYTES,
        PROMPT_PROTOCOL_INCOMPATIBLE_ERROR, PROMPT_PROTOCOL_VERSION, PROMPT_TIMEOUT_MS_MAX,
        PROMPT_TIMEOUT_MS_MIN, PROMPT_TOKEN_BYTES, PromptErrorCode, PromptOriginV1,
        PromptValidationError, Request, RespResult, Response, is_prompt_auth_terminal_response,
        prompt_origin_from_pam_rhost,
    };
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct LegacyEnrollSuccess {
        #[prost(float, repeated, tag = "1")]
        embedding: Vec<f32>,
        #[prost(float, tag = "2")]
        det_score: f32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyEnrollReq {
        #[prost(string, tag = "1")]
        username: String,
        #[prost(string, tag = "2")]
        label: String,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyEnrollBatchReq {
        #[prost(string, tag = "1")]
        username: String,
        #[prost(string, tag = "2")]
        session_dir: String,
        #[prost(string, tag = "3")]
        label: String,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyAuthenticateReq {
        #[prost(string, tag = "1")]
        username: String,
        #[prost(uint32, tag = "2")]
        timeout: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyRequest {
        #[prost(oneof = "legacy_request::Cmd", tags = "1, 2, 9")]
        cmd: Option<legacy_request::Cmd>,
    }

    mod legacy_request {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Cmd {
            #[prost(message, tag = "1")]
            Authenticate(super::LegacyAuthenticateReq),
            #[prost(message, tag = "2")]
            Enroll(super::LegacyEnrollReq),
            #[prost(message, tag = "9")]
            EnrollBatch(super::LegacyEnrollBatchReq),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyAuthResponse {
        #[prost(oneof = "legacy_auth_response::Result", tags = "1, 2, 9")]
        result: Option<legacy_auth_response::Result>,
    }

    mod legacy_auth_response {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Result {
            #[prost(message, tag = "1")]
            Success(super::super::AuthSuccess),
            #[prost(message, tag = "2")]
            AuthFailed(super::super::AuthFailed),
            #[prost(message, tag = "9")]
            Error(super::super::Error),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyEnrollBatchResult {
        #[prost(uint32, tag = "1")]
        frames_found: u32,
        #[prost(uint32, tag = "2")]
        frames_accepted: u32,
        #[prost(uint32, tag = "3")]
        frames_rejected: u32,
        #[prost(double, tag = "4")]
        elapsed_ms: f64,
        #[prost(string, repeated, tag = "5")]
        rejection_details: Vec<String>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyDetectedFace {
        #[prost(int32, tag = "1")]
        x1: i32,
        #[prost(int32, tag = "2")]
        y1: i32,
        #[prost(int32, tag = "3")]
        x2: i32,
        #[prost(int32, tag = "4")]
        y2: i32,
        #[prost(float, repeated, tag = "5")]
        landmarks: Vec<f32>,
        #[prost(float, tag = "6")]
        score: f32,
        #[prost(float, repeated, tag = "7")]
        embedding: Vec<f32>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyDetectResult {
        #[prost(message, repeated, tag = "1")]
        faces: Vec<LegacyDetectedFace>,
        #[prost(double, tag = "2")]
        elapsed_ms: f64,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyResponse {
        #[prost(oneof = "legacy_response::Result", tags = "4")]
        result: Option<legacy_response::Result>,
    }

    mod legacy_response {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Result {
            #[prost(message, tag = "4")]
            Detected(super::LegacyDetectResult),
        }
    }

    #[test]
    fn protocol_public_daemon_info_is_redacted_and_complete() {
        let response = Response::daemon_info("cpu", 512, 42, 1, true, false);
        let Some(RespResult::Info(info)) = response.result else {
            panic!("expected daemon info response");
        };
        assert_eq!(info.provider, "cpu");
        assert_eq!(info.embedding_dim, 512);
        assert_eq!(info.uptime_secs, 42);
        assert_eq!(info.active_security_mode, 1);
        assert!(info.prompt_required);
        assert!(!info.storage_ready);
        assert!(info.detector_model.is_empty());
        assert!(info.recognizer_model.is_empty());
    }

    #[test]
    fn protocol_public_daemon_info_round_trips_new_fields() {
        let response = Response::daemon_info("migraphx", 512, 7, 2, false, true);
        let encoded = response.encode_to_vec();
        let decoded = Response::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn prompt_v1_messages_use_frozen_tags_and_golden_wire() {
        let nonce = [0x11; PROMPT_NONCE_BYTES];
        let token = [0x22; PROMPT_TOKEN_BYTES];

        let begin = Request::begin_auth_v1("a", nonce, "s", PromptOriginV1::Local);
        let mut expected_begin = vec![0x92, 0x01, 0x2e, 0x08, 0x01, 0x12, 0x01, b'a', 0x22, 0x20];
        expected_begin.extend_from_slice(&nonce);
        expected_begin.extend_from_slice(&[0x2a, 0x05, 0x0a, 0x01, b's', 0x20, 0x01]);
        assert_eq!(begin.encode_to_vec(), expected_begin);
        assert_eq!(
            Request::begin_auth_v1_ref("a", &nonce, "s", PromptOriginV1::Local).encode_to_vec(),
            expected_begin
        );

        let commit = Request::commit_auth_v1(token, nonce);
        let mut expected_commit = vec![0x9a, 0x01, 0x46, 0x08, 0x01, 0x12, 0x20];
        expected_commit.extend_from_slice(&token);
        expected_commit.extend_from_slice(&[0x1a, 0x20]);
        expected_commit.extend_from_slice(&nonce);
        assert_eq!(commit.encode_to_vec(), expected_commit);

        let cancel = Request::cancel_auth_v1(token, nonce);
        let mut expected_cancel = expected_commit.clone();
        expected_cancel[0] = 0xa2;
        assert_eq!(cancel.encode_to_vec(), expected_cancel);

        let authenticate = Request::authenticate_v1("a", 4);
        assert_eq!(
            authenticate.encode_to_vec(),
            [0xaa, 0x01, 0x07, 0x08, 0x01, 0x12, 0x01, b'a', 0x18, 0x04]
        );

        let prompt = Response::prompt_required_v1(token, nonce, 1_000, 1_000);
        let mut expected_prompt = vec![0x8a, 0x01, 0x4c, 0x08, 0x01, 0x12, 0x20];
        expected_prompt.extend_from_slice(&token);
        expected_prompt.extend_from_slice(&[0x1a, 0x20]);
        expected_prompt.extend_from_slice(&nonce);
        expected_prompt.extend_from_slice(&[0x20, 0xe8, 0x07, 0x28, 0xe8, 0x07]);
        assert_eq!(prompt.encode_to_vec(), expected_prompt);

        let cancelled = Response::auth_cancelled_v1(nonce);
        let mut expected_cancelled = vec![0x92, 0x01, 0x24, 0x08, 0x01, 0x12, 0x20];
        expected_cancelled.extend_from_slice(&nonce);
        assert_eq!(cancelled.encode_to_vec(), expected_cancelled);
    }

    #[test]
    fn prompt_v1_round_trips_and_validates_all_forms() {
        let nonce = [7; PROMPT_NONCE_BYTES];
        let token = [9; PROMPT_TOKEN_BYTES];
        for request in [
            Request::authenticate_v1("alice", 0),
            Request::begin_auth_v1("alice", nonce, "sudo", PromptOriginV1::Local),
            Request::begin_auth_v1("alice", nonce, "login", PromptOriginV1::Remote),
            Request::commit_auth_v1(token, nonce),
            Request::cancel_auth_v1(token, nonce),
        ] {
            let decoded = Request::decode(request.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, request);
            match decoded.cmd.unwrap() {
                Cmd::AuthenticateV1(message) => message.validate().unwrap(),
                Cmd::BeginAuthV1(message) => message.validate().unwrap(),
                Cmd::CommitAuthV1(message) => message.validate().unwrap(),
                Cmd::CancelAuthV1(message) => message.validate().unwrap(),
                _ => unreachable!(),
            }
        }

        for response in [
            Response::prompt_required_v1(
                token,
                nonce,
                PROMPT_TIMEOUT_MS_MAX,
                COMMIT_RESPONSE_TIMEOUT_MS_MAX,
            ),
            Response::auth_cancelled_v1(nonce),
        ] {
            let decoded = Response::decode(response.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, response);
            match decoded.result.unwrap() {
                RespResult::PromptRequiredV1(message) => message.validate().unwrap(),
                RespResult::AuthCancelledV1(message) => message.validate().unwrap(),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn prompt_v1_rejects_malformed_bounds_versions_and_origins() {
        let nonce = [3; PROMPT_NONCE_BYTES];
        let token = [4; PROMPT_TOKEN_BYTES];
        let Some(Cmd::BeginAuthV1(valid_begin)) =
            Request::begin_auth_v1("alice", nonce, "sudo", PromptOriginV1::Local).cmd
        else {
            unreachable!()
        };
        let mut malformed_begins = Vec::new();
        for username in ["", "a/b", "é", &"a".repeat(65)] {
            malformed_begins.push(super::BeginAuthV1Req {
                username: username.to_string(),
                ..valid_begin.clone()
            });
        }
        let mut missing_policy = valid_begin.clone();
        missing_policy.policy = None;
        malformed_begins.push(missing_policy);
        let mut bad_nonce = valid_begin.clone();
        bad_nonce.client_nonce.pop();
        malformed_begins.push(bad_nonce);
        for origin in [0, 3, -1] {
            let mut begin = valid_begin.clone();
            begin.policy.as_mut().unwrap().origin = origin;
            malformed_begins.push(begin);
        }
        for service in ["", "bad/service", &"s".repeat(65)] {
            let mut begin = valid_begin.clone();
            begin.policy.as_mut().unwrap().pam_service = service.to_string();
            malformed_begins.push(begin);
        }
        for malformed in malformed_begins {
            assert_eq!(malformed.validate(), Err(PromptValidationError::Malformed));
        }
        let mut wrong_version = valid_begin;
        wrong_version.protocol_version = PROMPT_PROTOCOL_VERSION + 1;
        assert_eq!(
            wrong_version.validate(),
            Err(PromptValidationError::UnsupportedVersion)
        );
        assert_eq!(
            PromptValidationError::UnsupportedVersion
                .prompt_error()
                .as_str(),
            PROMPT_PROTOCOL_INCOMPATIBLE_ERROR
        );

        let Some(Cmd::CommitAuthV1(valid_commit)) = Request::commit_auth_v1(token, nonce).cmd
        else {
            unreachable!()
        };
        let mut bad_token = valid_commit.clone();
        bad_token.transaction_token.push(0);
        assert_eq!(bad_token.validate(), Err(PromptValidationError::Malformed));
        let mut bad_nonce = valid_commit;
        bad_nonce.client_nonce.clear();
        assert_eq!(bad_nonce.validate(), Err(PromptValidationError::Malformed));

        let Some(Cmd::AuthenticateV1(valid_authenticate)) =
            Request::authenticate_v1("alice", u32::MAX).cmd
        else {
            unreachable!()
        };
        valid_authenticate.validate().unwrap();
        let mut malformed_authenticate = valid_authenticate.clone();
        malformed_authenticate.username = "bad/user".into();
        assert_eq!(
            malformed_authenticate.validate(),
            Err(PromptValidationError::Malformed)
        );
        let mut unsupported_authenticate = valid_authenticate;
        unsupported_authenticate.protocol_version += 1;
        assert_eq!(
            unsupported_authenticate.validate(),
            Err(PromptValidationError::UnsupportedVersion)
        );

        for (prompt_timeout_ms, commit_response_timeout_ms, valid) in [
            (PROMPT_TIMEOUT_MS_MIN, COMMIT_RESPONSE_TIMEOUT_MS_MIN, true),
            (PROMPT_TIMEOUT_MS_MAX, COMMIT_RESPONSE_TIMEOUT_MS_MAX, true),
            (
                PROMPT_TIMEOUT_MS_MIN - 1,
                COMMIT_RESPONSE_TIMEOUT_MS_MIN,
                false,
            ),
            (
                PROMPT_TIMEOUT_MS_MAX + 1,
                COMMIT_RESPONSE_TIMEOUT_MS_MIN,
                false,
            ),
            (
                PROMPT_TIMEOUT_MS_MIN,
                COMMIT_RESPONSE_TIMEOUT_MS_MIN - 1,
                false,
            ),
            (
                PROMPT_TIMEOUT_MS_MIN,
                COMMIT_RESPONSE_TIMEOUT_MS_MAX + 1,
                false,
            ),
        ] {
            let Some(RespResult::PromptRequiredV1(prompt)) = Response::prompt_required_v1(
                token,
                nonce,
                prompt_timeout_ms,
                commit_response_timeout_ms,
            )
            .result
            else {
                unreachable!()
            };
            assert_eq!(prompt.validate().is_ok(), valid);
        }
    }

    #[test]
    fn prompt_origin_retains_only_local_or_remote_semantics() {
        assert_eq!(prompt_origin_from_pam_rhost(None), PromptOriginV1::Local);
        assert_eq!(
            prompt_origin_from_pam_rhost(Some("")),
            PromptOriginV1::Local
        );
        assert_eq!(
            prompt_origin_from_pam_rhost(Some("host.example")),
            PromptOriginV1::Remote
        );
        let request = Request::begin_auth_v1("alice", [1; 32], "sudo", PromptOriginV1::Remote);
        let encoded = request.encode_to_vec();
        assert!(
            !encoded
                .windows(b"host.example".len())
                .any(|bytes| bytes == b"host.example")
        );
        assert!(!encoded.windows(8).any(|bytes| bytes == b"PAM_TTY"));
    }

    #[test]
    fn prompt_v1_is_unknown_to_legacy_schema_without_affecting_one_shot_auth() {
        let one_shot = Request::authenticate("alice", 4);
        let legacy = LegacyRequest::decode(one_shot.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            legacy.cmd,
            Some(legacy_request::Cmd::Authenticate(_))
        ));

        let begin = Request::begin_auth_v1("alice", [1; 32], "sudo", PromptOriginV1::Local);
        assert!(
            LegacyRequest::decode(begin.encode_to_vec().as_slice())
                .unwrap()
                .cmd
                .is_none()
        );
        let authenticate_v1 = Request::authenticate_v1("alice", 4);
        assert!(
            LegacyRequest::decode(authenticate_v1.encode_to_vec().as_slice())
                .unwrap()
                .cmd
                .is_none()
        );
        let prompt = Response::prompt_required_v1([2; 32], [1; 32], 1_000, 1_000);
        assert!(
            LegacyAuthResponse::decode(prompt.encode_to_vec().as_slice())
                .unwrap()
                .result
                .is_none()
        );
    }

    #[test]
    fn committed_prompt_final_response_set_is_exact() {
        assert!(is_prompt_auth_terminal_response(&Response::success(
            0, "desk", 0.8, 1.0
        )));
        assert!(is_prompt_auth_terminal_response(&Response::auth_failed(
            0.2, 2, "timeout"
        )));
        assert!(is_prompt_auth_terminal_response(&Response::error(
            "unavailable"
        )));
        assert!(!is_prompt_auth_terminal_response(
            &Response::credential_valid()
        ));
        assert!(!is_prompt_auth_terminal_response(
            &Response::auth_cancelled_v1([1; 32])
        ));
        assert!(!is_prompt_auth_terminal_response(&Response::pong()));
    }

    #[test]
    fn prompt_errors_use_only_frozen_generic_codes_and_messages() {
        for code in [
            PromptErrorCode::Incompatible,
            PromptErrorCode::Violation,
            PromptErrorCode::Unavailable,
            PromptErrorCode::TransactionInvalid,
        ] {
            let response = Response::prompt_error(code);
            let Some(RespResult::Error(error)) = response.result else {
                unreachable!()
            };
            assert_eq!(error.code, code.as_str());
            assert!(!error.message.contains("alice"));
            assert!(!error.message.contains("11111111"));
            assert!(!error.message.contains("22222222"));
        }
    }

    #[test]
    fn protocol_storage_requests_and_metadata_responses_round_trip() {
        let requests = [
            Request::enrollment_presence("alice"),
            Request::list_enrollments("alice"),
            Request::remove_enrollment("alice", vec![7; 16], 9),
            Request::clear_enrollments("alice", 9),
            Request::reload_storage(),
            Request::security_info(),
        ];
        for request in requests {
            let decoded = Request::decode(request.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, request);
            assert!(decoded.cmd.is_some());
        }

        let response = Response::enrolled([3; 16], 4, 5, 0.9);
        assert_eq!(
            Response::decode(response.encode_to_vec().as_slice()).unwrap(),
            response
        );
        assert!(matches!(
            Request::reload_storage().cmd,
            Some(Cmd::ReloadStorage(_))
        ));

        let responses = [
            Response::enrollment_presence(true),
            Response::list_enrollments(
                4,
                vec![super::EnrollmentMetadataEntry {
                    enrollment_id: vec![3; 16],
                    label: "desk".into(),
                    created_unix_seconds: 12,
                }],
            ),
            Response::remove_enrollment(5, [3; 16]),
            Response::clear_enrollments(0, 1),
            Response::reload_storage(super::ReloadStorageResult {
                storage_ready: true,
                candidate_records: 1,
                mode_mismatch_records: 0,
                key_mismatch_records: 0,
                model_mismatch_records: 0,
                corrupt_records: 0,
            }),
            Response::security_info(super::SecurityInfoResult {
                detector_model: "/models/det.onnx".into(),
                recognizer_model: "/models/rec.onnx".into(),
                active_security_mode: 1,
                key_epoch: 1,
                storage_ready: true,
                prompt_required: false,
                namespaces: vec![
                    super::NamespaceDiagnostic {
                        mode: 0,
                        path: "/etc/howy/models".into(),
                        active: false,
                        implemented: true,
                    },
                    super::NamespaceDiagnostic {
                        mode: 1,
                        path: "/etc/howy/models/mode1".into(),
                        active: true,
                        implemented: true,
                    },
                    super::NamespaceDiagnostic {
                        mode: 2,
                        path: "/etc/howy/models/mode2".into(),
                        active: false,
                        implemented: false,
                    },
                ],
                config_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                credential_name: "howy.storage.mode1.epoch1".into(),
                configured_credential_source: "/etc/credstore.encrypted/howy.storage.mode1.epoch1"
                    .into(),
                backend_state: super::SecurityBackendStateV1::Ready as i32,
                readiness_state: super::SecurityReadinessStateV1::Ready as i32,
                poison_state: super::SecurityPoisonStateV1::NotPoisoned as i32,
                daemon_invocation_id:
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
                daemon_version: "0.1.0".into(),
                build_identity: "howy-0.1.0+test".into(),
                binary_absolute_path: "/usr/bin/howyd".into(),
                binary_sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                    .into(),
            }),
        ];
        for response in responses {
            assert_eq!(
                Response::decode(response.encode_to_vec().as_slice()).unwrap(),
                response
            );
        }
    }

    fn valid_security_info() -> super::SecurityInfoResult {
        super::SecurityInfoResult {
            detector_model: "/models/det.onnx".into(),
            recognizer_model: "/models/rec.onnx".into(),
            active_security_mode: 1,
            key_epoch: 1,
            storage_ready: true,
            prompt_required: false,
            namespaces: vec![
                super::NamespaceDiagnostic {
                    mode: 0,
                    path: "/etc/howy/models".into(),
                    active: false,
                    implemented: true,
                },
                super::NamespaceDiagnostic {
                    mode: 1,
                    path: "/etc/howy/models/mode1".into(),
                    active: true,
                    implemented: true,
                },
                super::NamespaceDiagnostic {
                    mode: 2,
                    path: "/etc/howy/models/mode2".into(),
                    active: false,
                    implemented: false,
                },
            ],
            config_sha256: "01".repeat(32),
            credential_name: "howy.storage.mode1.epoch1".into(),
            configured_credential_source: "/etc/credstore.encrypted/howy.storage.mode1.epoch1"
                .into(),
            backend_state: super::SecurityBackendStateV1::Ready as i32,
            readiness_state: super::SecurityReadinessStateV1::Ready as i32,
            poison_state: super::SecurityPoisonStateV1::NotPoisoned as i32,
            daemon_invocation_id: "23".repeat(32),
            daemon_version: "0.1.0".into(),
            build_identity: "howy-0.1.0+test".into(),
            binary_absolute_path: "/usr/bin/howyd".into(),
            binary_sha256: "45".repeat(32),
        }
    }

    #[test]
    fn security_status_validator_rejects_malicious_protobuf_vectors() {
        let valid = valid_security_info();
        let decoded = super::SecurityInfoResult::decode(valid.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            decoded.validate_strict().unwrap().backend,
            super::SecurityBackendStateV1::Ready
        );

        let mut malicious = Vec::new();
        for value in [0, 99] {
            let mut item = valid.clone();
            item.backend_state = value;
            malicious.push(item);
            let mut item = valid.clone();
            item.readiness_state = value;
            malicious.push(item);
            let mut item = valid.clone();
            item.poison_state = value;
            malicious.push(item);
        }
        let mut item = valid.clone();
        item.config_sha256 = "A".repeat(64);
        malicious.push(item);
        let mut item = valid.clone();
        item.binary_sha256 = "0".repeat(63);
        malicious.push(item);
        let mut item = valid.clone();
        item.daemon_invocation_id = "g".repeat(64);
        malicious.push(item);
        let mut item = valid.clone();
        item.daemon_version = "v".repeat(crate::provisioning::MAX_DAEMON_VERSION_BYTES + 1);
        malicious.push(item);
        let mut item = valid.clone();
        item.build_identity = "bad\nidentity".into();
        malicious.push(item);
        let mut item = valid.clone();
        item.binary_absolute_path = "relative/howyd".into();
        malicious.push(item);
        let mut item = valid.clone();
        item.detector_model = "/models/../secret".into();
        malicious.push(item);
        let mut item = valid.clone();
        item.configured_credential_source = "/etc/credstore.encrypted/other\n".into();
        malicious.push(item);
        let mut item = valid.clone();
        item.credential_name.clear();
        malicious.push(item);
        let mut item = valid.clone();
        item.active_security_mode = 0;
        item.namespaces[0].active = true;
        item.namespaces[1].active = false;
        malicious.push(item);
        let mut item = valid.clone();
        item.storage_ready = false;
        malicious.push(item);
        let mut item = valid.clone();
        item.poison_state = super::SecurityPoisonStateV1::Poisoned as i32;
        malicious.push(item);
        let mut item = valid.clone();
        item.namespaces.swap(0, 1);
        malicious.push(item);

        for malicious in malicious {
            let decoded =
                super::SecurityInfoResult::decode(malicious.encode_to_vec().as_slice()).unwrap();
            assert!(decoded.validate_strict().is_err(), "accepted {decoded:?}");
        }
    }

    #[test]
    fn public_daemon_status_is_strict_bounded_and_path_redacted() {
        let valid = super::DaemonInfo {
            provider: "CPUExecutionProvider".into(),
            detector_model: String::new(),
            recognizer_model: String::new(),
            embedding_dim: 512,
            uptime_secs: 10,
            active_security_mode: 1,
            prompt_required: true,
            storage_ready: true,
        };
        valid.validate_strict().unwrap();

        let mut malformed = Vec::new();
        let mut item = valid.clone();
        item.provider = "bad\nprovider".into();
        malformed.push(item);
        let mut item = valid.clone();
        item.provider = "x".repeat(super::PUBLIC_PROVIDER_MAX_BYTES + 1);
        malformed.push(item);
        let mut item = valid.clone();
        item.detector_model = "/secret/model.onnx".into();
        malformed.push(item);
        let mut item = valid.clone();
        item.embedding_dim = 0;
        malformed.push(item);
        let mut item = valid.clone();
        item.embedding_dim = super::PUBLIC_EMBEDDING_DIM_MAX + 1;
        malformed.push(item);
        let mut item = valid;
        item.active_security_mode = 2;
        malformed.push(item);

        for item in malformed {
            assert!(item.validate_strict().is_err(), "accepted {item:?}");
        }
    }

    #[test]
    fn public_activation_status_binds_policy_and_disabled_availability() {
        let valid = super::DaemonInfo {
            provider: "CPUExecutionProvider".into(),
            detector_model: String::new(),
            recognizer_model: String::new(),
            embedding_dim: 512,
            uptime_secs: 10,
            active_security_mode: 1,
            prompt_required: true,
            storage_ready: true,
        };
        let enabled = super::DaemonInfoExpectation {
            active_security_mode: 1,
            prompt_required: true,
            storage_ready: true,
            disabled: false,
        };
        super::validate_daemon_info_for_activation(Some(&valid), enabled).unwrap();
        assert!(super::validate_daemon_info_for_activation(None, enabled).is_err());

        for mutation in ["mode", "prompt", "ready", "malformed"] {
            let mut item = valid.clone();
            match mutation {
                "mode" => item.active_security_mode = 0,
                "prompt" => item.prompt_required = false,
                "ready" => item.storage_ready = false,
                "malformed" => item.provider = "bad\nprovider".into(),
                _ => unreachable!(),
            }
            assert!(super::validate_daemon_info_for_activation(Some(&item), enabled).is_err());
        }

        let disabled = super::DaemonInfoExpectation {
            active_security_mode: 1,
            prompt_required: true,
            storage_ready: false,
            disabled: true,
        };
        super::validate_daemon_info_for_activation(None, disabled).unwrap();
        assert!(super::validate_daemon_info_for_activation(Some(&valid), disabled).is_err());
        let mut impossible = disabled;
        impossible.storage_ready = true;
        assert!(super::validate_daemon_info_for_activation(None, impossible).is_err());
    }

    #[test]
    fn legacy_enrollment_embedding_tag_is_ignored_and_never_reused() {
        let legacy = LegacyEnrollSuccess {
            embedding: vec![0.25, 0.5],
            det_score: 0.75,
        };
        let decoded = super::EnrollSuccess::decode(legacy.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded.det_score, 0.75);
        assert!(decoded.enrollment_id.is_empty());
        assert_eq!(decoded.generation, 0);
        assert_eq!(decoded.total_count, 0);
        assert_eq!(decoded.enrollment_protocol_version, 0);

        let legacy_batch = LegacyEnrollBatchResult {
            frames_found: 2,
            frames_accepted: 1,
            frames_rejected: 1,
            elapsed_ms: 3.5,
            rejection_details: vec!["one".into()],
        };
        let decoded_batch =
            super::EnrollBatchResult::decode(legacy_batch.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded_batch.frames_accepted, 1);
        assert_eq!(decoded_batch.generation, 0);
        assert_eq!(decoded_batch.total_count, 0);
    }

    #[test]
    fn enrollment_operation_tags_are_side_effect_free_across_version_directions() {
        let legacy_live = LegacyRequest {
            cmd: Some(legacy_request::Cmd::Enroll(LegacyEnrollReq {
                username: "alice".into(),
                label: "desk".into(),
            })),
        };
        let decoded = Request::decode(legacy_live.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(decoded.cmd, Some(Cmd::Enroll(_))));

        let legacy_batch = LegacyRequest {
            cmd: Some(legacy_request::Cmd::EnrollBatch(LegacyEnrollBatchReq {
                username: "alice".into(),
                session_dir: "/session".into(),
                label: "desk".into(),
            })),
        };
        let decoded = Request::decode(legacy_batch.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(decoded.cmd, Some(Cmd::EnrollBatch(_))));

        let current_live = Request::enroll("alice", "desk");
        assert!(matches!(current_live.cmd, Some(Cmd::EnrollV1(_))));
        assert_eq!(
            Request::decode(current_live.encode_to_vec().as_slice()).unwrap(),
            current_live
        );
        let legacy_view = LegacyRequest::decode(current_live.encode_to_vec().as_slice()).unwrap();
        assert!(legacy_view.cmd.is_none());

        let current_batch = Request::enroll_batch("alice", "/session", "desk");
        assert!(matches!(current_batch.cmd, Some(Cmd::EnrollBatchV1(_))));
        assert_eq!(
            Request::decode(current_batch.encode_to_vec().as_slice()).unwrap(),
            current_batch
        );
        let legacy_view = LegacyRequest::decode(current_batch.encode_to_vec().as_slice()).unwrap();
        assert!(legacy_view.cmd.is_none());

        let current_response = Response::enrolled([7; 16], 3, 4, 0.9);
        let Some(RespResult::Enrolled(current_response)) = current_response.result else {
            panic!("expected enrollment response");
        };
        assert_eq!(
            current_response.enrollment_protocol_version,
            super::LIVE_ENROLLMENT_PROTOCOL_VERSION
        );
        let legacy_view =
            LegacyEnrollSuccess::decode(current_response.encode_to_vec().as_slice()).unwrap();
        assert!(legacy_view.embedding.is_empty());
        assert_eq!(legacy_view.det_score, 0.9);
    }

    #[test]
    fn legacy_detected_face_embedding_tag_is_ignored_and_not_reemitted() {
        let legacy = LegacyDetectedFace {
            x1: 11,
            y1: 12,
            x2: 31,
            y2: 42,
            landmarks: (0..10).map(|value| value as f32 + 0.5).collect(),
            score: 0.875,
            embedding: vec![0.25, -0.5, 0.75],
        };

        let decoded = super::DetectedFace::decode(legacy.encode_to_vec().as_slice()).unwrap();
        assert_eq!(
            (decoded.x1, decoded.y1, decoded.x2, decoded.y2),
            (11, 12, 31, 42)
        );
        assert_eq!(decoded.landmarks, legacy.landmarks);
        assert_eq!(decoded.score, legacy.score);

        let legacy_view = LegacyDetectedFace::decode(decoded.encode_to_vec().as_slice()).unwrap();
        assert!(legacy_view.embedding.is_empty());
        assert_eq!(legacy_view.landmarks, legacy.landmarks);
        assert_eq!(legacy_view.score, legacy.score);
    }

    #[test]
    fn detect_response_constructor_emits_detection_metadata_without_tag_7() {
        let face = super::DetectedFace::detection(
            [3, 5, 17, 19],
            [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],
            0.625,
        );
        let response = Response::detected(vec![face], 4.25);
        let response_bytes = response.encode_to_vec();
        let decoded = Response::decode(response_bytes.as_slice()).unwrap();
        let Some(RespResult::Detected(result)) = decoded.result else {
            panic!("expected detect response");
        };
        assert_eq!(result.elapsed_ms, 4.25);
        assert_eq!(result.faces.len(), 1);

        let legacy_response = LegacyResponse::decode(response_bytes.as_slice()).unwrap();
        let Some(legacy_response::Result::Detected(legacy_result)) = legacy_response.result else {
            panic!("expected legacy detect response view");
        };
        assert_eq!(legacy_result.elapsed_ms, 4.25);
        assert_eq!(legacy_result.faces.len(), 1);
        let legacy_face = &legacy_result.faces[0];
        assert!(legacy_face.embedding.is_empty());
        assert_eq!((legacy_face.x1, legacy_face.y1), (3, 5));
        assert_eq!((legacy_face.x2, legacy_face.y2), (17, 19));
        assert_eq!(legacy_face.landmarks.len(), 10);
        assert_eq!(legacy_face.score, 0.625);
    }
}
