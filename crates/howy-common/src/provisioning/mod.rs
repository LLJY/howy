//! Pure provisioning-v1 schemas, parsers, fingerprints, and state classifiers.
//!
//! This module deliberately performs no filesystem access, process execution,
//! or systemd calls. Side-effecting provisioning code must collect exact live
//! observations and pass them through these contracts before acting.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Component, Path};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::HowyConfig;

pub const PROVISIONING_SCHEMA_VERSION: u16 = 1;
pub const MODE1_KEY_EPOCH: u64 = 1;
pub const MODE1_CREDENTIAL_NAME: &str = "howy.storage.mode1.epoch1";
pub const MODE1_CREDENTIAL_PATH: &str = "/etc/credstore.encrypted/howy.storage.mode1.epoch1";
pub const MODE1_CREDENTIAL_SOURCE_COMPANION_NAME: &str = "howy.storage.mode1.source";
pub const MODE1_CREDENTIAL_DIRECTORY: &str = "/etc/credstore.encrypted";
pub const MODE1_NAMESPACE_PATH: &str = "/etc/howy/models/mode1";
pub const SYSTEMD_CREDENTIAL_PLAINTEXT_BYTES: u64 = 32;
pub const MAX_MODE1_CREDENTIAL_SOURCE_BYTES: usize = MAX_PATH_BYTES;

pub const MAX_CONFIG_BYTES: usize = 1_048_576;
pub const MAX_DROPIN_BYTES: usize = 65_536;
pub const MAX_JOURNAL_BYTES: usize = 4_500_000;
pub const MAX_RECEIPT_BYTES: usize = 131_072;
pub const MAX_TRANSACTION_ID_BYTES: usize = 64;
pub const MAX_PATH_BYTES: usize = 4_096;
pub const MAX_BUILD_ID_BYTES: usize = 256;
pub const MAX_DAEMON_VERSION_BYTES: usize = 128;
pub const MAX_VERIFIER_RESULT_BYTES: usize = 16_384;
pub const MAX_TRANSACTION_OWNED_PATHS: usize = 32;
pub const MAX_NAMESPACE_ENTRIES: usize = 1_000;
pub const MAX_NAMESPACE_NAME_BYTES: usize = 255;
pub const MAX_NAMESPACE_CIPHERTEXT_BYTES: u64 = 2_621_440;
pub const MAX_NAMESPACE_TOTAL_BYTES: u64 = 1_073_741_824;

/// Root-only provisioning state paths shared by the CLI transaction engine.
pub const HOWY_CONFIG_DIRECTORY: &str = "/etc/howy";
pub const HOWY_MODELS_DIRECTORY: &str = "/etc/howy/models";
pub const SYSTEMD_SERVICE_DROPIN_DIRECTORY: &str = "/etc/systemd/system/howy.service.d";
pub const HOWY_STATE_DIRECTORY: &str = "/var/lib/howy";
pub const SECURITY_STATE_DIRECTORY: &str = "/var/lib/howy/security-state";
pub const SECURITY_JOURNAL_DIRECTORY: &str = "/var/lib";
pub const SECURITY_LOCK_PATH: &str = "/run/lock/howy-security.lock";
pub const SECURITY_JOURNAL_PATH: &str = "/var/lib/howy-security-transaction-v1.json";
pub const SECURITY_RECEIPT_PATH: &str = "/var/lib/howy/security-state/receipt-v1.json";
pub const SECURITY_UNADOPTED_DIRECTORY: &str = "/var/lib/howy/security-state/unadopted";
pub const SECURITY_TRANSACTION_GUARD_PATH: &str = "/var/lib/howy-security-transaction.guard";
pub const PACKAGE_BOOTSTRAP_MARKER_PATH: &str = "/var/lib/howy-package-bootstrap.complete";
pub const MODE1_DROPIN_PATH: &str =
    "/etc/systemd/system/howy.service.d/60-howy-mode1-credential.conf";
pub const BASE_SERVICE_UNIT_PATH: &str = "/usr/lib/systemd/system/howy.service";
pub const BASE_SOCKET_UNIT_PATH: &str = "/usr/lib/systemd/system/howy.socket";
pub const SYSTEMD_HOST_SECRET_PATH: &str = "/var/lib/systemd/credential.secret";

pub const REQUIRED_SECURITY_DIRECTORIES: [(&str, u32); 8] = [
    (HOWY_CONFIG_DIRECTORY, 0o700),
    (HOWY_MODELS_DIRECTORY, 0o700),
    (MODE1_NAMESPACE_PATH, 0o700),
    (MODE1_CREDENTIAL_DIRECTORY, 0o700),
    (SYSTEMD_SERVICE_DROPIN_DIRECTORY, 0o755),
    (HOWY_STATE_DIRECTORY, 0o700),
    (SECURITY_STATE_DIRECTORY, 0o700),
    (SECURITY_UNADOPTED_DIRECTORY, 0o700),
];

// systemd v261 creds-util.h: 1 MiB plaintext plus 128 KiB envelope overhead.
pub const SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX: usize = 1_048_576 + 131_072;
// 79-column base64 plus line endings, with a small final-line allowance.
pub const SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX: usize =
    (SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX.div_ceil(3) * 4)
        + 2 * (SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX.div_ceil(3) * 4).div_ceil(79)
        + 2;

const SHA256_HEX_BYTES: usize = 64;
const SYSTEMD_MAIN_HEADER_BYTES: usize = 32;
const SYSTEMD_TPM_HEADER_BYTES: usize = 20;
const SYSTEMD_METADATA_HEADER_BYTES: usize = 20;
const SYSTEMD_AES_KEY_BYTES: u32 = 32;
// EVP_aes_256_gcm() reports a one-byte block size in systemd's v261 format.
const SYSTEMD_AES_BLOCK_BYTES: u32 = 1;
const SYSTEMD_AES_IV_BYTES: u32 = 12;
const SYSTEMD_AES_TAG_BYTES: u32 = 16;
const SYSTEMD_FIELD_SIZE_MAX: usize = 16 * 1024;
const NAMESPACE_DOMAIN: &[u8] = b"HOWNAMESPACE-v1\0";
const FILE_METADATA_DOMAIN: &[u8] = b"HOWFILEMETADATA-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProvisioningContractError {
    #[error("provisioning input exceeds the {0} limit")]
    LimitExceeded(&'static str),
    #[error("invalid provisioning JSON")]
    InvalidJson,
    #[error("invalid provisioning schema: {0}")]
    InvalidSchema(&'static str),
    #[error("invalid provisioning transition")]
    InvalidTransition,
    #[error("invalid provisioning TOML")]
    InvalidToml,
    #[error("configuration does not contain one exact active [core] disabled = true literal")]
    MissingDisabledLiteral,
    #[error("configuration contains an unsupported or ambiguous disabled-token layout")]
    AmbiguousDisabledLiteral,
    #[error("configuration is not valid UTF-8 or uses unsupported CR line endings")]
    InvalidConfigEncoding,
    #[error("invalid systemd encrypted credential envelope")]
    InvalidCredentialEnvelope,
    #[error("systemd encrypted credential policy is not admissible")]
    CredentialPolicyRejected,
    #[error("namespace inventory is not canonical")]
    InvalidNamespaceInventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode1CredentialSourcePolicy {
    Production,
    ReadinessCandidate,
}

/// Exact nonsecret encrypted-credential source asserted by a separate systemd
/// credential companion. This identifies configured unit input; it does not
/// claim that the daemon parsed or authenticated the encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfiguredMode1CredentialSource(String);

impl ConfiguredMode1CredentialSource {
    pub fn parse(
        bytes: &[u8],
        policy: Mode1CredentialSourcePolicy,
    ) -> Result<Self, ProvisioningContractError> {
        if bytes.is_empty()
            || bytes.len() > MAX_MODE1_CREDENTIAL_SOURCE_BYTES
            || !bytes.iter().all(u8::is_ascii)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "mode 1 credential source companion",
            ));
        }
        let source = std::str::from_utf8(bytes).map_err(|_| {
            ProvisioningContractError::InvalidSchema("mode 1 credential source companion")
        })?;
        validate_mode1_credential_source_path(source, policy)?;
        Ok(Self(source.to_owned()))
    }

    pub fn production() -> Self {
        Self(MODE1_CREDENTIAL_PATH.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(
        &self,
        policy: Mode1CredentialSourcePolicy,
    ) -> Result<(), ProvisioningContractError> {
        Self::parse(self.0.as_bytes(), policy).map(|_| ())
    }
}

fn validate_mode1_credential_source_path(
    source: &str,
    policy: Mode1CredentialSourcePolicy,
) -> Result<(), ProvisioningContractError> {
    if source.ends_with('/') {
        return Err(ProvisioningContractError::InvalidSchema(
            "mode 1 credential source",
        ));
    }
    validate_absolute_path(source, "mode 1 credential source")?;
    let path = Path::new(source);
    if path.parent() != Some(Path::new(MODE1_CREDENTIAL_DIRECTORY)) {
        return Err(ProvisioningContractError::InvalidSchema(
            "mode 1 credential source directory",
        ));
    }
    let name = path.file_name().and_then(|value| value.to_str()).ok_or(
        ProvisioningContractError::InvalidSchema("mode 1 credential source name"),
    )?;
    if name.is_empty()
        || name.len() > MAX_NAMESPACE_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "mode 1 credential source name",
        ));
    }
    if policy == Mode1CredentialSourcePolicy::Production && source != MODE1_CREDENTIAL_PATH {
        return Err(ProvisioningContractError::InvalidSchema(
            "production mode 1 credential source",
        ));
    }
    Ok(())
}

/// A SHA-256 value serialized as exactly 64 lowercase hexadecimal bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex_encode(&digest))
    }

    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(hex_encode(&bytes))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ProvisioningContractError> {
        let value = value.into();
        if is_lower_hex(&value, SHA256_HEX_BYTES) {
            Ok(Self(value))
        } else {
            Err(ProvisioningContractError::InvalidSchema("sha256"))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if is_lower_hex(&self.0, SHA256_HEX_BYTES) {
            Ok(())
        } else {
            Err(ProvisioningContractError::InvalidSchema("sha256"))
        }
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Exact non-secret bytes represented canonically as lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExactBytes(String);

impl ExactBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(bytes))
    }

    pub fn decode(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        hex_decode(&self.0)
    }

    pub fn byte_len(&self) -> usize {
        self.0.len() / 2
    }

    fn validate_max(
        &self,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), ProvisioningContractError> {
        if !self.0.len().is_multiple_of(2) || !is_lower_hex(&self.0, self.0.len()) {
            return Err(ProvisioningContractError::InvalidSchema(field));
        }
        if self.byte_len() > maximum {
            return Err(ProvisioningContractError::LimitExceeded(field));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ExactBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if !value.len().is_multiple_of(2) || !is_lower_hex(&value, value.len()) {
            return Err(serde::de::Error::custom("invalid canonical byte string"));
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JournalPhase {
    Prepared,
    Guarded,
    UnitsStopped,
    ArtifactCommitted,
    DropinCommitted,
    DisabledConfigCommitted,
    ReadinessVerified,
    DisabledReceiptCommitted,
    DisabledUnitsStarted,
    EnabledConfigCommitted,
    ActivationCommitted,
    UnitsStarted,
    EnabledReceiptCommitted,
}

impl JournalPhase {
    pub const ALL: [Self; 13] = [
        Self::Prepared,
        Self::Guarded,
        Self::UnitsStopped,
        Self::ArtifactCommitted,
        Self::DropinCommitted,
        Self::DisabledConfigCommitted,
        Self::ReadinessVerified,
        Self::DisabledReceiptCommitted,
        Self::DisabledUnitsStarted,
        Self::EnabledConfigCommitted,
        Self::ActivationCommitted,
        Self::UnitsStarted,
        Self::EnabledReceiptCommitted,
    ];

    pub const fn ordinal(self) -> usize {
        match self {
            Self::Prepared => 0,
            Self::Guarded => 1,
            Self::UnitsStopped => 2,
            Self::ArtifactCommitted => 3,
            Self::DropinCommitted => 4,
            Self::DisabledConfigCommitted => 5,
            Self::ReadinessVerified => 6,
            Self::DisabledReceiptCommitted => 7,
            Self::DisabledUnitsStarted => 8,
            Self::EnabledConfigCommitted => 9,
            Self::ActivationCommitted => 10,
            Self::UnitsStarted => 11,
            Self::EnabledReceiptCommitted => 12,
        }
    }

    pub const fn next(self) -> Option<Self> {
        let next = self.ordinal() + 1;
        if next < Self::ALL.len() {
            Some(Self::ALL[next])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryAction {
    RestorePriorState,
    CompleteDisabledProvisioning,
    RestoreDisabledState,
    CompleteEnabledActivation,
}

/// Mode 0 has no key artifact or Mode-1 receipt, but still uses a strict,
/// durable journal and the same persistent start guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlaintextJournalPhase {
    Prepared,
    Guarded,
    UnitsStopped,
    DropinRemoved,
    EnabledConfigCommitted,
    ActivationCommitted,
    UnitsStarted,
}

impl PlaintextJournalPhase {
    pub const ALL: [Self; 7] = [
        Self::Prepared,
        Self::Guarded,
        Self::UnitsStopped,
        Self::DropinRemoved,
        Self::EnabledConfigCommitted,
        Self::ActivationCommitted,
        Self::UnitsStarted,
    ];

    pub const fn ordinal(self) -> usize {
        match self {
            Self::Prepared => 0,
            Self::Guarded => 1,
            Self::UnitsStopped => 2,
            Self::DropinRemoved => 3,
            Self::EnabledConfigCommitted => 4,
            Self::ActivationCommitted => 5,
            Self::UnitsStarted => 6,
        }
    }

    pub const fn next(self) -> Option<Self> {
        let next = self.ordinal() + 1;
        if next < Self::ALL.len() {
            Some(Self::ALL[next])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlaintextRecoveryAction {
    RestorePriorState,
    CompleteActivation,
}

pub const fn plaintext_recovery_action_for_phase(
    phase: PlaintextJournalPhase,
) -> PlaintextRecoveryAction {
    match phase {
        PlaintextJournalPhase::Prepared
        | PlaintextJournalPhase::Guarded
        | PlaintextJournalPhase::UnitsStopped
        | PlaintextJournalPhase::DropinRemoved
        | PlaintextJournalPhase::EnabledConfigCommitted => {
            PlaintextRecoveryAction::RestorePriorState
        }
        PlaintextJournalPhase::ActivationCommitted | PlaintextJournalPhase::UnitsStarted => {
            PlaintextRecoveryAction::CompleteActivation
        }
    }
}

pub const fn recovery_action_for_phase(phase: JournalPhase) -> RecoveryAction {
    match phase {
        JournalPhase::Prepared
        | JournalPhase::Guarded
        | JournalPhase::UnitsStopped
        | JournalPhase::ArtifactCommitted
        | JournalPhase::DropinCommitted
        | JournalPhase::DisabledConfigCommitted
        | JournalPhase::ReadinessVerified => RecoveryAction::RestorePriorState,
        JournalPhase::DisabledReceiptCommitted | JournalPhase::DisabledUnitsStarted => {
            RecoveryAction::CompleteDisabledProvisioning
        }
        JournalPhase::EnabledConfigCommitted => RecoveryAction::RestoreDisabledState,
        JournalPhase::ActivationCommitted
        | JournalPhase::UnitsStarted
        | JournalPhase::EnabledReceiptCommitted => RecoveryAction::CompleteEnabledActivation,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitLoadState {
    Loaded,
    NotFound,
    Error,
    BadSetting,
    Masked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitActiveState {
    Active,
    Inactive,
    Activating,
    Deactivating,
    Reloading,
    Failed,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitSubState {
    Running,
    Dead,
    Failed,
    StartPre,
    Start,
    StartPost,
    Stop,
    StopSigterm,
    StopSigkill,
    StopPost,
    Reload,
    AutoRestart,
    Listening,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitFileState {
    Enabled,
    EnabledRuntime,
    Linked,
    LinkedRuntime,
    Alias,
    Masked,
    MaskedRuntime,
    Static,
    Disabled,
    Indirect,
    Generated,
    Transient,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitKind {
    Service,
    Socket,
}

impl UnitFileState {
    pub const fn is_masked(self) -> bool {
        matches!(self, Self::Masked | Self::MaskedRuntime)
    }

    pub const fn is_admissible(self) -> bool {
        !self.is_masked() && !matches!(self, Self::Bad)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableUnitState {
    pub unit_kind: UnitKind,
    pub load_state: UnitLoadState,
    pub active_state: UnitActiveState,
    pub sub_state: UnitSubState,
    pub unit_file_state: UnitFileState,
}

/// Durable create intent and exact observation for one required provisioning
/// directory. The intent (including the no-follow parent identity and whether
/// the target was absent) is persisted before `mkdirat(2)` is permitted.
/// `observed_directory` is persisted immediately after creation/reconciliation
/// and is the rollback identity. Only absent-at-intent entries may be removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityDirectoryRecordV1 {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub parent_directory: DirectoryIdentityV1,
    pub expected_directory: Option<DirectoryIdentityV1>,
    pub observed_directory: Option<DirectoryIdentityV1>,
    pub preexisted: bool,
}

impl SecurityDirectoryRecordV1 {
    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        let Some((_, required_mode)) = REQUIRED_SECURITY_DIRECTORIES
            .iter()
            .find(|(path, _)| *path == self.path)
        else {
            return Err(ProvisioningContractError::InvalidSchema(
                "security directory path",
            ));
        };
        let expected_parent = Path::new(&self.path)
            .parent()
            .and_then(Path::to_str)
            .ok_or(ProvisioningContractError::InvalidSchema(
                "security directory parent",
            ))?;
        if self.uid != 0
            || self.gid != 0
            || self.permissions != *required_mode
            || self.parent_directory.path != expected_parent
            || self.parent_directory.object_type != FileObjectType::Directory
            || self.parent_directory.uid != 0
            || self.parent_directory.gid != 0
            || self.parent_directory.permissions & 0o022 != 0
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "security directory metadata",
            ));
        }
        self.parent_directory.validate_shape()?;
        if self.preexisted != self.expected_directory.is_some() {
            return Err(ProvisioningContractError::InvalidSchema(
                "security directory preexistence",
            ));
        }
        if let Some(expected) = &self.expected_directory {
            validate_security_directory_identity(self, expected)?;
        }
        if let Some(observed) = &self.observed_directory {
            validate_security_directory_identity(self, observed)?;
            if let Some(expected) = &self.expected_directory
                && expected != observed
            {
                return Err(ProvisioningContractError::InvalidSchema(
                    "preexisting security directory changed",
                ));
            }
        }
        Ok(())
    }
}

fn validate_security_directory_identity(
    record: &SecurityDirectoryRecordV1,
    identity: &DirectoryIdentityV1,
) -> Result<(), ProvisioningContractError> {
    identity.validate_shape()?;
    if identity.path != record.path
        || identity.object_type != FileObjectType::Directory
        || identity.uid != record.uid
        || identity.gid != record.gid
        || identity.permissions != record.permissions
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "security directory identity",
        ));
    }
    Ok(())
}

pub fn validate_security_directory_record_prefix(
    records: &[SecurityDirectoryRecordV1],
) -> Result<(), ProvisioningContractError> {
    if records.len() > REQUIRED_SECURITY_DIRECTORIES.len() {
        return Err(ProvisioningContractError::InvalidSchema(
            "security directory count",
        ));
    }
    for ((required_path, _), record) in REQUIRED_SECURITY_DIRECTORIES.iter().zip(records) {
        record.validate()?;
        if record.path != *required_path {
            return Err(ProvisioningContractError::InvalidSchema(
                "security directory order",
            ));
        }
    }
    Ok(())
}

pub fn validate_security_directory_records(
    records: &[SecurityDirectoryRecordV1],
) -> Result<(), ProvisioningContractError> {
    if records.len() != REQUIRED_SECURITY_DIRECTORIES.len() {
        return Err(ProvisioningContractError::InvalidSchema(
            "security directory count",
        ));
    }
    validate_security_directory_record_prefix(records)?;
    if records
        .iter()
        .any(|record| record.observed_directory.is_none())
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "unobserved security directory",
        ));
    }
    Ok(())
}

impl StableUnitState {
    pub const fn rollback_target(&self) -> Option<StableRollbackTarget> {
        match (self.unit_kind, self.active_state, self.sub_state) {
            (UnitKind::Service, UnitActiveState::Active, UnitSubState::Running) => {
                Some(StableRollbackTarget::ActiveRunning)
            }
            (UnitKind::Socket, UnitActiveState::Active, UnitSubState::Listening) => {
                Some(StableRollbackTarget::ActiveListening)
            }
            (_, UnitActiveState::Inactive, UnitSubState::Dead) => {
                Some(StableRollbackTarget::InactiveDead)
            }
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.load_state != UnitLoadState::Loaded
            || !self.unit_file_state.is_admissible()
            || self.rollback_target().is_none()
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "stable unit state",
            ));
        }
        Ok(())
    }
}

pub fn disabled_post_provision_unit_targets(
    service: &StableUnitState,
    socket: &StableUnitState,
) -> Result<(StableUnitState, StableUnitState), ProvisioningContractError> {
    service.validate()?;
    socket.validate()?;
    if service.unit_kind != UnitKind::Service || socket.unit_kind != UnitKind::Socket {
        return Err(ProvisioningContractError::InvalidSchema(
            "disabled post-provision unit kind",
        ));
    }
    let mut service_target = service.clone();
    service_target.active_state = UnitActiveState::Inactive;
    service_target.sub_state = UnitSubState::Dead;
    service_target.validate()?;
    Ok((service_target, socket.clone()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTimestampV1 {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl FileTimestampV1 {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.nanoseconds > 999_999_999 {
            return Err(ProvisioningContractError::InvalidSchema("file timestamp"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorableFileTimestampsV1 {
    pub access: FileTimestampV1,
    pub modification: FileTimestampV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileObjectType {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileLinkPolicy {
    ExactlyOne,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMetadataSnapshotV1 {
    pub schema_version: u16,
    pub object_type: FileObjectType,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub link_count: u64,
    pub link_policy: FileLinkPolicy,
    pub byte_length: u64,
    pub restorable_timestamps: RestorableFileTimestampsV1,
}

impl FileMetadataSnapshotV1 {
    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(FILE_METADATA_DOMAIN);
        frame(&mut output, 1, &self.schema_version.to_le_bytes())?;
        frame(&mut output, 2, &[file_object_type_code(self.object_type)])?;
        frame(&mut output, 3, &self.uid.to_le_bytes())?;
        frame(&mut output, 4, &self.gid.to_le_bytes())?;
        frame(&mut output, 5, &self.permissions.to_le_bytes())?;
        frame_u64(&mut output, 6, self.link_count)?;
        frame(&mut output, 7, &[file_link_policy_code(self.link_policy)])?;
        frame_u64(&mut output, 8, self.byte_length)?;
        frame(
            &mut output,
            9,
            &self.restorable_timestamps.access.seconds.to_le_bytes(),
        )?;
        frame(
            &mut output,
            10,
            &self.restorable_timestamps.access.nanoseconds.to_le_bytes(),
        )?;
        frame(
            &mut output,
            11,
            &self
                .restorable_timestamps
                .modification
                .seconds
                .to_le_bytes(),
        )?;
        frame(
            &mut output,
            12,
            &self
                .restorable_timestamps
                .modification
                .nanoseconds
                .to_le_bytes(),
        )?;
        Ok(output)
    }

    pub fn deterministic_sha256(&self) -> Result<Sha256Digest, ProvisioningContractError> {
        self.deterministic_bytes()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION
            || self.object_type != FileObjectType::RegularFile
            || self.permissions & !0o7777 != 0
            || self.link_policy != FileLinkPolicy::ExactlyOne
            || self.link_count != 1
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "file metadata snapshot",
            ));
        }
        self.restorable_timestamps.access.validate()?;
        self.restorable_timestamps.modification.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFileSnapshot {
    pub bytes: ExactBytes,
    pub metadata: FileMetadataSnapshotV1,
    pub metadata_sha256: Sha256Digest,
}

/// Exact identity of a regular file used at an atomic rename boundary.
/// Timestamps are deliberately excluded: the identity binds the object that
/// may be exchanged, while timestamps on the replacement are part of the
/// write plan below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicFileIdentityV1 {
    pub device_id: u64,
    pub inode: u64,
    pub object_type: FileObjectType,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub link_count: u64,
    pub byte_length: u64,
    pub sha256: Sha256Digest,
}

impl AtomicFileIdentityV1 {
    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.device_id == 0
            || self.inode == 0
            || self.object_type != FileObjectType::RegularFile
            || self.permissions & !0o7777 != 0
            || self.link_count != 1
            || self.byte_length > MAX_JOURNAL_BYTES as u64
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic file identity",
            ));
        }
        self.sha256.validate()
    }
}

/// Strict, versioned content of the persistent systemd transaction guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionGuardV1 {
    pub schema_version: u16,
    pub transaction_id: String,
}

impl TransactionGuardV1 {
    pub fn new(transaction_id: &str) -> Result<Self, ProvisioningContractError> {
        let guard = Self {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, 256, "transaction guard bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, 256, "transaction guard bytes")
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema(
                "transaction guard version",
            ));
        }
        validate_transaction_id_v1(&self.transaction_id, "transaction guard id")
    }
}

/// Exact durable identity returned by guard creation and carried by every
/// guarded journal generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionGuardIdentityV1 {
    pub content: TransactionGuardV1,
    pub file: AtomicFileIdentityV1,
}

impl TransactionGuardIdentityV1 {
    pub fn new(
        transaction_id: &str,
        file: AtomicFileIdentityV1,
    ) -> Result<Self, ProvisioningContractError> {
        let identity = Self {
            content: TransactionGuardV1::new(transaction_id)?,
            file,
        };
        identity.validate(transaction_id)?;
        Ok(identity)
    }

    pub fn validate(&self, transaction_id: &str) -> Result<(), ProvisioningContractError> {
        self.content.validate()?;
        self.file.validate()?;
        let bytes = self.content.deterministic_bytes()?;
        if self.content.transaction_id != transaction_id
            || self.file.uid != 0
            || self.file.gid != 0
            || self.file.permissions != 0o600
            || self.file.byte_length != bytes.len() as u64
            || self.file.sha256 != Sha256Digest::from_bytes(&bytes)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "transaction guard identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "identity", rename_all = "kebab-case")]
pub enum AtomicExpectedTargetV1 {
    Absent,
    Present(AtomicFileIdentityV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AtomicWriteKindV1 {
    NoReplace,
    Exchange,
}

/// Fully bound, pre-journaled atomic write intent. The exchange staging name
/// is also the exact backup name: after `RENAME_EXCHANGE` it names the prior
/// target until the engine records a terminal phase and explicitly removes
/// that exact identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicWritePlanV1 {
    pub schema_version: u16,
    pub transaction_id: String,
    pub target_path: String,
    pub parent_directory: DirectoryIdentityV1,
    pub expected_target: AtomicExpectedTargetV1,
    pub staging_path: String,
    pub backup_path: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub timestamps: Option<RestorableFileTimestampsV1>,
    pub bytes_sha256: Sha256Digest,
    pub byte_length: u64,
    pub operation: AtomicWriteKindV1,
}

impl AtomicWritePlanV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: &str,
        target_path: &str,
        parent_directory: DirectoryIdentityV1,
        expected_target: AtomicExpectedTargetV1,
        uid: u32,
        gid: u32,
        permissions: u32,
        timestamps: Option<RestorableFileTimestampsV1>,
        bytes: &[u8],
        operation: AtomicWriteKindV1,
    ) -> Result<Self, ProvisioningContractError> {
        let bytes_sha256 = Sha256Digest::from_bytes(bytes);
        let staging_path =
            canonical_atomic_staging_path(transaction_id, target_path, &bytes_sha256)?;
        let backup_path = (operation == AtomicWriteKindV1::Exchange).then(|| staging_path.clone());
        let plan = Self {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.to_owned(),
            target_path: target_path.to_owned(),
            parent_directory,
            expected_target,
            staging_path,
            backup_path,
            uid,
            gid,
            permissions,
            timestamps,
            bytes_sha256,
            byte_length: u64::try_from(bytes.len())
                .map_err(|_| ProvisioningContractError::LimitExceeded("atomic write bytes"))?,
            operation,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION
            || self.permissions & !0o7777 != 0
            || self.byte_length > MAX_JOURNAL_BYTES as u64
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic write plan",
            ));
        }
        validate_transaction_id_v1(&self.transaction_id, "atomic transaction id")?;
        validate_absolute_path(&self.target_path, "atomic target path")?;
        self.parent_directory.validate_shape()?;
        let target = Path::new(&self.target_path);
        if target.parent() != Some(Path::new(&self.parent_directory.path)) {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic target parent",
            ));
        }
        match (&self.operation, &self.expected_target, &self.backup_path) {
            (AtomicWriteKindV1::NoReplace, AtomicExpectedTargetV1::Absent, None) => {}
            (
                AtomicWriteKindV1::Exchange,
                AtomicExpectedTargetV1::Present(identity),
                Some(backup),
            ) => {
                identity.validate()?;
                if identity.uid != self.uid
                    || identity.gid != self.gid
                    || identity.permissions & 0o022 != 0
                    || backup != &self.staging_path
                {
                    return Err(ProvisioningContractError::InvalidSchema(
                        "atomic exchange backup path",
                    ));
                }
            }
            _ => {
                return Err(ProvisioningContractError::InvalidSchema(
                    "atomic operation target state",
                ));
            }
        }
        if let Some(timestamps) = &self.timestamps {
            timestamps.access.validate()?;
            timestamps.modification.validate()?;
        }
        self.bytes_sha256.validate()?;
        let expected_stage = canonical_atomic_staging_path(
            &self.transaction_id,
            &self.target_path,
            &self.bytes_sha256,
        )?;
        if self.staging_path != expected_stage
            || self.staging_path == self.target_path
            || Path::new(&self.staging_path).parent()
                != Some(Path::new(&self.parent_directory.path))
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic staging path",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicWriteObservationV1 {
    pub target: AtomicFileIdentityV1,
    pub backup: Option<AtomicFileIdentityV1>,
}

impl AtomicWriteObservationV1 {
    pub fn validate_for_plan(
        &self,
        plan: &AtomicWritePlanV1,
    ) -> Result<(), ProvisioningContractError> {
        plan.validate()?;
        self.target.validate()?;
        if self.target.uid != plan.uid
            || self.target.gid != plan.gid
            || self.target.permissions != plan.permissions
            || self.target.byte_length != plan.byte_length
            || self.target.sha256 != plan.bytes_sha256
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic committed target",
            ));
        }
        match (&plan.expected_target, &self.backup) {
            (AtomicExpectedTargetV1::Absent, None) => Ok(()),
            (AtomicExpectedTargetV1::Present(expected), Some(backup)) if expected == backup => {
                backup.validate()
            }
            _ => Err(ProvisioningContractError::InvalidSchema(
                "atomic committed backup",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case")]
pub enum AtomicWriteStateV1 {
    Planned,
    Staged {
        identity: AtomicFileIdentityV1,
    },
    Aborted,
    Committed {
        observation: AtomicWriteObservationV1,
    },
    BackupCleaned {
        observation: AtomicWriteObservationV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtomicWriteRecordV1 {
    pub plan: AtomicWritePlanV1,
    pub state: AtomicWriteStateV1,
}

impl AtomicWriteRecordV1 {
    pub fn planned(plan: AtomicWritePlanV1) -> Self {
        Self {
            plan,
            state: AtomicWriteStateV1::Planned,
        }
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.plan.validate()?;
        match &self.state {
            AtomicWriteStateV1::Planned | AtomicWriteStateV1::Aborted => Ok(()),
            AtomicWriteStateV1::Staged { identity } => {
                validate_atomic_staged_identity(&self.plan, identity)
            }
            AtomicWriteStateV1::Committed { observation } => {
                observation.validate_for_plan(&self.plan)
            }
            AtomicWriteStateV1::BackupCleaned { observation } => {
                observation.validate_for_plan(&self.plan)?;
                if observation.backup.is_none() {
                    return Err(ProvisioningContractError::InvalidSchema(
                        "atomic backup cleanup state",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn validate_atomic_staged_identity(
    plan: &AtomicWritePlanV1,
    identity: &AtomicFileIdentityV1,
) -> Result<(), ProvisioningContractError> {
    identity.validate()?;
    if identity.object_type != FileObjectType::RegularFile
        || identity.uid != plan.uid
        || identity.gid != plan.gid
        || identity.permissions != plan.permissions
        || identity.link_count != 1
        || identity.byte_length != plan.byte_length
        || identity.sha256 != plan.bytes_sha256
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "atomic staged identity",
        ));
    }
    Ok(())
}

pub fn canonical_atomic_staging_path(
    transaction_id: &str,
    target_path: &str,
    bytes_sha256: &Sha256Digest,
) -> Result<String, ProvisioningContractError> {
    validate_transaction_id_v1(transaction_id, "atomic transaction id")?;
    validate_absolute_path(target_path, "atomic target path")?;
    bytes_sha256.validate()?;
    let target = Path::new(target_path);
    let parent = target
        .parent()
        .ok_or(ProvisioningContractError::InvalidSchema(
            "atomic target parent",
        ))?;
    let basename = target.file_name().and_then(|value| value.to_str()).ok_or(
        ProvisioningContractError::InvalidSchema("atomic target basename"),
    )?;
    if basename.is_empty()
        || basename.len() > 128
        || !basename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "atomic target basename",
        ));
    }
    let stage_name = format!(
        ".howy-{transaction_id}-{basename}-{}.stage",
        bytes_sha256.as_str()
    );
    if stage_name.len() > MAX_NAMESPACE_NAME_BYTES {
        return Err(ProvisioningContractError::LimitExceeded(
            "atomic staging basename",
        ));
    }
    Ok(parent.join(stage_name).to_string_lossy().into_owned())
}

pub fn canonical_journal_staging_path(
    transaction_id: &str,
) -> Result<String, ProvisioningContractError> {
    validate_transaction_id_v1(transaction_id, "journal transaction id")?;
    Ok(format!(
        "{SECURITY_JOURNAL_DIRECTORY}/.howy-{transaction_id}-transaction-v1.json-journal.stage"
    ))
}

fn validate_journal_staging_path(
    transaction_id: &str,
    path: &str,
) -> Result<(), ProvisioningContractError> {
    if path != canonical_journal_staging_path(transaction_id)? {
        return Err(ProvisioningContractError::InvalidSchema(
            "journal staging path",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackFileReconstructionV1 {
    pub bytes: Vec<u8>,
    pub metadata: FileMetadataSnapshotV1,
}

impl ExactFileSnapshot {
    pub fn new(
        bytes: &[u8],
        metadata: FileMetadataSnapshotV1,
    ) -> Result<Self, ProvisioningContractError> {
        metadata.validate()?;
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| ProvisioningContractError::LimitExceeded("file snapshot bytes"))?;
        if metadata.byte_length != byte_length {
            return Err(ProvisioningContractError::InvalidSchema(
                "file snapshot byte length",
            ));
        }
        let metadata_sha256 = metadata.deterministic_sha256()?;
        Ok(Self {
            bytes: ExactBytes::from_bytes(bytes),
            metadata,
            metadata_sha256,
        })
    }

    pub fn reconstruct(
        &self,
        maximum: usize,
    ) -> Result<RollbackFileReconstructionV1, ProvisioningContractError> {
        self.validate(maximum, "file snapshot bytes")?;
        Ok(RollbackFileReconstructionV1 {
            bytes: self.bytes.decode()?,
            metadata: self.metadata.clone(),
        })
    }

    fn validate(
        &self,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), ProvisioningContractError> {
        self.bytes.validate_max(maximum, field)?;
        self.metadata.validate()?;
        let byte_length = u64::try_from(self.bytes.byte_len())
            .map_err(|_| ProvisioningContractError::LimitExceeded(field))?;
        if self.metadata.byte_length != byte_length
            || self.metadata_sha256 != self.metadata.deterministic_sha256()?
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "file snapshot metadata binding",
            ));
        }
        self.metadata_sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveFileMetadataV1 {
    pub object_type: FileObjectType,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub link_count: u64,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveUnitFileV1 {
    pub path: String,
    pub sha256: Sha256Digest,
    pub metadata: EffectiveFileMetadataV1,
}

impl EffectiveUnitFileV1 {
    fn validate(
        &self,
        expected_path: &str,
        expected_permissions: u32,
    ) -> Result<(), ProvisioningContractError> {
        validate_absolute_path(&self.path, "effective unit file path")?;
        self.sha256.validate()?;
        if self.path != expected_path
            || self.metadata.object_type != FileObjectType::RegularFile
            || self.metadata.uid != 0
            || self.metadata.gid != 0
            || self.metadata.permissions != expected_permissions
            || self.metadata.link_count != 1
            || self.metadata.byte_length == 0
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "effective unit file",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveUnitConditionV1 {
    pub condition: String,
    pub trigger: bool,
    pub negate: bool,
    pub parameter: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCredentialLoadV1 {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveSetCredentialV1 {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveUnitObservationV1 {
    pub unit_kind: UnitKind,
    pub fragment: EffectiveUnitFileV1,
    /// Exact manager order after all unit search-path precedence rules.
    pub dropins: Vec<EffectiveUnitFileV1>,
    pub conditions: Vec<EffectiveUnitConditionV1>,
    pub load_credential_encrypted: Vec<EffectiveCredentialLoadV1>,
    pub set_credential: Vec<EffectiveSetCredentialV1>,
    /// Canonical absolute argv vectors. V1 permits exactly one service command.
    pub exec_start: Vec<Vec<String>>,
    /// Complete reviewed property/value set used by the v1 policy.
    pub hardening: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveUnitSetV1 {
    pub service: EffectiveUnitObservationV1,
    pub socket: EffectiveUnitObservationV1,
}

impl EffectiveUnitSetV1 {
    pub fn validate_mode1(
        &self,
        expected_dropin_sha256: &Sha256Digest,
    ) -> Result<(), ProvisioningContractError> {
        self.validate_common(expected_dropin_sha256)?;
        if self.service.load_credential_encrypted
            != [EffectiveCredentialLoadV1 {
                name: MODE1_CREDENTIAL_NAME.to_owned(),
                source: MODE1_CREDENTIAL_PATH.to_owned(),
            }]
            || self.service.set_credential
                != [EffectiveSetCredentialV1 {
                    name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.to_owned(),
                    value: MODE1_CREDENTIAL_PATH.to_owned(),
                }]
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "effective mode 1 credentials",
            ));
        }
        Ok(())
    }

    pub fn validate_mode0(
        &self,
        expected_dropin_sha256: &Sha256Digest,
    ) -> Result<(), ProvisioningContractError> {
        self.validate_common(expected_dropin_sha256)?;
        if !self.service.load_credential_encrypted.is_empty()
            || !self.service.set_credential.is_empty()
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "effective mode 0 credentials",
            ));
        }
        Ok(())
    }

    fn validate_common(
        &self,
        expected_dropin_sha256: &Sha256Digest,
    ) -> Result<(), ProvisioningContractError> {
        expected_dropin_sha256.validate()?;
        self.service
            .fragment
            .validate(BASE_SERVICE_UNIT_PATH, 0o644)?;
        self.socket
            .fragment
            .validate(BASE_SOCKET_UNIT_PATH, 0o644)?;
        if self.service.unit_kind != UnitKind::Service
            || self.socket.unit_kind != UnitKind::Socket
            || self.service.dropins.len() != 1
            || self.service.dropins[0].path != MODE1_DROPIN_PATH
            || self.service.dropins[0].sha256 != *expected_dropin_sha256
            || self.service.dropins[0]
                .validate(MODE1_DROPIN_PATH, 0o600)
                .is_err()
            || !self.socket.dropins.is_empty()
            || self.service.conditions != required_unit_conditions()
            || self.socket.conditions != required_unit_conditions()
            || self.service.exec_start != [vec!["/usr/bin/howyd".to_owned()]]
            || !self.socket.exec_start.is_empty()
            || !self.socket.load_credential_encrypted.is_empty()
            || !self.socket.set_credential.is_empty()
            || !self.socket.hardening.is_empty()
            || self.service.hardening != required_service_hardening()
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "effective unit policy",
            ));
        }
        Ok(())
    }
}

pub fn transaction_guard_condition() -> EffectiveUnitConditionV1 {
    EffectiveUnitConditionV1 {
        condition: "ConditionPathExists".to_owned(),
        trigger: false,
        negate: true,
        parameter: SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
    }
}

pub fn package_bootstrap_condition() -> EffectiveUnitConditionV1 {
    EffectiveUnitConditionV1 {
        condition: "ConditionPathExists".to_owned(),
        trigger: false,
        negate: false,
        parameter: PACKAGE_BOOTSTRAP_MARKER_PATH.to_owned(),
    }
}

pub fn required_unit_conditions() -> [EffectiveUnitConditionV1; 2] {
    [transaction_guard_condition(), package_bootstrap_condition()]
}

pub fn required_service_hardening() -> BTreeMap<String, String> {
    [
        ("LimitCORE", "0"),
        ("LimitMEMLOCK", "65536"),
        ("LockPersonality", "yes"),
        ("MemoryDenyWriteExecute", "no"),
        ("NoNewPrivileges", "yes"),
        ("PrivateTmp", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectHome", "read-only"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectSystem", "strict"),
        ("RestrictAddressFamilies", "AF_UNIX"),
        ("RestrictNamespaces", "yes"),
        ("RestrictRealtime", "yes"),
        ("UMask", "0077"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

pub fn planned_effective_units(
    observed_base: &EffectiveUnitSetV1,
    dropin_sha256: Sha256Digest,
    dropin_bytes: u64,
    mode1: bool,
) -> Result<EffectiveUnitSetV1, ProvisioningContractError> {
    if dropin_bytes == 0 || dropin_bytes > MAX_DROPIN_BYTES as u64 {
        return Err(ProvisioningContractError::LimitExceeded(
            "effective drop-in bytes",
        ));
    }
    let mut planned = observed_base.clone();
    planned.service.dropins = vec![EffectiveUnitFileV1 {
        path: MODE1_DROPIN_PATH.to_owned(),
        sha256: dropin_sha256.clone(),
        metadata: EffectiveFileMetadataV1 {
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions: 0o600,
            link_count: 1,
            byte_length: dropin_bytes,
        },
    }];
    planned.service.load_credential_encrypted = mode1
        .then(|| EffectiveCredentialLoadV1 {
            name: MODE1_CREDENTIAL_NAME.to_owned(),
            source: MODE1_CREDENTIAL_PATH.to_owned(),
        })
        .into_iter()
        .collect();
    planned.service.set_credential = mode1
        .then(|| EffectiveSetCredentialV1 {
            name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.to_owned(),
            value: MODE1_CREDENTIAL_PATH.to_owned(),
        })
        .into_iter()
        .collect();
    if mode1 {
        planned.validate_mode1(&dropin_sha256)?;
    } else {
        planned.validate_mode0(&dropin_sha256)?;
    }
    Ok(planned)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedObjectHashes {
    pub artifact_sha256: Sha256Digest,
    pub dropin_sha256: Sha256Digest,
    pub disabled_config_sha256: Sha256Digest,
    pub enabled_config_sha256: Sha256Digest,
    pub disabled_receipt_sha256: Sha256Digest,
    pub enabled_receipt_sha256: Sha256Digest,
}

impl PlannedObjectHashes {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.artifact_sha256.validate()?;
        self.dropin_sha256.validate()?;
        self.disabled_config_sha256.validate()?;
        self.enabled_config_sha256.validate()?;
        self.disabled_receipt_sha256.validate()?;
        self.enabled_receipt_sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveObjectHashes {
    pub artifact_sha256: Option<Sha256Digest>,
    pub dropin_sha256: Option<Sha256Digest>,
    pub config_sha256: Option<Sha256Digest>,
    pub disabled_receipt_sha256: Option<Sha256Digest>,
    pub enabled_receipt_sha256: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupHashes {
    pub artifact_sha256: Option<Sha256Digest>,
    pub config_sha256: Option<Sha256Digest>,
    pub dropin_sha256: Option<Sha256Digest>,
    pub receipt_sha256: Option<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningJournalV1 {
    pub schema_version: u16,
    pub transaction_id: String,
    pub generation: u64,
    pub prior_journal_identity: Option<AtomicFileIdentityV1>,
    pub journal_staging_path: String,
    pub guard: Option<TransactionGuardIdentityV1>,
    pub phase: JournalPhase,
    pub mode: u8,
    pub epoch: u64,
    pub credential_name: String,
    pub planned_hashes: PlannedObjectHashes,
    pub live_hashes: LiveObjectHashes,
    pub transaction_owned_paths: Vec<String>,
    pub atomic_writes: Vec<AtomicWriteRecordV1>,
    pub security_directories: Vec<SecurityDirectoryRecordV1>,
    pub artifact_preexisted: bool,
    pub transient_unit: String,
    pub prior_config: Option<ExactFileSnapshot>,
    pub prior_dropin: Option<ExactFileSnapshot>,
    pub prior_receipt: Option<ExactFileSnapshot>,
    pub service_unit_state: StableUnitState,
    pub socket_unit_state: StableUnitState,
    pub post_provision_service_target: StableUnitState,
    pub post_provision_socket_target: StableUnitState,
    pub prior_daemon_invocation_id: Option<String>,
    pub prior_effective_units: EffectiveUnitSetV1,
    pub effective_units: Option<EffectiveUnitSetV1>,
    pub backup_hashes: BackupHashes,
    pub recovery_action: RecoveryAction,
    pub supervisor_failed: bool,
}

impl ProvisioningJournalV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_JOURNAL_BYTES, "journal bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_JOURNAL_BYTES, "journal bytes")
    }

    pub fn deterministic_sha256(&self) -> Result<Sha256Digest, ProvisioningContractError> {
        self.deterministic_bytes()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema("journal version"));
        }
        validate_transaction_id_v1(&self.transaction_id, "transaction id")?;
        if self.generation == 0 {
            return Err(ProvisioningContractError::InvalidSchema(
                "journal generation",
            ));
        }
        validate_prior_journal_identity(self.generation, self.prior_journal_identity.as_ref())?;
        validate_journal_staging_path(&self.transaction_id, &self.journal_staging_path)?;
        validate_journal_guard(
            &self.transaction_id,
            self.phase.ordinal() >= JournalPhase::Guarded.ordinal(),
            self.guard.as_ref(),
        )?;
        validate_mode1_identity(self.mode, self.epoch, &self.credential_name)?;
        self.planned_hashes.validate()?;
        validate_paths(&self.transaction_owned_paths)?;
        validate_owned_journal_staging_path(
            &self.transaction_owned_paths,
            &self.journal_staging_path,
        )?;
        validate_atomic_write_records(
            &self.transaction_id,
            &self.transaction_owned_paths,
            &self.atomic_writes,
        )?;
        validate_security_directory_records(&self.security_directories)?;
        validate_transient_unit(&self.transient_unit)?;
        if let Some(snapshot) = &self.prior_config {
            snapshot.validate(MAX_CONFIG_BYTES, "prior config bytes")?;
        }
        if let Some(snapshot) = &self.prior_dropin {
            snapshot.validate(MAX_DROPIN_BYTES, "prior drop-in bytes")?;
        }
        if let Some(snapshot) = &self.prior_receipt {
            snapshot.validate(MAX_RECEIPT_BYTES, "prior receipt bytes")?;
        }
        if self.prior_config.is_some() != self.backup_hashes.config_sha256.is_some()
            || self.prior_dropin.is_some() != self.backup_hashes.dropin_sha256.is_some()
            || self.prior_receipt.is_some() != self.backup_hashes.receipt_sha256.is_some()
            || self.artifact_preexisted != self.backup_hashes.artifact_sha256.is_some()
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "journal backup presence",
            ));
        }
        if let (Some(snapshot), Some(backup)) =
            (&self.prior_config, &self.backup_hashes.config_sha256)
            && Sha256Digest::from_bytes(&snapshot.bytes.decode()?) != *backup
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "config backup hash",
            ));
        }
        if let (Some(snapshot), Some(backup)) =
            (&self.prior_dropin, &self.backup_hashes.dropin_sha256)
            && Sha256Digest::from_bytes(&snapshot.bytes.decode()?) != *backup
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "drop-in backup hash",
            ));
        }
        if let (Some(snapshot), Some(backup)) =
            (&self.prior_receipt, &self.backup_hashes.receipt_sha256)
            && Sha256Digest::from_bytes(&snapshot.bytes.decode()?) != *backup
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "receipt backup hash",
            ));
        }
        if self
            .backup_hashes
            .artifact_sha256
            .as_ref()
            .is_some_and(|backup| backup != &self.planned_hashes.artifact_sha256)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "artifact backup hash",
            ));
        }
        self.service_unit_state.validate()?;
        self.socket_unit_state.validate()?;
        if self.service_unit_state.unit_kind != UnitKind::Service
            || self.socket_unit_state.unit_kind != UnitKind::Socket
        {
            return Err(ProvisioningContractError::InvalidSchema("unit kind"));
        }
        let (service_target, socket_target) = disabled_post_provision_unit_targets(
            &self.service_unit_state,
            &self.socket_unit_state,
        )?;
        if self.post_provision_service_target != service_target
            || self.post_provision_socket_target != socket_target
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "post-provision unit target",
            ));
        }
        validate_prior_daemon_invocation(
            &self.service_unit_state,
            self.prior_daemon_invocation_id.as_deref(),
        )?;
        if self.prior_effective_units.service.unit_kind != UnitKind::Service
            || self.prior_effective_units.socket.unit_kind != UnitKind::Socket
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "prior effective unit kind",
            ));
        }
        let effective_required = self.phase.ordinal() >= JournalPhase::DropinCommitted.ordinal();
        if effective_required != self.effective_units.is_some() {
            return Err(ProvisioningContractError::InvalidSchema(
                "journal effective unit presence",
            ));
        }
        if let Some(effective) = &self.effective_units {
            effective.validate_mode1(&self.planned_hashes.dropin_sha256)?;
        }
        validate_optional_digests([
            self.backup_hashes.artifact_sha256.as_ref(),
            self.backup_hashes.config_sha256.as_ref(),
            self.backup_hashes.dropin_sha256.as_ref(),
            self.backup_hashes.receipt_sha256.as_ref(),
        ])?;
        if self.recovery_action != recovery_action_for_phase(self.phase) {
            return Err(ProvisioningContractError::InvalidSchema(
                "journal recovery action",
            ));
        }
        self.validate_live_hash_matrix()
    }

    fn validate_live_hash_matrix(&self) -> Result<(), ProvisioningContractError> {
        let ordinal = self.phase.ordinal();
        validate_phase_hash(
            ordinal >= JournalPhase::ArtifactCommitted.ordinal(),
            self.live_hashes.artifact_sha256.as_ref(),
            &self.planned_hashes.artifact_sha256,
        )?;
        validate_phase_hash(
            ordinal >= JournalPhase::DropinCommitted.ordinal(),
            self.live_hashes.dropin_sha256.as_ref(),
            &self.planned_hashes.dropin_sha256,
        )?;

        let expected_config = if ordinal < JournalPhase::DisabledConfigCommitted.ordinal() {
            None
        } else if ordinal < JournalPhase::EnabledConfigCommitted.ordinal() {
            Some(&self.planned_hashes.disabled_config_sha256)
        } else {
            Some(&self.planned_hashes.enabled_config_sha256)
        };
        if self.live_hashes.config_sha256.as_ref() != expected_config {
            return Err(ProvisioningContractError::InvalidSchema(
                "journal live config hash",
            ));
        }

        validate_phase_hash(
            ordinal >= JournalPhase::DisabledReceiptCommitted.ordinal(),
            self.live_hashes.disabled_receipt_sha256.as_ref(),
            &self.planned_hashes.disabled_receipt_sha256,
        )?;
        validate_phase_hash(
            ordinal >= JournalPhase::EnabledReceiptCommitted.ordinal(),
            self.live_hashes.enabled_receipt_sha256.as_ref(),
            &self.planned_hashes.enabled_receipt_sha256,
        )
    }

    fn stable_fields_equal(&self, next: &Self) -> bool {
        self.schema_version == next.schema_version
            && self.transaction_id == next.transaction_id
            && self.journal_staging_path == next.journal_staging_path
            && self.mode == next.mode
            && self.epoch == next.epoch
            && self.credential_name == next.credential_name
            && self.planned_hashes == next.planned_hashes
            && self.artifact_preexisted == next.artifact_preexisted
            && self.transient_unit == next.transient_unit
            && self.prior_config == next.prior_config
            && self.prior_dropin == next.prior_dropin
            && self.prior_receipt == next.prior_receipt
            && self.service_unit_state == next.service_unit_state
            && self.socket_unit_state == next.socket_unit_state
            && self.post_provision_service_target == next.post_provision_service_target
            && self.post_provision_socket_target == next.post_provision_socket_target
            && self.prior_daemon_invocation_id == next.prior_daemon_invocation_id
            && self.prior_effective_units == next.prior_effective_units
            && self.security_directories == next.security_directories
            && self.backup_hashes == next.backup_hashes
    }
}

pub fn validate_journal_transition(
    current: &ProvisioningJournalV1,
    next: &ProvisioningJournalV1,
) -> Result<(), ProvisioningContractError> {
    current.validate()?;
    next.validate()?;
    let effective_transition = match (&current.effective_units, &next.effective_units) {
        (None, Some(_)) => next.phase == JournalPhase::DropinCommitted,
        (left, right) => left == right,
    };
    let supervisor_transition = current.supervisor_failed == next.supervisor_failed
        || (!current.supervisor_failed && next.supervisor_failed && current.phase == next.phase);
    let ordinary_phase = current.phase.next() == Some(next.phase)
        && current.supervisor_failed == next.supervisor_failed;
    let supervisor_phase = current.phase == next.phase
        && !current.supervisor_failed
        && next.supervisor_failed
        && current.effective_units == next.effective_units;
    let guard_identity_phase = current.phase == next.phase
        && current.guard.is_some()
        && next.guard.is_some()
        && current.guard != next.guard
        && current.supervisor_failed == next.supervisor_failed
        && current.live_hashes == next.live_hashes
        && current.effective_units == next.effective_units
        && current.recovery_action == next.recovery_action
        && current.atomic_writes == next.atomic_writes
        && current.transaction_owned_paths == next.transaction_owned_paths;
    let atomic_phase = current.phase == next.phase
        && current.supervisor_failed == next.supervisor_failed
        && current.live_hashes == next.live_hashes
        && current.effective_units == next.effective_units
        && current.recovery_action == next.recovery_action
        && validate_atomic_write_records_transition(&current.atomic_writes, &next.atomic_writes)
        && validate_atomic_owned_paths_transition(
            &current.transaction_owned_paths,
            &next.transaction_owned_paths,
            &current.atomic_writes,
            &next.atomic_writes,
        );
    let records_stable = atomic_phase || current.atomic_writes == next.atomic_writes;
    let paths_stable =
        atomic_phase || current.transaction_owned_paths == next.transaction_owned_paths;
    if current.generation.checked_add(1) != Some(next.generation)
        || !validate_guard_transition(&current.guard, &next.guard, current.phase == next.phase)
        || !(ordinary_phase || supervisor_phase || atomic_phase || guard_identity_phase)
        || !current.stable_fields_equal(next)
        || !effective_transition
        || !supervisor_transition
        || !records_stable
        || !paths_stable
    {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextProvisioningJournalV1 {
    pub schema_version: u16,
    pub transaction_id: String,
    pub generation: u64,
    pub prior_journal_identity: Option<AtomicFileIdentityV1>,
    pub journal_staging_path: String,
    pub guard: Option<TransactionGuardIdentityV1>,
    pub phase: PlaintextJournalPhase,
    pub enabled_config_sha256: Sha256Digest,
    pub live_config_sha256: Option<Sha256Digest>,
    pub transaction_owned_paths: Vec<String>,
    pub atomic_writes: Vec<AtomicWriteRecordV1>,
    pub security_directories: Vec<SecurityDirectoryRecordV1>,
    pub prior_config: Option<ExactFileSnapshot>,
    pub prior_dropin: Option<ExactFileSnapshot>,
    pub service_unit_state: StableUnitState,
    pub socket_unit_state: StableUnitState,
    pub prior_daemon_invocation_id: Option<String>,
    pub prior_effective_units: EffectiveUnitSetV1,
    pub effective_units: Option<EffectiveUnitSetV1>,
    pub dropin_sha256: Sha256Digest,
    pub recovery_action: PlaintextRecoveryAction,
    pub supervisor_failed: bool,
}

impl PlaintextProvisioningJournalV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_JOURNAL_BYTES, "journal bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_JOURNAL_BYTES, "journal bytes")
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal version",
            ));
        }
        validate_transaction_id_v1(&self.transaction_id, "transaction id")?;
        if self.generation == 0 {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal generation",
            ));
        }
        validate_prior_journal_identity(self.generation, self.prior_journal_identity.as_ref())?;
        validate_journal_staging_path(&self.transaction_id, &self.journal_staging_path)?;
        validate_journal_guard(
            &self.transaction_id,
            self.phase.ordinal() >= PlaintextJournalPhase::Guarded.ordinal(),
            self.guard.as_ref(),
        )?;
        validate_paths(&self.transaction_owned_paths)?;
        validate_owned_journal_staging_path(
            &self.transaction_owned_paths,
            &self.journal_staging_path,
        )?;
        validate_atomic_write_records(
            &self.transaction_id,
            &self.transaction_owned_paths,
            &self.atomic_writes,
        )?;
        validate_security_directory_records(&self.security_directories)?;
        self.enabled_config_sha256.validate()?;
        self.dropin_sha256.validate()?;
        if let Some(hash) = &self.live_config_sha256 {
            hash.validate()?;
        }
        if let Some(snapshot) = &self.prior_config {
            snapshot.validate(MAX_CONFIG_BYTES, "prior config bytes")?;
        }
        if let Some(snapshot) = &self.prior_dropin {
            snapshot.validate(MAX_DROPIN_BYTES, "prior drop-in bytes")?;
        }
        self.service_unit_state.validate()?;
        self.socket_unit_state.validate()?;
        validate_prior_daemon_invocation(
            &self.service_unit_state,
            self.prior_daemon_invocation_id.as_deref(),
        )?;
        if self.service_unit_state.unit_kind != UnitKind::Service
            || self.socket_unit_state.unit_kind != UnitKind::Socket
            || self.recovery_action != plaintext_recovery_action_for_phase(self.phase)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal state",
            ));
        }
        let effective_required =
            self.phase.ordinal() >= PlaintextJournalPhase::DropinRemoved.ordinal();
        if effective_required != self.effective_units.is_some() {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal effective unit presence",
            ));
        }
        if let Some(effective) = &self.effective_units {
            effective.validate_mode0(&self.dropin_sha256)?;
        }
        let config_committed =
            self.phase.ordinal() >= PlaintextJournalPhase::EnabledConfigCommitted.ordinal();
        if self.live_config_sha256.as_ref()
            != config_committed.then_some(&self.enabled_config_sha256)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal live config hash",
            ));
        }
        Ok(())
    }

    fn stable_fields_equal(&self, next: &Self) -> bool {
        self.schema_version == next.schema_version
            && self.transaction_id == next.transaction_id
            && self.journal_staging_path == next.journal_staging_path
            && self.enabled_config_sha256 == next.enabled_config_sha256
            && self.prior_config == next.prior_config
            && self.prior_dropin == next.prior_dropin
            && self.service_unit_state == next.service_unit_state
            && self.socket_unit_state == next.socket_unit_state
            && self.prior_daemon_invocation_id == next.prior_daemon_invocation_id
            && self.prior_effective_units == next.prior_effective_units
            && self.dropin_sha256 == next.dropin_sha256
            && self.security_directories == next.security_directories
    }
}

pub fn validate_plaintext_journal_transition(
    current: &PlaintextProvisioningJournalV1,
    next: &PlaintextProvisioningJournalV1,
) -> Result<(), ProvisioningContractError> {
    current.validate()?;
    next.validate()?;
    let effective_transition = match (&current.effective_units, &next.effective_units) {
        (None, Some(_)) => next.phase == PlaintextJournalPhase::DropinRemoved,
        (left, right) => left == right,
    };
    let ordinary_phase = current.phase.next() == Some(next.phase)
        && current.supervisor_failed == next.supervisor_failed;
    let supervisor_phase = current.phase == next.phase
        && !current.supervisor_failed
        && next.supervisor_failed
        && current.effective_units == next.effective_units;
    let guard_identity_phase = current.phase == next.phase
        && current.guard.is_some()
        && next.guard.is_some()
        && current.guard != next.guard
        && current.supervisor_failed == next.supervisor_failed
        && current.live_config_sha256 == next.live_config_sha256
        && current.effective_units == next.effective_units
        && current.recovery_action == next.recovery_action
        && current.atomic_writes == next.atomic_writes
        && current.transaction_owned_paths == next.transaction_owned_paths;
    let atomic_phase = current.phase == next.phase
        && current.supervisor_failed == next.supervisor_failed
        && current.live_config_sha256 == next.live_config_sha256
        && current.effective_units == next.effective_units
        && current.recovery_action == next.recovery_action
        && validate_atomic_write_records_transition(&current.atomic_writes, &next.atomic_writes)
        && validate_atomic_owned_paths_transition(
            &current.transaction_owned_paths,
            &next.transaction_owned_paths,
            &current.atomic_writes,
            &next.atomic_writes,
        );
    let records_stable = atomic_phase || current.atomic_writes == next.atomic_writes;
    let paths_stable =
        atomic_phase || current.transaction_owned_paths == next.transaction_owned_paths;
    if current.generation.checked_add(1) != Some(next.generation)
        || !validate_guard_transition(&current.guard, &next.guard, current.phase == next.phase)
        || !(ordinary_phase || supervisor_phase || atomic_phase || guard_identity_phase)
        || !current.stable_fields_equal(next)
        || !effective_transition
        || !records_stable
        || !paths_stable
    {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorOperationV1 {
    ProvisionMode1,
    EnableMode1,
    ProvisionMode0,
    CleanupUnadopted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisorPhaseV1 {
    Prepared,
    Guarded,
    UnitsStopped,
    DirectoriesReady,
    MutationCommitted,
    UnitsRestored,
}

impl SupervisorPhaseV1 {
    pub const fn ordinal(self) -> usize {
        match self {
            Self::Prepared => 0,
            Self::Guarded => 1,
            Self::UnitsStopped => 2,
            Self::DirectoriesReady => 3,
            Self::MutationCommitted => 4,
            Self::UnitsRestored => 5,
        }
    }

    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::Guarded),
            Self::Guarded => Some(Self::UnitsStopped),
            Self::UnitsStopped => Some(Self::DirectoriesReady),
            Self::DirectoriesReady => Some(Self::MutationCommitted),
            Self::MutationCommitted => Some(Self::UnitsRestored),
            Self::UnitsRestored => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupQuarantineStateV1 {
    Planned,
    Renamed,
    Removed,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupQuarantineV1 {
    pub path: String,
    pub state: CleanupQuarantineStateV1,
}

/// Exact descriptor and canonical-content identity of the unadopted manifest
/// authorized by a cleanup transaction. Recovery may unlink this path only if
/// the same inode and deterministic manifest bytes are still present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupManifestIdentityV1 {
    pub path: String,
    pub file: AtomicFileIdentityV1,
}

impl CleanupManifestIdentityV1 {
    fn validate(
        &self,
        artifact: &CleanupArtifactIdentityV1,
    ) -> Result<(), ProvisioningContractError> {
        let expected_path = format!(
            "{SECURITY_UNADOPTED_DIRECTORY}/{}.json",
            artifact.transaction_id
        );
        let expected_bytes = UnadoptedArtifactV1::new(artifact.clone())?.deterministic_bytes()?;
        self.file.validate()?;
        if self.path != expected_path
            || self.path.len() > MAX_PATH_BYTES
            || self.file.object_type != FileObjectType::RegularFile
            || self.file.uid != 0
            || self.file.gid != 0
            || self.file.permissions != 0o600
            || self.file.link_count != 1
            || self.file.byte_length != expected_bytes.len() as u64
            || self.file.byte_length > MAX_RECEIPT_BYTES as u64
            || self.file.sha256 != Sha256Digest::from_bytes(&expected_bytes)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup manifest identity",
            ));
        }
        Ok(())
    }
}

impl CleanupQuarantineV1 {
    pub fn validate(&self, transaction_id: &str) -> Result<(), ProvisioningContractError> {
        let expected = format!("{MODE1_CREDENTIAL_DIRECTORY}/.howy-{transaction_id}.quarantine");
        if self.path != expected || self.path.len() > MAX_PATH_BYTES {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup quarantine path",
            ));
        }
        Ok(())
    }
}

/// Minimal durable intent written after fallible immutable snapshots and the
/// prior unit/invocation observation, but before the transaction guard or any
/// persistent mutation. A mode-specific journal replaces this only after
/// guarded unit quiescence and planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorJournalV1 {
    pub schema_version: u16,
    pub transaction_id: String,
    pub generation: u64,
    pub prior_journal_identity: Option<AtomicFileIdentityV1>,
    pub journal_staging_path: String,
    pub guard: Option<TransactionGuardIdentityV1>,
    pub operation: SupervisorOperationV1,
    pub phase: SupervisorPhaseV1,
    pub prior_config: Option<ExactFileSnapshot>,
    pub prior_dropin: Option<ExactFileSnapshot>,
    pub prior_receipt: Option<ExactFileSnapshot>,
    pub service_unit_state: Option<StableUnitState>,
    pub socket_unit_state: Option<StableUnitState>,
    pub prior_daemon_invocation_id: Option<String>,
    pub prior_effective_units: Option<EffectiveUnitSetV1>,
    pub transaction_owned_paths: Vec<String>,
    pub atomic_writes: Vec<AtomicWriteRecordV1>,
    pub security_directories: Vec<SecurityDirectoryRecordV1>,
    pub cleanup_artifact: Option<CleanupArtifactIdentityV1>,
    pub cleanup_manifest: Option<CleanupManifestIdentityV1>,
    pub cleanup_pre_admission: Option<CleanupPreAdmissionV1>,
    pub cleanup_quarantine: Option<CleanupQuarantineV1>,
    pub supervisor_failed: bool,
}

impl SupervisorJournalV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_JOURNAL_BYTES, "supervisor journal bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_JOURNAL_BYTES, "supervisor journal bytes")
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema(
                "supervisor journal version",
            ));
        }
        validate_transaction_id_v1(&self.transaction_id, "transaction id")?;
        if self.generation == 0 {
            return Err(ProvisioningContractError::InvalidSchema(
                "supervisor journal generation",
            ));
        }
        validate_prior_journal_identity(self.generation, self.prior_journal_identity.as_ref())?;
        validate_journal_staging_path(&self.transaction_id, &self.journal_staging_path)?;
        validate_journal_guard(
            &self.transaction_id,
            self.phase.ordinal() >= SupervisorPhaseV1::Guarded.ordinal(),
            self.guard.as_ref(),
        )?;
        validate_paths(&self.transaction_owned_paths)?;
        validate_owned_journal_staging_path(
            &self.transaction_owned_paths,
            &self.journal_staging_path,
        )?;
        validate_atomic_write_records(
            &self.transaction_id,
            &self.transaction_owned_paths,
            &self.atomic_writes,
        )?;
        let directories_ready =
            self.phase.ordinal() >= SupervisorPhaseV1::DirectoriesReady.ordinal();
        if directories_ready {
            validate_security_directory_records(&self.security_directories)?;
        } else {
            validate_security_directory_record_prefix(&self.security_directories)?;
        }
        if let Some(snapshot) = &self.prior_config {
            snapshot.validate(MAX_CONFIG_BYTES, "prior config bytes")?;
        }
        if let Some(snapshot) = &self.prior_dropin {
            snapshot.validate(MAX_DROPIN_BYTES, "prior drop-in bytes")?;
        }
        if let Some(snapshot) = &self.prior_receipt {
            snapshot.validate(MAX_RECEIPT_BYTES, "prior receipt bytes")?;
        }
        if self.service_unit_state.is_none()
            || self.socket_unit_state.is_none()
            || self.prior_effective_units.is_none()
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "supervisor unit snapshot presence",
            ));
        }
        if let (Some(service), Some(socket), Some(effective)) = (
            &self.service_unit_state,
            &self.socket_unit_state,
            &self.prior_effective_units,
        ) {
            service.validate()?;
            socket.validate()?;
            if service.unit_kind != UnitKind::Service
                || socket.unit_kind != UnitKind::Socket
                || effective.service.unit_kind != UnitKind::Service
                || effective.socket.unit_kind != UnitKind::Socket
            {
                return Err(ProvisioningContractError::InvalidSchema(
                    "supervisor unit kind",
                ));
            }
            validate_prior_daemon_invocation(service, self.prior_daemon_invocation_id.as_deref())?;
        } else if self.prior_daemon_invocation_id.is_some() {
            return Err(ProvisioningContractError::InvalidSchema(
                "premature daemon invocation snapshot",
            ));
        }
        match (
            &self.operation,
            &self.cleanup_artifact,
            &self.cleanup_manifest,
            &self.cleanup_pre_admission,
            &self.cleanup_quarantine,
        ) {
            (
                SupervisorOperationV1::CleanupUnadopted,
                Some(identity),
                Some(manifest),
                Some(pre_admission),
                Some(quarantine),
            ) => {
                identity.validate_expected()?;
                manifest.validate(identity)?;
                pre_admission.validate(identity)?;
                quarantine.validate(&self.transaction_id)?;
                if self
                    .transaction_owned_paths
                    .binary_search(&quarantine.path)
                    .is_err()
                {
                    return Err(ProvisioningContractError::InvalidSchema(
                        "transaction-owned cleanup quarantine",
                    ));
                }
            }
            (SupervisorOperationV1::CleanupUnadopted, _, _, _, _) => {
                return Err(ProvisioningContractError::InvalidSchema(
                    "cleanup supervisor identity",
                ));
            }
            (_, Some(_), _, _, _)
            | (_, _, Some(_), _, _)
            | (_, _, _, Some(_), _)
            | (_, _, _, _, Some(_)) => {
                return Err(ProvisioningContractError::InvalidSchema(
                    "unexpected cleanup supervisor identity",
                ));
            }
            (_, None, None, None, None) => {}
        }
        Ok(())
    }
}

pub fn validate_supervisor_journal_transition(
    current: &SupervisorJournalV1,
    next: &SupervisorJournalV1,
) -> Result<(), ProvisioningContractError> {
    current.validate()?;
    next.validate()?;
    let ordinary = (current.phase.next() == Some(next.phase)
        || (current.phase == SupervisorPhaseV1::UnitsStopped
            && next.phase == SupervisorPhaseV1::UnitsRestored)
        || (current.phase == SupervisorPhaseV1::DirectoriesReady
            && next.phase == SupervisorPhaseV1::UnitsRestored))
        && current.supervisor_failed == next.supervisor_failed;
    let fail_closed =
        current.phase == next.phase && !current.supervisor_failed && next.supervisor_failed;
    let guard_identity_phase = current.phase == next.phase
        && current.guard.is_some()
        && next.guard.is_some()
        && current.guard != next.guard
        && current.supervisor_failed == next.supervisor_failed
        && current.atomic_writes == next.atomic_writes
        && current.security_directories == next.security_directories
        && current.cleanup_quarantine == next.cleanup_quarantine
        && current.service_unit_state == next.service_unit_state
        && current.socket_unit_state == next.socket_unit_state
        && current.prior_daemon_invocation_id == next.prior_daemon_invocation_id
        && current.prior_effective_units == next.prior_effective_units;
    let snapshots_stable = current.schema_version == next.schema_version
        && current.transaction_id == next.transaction_id
        && current.journal_staging_path == next.journal_staging_path
        && current.operation == next.operation
        && current.prior_config == next.prior_config
        && current.prior_dropin == next.prior_dropin
        && current.prior_receipt == next.prior_receipt
        && current.transaction_owned_paths == next.transaction_owned_paths
        && current.cleanup_artifact == next.cleanup_artifact
        && current.cleanup_manifest == next.cleanup_manifest
        && current.cleanup_pre_admission == next.cleanup_pre_admission;
    let units_transition = current.service_unit_state == next.service_unit_state
        && current.socket_unit_state == next.socket_unit_state
        && current.prior_daemon_invocation_id == next.prior_daemon_invocation_id
        && current.prior_effective_units == next.prior_effective_units;
    let directories_transition = validate_security_directory_records_transition(
        current.phase,
        next.phase,
        &current.security_directories,
        &next.security_directories,
    );
    let quarantine_transition = match (&current.cleanup_quarantine, &next.cleanup_quarantine) {
        (None, None) => true,
        (Some(left), Some(right)) if left.path == right.path => matches!(
            (left.state, right.state),
            (
                CleanupQuarantineStateV1::Planned,
                CleanupQuarantineStateV1::Planned
            ) | (
                CleanupQuarantineStateV1::Planned,
                CleanupQuarantineStateV1::Renamed
            ) | (
                CleanupQuarantineStateV1::Renamed,
                CleanupQuarantineStateV1::Renamed
            ) | (
                CleanupQuarantineStateV1::Renamed,
                CleanupQuarantineStateV1::Removed
            ) | (
                CleanupQuarantineStateV1::Renamed,
                CleanupQuarantineStateV1::Restored
            ) | (
                CleanupQuarantineStateV1::Removed,
                CleanupQuarantineStateV1::Removed
            ) | (
                CleanupQuarantineStateV1::Restored,
                CleanupQuarantineStateV1::Restored
            )
        ),
        _ => false,
    };
    let quarantine_phase = current.phase == next.phase
        && current.supervisor_failed == next.supervisor_failed
        && current.atomic_writes == next.atomic_writes
        && current.cleanup_quarantine != next.cleanup_quarantine
        && quarantine_transition;
    let directory_phase = current.phase == SupervisorPhaseV1::UnitsStopped
        && next.phase == SupervisorPhaseV1::UnitsStopped
        && current.supervisor_failed == next.supervisor_failed
        && current.atomic_writes == next.atomic_writes
        && current.cleanup_quarantine == next.cleanup_quarantine
        && current.security_directories != next.security_directories
        && directories_transition;
    let atomic = current.phase == next.phase
        && current.supervisor_failed == next.supervisor_failed
        && current.service_unit_state == next.service_unit_state
        && current.socket_unit_state == next.socket_unit_state
        && current.prior_daemon_invocation_id == next.prior_daemon_invocation_id
        && current.prior_effective_units == next.prior_effective_units
        && current.security_directories == next.security_directories
        && validate_atomic_write_records_transition(&current.atomic_writes, &next.atomic_writes);
    let records_stable = atomic || current.atomic_writes == next.atomic_writes;
    if current.generation.checked_add(1) != Some(next.generation)
        || !validate_guard_transition(&current.guard, &next.guard, current.phase == next.phase)
        || !(ordinary
            || fail_closed
            || atomic
            || quarantine_phase
            || directory_phase
            || guard_identity_phase)
        || !snapshots_stable
        || !units_transition
        || !directories_transition
        || !quarantine_transition
        || !records_stable
    {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
}

fn validate_security_directory_records_transition(
    current_phase: SupervisorPhaseV1,
    next_phase: SupervisorPhaseV1,
    current: &[SecurityDirectoryRecordV1],
    next: &[SecurityDirectoryRecordV1],
) -> bool {
    if current == next {
        return true;
    }
    if current_phase != SupervisorPhaseV1::UnitsStopped
        || next_phase != SupervisorPhaseV1::UnitsStopped
    {
        return false;
    }
    if next.len() == current.len() + 1
        && next.starts_with(current)
        && next.last().is_some_and(|record| {
            record.observed_directory.is_none()
                && record.path == REQUIRED_SECURITY_DIRECTORIES[current.len()].0
        })
    {
        return true;
    }
    if next.len() == current.len() && !current.is_empty() {
        let last = current.len() - 1;
        return current[..last] == next[..last]
            && current[last].path == next[last].path
            && current[last].uid == next[last].uid
            && current[last].gid == next[last].gid
            && current[last].permissions == next[last].permissions
            && current[last].parent_directory == next[last].parent_directory
            && current[last].expected_directory == next[last].expected_directory
            && current[last].preexisted == next[last].preexisted
            && current[last].observed_directory.is_none()
            && next[last].observed_directory.is_some();
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigPatchV1 {
    pub byte_start: u64,
    pub byte_end: u64,
    pub before: String,
    pub after: String,
    pub disabled_sha256: Sha256Digest,
    pub enabled_sha256: Sha256Digest,
}

impl ConfigPatchV1 {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.before != "true"
            || self.after != "false"
            || self.byte_end.checked_sub(self.byte_start) != Some(4)
            || self.byte_end > MAX_CONFIG_BYTES as u64
            || self.disabled_sha256 == self.enabled_sha256
        {
            return Err(ProvisioningContractError::InvalidSchema("config patch"));
        }
        self.disabled_sha256.validate()?;
        self.enabled_sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedConfigPatch {
    pub contract: ConfigPatchV1,
    pub enabled_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct PatchDocument {
    core: PatchCore,
    #[serde(flatten)]
    _other: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
struct PatchCore {
    disabled: toml::Spanned<bool>,
    #[serde(flatten)]
    _other: BTreeMap<String, toml::Value>,
}

/// Prepare the unique byte-preserving `core.disabled = true` to `false` patch.
pub fn prepare_config_enable_patch(
    raw: &[u8],
) -> Result<PreparedConfigPatch, ProvisioningContractError> {
    if raw.len() > MAX_CONFIG_BYTES {
        return Err(ProvisioningContractError::LimitExceeded("config bytes"));
    }
    if raw.contains(&b'\r') {
        return Err(ProvisioningContractError::InvalidConfigEncoding);
    }
    let enabled_length = checked_enabled_config_length(raw.len())?;
    let source =
        std::str::from_utf8(raw).map_err(|_| ProvisioningContractError::InvalidConfigEncoding)?;
    let disabled_config: HowyConfig =
        toml::from_str(source).map_err(|_| ProvisioningContractError::InvalidToml)?;
    disabled_config
        .validate()
        .map_err(|_| ProvisioningContractError::InvalidToml)?;
    if !disabled_config.core.disabled {
        return Err(ProvisioningContractError::MissingDisabledLiteral);
    }

    let patch_document: PatchDocument =
        toml::from_str(source).map_err(|_| ProvisioningContractError::MissingDisabledLiteral)?;
    if !*patch_document.core.disabled.get_ref() {
        return Err(ProvisioningContractError::MissingDisabledLiteral);
    }
    let span = patch_document.core.disabled.span();
    validate_disabled_token_layout(source, &span)?;
    if raw.get(span.clone()) != Some(b"true") {
        return Err(ProvisioningContractError::AmbiguousDisabledLiteral);
    }

    let mut enabled_bytes = Vec::with_capacity(enabled_length);
    enabled_bytes.extend_from_slice(&raw[..span.start]);
    enabled_bytes.extend_from_slice(b"false");
    enabled_bytes.extend_from_slice(&raw[span.end..]);
    let enabled_source = std::str::from_utf8(&enabled_bytes)
        .map_err(|_| ProvisioningContractError::InvalidConfigEncoding)?;
    let enabled_config: HowyConfig =
        toml::from_str(enabled_source).map_err(|_| ProvisioningContractError::InvalidToml)?;
    enabled_config
        .validate()
        .map_err(|_| ProvisioningContractError::InvalidToml)?;
    if enabled_config.core.disabled {
        return Err(ProvisioningContractError::InvalidToml);
    }

    Ok(PreparedConfigPatch {
        contract: ConfigPatchV1 {
            byte_start: u64::try_from(span.start)
                .map_err(|_| ProvisioningContractError::LimitExceeded("config offset"))?,
            byte_end: u64::try_from(span.end)
                .map_err(|_| ProvisioningContractError::LimitExceeded("config offset"))?,
            before: "true".to_owned(),
            after: "false".to_owned(),
            disabled_sha256: Sha256Digest::from_bytes(raw),
            enabled_sha256: Sha256Digest::from_bytes(&enabled_bytes),
        },
        enabled_bytes,
    })
}

fn checked_enabled_config_length(
    disabled_length: usize,
) -> Result<usize, ProvisioningContractError> {
    let enabled_length =
        disabled_length
            .checked_add(1)
            .ok_or(ProvisioningContractError::LimitExceeded(
                "enabled config bytes",
            ))?;
    if enabled_length > MAX_CONFIG_BYTES {
        return Err(ProvisioningContractError::LimitExceeded(
            "enabled config bytes",
        ));
    }
    Ok(enabled_length)
}

pub fn apply_receipted_config_patch(
    disabled_bytes: &[u8],
    patch: &ConfigPatchV1,
) -> Result<Vec<u8>, ProvisioningContractError> {
    patch.validate()?;
    if disabled_bytes.len() > MAX_CONFIG_BYTES
        || Sha256Digest::from_bytes(disabled_bytes) != patch.disabled_sha256
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "disabled config hash",
        ));
    }
    let start = usize::try_from(patch.byte_start)
        .map_err(|_| ProvisioningContractError::InvalidSchema("config patch offset"))?;
    let end = usize::try_from(patch.byte_end)
        .map_err(|_| ProvisioningContractError::InvalidSchema("config patch offset"))?;
    if disabled_bytes.get(start..end) != Some(b"true") {
        return Err(ProvisioningContractError::InvalidSchema(
            "disabled config token",
        ));
    }
    let prepared = prepare_config_enable_patch(disabled_bytes)?;
    if &prepared.contract != patch {
        return Err(ProvisioningContractError::InvalidSchema(
            "unique config patch",
        ));
    }
    Ok(prepared.enabled_bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptState {
    ProvisionedDisabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialSelector {
    Host,
    Tpm2,
    HostAndTpm2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemdCredentialKeyId {
    Host,
    Tpm2Hmac,
    HostAndTpm2Hmac,
}

impl SystemdCredentialKeyId {
    pub const fn selector(self) -> CredentialSelector {
        match self {
            Self::Host => CredentialSelector::Host,
            Self::Tpm2Hmac => CredentialSelector::Tpm2,
            Self::HostAndTpm2Hmac => CredentialSelector::HostAndTpm2,
        }
    }

    pub const fn uses_tpm(self) -> bool {
        matches!(self, Self::Tpm2Hmac | Self::HostAndTpm2Hmac)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPolicyMetadata {
    pub requested_selector: CredentialSelector,
    pub actual_key_id: SystemdCredentialKeyId,
    pub system_scope: bool,
    pub embedded_name: String,
    pub literal_pcr_mask: Option<u64>,
    pub public_key_policy: bool,
    pub null_key: bool,
    pub envelope_sha256: Sha256Digest,
    pub envelope_size: u64,
}

impl CredentialPolicyMetadata {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.actual_key_id.selector() != self.requested_selector
            || !self.system_scope
            || self.embedded_name != MODE1_CREDENTIAL_NAME
            || self.public_key_policy
            || self.null_key
            || (self.actual_key_id.uses_tpm() && self.literal_pcr_mask != Some(0))
            || (!self.actual_key_id.uses_tpm() && self.literal_pcr_mask.is_some())
            || self.envelope_size == 0
            || self.envelope_size > SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX as u64
        {
            return Err(ProvisioningContractError::CredentialPolicyRejected);
        }
        self.envelope_sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedCredentialEnvelope {
    pub actual_key_id: SystemdCredentialKeyId,
    pub literal_pcr_mask: Option<u64>,
    pub envelope_sha256: Sha256Digest,
    pub envelope_size: u64,
    pub authenticated_data_bytes: u64,
}

/// Non-secret evidence returned by a cryptographic verifier that authenticated
/// and exactly consumed the envelope. The embedded metadata header (including
/// its name) is AES-GCM ciphertext in systemd v261 and cannot be read by an
/// outer-envelope parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCryptographicValidation {
    pub envelope_sha256: Sha256Digest,
    pub embedded_name: String,
    pub plaintext_size: u64,
    pub authenticated: bool,
    pub exact_consumption: bool,
}

/// Decode and structurally inspect a systemd v261 encrypted credential.
///
/// The accepted outer IDs are the three non-scoped, non-null, non-PK system
/// IDs from `src/shared/creds-util.h` at tag v261. TPM-bearing envelopes also
/// parse the packed TPM header and require zero literal-PCR policy. The
/// encrypted metadata/ciphertext remains opaque.
pub fn inspect_systemd_credential_envelope(
    encoded: &[u8],
) -> Result<InspectedCredentialEnvelope, ProvisioningContractError> {
    if encoded.len() > SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX {
        return Err(ProvisioningContractError::LimitExceeded(
            "credential text bytes",
        ));
    }
    let binary = decode_base64_strict(encoded)?;
    if binary.len() > SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX
        || binary.len() < SYSTEMD_MAIN_HEADER_BYTES
    {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }

    let id: [u8; 16] = binary[..16]
        .try_into()
        .map_err(|_| ProvisioningContractError::InvalidCredentialEnvelope)?;
    let actual_key_id = credential_key_id(id)?;
    if read_le_u32(&binary, 16)? != SYSTEMD_AES_KEY_BYTES
        || read_le_u32(&binary, 20)? != SYSTEMD_AES_BLOCK_BYTES
        || read_le_u32(&binary, 24)? != SYSTEMD_AES_IV_BYTES
        || read_le_u32(&binary, 28)? != SYSTEMD_AES_TAG_BYTES
    {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }
    let main_end = SYSTEMD_MAIN_HEADER_BYTES
        .checked_add(SYSTEMD_AES_IV_BYTES as usize)
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    let mut position = align8(main_end)?;
    validate_zero_padding(&binary, main_end, position)?;
    if position > binary.len() {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }

    let literal_pcr_mask = if actual_key_id.uses_tpm() {
        let fixed_end = position
            .checked_add(SYSTEMD_TPM_HEADER_BYTES)
            .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
        if fixed_end > binary.len() {
            return Err(ProvisioningContractError::InvalidCredentialEnvelope);
        }
        let pcr_mask = read_le_u64(&binary, position)?;
        if pcr_mask != 0 {
            return Err(ProvisioningContractError::CredentialPolicyRejected);
        }
        let pcr_bank = read_le_u16(&binary, position + 8)?;
        let primary_alg = read_le_u16(&binary, position + 10)?;
        let blob_size = usize::try_from(read_le_u32(&binary, position + 12)?)
            .map_err(|_| ProvisioningContractError::InvalidCredentialEnvelope)?;
        let policy_hash_size = usize::try_from(read_le_u32(&binary, position + 16)?)
            .map_err(|_| ProvisioningContractError::InvalidCredentialEnvelope)?;
        if !matches!(pcr_bank, 0x0004 | 0x000b)
            || !matches!(primary_alg, 0x0001 | 0x0023)
            || blob_size == 0
            || policy_hash_size != 32
            || blob_size > SYSTEMD_FIELD_SIZE_MAX
            || policy_hash_size > SYSTEMD_FIELD_SIZE_MAX
        {
            return Err(ProvisioningContractError::InvalidCredentialEnvelope);
        }
        let payload_end = fixed_end
            .checked_add(blob_size)
            .and_then(|value| value.checked_add(policy_hash_size))
            .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
        let aligned_end = align8(payload_end)?;
        if aligned_end > binary.len() {
            return Err(ProvisioningContractError::InvalidCredentialEnvelope);
        }
        validate_zero_padding(&binary, payload_end, aligned_end)?;
        position = aligned_end;
        Some(pcr_mask)
    } else {
        None
    };

    let minimum_ciphertext = align8(SYSTEMD_METADATA_HEADER_BYTES)?;
    if binary.len()
        < position
            .checked_add(minimum_ciphertext)
            .and_then(|value| value.checked_add(SYSTEMD_AES_TAG_BYTES as usize))
            .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?
    {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }

    Ok(InspectedCredentialEnvelope {
        actual_key_id,
        literal_pcr_mask,
        envelope_sha256: Sha256Digest::from_bytes(&binary),
        envelope_size: u64::try_from(binary.len())
            .map_err(|_| ProvisioningContractError::InvalidCredentialEnvelope)?,
        authenticated_data_bytes: u64::try_from(position)
            .map_err(|_| ProvisioningContractError::InvalidCredentialEnvelope)?,
    })
}

/// Complete Howy's systemd credential policy validation with cryptographic
/// name/exact-consumption evidence from systemd's AES-GCM verifier.
pub fn validate_systemd_credential_envelope(
    encoded: &[u8],
    requested_selector: CredentialSelector,
    expected_name: &str,
    validation: &CredentialCryptographicValidation,
) -> Result<CredentialPolicyMetadata, ProvisioningContractError> {
    if expected_name != MODE1_CREDENTIAL_NAME {
        return Err(ProvisioningContractError::CredentialPolicyRejected);
    }
    let inspected = inspect_systemd_credential_envelope(encoded)?;
    if inspected.actual_key_id.selector() != requested_selector
        || validation.envelope_sha256 != inspected.envelope_sha256
        || validation.embedded_name != expected_name
        || validation.plaintext_size != SYSTEMD_CREDENTIAL_PLAINTEXT_BYTES
        || !validation.authenticated
        || !validation.exact_consumption
    {
        return Err(ProvisioningContractError::CredentialPolicyRejected);
    }

    let expected_ciphertext_bytes = align8(
        SYSTEMD_METADATA_HEADER_BYTES
            .checked_add(expected_name.len())
            .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?,
    )?
    .checked_add(SYSTEMD_CREDENTIAL_PLAINTEXT_BYTES as usize)
    .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    let expected_envelope_bytes = usize::try_from(inspected.authenticated_data_bytes)
        .ok()
        .and_then(|value| value.checked_add(expected_ciphertext_bytes))
        .and_then(|value| value.checked_add(SYSTEMD_AES_TAG_BYTES as usize))
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    if expected_envelope_bytes != inspected.envelope_size as usize {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }

    let metadata = CredentialPolicyMetadata {
        requested_selector,
        actual_key_id: inspected.actual_key_id,
        system_scope: true,
        embedded_name: expected_name.to_owned(),
        literal_pcr_mask: inspected.literal_pcr_mask,
        public_key_policy: false,
        null_key: false,
        envelope_sha256: inspected.envelope_sha256,
        envelope_size: inspected.envelope_size,
    };
    metadata.validate()?;
    Ok(metadata)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReceipt {
    pub path: String,
    pub sha256: Sha256Digest,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub credential_policy: CredentialPolicyMetadata,
}

impl ArtifactReceipt {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.path != MODE1_CREDENTIAL_PATH
            || self.size == 0
            || self.size > SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX as u64
            || self.uid != 0
            || self.gid != 0
            || self.mode != 0o600
            || self.nlink != 1
            || self.credential_policy.envelope_size > self.size
        {
            return Err(ProvisioningContractError::InvalidSchema("receipt artifact"));
        }
        self.sha256.validate()?;
        self.credential_policy.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCredentialReceipt {
    pub base_unit_sha256: Sha256Digest,
    pub dropin_sha256: Sha256Digest,
    pub source_companion_name: String,
    pub configured_credential_source: ConfiguredMode1CredentialSource,
}

impl UnitCredentialReceipt {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.base_unit_sha256.validate()?;
        self.dropin_sha256.validate()?;
        if self.source_companion_name != MODE1_CREDENTIAL_SOURCE_COMPANION_NAME {
            return Err(ProvisioningContractError::InvalidSchema(
                "credential source companion name",
            ));
        }
        self.configured_credential_source
            .validate(Mode1CredentialSourcePolicy::Production)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecognizerIdentity {
    pub absolute_path: String,
    pub sha256: Sha256Digest,
}

impl RecognizerIdentity {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        validate_absolute_path(&self.absolute_path, "recognizer path")?;
        self.sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessResultV1 {
    pub protocol_version: u16,
    pub success: bool,
    pub namespace: NamespaceFingerprintV1,
    pub record_count: u64,
    pub verified_record_count: u64,
    pub key_record_compatibility: KeyRecordCompatibility,
    pub recognizer: Option<RecognizerIdentity>,
    pub cache_population_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRecordCompatibility {
    Verified,
    EmptyNotApplicable,
}

impl ReadinessResultV1 {
    pub fn new_verified(
        namespace: NamespaceFingerprintV1,
        recognizer: Option<RecognizerIdentity>,
    ) -> Result<Self, ProvisioningContractError> {
        namespace.validate()?;
        let empty = namespace.entry_count == 0;
        let result = Self {
            protocol_version: PROVISIONING_SCHEMA_VERSION,
            success: true,
            record_count: namespace.entry_count,
            verified_record_count: namespace.entry_count,
            namespace,
            key_record_compatibility: if empty {
                KeyRecordCompatibility::EmptyNotApplicable
            } else {
                KeyRecordCompatibility::Verified
            },
            recognizer,
            cache_population_count: 0,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.namespace.validate()?;
        let empty = self.namespace.entry_count == 0;
        if self.protocol_version != PROVISIONING_SCHEMA_VERSION
            || !self.success
            || self.record_count != self.namespace.entry_count
            || self.verified_record_count != self.namespace.entry_count
            || self.cache_population_count != 0
            || empty != self.recognizer.is_none()
            || (empty
                && self.key_record_compatibility != KeyRecordCompatibility::EmptyNotApplicable)
            || (!empty && self.key_record_compatibility != KeyRecordCompatibility::Verified)
        {
            return Err(ProvisioningContractError::InvalidSchema("readiness result"));
        }
        if let Some(recognizer) = &self.recognizer {
            recognizer.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonVerifierIdentityV1 {
    pub version: String,
    pub build_identity: String,
    pub binary_absolute_path: String,
    pub binary_sha256: Sha256Digest,
}

impl DaemonVerifierIdentityV1 {
    fn validate(&self) -> Result<(), ProvisioningContractError> {
        validate_bounded_printable(&self.version, MAX_DAEMON_VERSION_BYTES, "daemon version")?;
        validate_bounded_printable(
            &self.build_identity,
            MAX_BUILD_ID_BYTES,
            "verifier build identity",
        )?;
        validate_absolute_path(&self.binary_absolute_path, "verifier binary")?;
        self.binary_sha256.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierResultV1 {
    pub config_sha256: Sha256Digest,
    pub daemon: DaemonVerifierIdentityV1,
    pub readiness: ReadinessResultV1,
}

impl VerifierResultV1 {
    pub fn new(
        config_sha256: Sha256Digest,
        daemon: DaemonVerifierIdentityV1,
        readiness: ReadinessResultV1,
    ) -> Result<Self, ProvisioningContractError> {
        let result = Self {
            config_sha256,
            daemon,
            readiness,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_VERIFIER_RESULT_BYTES, "verifier result bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_VERIFIER_RESULT_BYTES, "verifier result bytes")
    }

    pub fn deterministic_sha256(&self) -> Result<Sha256Digest, ProvisioningContractError> {
        self.deterministic_bytes()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.config_sha256.validate()?;
        self.daemon.validate()?;
        self.readiness.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierReceipt {
    pub output: VerifierResultV1,
    pub output_sha256: Sha256Digest,
}

impl VerifierReceipt {
    pub fn new(output: VerifierResultV1) -> Result<Self, ProvisioningContractError> {
        let output_sha256 = output.deterministic_sha256()?;
        Ok(Self {
            output,
            output_sha256,
        })
    }

    fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.output.validate()?;
        self.output_sha256.validate()?;
        if self.output.deterministic_sha256()? != self.output_sha256 {
            return Err(ProvisioningContractError::InvalidSchema(
                "verifier output hash",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningReceiptV1 {
    pub schema_version: u16,
    pub state: ReceiptState,
    pub transaction_id: String,
    pub mode: u8,
    pub epoch: u64,
    pub credential_name: String,
    pub artifact: ArtifactReceipt,
    pub config_patch: ConfigPatchV1,
    pub unit_credential: UnitCredentialReceipt,
    pub effective_units: EffectiveUnitSetV1,
    pub verifier: VerifierReceipt,
}

impl ProvisioningReceiptV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_RECEIPT_BYTES, "receipt bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_RECEIPT_BYTES, "receipt bytes")
    }

    pub fn deterministic_sha256(&self) -> Result<Sha256Digest, ProvisioningContractError> {
        self.deterministic_bytes()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema("receipt version"));
        }
        validate_safe_name(
            &self.transaction_id,
            MAX_TRANSACTION_ID_BYTES,
            "transaction id",
        )?;
        validate_mode1_identity(self.mode, self.epoch, &self.credential_name)?;
        self.artifact.validate()?;
        if self.artifact.credential_policy.embedded_name != self.credential_name {
            return Err(ProvisioningContractError::InvalidSchema(
                "artifact credential binding",
            ));
        }
        self.config_patch.validate()?;
        self.unit_credential.validate()?;
        self.effective_units
            .validate_mode1(&self.unit_credential.dropin_sha256)?;
        self.verifier.validate()?;
        let expected_config = match self.state {
            ReceiptState::ProvisionedDisabled => &self.config_patch.disabled_sha256,
            ReceiptState::Enabled => &self.config_patch.enabled_sha256,
        };
        if &self.verifier.output.config_sha256 != expected_config {
            return Err(ProvisioningContractError::InvalidSchema(
                "verifier config binding",
            ));
        }
        Ok(())
    }
}

pub fn validate_receipt_transition(
    disabled: &ProvisioningReceiptV1,
    enabled: &ProvisioningReceiptV1,
) -> Result<(), ProvisioningContractError> {
    disabled.validate()?;
    enabled.validate()?;
    if disabled.state != ReceiptState::ProvisionedDisabled || enabled.state != ReceiptState::Enabled
    {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    let mut expected = disabled.clone();
    expected.state = ReceiptState::Enabled;
    expected.verifier.output.config_sha256 = expected.config_patch.enabled_sha256.clone();
    expected.verifier.output_sha256 = expected.verifier.output.deterministic_sha256()?;
    if expected != *enabled {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceFileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceEntryClassification {
    Authoritative { username: String },
    Temporary,
    Staged,
    Clear,
    Rollback,
    Symlink,
    Directory,
    Hardlink,
    NonUtf8,
    Unknown,
}

impl NamespaceEntryClassification {
    const fn code(&self) -> u8 {
        match self {
            Self::Authoritative { .. } => 1,
            Self::Temporary => 2,
            Self::Staged => 3,
            Self::Clear => 4,
            Self::Rollback => 5,
            Self::Symlink => 6,
            Self::Directory => 7,
            Self::Hardlink => 8,
            Self::NonUtf8 => 9,
            Self::Unknown => 10,
        }
    }

    pub const fn is_authoritative(&self) -> bool {
        matches!(self, Self::Authoritative { .. })
    }
}

pub fn classify_mode1_namespace_entry(
    name: &[u8],
    file_type: NamespaceFileType,
    nlink: u64,
) -> NamespaceEntryClassification {
    let Ok(name_text) = std::str::from_utf8(name) else {
        return NamespaceEntryClassification::NonUtf8;
    };
    match file_type {
        NamespaceFileType::Symlink => return NamespaceEntryClassification::Symlink,
        NamespaceFileType::Directory => return NamespaceEntryClassification::Directory,
        NamespaceFileType::Other => return NamespaceEntryClassification::Unknown,
        NamespaceFileType::Regular => {}
    }
    if nlink != 1 {
        return NamespaceEntryClassification::Hardlink;
    }
    if let Some(username) = name_text.strip_suffix(".hye")
        && crate::paths::is_canonical_username(username)
    {
        return NamespaceEntryClassification::Authoritative {
            username: username.to_owned(),
        };
    }
    if parse_mode1_transaction_artifact(name, b".tmp.").is_some() {
        return NamespaceEntryClassification::Temporary;
    }
    if parse_mode1_transaction_artifact(name, b".staged.").is_some() {
        return NamespaceEntryClassification::Staged;
    }
    if parse_mode1_transaction_artifact(name, b".clear.").is_some()
        || name.ends_with(b".bin")
        || name.ends_with(b".json")
    {
        return NamespaceEntryClassification::Clear;
    }
    if parse_mode1_transaction_artifact(name, b".rollback.").is_some() {
        return NamespaceEntryClassification::Rollback;
    }
    NamespaceEntryClassification::Unknown
}

pub fn classified_mode1_transaction_username(
    name: &[u8],
    classification: &NamespaceEntryClassification,
) -> Option<String> {
    let marker = match classification {
        NamespaceEntryClassification::Temporary => b".tmp.".as_slice(),
        NamespaceEntryClassification::Staged => b".staged.".as_slice(),
        NamespaceEntryClassification::Clear => b".clear.".as_slice(),
        NamespaceEntryClassification::Rollback => b".rollback.".as_slice(),
        _ => return None,
    };
    parse_mode1_transaction_artifact(name, marker).map(str::to_owned)
}

fn parse_mode1_transaction_artifact<'a>(name: &'a [u8], marker: &[u8]) -> Option<&'a str> {
    if name.first() != Some(&b'.') {
        return None;
    }
    name.windows(marker.len())
        .enumerate()
        .find_map(|(offset, candidate)| {
            if candidate != marker {
                return None;
            }
            let Some(prefix) = name.get(1..offset) else {
                return None;
            };
            let Some(username) = prefix.strip_suffix(b".hye") else {
                return None;
            };
            let suffix_start = offset + marker.len();
            let Some(suffix) = name.get(suffix_start..) else {
                return None;
            };
            (suffix.len() == 32
                && suffix
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                && std::str::from_utf8(username)
                    .ok()
                    .is_some_and(crate::paths::is_canonical_username))
            .then(|| std::str::from_utf8(username).expect("validated UTF-8 username"))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceDirectoryMetadata {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceFingerprintEntry {
    pub name: Vec<u8>,
    pub file_type: NamespaceFileType,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub ciphertext_sha256: Sha256Digest,
    pub classification: NamespaceEntryClassification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceInventoryV1 {
    pub directory: NamespaceDirectoryMetadata,
    pub entries: Vec<NamespaceFingerprintEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceFingerprintV1 {
    pub sha256: Sha256Digest,
    pub entry_count: u64,
    pub ciphertext_bytes: u64,
}

impl NamespaceFingerprintV1 {
    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        self.sha256.validate()?;
        let maximum_count = u64::try_from(MAX_NAMESPACE_ENTRIES)
            .map_err(|_| ProvisioningContractError::LimitExceeded("namespace entry count"))?;
        let maximum_bytes = self
            .entry_count
            .checked_mul(MAX_NAMESPACE_CIPHERTEXT_BYTES)
            .ok_or(ProvisioningContractError::InvalidSchema(
                "namespace fingerprint total overflow",
            ))?;
        if self.entry_count > maximum_count
            || self.ciphertext_bytes > MAX_NAMESPACE_TOTAL_BYTES
            || self.ciphertext_bytes > maximum_bytes
            || (self.entry_count == 0) != (self.ciphertext_bytes == 0)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "namespace fingerprint totals",
            ));
        }
        Ok(())
    }
}

pub fn validate_readiness_inventory(
    inventory: &NamespaceInventoryV1,
) -> Result<(), ProvisioningContractError> {
    validate_inventory(inventory)?;
    if inventory.directory.path != MODE1_NAMESPACE_PATH
        || inventory.directory.uid != 0
        || inventory.directory.gid != 0
        || inventory.directory.mode != 0o700
        || inventory.directory.nlink == 0
    {
        return Err(ProvisioningContractError::InvalidNamespaceInventory);
    }
    if inventory.entries.iter().any(|entry| {
        !entry.classification.is_authoritative()
            || entry.file_type != NamespaceFileType::Regular
            || entry.uid != 0
            || entry.gid != 0
            || entry.mode != 0o600
            || entry.nlink != 1
    }) {
        return Err(ProvisioningContractError::InvalidNamespaceInventory);
    }
    Ok(())
}

pub fn encode_namespace_fingerprint_frame(
    inventory: &NamespaceInventoryV1,
) -> Result<Vec<u8>, ProvisioningContractError> {
    validate_inventory(inventory)?;
    let mut sorted: Vec<&NamespaceFingerprintEntry> = inventory.entries.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));

    let mut total_bytes = 0u64;
    let mut output = Vec::new();
    output.extend_from_slice(NAMESPACE_DOMAIN);
    frame(&mut output, 1, inventory.directory.path.as_bytes())?;
    frame(&mut output, 2, b"root-owned-mode0700-no-follow-v1")?;
    frame_u64(&mut output, 3, u64::from(inventory.directory.uid))?;
    frame_u64(&mut output, 4, u64::from(inventory.directory.gid))?;
    frame_u64(&mut output, 5, u64::from(inventory.directory.mode))?;
    frame_u64(&mut output, 6, inventory.directory.nlink)?;

    for entry in sorted {
        total_bytes =
            total_bytes
                .checked_add(entry.size)
                .ok_or(ProvisioningContractError::LimitExceeded(
                    "namespace ciphertext bytes",
                ))?;
        frame(&mut output, 16, b"entry")?;
        frame(&mut output, 17, &entry.name)?;
        frame(&mut output, 18, &[file_type_code(entry.file_type)])?;
        frame_u64(&mut output, 19, u64::from(entry.uid))?;
        frame_u64(&mut output, 20, u64::from(entry.gid))?;
        frame_u64(&mut output, 21, u64::from(entry.mode))?;
        frame_u64(&mut output, 22, entry.nlink)?;
        frame_u64(&mut output, 23, entry.size)?;
        let digest = hex_decode(entry.ciphertext_sha256.as_str())?;
        frame(&mut output, 24, &digest)?;
        frame(&mut output, 25, &[entry.classification.code()])?;
    }
    frame_u64(
        &mut output,
        32,
        u64::try_from(inventory.entries.len())
            .map_err(|_| ProvisioningContractError::LimitExceeded("namespace entry count"))?,
    )?;
    frame_u64(&mut output, 33, total_bytes)?;
    Ok(output)
}

pub fn namespace_fingerprint(
    inventory: &NamespaceInventoryV1,
) -> Result<NamespaceFingerprintV1, ProvisioningContractError> {
    let frame = encode_namespace_fingerprint_frame(inventory)?;
    let ciphertext_bytes = inventory.entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.size)
            .ok_or(ProvisioningContractError::LimitExceeded(
                "namespace ciphertext bytes",
            ))
    })?;
    let fingerprint = NamespaceFingerprintV1 {
        sha256: Sha256Digest::from_bytes(&frame),
        entry_count: u64::try_from(inventory.entries.len())
            .map_err(|_| ProvisioningContractError::LimitExceeded("namespace entry count"))?,
        ciphertext_bytes,
    };
    fingerprint.validate()?;
    Ok(fingerprint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingProvisioningConfig {
    Absent,
    Explicit { mode: u8, epoch: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingProvisioningArtifact {
    Absent,
    Verified,
    Unverified,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningStateInput {
    pub config: ExistingProvisioningConfig,
    pub artifact: ExistingProvisioningArtifact,
    pub namespace_nonempty: bool,
    pub new_key_requested: bool,
    pub adopt_existing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    Fresh,
    Adopt,
    Idempotent,
    Unadopted,
    Mismatch,
    Missing,
    Nonempty,
    NewKey,
    DifferentMode(DifferentModeArtifactState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentModeArtifactState {
    Absent,
    Receipted,
    Unadopted,
    Mismatch,
}

impl ProvisioningState {
    pub const fn permits_automatic_provisioning(self) -> bool {
        matches!(self, Self::Fresh | Self::Adopt | Self::Idempotent)
    }
}

pub const fn classify_provisioning_state(input: ProvisioningStateInput) -> ProvisioningState {
    if input.namespace_nonempty
        && input.new_key_requested
        && !matches!(
            input.config,
            ExistingProvisioningConfig::Explicit { mode, .. } if mode != 1
        )
    {
        return ProvisioningState::NewKey;
    }
    match input.config {
        ExistingProvisioningConfig::Explicit { mode, .. } if mode != 1 => match input.artifact {
            ExistingProvisioningArtifact::Absent => {
                ProvisioningState::DifferentMode(DifferentModeArtifactState::Absent)
            }
            ExistingProvisioningArtifact::Verified => {
                ProvisioningState::DifferentMode(DifferentModeArtifactState::Receipted)
            }
            ExistingProvisioningArtifact::Unverified => {
                ProvisioningState::DifferentMode(DifferentModeArtifactState::Unadopted)
            }
            ExistingProvisioningArtifact::Mismatch => {
                ProvisioningState::DifferentMode(DifferentModeArtifactState::Mismatch)
            }
        },
        ExistingProvisioningConfig::Explicit { mode: 1, epoch } if epoch != MODE1_KEY_EPOCH => {
            ProvisioningState::Mismatch
        }
        ExistingProvisioningConfig::Absent => match input.artifact {
            ExistingProvisioningArtifact::Absent if !input.namespace_nonempty => {
                ProvisioningState::Fresh
            }
            ExistingProvisioningArtifact::Verified | ExistingProvisioningArtifact::Unverified => {
                if input.adopt_existing {
                    ProvisioningState::Adopt
                } else {
                    ProvisioningState::Unadopted
                }
            }
            ExistingProvisioningArtifact::Mismatch => ProvisioningState::Mismatch,
            ExistingProvisioningArtifact::Absent => ProvisioningState::Nonempty,
        },
        ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 } => match input.artifact {
            ExistingProvisioningArtifact::Verified => ProvisioningState::Idempotent,
            ExistingProvisioningArtifact::Absent => ProvisioningState::Missing,
            ExistingProvisioningArtifact::Unverified => {
                if input.adopt_existing {
                    ProvisioningState::Adopt
                } else if input.namespace_nonempty {
                    ProvisioningState::Nonempty
                } else {
                    ProvisioningState::Mismatch
                }
            }
            ExistingProvisioningArtifact::Mismatch => ProvisioningState::Mismatch,
        },
        ExistingProvisioningConfig::Explicit { .. } => ProvisioningState::Mismatch,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableRollbackTarget {
    ActiveRunning,
    ActiveListening,
    InactiveDead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitObservation {
    pub unit_kind: UnitKind,
    pub load_state: UnitLoadState,
    pub active_state: UnitActiveState,
    pub sub_state: UnitSubState,
    pub unit_file_state: UnitFileState,
    pub has_queued_job: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitAdmissibility {
    Settle,
    RefuseMasked,
    RefuseFailed,
    RefuseUnstable,
    Admissible {
        rollback_target: StableRollbackTarget,
        mutate_enablement: bool,
    },
}

pub fn classify_unit_admissibility(unit: UnitObservation) -> UnitAdmissibility {
    if unit.load_state == UnitLoadState::Masked || unit.unit_file_state.is_masked() {
        return UnitAdmissibility::RefuseMasked;
    }
    if unit.active_state == UnitActiveState::Failed || unit.sub_state == UnitSubState::Failed {
        return UnitAdmissibility::RefuseFailed;
    }
    if unit.has_queued_job
        || matches!(
            unit.active_state,
            UnitActiveState::Activating
                | UnitActiveState::Deactivating
                | UnitActiveState::Reloading
        )
    {
        return UnitAdmissibility::Settle;
    }
    if unit.load_state != UnitLoadState::Loaded || !unit.unit_file_state.is_admissible() {
        return UnitAdmissibility::RefuseUnstable;
    }
    let rollback_target = match (unit.unit_kind, unit.active_state, unit.sub_state) {
        (UnitKind::Service, UnitActiveState::Active, UnitSubState::Running) => {
            StableRollbackTarget::ActiveRunning
        }
        (UnitKind::Socket, UnitActiveState::Active, UnitSubState::Listening) => {
            StableRollbackTarget::ActiveListening
        }
        (_, UnitActiveState::Inactive, UnitSubState::Dead) => StableRollbackTarget::InactiveDead,
        _ => return UnitAdmissibility::RefuseUnstable,
    };
    UnitAdmissibility::Admissible {
        rollback_target,
        mutate_enablement: false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupReferences {
    pub config: bool,
    pub receipt: bool,
    pub dropin: bool,
    pub journal: bool,
    pub active_transaction: bool,
    pub effective_unit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupPreAdmissionV1 {
    pub observed_artifact: CleanupArtifactIdentityV1,
    pub references: CleanupReferences,
    pub service: UnitObservation,
    pub socket: UnitObservation,
    pub readiness_transient_exists: bool,
    pub daemon_responded: bool,
    pub effective_units: EffectiveUnitSetV1,
}

impl CleanupPreAdmissionV1 {
    fn validate(
        &self,
        expected_artifact: &CleanupArtifactIdentityV1,
    ) -> Result<(), ProvisioningContractError> {
        if self.effective_units.service.unit_kind != UnitKind::Service
            || self.effective_units.socket.unit_kind != UnitKind::Socket
            || classify_cleanup_admissibility(CleanupStateInput {
                expected_artifact: ExpectedCleanupArtifactIdentityV1(expected_artifact.clone()),
                observed_artifact: ObservedCleanupArtifactIdentityV1(
                    self.observed_artifact.clone(),
                ),
                references: self.references,
                service: self.service,
                socket: self.socket,
                readiness_transient_exists: self.readiness_transient_exists,
                daemon_responded: self.daemon_responded,
            }) != CleanupAdmissibility::Admissible
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup pre-admission",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentityV1 {
    pub path: String,
    pub object_type: FileObjectType,
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub link_count: u64,
}

impl DirectoryIdentityV1 {
    fn validate_shape(&self) -> Result<(), ProvisioningContractError> {
        validate_absolute_path(&self.path, "credential directory path")?;
        if self.device_id == 0
            || self.inode == 0
            || self.permissions & !0o7777 != 0
            || self.link_count == 0
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "credential directory identity",
            ));
        }
        Ok(())
    }

    fn validate_expected(&self) -> Result<(), ProvisioningContractError> {
        self.validate_shape()?;
        if self.path != MODE1_CREDENTIAL_DIRECTORY || self.object_type != FileObjectType::Directory
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "credential directory identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialArtifactSourceIdentityV1 {
    pub credential_name: String,
    pub envelope_sha256: Sha256Digest,
    pub envelope_size: u64,
    pub actual_key_id: SystemdCredentialKeyId,
}

impl CredentialArtifactSourceIdentityV1 {
    fn validate_shape(&self) -> Result<(), ProvisioningContractError> {
        validate_safe_name(&self.credential_name, 128, "credential source name")?;
        if self.envelope_size == 0
            || self.envelope_size > SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX as u64
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "credential source identity",
            ));
        }
        self.envelope_sha256.validate()
    }

    fn validate_expected(&self) -> Result<(), ProvisioningContractError> {
        self.validate_shape()?;
        if self.credential_name != MODE1_CREDENTIAL_NAME {
            return Err(ProvisioningContractError::InvalidSchema(
                "credential source identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorIdentityV1 {
    pub path: String,
    pub device_id: u64,
    pub inode: u64,
    pub sha256: Sha256Digest,
    pub byte_length: u64,
    pub object_type: FileObjectType,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub link_count: u64,
    pub parent_directory: DirectoryIdentityV1,
}

impl ArtifactDescriptorIdentityV1 {
    fn validate_shape(&self) -> Result<(), ProvisioningContractError> {
        validate_absolute_path(&self.path, "cleanup artifact path")?;
        if self.byte_length == 0
            || self.byte_length > SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX as u64
            || self.device_id == 0
            || self.inode == 0
            || self.permissions & !0o7777 != 0
            || self.link_count == 0
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup artifact descriptor",
            ));
        }
        self.sha256.validate()?;
        self.parent_directory.validate_shape()
    }

    fn validate_expected(&self) -> Result<(), ProvisioningContractError> {
        self.validate_shape()?;
        if self.path != MODE1_CREDENTIAL_PATH
            || self.object_type != FileObjectType::RegularFile
            || self.uid != 0
            || self.gid != 0
            || self.permissions != 0o600
            || self.link_count != 1
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup artifact descriptor",
            ));
        }
        self.parent_directory.validate_expected()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupArtifactIdentityV1 {
    pub transaction_id: String,
    pub descriptor: ArtifactDescriptorIdentityV1,
    pub source: CredentialArtifactSourceIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnadoptedArtifactV1 {
    pub schema_version: u16,
    pub identity: CleanupArtifactIdentityV1,
}

impl UnadoptedArtifactV1 {
    pub fn new(identity: CleanupArtifactIdentityV1) -> Result<Self, ProvisioningContractError> {
        let manifest = Self {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            identity,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ProvisioningContractError> {
        parse_bounded_json(bytes, MAX_RECEIPT_BYTES, "unadopted manifest bytes")
            .and_then(|value: Self| value.validated())
    }

    pub fn deterministic_bytes(&self) -> Result<Vec<u8>, ProvisioningContractError> {
        self.validate()?;
        canonical_json(self, MAX_RECEIPT_BYTES, "unadopted manifest bytes")
    }

    pub fn validated(self) -> Result<Self, ProvisioningContractError> {
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ProvisioningContractError> {
        if self.schema_version != PROVISIONING_SCHEMA_VERSION {
            return Err(ProvisioningContractError::InvalidSchema(
                "unadopted manifest version",
            ));
        }
        self.identity.validate_expected()
    }
}

impl CleanupArtifactIdentityV1 {
    fn validate_expected(&self) -> Result<(), ProvisioningContractError> {
        validate_transaction_id_v1(&self.transaction_id, "cleanup transaction id")?;
        self.descriptor.validate_expected()?;
        self.source.validate_expected()?;
        if self.source.envelope_size > self.descriptor.byte_length {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup artifact source size",
            ));
        }
        Ok(())
    }

    fn validate_observed(&self) -> Result<(), ProvisioningContractError> {
        validate_transaction_id_v1(&self.transaction_id, "cleanup transaction id")?;
        self.descriptor.validate_shape()?;
        self.source.validate_shape()?;
        if self.source.envelope_size > self.descriptor.byte_length {
            return Err(ProvisioningContractError::InvalidSchema(
                "cleanup artifact source size",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedCleanupArtifactIdentityV1(pub CleanupArtifactIdentityV1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCleanupArtifactIdentityV1(pub CleanupArtifactIdentityV1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupStateInput {
    pub expected_artifact: ExpectedCleanupArtifactIdentityV1,
    pub observed_artifact: ObservedCleanupArtifactIdentityV1,
    pub references: CleanupReferences,
    pub service: UnitObservation,
    pub socket: UnitObservation,
    pub readiness_transient_exists: bool,
    pub daemon_responded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupRefusal {
    ExpectedIdentityInvalid,
    ObservedIdentityInvalid,
    TransactionMismatch,
    PathMismatch,
    ObjectIdentityMismatch,
    HashMismatch,
    LengthMismatch,
    TypeMismatch,
    OwnershipMismatch,
    ModeMismatch,
    LinkMismatch,
    DirectoryMismatch,
    SourceMismatch,
    ConfigReference,
    ReceiptReference,
    DropinReference,
    JournalReference,
    ActiveTransaction,
    EffectiveUnitReference,
    UnitNotInactive,
    UnitUnstable,
    UnitTransitional,
    UnitJobQueued,
    ReadinessTransient,
    DaemonReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupAdmissibility {
    Admissible,
    Refuse(CleanupRefusal),
}

pub fn classify_cleanup_admissibility(input: CleanupStateInput) -> CleanupAdmissibility {
    let expected = &input.expected_artifact.0;
    let observed = &input.observed_artifact.0;
    if expected.validate_expected().is_err() {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ExpectedIdentityInvalid);
    }
    if observed.validate_observed().is_err() {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ObservedIdentityInvalid);
    }
    if expected.transaction_id != observed.transaction_id {
        return CleanupAdmissibility::Refuse(CleanupRefusal::TransactionMismatch);
    }
    if expected.descriptor.path != observed.descriptor.path {
        return CleanupAdmissibility::Refuse(CleanupRefusal::PathMismatch);
    }
    if expected.descriptor.device_id != observed.descriptor.device_id
        || expected.descriptor.inode != observed.descriptor.inode
    {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ObjectIdentityMismatch);
    }
    if expected.descriptor.sha256 != observed.descriptor.sha256 {
        return CleanupAdmissibility::Refuse(CleanupRefusal::HashMismatch);
    }
    if expected.descriptor.byte_length != observed.descriptor.byte_length {
        return CleanupAdmissibility::Refuse(CleanupRefusal::LengthMismatch);
    }
    if expected.descriptor.object_type != observed.descriptor.object_type {
        return CleanupAdmissibility::Refuse(CleanupRefusal::TypeMismatch);
    }
    if expected.descriptor.uid != observed.descriptor.uid
        || expected.descriptor.gid != observed.descriptor.gid
    {
        return CleanupAdmissibility::Refuse(CleanupRefusal::OwnershipMismatch);
    }
    if expected.descriptor.permissions != observed.descriptor.permissions {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ModeMismatch);
    }
    if expected.descriptor.link_count != observed.descriptor.link_count {
        return CleanupAdmissibility::Refuse(CleanupRefusal::LinkMismatch);
    }
    if expected.descriptor.parent_directory != observed.descriptor.parent_directory {
        return CleanupAdmissibility::Refuse(CleanupRefusal::DirectoryMismatch);
    }
    if expected.source != observed.source {
        return CleanupAdmissibility::Refuse(CleanupRefusal::SourceMismatch);
    }
    if input.references.config {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ConfigReference);
    }
    if input.references.receipt {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ReceiptReference);
    }
    if input.references.dropin {
        return CleanupAdmissibility::Refuse(CleanupRefusal::DropinReference);
    }
    if input.references.journal {
        return CleanupAdmissibility::Refuse(CleanupRefusal::JournalReference);
    }
    if input.references.active_transaction {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ActiveTransaction);
    }
    if input.references.effective_unit {
        return CleanupAdmissibility::Refuse(CleanupRefusal::EffectiveUnitReference);
    }
    if input.readiness_transient_exists {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ReadinessTransient);
    }
    if input.daemon_responded {
        return CleanupAdmissibility::Refuse(CleanupRefusal::DaemonReference);
    }
    if input.service.unit_kind != UnitKind::Service || input.socket.unit_kind != UnitKind::Socket {
        return CleanupAdmissibility::Refuse(CleanupRefusal::UnitUnstable);
    }
    for unit in [input.service, input.socket] {
        if unit.has_queued_job {
            return CleanupAdmissibility::Refuse(CleanupRefusal::UnitJobQueued);
        }
        if matches!(
            unit.active_state,
            UnitActiveState::Activating
                | UnitActiveState::Deactivating
                | UnitActiveState::Reloading
        ) {
            return CleanupAdmissibility::Refuse(CleanupRefusal::UnitTransitional);
        }
        if unit.load_state != UnitLoadState::Loaded
            || !unit.unit_file_state.is_admissible()
            || unit.active_state == UnitActiveState::Failed
            || unit.sub_state == UnitSubState::Failed
        {
            return CleanupAdmissibility::Refuse(CleanupRefusal::UnitUnstable);
        }
        if unit.active_state != UnitActiveState::Inactive || unit.sub_state != UnitSubState::Dead {
            return CleanupAdmissibility::Refuse(CleanupRefusal::UnitNotInactive);
        }
    }
    CleanupAdmissibility::Admissible
}

fn validate_mode1_identity(
    mode: u8,
    epoch: u64,
    credential_name: &str,
) -> Result<(), ProvisioningContractError> {
    if mode != 1 || epoch != MODE1_KEY_EPOCH || credential_name != MODE1_CREDENTIAL_NAME {
        return Err(ProvisioningContractError::InvalidSchema("mode-1 identity"));
    }
    Ok(())
}

fn validate_phase_hash(
    required: bool,
    actual: Option<&Sha256Digest>,
    expected: &Sha256Digest,
) -> Result<(), ProvisioningContractError> {
    if (required && actual != Some(expected)) || (!required && actual.is_some()) {
        return Err(ProvisioningContractError::InvalidSchema(
            "journal phase hash",
        ));
    }
    Ok(())
}

fn validate_optional_digests<'a>(
    digests: impl IntoIterator<Item = Option<&'a Sha256Digest>>,
) -> Result<(), ProvisioningContractError> {
    for digest in digests.into_iter().flatten() {
        digest.validate()?;
    }
    Ok(())
}

fn parse_bounded_json<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    field: &'static str,
) -> Result<T, ProvisioningContractError> {
    if bytes.len() > maximum {
        return Err(ProvisioningContractError::LimitExceeded(field));
    }
    serde_json::from_slice(bytes).map_err(|_| ProvisioningContractError::InvalidJson)
}

fn canonical_json<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, ProvisioningContractError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProvisioningContractError::InvalidJson)?;
    if bytes.len() > maximum {
        return Err(ProvisioningContractError::LimitExceeded(field));
    }
    Ok(bytes)
}

fn validate_safe_name(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProvisioningContractError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProvisioningContractError::InvalidSchema(field));
    }
    Ok(())
}

fn validate_transaction_id_v1(
    value: &str,
    field: &'static str,
) -> Result<(), ProvisioningContractError> {
    let Some(suffix) = value.strip_prefix("txn-") else {
        return Err(ProvisioningContractError::InvalidSchema(field));
    };
    if value.len() > MAX_TRANSACTION_ID_BYTES
        || suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProvisioningContractError::InvalidSchema(field));
    }
    Ok(())
}

fn validate_prior_daemon_invocation(
    service: &StableUnitState,
    invocation_id: Option<&str>,
) -> Result<(), ProvisioningContractError> {
    let service_was_active = service.rollback_target() == Some(StableRollbackTarget::ActiveRunning);
    if service_was_active != invocation_id.is_some() {
        return Err(ProvisioningContractError::InvalidSchema(
            "prior daemon invocation presence",
        ));
    }
    if let Some(value) = invocation_id
        && !is_lower_hex(value, 64)
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "prior daemon invocation id",
        ));
    }
    Ok(())
}

fn validate_journal_guard(
    transaction_id: &str,
    required: bool,
    guard: Option<&TransactionGuardIdentityV1>,
) -> Result<(), ProvisioningContractError> {
    if required != guard.is_some() {
        return Err(ProvisioningContractError::InvalidSchema(
            "journal guard presence",
        ));
    }
    if let Some(guard) = guard {
        guard.validate(transaction_id)?;
    }
    Ok(())
}

fn validate_prior_journal_identity(
    generation: u64,
    prior: Option<&AtomicFileIdentityV1>,
) -> Result<(), ProvisioningContractError> {
    if (generation == 1) != prior.is_none() {
        return Err(ProvisioningContractError::InvalidSchema(
            "prior journal identity presence",
        ));
    }
    if let Some(prior) = prior {
        prior.validate()?;
        if prior.uid != 0 || prior.gid != 0 || prior.permissions != 0o600 {
            return Err(ProvisioningContractError::InvalidSchema(
                "prior journal identity metadata",
            ));
        }
    }
    Ok(())
}

fn validate_guard_transition(
    current: &Option<TransactionGuardIdentityV1>,
    next: &Option<TransactionGuardIdentityV1>,
    same_phase: bool,
) -> bool {
    match (current, next) {
        (None, None) | (Some(_), None) => current == next,
        (None, Some(_)) => true,
        (Some(left), Some(right)) => left == right || same_phase,
    }
}

fn validate_atomic_write_records(
    transaction_id: &str,
    transaction_owned_paths: &[String],
    records: &[AtomicWriteRecordV1],
) -> Result<(), ProvisioningContractError> {
    if records.len() > MAX_TRANSACTION_OWNED_PATHS {
        return Err(ProvisioningContractError::LimitExceeded(
            "atomic write records",
        ));
    }
    for (index, record) in records.iter().enumerate() {
        record.validate()?;
        if record.plan.transaction_id != transaction_id {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic write transaction binding",
            ));
        }
        if transaction_owned_paths
            .binary_search(&record.plan.staging_path)
            .is_err()
            || record
                .plan
                .backup_path
                .as_ref()
                .is_some_and(|backup| transaction_owned_paths.binary_search(backup).is_err())
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic transaction-owned path",
            ));
        }
        if records[index + 1..].iter().any(|later| {
            later.plan.staging_path == record.plan.staging_path
                && !matches!(&record.state, AtomicWriteStateV1::BackupCleaned { .. })
                && !matches!(&record.state, AtomicWriteStateV1::Aborted)
        }) {
            return Err(ProvisioningContractError::InvalidSchema(
                "atomic staging path reuse",
            ));
        }
    }
    Ok(())
}

fn validate_atomic_owned_paths_transition(
    current_paths: &[String],
    next_paths: &[String],
    current_records: &[AtomicWriteRecordV1],
    next_records: &[AtomicWriteRecordV1],
) -> bool {
    if next_records.len() == current_records.len() + 1
        && next_records[..current_records.len()] == current_records[..]
    {
        let mut expected = current_paths.to_vec();
        let plan = &next_records.last().expect("length checked").plan;
        expected.push(plan.staging_path.clone());
        if let Some(backup) = &plan.backup_path {
            expected.push(backup.clone());
        }
        expected.sort();
        expected.dedup();
        expected == next_paths
    } else {
        current_paths == next_paths
    }
}

fn validate_atomic_write_records_transition(
    current: &[AtomicWriteRecordV1],
    next: &[AtomicWriteRecordV1],
) -> bool {
    if next.len() == current.len() + 1
        && next[..current.len()] == *current
        && matches!(
            next.last().map(|record| &record.state),
            Some(AtomicWriteStateV1::Planned)
        )
    {
        return true;
    }
    if next.len() != current.len() {
        return false;
    }
    let changed: Vec<_> = current
        .iter()
        .zip(next)
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .collect();
    if changed.len() != 1 {
        return false;
    }
    let (_, (left, right)) = changed[0];
    if left.plan != right.plan {
        return false;
    }
    match (&left.state, &right.state) {
        (AtomicWriteStateV1::Planned, AtomicWriteStateV1::Staged { identity }) => {
            validate_atomic_staged_identity(&left.plan, identity).is_ok()
        }
        (AtomicWriteStateV1::Planned, AtomicWriteStateV1::Aborted) => true,
        (
            AtomicWriteStateV1::Staged { identity },
            AtomicWriteStateV1::Committed { observation },
        ) => observation.target == *identity && observation.validate_for_plan(&left.plan).is_ok(),
        (AtomicWriteStateV1::Staged { .. }, AtomicWriteStateV1::Aborted) => true,
        (
            AtomicWriteStateV1::Committed { observation: left },
            AtomicWriteStateV1::BackupCleaned { observation: right },
        ) => left == right && left.backup.is_some(),
        _ => false,
    }
}

fn validate_bounded_printable(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProvisioningContractError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| matches!(byte, b' '..=b'~'))
    {
        return Err(ProvisioningContractError::InvalidSchema(field));
    }
    Ok(())
}

fn validate_absolute_path(
    value: &str,
    field: &'static str,
) -> Result<(), ProvisioningContractError> {
    if value.is_empty() || value.len() > MAX_PATH_BYTES || value.as_bytes().contains(&0) {
        return Err(ProvisioningContractError::InvalidSchema(field));
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || value.contains("//")
    {
        return Err(ProvisioningContractError::InvalidSchema(field));
    }
    Ok(())
}

fn validate_paths(paths: &[String]) -> Result<(), ProvisioningContractError> {
    if paths.is_empty() || paths.len() > MAX_TRANSACTION_OWNED_PATHS {
        return Err(ProvisioningContractError::LimitExceeded(
            "transaction-owned paths",
        ));
    }
    let mut previous: Option<&str> = None;
    for path in paths {
        validate_absolute_path(path, "transaction-owned path")?;
        if previous.is_some_and(|value| value >= path.as_str()) {
            return Err(ProvisioningContractError::InvalidSchema(
                "transaction-owned path ordering",
            ));
        }
        previous = Some(path);
    }
    Ok(())
}

fn validate_owned_journal_staging_path(
    paths: &[String],
    journal_staging_path: &str,
) -> Result<(), ProvisioningContractError> {
    if paths
        .binary_search_by(|candidate| candidate.as_str().cmp(journal_staging_path))
        .is_err()
    {
        return Err(ProvisioningContractError::InvalidSchema(
            "transaction-owned journal staging path",
        ));
    }
    Ok(())
}

fn validate_transient_unit(value: &str) -> Result<(), ProvisioningContractError> {
    validate_safe_name(value, 128, "transient unit")?;
    if !value.starts_with("howy-readiness-") || !value.ends_with(".service") {
        return Err(ProvisioningContractError::InvalidSchema("transient unit"));
    }
    Ok(())
}

fn validate_disabled_token_layout(
    source: &str,
    span: &Range<usize>,
) -> Result<(), ProvisioningContractError> {
    let line_start = source[..span.start]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    let line_end = source[span.end..]
        .find('\n')
        .map_or(source.len(), |position| span.end + position);
    let prefix = &source[line_start..span.start];
    let suffix = &source[span.end..line_end];
    let mut prefix_parts = prefix.split('=');
    let key = prefix_parts.next().unwrap_or_default().trim();
    let before_value = prefix_parts.next().unwrap_or_default();
    if prefix_parts.next().is_some()
        || key != "disabled"
        || !before_value
            .bytes()
            .all(|byte| matches!(byte, b' ' | b'\t'))
    {
        return Err(ProvisioningContractError::AmbiguousDisabledLiteral);
    }
    let suffix = suffix.trim_start_matches([' ', '\t']);
    if !suffix.is_empty() && !suffix.starts_with('#') {
        return Err(ProvisioningContractError::AmbiguousDisabledLiteral);
    }

    let mut active_header = None;
    for line in source[..line_start].lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let code = trimmed.split('#').next().unwrap_or_default().trim();
            active_header = Some(code);
        }
    }
    if active_header != Some("[core]") {
        return Err(ProvisioningContractError::AmbiguousDisabledLiteral);
    }
    Ok(())
}

fn credential_key_id(id: [u8; 16]) -> Result<SystemdCredentialKeyId, ProvisioningContractError> {
    // systemd v261 src/shared/creds-util.h.
    const HOST: [u8; 16] = [
        0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1,
        0x9a,
    ];
    const TPM2: [u8; 16] = [
        0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91, 0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20,
        0xfe,
    ];
    const HOST_TPM2: [u8; 16] = [
        0x93, 0xa8, 0x94, 0x09, 0x48, 0x74, 0x44, 0x90, 0x90, 0xca, 0xf2, 0xfc, 0x93, 0xca, 0xb5,
        0x53,
    ];
    match id {
        HOST => Ok(SystemdCredentialKeyId::Host),
        TPM2 => Ok(SystemdCredentialKeyId::Tpm2Hmac),
        HOST_TPM2 => Ok(SystemdCredentialKeyId::HostAndTpm2Hmac),
        _ => Err(ProvisioningContractError::CredentialPolicyRejected),
    }
}

fn decode_base64_strict(input: &[u8]) -> Result<Vec<u8>, ProvisioningContractError> {
    let mut symbols = Vec::with_capacity(input.len());
    for &byte in input {
        if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if base64_value(byte).is_some() || byte == b'=' {
            symbols.push(byte);
        } else {
            return Err(ProvisioningContractError::InvalidCredentialEnvelope);
        }
    }
    if symbols.is_empty() || symbols.len() % 4 != 0 {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }
    let padding = symbols
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'=')
        .count();
    if padding > 2 || symbols[..symbols.len() - padding].contains(&b'=') {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }
    let decoded_len = symbols
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| bytes.checked_sub(padding))
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    if decoded_len > SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX {
        return Err(ProvisioningContractError::LimitExceeded(
            "credential envelope bytes",
        ));
    }
    let mut output = Vec::with_capacity(decoded_len);
    for (index, chunk) in symbols.chunks_exact(4).enumerate() {
        let last = index + 1 == symbols.len() / 4;
        let a =
            base64_value(chunk[0]).ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
        let b =
            base64_value(chunk[1]).ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
        let c = if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || (b & 0x0f) != 0 {
                return Err(ProvisioningContractError::InvalidCredentialEnvelope);
            }
            0
        } else {
            base64_value(chunk[2]).ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?
        };
        let d = if chunk[3] == b'=' {
            if !last || chunk[2] == b'=' && padding != 2 || (c & 0x03) != 0 {
                return Err(ProvisioningContractError::InvalidCredentialEnvelope);
            }
            0
        } else {
            base64_value(chunk[3]).ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?
        };
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    if output.len() != decoded_len {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn align8(value: usize) -> Result<usize, ProvisioningContractError> {
    value
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)
}

fn validate_zero_padding(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<(), ProvisioningContractError> {
    if bytes
        .get(start..end)
        .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(ProvisioningContractError::InvalidCredentialEnvelope);
    }
    Ok(())
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, ProvisioningContractError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, ProvisioningContractError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64, ProvisioningContractError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProvisioningContractError::InvalidCredentialEnvelope)?;
    Ok(u64::from_le_bytes(raw))
}

fn validate_inventory(inventory: &NamespaceInventoryV1) -> Result<(), ProvisioningContractError> {
    validate_absolute_path(&inventory.directory.path, "namespace path")?;
    if inventory.entries.len() > MAX_NAMESPACE_ENTRIES {
        return Err(ProvisioningContractError::LimitExceeded(
            "namespace entry count",
        ));
    }
    let mut names: Vec<&[u8]> = Vec::with_capacity(inventory.entries.len());
    let mut total = 0u64;
    for entry in &inventory.entries {
        if entry.name.is_empty() || entry.name.len() > MAX_NAMESPACE_NAME_BYTES {
            return Err(ProvisioningContractError::LimitExceeded(
                "namespace entry name",
            ));
        }
        entry.ciphertext_sha256.validate()?;
        if entry.size > MAX_NAMESPACE_CIPHERTEXT_BYTES {
            return Err(ProvisioningContractError::LimitExceeded(
                "namespace entry bytes",
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or(ProvisioningContractError::LimitExceeded(
                "namespace ciphertext bytes",
            ))?;
        if total > MAX_NAMESPACE_TOTAL_BYTES {
            return Err(ProvisioningContractError::LimitExceeded(
                "namespace ciphertext bytes",
            ));
        }
        if classify_mode1_namespace_entry(&entry.name, entry.file_type, entry.nlink)
            != entry.classification
        {
            return Err(ProvisioningContractError::InvalidNamespaceInventory);
        }
        names.push(&entry.name);
    }
    names.sort_unstable();
    if names.windows(2).any(|window| window[0] == window[1]) {
        return Err(ProvisioningContractError::InvalidNamespaceInventory);
    }
    Ok(())
}

fn frame(output: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), ProvisioningContractError> {
    output.push(tag);
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| ProvisioningContractError::LimitExceeded("fingerprint frame"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn frame_u64(output: &mut Vec<u8>, tag: u8, value: u64) -> Result<(), ProvisioningContractError> {
    frame(output, tag, &value.to_le_bytes())
}

const fn file_type_code(file_type: NamespaceFileType) -> u8 {
    match file_type {
        NamespaceFileType::Regular => 1,
        NamespaceFileType::Directory => 2,
        NamespaceFileType::Symlink => 3,
        NamespaceFileType::Other => 4,
    }
}

const fn file_object_type_code(file_type: FileObjectType) -> u8 {
    match file_type {
        FileObjectType::RegularFile => 1,
        FileObjectType::Directory => 2,
        FileObjectType::Symlink => 3,
        FileObjectType::Other => 4,
    }
}

const fn file_link_policy_code(policy: FileLinkPolicy) -> u8 {
    match policy {
        FileLinkPolicy::ExactlyOne => 1,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ProvisioningContractError> {
    if !value.len().is_multiple_of(2) || !is_lower_hex(value, value.len()) {
        return Err(ProvisioningContractError::InvalidSchema("hex bytes"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0])?;
            let low = hex_value(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_value(byte: u8) -> Result<u8, ProvisioningContractError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ProvisioningContractError::InvalidSchema("hex bytes")),
    }
}

fn is_lower_hex(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests;
