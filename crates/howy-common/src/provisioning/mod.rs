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
pub const SECURITY_STATE_DIRECTORY: &str = "/etc/howy/security-state";
pub const SECURITY_LOCK_PATH: &str = "/etc/howy/security-state/lock";
pub const SECURITY_JOURNAL_PATH: &str = "/etc/howy/security-state/transaction-v1.json";
pub const SECURITY_RECEIPT_PATH: &str = "/etc/howy/security-state/receipt-v1.json";
pub const SECURITY_UNADOPTED_DIRECTORY: &str = "/etc/howy/security-state/unadopted";
pub const SECURITY_TRANSACTION_GUARD_PATH: &str = "/etc/howy/.security-transaction";
pub const MODE1_DROPIN_PATH: &str =
    "/etc/systemd/system/howy.service.d/60-howy-mode1-credential.conf";
pub const BASE_SERVICE_UNIT_PATH: &str = "/usr/lib/systemd/system/howy.service";

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
    EnabledConfigCommitted,
    ActivationCommitted,
    UnitsStarted,
    EnabledReceiptCommitted,
}

impl JournalPhase {
    pub const ALL: [Self; 12] = [
        Self::Prepared,
        Self::Guarded,
        Self::UnitsStopped,
        Self::ArtifactCommitted,
        Self::DropinCommitted,
        Self::DisabledConfigCommitted,
        Self::ReadinessVerified,
        Self::DisabledReceiptCommitted,
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
            Self::EnabledConfigCommitted => 8,
            Self::ActivationCommitted => 9,
            Self::UnitsStarted => 10,
            Self::EnabledReceiptCommitted => 11,
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
        JournalPhase::DisabledReceiptCommitted => RecoveryAction::CompleteDisabledProvisioning,
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
    pub phase: JournalPhase,
    pub mode: u8,
    pub epoch: u64,
    pub credential_name: String,
    pub planned_hashes: PlannedObjectHashes,
    pub live_hashes: LiveObjectHashes,
    pub transaction_owned_paths: Vec<String>,
    pub artifact_preexisted: bool,
    pub transient_unit: String,
    pub prior_config: Option<ExactFileSnapshot>,
    pub prior_dropin: Option<ExactFileSnapshot>,
    pub prior_receipt: Option<ExactFileSnapshot>,
    pub service_unit_state: StableUnitState,
    pub socket_unit_state: StableUnitState,
    pub backup_hashes: BackupHashes,
    pub recovery_action: RecoveryAction,
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
        validate_safe_name(
            &self.transaction_id,
            MAX_TRANSACTION_ID_BYTES,
            "transaction id",
        )?;
        validate_mode1_identity(self.mode, self.epoch, &self.credential_name)?;
        self.planned_hashes.validate()?;
        validate_paths(&self.transaction_owned_paths)?;
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
            && self.mode == next.mode
            && self.epoch == next.epoch
            && self.credential_name == next.credential_name
            && self.planned_hashes == next.planned_hashes
            && self.transaction_owned_paths == next.transaction_owned_paths
            && self.artifact_preexisted == next.artifact_preexisted
            && self.transient_unit == next.transient_unit
            && self.prior_config == next.prior_config
            && self.prior_dropin == next.prior_dropin
            && self.prior_receipt == next.prior_receipt
            && self.service_unit_state == next.service_unit_state
            && self.socket_unit_state == next.socket_unit_state
            && self.backup_hashes == next.backup_hashes
    }
}

pub fn validate_journal_transition(
    current: &ProvisioningJournalV1,
    next: &ProvisioningJournalV1,
) -> Result<(), ProvisioningContractError> {
    current.validate()?;
    next.validate()?;
    if current.phase.next() != Some(next.phase) || !current.stable_fields_equal(next) {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaintextProvisioningJournalV1 {
    pub schema_version: u16,
    pub transaction_id: String,
    pub phase: PlaintextJournalPhase,
    pub enabled_config_sha256: Sha256Digest,
    pub live_config_sha256: Option<Sha256Digest>,
    pub prior_config: Option<ExactFileSnapshot>,
    pub prior_dropin: Option<ExactFileSnapshot>,
    pub service_unit_state: StableUnitState,
    pub socket_unit_state: StableUnitState,
    pub recovery_action: PlaintextRecoveryAction,
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
        validate_safe_name(
            &self.transaction_id,
            MAX_TRANSACTION_ID_BYTES,
            "transaction id",
        )?;
        self.enabled_config_sha256.validate()?;
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
        if self.service_unit_state.unit_kind != UnitKind::Service
            || self.socket_unit_state.unit_kind != UnitKind::Socket
            || self.recovery_action != plaintext_recovery_action_for_phase(self.phase)
        {
            return Err(ProvisioningContractError::InvalidSchema(
                "plaintext journal state",
            ));
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
            && self.enabled_config_sha256 == next.enabled_config_sha256
            && self.prior_config == next.prior_config
            && self.prior_dropin == next.prior_dropin
            && self.service_unit_state == next.service_unit_state
            && self.socket_unit_state == next.socket_unit_state
    }
}

pub fn validate_plaintext_journal_transition(
    current: &PlaintextProvisioningJournalV1,
    next: &PlaintextProvisioningJournalV1,
) -> Result<(), ProvisioningContractError> {
    current.validate()?;
    next.validate()?;
    if current.phase.next() != Some(next.phase) || !current.stable_fields_equal(next) {
        return Err(ProvisioningContractError::InvalidTransition);
    }
    Ok(())
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningState {
    Fresh,
    Idempotent,
    Unadopted,
    Mismatch,
    Missing,
    Nonempty,
    NewKey,
    DifferentMode,
}

impl ProvisioningState {
    pub const fn permits_automatic_provisioning(self) -> bool {
        matches!(self, Self::Fresh | Self::Idempotent)
    }
}

pub const fn classify_provisioning_state(input: ProvisioningStateInput) -> ProvisioningState {
    if input.namespace_nonempty && input.new_key_requested {
        return ProvisioningState::NewKey;
    }
    match input.config {
        ExistingProvisioningConfig::Explicit { mode, .. } if mode != 1 => {
            ProvisioningState::DifferentMode
        }
        ExistingProvisioningConfig::Explicit { mode: 1, epoch } if epoch != MODE1_KEY_EPOCH => {
            ProvisioningState::Mismatch
        }
        ExistingProvisioningConfig::Absent => match input.artifact {
            ExistingProvisioningArtifact::Absent if !input.namespace_nonempty => {
                ProvisioningState::Fresh
            }
            ExistingProvisioningArtifact::Verified
            | ExistingProvisioningArtifact::Unverified
            | ExistingProvisioningArtifact::Mismatch => ProvisioningState::Unadopted,
            ExistingProvisioningArtifact::Absent => ProvisioningState::Nonempty,
        },
        ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 } => match input.artifact {
            ExistingProvisioningArtifact::Verified => ProvisioningState::Idempotent,
            ExistingProvisioningArtifact::Absent => ProvisioningState::Missing,
            ExistingProvisioningArtifact::Unverified | ExistingProvisioningArtifact::Mismatch => {
                if input.namespace_nonempty {
                    ProvisioningState::Nonempty
                } else {
                    ProvisioningState::Mismatch
                }
            }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupReferences {
    pub config: bool,
    pub receipt: bool,
    pub dropin: bool,
    pub journal: bool,
    pub active_transaction: bool,
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
        validate_safe_name(
            &self.transaction_id,
            MAX_TRANSACTION_ID_BYTES,
            "cleanup transaction id",
        )?;
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
        validate_safe_name(
            &self.transaction_id,
            MAX_TRANSACTION_ID_BYTES,
            "cleanup transaction id",
        )?;
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
    pub daemon_reports_credential: bool,
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
    if input.readiness_transient_exists {
        return CleanupAdmissibility::Refuse(CleanupRefusal::ReadinessTransient);
    }
    if input.daemon_reports_credential {
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
