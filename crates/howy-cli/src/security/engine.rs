use std::fmt;

use howy_common::config::{EmbeddingSecurityMode, HowyConfig, PresenceMode};
use howy_common::protocol::{SecurityBackendStateV1, SecurityInfoResult};
use howy_common::provisioning::{
    ArtifactDescriptorIdentityV1, ArtifactReceipt, BASE_SERVICE_UNIT_PATH, BackupHashes,
    CleanupAdmissibility, CleanupArtifactIdentityV1, CleanupReferences, CleanupStateInput,
    ConfiguredMode1CredentialSource, CredentialArtifactSourceIdentityV1,
    CredentialCryptographicValidation, CredentialPolicyMetadata, CredentialSelector,
    ExactFileSnapshot, FileMetadataSnapshotV1, FileObjectType, JournalPhase, LiveObjectHashes,
    MAX_CONFIG_BYTES, MAX_DROPIN_BYTES, MAX_JOURNAL_BYTES, MAX_RECEIPT_BYTES,
    MODE1_CREDENTIAL_NAME, MODE1_CREDENTIAL_PATH, MODE1_CREDENTIAL_SOURCE_COMPANION_NAME,
    MODE1_DROPIN_PATH, MODE1_KEY_EPOCH, Mode1CredentialSourcePolicy,
    ObservedCleanupArtifactIdentityV1, PROVISIONING_SCHEMA_VERSION, PlaintextJournalPhase,
    PlaintextProvisioningJournalV1, PlaintextRecoveryAction, PlannedObjectHashes,
    ProvisioningJournalV1, ProvisioningReceiptV1, ReceiptState, RecoveryAction,
    SECURITY_JOURNAL_PATH, SECURITY_RECEIPT_PATH, SECURITY_TRANSACTION_GUARD_PATH,
    SECURITY_UNADOPTED_DIRECTORY, Sha256Digest, StableRollbackTarget, StableUnitState,
    SystemdCredentialKeyId, UnadoptedArtifactV1, UnitAdmissibility, UnitCredentialReceipt,
    UnitKind, UnitObservation, VerifierReceipt, VerifierResultV1, apply_receipted_config_patch,
    classify_cleanup_admissibility, classify_unit_admissibility,
    inspect_systemd_credential_envelope, plaintext_recovery_action_for_phase,
    prepare_config_enable_patch, recovery_action_for_phase, validate_journal_transition,
    validate_plaintext_journal_transition, validate_receipt_transition,
    validate_systemd_credential_envelope,
};

use super::command::{
    CommandSpec, KeySelection, credential_encrypt_command, readiness_command, readiness_unit_name,
};

pub const MODE1_DROPIN_BYTES: &[u8] = b"[Service]\n\
LoadCredentialEncrypted=\n\
LoadCredentialEncrypted=howy.storage.mode1.epoch1:/etc/credstore.encrypted/howy.storage.mode1.epoch1\n\
SetCredential=howy.storage.mode1.source:/etc/credstore.encrypted/howy.storage.mode1.epoch1\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionMode {
    Plaintext,
    CachedAead,
    EphemeralAead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub mode: ProvisionMode,
    pub with_key: KeySelection,
    pub adopt_existing: bool,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRequest {
    pub transaction_id: String,
    pub artifact_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityOutcome {
    pub messages: Vec<String>,
    pub cleanup_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    Refused(String),
    Operation(String),
    Uncertain(String),
    #[cfg(test)]
    InjectedCrash(String),
}

impl SecurityError {
    pub fn operation(message: impl Into<String>) -> Self {
        Self::Operation(message.into())
    }

    fn is_crash(&self) -> bool {
        #[cfg(test)]
        {
            matches!(self, Self::InjectedCrash(_))
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(message) | Self::Operation(message) => formatter.write_str(message),
            Self::Uncertain(message) => write!(formatter, "uncertain security state: {message}"),
            #[cfg(test)]
            Self::InjectedCrash(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SecurityError {}

pub type SecurityResult<T> = Result<T, SecurityError>;

pub trait SecretKeyMaterial {
    fn expose(&self) -> &[u8];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFile {
    pub bytes: Vec<u8>,
    pub metadata: FileMetadataSnapshotV1,
    pub device_id: u64,
    pub inode: u64,
    pub parent_device_id: u64,
    pub parent_inode: u64,
    pub parent_uid: u32,
    pub parent_gid: u32,
    pub parent_permissions: u32,
    pub parent_link_count: u64,
}

impl ObservedFile {
    pub fn sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.bytes)
    }

    pub fn snapshot(&self, maximum: usize) -> SecurityResult<ExactFileSnapshot> {
        if self.bytes.len() > maximum {
            return Err(SecurityError::operation(
                "file exceeds transaction byte cap",
            ));
        }
        ExactFileSnapshot::new(&self.bytes, self.metadata.clone())
            .map_err(|error| SecurityError::operation(error.to_string()))
    }

    fn validate_regular(&self, uid: u32, gid: u32, permissions: u32) -> SecurityResult<()> {
        if self.metadata.object_type != FileObjectType::RegularFile
            || self.metadata.uid != uid
            || self.metadata.gid != gid
            || self.metadata.permissions != permissions
            || self.metadata.link_count != 1
            || self.metadata.byte_length != self.bytes.len() as u64
            || self.device_id == 0
            || self.inode == 0
        {
            return Err(SecurityError::operation("unsafe file metadata"));
        }
        Ok(())
    }

    fn cleanup_descriptor(&self) -> ArtifactDescriptorIdentityV1 {
        ArtifactDescriptorIdentityV1 {
            path: MODE1_CREDENTIAL_PATH.into(),
            device_id: self.device_id,
            inode: self.inode,
            sha256: self.sha256(),
            byte_length: self.bytes.len() as u64,
            object_type: self.metadata.object_type,
            uid: self.metadata.uid,
            gid: self.metadata.gid,
            permissions: self.metadata.permissions,
            link_count: self.metadata.link_count,
            parent_directory: howy_common::provisioning::DirectoryIdentityV1 {
                path: howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY.into(),
                object_type: FileObjectType::Directory,
                device_id: self.parent_device_id,
                inode: self.parent_inode,
                uid: self.parent_uid,
                gid: self.parent_gid,
                permissions: self.parent_permissions,
                link_count: self.parent_link_count,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicWriteMode {
    NoReplace,
    ExchangeOrCreate,
}

pub trait SecurityRuntime {
    fn require_root(&mut self) -> SecurityResult<()>;
    fn acquire_lock(&mut self) -> SecurityResult<()>;
    fn require_systemd_261(&mut self) -> SecurityResult<()>;
    fn transaction_id(&mut self) -> SecurityResult<String>;
    fn generate_key(&mut self) -> SecurityResult<Box<dyn SecretKeyMaterial>>;
    fn read_file(&mut self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>>;
    fn write_file_atomic(
        &mut self,
        path: &str,
        bytes: &[u8],
        permissions: u32,
        mode: AtomicWriteMode,
    ) -> SecurityResult<()>;
    fn restore_file(
        &mut self,
        path: &str,
        snapshot: Option<&ExactFileSnapshot>,
    ) -> SecurityResult<()>;
    fn create_guard(&mut self, transaction_id: &str) -> SecurityResult<()>;
    fn remove_guard(&mut self) -> SecurityResult<()>;
    fn persist_journal(&mut self, bytes: &[u8]) -> SecurityResult<()>;
    fn remove_journal(&mut self) -> SecurityResult<()>;
    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation>;
    fn monotonic_millis(&mut self) -> u64;
    fn settle_step(&mut self) -> SecurityResult<()>;
    fn stop_unit(&mut self, unit: UnitKind) -> SecurityResult<()>;
    fn start_unit(&mut self, unit: UnitKind) -> SecurityResult<()>;
    fn daemon_reload(&mut self) -> SecurityResult<()>;
    fn transient_exists(&mut self, unit: &str) -> SecurityResult<bool>;
    fn stop_and_kill_transient(&mut self, unit: &str) -> SecurityResult<()>;
    fn encrypt_credential(
        &mut self,
        command: &CommandSpec,
        plaintext: &[u8],
    ) -> SecurityResult<Vec<u8>>;
    fn run_readiness(&mut self, command: &CommandSpec) -> SecurityResult<Vec<u8>>;
    fn preview_verifier(&mut self, config: &[u8]) -> SecurityResult<VerifierResultV1>;
    fn namespace_nonempty(&mut self) -> SecurityResult<bool>;
    fn security_info(&mut self) -> SecurityResult<Option<SecurityInfoResult>>;
    fn unlink_artifact_exact(
        &mut self,
        expected: &ArtifactDescriptorIdentityV1,
    ) -> SecurityResult<()>;
    fn boundary(&mut self, name: &'static str) -> SecurityResult<()>;
}

pub struct SecurityEngine<'a, R: SecurityRuntime> {
    runtime: &'a mut R,
}

impl<'a, R: SecurityRuntime> SecurityEngine<'a, R> {
    pub fn new(runtime: &'a mut R) -> Self {
        Self { runtime }
    }

    pub fn provision(&mut self, request: ProvisionRequest) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        if request.mode == ProvisionMode::EphemeralAead {
            return Err(SecurityError::Refused(
                "security mode 2 is unavailable until its feasibility gate passes".into(),
            ));
        }
        if !request.confirmed {
            return Err(SecurityError::Refused(
                "security migration requires explicit confirmation".into(),
            ));
        }
        self.runtime.acquire_lock()?;
        if let Some(command) = self.recover_locked()? {
            return Err(SecurityError::Refused(format!(
                "a prior transaction was recovered with an unadopted artifact; use `{command}` before continuing"
            )));
        }
        self.runtime.require_systemd_261()?;
        match request.mode {
            ProvisionMode::Plaintext => self.provision_plaintext(),
            ProvisionMode::CachedAead => self.provision_mode1(request),
            ProvisionMode::EphemeralAead => unreachable!(),
        }
    }

    pub fn enable(&mut self) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        if let Some(command) = self.recover_locked()? {
            return Err(SecurityError::Refused(format!(
                "a prior transaction was recovered with an unadopted artifact; use `{command}` before continuing"
            )));
        }
        self.runtime.require_systemd_261()?;
        self.enable_mode1()
    }

    pub fn recover(&mut self) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        let cleanup_command = self.recover_locked()?;
        Ok(SecurityOutcome {
            messages: vec!["Security transaction recovery complete.".into()],
            cleanup_command,
        })
    }

    pub fn cleanup_unadopted(
        &mut self,
        request: CleanupRequest,
    ) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        self.cleanup_locked(request)
    }

    fn provision_mode1(&mut self, request: ProvisionRequest) -> SecurityResult<SecurityOutcome> {
        let namespace_nonempty = self.runtime.namespace_nonempty()?;
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
        let existing_mode = parse_explicit_mode(config.as_ref())?;
        let existing_receipt_file = self.read_receipt_file()?;
        let existing_receipt = existing_receipt_file.as_ref().map(|(_, receipt)| receipt);
        let existing_artifact = self.runtime.read_file(
            MODE1_CREDENTIAL_PATH,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )?;
        // Snapshot and reject unsafe unit states before RNG or systemd-creds,
        // since host-key setup by systemd-creds may itself be persistent.
        let service_state = self.stable_unit(UnitKind::Service)?;
        let socket_state = self.stable_unit(UnitKind::Socket)?;

        if let (Some(config), Some(receipt), Some(artifact)) =
            (&config, existing_receipt, &existing_artifact)
            && receipt_matches_live(receipt, config, artifact, self.runtime)?
        {
            return match receipt.state {
                ReceiptState::ProvisionedDisabled => self.verify_disabled_idempotent(
                    config,
                    receipt,
                    artifact,
                    &existing_receipt_file
                        .as_ref()
                        .expect("matched receipt has an observed file")
                        .0,
                    service_state,
                    socket_state,
                ),
                ReceiptState::Enabled => Ok(SecurityOutcome {
                    messages: vec!["Mode 1 is already enabled and receipted.".into()],
                    cleanup_command: None,
                }),
            };
        }

        if matches!(existing_mode, Some((1, epoch)) if epoch != MODE1_KEY_EPOCH) {
            return Err(SecurityError::Refused(
                "Mode 1 v1 supports epoch 1 only; epoch-2 rotation is not implemented".into(),
            ));
        }
        if matches!(existing_mode, Some((mode, _)) if mode != 1) && !request.confirmed {
            return Err(SecurityError::Refused(
                "existing different security mode requires migration confirmation".into(),
            ));
        }
        if namespace_nonempty && existing_artifact.is_none() {
            return Err(SecurityError::Refused(
                "Mode 1 namespace is nonempty but the epoch-1 artifact is missing; refusing a new key"
                    .into(),
            ));
        }
        let artifact_is_receipted = existing_artifact.as_ref().is_some_and(|artifact| {
            existing_receipt.is_some_and(|receipt| {
                receipt.artifact.path == MODE1_CREDENTIAL_PATH
                    && receipt.artifact.sha256 == artifact.sha256()
                    && receipt.artifact.size == artifact.metadata.byte_length
                    && receipt.artifact.uid == artifact.metadata.uid
                    && receipt.artifact.gid == artifact.metadata.gid
                    && receipt.artifact.mode == artifact.metadata.permissions
                    && receipt.artifact.nlink == artifact.metadata.link_count
            })
        });
        if existing_artifact.is_some() && !artifact_is_receipted && !request.adopt_existing {
            return Err(SecurityError::Refused(
                "existing credential artifact is unadopted; rerun with --adopt-existing after verification"
                    .into(),
            ));
        }
        if request.adopt_existing && existing_artifact.is_none() {
            return Err(SecurityError::Refused(
                "--adopt-existing requires an existing credential artifact".into(),
            ));
        }

        let transaction_id = self.runtime.transaction_id()?;
        let (artifact_bytes, requested_selector, generated) = match existing_artifact {
            Some(ref artifact) => {
                artifact.validate_regular(0, 0, 0o600)?;
                let inspected = inspect_systemd_credential_envelope(&artifact.bytes)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                (
                    artifact.bytes.clone(),
                    inspected.actual_key_id.selector(),
                    false,
                )
            }
            None => {
                let key = self.runtime.generate_key()?;
                if key.expose().len() != 32 {
                    return Err(SecurityError::operation("RNG returned a non-32-byte key"));
                }
                let selection = request.with_key;
                let artifact = self
                    .runtime
                    .encrypt_credential(&credential_encrypt_command(selection), key.expose())?;
                // A signed-public-key or otherwise inadmissible `auto`
                // envelope is refused. We do not guess which explicit selector
                // the administrator intended.
                let inspected = inspect_systemd_credential_envelope(&artifact)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                let requested = match selection {
                    KeySelection::Auto => inspected.actual_key_id.selector(),
                    KeySelection::Host => CredentialSelector::Host,
                    KeySelection::Tpm2 => CredentialSelector::Tpm2,
                    KeySelection::HostAndTpm2 => CredentialSelector::HostAndTpm2,
                };
                if inspected.actual_key_id.selector() != requested {
                    return Err(SecurityError::operation(
                        "systemd-creds returned a different key selector",
                    ));
                }
                (artifact, requested, true)
            }
        };
        self.runtime.boundary("credential-ready")?;

        let disabled_config = build_disabled_mode1_config(config.as_ref())?;
        let config_patch = prepare_config_enable_patch(&disabled_config)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let expected_verifier = self.runtime.preview_verifier(&disabled_config)?;
        if expected_verifier.config_sha256 != config_patch.contract.disabled_sha256 {
            return Err(SecurityError::operation(
                "verifier preview did not bind the candidate config",
            ));
        }
        let inspected = inspect_systemd_credential_envelope(&artifact_bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let artifact_observation = existing_artifact.as_ref();
        let artifact_metadata = artifact_observation
            .map(|value| value.metadata.clone())
            .unwrap_or_else(generated_artifact_metadata);
        let base_unit = self
            .runtime
            .read_file(BASE_SERVICE_UNIT_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("base howy.service is missing"))?;
        base_unit.validate_regular(0, 0, base_unit.metadata.permissions)?;
        let policy = anticipated_policy(&inspected, requested_selector)?;
        let disabled_receipt = build_disabled_receipt(
            &transaction_id,
            &artifact_bytes,
            &artifact_metadata,
            policy,
            config_patch.contract.clone(),
            base_unit.sha256(),
            expected_verifier,
        )?;
        let enabled_receipt = enabled_receipt_from(&disabled_receipt)?;
        let disabled_receipt_bytes = disabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let enabled_receipt_bytes = enabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let prior_config = config
            .as_ref()
            .map(|file| file.snapshot(MAX_CONFIG_BYTES))
            .transpose()?;
        let prior_dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .map(|file| {
                file.validate_regular(0, 0, 0o600)?;
                file.snapshot(MAX_DROPIN_BYTES)
            })
            .transpose()?;
        let prior_receipt = existing_receipt_file
            .as_ref()
            .map(|(file, _)| file.snapshot(MAX_RECEIPT_BYTES))
            .transpose()?;
        let mut owned_paths = vec![
            howy_common::paths::CONFIG_FILE.to_owned(),
            MODE1_CREDENTIAL_PATH.to_owned(),
            MODE1_DROPIN_PATH.to_owned(),
            SECURITY_RECEIPT_PATH.to_owned(),
            SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
        ];
        owned_paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            phase: JournalPhase::Prepared,
            mode: 1,
            epoch: MODE1_KEY_EPOCH,
            credential_name: MODE1_CREDENTIAL_NAME.into(),
            planned_hashes: PlannedObjectHashes {
                artifact_sha256: Sha256Digest::from_bytes(&artifact_bytes),
                dropin_sha256: Sha256Digest::from_bytes(MODE1_DROPIN_BYTES),
                disabled_config_sha256: config_patch.contract.disabled_sha256.clone(),
                enabled_config_sha256: config_patch.contract.enabled_sha256.clone(),
                disabled_receipt_sha256: Sha256Digest::from_bytes(&disabled_receipt_bytes),
                enabled_receipt_sha256: Sha256Digest::from_bytes(&enabled_receipt_bytes),
            },
            live_hashes: LiveObjectHashes::default(),
            transaction_owned_paths: owned_paths,
            artifact_preexisted: !generated,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config,
            prior_dropin,
            prior_receipt,
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            backup_hashes: BackupHashes {
                artifact_sha256: (!generated).then(|| Sha256Digest::from_bytes(&artifact_bytes)),
                config_sha256: config.as_ref().map(ObservedFile::sha256),
                dropin_sha256: self
                    .runtime
                    .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
                    .map(|file| file.sha256()),
                receipt_sha256: existing_receipt_file
                    .as_ref()
                    .map(|(file, _)| file.sha256()),
            },
            recovery_action: RecoveryAction::RestorePriorState,
        };
        self.persist_mode1_journal(&journal)?;
        self.runtime.boundary("phase-prepared")?;

        let execution = self.execute_mode1_provision(
            &mut journal,
            &artifact_bytes,
            &disabled_config,
            &disabled_receipt,
            &disabled_receipt_bytes,
            &inspected,
            requested_selector,
            generated,
        );
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec![
                    "Mode 1 provisioned and verified in disabled state.".into(),
                    "Run `sudo howy security enable` after review.".into(),
                ],
                cleanup_command: None,
            }),
            Err(error) if error.is_crash() => Err(error),
            Err(error) => {
                let cleanup =
                    self.rollback_mode1(&journal, generated, Some((&artifact_bytes, &inspected)));
                match cleanup {
                    Ok(cleanup_command) => Err(SecurityError::Operation(match cleanup_command {
                        Some(command) => {
                            format!("{error}; unadopted artifact retained; use `{command}`")
                        }
                        None => error.to_string(),
                    })),
                    Err(rollback) => Err(SecurityError::Uncertain(format!(
                        "{error}; rollback failed: {rollback}"
                    ))),
                }
            }
        }
    }

    fn verify_disabled_idempotent(
        &mut self,
        config: &ObservedFile,
        receipt: &ProvisioningReceiptV1,
        artifact: &ObservedFile,
        receipt_file: &ObservedFile,
        service_state: StableUnitState,
        socket_state: StableUnitState,
    ) -> SecurityResult<SecurityOutcome> {
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted drop-in disappeared"))?;
        dropin.validate_regular(0, 0, 0o600)?;
        let expected = self.runtime.preview_verifier(&config.bytes)?;
        if expected != receipt.verifier.output {
            return Err(SecurityError::operation(
                "idempotent verifier inputs differ from receipt",
            ));
        }
        let enabled_receipt = enabled_receipt_from(receipt)?;
        let disabled_receipt_bytes = receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let enabled_receipt_bytes = enabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let transaction_id = self.runtime.transaction_id()?;
        let mut paths = vec![
            howy_common::paths::CONFIG_FILE.into(),
            MODE1_CREDENTIAL_PATH.into(),
            MODE1_DROPIN_PATH.into(),
            SECURITY_RECEIPT_PATH.into(),
            SECURITY_TRANSACTION_GUARD_PATH.into(),
        ];
        paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            phase: JournalPhase::Prepared,
            mode: 1,
            epoch: 1,
            credential_name: MODE1_CREDENTIAL_NAME.into(),
            planned_hashes: PlannedObjectHashes {
                artifact_sha256: artifact.sha256(),
                dropin_sha256: dropin.sha256(),
                disabled_config_sha256: receipt.config_patch.disabled_sha256.clone(),
                enabled_config_sha256: receipt.config_patch.enabled_sha256.clone(),
                disabled_receipt_sha256: Sha256Digest::from_bytes(&disabled_receipt_bytes),
                enabled_receipt_sha256: Sha256Digest::from_bytes(&enabled_receipt_bytes),
            },
            live_hashes: LiveObjectHashes::default(),
            transaction_owned_paths: paths,
            artifact_preexisted: true,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config: Some(config.snapshot(MAX_CONFIG_BYTES)?),
            prior_dropin: Some(dropin.snapshot(MAX_DROPIN_BYTES)?),
            prior_receipt: Some(receipt_file.snapshot(MAX_RECEIPT_BYTES)?),
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            backup_hashes: BackupHashes {
                artifact_sha256: Some(artifact.sha256()),
                config_sha256: Some(config.sha256()),
                dropin_sha256: Some(dropin.sha256()),
                receipt_sha256: Some(receipt_file.sha256()),
            },
            recovery_action: RecoveryAction::RestorePriorState,
        };
        self.persist_mode1_journal(&journal)?;
        let execution = (|| {
            self.runtime.create_guard(&transaction_id)?;
            self.advance_mode1(&mut journal, JournalPhase::Guarded)?;
            self.stop_units_stably()?;
            self.advance_mode1(&mut journal, JournalPhase::UnitsStopped)?;
            self.advance_mode1(&mut journal, JournalPhase::ArtifactCommitted)?;
            self.advance_mode1(&mut journal, JournalPhase::DropinCommitted)?;
            self.advance_mode1(&mut journal, JournalPhase::DisabledConfigCommitted)?;
            let output = self.run_strong_readiness(
                &transaction_id,
                howy_common::paths::CONFIG_FILE,
                MODE1_CREDENTIAL_PATH,
            )?;
            if output != receipt.verifier.output {
                return Err(SecurityError::operation(
                    "idempotent strong readiness result changed",
                ));
            }
            self.advance_mode1(&mut journal, JournalPhase::ReadinessVerified)?;
            self.advance_mode1(&mut journal, JournalPhase::DisabledReceiptCommitted)?;
            self.complete_disabled_transaction(&journal)
        })();
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec![
                    "Mode 1 disabled state was idempotently reverified.".into(),
                    "Run `sudo howy security enable` after review.".into(),
                ],
                cleanup_command: None,
            }),
            Err(error) if error.is_crash() => Err(error),
            Err(error) => match self.rollback_mode1(&journal, false, None) {
                Ok(_) => Err(SecurityError::Operation(error.to_string())),
                Err(rollback) => Err(SecurityError::Uncertain(format!(
                    "{error}; rollback failed: {rollback}"
                ))),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_mode1_provision(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        artifact: &[u8],
        disabled_config: &[u8],
        disabled_receipt: &ProvisioningReceiptV1,
        disabled_receipt_bytes: &[u8],
        inspected: &howy_common::provisioning::InspectedCredentialEnvelope,
        selector: CredentialSelector,
        generated: bool,
    ) -> SecurityResult<()> {
        self.runtime.create_guard(&journal.transaction_id)?;
        self.runtime.boundary("guard-created")?;
        self.advance_mode1(journal, JournalPhase::Guarded)?;
        self.stop_units_stably()?;
        self.advance_mode1(journal, JournalPhase::UnitsStopped)?;

        if generated {
            self.runtime.write_file_atomic(
                MODE1_CREDENTIAL_PATH,
                artifact,
                0o600,
                AtomicWriteMode::NoReplace,
            )?;
        }
        let installed = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("credential artifact disappeared"))?;
        installed.validate_regular(0, 0, 0o600)?;
        if installed.sha256() != journal.planned_hashes.artifact_sha256 {
            return Err(SecurityError::operation("credential artifact changed"));
        }
        self.runtime.boundary("artifact-installed")?;
        self.advance_mode1(journal, JournalPhase::ArtifactCommitted)?;

        self.runtime.write_file_atomic(
            MODE1_DROPIN_PATH,
            MODE1_DROPIN_BYTES,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )?;
        self.runtime.daemon_reload()?;
        self.runtime.boundary("dropin-installed")?;
        self.advance_mode1(journal, JournalPhase::DropinCommitted)?;

        self.runtime.write_file_atomic(
            howy_common::paths::CONFIG_FILE,
            disabled_config,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )?;
        self.runtime.boundary("disabled-config-installed")?;
        self.advance_mode1(journal, JournalPhase::DisabledConfigCommitted)?;

        let output = self.run_strong_readiness(
            &journal.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
        )?;
        if output != disabled_receipt.verifier.output {
            return Err(SecurityError::operation(
                "strong readiness output did not match the planned descriptor-bound result",
            ));
        }
        let evidence = CredentialCryptographicValidation {
            envelope_sha256: inspected.envelope_sha256.clone(),
            embedded_name: MODE1_CREDENTIAL_NAME.into(),
            plaintext_size: 32,
            authenticated: true,
            exact_consumption: true,
        };
        let validated = validate_systemd_credential_envelope(
            artifact,
            selector,
            MODE1_CREDENTIAL_NAME,
            &evidence,
        )
        .map_err(|error| SecurityError::operation(error.to_string()))?;
        if validated != disabled_receipt.artifact.credential_policy {
            return Err(SecurityError::operation(
                "credential policy changed after strong readiness",
            ));
        }
        let live_artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("artifact disappeared after readiness"))?;
        let live_dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("drop-in disappeared after readiness"))?;
        let live_base = self
            .runtime
            .read_file(BASE_SERVICE_UNIT_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("base unit disappeared after readiness"))?;
        if live_artifact.sha256() != disabled_receipt.artifact.sha256
            || live_dropin.sha256() != disabled_receipt.unit_credential.dropin_sha256
            || live_dropin.bytes != MODE1_DROPIN_BYTES
            || live_base.sha256() != disabled_receipt.unit_credential.base_unit_sha256
        {
            return Err(SecurityError::operation(
                "provisioning object changed after strong readiness",
            ));
        }
        self.runtime.boundary("readiness-verified")?;
        self.advance_mode1(journal, JournalPhase::ReadinessVerified)?;

        self.runtime.write_file_atomic(
            SECURITY_RECEIPT_PATH,
            disabled_receipt_bytes,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )?;
        self.runtime.boundary("disabled-receipt-installed")?;
        self.advance_mode1(journal, JournalPhase::DisabledReceiptCommitted)?;
        self.complete_disabled_transaction(journal)
    }

    fn enable_mode1(&mut self) -> SecurityResult<SecurityOutcome> {
        let (receipt_file, receipt) = self.read_receipt_file()?.ok_or_else(|| {
            SecurityError::Refused("Mode 1 provisioning receipt is missing".into())
        })?;
        if receipt.state != ReceiptState::ProvisionedDisabled {
            return Err(SecurityError::Refused(
                "Mode 1 receipt is not in provisioned-disabled state".into(),
            ));
        }
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted config is missing"))?;
        config.validate_regular(0, 0, 0o600)?;
        if config.sha256() != receipt.config_patch.disabled_sha256 {
            return Err(SecurityError::operation(
                "live config does not match the disabled receipt",
            ));
        }
        let enabled_config = apply_receipted_config_patch(&config.bytes, &receipt.config_patch)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("receipted artifact is missing"))?;
        artifact.validate_regular(0, 0, 0o600)?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted drop-in is missing"))?;
        dropin.validate_regular(0, 0, 0o600)?;
        let base_unit = self
            .runtime
            .read_file(BASE_SERVICE_UNIT_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted base unit is missing"))?;
        base_unit.validate_regular(0, 0, base_unit.metadata.permissions)?;
        if artifact.sha256() != receipt.artifact.sha256
            || artifact.metadata.byte_length != receipt.artifact.size
            || dropin.sha256() != receipt.unit_credential.dropin_sha256
            || dropin.bytes != MODE1_DROPIN_BYTES
            || base_unit.sha256() != receipt.unit_credential.base_unit_sha256
        {
            return Err(SecurityError::operation("receipted object mismatch"));
        }
        let expected = self.runtime.preview_verifier(&config.bytes)?;
        if expected != receipt.verifier.output {
            return Err(SecurityError::operation(
                "live verifier inputs differ from receipt",
            ));
        }
        let service_state = self.stable_unit(UnitKind::Service)?;
        let socket_state = self.stable_unit(UnitKind::Socket)?;
        let prior_invocation = self.runtime.security_info()?.and_then(|status| {
            status
                .validate_strict()
                .ok()
                .map(|_| status.daemon_invocation_id)
        });
        let enabled_receipt = enabled_receipt_from(&receipt)?;
        let disabled_receipt_bytes = receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let enabled_receipt_bytes = enabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let transaction_id = self.runtime.transaction_id()?;
        let mut paths = vec![
            howy_common::paths::CONFIG_FILE.into(),
            MODE1_CREDENTIAL_PATH.into(),
            MODE1_DROPIN_PATH.into(),
            SECURITY_RECEIPT_PATH.into(),
            SECURITY_TRANSACTION_GUARD_PATH.into(),
        ];
        paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            phase: JournalPhase::Prepared,
            mode: 1,
            epoch: 1,
            credential_name: MODE1_CREDENTIAL_NAME.into(),
            planned_hashes: PlannedObjectHashes {
                artifact_sha256: artifact.sha256(),
                dropin_sha256: dropin.sha256(),
                disabled_config_sha256: receipt.config_patch.disabled_sha256.clone(),
                enabled_config_sha256: receipt.config_patch.enabled_sha256.clone(),
                disabled_receipt_sha256: Sha256Digest::from_bytes(&disabled_receipt_bytes),
                enabled_receipt_sha256: Sha256Digest::from_bytes(&enabled_receipt_bytes),
            },
            live_hashes: LiveObjectHashes::default(),
            transaction_owned_paths: paths,
            artifact_preexisted: true,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config: Some(config.snapshot(MAX_CONFIG_BYTES)?),
            prior_dropin: Some(dropin.snapshot(MAX_DROPIN_BYTES)?),
            prior_receipt: Some(receipt_file.snapshot(MAX_RECEIPT_BYTES)?),
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            backup_hashes: BackupHashes {
                artifact_sha256: Some(artifact.sha256()),
                config_sha256: Some(config.sha256()),
                dropin_sha256: Some(dropin.sha256()),
                receipt_sha256: Some(receipt_file.sha256()),
            },
            recovery_action: RecoveryAction::RestorePriorState,
        };
        self.persist_mode1_journal(&journal)?;
        self.runtime.boundary("phase-prepared")?;
        let execution = self.execute_enable(
            &mut journal,
            &receipt,
            &enabled_receipt,
            &enabled_receipt_bytes,
            &enabled_config,
            prior_invocation.as_deref(),
        );
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec!["Mode 1 enabled and verified.".into()],
                cleanup_command: None,
            }),
            Err(error) if error.is_crash() => Err(error),
            Err(error) => match self.rollback_mode1(&journal, false, None) {
                Ok(_) => Err(SecurityError::Operation(error.to_string())),
                Err(rollback) => Err(SecurityError::Uncertain(format!(
                    "{error}; rollback failed: {rollback}"
                ))),
            },
        }
    }

    fn execute_enable(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        disabled_receipt: &ProvisioningReceiptV1,
        enabled_receipt: &ProvisioningReceiptV1,
        enabled_receipt_bytes: &[u8],
        enabled_config: &[u8],
        prior_invocation: Option<&str>,
    ) -> SecurityResult<()> {
        self.runtime.create_guard(&journal.transaction_id)?;
        self.advance_mode1(journal, JournalPhase::Guarded)?;
        self.stop_units_stably()?;
        self.advance_mode1(journal, JournalPhase::UnitsStopped)?;
        self.advance_mode1(journal, JournalPhase::ArtifactCommitted)?;
        self.advance_mode1(journal, JournalPhase::DropinCommitted)?;
        self.advance_mode1(journal, JournalPhase::DisabledConfigCommitted)?;
        let readiness = self.run_strong_readiness(
            &journal.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
        )?;
        if readiness != disabled_receipt.verifier.output {
            return Err(SecurityError::operation("enable readiness result changed"));
        }
        self.advance_mode1(journal, JournalPhase::ReadinessVerified)?;
        self.advance_mode1(journal, JournalPhase::DisabledReceiptCommitted)?;
        self.runtime.write_file_atomic(
            howy_common::paths::CONFIG_FILE,
            enabled_config,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )?;
        self.runtime.boundary("enabled-config-installed")?;
        self.advance_mode1(journal, JournalPhase::EnabledConfigCommitted)?;
        self.advance_mode1(journal, JournalPhase::ActivationCommitted)?;
        self.runtime.remove_guard()?;
        self.runtime.daemon_reload()?;
        self.start_controlled()?;
        let status = self
            .runtime
            .security_info()?
            .ok_or_else(|| SecurityError::operation("daemon root security status unavailable"))?;
        validate_enabled_status(
            &status,
            enabled_receipt,
            prior_invocation,
            &journal.planned_hashes.enabled_config_sha256,
        )?;
        self.advance_mode1(journal, JournalPhase::UnitsStarted)?;
        self.runtime.write_file_atomic(
            SECURITY_RECEIPT_PATH,
            enabled_receipt_bytes,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )?;
        self.runtime.boundary("enabled-receipt-installed")?;
        self.advance_mode1(journal, JournalPhase::EnabledReceiptCommitted)?;
        self.runtime.remove_journal()?;
        Ok(())
    }

    fn provision_plaintext(&mut self) -> SecurityResult<SecurityOutcome> {
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
        if let Some(config) = &config {
            config.validate_regular(0, 0, 0o600)?;
        }
        let enabled_config = build_enabled_mode0_config(config.as_ref())?;
        let transaction_id = self.runtime.transaction_id()?;
        let service = self.stable_unit(UnitKind::Service)?;
        let socket = self.stable_unit(UnitKind::Socket)?;
        let prior_dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .map(|file| {
                file.validate_regular(0, 0, 0o600)?;
                file.snapshot(MAX_DROPIN_BYTES)
            })
            .transpose()?;
        let mut journal = PlaintextProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            phase: PlaintextJournalPhase::Prepared,
            enabled_config_sha256: Sha256Digest::from_bytes(&enabled_config),
            live_config_sha256: None,
            prior_config: config
                .as_ref()
                .map(|file| file.snapshot(MAX_CONFIG_BYTES))
                .transpose()?,
            prior_dropin,
            service_unit_state: service,
            socket_unit_state: socket,
            recovery_action: PlaintextRecoveryAction::RestorePriorState,
        };
        self.persist_plaintext_journal(&journal)?;
        let execution = (|| {
            self.runtime.create_guard(&transaction_id)?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::Guarded)?;
            self.stop_units_stably()?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::UnitsStopped)?;
            self.runtime.restore_file(MODE1_DROPIN_PATH, None)?;
            self.runtime.daemon_reload()?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::DropinRemoved)?;
            self.runtime.write_file_atomic(
                howy_common::paths::CONFIG_FILE,
                &enabled_config,
                0o600,
                AtomicWriteMode::ExchangeOrCreate,
            )?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::EnabledConfigCommitted)?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::ActivationCommitted)?;
            self.runtime.remove_guard()?;
            self.start_controlled()?;
            let status = self.runtime.security_info()?.ok_or_else(|| {
                SecurityError::operation("daemon root security status unavailable")
            })?;
            validate_mode0_status(&status, &journal.enabled_config_sha256)?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::UnitsStarted)?;
            self.runtime.remove_journal()
        })();
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec![
                    "WARNING: explicit plaintext Mode 0 is enabled; encrypted artifacts and namespaces were preserved."
                        .into(),
                ],
                cleanup_command: None,
            }),
            Err(error) if error.is_crash() => Err(error),
            Err(error) => match self.rollback_plaintext(&journal) {
                Ok(()) => Err(SecurityError::Operation(error.to_string())),
                Err(rollback) => Err(SecurityError::Uncertain(format!(
                    "{error}; rollback failed: {rollback}"
                ))),
            },
        }
    }

    fn cleanup_locked(&mut self, request: CleanupRequest) -> SecurityResult<SecurityOutcome> {
        validate_transaction_id(&request.transaction_id)?;
        let manifest_path = unadopted_manifest_path(&request.transaction_id);
        let manifest_file = self
            .runtime
            .read_file(&manifest_path, MAX_RECEIPT_BYTES)?
            .ok_or_else(|| {
                SecurityError::Refused("unadopted transaction manifest is missing".into())
            })?;
        manifest_file.validate_regular(0, 0, 0o600)?;
        let manifest = UnadoptedArtifactV1::parse(&manifest_file.bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if manifest.identity.transaction_id != request.transaction_id
            || manifest.identity.descriptor.sha256 != request.artifact_sha256
        {
            return Err(SecurityError::Refused(
                "cleanup transaction or artifact hash does not match the manifest".into(),
            ));
        }
        let observed_file = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Refused("unadopted artifact is absent".into()))?;
        let inspected = inspect_systemd_credential_envelope(&observed_file.bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let observed_identity = cleanup_identity(
            &request.transaction_id,
            &observed_file,
            inspected.actual_key_id,
            inspected.envelope_sha256,
            inspected.envelope_size,
        );
        let references = self.cleanup_references(&manifest.identity)?;
        let service = self.runtime.unit_observation(UnitKind::Service)?;
        let socket = self.runtime.unit_observation(UnitKind::Socket)?;
        let transient = self
            .runtime
            .transient_exists(&readiness_unit_name(&request.transaction_id))?;
        let daemon_reports = self.runtime.security_info()?.is_some_and(|status| {
            status.validate_strict().is_ok()
                && status.credential_name == manifest.identity.source.credential_name
                && status.configured_credential_source == manifest.identity.descriptor.path
        });
        let admissibility = classify_cleanup_admissibility(CleanupStateInput {
            expected_artifact: howy_common::provisioning::ExpectedCleanupArtifactIdentityV1(
                manifest.identity.clone(),
            ),
            observed_artifact: ObservedCleanupArtifactIdentityV1(observed_identity),
            references,
            service,
            socket,
            readiness_transient_exists: transient,
            daemon_reports_credential: daemon_reports,
        });
        if let CleanupAdmissibility::Refuse(reason) = admissibility {
            return Err(SecurityError::Refused(format!(
                "unadopted cleanup refused: {reason:?}"
            )));
        }
        let immediate = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Refused("artifact changed before unlink".into()))?;
        if immediate.cleanup_descriptor() != manifest.identity.descriptor {
            return Err(SecurityError::Refused(
                "artifact descriptor changed before unlink".into(),
            ));
        }
        self.runtime
            .unlink_artifact_exact(&manifest.identity.descriptor)?;
        self.runtime.restore_file(&manifest_path, None)?;
        Ok(SecurityOutcome {
            messages: vec!["Unadopted artifact removed after reference-safe revalidation.".into()],
            cleanup_command: None,
        })
    }

    fn cleanup_references(
        &mut self,
        identity: &CleanupArtifactIdentityV1,
    ) -> SecurityResult<CleanupReferences> {
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
        let config_reference = config.as_ref().is_some_and(|file| {
            toml::from_str::<HowyConfig>(std::str::from_utf8(&file.bytes).unwrap_or_default())
                .is_ok_and(|config| {
                    config.security.embedding_mode == EmbeddingSecurityMode::AeadCached
                        && config.security.cached.credential_name == identity.source.credential_name
                })
        });
        let receipt_reference = self
            .runtime
            .read_file(SECURITY_RECEIPT_PATH, MAX_RECEIPT_BYTES)?
            .is_some_and(|file| {
                ProvisioningReceiptV1::parse(&file.bytes).is_ok_and(|receipt| {
                    receipt.artifact.path == identity.descriptor.path
                        && receipt.artifact.sha256 == identity.descriptor.sha256
                })
            });
        let dropin_reference = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .is_some_and(|file| {
                file.bytes
                    .windows(identity.descriptor.path.len())
                    .any(|window| window == identity.descriptor.path.as_bytes())
            });
        let journal_reference = self
            .runtime
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)?
            .is_some();
        let active_transaction = self
            .runtime
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?
            .is_some();
        Ok(CleanupReferences {
            config: config_reference,
            receipt: receipt_reference,
            dropin: dropin_reference,
            journal: journal_reference,
            active_transaction,
        })
    }

    fn recover_locked(&mut self) -> SecurityResult<Option<String>> {
        let Some(file) = self
            .runtime
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)?
        else {
            return Ok(None);
        };
        file.validate_regular(0, 0, 0o600)?;
        if let Ok(journal) = ProvisioningJournalV1::parse(&file.bytes) {
            return self.recover_mode1(journal);
        }
        if let Ok(journal) = PlaintextProvisioningJournalV1::parse(&file.bytes) {
            return self.recover_plaintext(journal);
        }
        Err(SecurityError::Uncertain(
            "transaction journal is malformed; guard and units must remain closed".into(),
        ))
    }

    fn recover_mode1(&mut self, journal: ProvisioningJournalV1) -> SecurityResult<Option<String>> {
        match journal.recovery_action {
            RecoveryAction::RestorePriorState => {
                self.runtime.create_guard(&journal.transaction_id)?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_stably()?;
                let artifact = self.runtime.read_file(
                    MODE1_CREDENTIAL_PATH,
                    howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
                )?;
                let cleanup = if journal.artifact_preexisted {
                    None
                } else {
                    match artifact {
                        Some(artifact)
                            if artifact.sha256() == journal.planned_hashes.artifact_sha256 =>
                        {
                            let inspected = inspect_systemd_credential_envelope(&artifact.bytes)
                                .map_err(|error| SecurityError::operation(error.to_string()))?;
                            self.write_unadopted_manifest(
                                &journal.transaction_id,
                                &artifact,
                                &inspected,
                            )?;
                            Some(cleanup_command(&journal.transaction_id, &artifact.sha256()))
                        }
                        Some(_) => {
                            return Err(SecurityError::Uncertain(
                                "transaction-owned credential artifact changed during recovery"
                                    .into(),
                            ));
                        }
                        None => None,
                    }
                };
                self.restore_mode1_prior(&journal)?;
                self.finish_rollback_units(
                    &journal.service_unit_state,
                    &journal.socket_unit_state,
                )?;
                Ok(cleanup)
            }
            RecoveryAction::CompleteDisabledProvisioning => {
                self.runtime.create_guard(&journal.transaction_id)?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_stably()?;
                let config = self
                    .runtime
                    .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| SecurityError::Uncertain("committed config missing".into()))?;
                if config.sha256() == journal.planned_hashes.enabled_config_sha256 {
                    let disabled = journal.prior_config.as_ref().ok_or_else(|| {
                        SecurityError::Uncertain("disabled config backup missing".into())
                    })?;
                    let disabled_bytes = disabled
                        .bytes
                        .decode()
                        .map_err(|error| SecurityError::operation(error.to_string()))?;
                    if Sha256Digest::from_bytes(&disabled_bytes)
                        != journal.planned_hashes.disabled_config_sha256
                    {
                        return Err(SecurityError::Uncertain(
                            "disabled config backup hash changed".into(),
                        ));
                    }
                    self.runtime
                        .restore_file(howy_common::paths::CONFIG_FILE, Some(disabled))?;
                }
                self.validate_disabled_live(&journal)?;
                self.complete_disabled_transaction(&journal)?;
                Ok(None)
            }
            RecoveryAction::RestoreDisabledState => {
                self.runtime.create_guard(&journal.transaction_id)?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_stably()?;
                let receipt = self.read_receipt()?.ok_or_else(|| {
                    SecurityError::Uncertain("disabled receipt disappeared".into())
                })?;
                let disabled = journal
                    .prior_config
                    .as_ref()
                    .ok_or_else(|| SecurityError::Uncertain("disabled backup missing".into()))?;
                self.runtime
                    .restore_file(howy_common::paths::CONFIG_FILE, Some(disabled))?;
                if Sha256Digest::from_bytes(
                    &disabled
                        .bytes
                        .decode()
                        .map_err(|error| SecurityError::operation(error.to_string()))?,
                ) != receipt.config_patch.disabled_sha256
                {
                    return Err(SecurityError::Uncertain(
                        "disabled backup does not match receipt".into(),
                    ));
                }
                self.finish_rollback_units(
                    &journal.service_unit_state,
                    &journal.socket_unit_state,
                )?;
                Ok(None)
            }
            RecoveryAction::CompleteEnabledActivation => {
                self.runtime.create_guard(&journal.transaction_id)?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_stably()?;
                let receipt = self
                    .read_receipt()?
                    .ok_or_else(|| SecurityError::Uncertain("activation receipt missing".into()))?;
                let enabled = apply_receipted_config_patch(
                    &journal
                        .prior_config
                        .as_ref()
                        .ok_or_else(|| SecurityError::Uncertain("disabled backup missing".into()))?
                        .bytes
                        .decode()
                        .map_err(|error| SecurityError::operation(error.to_string()))?,
                    &receipt.config_patch,
                )
                .map_err(|error| SecurityError::operation(error.to_string()))?;
                self.runtime.write_file_atomic(
                    howy_common::paths::CONFIG_FILE,
                    &enabled,
                    0o600,
                    AtomicWriteMode::ExchangeOrCreate,
                )?;
                self.runtime.remove_guard()?;
                self.start_controlled()?;
                let enabled_receipt = match receipt.state {
                    ReceiptState::ProvisionedDisabled => enabled_receipt_from(&receipt)?,
                    ReceiptState::Enabled => receipt,
                };
                let status = self.runtime.security_info()?.ok_or_else(|| {
                    SecurityError::Uncertain("enabled daemon status missing".into())
                })?;
                validate_enabled_status(
                    &status,
                    &enabled_receipt,
                    None,
                    &journal.planned_hashes.enabled_config_sha256,
                )?;
                self.runtime.write_file_atomic(
                    SECURITY_RECEIPT_PATH,
                    &enabled_receipt
                        .deterministic_bytes()
                        .map_err(|error| SecurityError::operation(error.to_string()))?,
                    0o600,
                    AtomicWriteMode::ExchangeOrCreate,
                )?;
                self.runtime.remove_journal()?;
                Ok(None)
            }
        }
    }

    fn recover_plaintext(
        &mut self,
        journal: PlaintextProvisioningJournalV1,
    ) -> SecurityResult<Option<String>> {
        match journal.recovery_action {
            PlaintextRecoveryAction::RestorePriorState => {
                self.rollback_plaintext(&journal)?;
                Ok(None)
            }
            PlaintextRecoveryAction::CompleteActivation => {
                let config = self
                    .runtime
                    .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| SecurityError::Uncertain("Mode 0 config missing".into()))?;
                if config.sha256() != journal.enabled_config_sha256 {
                    return Err(SecurityError::Uncertain(
                        "Mode 0 config changed during recovery".into(),
                    ));
                }
                self.runtime.restore_file(MODE1_DROPIN_PATH, None)?;
                self.runtime.remove_guard()?;
                self.start_controlled()?;
                self.runtime.remove_journal()?;
                Ok(None)
            }
        }
    }

    fn rollback_mode1(
        &mut self,
        journal: &ProvisioningJournalV1,
        generated: bool,
        artifact: Option<(
            &[u8],
            &howy_common::provisioning::InspectedCredentialEnvelope,
        )>,
    ) -> SecurityResult<Option<String>> {
        self.runtime.create_guard(&journal.transaction_id)?;
        self.stop_readiness_transient(&journal.transient_unit)?;
        self.stop_units_stably()?;
        let mut cleanup = None;
        if generated {
            match self.runtime.read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )? {
                Some(observed) if observed.sha256() == journal.planned_hashes.artifact_sha256 => {
                    let (_, inspected) = artifact.ok_or_else(|| {
                        SecurityError::Uncertain(
                            "generated artifact evidence is unavailable during rollback".into(),
                        )
                    })?;
                    self.write_unadopted_manifest(&journal.transaction_id, &observed, inspected)?;
                    cleanup = Some(cleanup_command(&journal.transaction_id, &observed.sha256()));
                }
                Some(_) => {
                    return Err(SecurityError::Uncertain(
                        "transaction-owned credential artifact changed during rollback".into(),
                    ));
                }
                None => {}
            }
        }
        self.restore_mode1_prior(journal)?;
        self.finish_rollback_units(&journal.service_unit_state, &journal.socket_unit_state)?;
        Ok(cleanup)
    }

    fn restore_mode1_prior(&mut self, journal: &ProvisioningJournalV1) -> SecurityResult<()> {
        self.runtime.restore_file(
            howy_common::paths::CONFIG_FILE,
            journal.prior_config.as_ref(),
        )?;
        self.runtime
            .restore_file(MODE1_DROPIN_PATH, journal.prior_dropin.as_ref())?;
        self.runtime
            .restore_file(SECURITY_RECEIPT_PATH, journal.prior_receipt.as_ref())?;
        self.runtime.daemon_reload()
    }

    fn rollback_plaintext(
        &mut self,
        journal: &PlaintextProvisioningJournalV1,
    ) -> SecurityResult<()> {
        self.runtime.create_guard(&journal.transaction_id)?;
        self.stop_units_stably()?;
        self.runtime.restore_file(
            howy_common::paths::CONFIG_FILE,
            journal.prior_config.as_ref(),
        )?;
        self.runtime
            .restore_file(MODE1_DROPIN_PATH, journal.prior_dropin.as_ref())?;
        self.runtime.daemon_reload()?;
        self.finish_rollback_units(&journal.service_unit_state, &journal.socket_unit_state)
    }

    fn finish_rollback_units(
        &mut self,
        service: &StableUnitState,
        socket: &StableUnitState,
    ) -> SecurityResult<()> {
        self.runtime.remove_guard()?;
        restore_unit_target(self.runtime, socket)?;
        restore_unit_target(self.runtime, service)?;
        self.runtime.remove_journal()
    }

    fn complete_disabled_transaction(
        &mut self,
        journal: &ProvisioningJournalV1,
    ) -> SecurityResult<()> {
        self.validate_disabled_live(journal)?;
        self.runtime.remove_guard()?;
        self.runtime.remove_journal()?;
        // A disabled configuration cannot expose authentication. Restore only
        // the exact stable active targets observed before the transaction.
        restore_unit_target(self.runtime, &journal.socket_unit_state)?;
        restore_unit_target(self.runtime, &journal.service_unit_state)
    }

    fn validate_disabled_live(&mut self, journal: &ProvisioningJournalV1) -> SecurityResult<()> {
        for (path, maximum, expected) in [
            (
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
                &journal.planned_hashes.artifact_sha256,
            ),
            (
                MODE1_DROPIN_PATH,
                MAX_DROPIN_BYTES,
                &journal.planned_hashes.dropin_sha256,
            ),
            (
                howy_common::paths::CONFIG_FILE,
                MAX_CONFIG_BYTES,
                &journal.planned_hashes.disabled_config_sha256,
            ),
            (
                SECURITY_RECEIPT_PATH,
                MAX_RECEIPT_BYTES,
                &journal.planned_hashes.disabled_receipt_sha256,
            ),
        ] {
            let file = self.runtime.read_file(path, maximum)?.ok_or_else(|| {
                SecurityError::Uncertain(format!("committed object missing: {path}"))
            })?;
            if file.sha256() != *expected {
                return Err(SecurityError::Uncertain(format!(
                    "committed object changed: {path}"
                )));
            }
        }
        Ok(())
    }

    fn write_unadopted_manifest(
        &mut self,
        transaction_id: &str,
        artifact: &ObservedFile,
        inspected: &howy_common::provisioning::InspectedCredentialEnvelope,
    ) -> SecurityResult<()> {
        let identity = cleanup_identity(
            transaction_id,
            artifact,
            inspected.actual_key_id,
            inspected.envelope_sha256.clone(),
            inspected.envelope_size,
        );
        let bytes = UnadoptedArtifactV1::new(identity)
            .and_then(|manifest| manifest.deterministic_bytes())
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.runtime.write_file_atomic(
            &unadopted_manifest_path(transaction_id),
            &bytes,
            0o600,
            AtomicWriteMode::ExchangeOrCreate,
        )
    }

    fn read_receipt(&mut self) -> SecurityResult<Option<ProvisioningReceiptV1>> {
        self.read_receipt_file()
            .map(|receipt| receipt.map(|(_, receipt)| receipt))
    }

    fn read_receipt_file(
        &mut self,
    ) -> SecurityResult<Option<(ObservedFile, ProvisioningReceiptV1)>> {
        self.runtime
            .read_file(SECURITY_RECEIPT_PATH, MAX_RECEIPT_BYTES)?
            .map(|file| {
                file.validate_regular(0, 0, 0o600)?;
                let receipt = ProvisioningReceiptV1::parse(&file.bytes)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                Ok((file, receipt))
            })
            .transpose()
    }

    fn run_strong_readiness(
        &mut self,
        transaction_id: &str,
        config_path: &str,
        artifact_path: &str,
    ) -> SecurityResult<VerifierResultV1> {
        let command = readiness_command(transaction_id, config_path, artifact_path);
        match self.runtime.run_readiness(&command) {
            Ok(output) => VerifierResultV1::parse(&output)
                .map_err(|error| SecurityError::operation(error.to_string())),
            Err(error) => {
                let _ = self
                    .runtime
                    .stop_and_kill_transient(&readiness_unit_name(transaction_id));
                Err(error)
            }
        }
    }

    fn stop_readiness_transient(&mut self, unit: &str) -> SecurityResult<()> {
        if self.runtime.transient_exists(unit)? {
            self.runtime.stop_and_kill_transient(unit)?;
        }
        Ok(())
    }

    fn stable_unit(&mut self, unit: UnitKind) -> SecurityResult<StableUnitState> {
        let deadline = self
            .runtime
            .monotonic_millis()
            .checked_add(10_000)
            .ok_or_else(|| SecurityError::operation("unit settle deadline overflow"))?;
        loop {
            if self.runtime.monotonic_millis() >= deadline {
                return Err(SecurityError::Refused(
                    "required unit did not reach a stable state".into(),
                ));
            }
            let observation = self.runtime.unit_observation(unit)?;
            match classify_unit_admissibility(observation) {
                UnitAdmissibility::Admissible { .. } => {
                    return Ok(StableUnitState {
                        unit_kind: observation.unit_kind,
                        load_state: observation.load_state,
                        active_state: observation.active_state,
                        sub_state: observation.sub_state,
                        unit_file_state: observation.unit_file_state,
                    });
                }
                UnitAdmissibility::Settle => self.runtime.settle_step()?,
                UnitAdmissibility::RefuseMasked => {
                    return Err(SecurityError::Refused("required unit is masked".into()));
                }
                UnitAdmissibility::RefuseFailed => {
                    return Err(SecurityError::Refused("required unit is failed".into()));
                }
                UnitAdmissibility::RefuseUnstable => {
                    return Err(SecurityError::Refused(
                        "required unit state is unsupported".into(),
                    ));
                }
            }
        }
    }

    fn stop_units_stably(&mut self) -> SecurityResult<()> {
        self.runtime.stop_unit(UnitKind::Socket)?;
        self.runtime.boundary("socket-stopped")?;
        self.runtime.stop_unit(UnitKind::Service)?;
        self.runtime.boundary("service-stopped")?;
        for kind in [UnitKind::Socket, UnitKind::Service] {
            let state = self.stable_unit(kind)?;
            if state.rollback_target() != Some(StableRollbackTarget::InactiveDead) {
                return Err(SecurityError::operation("unit did not stop stably"));
            }
        }
        Ok(())
    }

    fn start_controlled(&mut self) -> SecurityResult<()> {
        self.runtime.start_unit(UnitKind::Socket)?;
        self.runtime.boundary("socket-started")?;
        self.runtime.start_unit(UnitKind::Service)?;
        self.runtime.boundary("service-started")?;
        let socket = self.stable_unit(UnitKind::Socket)?;
        let service = self.stable_unit(UnitKind::Service)?;
        if socket.rollback_target() != Some(StableRollbackTarget::ActiveListening)
            || service.rollback_target() != Some(StableRollbackTarget::ActiveRunning)
        {
            return Err(SecurityError::operation("units did not start stably"));
        }
        Ok(())
    }

    fn persist_mode1_journal(&mut self, journal: &ProvisioningJournalV1) -> SecurityResult<()> {
        let bytes = journal
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.runtime.persist_journal(&bytes)
    }

    fn advance_mode1(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        phase: JournalPhase,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = phase;
        journal.recovery_action = recovery_action_for_phase(phase);
        match phase {
            JournalPhase::ArtifactCommitted => {
                journal.live_hashes.artifact_sha256 =
                    Some(journal.planned_hashes.artifact_sha256.clone());
            }
            JournalPhase::DropinCommitted => {
                journal.live_hashes.dropin_sha256 =
                    Some(journal.planned_hashes.dropin_sha256.clone());
            }
            JournalPhase::DisabledConfigCommitted => {
                journal.live_hashes.config_sha256 =
                    Some(journal.planned_hashes.disabled_config_sha256.clone());
            }
            JournalPhase::DisabledReceiptCommitted => {
                journal.live_hashes.disabled_receipt_sha256 =
                    Some(journal.planned_hashes.disabled_receipt_sha256.clone());
            }
            JournalPhase::EnabledConfigCommitted => {
                journal.live_hashes.config_sha256 =
                    Some(journal.planned_hashes.enabled_config_sha256.clone());
            }
            JournalPhase::EnabledReceiptCommitted => {
                journal.live_hashes.enabled_receipt_sha256 =
                    Some(journal.planned_hashes.enabled_receipt_sha256.clone());
            }
            _ => {}
        }
        validate_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_mode1_journal(journal)?;
        self.runtime.boundary("journal-phase-synced")
    }

    fn persist_plaintext_journal(
        &mut self,
        journal: &PlaintextProvisioningJournalV1,
    ) -> SecurityResult<()> {
        let bytes = journal
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.runtime.persist_journal(&bytes)
    }

    fn advance_plaintext(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
        phase: PlaintextJournalPhase,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = phase;
        journal.recovery_action = plaintext_recovery_action_for_phase(phase);
        if phase.ordinal() >= PlaintextJournalPhase::EnabledConfigCommitted.ordinal() {
            journal.live_config_sha256 = Some(journal.enabled_config_sha256.clone());
        }
        validate_plaintext_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_plaintext_journal(journal)?;
        self.runtime.boundary("journal-phase-synced")
    }
}

fn parse_explicit_mode(config: Option<&ObservedFile>) -> SecurityResult<Option<(u8, u64)>> {
    let Some(config) = config else {
        return Ok(None);
    };
    config.validate_regular(0, 0, 0o600)?;
    let source = std::str::from_utf8(&config.bytes)
        .map_err(|_| SecurityError::operation("configuration is not UTF-8"))?;
    let parsed: HowyConfig =
        toml::from_str(source).map_err(|_| SecurityError::operation("configuration is invalid"))?;
    parsed.validate().map_err(SecurityError::operation)?;
    Ok(Some((
        parsed.security.embedding_mode as u8,
        parsed.security.key_epoch,
    )))
}

fn build_disabled_mode1_config(config: Option<&ObservedFile>) -> SecurityResult<Vec<u8>> {
    let mut parsed = match config {
        Some(file) => toml::from_str::<HowyConfig>(
            std::str::from_utf8(&file.bytes)
                .map_err(|_| SecurityError::operation("configuration is not UTF-8"))?,
        )
        .map_err(|_| SecurityError::operation("configuration is invalid"))?,
        None => HowyConfig::secure_bootstrap_template(),
    };
    parsed.core.disabled = true;
    parsed.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
    parsed.security.key_epoch = MODE1_KEY_EPOCH;
    parsed.security.cached.credential_name = MODE1_CREDENTIAL_NAME.into();
    parsed.presence.mode = PresenceMode::Confirm;
    if parsed.presence.allowed_pam_services.is_empty() {
        parsed.presence.allowed_pam_services = vec!["sudo".into()];
    }
    parsed.validate().map_err(SecurityError::operation)?;
    let bytes = toml::to_string_pretty(&parsed)
        .map_err(|_| SecurityError::operation("candidate configuration serialization failed"))?
        .into_bytes();
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(SecurityError::operation(
            "candidate configuration is too large",
        ));
    }
    Ok(bytes)
}

fn build_enabled_mode0_config(config: Option<&ObservedFile>) -> SecurityResult<Vec<u8>> {
    let mut parsed = match config {
        Some(file) => toml::from_str::<HowyConfig>(
            std::str::from_utf8(&file.bytes)
                .map_err(|_| SecurityError::operation("configuration is not UTF-8"))?,
        )
        .map_err(|_| SecurityError::operation("configuration is invalid"))?,
        None => HowyConfig::legacy_defaults(),
    };
    parsed.core.disabled = false;
    parsed.security.embedding_mode = EmbeddingSecurityMode::Plaintext;
    parsed.validate().map_err(SecurityError::operation)?;
    let bytes = toml::to_string_pretty(&parsed)
        .map_err(|_| SecurityError::operation("Mode 0 configuration serialization failed"))?
        .into_bytes();
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(SecurityError::operation(
            "Mode 0 configuration is too large",
        ));
    }
    Ok(bytes)
}

fn anticipated_policy(
    inspected: &howy_common::provisioning::InspectedCredentialEnvelope,
    requested_selector: CredentialSelector,
) -> SecurityResult<CredentialPolicyMetadata> {
    if inspected.actual_key_id.selector() != requested_selector {
        return Err(SecurityError::operation("credential selector mismatch"));
    }
    Ok(CredentialPolicyMetadata {
        requested_selector,
        actual_key_id: inspected.actual_key_id,
        system_scope: true,
        embedded_name: MODE1_CREDENTIAL_NAME.into(),
        literal_pcr_mask: inspected.literal_pcr_mask,
        public_key_policy: false,
        null_key: false,
        envelope_sha256: inspected.envelope_sha256.clone(),
        envelope_size: inspected.envelope_size,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_disabled_receipt(
    transaction_id: &str,
    artifact: &[u8],
    artifact_metadata: &FileMetadataSnapshotV1,
    policy: CredentialPolicyMetadata,
    config_patch: howy_common::provisioning::ConfigPatchV1,
    base_unit_sha256: Sha256Digest,
    verifier: VerifierResultV1,
) -> SecurityResult<ProvisioningReceiptV1> {
    let receipt = ProvisioningReceiptV1 {
        schema_version: PROVISIONING_SCHEMA_VERSION,
        state: ReceiptState::ProvisionedDisabled,
        transaction_id: transaction_id.into(),
        mode: 1,
        epoch: 1,
        credential_name: MODE1_CREDENTIAL_NAME.into(),
        artifact: ArtifactReceipt {
            path: MODE1_CREDENTIAL_PATH.into(),
            sha256: Sha256Digest::from_bytes(artifact),
            size: artifact.len() as u64,
            uid: artifact_metadata.uid,
            gid: artifact_metadata.gid,
            mode: artifact_metadata.permissions,
            nlink: artifact_metadata.link_count,
            credential_policy: policy,
        },
        config_patch,
        unit_credential: UnitCredentialReceipt {
            base_unit_sha256,
            dropin_sha256: Sha256Digest::from_bytes(MODE1_DROPIN_BYTES),
            source_companion_name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.into(),
            configured_credential_source: ConfiguredMode1CredentialSource::parse(
                MODE1_CREDENTIAL_PATH.as_bytes(),
                Mode1CredentialSourcePolicy::Production,
            )
            .map_err(|error| SecurityError::operation(error.to_string()))?,
        },
        verifier: VerifierReceipt::new(verifier)
            .map_err(|error| SecurityError::operation(error.to_string()))?,
    };
    receipt
        .validate()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    Ok(receipt)
}

fn enabled_receipt_from(disabled: &ProvisioningReceiptV1) -> SecurityResult<ProvisioningReceiptV1> {
    let mut enabled = disabled.clone();
    enabled.state = ReceiptState::Enabled;
    enabled.verifier.output.config_sha256 = enabled.config_patch.enabled_sha256.clone();
    enabled.verifier.output_sha256 = enabled
        .verifier
        .output
        .deterministic_sha256()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    validate_receipt_transition(disabled, &enabled)
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    Ok(enabled)
}

fn receipt_matches_live<R: SecurityRuntime>(
    receipt: &ProvisioningReceiptV1,
    config: &ObservedFile,
    artifact: &ObservedFile,
    runtime: &mut R,
) -> SecurityResult<bool> {
    let expected_config = match receipt.state {
        ReceiptState::ProvisionedDisabled => &receipt.config_patch.disabled_sha256,
        ReceiptState::Enabled => &receipt.config_patch.enabled_sha256,
    };
    if config.sha256() != *expected_config
        || artifact.sha256() != receipt.artifact.sha256
        || artifact.metadata.uid != receipt.artifact.uid
        || artifact.metadata.gid != receipt.artifact.gid
        || artifact.metadata.permissions != receipt.artifact.mode
        || artifact.metadata.link_count != receipt.artifact.nlink
    {
        return Ok(false);
    }
    let dropin = runtime.read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?;
    let base_unit = runtime.read_file(BASE_SERVICE_UNIT_PATH, MAX_DROPIN_BYTES)?;
    Ok(dropin.is_some_and(|dropin| {
        dropin.sha256() == receipt.unit_credential.dropin_sha256
            && dropin.bytes == MODE1_DROPIN_BYTES
    }) && base_unit
        .is_some_and(|unit| unit.sha256() == receipt.unit_credential.base_unit_sha256))
}

fn generated_artifact_metadata() -> FileMetadataSnapshotV1 {
    FileMetadataSnapshotV1 {
        schema_version: PROVISIONING_SCHEMA_VERSION,
        object_type: FileObjectType::RegularFile,
        uid: 0,
        gid: 0,
        permissions: 0o600,
        link_count: 1,
        link_policy: howy_common::provisioning::FileLinkPolicy::ExactlyOne,
        byte_length: 0,
        restorable_timestamps: howy_common::provisioning::RestorableFileTimestampsV1 {
            access: howy_common::provisioning::FileTimestampV1 {
                seconds: 0,
                nanoseconds: 0,
            },
            modification: howy_common::provisioning::FileTimestampV1 {
                seconds: 0,
                nanoseconds: 0,
            },
        },
    }
}

fn cleanup_identity(
    transaction_id: &str,
    artifact: &ObservedFile,
    actual_key_id: SystemdCredentialKeyId,
    envelope_sha256: Sha256Digest,
    envelope_size: u64,
) -> CleanupArtifactIdentityV1 {
    CleanupArtifactIdentityV1 {
        transaction_id: transaction_id.into(),
        descriptor: artifact.cleanup_descriptor(),
        source: CredentialArtifactSourceIdentityV1 {
            credential_name: MODE1_CREDENTIAL_NAME.into(),
            envelope_sha256,
            envelope_size,
            actual_key_id,
        },
    }
}

fn validate_enabled_status(
    status: &SecurityInfoResult,
    receipt: &ProvisioningReceiptV1,
    prior_invocation: Option<&str>,
    config_sha256: &Sha256Digest,
) -> SecurityResult<()> {
    let states = status
        .validate_strict()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    if status.active_security_mode != 1
        || status.key_epoch != 1
        || status.config_sha256 != config_sha256.as_str()
        || status.credential_name != MODE1_CREDENTIAL_NAME
        || status.configured_credential_source != MODE1_CREDENTIAL_PATH
        || !status.prompt_required
        || states.backend != SecurityBackendStateV1::Ready
        || status.daemon_version != receipt.verifier.output.daemon.version
        || status.build_identity != receipt.verifier.output.daemon.build_identity
        || status.binary_absolute_path != receipt.verifier.output.daemon.binary_absolute_path
        || status.binary_sha256 != receipt.verifier.output.daemon.binary_sha256.as_str()
        || prior_invocation.is_some_and(|prior| prior == status.daemon_invocation_id)
    {
        return Err(SecurityError::operation(
            "started daemon status does not match the enabled receipt",
        ));
    }
    Ok(())
}

fn validate_mode0_status(
    status: &SecurityInfoResult,
    config_sha256: &Sha256Digest,
) -> SecurityResult<()> {
    let states = status
        .validate_strict()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    if status.active_security_mode != 0
        || status.config_sha256 != config_sha256.as_str()
        || !status.credential_name.is_empty()
        || !status.configured_credential_source.is_empty()
        || states.backend != SecurityBackendStateV1::Ready
    {
        return Err(SecurityError::operation(
            "started daemon is not exact Mode 0",
        ));
    }
    Ok(())
}

fn restore_unit_target<R: SecurityRuntime>(
    runtime: &mut R,
    state: &StableUnitState,
) -> SecurityResult<()> {
    match state.rollback_target() {
        Some(StableRollbackTarget::ActiveRunning) => runtime.start_unit(UnitKind::Service),
        Some(StableRollbackTarget::ActiveListening) => runtime.start_unit(UnitKind::Socket),
        Some(StableRollbackTarget::InactiveDead) => Ok(()),
        None => Err(SecurityError::Uncertain(
            "journal contains an unstable rollback target".into(),
        )),
    }
}

fn validate_transaction_id(value: &str) -> SecurityResult<()> {
    if value.is_empty()
        || value.len() > howy_common::provisioning::MAX_TRANSACTION_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SecurityError::Refused("invalid transaction ID".into()));
    }
    Ok(())
}

fn cleanup_command(transaction_id: &str, artifact_sha256: &Sha256Digest) -> String {
    format!(
        "sudo howy security cleanup-unadopted --transaction {transaction_id} --artifact-sha256 {}",
        artifact_sha256.as_str()
    )
}

fn unadopted_manifest_path(transaction_id: &str) -> String {
    format!("{SECURITY_UNADOPTED_DIRECTORY}/{transaction_id}.json")
}
