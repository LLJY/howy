use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use howy_common::config::{EmbeddingSecurityMode, HowyConfig, PresenceMode};
use howy_common::protocol::{
    DaemonInfo, DaemonInfoExpectation, SecurityBackendStateV1, SecurityInfoResult,
    SecurityPoisonStateV1, SecurityReadinessStateV1, validate_daemon_info_for_activation,
};
use howy_common::provisioning::{
    ArtifactDescriptorIdentityV1, ArtifactReceipt, AtomicExpectedTargetV1, AtomicFileIdentityV1,
    AtomicWriteKindV1, AtomicWriteObservationV1, AtomicWritePlanV1, AtomicWriteRecordV1,
    AtomicWriteStateV1, BASE_SERVICE_UNIT_PATH, BackupHashes, CleanupAdmissibility,
    CleanupArtifactIdentityV1, CleanupManifestIdentityV1, CleanupPreAdmissionV1,
    CleanupQuarantineStateV1, CleanupQuarantineV1, CleanupReferences, CleanupStateInput,
    ConfiguredMode1CredentialSource, CredentialArtifactSourceIdentityV1,
    CredentialCryptographicValidation, CredentialPolicyMetadata, CredentialSelector,
    DaemonVerifierIdentityV1, DifferentModeArtifactState, DirectoryIdentityV1, EffectiveUnitSetV1,
    ExactFileSnapshot, ExistingProvisioningArtifact, ExistingProvisioningConfig,
    FileMetadataSnapshotV1, FileObjectType, JournalPhase, LiveObjectHashes, MAX_CONFIG_BYTES,
    MAX_DROPIN_BYTES, MAX_JOURNAL_BYTES, MAX_RECEIPT_BYTES, MODE1_CREDENTIAL_NAME,
    MODE1_CREDENTIAL_PATH, MODE1_CREDENTIAL_SOURCE_COMPANION_NAME, MODE1_DROPIN_PATH,
    MODE1_KEY_EPOCH, Mode1CredentialSourcePolicy, ObservedCleanupArtifactIdentityV1,
    PROVISIONING_SCHEMA_VERSION, PlaintextJournalPhase, PlaintextProvisioningJournalV1,
    PlaintextRecoveryAction, PlannedObjectHashes, ProvisioningJournalV1, ProvisioningReceiptV1,
    ProvisioningState, ProvisioningStateInput, REQUIRED_SECURITY_DIRECTORIES, ReceiptState,
    RecoveryAction, RestorableFileTimestampsV1, SECURITY_JOURNAL_PATH, SECURITY_RECEIPT_PATH,
    SECURITY_TRANSACTION_GUARD_PATH, SECURITY_UNADOPTED_DIRECTORY, SecurityDirectoryRecordV1,
    Sha256Digest, StableRollbackTarget, StableUnitState, SupervisorJournalV1,
    SupervisorOperationV1, SupervisorPhaseV1, SystemdCredentialKeyId, TransactionGuardIdentityV1,
    UnadoptedArtifactV1, UnitAdmissibility, UnitCredentialReceipt, UnitKind, UnitObservation,
    VerifierReceipt, VerifierResultV1, apply_receipted_config_patch,
    canonical_journal_staging_path, classify_cleanup_admissibility, classify_provisioning_state,
    classify_unit_admissibility, disabled_post_provision_unit_targets,
    inspect_systemd_credential_envelope, plaintext_recovery_action_for_phase,
    planned_effective_units, prepare_config_enable_patch, recovery_action_for_phase,
    validate_journal_transition, validate_plaintext_journal_transition,
    validate_receipt_transition, validate_supervisor_journal_transition,
    validate_systemd_credential_envelope,
};

use super::command::{
    CommandSpec, KeySelection, credential_encrypt_command, readiness_command, readiness_unit_name,
};

pub const MODE1_DROPIN_BYTES: &[u8] = b"[Service]\n\
LoadCredentialEncrypted=\n\
LoadCredentialEncrypted=howy.storage.mode1.epoch1:/etc/credstore.encrypted/howy.storage.mode1.epoch1\n\
SetCredential=\n\
SetCredential=howy.storage.mode1.source:/etc/credstore.encrypted/howy.storage.mode1.epoch1\n";

pub const MODE0_DROPIN_BYTES: &[u8] = b"[Service]\n\
LoadCredentialEncrypted=\n\
SetCredential=\n";

/// Compile-time pins for the exact packaged fragments reviewed by the
/// transaction engine. Effective-unit trust is never learned from arbitrary
/// live fragment contents.
pub const BASE_SERVICE_UNIT_BYTES: &[u8] = include_bytes!("../../../../systemd/howy.service");
pub const BASE_SOCKET_UNIT_BYTES: &[u8] = include_bytes!("../../../../systemd/howy.socket");

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

    pub(super) fn validate_regular(
        &self,
        uid: u32,
        gid: u32,
        permissions: u32,
    ) -> SecurityResult<()> {
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

    pub(super) fn cleanup_descriptor(&self) -> ArtifactDescriptorIdentityV1 {
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

    pub(super) fn atomic_identity(&self) -> AtomicFileIdentityV1 {
        AtomicFileIdentityV1 {
            device_id: self.device_id,
            inode: self.inode,
            object_type: self.metadata.object_type,
            uid: self.metadata.uid,
            gid: self.metadata.gid,
            permissions: self.metadata.permissions,
            link_count: self.metadata.link_count,
            byte_length: self.metadata.byte_length,
            sha256: self.sha256(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicTargetObservation {
    pub parent_directory: DirectoryIdentityV1,
    pub target: Option<ObservedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtomicWriteReconciliation {
    NotCommitted,
    Committed(AtomicWriteObservationV1),
}

pub trait SecurityRuntime {
    fn require_root(&mut self) -> SecurityResult<()>;
    fn acquire_lock(&mut self) -> SecurityResult<()>;
    fn require_systemd_261(&mut self) -> SecurityResult<()>;
    fn transaction_id(&mut self) -> SecurityResult<String>;
    fn generate_key(&mut self) -> SecurityResult<Box<dyn SecretKeyMaterial>>;
    fn read_file(&mut self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>>;
    fn observe_atomic_target(
        &mut self,
        path: &str,
        maximum: usize,
    ) -> SecurityResult<AtomicTargetObservation>;
    fn create_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        bytes: &[u8],
    ) -> SecurityResult<AtomicFileIdentityV1>;
    fn commit_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: &AtomicFileIdentityV1,
    ) -> SecurityResult<AtomicWriteObservationV1>;
    fn reconcile_atomic_write(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: Option<&AtomicFileIdentityV1>,
    ) -> SecurityResult<AtomicWriteReconciliation>;
    fn remove_atomic_backup(
        &mut self,
        plan: &AtomicWritePlanV1,
        observation: &AtomicWriteObservationV1,
    ) -> SecurityResult<()>;
    fn remove_file_exact(
        &mut self,
        path: &str,
        expected: &AtomicFileIdentityV1,
    ) -> SecurityResult<()>;
    fn plan_security_directory(
        &mut self,
        path: &str,
        permissions: u32,
    ) -> SecurityResult<SecurityDirectoryRecordV1>;
    fn ensure_security_directory(
        &mut self,
        intent: &SecurityDirectoryRecordV1,
    ) -> SecurityResult<DirectoryIdentityV1>;
    fn verify_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()>;
    fn rollback_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()>;
    fn create_guard(
        &mut self,
        transaction_id: &str,
        expected: Option<&TransactionGuardIdentityV1>,
    ) -> SecurityResult<TransactionGuardIdentityV1>;
    fn remove_guard(
        &mut self,
        transaction_id: &str,
        expected: &TransactionGuardIdentityV1,
    ) -> SecurityResult<()>;
    fn load_journal(&mut self) -> SecurityResult<Option<ObservedFile>>;
    fn persist_journal(
        &mut self,
        prior: Option<&ObservedFile>,
        bytes: &[u8],
    ) -> SecurityResult<ObservedFile>;
    fn remove_journal(
        &mut self,
        transaction_id: &str,
        expected: &ObservedFile,
    ) -> SecurityResult<()>;
    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation>;
    fn effective_unit_observation(
        &mut self,
        unit: UnitKind,
    ) -> SecurityResult<howy_common::provisioning::EffectiveUnitObservationV1>;
    fn resolve_key_selection(&mut self, requested: KeySelection) -> SecurityResult<KeySelection>;
    fn host_secret_preexisting_secure(&mut self) -> SecurityResult<bool>;
    fn daemon_verifier_identity(&mut self) -> SecurityResult<DaemonVerifierIdentityV1>;
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
    fn daemon_info(&mut self) -> SecurityResult<Option<DaemonInfo>>;
    fn quarantine_artifact_exact(
        &mut self,
        expected: &ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()>;
    fn restore_quarantined_artifact_exact(
        &mut self,
        expected: &ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()>;
    fn unlink_quarantined_artifact_exact(
        &mut self,
        expected: &ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()>;
    fn boundary(&mut self, name: &'static str) -> SecurityResult<()>;
}

pub struct SecurityEngine<'a, R: SecurityRuntime> {
    runtime: &'a mut R,
    armed_transaction: Option<String>,
    active_guard: Option<TransactionGuardIdentityV1>,
    journal_observation: Option<ObservedFile>,
}

impl<'a, R: SecurityRuntime> SecurityEngine<'a, R> {
    pub fn new(runtime: &'a mut R) -> Self {
        Self {
            runtime,
            armed_transaction: None,
            active_guard: None,
            journal_observation: None,
        }
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
        self.supervise(|engine| {
            if let Some(command) = engine.recover_locked()? {
                return Err(SecurityError::Refused(format!(
                    "a prior transaction was recovered with an unadopted artifact; use `{command}` before continuing"
                )));
            }
            engine.runtime.require_systemd_261()?;
            match request.mode {
                ProvisionMode::Plaintext => engine.provision_plaintext(),
                ProvisionMode::CachedAead => engine.provision_mode1(request),
                ProvisionMode::EphemeralAead => unreachable!(),
            }
        })
    }

    pub fn enable(&mut self) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        self.supervise(|engine| {
            if let Some(command) = engine.recover_locked()? {
                return Err(SecurityError::Refused(format!(
                    "a prior transaction was recovered with an unadopted artifact; use `{command}` before continuing"
                )));
            }
            engine.runtime.require_systemd_261()?;
            engine.enable_mode1()
        })
    }

    pub fn recover(&mut self) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        self.supervise(|engine| {
            let cleanup_command = engine.recover_locked()?;
            Ok(SecurityOutcome {
                messages: vec!["Security transaction recovery complete.".into()],
                cleanup_command,
            })
        })
    }

    pub fn cleanup_unadopted(
        &mut self,
        request: CleanupRequest,
    ) -> SecurityResult<SecurityOutcome> {
        self.runtime.require_root()?;
        self.runtime.acquire_lock()?;
        self.supervise(|engine| {
            let _ = engine.recover_locked()?;
            engine.cleanup_locked(request)
        })
    }

    fn supervise<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> SecurityResult<T>,
    ) -> SecurityResult<T> {
        let result = catch_unwind(AssertUnwindSafe(|| action(self)));
        match result {
            Ok(Ok(value)) => Ok(value),
            #[cfg(test)]
            Ok(Err(error @ SecurityError::InjectedCrash(_))) => Err(error),
            Ok(Err(error)) if self.armed_transaction.is_none() => Err(error),
            Ok(Err(error)) => Err(self.fail_closed(error.to_string())),
            Err(_) if self.armed_transaction.is_none() => Err(SecurityError::Uncertain(
                "security transaction panicked before its durable identity was available".into(),
            )),
            Err(_) => Err(self.fail_closed("security transaction panicked")),
        }
    }

    fn fail_closed(&mut self, reason: impl Into<String>) -> SecurityError {
        let reason = reason.into();
        let mut transaction_id = self
            .armed_transaction
            .clone()
            .unwrap_or_else(|| "manual-recovery".to_owned());
        let mut failures = Vec::new();
        if validate_transaction_id(&transaction_id).is_err() {
            match self.runtime.transaction_id() {
                Ok(generated) if validate_transaction_id(&generated).is_ok() => {
                    transaction_id = generated;
                }
                Ok(_) => {
                    failures.push("guard: generated fail-closed transaction id is invalid".into())
                }
                Err(error) => failures.push(format!("guard identity: {error}")),
            }
        }
        let prior_guard = self.active_guard.clone();
        let mut guard_transition_failed = false;
        match self
            .runtime
            .create_guard(&transaction_id, self.active_guard.as_ref())
        {
            Ok(guard) => {
                let identity_changed = prior_guard.as_ref() != Some(&guard);
                self.active_guard = Some(guard.clone());
                if identity_changed
                    && let Err(error) = self.persist_guard_identity_transition(&guard)
                {
                    guard_transition_failed = true;
                    failures.push(format!("guard journal transition: {error}"));
                }
            }
            Err(error) => failures.push(format!("guard: {error}")),
        }
        if let Err(error) = self.stop_units_under_one_deadline() {
            failures.push(format!("unit quiescence: {error}"));
        }
        if !guard_transition_failed && let Err(error) = self.persist_supervisor_failure_marker() {
            failures.push(format!("journal marker: {error}"));
        }
        let suffix = if failures.is_empty() {
            String::new()
        } else {
            format!(
                "; fail-closed best effort also reported {}",
                failures.join(", ")
            )
        };
        SecurityError::Uncertain(format!(
            "{reason}; guard and journal retained with units required inactive{suffix}"
        ))
    }

    fn begin_supervised_transaction(
        &mut self,
        operation: SupervisorOperationV1,
        cleanup: Option<(
            CleanupArtifactIdentityV1,
            CleanupManifestIdentityV1,
            CleanupPreAdmissionV1,
        )>,
    ) -> SecurityResult<SupervisorJournalV1> {
        let transaction_id = self.runtime.transaction_id()?;
        // Cleanup has already captured and classified every immutable input in
        // its bound pre-admission snapshot. Re-reading those inputs here would
        // create an unguarded race window. Other operations capture exact
        // rollback snapshots before their first durable side effect.
        let (
            prior_config_file,
            prior_config,
            prior_dropin_file,
            prior_dropin,
            prior_receipt_file,
            prior_receipt,
        ) = if cleanup.is_some() {
            (None, None, None, None, None, None)
        } else {
            let prior_config_file = self
                .runtime
                .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
            if let Some(file) = &prior_config_file {
                file.validate_regular(0, 0, 0o600)?;
                let source = std::str::from_utf8(&file.bytes)
                    .map_err(|_| SecurityError::operation("prior config is not UTF-8"))?;
                let config: HowyConfig = toml::from_str(source)
                    .map_err(|_| SecurityError::operation("prior config is malformed"))?;
                config.validate().map_err(SecurityError::operation)?;
            }
            let prior_config = prior_config_file
                .as_ref()
                .map(|file| file.snapshot(MAX_CONFIG_BYTES))
                .transpose()?;

            let prior_dropin_file = self
                .runtime
                .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?;
            if let Some(file) = &prior_dropin_file {
                file.validate_regular(0, 0, 0o600)?;
                if file.bytes != MODE0_DROPIN_BYTES && file.bytes != MODE1_DROPIN_BYTES {
                    return Err(SecurityError::operation(
                        "prior security drop-in is not an exact reviewed mode",
                    ));
                }
            }
            let prior_dropin = prior_dropin_file
                .as_ref()
                .map(|file| file.snapshot(MAX_DROPIN_BYTES))
                .transpose()?;

            let prior_receipt_file = self
                .runtime
                .read_file(SECURITY_RECEIPT_PATH, MAX_RECEIPT_BYTES)?;
            if let Some(file) = &prior_receipt_file {
                file.validate_regular(0, 0, 0o600)?;
                ProvisioningReceiptV1::parse(&file.bytes)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
            }
            let prior_receipt = prior_receipt_file
                .as_ref()
                .map(|file| file.snapshot(MAX_RECEIPT_BYTES))
                .transpose()?;
            (
                prior_config_file,
                prior_config,
                prior_dropin_file,
                prior_dropin,
                prior_receipt_file,
                prior_receipt,
            )
        };

        let (service, socket, effective, prior_daemon_invocation_id) =
            if let Some((_, _, pre_admission)) = cleanup.as_ref() {
                (
                    stable_cleanup_unit(pre_admission.service)?,
                    stable_cleanup_unit(pre_admission.socket)?,
                    pre_admission.effective_units.clone(),
                    None,
                )
            } else {
                let (service, socket) = self.stable_unit_pair()?;
                let effective = self.observe_effective_units()?;
                let prior_daemon_invocation_id = self.capture_prior_daemon_invocation(&service)?;
                let (confirmed_service, confirmed_socket) = self.stable_unit_pair()?;
                let confirmed_effective = self.observe_effective_units()?;
                let confirmed_invocation =
                    self.capture_prior_daemon_invocation(&confirmed_service)?;
                if service != confirmed_service
                    || socket != confirmed_socket
                    || effective != confirmed_effective
                    || prior_daemon_invocation_id != confirmed_invocation
                {
                    return Err(SecurityError::operation(
                        "pre-journal unit/invocation snapshot did not remain coherent",
                    ));
                }
                (service, socket, effective, prior_daemon_invocation_id)
            };
        let cleanup_artifact = cleanup.as_ref().map(|(artifact, _, _)| artifact.clone());
        let cleanup_manifest = cleanup.as_ref().map(|(_, manifest, _)| manifest.clone());
        let cleanup_pre_admission = cleanup
            .as_ref()
            .map(|(_, _, pre_admission)| pre_admission.clone());
        let mut journal = SupervisorJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            generation: 1,
            prior_journal_identity: None,
            journal_staging_path: canonical_journal_staging_path(&transaction_id)
                .map_err(|error| SecurityError::operation(error.to_string()))?,
            guard: None,
            operation,
            phase: SupervisorPhaseV1::Prepared,
            prior_config,
            prior_dropin,
            prior_receipt,
            service_unit_state: Some(service.clone()),
            socket_unit_state: Some(socket.clone()),
            prior_daemon_invocation_id: prior_daemon_invocation_id.clone(),
            prior_effective_units: Some(effective.clone()),
            transaction_owned_paths: {
                let mut paths = sorted_paths([
                    howy_common::paths::CONFIG_FILE,
                    MODE1_DROPIN_PATH,
                    SECURITY_RECEIPT_PATH,
                    SECURITY_TRANSACTION_GUARD_PATH,
                ]);
                paths.push(
                    canonical_journal_staging_path(&transaction_id)
                        .map_err(|error| SecurityError::operation(error.to_string()))?,
                );
                if operation == SupervisorOperationV1::CleanupUnadopted {
                    paths.push(cleanup_quarantine_path(&transaction_id));
                }
                paths.sort();
                paths
            },
            atomic_writes: Vec::new(),
            security_directories: Vec::new(),
            cleanup_artifact,
            cleanup_manifest,
            cleanup_pre_admission,
            cleanup_quarantine: (operation == SupervisorOperationV1::CleanupUnadopted).then(|| {
                CleanupQuarantineV1 {
                    path: cleanup_quarantine_path(&transaction_id),
                    state: CleanupQuarantineStateV1::Planned,
                }
            }),
            supervisor_failed: false,
        };
        self.armed_transaction = Some(transaction_id.clone());
        self.persist_supervisor_journal(&journal)?;
        self.runtime.boundary("supervisor-prepared")?;
        let guard = self.runtime.create_guard(&transaction_id, None)?;
        self.active_guard = Some(guard.clone());
        self.runtime.boundary("guard-created")?;
        if operation != SupervisorOperationV1::CleanupUnadopted {
            let guarded_config = self
                .runtime
                .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
            let guarded_dropin = self
                .runtime
                .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?;
            let guarded_receipt = self
                .runtime
                .read_file(SECURITY_RECEIPT_PATH, MAX_RECEIPT_BYTES)?;
            if guarded_config.as_ref().map(ObservedFile::sha256)
                != prior_config_file.as_ref().map(ObservedFile::sha256)
                || guarded_dropin.as_ref().map(ObservedFile::sha256)
                    != prior_dropin_file.as_ref().map(ObservedFile::sha256)
                || guarded_receipt.as_ref().map(ObservedFile::sha256)
                    != prior_receipt_file.as_ref().map(ObservedFile::sha256)
            {
                return Err(SecurityError::Uncertain(
                    "transaction files changed between durable intent and guard".into(),
                ));
            }
        }
        self.advance_supervisor_guarded(
            &mut journal,
            service,
            socket,
            prior_daemon_invocation_id,
            effective,
            guard,
        )?;
        if operation == SupervisorOperationV1::CleanupUnadopted {
            return Ok(journal);
        }
        self.stop_units_under_one_deadline()?;
        self.advance_supervisor(&mut journal, SupervisorPhaseV1::UnitsStopped)?;
        self.prepare_security_directories(&mut journal)?;
        Ok(journal)
    }

    fn persist_supervisor_journal(&mut self, journal: &SupervisorJournalV1) -> SecurityResult<()> {
        let bytes = journal
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let observation = self
            .runtime
            .persist_journal(self.journal_observation.as_ref(), &bytes)?;
        self.journal_observation = Some(observation);
        Ok(())
    }

    fn ensure_guard(
        &mut self,
        transaction_id: &str,
        expected: Option<&TransactionGuardIdentityV1>,
    ) -> SecurityResult<TransactionGuardIdentityV1> {
        let guard = self.runtime.create_guard(transaction_id, expected)?;
        self.active_guard = Some(guard.clone());
        Ok(guard)
    }

    fn remove_active_guard(&mut self) -> SecurityResult<()> {
        let transaction_id = self
            .armed_transaction
            .as_deref()
            .ok_or_else(|| SecurityError::Uncertain("guard transaction identity missing".into()))?;
        let guard = self
            .active_guard
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("guard file identity missing".into()))?;
        self.runtime.remove_guard(transaction_id, guard)
    }

    fn remove_current_journal(&mut self) -> SecurityResult<()> {
        let transaction_id = self.armed_transaction.as_deref().ok_or_else(|| {
            SecurityError::Uncertain("journal transaction identity missing".into())
        })?;
        let observation = self
            .journal_observation
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("latest journal identity missing".into()))?;
        self.runtime.remove_journal(transaction_id, observation)?;
        self.journal_observation = None;
        Ok(())
    }

    fn latest_journal_identity(&self) -> SecurityResult<AtomicFileIdentityV1> {
        self.journal_observation
            .as_ref()
            .map(ObservedFile::atomic_identity)
            .ok_or_else(|| SecurityError::Uncertain("prior journal identity missing".into()))
    }

    fn bind_next_generation(
        &self,
        generation: &mut u64,
        prior_journal_identity: &mut Option<AtomicFileIdentityV1>,
    ) -> SecurityResult<()> {
        *prior_journal_identity = Some(self.latest_journal_identity()?);
        bump_generation(generation)
    }

    fn advance_supervisor(
        &mut self,
        journal: &mut SupervisorJournalV1,
        phase: SupervisorPhaseV1,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = phase;
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("supervisor-phase-synced")
    }

    fn advance_supervisor_guarded(
        &mut self,
        journal: &mut SupervisorJournalV1,
        service: StableUnitState,
        socket: StableUnitState,
        prior_daemon_invocation_id: Option<String>,
        effective: EffectiveUnitSetV1,
        guard: TransactionGuardIdentityV1,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = SupervisorPhaseV1::Guarded;
        journal.guard = Some(guard);
        journal.service_unit_state = Some(service);
        journal.socket_unit_state = Some(socket);
        journal.prior_daemon_invocation_id = prior_daemon_invocation_id;
        journal.prior_effective_units = Some(effective);
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("supervisor-guarded-snapshot")
    }

    fn persist_directory_intent(
        &mut self,
        journal: &mut SupervisorJournalV1,
        intent: SecurityDirectoryRecordV1,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.security_directories.push(intent);
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("directory-intent-synced")
    }

    fn persist_directory_observation(
        &mut self,
        journal: &mut SupervisorJournalV1,
        observed: DirectoryIdentityV1,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal
            .security_directories
            .last_mut()
            .ok_or_else(|| SecurityError::operation("directory intent missing"))?
            .observed_directory = Some(observed);
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("directory-observation-synced")
    }

    fn prepare_security_directories(
        &mut self,
        journal: &mut SupervisorJournalV1,
    ) -> SecurityResult<()> {
        if journal.phase != SupervisorPhaseV1::UnitsStopped {
            return Err(SecurityError::operation(
                "directory preparation requires stopped units",
            ));
        }
        if let Some(intent) = journal.security_directories.last()
            && intent.observed_directory.is_none()
        {
            let observed = self.runtime.ensure_security_directory(intent)?;
            self.runtime
                .boundary("directory-created-before-observation")?;
            self.persist_directory_observation(journal, observed)?;
        }
        while journal.security_directories.len() < REQUIRED_SECURITY_DIRECTORIES.len() {
            let index = journal.security_directories.len();
            let (path, permissions) = REQUIRED_SECURITY_DIRECTORIES[index];
            let intent = self.runtime.plan_security_directory(path, permissions)?;
            self.persist_directory_intent(journal, intent)?;
            let observed = self.runtime.ensure_security_directory(
                journal
                    .security_directories
                    .last()
                    .expect("directory intent was just appended"),
            )?;
            self.runtime
                .boundary("directory-created-before-observation")?;
            self.persist_directory_observation(journal, observed)?;
        }
        let current = journal.clone();
        journal.phase = SupervisorPhaseV1::DirectoriesReady;
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("supervisor-directories-ready")
    }

    fn provision_mode1(&mut self, request: ProvisionRequest) -> SecurityResult<SecurityOutcome> {
        let supervisor =
            self.begin_supervised_transaction(SupervisorOperationV1::ProvisionMode1, None)?;
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
        let service_state = supervisor
            .service_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor service snapshot missing"))?;
        let socket_state = supervisor
            .socket_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor socket snapshot missing"))?;
        let (post_provision_service_target, post_provision_socket_target) =
            disabled_post_provision_unit_targets(&service_state, &socket_state)
                .map_err(|error| SecurityError::operation(error.to_string()))?;

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
                    supervisor,
                ),
                ReceiptState::Enabled => self.verify_enabled_idempotent(
                    config,
                    receipt,
                    artifact,
                    &existing_receipt_file
                        .as_ref()
                        .expect("matched receipt has an observed file")
                        .0,
                    service_state,
                    socket_state,
                    supervisor,
                ),
            };
        }

        let config_state = existing_mode
            .map_or(ExistingProvisioningConfig::Absent, |(mode, epoch)| {
                ExistingProvisioningConfig::Explicit { mode, epoch }
            });
        let artifact_state = match &existing_artifact {
            None => ExistingProvisioningArtifact::Absent,
            Some(artifact) => {
                artifact.validate_regular(0, 0, 0o600)?;
                if inspect_systemd_credential_envelope(&artifact.bytes).is_ok() {
                    if existing_receipt.is_some_and(|receipt| {
                        receipt.artifact.path == MODE1_CREDENTIAL_PATH
                            && receipt.artifact.sha256 == artifact.sha256()
                            && receipt.artifact.size == artifact.metadata.byte_length
                            && receipt.artifact.uid == artifact.metadata.uid
                            && receipt.artifact.gid == artifact.metadata.gid
                            && receipt.artifact.mode == artifact.metadata.permissions
                            && receipt.artifact.nlink == artifact.metadata.link_count
                    }) {
                        ExistingProvisioningArtifact::Verified
                    } else {
                        ExistingProvisioningArtifact::Unverified
                    }
                } else {
                    ExistingProvisioningArtifact::Mismatch
                }
            }
        };
        let provisioning_state = classify_provisioning_state(ProvisioningStateInput {
            config: config_state,
            artifact: artifact_state,
            namespace_nonempty,
            new_key_requested: existing_artifact.is_none(),
            adopt_existing: request.adopt_existing,
        });
        match provisioning_state {
            ProvisioningState::Fresh | ProvisioningState::Adopt => {}
            ProvisioningState::DifferentMode(DifferentModeArtifactState::Absent)
                if !namespace_nonempty => {}
            ProvisioningState::DifferentMode(DifferentModeArtifactState::Absent) => {
                return Err(SecurityError::Refused(
                    "a different configured mode has a nonempty Mode 1 namespace; refusing a new key"
                        .into(),
                ));
            }
            ProvisioningState::DifferentMode(DifferentModeArtifactState::Receipted)
            | ProvisioningState::DifferentMode(DifferentModeArtifactState::Unadopted)
                if request.adopt_existing => {}
            ProvisioningState::DifferentMode(DifferentModeArtifactState::Receipted)
            | ProvisioningState::DifferentMode(DifferentModeArtifactState::Unadopted) => {
                return Err(SecurityError::Refused(
                    "a different configured mode has a preexisting Mode 1 artifact; --adopt-existing and strong readiness are required"
                        .into(),
                ));
            }
            ProvisioningState::DifferentMode(DifferentModeArtifactState::Mismatch) => {
                return Err(SecurityError::Refused(
                    "a different configured mode has an invalid Mode 1 artifact".into(),
                ));
            }
            ProvisioningState::Unadopted => {
                return Err(SecurityError::Refused(
                    "existing credential artifact is unadopted; rerun with --adopt-existing after verification"
                        .into(),
                ));
            }
            ProvisioningState::Missing
            | ProvisioningState::NewKey
            | ProvisioningState::Nonempty => {
                return Err(SecurityError::Refused(
                    "Mode 1 namespace/config requires the existing verified epoch-1 artifact; refusing a new key"
                        .into(),
                ));
            }
            ProvisioningState::Mismatch => {
                return Err(SecurityError::Refused(
                    "existing Mode 1 configuration or artifact does not match v1 policy".into(),
                ));
            }
            ProvisioningState::Idempotent => unreachable!("unreceipted input is not pre-verified"),
        }

        let transaction_id = supervisor.transaction_id.clone();
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
                let selection = self.runtime.resolve_key_selection(request.with_key)?;
                if selection.may_use_host_secret()
                    && !self.runtime.host_secret_preexisting_secure()?
                {
                    return Err(SecurityError::Refused(
                        "host-backed systemd credentials require an exact pre-existing secure /var/lib/systemd/credential.secret in v1"
                            .into(),
                    ));
                }
                let key = self.runtime.generate_key()?;
                if key.expose().len() != 32 {
                    return Err(SecurityError::operation("RNG returned a non-32-byte key"));
                }
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
        let planned_effective = planned_effective_units(
            supervisor
                .prior_effective_units
                .as_ref()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            Sha256Digest::from_bytes(MODE1_DROPIN_BYTES),
            MODE1_DROPIN_BYTES.len() as u64,
            true,
        )
        .map_err(|error| SecurityError::operation(error.to_string()))?;
        let disabled_receipt = build_disabled_receipt(
            &transaction_id,
            &artifact_bytes,
            &artifact_metadata,
            policy,
            config_patch.contract.clone(),
            base_unit.sha256(),
            planned_effective,
            expected_verifier,
        )?;
        let enabled_receipt = enabled_receipt_from(&disabled_receipt)?;
        let disabled_receipt_bytes = disabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let enabled_receipt_bytes = enabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let mut owned_paths = vec![
            howy_common::paths::CONFIG_FILE.to_owned(),
            MODE1_CREDENTIAL_PATH.to_owned(),
            MODE1_DROPIN_PATH.to_owned(),
            SECURITY_RECEIPT_PATH.to_owned(),
            SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
            supervisor.journal_staging_path.clone(),
        ];
        owned_paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            generation: supervisor
                .generation
                .checked_add(1)
                .ok_or_else(|| SecurityError::operation("journal generation overflow"))?,
            prior_journal_identity: Some(self.latest_journal_identity()?),
            journal_staging_path: supervisor.journal_staging_path.clone(),
            guard: supervisor.guard.clone(),
            phase: JournalPhase::UnitsStopped,
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
            atomic_writes: Vec::new(),
            security_directories: supervisor.security_directories.clone(),
            artifact_preexisted: !generated,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config: supervisor.prior_config.clone(),
            prior_dropin: supervisor.prior_dropin.clone(),
            prior_receipt: supervisor.prior_receipt.clone(),
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            post_provision_service_target,
            post_provision_socket_target,
            prior_daemon_invocation_id: supervisor.prior_daemon_invocation_id.clone(),
            prior_effective_units: supervisor
                .prior_effective_units
                .clone()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            effective_units: None,
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
            supervisor_failed: false,
        };
        self.persist_mode1_journal(&journal)?;
        self.runtime.boundary("mode1-planned")?;

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
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_disabled_idempotent(
        &mut self,
        config: &ObservedFile,
        receipt: &ProvisioningReceiptV1,
        artifact: &ObservedFile,
        receipt_file: &ObservedFile,
        service_state: StableUnitState,
        socket_state: StableUnitState,
        supervisor: SupervisorJournalV1,
    ) -> SecurityResult<SecurityOutcome> {
        config.validate_regular(0, 0, 0o600)?;
        artifact.validate_regular(0, 0, 0o600)?;
        receipt_file.validate_regular(0, 0, 0o600)?;
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
        let transaction_id = supervisor.transaction_id.clone();
        let (post_provision_service_target, post_provision_socket_target) =
            disabled_post_provision_unit_targets(&service_state, &socket_state)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
        let mut paths = vec![
            howy_common::paths::CONFIG_FILE.into(),
            MODE1_CREDENTIAL_PATH.into(),
            MODE1_DROPIN_PATH.into(),
            SECURITY_RECEIPT_PATH.into(),
            SECURITY_TRANSACTION_GUARD_PATH.into(),
            supervisor.journal_staging_path.clone(),
        ];
        paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            generation: supervisor
                .generation
                .checked_add(1)
                .ok_or_else(|| SecurityError::operation("journal generation overflow"))?,
            prior_journal_identity: Some(self.latest_journal_identity()?),
            journal_staging_path: supervisor.journal_staging_path.clone(),
            guard: supervisor.guard.clone(),
            phase: JournalPhase::UnitsStopped,
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
            atomic_writes: Vec::new(),
            security_directories: supervisor.security_directories.clone(),
            artifact_preexisted: true,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config: supervisor.prior_config.clone(),
            prior_dropin: supervisor.prior_dropin.clone(),
            prior_receipt: supervisor.prior_receipt.clone(),
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            post_provision_service_target,
            post_provision_socket_target,
            prior_daemon_invocation_id: supervisor.prior_daemon_invocation_id.clone(),
            prior_effective_units: supervisor
                .prior_effective_units
                .clone()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            effective_units: None,
            backup_hashes: BackupHashes {
                artifact_sha256: Some(artifact.sha256()),
                config_sha256: Some(config.sha256()),
                dropin_sha256: Some(dropin.sha256()),
                receipt_sha256: Some(receipt_file.sha256()),
            },
            recovery_action: RecoveryAction::RestorePriorState,
            supervisor_failed: false,
        };
        self.persist_mode1_journal(&journal)?;
        let execution = (|| {
            self.advance_mode1(&mut journal, JournalPhase::ArtifactCommitted)?;
            self.runtime.daemon_reload()?;
            self.advance_mode1(&mut journal, JournalPhase::DropinCommitted)?;
            self.require_effective_mode1(&receipt.effective_units)?;
            self.advance_mode1(&mut journal, JournalPhase::DisabledConfigCommitted)?;
            let output = self.run_stable_strong_readiness(
                &transaction_id,
                howy_common::paths::CONFIG_FILE,
                MODE1_CREDENTIAL_PATH,
                &config.bytes,
            )?;
            if output != receipt.verifier.output {
                return Err(SecurityError::operation(
                    "idempotent strong readiness result changed",
                ));
            }
            self.advance_mode1(&mut journal, JournalPhase::ReadinessVerified)?;
            self.advance_mode1(&mut journal, JournalPhase::DisabledReceiptCommitted)?;
            self.complete_disabled_transaction(&mut journal)
        })();
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec![
                    "Mode 1 disabled state was idempotently reverified.".into(),
                    "Run `sudo howy security enable` after review.".into(),
                ],
                cleanup_command: None,
            }),
            Err(error) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_enabled_idempotent(
        &mut self,
        config: &ObservedFile,
        receipt: &ProvisioningReceiptV1,
        artifact: &ObservedFile,
        receipt_file: &ObservedFile,
        service_state: StableUnitState,
        socket_state: StableUnitState,
        mut supervisor: SupervisorJournalV1,
    ) -> SecurityResult<SecurityOutcome> {
        config.validate_regular(0, 0, 0o600)?;
        artifact.validate_regular(0, 0, 0o600)?;
        let inspected = inspect_systemd_credential_envelope(&artifact.bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if artifact.sha256() != receipt.artifact.sha256
            || inspected.envelope_sha256 != receipt.artifact.credential_policy.envelope_sha256
            || config.sha256() != receipt.config_patch.enabled_sha256
        {
            return Err(SecurityError::Refused(
                "enabled receipt correlation is stale".into(),
            ));
        }
        self.runtime.daemon_reload()?;
        self.require_effective_mode1(&receipt.effective_units)?;
        let readiness = self.run_stable_strong_readiness(
            &supervisor.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
            &config.bytes,
        )?;
        if readiness != receipt.verifier.output
            || self.runtime.preview_verifier(&config.bytes)? != readiness
        {
            return Err(SecurityError::operation(
                "enabled idempotent strong readiness changed",
            ));
        }
        self.require_effective_mode1(&receipt.effective_units)?;
        self.revalidate_receipted_live(receipt, &config.bytes, &receipt_file.sha256(), &readiness)?;
        self.advance_supervisor(&mut supervisor, SupervisorPhaseV1::MutationCommitted)?;
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, &socket_state)?;
        restore_unit_target(self.runtime, &service_state)?;
        self.verify_restored_targets(&service_state, &socket_state)?;
        let status = self
            .runtime
            .security_info()?
            .ok_or_else(|| SecurityError::operation("enabled daemon root status unavailable"))?;
        validate_enabled_status(
            &status,
            receipt,
            supervisor.prior_daemon_invocation_id.as_deref(),
            &receipt.config_patch.enabled_sha256,
        )?;
        self.require_public_status(&status)?;
        self.revalidate_receipted_live(receipt, &config.bytes, &receipt_file.sha256(), &readiness)?;
        self.advance_supervisor(&mut supervisor, SupervisorPhaseV1::UnitsRestored)?;
        let final_status = self
            .runtime
            .security_info()?
            .ok_or_else(|| SecurityError::operation("enabled daemon root status disappeared"))?;
        validate_enabled_status(
            &final_status,
            receipt,
            supervisor.prior_daemon_invocation_id.as_deref(),
            &receipt.config_patch.enabled_sha256,
        )?;
        self.require_public_status(&final_status)?;
        if final_status.daemon_invocation_id != status.daemon_invocation_id {
            return Err(SecurityError::operation(
                "enabled daemon invocation changed before journal deletion",
            ));
        }
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(SecurityOutcome {
            messages: vec!["Mode 1 enabled state was strongly reverified.".into()],
            cleanup_command: None,
        })
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
        let artifact_write = if generated {
            Some(self.execute_mode1_atomic(
                journal,
                MODE1_CREDENTIAL_PATH,
                artifact,
                0,
                0,
                0o600,
                None,
                true,
            )?)
        } else {
            None
        };
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
        if let Some(index) = artifact_write {
            self.cleanup_mode1_atomic(journal, index)?;
        }

        let dropin_write = self.execute_mode1_atomic(
            journal,
            MODE1_DROPIN_PATH,
            MODE1_DROPIN_BYTES,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.runtime.daemon_reload()?;
        self.runtime.boundary("dropin-installed")?;
        self.advance_mode1(journal, JournalPhase::DropinCommitted)?;
        self.cleanup_mode1_atomic(journal, dropin_write)?;
        if journal.effective_units.as_ref() != Some(&disabled_receipt.effective_units) {
            return Err(SecurityError::operation(
                "effective unit policy differs from the planned receipt",
            ));
        }

        let config_write = self.execute_mode1_atomic(
            journal,
            howy_common::paths::CONFIG_FILE,
            disabled_config,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.runtime.boundary("disabled-config-installed")?;
        self.advance_mode1(journal, JournalPhase::DisabledConfigCommitted)?;
        self.cleanup_mode1_atomic(journal, config_write)?;

        self.require_effective_mode1(&disabled_receipt.effective_units)?;
        let output = self.run_stable_strong_readiness(
            &journal.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
            disabled_config,
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
        self.require_effective_mode1(&disabled_receipt.effective_units)?;
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
        let live_config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("candidate config disappeared"))?;
        live_config.validate_regular(0, 0, 0o600)?;
        if live_config.bytes != disabled_config
            || live_config.sha256() != disabled_receipt.config_patch.disabled_sha256
            || self.runtime.preview_verifier(&live_config.bytes)? != output
            || disabled_receipt
                .deterministic_sha256()
                .map_err(|error| SecurityError::operation(error.to_string()))?
                != journal.planned_hashes.disabled_receipt_sha256
        {
            return Err(SecurityError::operation(
                "post-readiness candidate correlation changed",
            ));
        }
        self.runtime.boundary("readiness-verified")?;
        self.advance_mode1(journal, JournalPhase::ReadinessVerified)?;

        let receipt_write = self.execute_mode1_atomic(
            journal,
            SECURITY_RECEIPT_PATH,
            disabled_receipt_bytes,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.runtime.boundary("disabled-receipt-installed")?;
        self.advance_mode1(journal, JournalPhase::DisabledReceiptCommitted)?;
        self.cleanup_mode1_atomic(journal, receipt_write)?;
        self.complete_disabled_transaction(journal)
    }

    fn enable_mode1(&mut self) -> SecurityResult<SecurityOutcome> {
        let supervisor =
            self.begin_supervised_transaction(SupervisorOperationV1::EnableMode1, None)?;
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
        self.runtime.daemon_reload()?;
        self.require_effective_mode1(&receipt.effective_units)?;
        let service_state = supervisor
            .service_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor service snapshot missing"))?;
        let socket_state = supervisor
            .socket_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor socket snapshot missing"))?;
        let enabled_receipt = enabled_receipt_from(&receipt)?;
        let disabled_receipt_bytes = receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let enabled_receipt_bytes = enabled_receipt
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let transaction_id = supervisor.transaction_id.clone();
        let (post_provision_service_target, post_provision_socket_target) =
            disabled_post_provision_unit_targets(&service_state, &socket_state)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
        let mut paths = vec![
            howy_common::paths::CONFIG_FILE.into(),
            MODE1_CREDENTIAL_PATH.into(),
            MODE1_DROPIN_PATH.into(),
            SECURITY_RECEIPT_PATH.into(),
            SECURITY_TRANSACTION_GUARD_PATH.into(),
            supervisor.journal_staging_path.clone(),
        ];
        paths.sort();
        let mut journal = ProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            generation: supervisor
                .generation
                .checked_add(1)
                .ok_or_else(|| SecurityError::operation("journal generation overflow"))?,
            prior_journal_identity: Some(self.latest_journal_identity()?),
            journal_staging_path: supervisor.journal_staging_path.clone(),
            guard: supervisor.guard.clone(),
            phase: JournalPhase::DisabledUnitsStarted,
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
            live_hashes: LiveObjectHashes {
                artifact_sha256: Some(artifact.sha256()),
                dropin_sha256: Some(dropin.sha256()),
                config_sha256: Some(receipt.config_patch.disabled_sha256.clone()),
                disabled_receipt_sha256: Some(Sha256Digest::from_bytes(&disabled_receipt_bytes)),
                enabled_receipt_sha256: None,
            },
            transaction_owned_paths: paths,
            atomic_writes: Vec::new(),
            security_directories: supervisor.security_directories.clone(),
            artifact_preexisted: true,
            transient_unit: readiness_unit_name(&transaction_id),
            prior_config: supervisor.prior_config.clone(),
            prior_dropin: supervisor.prior_dropin.clone(),
            prior_receipt: supervisor.prior_receipt.clone(),
            service_unit_state: service_state,
            socket_unit_state: socket_state,
            post_provision_service_target,
            post_provision_socket_target,
            prior_daemon_invocation_id: supervisor.prior_daemon_invocation_id.clone(),
            prior_effective_units: supervisor
                .prior_effective_units
                .clone()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            effective_units: Some(receipt.effective_units.clone()),
            backup_hashes: BackupHashes {
                artifact_sha256: Some(artifact.sha256()),
                config_sha256: Some(config.sha256()),
                dropin_sha256: Some(dropin.sha256()),
                receipt_sha256: Some(receipt_file.sha256()),
            },
            recovery_action: RecoveryAction::CompleteDisabledProvisioning,
            supervisor_failed: false,
        };
        self.persist_mode1_journal(&journal)?;
        self.runtime.boundary("phase-prepared")?;
        let prior_invocation = journal.prior_daemon_invocation_id.clone();
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
            Err(error) => Err(error),
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
        self.require_effective_mode1(&disabled_receipt.effective_units)?;
        let disabled_config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("disabled config disappeared"))?;
        let readiness = self.run_stable_strong_readiness(
            &journal.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
            &disabled_config.bytes,
        )?;
        if readiness != disabled_receipt.verifier.output {
            return Err(SecurityError::operation("enable readiness result changed"));
        }
        self.revalidate_enable_candidate(disabled_receipt, &disabled_config.bytes, &readiness)?;
        let config_write = self.execute_mode1_atomic(
            journal,
            howy_common::paths::CONFIG_FILE,
            enabled_config,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.runtime.boundary("enabled-config-installed")?;
        self.advance_mode1(journal, JournalPhase::EnabledConfigCommitted)?;
        self.cleanup_mode1_atomic(journal, config_write)?;
        self.revalidate_enabled_objects(disabled_receipt, enabled_config)?;
        self.advance_mode1(journal, JournalPhase::ActivationCommitted)?;
        self.remove_active_guard()?;
        self.runtime.daemon_reload()?;
        self.start_controlled()?;
        self.require_effective_mode1(&enabled_receipt.effective_units)?;
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
        self.require_public_status(&status)?;
        self.advance_mode1(journal, JournalPhase::UnitsStarted)?;
        let receipt_write = self.execute_mode1_atomic(
            journal,
            SECURITY_RECEIPT_PATH,
            enabled_receipt_bytes,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.runtime.boundary("enabled-receipt-installed")?;
        self.advance_mode1(journal, JournalPhase::EnabledReceiptCommitted)?;
        self.cleanup_mode1_atomic(journal, receipt_write)?;
        self.revalidate_receipted_live(
            enabled_receipt,
            enabled_config,
            &journal.planned_hashes.enabled_receipt_sha256,
            &enabled_receipt.verifier.output,
        )?;
        let final_status = self
            .runtime
            .security_info()?
            .ok_or_else(|| SecurityError::operation("enabled daemon status disappeared"))?;
        validate_enabled_status(
            &final_status,
            enabled_receipt,
            None,
            &journal.planned_hashes.enabled_config_sha256,
        )?;
        self.require_public_status(&final_status)?;
        if final_status.daemon_invocation_id != status.daemon_invocation_id {
            return Err(SecurityError::operation(
                "enabled daemon restarted before transaction commit",
            ));
        }
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn provision_plaintext(&mut self) -> SecurityResult<SecurityOutcome> {
        let supervisor =
            self.begin_supervised_transaction(SupervisorOperationV1::ProvisionMode0, None)?;
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
        if let Some(config) = &config {
            config.validate_regular(0, 0, 0o600)?;
        }
        let enabled_config = build_enabled_mode0_config(config.as_ref())?;
        let prompt_required = config_prompt_required(&enabled_config)?;
        let transaction_id = supervisor.transaction_id.clone();
        let service = supervisor
            .service_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor service snapshot missing"))?;
        let socket = supervisor
            .socket_unit_state
            .clone()
            .ok_or_else(|| SecurityError::operation("supervisor socket snapshot missing"))?;
        let planned_effective = planned_effective_units(
            supervisor
                .prior_effective_units
                .as_ref()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            Sha256Digest::from_bytes(MODE0_DROPIN_BYTES),
            MODE0_DROPIN_BYTES.len() as u64,
            false,
        )
        .map_err(|error| SecurityError::operation(error.to_string()))?;
        let mut journal = PlaintextProvisioningJournalV1 {
            schema_version: PROVISIONING_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            generation: supervisor
                .generation
                .checked_add(1)
                .ok_or_else(|| SecurityError::operation("journal generation overflow"))?,
            prior_journal_identity: Some(self.latest_journal_identity()?),
            journal_staging_path: supervisor.journal_staging_path.clone(),
            guard: supervisor.guard.clone(),
            phase: PlaintextJournalPhase::UnitsStopped,
            enabled_config_sha256: Sha256Digest::from_bytes(&enabled_config),
            live_config_sha256: None,
            transaction_owned_paths: {
                let mut paths = sorted_paths([
                    howy_common::paths::CONFIG_FILE,
                    MODE1_DROPIN_PATH,
                    SECURITY_TRANSACTION_GUARD_PATH,
                ]);
                paths.push(supervisor.journal_staging_path.clone());
                paths.sort();
                paths
            },
            atomic_writes: Vec::new(),
            security_directories: supervisor.security_directories.clone(),
            prior_config: supervisor.prior_config.clone(),
            prior_dropin: supervisor.prior_dropin.clone(),
            service_unit_state: service,
            socket_unit_state: socket,
            prior_daemon_invocation_id: supervisor.prior_daemon_invocation_id.clone(),
            prior_effective_units: supervisor
                .prior_effective_units
                .clone()
                .ok_or_else(|| SecurityError::operation("prior effective units missing"))?,
            effective_units: None,
            dropin_sha256: Sha256Digest::from_bytes(MODE0_DROPIN_BYTES),
            recovery_action: PlaintextRecoveryAction::RestorePriorState,
            supervisor_failed: false,
        };
        self.persist_plaintext_journal(&journal)?;
        let execution = (|| {
            let dropin_write = self.execute_plaintext_atomic(
                &mut journal,
                MODE1_DROPIN_PATH,
                MODE0_DROPIN_BYTES,
                0,
                0,
                0o600,
                None,
            )?;
            self.runtime.daemon_reload()?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::DropinRemoved)?;
            self.cleanup_plaintext_atomic(&mut journal, dropin_write)?;
            if journal.effective_units.as_ref() != Some(&planned_effective) {
                return Err(SecurityError::operation(
                    "effective Mode 0 unit policy differs from plan",
                ));
            }
            let config_write = self.execute_plaintext_atomic(
                &mut journal,
                howy_common::paths::CONFIG_FILE,
                &enabled_config,
                0,
                0,
                0o600,
                None,
            )?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::EnabledConfigCommitted)?;
            self.cleanup_plaintext_atomic(&mut journal, config_write)?;
            self.revalidate_mode0_objects(&journal.enabled_config_sha256, &planned_effective)?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::ActivationCommitted)?;
            let expected_daemon = self.runtime.daemon_verifier_identity()?;
            self.remove_active_guard()?;
            self.start_controlled()?;
            let status = self.runtime.security_info()?.ok_or_else(|| {
                SecurityError::operation("daemon root security status unavailable")
            })?;
            validate_mode0_status(
                &status,
                &journal.enabled_config_sha256,
                journal.prior_daemon_invocation_id.as_deref(),
                &expected_daemon,
                prompt_required,
            )?;
            self.require_public_status(&status)?;
            self.require_effective_mode0(&planned_effective)?;
            self.revalidate_mode0_live(
                &journal.enabled_config_sha256,
                &planned_effective,
                &expected_daemon,
                prompt_required,
                &status.daemon_invocation_id,
            )?;
            self.advance_plaintext(&mut journal, PlaintextJournalPhase::UnitsStarted)?;
            self.revalidate_mode0_live(
                &journal.enabled_config_sha256,
                &planned_effective,
                &expected_daemon,
                prompt_required,
                &status.daemon_invocation_id,
            )?;
            self.remove_current_journal()?;
            self.armed_transaction = None;
            self.active_guard = None;
            Ok(())
        })();
        match execution {
            Ok(()) => Ok(SecurityOutcome {
                messages: vec![
                    "WARNING: explicit plaintext Mode 0 is enabled; encrypted artifacts and namespaces were preserved."
                        .into(),
                ],
                cleanup_command: None,
            }),
            Err(error) => Err(error),
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
        let pre_admission = self.observe_cleanup_pre_admission(&manifest.identity)?;
        let mut supervisor = self.begin_supervised_transaction(
            SupervisorOperationV1::CleanupUnadopted,
            Some((
                manifest.identity.clone(),
                CleanupManifestIdentityV1 {
                    path: manifest_path.clone(),
                    file: manifest_file.atomic_identity(),
                },
                pre_admission.clone(),
            )),
        )?;
        self.recheck_cleanup_pre_admission(&pre_admission, &supervisor)?;
        self.runtime.boundary("cleanup-admitted")?;
        self.stop_units_under_one_deadline()?;
        self.advance_supervisor(&mut supervisor, SupervisorPhaseV1::UnitsStopped)?;
        self.prepare_security_directories(&mut supervisor)?;
        let quarantine_path = supervisor
            .cleanup_quarantine
            .as_ref()
            .ok_or_else(|| SecurityError::operation("cleanup quarantine plan missing"))?
            .path
            .clone();
        self.runtime
            .quarantine_artifact_exact(&manifest.identity.descriptor, &quarantine_path)?;
        self.advance_cleanup_quarantine(&mut supervisor, CleanupQuarantineStateV1::Renamed)?;
        self.runtime.boundary("artifact-quarantined")?;

        if let Err(conflict) =
            self.admit_quarantined_cleanup(&manifest.identity, &quarantine_path, &supervisor)
        {
            self.restore_cleanup_quarantine(&mut supervisor, &manifest.identity)?;
            return Err(conflict);
        }
        self.runtime.boundary("cleanup-final-recheck")?;
        if let Err(conflict) =
            self.admit_quarantined_cleanup(&manifest.identity, &quarantine_path, &supervisor)
        {
            self.restore_cleanup_quarantine(&mut supervisor, &manifest.identity)?;
            return Err(conflict);
        }
        self.runtime
            .unlink_quarantined_artifact_exact(&manifest.identity.descriptor, &quarantine_path)?;
        self.advance_cleanup_quarantine(&mut supervisor, CleanupQuarantineStateV1::Removed)?;
        self.runtime.boundary("quarantine-unlinked")?;
        self.advance_supervisor(&mut supervisor, SupervisorPhaseV1::MutationCommitted)?;
        self.remove_cleanup_manifest(&supervisor)?;
        self.remove_active_guard()?;
        let service = supervisor
            .service_unit_state
            .as_ref()
            .ok_or_else(|| SecurityError::operation("cleanup service target missing"))?;
        let socket = supervisor
            .socket_unit_state
            .as_ref()
            .ok_or_else(|| SecurityError::operation("cleanup socket target missing"))?;
        restore_unit_target(self.runtime, socket)?;
        restore_unit_target(self.runtime, service)?;
        self.verify_restored_targets(service, socket)?;
        self.advance_supervisor(&mut supervisor, SupervisorPhaseV1::UnitsRestored)?;
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(SecurityOutcome {
            messages: vec![
                "Unadopted artifact quarantined and removed after reference-safe revalidation."
                    .into(),
            ],
            cleanup_command: None,
        })
    }

    fn observe_cleanup_pre_admission(
        &mut self,
        identity: &CleanupArtifactIdentityV1,
    ) -> SecurityResult<CleanupPreAdmissionV1> {
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
            &identity.transaction_id,
            &observed_file,
            inspected.actual_key_id,
            inspected.envelope_sha256,
            inspected.envelope_size,
        );
        let (mut references, effective_units) = self.cleanup_external_references(identity)?;
        references.journal = self
            .runtime
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)?
            .is_some();
        references.active_transaction = self
            .runtime
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?
            .is_some();
        let service = self.runtime.unit_observation(UnitKind::Service)?;
        let socket = self.runtime.unit_observation(UnitKind::Socket)?;
        let transient = self
            .runtime
            .transient_exists(&readiness_unit_name(&identity.transaction_id))?;
        let daemon_responded = self.daemon_responded_for_cleanup()?;
        let pre_admission = CleanupPreAdmissionV1 {
            observed_artifact: observed_identity,
            references,
            service,
            socket,
            readiness_transient_exists: transient,
            daemon_responded,
            effective_units,
        };
        let admissibility = classify_cleanup_admissibility(CleanupStateInput {
            expected_artifact: howy_common::provisioning::ExpectedCleanupArtifactIdentityV1(
                identity.clone(),
            ),
            observed_artifact: ObservedCleanupArtifactIdentityV1(
                pre_admission.observed_artifact.clone(),
            ),
            references: pre_admission.references,
            service: pre_admission.service,
            socket: pre_admission.socket,
            readiness_transient_exists: pre_admission.readiness_transient_exists,
            daemon_responded: pre_admission.daemon_responded,
        });
        if let CleanupAdmissibility::Refuse(reason) = admissibility {
            return Err(SecurityError::Refused(format!(
                "unadopted cleanup refused: {reason:?}"
            )));
        }
        Ok(pre_admission)
    }

    fn recheck_cleanup_pre_admission(
        &mut self,
        initial: &CleanupPreAdmissionV1,
        journal: &SupervisorJournalV1,
    ) -> SecurityResult<()> {
        let identity = journal
            .cleanup_artifact
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("cleanup identity missing".into()))?;
        let observed_file = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Uncertain("unadopted artifact disappeared".into()))?;
        let inspected = inspect_systemd_credential_envelope(&observed_file.bytes)
            .map_err(|error| SecurityError::Uncertain(error.to_string()))?;
        let observed_artifact = cleanup_identity(
            &identity.transaction_id,
            &observed_file,
            inspected.actual_key_id,
            inspected.envelope_sha256,
            inspected.envelope_size,
        );
        let (references, effective_units) = self.cleanup_references(identity, journal)?;
        let current = CleanupPreAdmissionV1 {
            observed_artifact,
            references,
            service: self.runtime.unit_observation(UnitKind::Service)?,
            socket: self.runtime.unit_observation(UnitKind::Socket)?,
            readiness_transient_exists: self
                .runtime
                .transient_exists(&readiness_unit_name(&identity.transaction_id))?,
            daemon_responded: self.daemon_responded_for_cleanup()?,
            effective_units,
        };
        let admissibility = classify_cleanup_admissibility(CleanupStateInput {
            expected_artifact: howy_common::provisioning::ExpectedCleanupArtifactIdentityV1(
                identity.clone(),
            ),
            observed_artifact: ObservedCleanupArtifactIdentityV1(current.observed_artifact.clone()),
            references: current.references,
            service: current.service,
            socket: current.socket,
            readiness_transient_exists: current.readiness_transient_exists,
            daemon_responded: current.daemon_responded,
        });
        if current != *initial || admissibility != CleanupAdmissibility::Admissible {
            return Err(SecurityError::Uncertain(
                "cleanup pre-admission predicates changed after guard creation".into(),
            ));
        }
        Ok(())
    }

    fn admit_quarantined_cleanup(
        &mut self,
        identity: &CleanupArtifactIdentityV1,
        quarantine_path: &str,
        journal: &SupervisorJournalV1,
    ) -> SecurityResult<()> {
        if self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .is_some()
        {
            return Err(SecurityError::Refused(
                "cleanup refused because the original artifact path was repopulated".into(),
            ));
        }
        let quarantined = self
            .runtime
            .read_file(
                quarantine_path,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Uncertain("cleanup quarantine disappeared".into()))?;
        let inspected = inspect_systemd_credential_envelope(&quarantined.bytes)
            .map_err(|error| SecurityError::Uncertain(error.to_string()))?;
        let observed_identity = cleanup_identity(
            &identity.transaction_id,
            &quarantined,
            inspected.actual_key_id,
            inspected.envelope_sha256,
            inspected.envelope_size,
        );
        let (references, _) = self.cleanup_references(identity, journal)?;
        let service = self.runtime.unit_observation(UnitKind::Service)?;
        let socket = self.runtime.unit_observation(UnitKind::Socket)?;
        let transient = self
            .runtime
            .transient_exists(&readiness_unit_name(&identity.transaction_id))?;
        let daemon_responded = self.daemon_responded_for_cleanup()?;
        let admissibility = classify_cleanup_admissibility(CleanupStateInput {
            expected_artifact: howy_common::provisioning::ExpectedCleanupArtifactIdentityV1(
                identity.clone(),
            ),
            observed_artifact: ObservedCleanupArtifactIdentityV1(observed_identity),
            references,
            service,
            socket,
            readiness_transient_exists: transient,
            daemon_responded,
        });
        if let CleanupAdmissibility::Refuse(reason) = admissibility {
            return Err(SecurityError::Refused(format!(
                "quarantined cleanup refused: {reason:?}"
            )));
        }
        Ok(())
    }

    fn advance_cleanup_quarantine(
        &mut self,
        journal: &mut SupervisorJournalV1,
        state: CleanupQuarantineStateV1,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal
            .cleanup_quarantine
            .as_mut()
            .ok_or_else(|| SecurityError::operation("cleanup quarantine journal missing"))?
            .state = state;
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_supervisor_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_supervisor_journal(journal)?;
        self.runtime.boundary("cleanup-quarantine-state-synced")
    }

    fn restore_cleanup_quarantine(
        &mut self,
        journal: &mut SupervisorJournalV1,
        identity: &CleanupArtifactIdentityV1,
    ) -> SecurityResult<()> {
        let quarantine_path = journal
            .cleanup_quarantine
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("cleanup quarantine journal missing".into()))?
            .path
            .clone();
        let controls_were_intact = self.cleanup_controls_match(journal).is_ok();
        self.runtime.boundary("cleanup-restore-requested")?;
        self.runtime
            .restore_quarantined_artifact_exact(&identity.descriptor, &quarantine_path)?;
        self.runtime.boundary("cleanup-quarantine-restored")?;
        if !controls_were_intact || self.cleanup_controls_match(journal).is_err() {
            return Err(SecurityError::Uncertain(
                "cleanup artifact was restored but transaction controls changed; guard and journal retained"
                    .into(),
            ));
        }
        self.advance_cleanup_quarantine(journal, CleanupQuarantineStateV1::Restored)?;
        let service = journal
            .service_unit_state
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("cleanup service target missing".into()))?;
        let socket = journal
            .socket_unit_state
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("cleanup socket target missing".into()))?;
        self.runtime
            .rollback_security_directories(&journal.security_directories)?;
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, &socket)?;
        restore_unit_target(self.runtime, &service)?;
        self.verify_restored_targets(&service, &socket)?;
        self.advance_supervisor(journal, SupervisorPhaseV1::UnitsRestored)?;
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn cleanup_external_references(
        &mut self,
        identity: &CleanupArtifactIdentityV1,
    ) -> SecurityResult<(CleanupReferences, EffectiveUnitSetV1)> {
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?;
        let config_reference = match config {
            None => false,
            Some(file) => {
                file.validate_regular(0, 0, 0o600)?;
                let source = std::str::from_utf8(&file.bytes).map_err(|_| {
                    SecurityError::operation("malformed config is a cleanup reference")
                })?;
                let config: HowyConfig = toml::from_str(source).map_err(|_| {
                    SecurityError::operation("malformed config is a cleanup reference")
                })?;
                config.validate().map_err(SecurityError::operation)?;
                config.security.embedding_mode == EmbeddingSecurityMode::AeadCached
                    && config.security.cached.credential_name == identity.source.credential_name
            }
        };
        let receipt_reference = match self
            .runtime
            .read_file(SECURITY_RECEIPT_PATH, MAX_RECEIPT_BYTES)?
        {
            None => false,
            Some(file) => {
                file.validate_regular(0, 0, 0o600)?;
                let receipt = ProvisioningReceiptV1::parse(&file.bytes).map_err(|_| {
                    SecurityError::operation("malformed receipt is a cleanup reference")
                })?;
                receipt.artifact.path == MODE1_CREDENTIAL_PATH
            }
        };
        let dropin_reference = match self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
        {
            None => false,
            Some(file) => {
                file.validate_regular(0, 0, 0o600)?;
                if file.bytes == MODE0_DROPIN_BYTES {
                    false
                } else if file.bytes == MODE1_DROPIN_BYTES {
                    true
                } else {
                    return Err(SecurityError::operation(
                        "unknown or malformed drop-in is a cleanup reference",
                    ));
                }
            }
        };
        let effective_units = self.observe_effective_units()?;
        let effective_unit_reference = effective_units
            .service
            .load_credential_encrypted
            .iter()
            .any(|credential| credential.source == identity.descriptor.path)
            || effective_units
                .service
                .set_credential
                .iter()
                .any(|credential| {
                    credential.name == MODE1_CREDENTIAL_SOURCE_COMPANION_NAME
                        && credential.value == identity.descriptor.path
                });
        Ok((
            CleanupReferences {
                config: config_reference,
                receipt: receipt_reference,
                dropin: dropin_reference,
                journal: false,
                active_transaction: false,
                effective_unit: effective_unit_reference,
            },
            effective_units,
        ))
    }

    fn cleanup_references(
        &mut self,
        identity: &CleanupArtifactIdentityV1,
        journal: &SupervisorJournalV1,
    ) -> SecurityResult<(CleanupReferences, EffectiveUnitSetV1)> {
        let (mut references, effective_units) = self.cleanup_external_references(identity)?;
        let journal_reference = match self
            .runtime
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)?
        {
            Some(file) => {
                file.validate_regular(0, 0, 0o600)?;
                self.journal_observation.as_ref() != Some(&file)
                    || SupervisorJournalV1::parse(&file.bytes).ok().as_ref() != Some(journal)
            }
            None => true,
        };
        let active_transaction = match self
            .runtime
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?
        {
            Some(file) => {
                file.validate_regular(0, 0, 0o600)?;
                let expected = journal.guard.as_ref();
                expected.is_none_or(|expected| {
                    file.atomic_identity() != expected.file
                        || file.bytes != expected.content.deterministic_bytes().unwrap_or_default()
                })
            }
            None => true,
        };
        references.journal = journal_reference;
        references.active_transaction = active_transaction;
        Ok((references, effective_units))
    }

    fn daemon_responded_for_cleanup(&mut self) -> SecurityResult<bool> {
        let Some(status) = self.runtime.security_info()? else {
            return Ok(false);
        };
        status.validate_strict().map_err(|_| {
            SecurityError::operation("malformed daemon status is a cleanup reference")
        })?;
        Ok(true)
    }

    fn cleanup_controls_match(&mut self, journal: &SupervisorJournalV1) -> SecurityResult<()> {
        let live_journal = self
            .runtime
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)?
            .ok_or_else(|| SecurityError::Uncertain("cleanup journal disappeared".into()))?;
        live_journal.validate_regular(0, 0, 0o600)?;
        if self.journal_observation.as_ref() != Some(&live_journal)
            || SupervisorJournalV1::parse(&live_journal.bytes)
                .ok()
                .as_ref()
                != Some(journal)
        {
            return Err(SecurityError::Uncertain(
                "cleanup journal changed concurrently".into(),
            ));
        }
        let guard = self
            .runtime
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?
            .ok_or_else(|| SecurityError::Uncertain("cleanup guard disappeared".into()))?;
        guard.validate_regular(0, 0, 0o600)?;
        let expected_guard = journal
            .guard
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("cleanup guard identity missing".into()))?;
        if guard.atomic_identity() != expected_guard.file
            || guard.bytes
                != expected_guard
                    .content
                    .deterministic_bytes()
                    .map_err(|error| SecurityError::Uncertain(error.to_string()))?
        {
            return Err(SecurityError::Uncertain(
                "cleanup guard changed concurrently".into(),
            ));
        }
        Ok(())
    }

    fn recover_locked(&mut self) -> SecurityResult<Option<String>> {
        self.armed_transaction = Some("manual-recovery".to_owned());
        let Some(file) = self.runtime.load_journal()? else {
            self.journal_observation = None;
            let guard = self
                .runtime
                .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)?;
            if let Some(guard) = guard {
                guard.validate_regular(0, 0, 0o600)?;
                if let Ok(guard) =
                    howy_common::provisioning::TransactionGuardV1::parse(&guard.bytes)
                {
                    self.armed_transaction = Some(guard.transaction_id);
                }
                return Err(SecurityError::Uncertain(
                    "transaction guard exists without a recoverable journal".into(),
                ));
            }
            self.armed_transaction = None;
            self.active_guard = None;
            return Ok(None);
        };
        self.journal_observation = Some(file.clone());
        file.validate_regular(0, 0, 0o600)?;
        if let Ok(journal) = ProvisioningJournalV1::parse(&file.bytes) {
            self.armed_transaction = Some(journal.transaction_id.clone());
            return self.recover_mode1(journal);
        }
        if let Ok(journal) = PlaintextProvisioningJournalV1::parse(&file.bytes) {
            self.armed_transaction = Some(journal.transaction_id.clone());
            return self.recover_plaintext(journal);
        }
        if let Ok(journal) = SupervisorJournalV1::parse(&file.bytes) {
            self.armed_transaction = Some(journal.transaction_id.clone());
            return self.recover_supervisor(journal);
        }
        Err(SecurityError::Uncertain(
            "transaction journal is malformed; guard and units must remain closed".into(),
        ))
    }

    fn recover_supervisor(
        &mut self,
        mut journal: SupervisorJournalV1,
    ) -> SecurityResult<Option<String>> {
        let guard = self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
        if journal.phase == SupervisorPhaseV1::Prepared {
            let service = journal.service_unit_state.clone().ok_or_else(|| {
                SecurityError::Uncertain("prepared service snapshot missing".into())
            })?;
            let socket = journal.socket_unit_state.clone().ok_or_else(|| {
                SecurityError::Uncertain("prepared socket snapshot missing".into())
            })?;
            let effective = journal.prior_effective_units.clone().ok_or_else(|| {
                SecurityError::Uncertain("prepared effective-unit snapshot missing".into())
            })?;
            let prior_daemon_invocation_id = journal.prior_daemon_invocation_id.clone();
            self.advance_supervisor_guarded(
                &mut journal,
                service,
                socket,
                prior_daemon_invocation_id,
                effective,
                guard,
            )?;
        } else if journal.guard.as_ref() != Some(&guard) {
            let current = journal.clone();
            journal.guard = Some(guard);
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_supervisor_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            self.persist_supervisor_journal(&journal)?;
        }
        self.stop_units_under_one_deadline()?;
        if journal.phase == SupervisorPhaseV1::Guarded {
            self.advance_supervisor(&mut journal, SupervisorPhaseV1::UnitsStopped)?;
        }
        if journal.phase == SupervisorPhaseV1::UnitsStopped {
            self.prepare_security_directories(&mut journal)?;
        }
        self.runtime
            .verify_security_directories(&journal.security_directories)?;
        if journal.operation == SupervisorOperationV1::CleanupUnadopted {
            return self.recover_cleanup_supervisor(journal);
        }
        let service = journal
            .service_unit_state
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("service target missing".into()))?;
        let socket = journal
            .socket_unit_state
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("socket target missing".into()))?;
        self.runtime
            .rollback_security_directories(&journal.security_directories)?;
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, socket)?;
        restore_unit_target(self.runtime, service)?;
        self.verify_restored_targets(service, socket)?;
        if journal.phase != SupervisorPhaseV1::UnitsRestored {
            self.advance_supervisor(&mut journal, SupervisorPhaseV1::UnitsRestored)?;
        }
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(None)
    }

    fn recover_cleanup_supervisor(
        &mut self,
        mut journal: SupervisorJournalV1,
    ) -> SecurityResult<Option<String>> {
        let identity = journal
            .cleanup_artifact
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("cleanup identity missing".into()))?;
        let quarantine = journal
            .cleanup_quarantine
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("cleanup quarantine missing".into()))?;
        let original = self.runtime.read_file(
            MODE1_CREDENTIAL_PATH,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )?;
        let quarantined = self.runtime.read_file(
            &quarantine.path,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )?;
        let original_matches = original
            .as_ref()
            .is_some_and(|file| cleanup_file_matches(&identity, file));
        let quarantine_matches = quarantined
            .as_ref()
            .is_some_and(|file| cleanup_file_matches(&identity, file));

        match quarantine.state {
            CleanupQuarantineStateV1::Planned if original_matches && quarantined.is_none() => {
                return self.finish_supervisor_units(&mut journal).map(|()| None);
            }
            CleanupQuarantineStateV1::Planned if original.is_none() && quarantine_matches => {
                self.advance_cleanup_quarantine(&mut journal, CleanupQuarantineStateV1::Renamed)?;
            }
            CleanupQuarantineStateV1::Renamed if original.is_none() && quarantine_matches => {}
            CleanupQuarantineStateV1::Renamed if original.is_none() && quarantined.is_none() => {
                self.runtime
                    .unlink_quarantined_artifact_exact(&identity.descriptor, &quarantine.path)?;
                self.advance_cleanup_quarantine(&mut journal, CleanupQuarantineStateV1::Removed)?;
                self.remove_cleanup_manifest(&journal)?;
                return self.finish_supervisor_units(&mut journal).map(|()| None);
            }
            CleanupQuarantineStateV1::Renamed if original_matches && quarantined.is_none() => {
                self.runtime
                    .restore_quarantined_artifact_exact(&identity.descriptor, &quarantine.path)?;
                self.advance_cleanup_quarantine(&mut journal, CleanupQuarantineStateV1::Restored)?;
                return self.finish_supervisor_units(&mut journal).map(|()| None);
            }
            CleanupQuarantineStateV1::Removed if original.is_none() && quarantined.is_none() => {
                self.remove_cleanup_manifest(&journal)?;
                return self.finish_supervisor_units(&mut journal).map(|()| None);
            }
            CleanupQuarantineStateV1::Restored if original_matches && quarantined.is_none() => {
                return self.finish_supervisor_units(&mut journal).map(|()| None);
            }
            _ => {
                return Err(SecurityError::Uncertain(
                    "cleanup recovery found artifact paths outside the journaled quarantine state"
                        .into(),
                ));
            }
        }

        if self
            .admit_quarantined_cleanup(&identity, &quarantine.path, &journal)
            .is_err()
        {
            self.restore_cleanup_quarantine(&mut journal, &identity)?;
            return Ok(None);
        }
        self.runtime
            .unlink_quarantined_artifact_exact(&identity.descriptor, &quarantine.path)?;
        self.advance_cleanup_quarantine(&mut journal, CleanupQuarantineStateV1::Removed)?;
        if journal.phase != SupervisorPhaseV1::MutationCommitted {
            self.advance_supervisor(&mut journal, SupervisorPhaseV1::MutationCommitted)?;
        }
        self.remove_cleanup_manifest(&journal)?;
        self.finish_supervisor_units(&mut journal)?;
        Ok(None)
    }

    fn remove_cleanup_manifest(&mut self, journal: &SupervisorJournalV1) -> SecurityResult<()> {
        let identity = journal
            .cleanup_artifact
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("cleanup artifact identity missing".into()))?;
        let expected = journal
            .cleanup_manifest
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("cleanup manifest identity missing".into()))?;
        let Some(manifest) = self.runtime.read_file(&expected.path, MAX_RECEIPT_BYTES)? else {
            if journal
                .cleanup_quarantine
                .as_ref()
                .is_some_and(|quarantine| quarantine.state == CleanupQuarantineStateV1::Removed)
            {
                return Ok(());
            }
            return Err(SecurityError::Uncertain(
                "cleanup manifest disappeared before authorized removal".into(),
            ));
        };
        manifest.validate_regular(0, 0, 0o600)?;
        let canonical = UnadoptedArtifactV1::new(identity.clone())
            .and_then(|manifest| manifest.deterministic_bytes())
            .map_err(|error| SecurityError::Uncertain(error.to_string()))?;
        if manifest.bytes != canonical || manifest.atomic_identity() != expected.file {
            return Err(SecurityError::Uncertain(
                "cleanup manifest was replaced or is not canonical; guard retained".into(),
            ));
        }
        self.runtime
            .remove_file_exact(&expected.path, &expected.file)?;
        Ok(())
    }

    fn finish_supervisor_units(&mut self, journal: &mut SupervisorJournalV1) -> SecurityResult<()> {
        let service = journal
            .service_unit_state
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("service target missing".into()))?;
        let socket = journal
            .socket_unit_state
            .clone()
            .ok_or_else(|| SecurityError::Uncertain("socket target missing".into()))?;
        self.runtime
            .rollback_security_directories(&journal.security_directories)?;
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, &socket)?;
        restore_unit_target(self.runtime, &service)?;
        self.verify_restored_targets(&service, &socket)?;
        if journal.phase != SupervisorPhaseV1::UnitsRestored {
            self.advance_supervisor(journal, SupervisorPhaseV1::UnitsRestored)?;
        }
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn recover_mode1(
        &mut self,
        mut journal: ProvisioningJournalV1,
    ) -> SecurityResult<Option<String>> {
        let guard = self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
        if journal.guard.as_ref() != Some(&guard) {
            let current = journal.clone();
            journal.guard = Some(guard);
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            self.persist_mode1_journal(&journal)?;
        }
        self.stop_readiness_transient(&journal.transient_unit)?;
        self.stop_units_under_one_deadline()?;
        self.runtime
            .verify_security_directories(&journal.security_directories)?;
        self.reconcile_mode1_atomic_records(&mut journal)?;
        match journal.recovery_action {
            RecoveryAction::RestorePriorState => {
                self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_under_one_deadline()?;
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
                            let transaction_id = journal.transaction_id.clone();
                            self.write_unadopted_manifest(
                                &mut journal,
                                &transaction_id,
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
                self.restore_mode1_prior(&mut journal)?;
                self.finish_rollback_units(
                    &journal.service_unit_state,
                    &journal.socket_unit_state,
                    &journal.security_directories,
                )?;
                Ok(cleanup)
            }
            RecoveryAction::CompleteDisabledProvisioning => {
                self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_under_one_deadline()?;
                let config = self
                    .runtime
                    .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| SecurityError::Uncertain("committed config missing".into()))?;
                if config.sha256() == journal.planned_hashes.enabled_config_sha256 {
                    let disabled = journal.prior_config.clone().ok_or_else(|| {
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
                    self.restore_mode1_snapshot(
                        &mut journal,
                        howy_common::paths::CONFIG_FILE,
                        Some(&disabled),
                        MAX_CONFIG_BYTES,
                    )?;
                }
                self.validate_disabled_live(&journal)?;
                let receipt = self.read_receipt()?.ok_or_else(|| {
                    SecurityError::Uncertain("disabled receipt disappeared".into())
                })?;
                self.require_effective_mode1(&receipt.effective_units)?;
                let config = self
                    .runtime
                    .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| SecurityError::Uncertain("disabled config missing".into()))?;
                let readiness = self.run_stable_strong_readiness(
                    &journal.transaction_id,
                    howy_common::paths::CONFIG_FILE,
                    MODE1_CREDENTIAL_PATH,
                    &config.bytes,
                )?;
                if readiness != receipt.verifier.output {
                    return Err(SecurityError::Uncertain(
                        "disabled recovery readiness changed".into(),
                    ));
                }
                self.complete_disabled_transaction(&mut journal)?;
                Ok(None)
            }
            RecoveryAction::RestoreDisabledState => {
                self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_under_one_deadline()?;
                let receipt = self.read_receipt()?.ok_or_else(|| {
                    SecurityError::Uncertain("disabled receipt disappeared".into())
                })?;
                let disabled = journal
                    .prior_config
                    .clone()
                    .ok_or_else(|| SecurityError::Uncertain("disabled backup missing".into()))?;
                self.restore_mode1_snapshot(
                    &mut journal,
                    howy_common::paths::CONFIG_FILE,
                    Some(&disabled),
                    MAX_CONFIG_BYTES,
                )?;
                let disabled_bytes = disabled
                    .bytes
                    .decode()
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                if Sha256Digest::from_bytes(&disabled_bytes) != receipt.config_patch.disabled_sha256
                {
                    return Err(SecurityError::Uncertain(
                        "disabled backup does not match receipt".into(),
                    ));
                }
                self.validate_disabled_live(&journal)?;
                let readiness = self.run_stable_strong_readiness(
                    &journal.transaction_id,
                    howy_common::paths::CONFIG_FILE,
                    MODE1_CREDENTIAL_PATH,
                    &disabled_bytes,
                )?;
                if readiness != receipt.verifier.output {
                    return Err(SecurityError::Uncertain(
                        "restored disabled readiness changed".into(),
                    ));
                }
                self.revalidate_enable_candidate(&receipt, &disabled_bytes, &readiness)?;
                self.finish_disabled_units(
                    &journal,
                    &journal.post_provision_service_target,
                    &journal.post_provision_socket_target,
                )?;
                Ok(None)
            }
            RecoveryAction::CompleteEnabledActivation => {
                self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
                self.stop_readiness_transient(&journal.transient_unit)?;
                self.stop_units_under_one_deadline()?;
                let _live_receipt = self
                    .read_receipt()?
                    .ok_or_else(|| SecurityError::Uncertain("activation receipt missing".into()))?;
                let receipt = ProvisioningReceiptV1::parse(
                    &journal
                        .prior_receipt
                        .as_ref()
                        .ok_or_else(|| {
                            SecurityError::Uncertain("disabled receipt backup missing".into())
                        })?
                        .bytes
                        .decode()
                        .map_err(|error| SecurityError::operation(error.to_string()))?,
                )
                .map_err(|error| SecurityError::Uncertain(error.to_string()))?;
                if receipt.state != ReceiptState::ProvisionedDisabled {
                    return Err(SecurityError::Uncertain(
                        "activation recovery disabled receipt backup is not disabled".into(),
                    ));
                }
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
                self.require_effective_mode1(&receipt.effective_units)?;
                let disabled_bytes = journal
                    .prior_config
                    .as_ref()
                    .ok_or_else(|| SecurityError::Uncertain("disabled backup missing".into()))?
                    .bytes
                    .decode()
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                let prior_config = journal.prior_config.clone();
                self.restore_mode1_snapshot(
                    &mut journal,
                    howy_common::paths::CONFIG_FILE,
                    prior_config.as_ref(),
                    MAX_CONFIG_BYTES,
                )?;
                let readiness = self.run_stable_strong_readiness(
                    &journal.transaction_id,
                    howy_common::paths::CONFIG_FILE,
                    MODE1_CREDENTIAL_PATH,
                    &disabled_bytes,
                )?;
                if readiness != receipt.verifier.output {
                    return Err(SecurityError::Uncertain(
                        "activation recovery readiness changed".into(),
                    ));
                }
                self.revalidate_enable_candidate(&receipt, &disabled_bytes, &readiness)?;
                let enabled_config_write = self.execute_mode1_atomic(
                    &mut journal,
                    howy_common::paths::CONFIG_FILE,
                    &enabled,
                    0,
                    0,
                    0o600,
                    None,
                    false,
                )?;
                self.cleanup_mode1_atomic(&mut journal, enabled_config_write)?;
                self.revalidate_enabled_objects(&receipt, &enabled)?;
                self.remove_active_guard()?;
                self.runtime.daemon_reload()?;
                self.start_controlled()?;
                let enabled_receipt = enabled_receipt_from(&receipt)?;
                let started_status = self.runtime.security_info()?.ok_or_else(|| {
                    SecurityError::Uncertain("enabled daemon status missing".into())
                })?;
                validate_enabled_status(
                    &started_status,
                    &enabled_receipt,
                    journal.prior_daemon_invocation_id.as_deref(),
                    &journal.planned_hashes.enabled_config_sha256,
                )?;
                self.require_public_status(&started_status)?;
                self.require_effective_mode1(&enabled_receipt.effective_units)?;
                let enabled_receipt_bytes = enabled_receipt
                    .deterministic_bytes()
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                let enabled_receipt_write = self.execute_mode1_atomic(
                    &mut journal,
                    SECURITY_RECEIPT_PATH,
                    &enabled_receipt_bytes,
                    0,
                    0,
                    0o600,
                    None,
                    false,
                )?;
                self.cleanup_mode1_atomic(&mut journal, enabled_receipt_write)?;
                self.revalidate_enabled_objects(&receipt, &enabled)?;
                self.revalidate_receipted_live(
                    &enabled_receipt,
                    &enabled,
                    &journal.planned_hashes.enabled_receipt_sha256,
                    &enabled_receipt.verifier.output,
                )?;
                self.require_effective_mode1(&enabled_receipt.effective_units)?;
                let final_status = self.runtime.security_info()?.ok_or_else(|| {
                    SecurityError::Uncertain("enabled daemon status disappeared".into())
                })?;
                validate_enabled_status(
                    &final_status,
                    &enabled_receipt,
                    journal.prior_daemon_invocation_id.as_deref(),
                    &journal.planned_hashes.enabled_config_sha256,
                )?;
                self.require_public_status(&final_status)?;
                if final_status.daemon_invocation_id != started_status.daemon_invocation_id {
                    return Err(SecurityError::Uncertain(
                        "enabled daemon restarted during activation recovery".into(),
                    ));
                }
                self.remove_current_journal()?;
                self.armed_transaction = None;
                self.active_guard = None;
                Ok(None)
            }
        }
    }

    fn recover_plaintext(
        &mut self,
        mut journal: PlaintextProvisioningJournalV1,
    ) -> SecurityResult<Option<String>> {
        let guard = self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
        if journal.guard.as_ref() != Some(&guard) {
            let current = journal.clone();
            journal.guard = Some(guard);
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_plaintext_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            self.persist_plaintext_journal(&journal)?;
        }
        self.stop_units_under_one_deadline()?;
        self.runtime
            .verify_security_directories(&journal.security_directories)?;
        self.reconcile_plaintext_atomic_records(&mut journal)?;
        match journal.recovery_action {
            PlaintextRecoveryAction::RestorePriorState => {
                self.rollback_plaintext(&mut journal)?;
                Ok(None)
            }
            PlaintextRecoveryAction::CompleteActivation => {
                self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
                self.stop_units_under_one_deadline()?;
                let config = self
                    .runtime
                    .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
                    .ok_or_else(|| SecurityError::Uncertain("Mode 0 config missing".into()))?;
                if config.sha256() != journal.enabled_config_sha256 {
                    return Err(SecurityError::Uncertain(
                        "Mode 0 config changed during recovery".into(),
                    ));
                }
                let prompt_required = config_prompt_required(&config.bytes)?;
                let effective = journal.effective_units.as_ref().ok_or_else(|| {
                    SecurityError::Uncertain("Mode 0 effective units missing".into())
                })?;
                self.require_effective_mode0(effective)?;
                let expected_daemon = self.runtime.daemon_verifier_identity()?;
                self.revalidate_mode0_objects(&journal.enabled_config_sha256, effective)?;
                self.remove_active_guard()?;
                self.runtime.daemon_reload()?;
                self.start_controlled()?;
                let status = self.runtime.security_info()?.ok_or_else(|| {
                    SecurityError::Uncertain("Mode 0 daemon status missing".into())
                })?;
                validate_mode0_status(
                    &status,
                    &journal.enabled_config_sha256,
                    journal.prior_daemon_invocation_id.as_deref(),
                    &expected_daemon,
                    prompt_required,
                )?;
                self.require_public_status(&status)?;
                self.require_effective_mode0(effective)?;
                self.revalidate_mode0_live(
                    &journal.enabled_config_sha256,
                    effective,
                    &expected_daemon,
                    prompt_required,
                    &status.daemon_invocation_id,
                )?;
                self.remove_current_journal()?;
                self.armed_transaction = None;
                self.active_guard = None;
                Ok(None)
            }
        }
    }

    fn restore_mode1_prior(&mut self, journal: &mut ProvisioningJournalV1) -> SecurityResult<()> {
        let prior_config = journal.prior_config.clone();
        let prior_dropin = journal.prior_dropin.clone();
        let prior_receipt = journal.prior_receipt.clone();
        self.restore_mode1_snapshot(
            journal,
            howy_common::paths::CONFIG_FILE,
            prior_config.as_ref(),
            MAX_CONFIG_BYTES,
        )?;
        self.restore_mode1_snapshot(
            journal,
            MODE1_DROPIN_PATH,
            prior_dropin.as_ref(),
            MAX_DROPIN_BYTES,
        )?;
        self.restore_mode1_snapshot(
            journal,
            SECURITY_RECEIPT_PATH,
            prior_receipt.as_ref(),
            MAX_RECEIPT_BYTES,
        )?;
        self.runtime.daemon_reload()?;
        if self.observe_effective_units()? != journal.prior_effective_units {
            return Err(SecurityError::Uncertain(
                "restored effective units differ from journal".into(),
            ));
        }
        Ok(())
    }

    fn rollback_plaintext(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
    ) -> SecurityResult<()> {
        self.ensure_guard(&journal.transaction_id, journal.guard.as_ref())?;
        self.stop_units_under_one_deadline()?;
        let prior_config = journal.prior_config.clone();
        let prior_dropin = journal.prior_dropin.clone();
        self.restore_plaintext_snapshot(
            journal,
            howy_common::paths::CONFIG_FILE,
            prior_config.as_ref(),
            MAX_CONFIG_BYTES,
        )?;
        self.restore_plaintext_snapshot(
            journal,
            MODE1_DROPIN_PATH,
            prior_dropin.as_ref(),
            MAX_DROPIN_BYTES,
        )?;
        self.runtime.daemon_reload()?;
        if self.observe_effective_units()? != journal.prior_effective_units {
            return Err(SecurityError::Uncertain(
                "restored Mode 0 prior effective units differ from journal".into(),
            ));
        }
        self.finish_rollback_units(
            &journal.service_unit_state,
            &journal.socket_unit_state,
            &journal.security_directories,
        )
    }

    fn finish_rollback_units(
        &mut self,
        service: &StableUnitState,
        socket: &StableUnitState,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        self.runtime.rollback_security_directories(directories)?;
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, socket)?;
        restore_unit_target(self.runtime, service)?;
        self.verify_restored_targets(service, socket)?;
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn finish_disabled_units(
        &mut self,
        journal: &ProvisioningJournalV1,
        service_target: &StableUnitState,
        socket_target: &StableUnitState,
    ) -> SecurityResult<()> {
        self.remove_active_guard()?;
        restore_unit_target(self.runtime, socket_target)?;
        self.verify_restored_targets(service_target, socket_target)?;
        self.final_disabled_revalidation(journal)?;
        self.verify_restored_targets(service_target, socket_target)?;
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn complete_disabled_transaction(
        &mut self,
        journal: &mut ProvisioningJournalV1,
    ) -> SecurityResult<()> {
        self.validate_disabled_live(journal)?;
        let effective = journal
            .effective_units
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("disabled effective units missing".into()))?;
        self.require_effective_mode1(effective)?;
        let service_target = journal.post_provision_service_target.clone();
        let socket_target = journal.post_provision_socket_target.clone();
        self.remove_active_guard()?;
        // Socket activation policy is preserved, but a successful disabled
        // daemon invocation exits and therefore has an inactive/dead service.
        restore_unit_target(self.runtime, &socket_target)?;
        self.verify_restored_targets(&service_target, &socket_target)?;
        if journal.phase != JournalPhase::DisabledUnitsStarted {
            self.advance_mode1(journal, JournalPhase::DisabledUnitsStarted)?;
        }
        self.final_disabled_revalidation(journal)?;
        self.verify_restored_targets(&service_target, &socket_target)?;
        self.remove_current_journal()?;
        self.armed_transaction = None;
        self.active_guard = None;
        Ok(())
    }

    fn final_disabled_revalidation(
        &mut self,
        journal: &ProvisioningJournalV1,
    ) -> SecurityResult<()> {
        self.runtime
            .verify_security_directories(&journal.security_directories)?;
        self.validate_disabled_live(journal)?;
        let (receipt_file, receipt) = self
            .read_receipt_file()?
            .ok_or_else(|| SecurityError::Uncertain("disabled receipt disappeared".into()))?;
        if receipt.state != ReceiptState::ProvisionedDisabled
            || receipt_file.sha256() != journal.planned_hashes.disabled_receipt_sha256
        {
            return Err(SecurityError::Uncertain(
                "disabled receipt identity changed before journal deletion".into(),
            ));
        }
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::Uncertain("disabled config disappeared".into()))?;
        config.validate_regular(0, 0, 0o600)?;
        if config.sha256() != journal.planned_hashes.disabled_config_sha256 {
            return Err(SecurityError::Uncertain(
                "disabled config identity changed before journal deletion".into(),
            ));
        }
        let readiness = self.run_stable_strong_readiness(
            &journal.transaction_id,
            howy_common::paths::CONFIG_FILE,
            MODE1_CREDENTIAL_PATH,
            &config.bytes,
        )?;
        if readiness != receipt.verifier.output {
            return Err(SecurityError::Uncertain(
                "disabled namespace/readiness changed before journal deletion".into(),
            ));
        }
        self.revalidate_receipted_live(
            &receipt,
            &config.bytes,
            &journal.planned_hashes.disabled_receipt_sha256,
            &readiness,
        )?;
        if self.runtime.security_info()?.is_some() {
            return Err(SecurityError::Uncertain(
                "disabled daemon unexpectedly returned root status".into(),
            ));
        }
        self.require_disabled_public_status()
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
            file.validate_regular(0, 0, 0o600)?;
            if file.sha256() != *expected {
                return Err(SecurityError::Uncertain(format!(
                    "committed object changed: {path}"
                )));
            }
        }
        let artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::Uncertain("committed artifact missing".into()))?;
        artifact.validate_regular(0, 0, 0o600)?;
        inspect_systemd_credential_envelope(&artifact.bytes)
            .map_err(|error| SecurityError::Uncertain(error.to_string()))?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::Uncertain("committed drop-in missing".into()))?;
        dropin.validate_regular(0, 0, 0o600)?;
        if dropin.bytes != MODE1_DROPIN_BYTES {
            return Err(SecurityError::Uncertain(
                "committed drop-in bytes changed".into(),
            ));
        }
        let effective = journal
            .effective_units
            .as_ref()
            .ok_or_else(|| SecurityError::Uncertain("effective units missing".into()))?;
        self.require_effective_mode1(effective)?;
        Ok(())
    }

    fn write_unadopted_manifest(
        &mut self,
        journal: &mut ProvisioningJournalV1,
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
        let write = self.execute_mode1_atomic(
            journal,
            &unadopted_manifest_path(transaction_id),
            &bytes,
            0,
            0,
            0o600,
            None,
            false,
        )?;
        self.cleanup_mode1_atomic(journal, write)
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

    fn run_stable_strong_readiness(
        &mut self,
        transaction_id: &str,
        config_path: &str,
        artifact_path: &str,
        expected_config: &[u8],
    ) -> SecurityResult<VerifierResultV1> {
        for _ in 0..3 {
            let config = self
                .runtime
                .read_file(config_path, MAX_CONFIG_BYTES)?
                .ok_or_else(|| SecurityError::operation("readiness config disappeared"))?;
            config.validate_regular(0, 0, 0o600)?;
            if config.bytes != expected_config {
                return Err(SecurityError::operation(
                    "readiness config changed before verification",
                ));
            }
            let before = self.runtime.preview_verifier(expected_config)?;
            let output = self.run_strong_readiness(transaction_id, config_path, artifact_path)?;
            let after = self.runtime.preview_verifier(expected_config)?;
            if before == output && output == after {
                return Ok(output);
            }
        }
        Err(SecurityError::operation(
            "namespace or verifier identity did not stabilize across readiness",
        ))
    }

    fn observe_effective_units(&mut self) -> SecurityResult<EffectiveUnitSetV1> {
        Ok(EffectiveUnitSetV1 {
            service: self.runtime.effective_unit_observation(UnitKind::Service)?,
            socket: self.runtime.effective_unit_observation(UnitKind::Socket)?,
        })
    }

    fn capture_prior_daemon_invocation(
        &mut self,
        service: &StableUnitState,
    ) -> SecurityResult<Option<String>> {
        if service.rollback_target() != Some(StableRollbackTarget::ActiveRunning) {
            return Ok(None);
        }
        let status = self.runtime.security_info()?.ok_or_else(|| {
            SecurityError::operation(
                "active prior service requires root status and an invocation id before journaling",
            )
        })?;
        status
            .validate_strict()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        Ok(Some(status.daemon_invocation_id))
    }

    fn require_public_status(&mut self, root: &SecurityInfoResult) -> SecurityResult<()> {
        let public = self
            .runtime
            .daemon_info()?
            .ok_or_else(|| SecurityError::operation("daemon public status unavailable"))?;
        validate_daemon_info_for_activation(
            Some(&public),
            DaemonInfoExpectation {
                active_security_mode: root.active_security_mode,
                prompt_required: root.prompt_required,
                storage_ready: root.storage_ready,
                disabled: false,
            },
        )
        .map_err(|error| SecurityError::operation(error.to_string()))
    }

    fn require_disabled_public_status(&mut self) -> SecurityResult<()> {
        let public = self.runtime.daemon_info()?;
        validate_daemon_info_for_activation(
            public.as_ref(),
            DaemonInfoExpectation {
                active_security_mode: EmbeddingSecurityMode::AeadCached as u32,
                prompt_required: true,
                storage_ready: false,
                disabled: true,
            },
        )
        .map_err(|error| SecurityError::operation(error.to_string()))
    }

    fn require_effective_mode1(&mut self, expected: &EffectiveUnitSetV1) -> SecurityResult<()> {
        expected
            .validate_mode1(&Sha256Digest::from_bytes(MODE1_DROPIN_BYTES))
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let observed = self.observe_effective_units()?;
        observed
            .validate_mode1(&Sha256Digest::from_bytes(MODE1_DROPIN_BYTES))
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if observed != *expected {
            return Err(SecurityError::operation(
                "effective Mode 1 units changed or are shadowed",
            ));
        }
        Ok(())
    }

    fn require_effective_mode0(&mut self, expected: &EffectiveUnitSetV1) -> SecurityResult<()> {
        expected
            .validate_mode0(&Sha256Digest::from_bytes(MODE0_DROPIN_BYTES))
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let observed = self.observe_effective_units()?;
        observed
            .validate_mode0(&Sha256Digest::from_bytes(MODE0_DROPIN_BYTES))
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if observed != *expected {
            return Err(SecurityError::operation(
                "effective Mode 0 units changed or are shadowed",
            ));
        }
        Ok(())
    }

    fn revalidate_mode0_live(
        &mut self,
        expected_config_sha256: &Sha256Digest,
        expected_effective: &EffectiveUnitSetV1,
        expected_daemon: &DaemonVerifierIdentityV1,
        prompt_required: bool,
        expected_invocation_id: &str,
    ) -> SecurityResult<()> {
        self.revalidate_mode0_objects(expected_config_sha256, expected_effective)?;
        let status = self
            .runtime
            .security_info()?
            .ok_or_else(|| SecurityError::operation("Mode 0 daemon status disappeared"))?;
        validate_mode0_status(
            &status,
            expected_config_sha256,
            None,
            expected_daemon,
            prompt_required,
        )?;
        if status.daemon_invocation_id != expected_invocation_id {
            return Err(SecurityError::operation(
                "Mode 0 daemon restarted before transaction commit",
            ));
        }
        self.require_public_status(&status)
    }

    fn revalidate_mode0_objects(
        &mut self,
        expected_config_sha256: &Sha256Digest,
        expected_effective: &EffectiveUnitSetV1,
    ) -> SecurityResult<()> {
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("Mode 0 config disappeared"))?;
        config.validate_regular(0, 0, 0o600)?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| {
                SecurityError::operation("Mode 0 credential-clearing drop-in disappeared")
            })?;
        dropin.validate_regular(0, 0, 0o600)?;
        self.require_effective_mode0(expected_effective)?;
        if config.sha256() != *expected_config_sha256 || dropin.bytes != MODE0_DROPIN_BYTES {
            return Err(SecurityError::operation(
                "Mode 0 config or credential-clearing drop-in changed",
            ));
        }
        Ok(())
    }

    fn revalidate_enable_candidate(
        &mut self,
        receipt: &ProvisioningReceiptV1,
        disabled_config: &[u8],
        readiness: &VerifierResultV1,
    ) -> SecurityResult<()> {
        let artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("artifact disappeared after readiness"))?;
        artifact.validate_regular(0, 0, 0o600)?;
        let inspected = inspect_systemd_credential_envelope(&artifact.bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("config disappeared after readiness"))?;
        config.validate_regular(0, 0, 0o600)?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("drop-in disappeared after readiness"))?;
        dropin.validate_regular(0, 0, 0o600)?;
        self.require_effective_mode1(&receipt.effective_units)?;
        if config.bytes != disabled_config
            || config.sha256() != receipt.config_patch.disabled_sha256
            || artifact.sha256() != receipt.artifact.sha256
            || artifact.metadata.byte_length != receipt.artifact.size
            || inspected.envelope_sha256 != receipt.artifact.credential_policy.envelope_sha256
            || inspected.actual_key_id != receipt.artifact.credential_policy.actual_key_id
            || dropin.bytes != MODE1_DROPIN_BYTES
            || dropin.sha256() != receipt.unit_credential.dropin_sha256
            || self.runtime.preview_verifier(disabled_config)? != *readiness
            || receipt.verifier.output != *readiness
        {
            return Err(SecurityError::operation(
                "post-readiness Mode 1 candidate changed",
            ));
        }
        Ok(())
    }

    fn revalidate_enabled_objects(
        &mut self,
        disabled_receipt: &ProvisioningReceiptV1,
        enabled_config: &[u8],
    ) -> SecurityResult<()> {
        let enabled_receipt = enabled_receipt_from(disabled_receipt)?;
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("enabled config disappeared"))?;
        config.validate_regular(0, 0, 0o600)?;
        self.require_effective_mode1(&enabled_receipt.effective_units)?;
        if config.bytes != enabled_config
            || config.sha256() != enabled_receipt.config_patch.enabled_sha256
            || self.runtime.preview_verifier(enabled_config)? != enabled_receipt.verifier.output
        {
            return Err(SecurityError::operation(
                "enabled objects changed before activation commit",
            ));
        }
        let artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("enabled artifact disappeared"))?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("enabled drop-in disappeared"))?;
        artifact.validate_regular(0, 0, 0o600)?;
        dropin.validate_regular(0, 0, 0o600)?;
        if artifact.sha256() != enabled_receipt.artifact.sha256
            || dropin.bytes != MODE1_DROPIN_BYTES
            || dropin.sha256() != enabled_receipt.unit_credential.dropin_sha256
        {
            return Err(SecurityError::operation(
                "enabled artifact or drop-in changed before activation",
            ));
        }
        Ok(())
    }

    fn revalidate_receipted_live(
        &mut self,
        receipt: &ProvisioningReceiptV1,
        expected_config: &[u8],
        expected_receipt_sha256: &Sha256Digest,
        expected_verifier: &VerifierResultV1,
    ) -> SecurityResult<()> {
        let config = self
            .runtime
            .read_file(howy_common::paths::CONFIG_FILE, MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted config disappeared"))?;
        config.validate_regular(0, 0, 0o600)?;
        let artifact = self
            .runtime
            .read_file(
                MODE1_CREDENTIAL_PATH,
                howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
            )?
            .ok_or_else(|| SecurityError::operation("receipted artifact disappeared"))?;
        artifact.validate_regular(0, 0, 0o600)?;
        let inspected = inspect_systemd_credential_envelope(&artifact.bytes)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let dropin = self
            .runtime
            .read_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted drop-in disappeared"))?;
        dropin.validate_regular(0, 0, 0o600)?;
        let base = self
            .runtime
            .read_file(BASE_SERVICE_UNIT_PATH, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("receipted base unit disappeared"))?;
        base.validate_regular(0, 0, base.metadata.permissions)?;
        let (receipt_file, live_receipt) = self
            .read_receipt_file()?
            .ok_or_else(|| SecurityError::operation("receipted receipt disappeared"))?;
        self.require_effective_mode1(&receipt.effective_units)?;
        let expected_config_sha256 = match receipt.state {
            ReceiptState::ProvisionedDisabled => &receipt.config_patch.disabled_sha256,
            ReceiptState::Enabled => &receipt.config_patch.enabled_sha256,
        };
        if config.bytes != expected_config
            || config.sha256() != *expected_config_sha256
            || artifact.sha256() != receipt.artifact.sha256
            || artifact.metadata.byte_length != receipt.artifact.size
            || inspected.envelope_sha256 != receipt.artifact.credential_policy.envelope_sha256
            || inspected.actual_key_id != receipt.artifact.credential_policy.actual_key_id
            || dropin.bytes != MODE1_DROPIN_BYTES
            || dropin.sha256() != receipt.unit_credential.dropin_sha256
            || base.sha256() != receipt.unit_credential.base_unit_sha256
            || receipt_file.sha256() != *expected_receipt_sha256
            || live_receipt != *receipt
            || self.runtime.preview_verifier(expected_config)? != *expected_verifier
            || receipt.verifier.output != *expected_verifier
        {
            return Err(SecurityError::operation(
                "receipted Mode 1 state changed during strong verification",
            ));
        }
        Ok(())
    }

    fn persist_supervisor_failure_marker(&mut self) -> SecurityResult<()> {
        let Some(file) = self.runtime.load_journal()? else {
            return Err(SecurityError::operation(
                "durable transaction journal disappeared",
            ));
        };
        self.journal_observation = Some(file.clone());
        if let Ok(mut journal) = ProvisioningJournalV1::parse(&file.bytes) {
            if journal.supervisor_failed {
                return Ok(());
            }
            let current = journal.clone();
            journal.supervisor_failed = true;
            if let Some(guard) = &self.active_guard {
                journal.guard = Some(guard.clone());
            }
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_mode1_journal(&journal);
        }
        if let Ok(mut journal) = PlaintextProvisioningJournalV1::parse(&file.bytes) {
            if journal.supervisor_failed {
                return Ok(());
            }
            let current = journal.clone();
            journal.supervisor_failed = true;
            if let Some(guard) = &self.active_guard {
                journal.guard = Some(guard.clone());
            }
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_plaintext_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_plaintext_journal(&journal);
        }
        if let Ok(mut journal) = SupervisorJournalV1::parse(&file.bytes) {
            if journal.supervisor_failed {
                return Ok(());
            }
            let current = journal.clone();
            journal.supervisor_failed = true;
            if let Some(guard) = &self.active_guard {
                journal.guard = Some(guard.clone());
            }
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_supervisor_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_supervisor_journal(&journal);
        }
        Err(SecurityError::Uncertain(
            "malformed journal retained without rewrite".into(),
        ))
    }

    fn persist_guard_identity_transition(
        &mut self,
        guard: &TransactionGuardIdentityV1,
    ) -> SecurityResult<()> {
        let file = self.runtime.load_journal()?.ok_or_else(|| {
            SecurityError::Uncertain("durable transaction journal disappeared".into())
        })?;
        self.journal_observation = Some(file.clone());
        if let Ok(mut journal) = ProvisioningJournalV1::parse(&file.bytes) {
            if journal.guard.as_ref() == Some(guard) {
                return Ok(());
            }
            let current = journal.clone();
            journal.guard = Some(guard.clone());
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_mode1_journal(&journal);
        }
        if let Ok(mut journal) = PlaintextProvisioningJournalV1::parse(&file.bytes) {
            if journal.guard.as_ref() == Some(guard) {
                return Ok(());
            }
            let current = journal.clone();
            journal.guard = Some(guard.clone());
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_plaintext_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_plaintext_journal(&journal);
        }
        if let Ok(mut journal) = SupervisorJournalV1::parse(&file.bytes) {
            if journal.guard.as_ref() == Some(guard) {
                return Ok(());
            }
            let current = journal.clone();
            journal.guard = Some(guard.clone());
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_supervisor_journal_transition(&current, &journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            return self.persist_supervisor_journal(&journal);
        }
        Err(SecurityError::Uncertain(
            "malformed journal retained without guard identity rewrite".into(),
        ))
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
        self.stable_unit_until(unit, deadline)
    }

    fn stable_unit_until(
        &mut self,
        unit: UnitKind,
        deadline: u64,
    ) -> SecurityResult<StableUnitState> {
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

    fn stable_unit_pair(&mut self) -> SecurityResult<(StableUnitState, StableUnitState)> {
        let deadline = self
            .runtime
            .monotonic_millis()
            .checked_add(10_000)
            .ok_or_else(|| SecurityError::operation("unit settle deadline overflow"))?;
        let mut previous = None;
        loop {
            if self.runtime.monotonic_millis() >= deadline {
                return Err(SecurityError::Refused(
                    "required unit pair did not reach a coherent stable state".into(),
                ));
            }
            let service = self.runtime.unit_observation(UnitKind::Service)?;
            let socket = self.runtime.unit_observation(UnitKind::Socket)?;
            let observations = [service, socket];
            let mut states = Vec::with_capacity(2);
            let mut settle = false;
            for observation in observations {
                match classify_unit_admissibility(observation) {
                    UnitAdmissibility::Admissible { .. } => states.push(StableUnitState {
                        unit_kind: observation.unit_kind,
                        load_state: observation.load_state,
                        active_state: observation.active_state,
                        sub_state: observation.sub_state,
                        unit_file_state: observation.unit_file_state,
                    }),
                    UnitAdmissibility::Settle => settle = true,
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
            if settle {
                previous = None;
                self.runtime.settle_step()?;
                continue;
            }
            let pair = (states.remove(0), states.remove(0));
            if previous.as_ref() == Some(&pair) {
                return Ok(pair);
            }
            previous = Some(pair);
            self.runtime.settle_step()?;
        }
    }

    fn stop_units_under_one_deadline(&mut self) -> SecurityResult<()> {
        let deadline = self
            .runtime
            .monotonic_millis()
            .checked_add(10_000)
            .ok_or_else(|| SecurityError::operation("unit settle deadline overflow"))?;
        let mut failures = Vec::new();
        if let Err(error) = self.runtime.stop_unit(UnitKind::Socket) {
            failures.push(format!("socket stop: {error}"));
        }
        if let Err(error) = self.runtime.boundary("socket-stopped") {
            #[cfg(test)]
            if matches!(error, SecurityError::InjectedCrash(_)) {
                return Err(error);
            }
            failures.push(format!("socket boundary: {error}"));
        }
        if let Err(error) = self.runtime.stop_unit(UnitKind::Service) {
            failures.push(format!("service stop: {error}"));
        }
        if let Err(error) = self.runtime.boundary("service-stopped") {
            #[cfg(test)]
            if matches!(error, SecurityError::InjectedCrash(_)) {
                return Err(error);
            }
            failures.push(format!("service boundary: {error}"));
        }
        for kind in [UnitKind::Socket, UnitKind::Service] {
            match self.stable_unit_until(kind, deadline) {
                Ok(state)
                    if state.rollback_target() == Some(StableRollbackTarget::InactiveDead) =>
                {
                    let boundary = match kind {
                        UnitKind::Socket => "socket-settled-inactive",
                        UnitKind::Service => "service-settled-inactive",
                    };
                    if let Err(error) = self.runtime.boundary(boundary) {
                        #[cfg(test)]
                        if matches!(error, SecurityError::InjectedCrash(_)) {
                            return Err(error);
                        }
                        failures.push(format!("{kind:?} settle boundary: {error}"));
                    }
                }
                Ok(_) => failures.push(format!("{kind:?} did not stop stably")),
                Err(error) => failures.push(format!("{kind:?} settle: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SecurityError::operation(failures.join("; ")))
        }
    }

    fn verify_restored_targets(
        &mut self,
        service_target: &StableUnitState,
        socket_target: &StableUnitState,
    ) -> SecurityResult<()> {
        let (service, socket) = self.stable_unit_pair()?;
        if service != *service_target || socket != *socket_target {
            return Err(SecurityError::Uncertain(
                "restored unit states differ from the exact journal targets".into(),
            ));
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
        let observation = self
            .runtime
            .persist_journal(self.journal_observation.as_ref(), &bytes)?;
        self.journal_observation = Some(observation);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_atomic_plan(
        &mut self,
        transaction_id: &str,
        path: &str,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        permissions: u32,
        timestamps: Option<RestorableFileTimestampsV1>,
        require_absent: bool,
    ) -> SecurityResult<AtomicWritePlanV1> {
        let context = self
            .runtime
            .observe_atomic_target(path, atomic_maximum_for(path))?;
        let expected_parent = expected_parent_permissions(path)?;
        if context.parent_directory.object_type != FileObjectType::Directory
            || context.parent_directory.uid != 0
            || context.parent_directory.gid != 0
            || context.parent_directory.permissions != expected_parent
            || context.parent_directory.link_count == 0
        {
            return Err(SecurityError::operation("unsafe atomic parent metadata"));
        }
        let (expected_target, operation) = match context.target {
            Some(target) => {
                if require_absent {
                    return Err(SecurityError::operation("no-replace target is occupied"));
                }
                target.validate_regular(0, 0, target.metadata.permissions)?;
                (
                    AtomicExpectedTargetV1::Present(target.atomic_identity()),
                    AtomicWriteKindV1::Exchange,
                )
            }
            None => (AtomicExpectedTargetV1::Absent, AtomicWriteKindV1::NoReplace),
        };
        AtomicWritePlanV1::new(
            transaction_id,
            path,
            context.parent_directory,
            expected_target,
            uid,
            gid,
            permissions,
            timestamps,
            bytes,
            operation,
        )
        .map_err(|error| SecurityError::operation(error.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_mode1_atomic(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        path: &str,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        permissions: u32,
        timestamps: Option<RestorableFileTimestampsV1>,
        require_absent: bool,
    ) -> SecurityResult<usize> {
        let plan = self.prepare_atomic_plan(
            &journal.transaction_id,
            path,
            bytes,
            uid,
            gid,
            permissions,
            timestamps,
            require_absent,
        )?;
        let current = journal.clone();
        journal
            .transaction_owned_paths
            .push(plan.staging_path.clone());
        if let Some(backup) = &plan.backup_path {
            journal.transaction_owned_paths.push(backup.clone());
        }
        journal.transaction_owned_paths.sort();
        journal.transaction_owned_paths.dedup();
        journal
            .atomic_writes
            .push(AtomicWriteRecordV1::planned(plan.clone()));
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_mode1_journal(journal)?;
        self.runtime.boundary("atomic-plan-synced")?;

        let index = journal.atomic_writes.len() - 1;
        let staged = self.runtime.create_atomic_stage(&plan, bytes)?;
        self.runtime.boundary("atomic-stage-created")?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::Staged {
            identity: staged.clone(),
        };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_mode1_journal(journal)?;
        self.runtime.boundary("atomic-stage-synced")?;
        let observation = self.runtime.commit_atomic_stage(&plan, &staged)?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::Committed {
            observation: observation.clone(),
        };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_mode1_journal(journal)?;
        self.runtime.boundary("atomic-observation-synced")?;
        Ok(index)
    }

    fn cleanup_mode1_atomic(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        index: usize,
    ) -> SecurityResult<()> {
        let (plan, observation) = committed_atomic_record(&journal.atomic_writes, index)?;
        let Some(_) = observation.backup else {
            return Ok(());
        };
        self.runtime.remove_atomic_backup(&plan, &observation)?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::BackupCleaned { observation };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_mode1_journal(journal)?;
        self.runtime.boundary("atomic-backup-cleaned")
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_plaintext_atomic(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
        path: &str,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        permissions: u32,
        timestamps: Option<RestorableFileTimestampsV1>,
    ) -> SecurityResult<usize> {
        let plan = self.prepare_atomic_plan(
            &journal.transaction_id,
            path,
            bytes,
            uid,
            gid,
            permissions,
            timestamps,
            false,
        )?;
        let current = journal.clone();
        journal
            .transaction_owned_paths
            .push(plan.staging_path.clone());
        if let Some(backup) = &plan.backup_path {
            journal.transaction_owned_paths.push(backup.clone());
        }
        journal.transaction_owned_paths.sort();
        journal.transaction_owned_paths.dedup();
        journal
            .atomic_writes
            .push(AtomicWriteRecordV1::planned(plan.clone()));
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_plaintext_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_plaintext_journal(journal)?;
        self.runtime.boundary("atomic-plan-synced")?;

        let index = journal.atomic_writes.len() - 1;
        let staged = self.runtime.create_atomic_stage(&plan, bytes)?;
        self.runtime.boundary("atomic-stage-created")?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::Staged {
            identity: staged.clone(),
        };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_plaintext_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_plaintext_journal(journal)?;
        self.runtime.boundary("atomic-stage-synced")?;
        let observation = self.runtime.commit_atomic_stage(&plan, &staged)?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::Committed {
            observation: observation.clone(),
        };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_plaintext_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_plaintext_journal(journal)?;
        self.runtime.boundary("atomic-observation-synced")?;
        Ok(index)
    }

    fn cleanup_plaintext_atomic(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
        index: usize,
    ) -> SecurityResult<()> {
        let (plan, observation) = committed_atomic_record(&journal.atomic_writes, index)?;
        let Some(_) = observation.backup else {
            return Ok(());
        };
        self.runtime.remove_atomic_backup(&plan, &observation)?;
        let current = journal.clone();
        journal.atomic_writes[index].state = AtomicWriteStateV1::BackupCleaned { observation };
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
        validate_plaintext_journal_transition(&current, journal)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        self.persist_plaintext_journal(journal)?;
        self.runtime.boundary("atomic-backup-cleaned")
    }

    fn reconcile_mode1_atomic_records(
        &mut self,
        journal: &mut ProvisioningJournalV1,
    ) -> SecurityResult<()> {
        for index in 0..journal.atomic_writes.len() {
            let staged = match &journal.atomic_writes[index].state {
                AtomicWriteStateV1::Planned => None,
                AtomicWriteStateV1::Staged { identity } => Some(identity.clone()),
                _ => continue,
            };
            let plan = journal.atomic_writes[index].plan.clone();
            let reconciliation = self
                .runtime
                .reconcile_atomic_write(&plan, staged.as_ref())?;
            if staged.is_none() && matches!(reconciliation, AtomicWriteReconciliation::Committed(_))
            {
                return Err(SecurityError::Uncertain(
                    "unjournaled atomic stage cannot authorize a committed write".into(),
                ));
            }
            let current = journal.clone();
            journal.atomic_writes[index].state = match reconciliation {
                AtomicWriteReconciliation::NotCommitted => AtomicWriteStateV1::Aborted,
                AtomicWriteReconciliation::Committed(observation) => {
                    AtomicWriteStateV1::Committed { observation }
                }
            };
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_journal_transition(&current, journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            self.persist_mode1_journal(journal)?;
            self.runtime.boundary("atomic-reconciled")?;
        }
        let pending: Vec<_> = journal
            .atomic_writes
            .iter()
            .enumerate()
            .filter_map(|(index, record)| match &record.state {
                AtomicWriteStateV1::Committed { observation } if observation.backup.is_some() => {
                    Some(index)
                }
                _ => None,
            })
            .collect();
        for index in pending {
            self.cleanup_mode1_atomic(journal, index)?;
        }
        Ok(())
    }

    fn reconcile_plaintext_atomic_records(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
    ) -> SecurityResult<()> {
        for index in 0..journal.atomic_writes.len() {
            let staged = match &journal.atomic_writes[index].state {
                AtomicWriteStateV1::Planned => None,
                AtomicWriteStateV1::Staged { identity } => Some(identity.clone()),
                _ => continue,
            };
            let plan = journal.atomic_writes[index].plan.clone();
            let reconciliation = self
                .runtime
                .reconcile_atomic_write(&plan, staged.as_ref())?;
            if staged.is_none() && matches!(reconciliation, AtomicWriteReconciliation::Committed(_))
            {
                return Err(SecurityError::Uncertain(
                    "unjournaled atomic stage cannot authorize a committed write".into(),
                ));
            }
            let current = journal.clone();
            journal.atomic_writes[index].state = match reconciliation {
                AtomicWriteReconciliation::NotCommitted => AtomicWriteStateV1::Aborted,
                AtomicWriteReconciliation::Committed(observation) => {
                    AtomicWriteStateV1::Committed { observation }
                }
            };
            self.bind_next_generation(
                &mut journal.generation,
                &mut journal.prior_journal_identity,
            )?;
            validate_plaintext_journal_transition(&current, journal)
                .map_err(|error| SecurityError::operation(error.to_string()))?;
            self.persist_plaintext_journal(journal)?;
            self.runtime.boundary("atomic-reconciled")?;
        }
        let pending: Vec<_> = journal
            .atomic_writes
            .iter()
            .enumerate()
            .filter_map(|(index, record)| match &record.state {
                AtomicWriteStateV1::Committed { observation } if observation.backup.is_some() => {
                    Some(index)
                }
                _ => None,
            })
            .collect();
        for index in pending {
            self.cleanup_plaintext_atomic(journal, index)?;
        }
        Ok(())
    }

    fn restore_mode1_snapshot(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        path: &str,
        snapshot: Option<&ExactFileSnapshot>,
        maximum: usize,
    ) -> SecurityResult<()> {
        match snapshot {
            Some(snapshot) => {
                let reconstruction = snapshot
                    .reconstruct(maximum)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                let write = self.execute_mode1_atomic(
                    journal,
                    path,
                    &reconstruction.bytes,
                    reconstruction.metadata.uid,
                    reconstruction.metadata.gid,
                    reconstruction.metadata.permissions,
                    Some(reconstruction.metadata.restorable_timestamps),
                    false,
                )?;
                self.cleanup_mode1_atomic(journal, write)
            }
            None => self.remove_transaction_owned_target(path, &journal.atomic_writes),
        }
    }

    fn restore_plaintext_snapshot(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
        path: &str,
        snapshot: Option<&ExactFileSnapshot>,
        maximum: usize,
    ) -> SecurityResult<()> {
        match snapshot {
            Some(snapshot) => {
                let reconstruction = snapshot
                    .reconstruct(maximum)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                let write = self.execute_plaintext_atomic(
                    journal,
                    path,
                    &reconstruction.bytes,
                    reconstruction.metadata.uid,
                    reconstruction.metadata.gid,
                    reconstruction.metadata.permissions,
                    Some(reconstruction.metadata.restorable_timestamps),
                )?;
                self.cleanup_plaintext_atomic(journal, write)
            }
            None => self.remove_transaction_owned_target(path, &journal.atomic_writes),
        }
    }

    fn remove_transaction_owned_target(
        &mut self,
        path: &str,
        records: &[AtomicWriteRecordV1],
    ) -> SecurityResult<()> {
        let context = self
            .runtime
            .observe_atomic_target(path, atomic_maximum_for(path))?;
        let Some(target) = context.target else {
            return Ok(());
        };
        let identity = target.atomic_identity();
        let owned = records.iter().rev().any(|record| {
            record.plan.target_path == path
                && match &record.state {
                    AtomicWriteStateV1::Committed { observation }
                    | AtomicWriteStateV1::BackupCleaned { observation } => {
                        observation.target == identity
                    }
                    AtomicWriteStateV1::Planned
                    | AtomicWriteStateV1::Staged { .. }
                    | AtomicWriteStateV1::Aborted => false,
                }
        });
        if !owned {
            return Err(SecurityError::Uncertain(format!(
                "refusing to remove unowned transaction target: {path}"
            )));
        }
        self.runtime.remove_file_exact(path, &identity)
    }

    fn advance_mode1(
        &mut self,
        journal: &mut ProvisioningJournalV1,
        phase: JournalPhase,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = phase;
        journal.recovery_action = recovery_action_for_phase(phase);
        if phase == JournalPhase::DropinCommitted {
            journal.effective_units = Some(self.observe_effective_units()?);
        }
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
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
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
        let observation = self
            .runtime
            .persist_journal(self.journal_observation.as_ref(), &bytes)?;
        self.journal_observation = Some(observation);
        Ok(())
    }

    fn advance_plaintext(
        &mut self,
        journal: &mut PlaintextProvisioningJournalV1,
        phase: PlaintextJournalPhase,
    ) -> SecurityResult<()> {
        let current = journal.clone();
        journal.phase = phase;
        journal.recovery_action = plaintext_recovery_action_for_phase(phase);
        if phase == PlaintextJournalPhase::DropinRemoved {
            journal.effective_units = Some(self.observe_effective_units()?);
        }
        if phase.ordinal() >= PlaintextJournalPhase::EnabledConfigCommitted.ordinal() {
            journal.live_config_sha256 = Some(journal.enabled_config_sha256.clone());
        }
        self.bind_next_generation(&mut journal.generation, &mut journal.prior_journal_identity)?;
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

fn stable_cleanup_unit(observation: UnitObservation) -> SecurityResult<StableUnitState> {
    if observation.load_state != howy_common::provisioning::UnitLoadState::Loaded
        || observation.active_state != howy_common::provisioning::UnitActiveState::Inactive
        || observation.sub_state != howy_common::provisioning::UnitSubState::Dead
        || !observation.unit_file_state.is_admissible()
        || observation.has_queued_job
    {
        return Err(SecurityError::Refused(
            "cleanup unit snapshot is not initially inactive and stable".into(),
        ));
    }
    Ok(StableUnitState {
        unit_kind: observation.unit_kind,
        load_state: observation.load_state,
        active_state: observation.active_state,
        sub_state: observation.sub_state,
        unit_file_state: observation.unit_file_state,
    })
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

fn config_prompt_required(bytes: &[u8]) -> SecurityResult<bool> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| SecurityError::operation("configuration is not UTF-8"))?;
    let config: HowyConfig =
        toml::from_str(source).map_err(|_| SecurityError::operation("configuration is invalid"))?;
    config.validate().map_err(SecurityError::operation)?;
    Ok(config.presence.mode == PresenceMode::Confirm)
}

fn bump_generation(generation: &mut u64) -> SecurityResult<()> {
    *generation = generation
        .checked_add(1)
        .ok_or_else(|| SecurityError::Uncertain("journal generation overflow".into()))?;
    Ok(())
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
    effective_units: EffectiveUnitSetV1,
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
        effective_units,
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

fn cleanup_file_matches(identity: &CleanupArtifactIdentityV1, file: &ObservedFile) -> bool {
    inspect_systemd_credential_envelope(&file.bytes).is_ok_and(|inspected| {
        cleanup_identity(
            &identity.transaction_id,
            file,
            inspected.actual_key_id,
            inspected.envelope_sha256,
            inspected.envelope_size,
        ) == *identity
    })
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
        || states.readiness != SecurityReadinessStateV1::Ready
        || states.poison != SecurityPoisonStateV1::NotPoisoned
        || !status.storage_ready
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
    prior_invocation: Option<&str>,
    expected_daemon: &DaemonVerifierIdentityV1,
    prompt_required: bool,
) -> SecurityResult<()> {
    let states = status
        .validate_strict()
        .map_err(|error| SecurityError::operation(error.to_string()))?;
    if status.active_security_mode != 0
        || status.config_sha256 != config_sha256.as_str()
        || !status.credential_name.is_empty()
        || !status.configured_credential_source.is_empty()
        || status.prompt_required != prompt_required
        || states.backend != SecurityBackendStateV1::Ready
        || states.readiness != SecurityReadinessStateV1::Ready
        || states.poison != SecurityPoisonStateV1::NotPoisoned
        || !status.storage_ready
        || status.daemon_version != expected_daemon.version
        || status.build_identity != expected_daemon.build_identity
        || status.binary_absolute_path != expected_daemon.binary_absolute_path
        || status.binary_sha256 != expected_daemon.binary_sha256.as_str()
        || prior_invocation.is_some_and(|prior| prior == status.daemon_invocation_id)
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
    let valid = value.strip_prefix("txn-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if !valid {
        return Err(SecurityError::Refused("invalid transaction ID".into()));
    }
    Ok(())
}

fn sorted_paths<const N: usize>(paths: [&str; N]) -> Vec<String> {
    let mut paths: Vec<_> = paths.into_iter().map(str::to_owned).collect();
    paths.sort();
    paths.dedup();
    paths
}

fn atomic_maximum_for(path: &str) -> usize {
    match path {
        howy_common::paths::CONFIG_FILE => MAX_CONFIG_BYTES,
        MODE1_CREDENTIAL_PATH => howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        MODE1_DROPIN_PATH => MAX_DROPIN_BYTES,
        SECURITY_RECEIPT_PATH => MAX_RECEIPT_BYTES,
        _ if path.starts_with(&format!("{SECURITY_UNADOPTED_DIRECTORY}/")) => MAX_RECEIPT_BYTES,
        _ => MAX_JOURNAL_BYTES,
    }
}

fn expected_parent_permissions(path: &str) -> SecurityResult<u32> {
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(std::path::Path::to_str)
        .ok_or_else(|| SecurityError::operation("atomic target parent is invalid"))?;
    Ok(
        if matches!(
            parent,
            howy_common::provisioning::HOWY_CONFIG_DIRECTORY
                | howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY
                | howy_common::provisioning::SECURITY_STATE_DIRECTORY
                | SECURITY_UNADOPTED_DIRECTORY
        ) {
            0o700
        } else {
            0o755
        },
    )
}

fn committed_atomic_record(
    records: &[AtomicWriteRecordV1],
    index: usize,
) -> SecurityResult<(AtomicWritePlanV1, AtomicWriteObservationV1)> {
    let record = records
        .get(index)
        .ok_or_else(|| SecurityError::operation("atomic write record is missing"))?;
    let observation = match &record.state {
        AtomicWriteStateV1::Committed { observation } => observation.clone(),
        _ => {
            return Err(SecurityError::operation(
                "atomic write is not awaiting backup cleanup",
            ));
        }
    };
    Ok((record.plan.clone(), observation))
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

fn cleanup_quarantine_path(transaction_id: &str) -> String {
    format!(
        "{}/.howy-{transaction_id}.quarantine",
        howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY
    )
}
