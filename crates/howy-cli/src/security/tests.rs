use std::collections::{BTreeMap, BTreeSet};

use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
use howy_common::protocol::{
    DaemonInfo, NamespaceDiagnostic, SecurityBackendStateV1, SecurityInfoResult,
    SecurityPoisonStateV1, SecurityReadinessStateV1,
};
use howy_common::provisioning::{
    AtomicExpectedTargetV1, AtomicFileIdentityV1, AtomicWriteKindV1, AtomicWriteObservationV1,
    AtomicWritePlanV1, BASE_SERVICE_UNIT_PATH, BASE_SOCKET_UNIT_PATH, DaemonVerifierIdentityV1,
    DirectoryIdentityV1, EffectiveCredentialLoadV1, EffectiveFileMetadataV1,
    EffectiveSetCredentialV1, EffectiveUnitFileV1, EffectiveUnitObservationV1, EffectiveUnitSetV1,
    FileLinkPolicy, FileMetadataSnapshotV1, FileObjectType, FileTimestampV1, JournalPhase,
    MAX_CONFIG_BYTES, MAX_JOURNAL_BYTES, MODE1_CREDENTIAL_NAME, MODE1_CREDENTIAL_PATH,
    MODE1_CREDENTIAL_SOURCE_COMPANION_NAME, MODE1_DROPIN_PATH, MODE1_NAMESPACE_PATH,
    NamespaceFingerprintV1, PlaintextJournalPhase, PlaintextProvisioningJournalV1,
    ProvisioningJournalV1, ProvisioningReceiptV1, ReadinessResultV1, ReceiptState,
    RestorableFileTimestampsV1, SECURITY_JOURNAL_PATH, SECURITY_RECEIPT_PATH,
    SECURITY_TRANSACTION_GUARD_PATH, SECURITY_UNADOPTED_DIRECTORY, SecurityDirectoryRecordV1,
    Sha256Digest, StableRollbackTarget, SupervisorJournalV1, SupervisorPhaseV1,
    TransactionGuardIdentityV1, TransactionGuardV1, UnadoptedArtifactV1, UnitActiveState,
    UnitFileState, UnitKind, UnitLoadState, UnitObservation, UnitSubState, VerifierResultV1,
    required_service_hardening, required_unit_conditions,
};

use super::command::{CommandSpec, KeySelection};
use super::engine::{
    AtomicTargetObservation, AtomicWriteReconciliation, CleanupRequest, MODE0_DROPIN_BYTES,
    MODE1_DROPIN_BYTES, ObservedFile, ProvisionMode, ProvisionRequest, SecretKeyMaterial,
    SecurityEngine, SecurityError, SecurityOutcome, SecurityResult, SecurityRuntime,
};

#[derive(Clone)]
struct FakeFile {
    bytes: Vec<u8>,
    metadata: FileMetadataSnapshotV1,
    device: u64,
    inode: u64,
}

impl FakeFile {
    fn observed(&self) -> ObservedFile {
        ObservedFile {
            bytes: self.bytes.clone(),
            metadata: self.metadata.clone(),
            device_id: self.device,
            inode: self.inode,
            parent_device_id: 8,
            parent_inode: 42,
            parent_uid: 0,
            parent_gid: 0,
            parent_permissions: 0o700,
            parent_link_count: 2,
        }
    }
}

struct FakeKey([u8; 32]);

impl SecretKeyMaterial for FakeKey {
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for FakeKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone)]
struct FakeRuntime {
    files: BTreeMap<String, FakeFile>,
    directories: BTreeMap<String, (u64, u32)>,
    transaction_created_directories: BTreeSet<String>,
    next_inode: u64,
    service: UnitObservation,
    socket: UnitObservation,
    events: Vec<String>,
    commands: Vec<CommandSpec>,
    credential_input_lengths: Vec<usize>,
    envelope: Vec<u8>,
    namespace_nonempty: bool,
    readiness_error: Option<SecurityError>,
    malformed_readiness: bool,
    encrypt_error: Option<SecurityError>,
    rng_error: bool,
    root: bool,
    locked: bool,
    systemd_checked: bool,
    transaction_id_counter: usize,
    boundary_count: usize,
    crash_at: Option<usize>,
    crash_name: Option<&'static str>,
    transient_killed: bool,
    transient_exists: bool,
    status_available: bool,
    invocation_counter: u8,
    preserve_invocation_on_start: bool,
    artifact_read_count: usize,
    swap_artifact_on_read: Option<usize>,
    monotonic_millis: u64,
    effective_units: EffectiveUnitSetV1,
    effective_override: Option<EffectiveUnitSetV1>,
    host_secret_secure: bool,
    auto_tpm2_available: bool,
    fail_after: Option<&'static str>,
    settle_units: bool,
    mutate_after_readiness: Option<&'static str>,
    mutate_on_readiness_call: Option<(usize, &'static str)>,
    readiness_calls: usize,
    cleanup_mutation: Option<&'static str>,
    cleanup_pre_guard_mutation: Option<&'static str>,
    public_status_mutation: Option<&'static str>,
}

impl FakeRuntime {
    fn fresh() -> Self {
        let mut runtime = Self {
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            transaction_created_directories: BTreeSet::new(),
            next_inode: 100,
            service: unit(UnitKind::Service, false),
            socket: unit(UnitKind::Socket, false),
            events: Vec::new(),
            commands: Vec::new(),
            credential_input_lengths: Vec::new(),
            envelope: host_envelope_text(),
            namespace_nonempty: false,
            readiness_error: None,
            malformed_readiness: false,
            encrypt_error: None,
            rng_error: false,
            root: true,
            locked: false,
            systemd_checked: false,
            transaction_id_counter: 0,
            boundary_count: 0,
            crash_at: None,
            crash_name: None,
            transient_killed: false,
            transient_exists: false,
            status_available: false,
            invocation_counter: 1,
            preserve_invocation_on_start: false,
            artifact_read_count: 0,
            swap_artifact_on_read: None,
            monotonic_millis: 0,
            effective_units: base_effective_units(),
            effective_override: None,
            host_secret_secure: true,
            auto_tpm2_available: false,
            fail_after: None,
            settle_units: false,
            mutate_after_readiness: None,
            mutate_on_readiness_call: None,
            readiness_calls: 0,
            cleanup_mutation: None,
            cleanup_pre_guard_mutation: None,
            public_status_mutation: None,
        };
        runtime.put(
            BASE_SERVICE_UNIT_PATH,
            b"[Service]\nExecStart=/usr/bin/howyd\n",
            0o644,
        );
        runtime.put(
            BASE_SOCKET_UNIT_PATH,
            b"[Socket]\nListenStream=/run/howy/howy.sock\n",
            0o644,
        );
        runtime
    }

    fn put(&mut self, path: &str, bytes: &[u8], permissions: u32) {
        self.next_inode += 1;
        self.files.insert(
            path.into(),
            FakeFile {
                bytes: bytes.to_vec(),
                metadata: metadata(bytes.len(), permissions),
                device: 8,
                inode: self.next_inode,
            },
        );
    }

    fn remove(&mut self, path: &str) {
        self.files.remove(path);
    }

    fn fail_after(&mut self, point: &'static str) -> SecurityResult<()> {
        if self.fail_after == Some(point) {
            self.fail_after = None;
            Err(SecurityError::operation(format!(
                "injected failure after {point}"
            )))
        } else {
            Ok(())
        }
    }

    fn receipt(&self) -> ProvisioningReceiptV1 {
        ProvisioningReceiptV1::parse(&self.files[SECURITY_RECEIPT_PATH].bytes).unwrap()
    }

    fn verifier_for(&self, config: &[u8]) -> VerifierResultV1 {
        VerifierResultV1::new(
            Sha256Digest::from_bytes(config),
            howy_common::provisioning::DaemonVerifierIdentityV1 {
                version: env!("CARGO_PKG_VERSION").into(),
                build_identity: "howy-test-build".into(),
                binary_absolute_path: "/usr/bin/howyd".into(),
                binary_sha256: Sha256Digest::from_bytes(b"fake-howyd"),
            },
            ReadinessResultV1::new_verified(
                NamespaceFingerprintV1 {
                    sha256: Sha256Digest::from_bytes(b"empty-mode1-namespace"),
                    entry_count: if self.namespace_nonempty { 1 } else { 0 },
                    ciphertext_bytes: if self.namespace_nonempty { 128 } else { 0 },
                },
                self.namespace_nonempty
                    .then(|| howy_common::provisioning::RecognizerIdentity {
                        absolute_path: "/usr/share/howy/onnx-data/w600k_r50.onnx".into(),
                        sha256: Sha256Digest::from_bytes(b"recognizer"),
                    }),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn status(&mut self) -> Option<SecurityInfoResult> {
        if !self.status_available || self.service.active_state != UnitActiveState::Active {
            return None;
        }
        let config_file = self.files.get(howy_common::paths::CONFIG_FILE);
        let config: HowyConfig = match config_file {
            Some(file) => toml::from_str(std::str::from_utf8(&file.bytes).ok()?).ok()?,
            None => HowyConfig::legacy_defaults(),
        };
        let mode = config.security.embedding_mode as u32;
        let mode1 = mode == 1;
        Some(SecurityInfoResult {
            detector_model: "/usr/share/howy/onnx-data/det_10g.onnx".into(),
            recognizer_model: "/usr/share/howy/onnx-data/w600k_r50.onnx".into(),
            active_security_mode: mode,
            key_epoch: config.security.key_epoch,
            storage_ready: true,
            prompt_required: config.presence.mode == howy_common::config::PresenceMode::Confirm,
            namespaces: [
                (0, "/etc/howy/models"),
                (1, MODE1_NAMESPACE_PATH),
                (2, "/etc/howy/models/mode2"),
            ]
            .into_iter()
            .map(|(namespace_mode, path)| NamespaceDiagnostic {
                mode: namespace_mode,
                path: path.into(),
                active: namespace_mode == mode,
                implemented: namespace_mode < 2,
            })
            .collect(),
            config_sha256: config_file
                .map(|file| file.observed().sha256())
                .unwrap_or_else(|| Sha256Digest::from_bytes(b"absent-prior-config"))
                .as_str()
                .into(),
            credential_name: if mode1 {
                "howy.storage.mode1.epoch1"
            } else {
                ""
            }
            .into(),
            configured_credential_source: if mode1 { MODE1_CREDENTIAL_PATH } else { "" }.into(),
            backend_state: SecurityBackendStateV1::Ready as i32,
            readiness_state: SecurityReadinessStateV1::Ready as i32,
            poison_state: SecurityPoisonStateV1::NotPoisoned as i32,
            daemon_invocation_id: format!("{:02x}", self.invocation_counter).repeat(32),
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            build_identity: "howy-test-build".into(),
            binary_absolute_path: "/usr/bin/howyd".into(),
            binary_sha256: Sha256Digest::from_bytes(b"fake-howyd").as_str().into(),
        })
    }
}

impl SecurityRuntime for FakeRuntime {
    fn require_root(&mut self) -> SecurityResult<()> {
        self.events.push("require-root".into());
        if self.root {
            Ok(())
        } else {
            Err(SecurityError::Refused("not root".into()))
        }
    }

    fn acquire_lock(&mut self) -> SecurityResult<()> {
        self.events.push("lock".into());
        self.locked = true;
        Ok(())
    }

    fn require_systemd_261(&mut self) -> SecurityResult<()> {
        self.events.push("systemd-261".into());
        self.systemd_checked = true;
        Ok(())
    }

    fn transaction_id(&mut self) -> SecurityResult<String> {
        self.transaction_id_counter += 1;
        Ok(format!(
            "txn-{:032x}",
            0x0123456789abcdef0123456789abcdefu128 + self.transaction_id_counter as u128 - 1
        ))
    }

    fn generate_key(&mut self) -> SecurityResult<Box<dyn SecretKeyMaterial>> {
        self.events.push("rng-mlock".into());
        if self.rng_error {
            Err(SecurityError::operation("rng/mlock failed"))
        } else {
            Ok(Box::new(FakeKey([0x5a; 32])))
        }
    }

    fn read_file(&mut self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>> {
        self.events.push(format!("read:{path}"));
        if path == MODE1_CREDENTIAL_PATH {
            self.artifact_read_count += 1;
            if self.swap_artifact_on_read == Some(self.artifact_read_count) {
                self.put(path, b"swapped", 0o600);
            }
        }
        self.files
            .get(path)
            .map(|file| {
                if file.bytes.len() > maximum {
                    Err(SecurityError::operation("fake bounded read overflow"))
                } else {
                    Ok(file.observed())
                }
            })
            .transpose()
    }

    fn observe_atomic_target(
        &mut self,
        path: &str,
        maximum: usize,
    ) -> SecurityResult<AtomicTargetObservation> {
        self.events.push(format!("atomic-observe:{path}"));
        let parent = std::path::Path::new(path)
            .parent()
            .and_then(std::path::Path::to_str)
            .unwrap();
        let permissions = if matches!(
            parent,
            howy_common::provisioning::HOWY_CONFIG_DIRECTORY
                | howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY
                | howy_common::provisioning::SECURITY_STATE_DIRECTORY
                | SECURITY_UNADOPTED_DIRECTORY
        ) {
            0o700
        } else {
            0o755
        };
        let target = self
            .files
            .get(path)
            .map(|file| {
                if file.bytes.len() > maximum {
                    Err(SecurityError::operation("fake atomic read overflow"))
                } else {
                    Ok(file.observed())
                }
            })
            .transpose()?;
        Ok(AtomicTargetObservation {
            parent_directory: DirectoryIdentityV1 {
                path: parent.into(),
                object_type: FileObjectType::Directory,
                device_id: 8,
                inode: 42,
                uid: 0,
                gid: 0,
                permissions,
                link_count: 2,
            },
            target,
        })
    }

    fn create_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        bytes: &[u8],
    ) -> SecurityResult<AtomicFileIdentityV1> {
        plan.validate()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let journaled = self
            .files
            .get(SECURITY_JOURNAL_PATH)
            .is_some_and(|file| journal_contains_atomic_plan(&file.bytes, plan));
        if !journaled {
            return Err(SecurityError::operation(
                "fake runtime observed an unjournaled atomic stage",
            ));
        }
        self.events
            .push(format!("atomic-create:{}", plan.staging_path));
        if self.files.contains_key(&plan.staging_path) {
            return Err(SecurityError::Uncertain(
                "fake atomic stage collision was retained".into(),
            ));
        }
        self.put(&plan.staging_path, bytes, plan.permissions);
        Ok(self.files[&plan.staging_path].observed().atomic_identity())
    }

    fn commit_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: &AtomicFileIdentityV1,
    ) -> SecurityResult<AtomicWriteObservationV1> {
        let staged_file = self
            .files
            .get(&plan.staging_path)
            .cloned()
            .ok_or_else(|| SecurityError::Uncertain("fake atomic stage disappeared".into()))?;
        if staged_file.observed().atomic_identity() != *staged {
            return Err(SecurityError::Uncertain(
                "fake atomic stage identity changed".into(),
            ));
        }
        let current = self.files.get(&plan.target_path).cloned();
        let expected_matches = match (&plan.expected_target, &current) {
            (AtomicExpectedTargetV1::Absent, None) => true,
            (AtomicExpectedTargetV1::Present(expected), Some(current)) => {
                current.observed().atomic_identity() == *expected
            }
            _ => false,
        };
        if !expected_matches {
            return Err(SecurityError::operation("fake atomic target changed"));
        }
        let staged_file = self.files.remove(&plan.staging_path).unwrap();
        match plan.operation {
            AtomicWriteKindV1::Exchange => {
                let old = self
                    .files
                    .remove(&plan.target_path)
                    .expect("validated present");
                self.files.insert(plan.target_path.clone(), staged_file);
                self.files.insert(plan.staging_path.clone(), old);
            }
            AtomicWriteKindV1::NoReplace => {
                self.files.insert(plan.target_path.clone(), staged_file);
            }
        }
        let target = self.files[&plan.target_path].observed().atomic_identity();
        let backup = plan
            .backup_path
            .as_ref()
            .and_then(|path| self.files.get(path))
            .map(|file| file.observed().atomic_identity());
        let observation = AtomicWriteObservationV1 { target, backup };
        observation
            .validate_for_plan(plan)
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        if plan.target_path == SECURITY_RECEIPT_PATH {
            self.fail_after("receipt-write")?;
        }
        Ok(observation)
    }

    fn reconcile_atomic_write(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: Option<&AtomicFileIdentityV1>,
    ) -> SecurityResult<AtomicWriteReconciliation> {
        let target = self
            .files
            .get(&plan.target_path)
            .map(|file| file.observed());
        let stage = self
            .files
            .get(&plan.staging_path)
            .map(|file| file.observed());
        let target_old = match (&plan.expected_target, target.as_ref()) {
            (AtomicExpectedTargetV1::Absent, None) => true,
            (AtomicExpectedTargetV1::Present(expected), Some(file)) => {
                file.atomic_identity() == *expected
            }
            _ => false,
        };
        let Some(staged) = staged else {
            if target_old && stage.is_none() {
                return Ok(AtomicWriteReconciliation::NotCommitted);
            }
            return Err(SecurityError::Uncertain(
                "fake retained stage without durable identity".into(),
            ));
        };
        if target
            .as_ref()
            .is_some_and(|file| file.atomic_identity() == *staged)
        {
            let observation = AtomicWriteObservationV1 {
                target: target.unwrap().atomic_identity(),
                backup: stage.map(|file| file.atomic_identity()),
            };
            observation
                .validate_for_plan(plan)
                .map_err(|_| SecurityError::Uncertain("fake reconciliation mismatch".into()))?;
            return Ok(AtomicWriteReconciliation::Committed(observation));
        }
        if target_old
            && stage
                .as_ref()
                .is_some_and(|file| file.atomic_identity() == *staged)
        {
            self.files.remove(&plan.staging_path);
            return Ok(AtomicWriteReconciliation::NotCommitted);
        }
        Err(SecurityError::Uncertain(
            "fake atomic reconciliation refused".into(),
        ))
    }

    fn remove_atomic_backup(
        &mut self,
        plan: &AtomicWritePlanV1,
        observation: &AtomicWriteObservationV1,
    ) -> SecurityResult<()> {
        self.events
            .push(format!("atomic-cleanup:{}", plan.staging_path));
        let backup = observation
            .backup
            .as_ref()
            .ok_or_else(|| SecurityError::operation("fake backup absent"))?;
        let live = self
            .files
            .get(&plan.staging_path)
            .ok_or_else(|| SecurityError::operation("fake backup disappeared"))?
            .observed()
            .atomic_identity();
        if &live != backup {
            return Err(SecurityError::Uncertain("fake backup changed".into()));
        }
        self.files.remove(&plan.staging_path);
        Ok(())
    }

    fn remove_file_exact(
        &mut self,
        path: &str,
        expected: &AtomicFileIdentityV1,
    ) -> SecurityResult<()> {
        self.events.push(format!("remove-exact:{path}"));
        let live = self
            .files
            .get(path)
            .ok_or_else(|| SecurityError::operation("fake exact file absent"))?
            .observed()
            .atomic_identity();
        if &live != expected {
            return Err(SecurityError::Uncertain("fake exact file changed".into()));
        }
        self.remove(path);
        self.fail_after("restore-file")
    }

    fn plan_security_directory(
        &mut self,
        path: &str,
        permissions: u32,
    ) -> SecurityResult<SecurityDirectoryRecordV1> {
        self.events.push(format!("directory:plan:{path}"));
        let parent = std::path::Path::new(path)
            .parent()
            .and_then(std::path::Path::to_str)
            .ok_or_else(|| SecurityError::operation("fake directory parent missing"))?;
        let parent_permissions = self
            .directories
            .get(parent)
            .map(|(_, mode)| *mode)
            .unwrap_or(0o755);
        let parent_inode = self
            .directories
            .get(parent)
            .map(|(inode, _)| *inode)
            .unwrap_or(42);
        let expected_directory =
            self.directories
                .get(path)
                .map(|(inode, mode)| DirectoryIdentityV1 {
                    path: path.into(),
                    object_type: FileObjectType::Directory,
                    device_id: 8,
                    inode: *inode,
                    uid: 0,
                    gid: 0,
                    permissions: *mode,
                    link_count: 2,
                });
        if expected_directory
            .as_ref()
            .is_some_and(|identity| identity.permissions != permissions)
        {
            return Err(SecurityError::operation("fake unsafe directory metadata"));
        }
        Ok(SecurityDirectoryRecordV1 {
            path: path.into(),
            uid: 0,
            gid: 0,
            permissions,
            parent_directory: DirectoryIdentityV1 {
                path: parent.into(),
                object_type: FileObjectType::Directory,
                device_id: 8,
                inode: parent_inode,
                uid: 0,
                gid: 0,
                permissions: parent_permissions,
                link_count: 2,
            },
            preexisted: expected_directory.is_some(),
            expected_directory,
            observed_directory: None,
        })
    }

    fn ensure_security_directory(
        &mut self,
        intent: &SecurityDirectoryRecordV1,
    ) -> SecurityResult<DirectoryIdentityV1> {
        self.events
            .push(format!("directory:ensure:{}", intent.path));
        let (inode, permissions) = match self.directories.get(&intent.path).copied() {
            Some(existing) => existing,
            None => {
                self.next_inode += 1;
                let value = (self.next_inode, intent.permissions);
                self.directories.insert(intent.path.clone(), value);
                self.transaction_created_directories
                    .insert(intent.path.clone());
                value
            }
        };
        if permissions != intent.permissions {
            return Err(SecurityError::operation("fake unsafe directory metadata"));
        }
        Ok(DirectoryIdentityV1 {
            path: intent.path.clone(),
            object_type: FileObjectType::Directory,
            device_id: 8,
            inode,
            uid: 0,
            gid: 0,
            permissions,
            link_count: 2,
        })
    }

    fn verify_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        for expected in directories {
            let Some((inode, permissions)) = self.directories.get(&expected.path) else {
                return Err(SecurityError::Uncertain(
                    "fake directory disappeared".into(),
                ));
            };
            let observed = expected.observed_directory.as_ref().ok_or_else(|| {
                SecurityError::Uncertain("fake directory observation missing".into())
            })?;
            if *inode != observed.inode || *permissions != expected.permissions {
                return Err(SecurityError::Uncertain(
                    "fake directory identity changed".into(),
                ));
            }
        }
        Ok(())
    }

    fn rollback_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        self.events.push("directories:rollback".into());
        for record in directories.iter().rev().filter(|record| !record.preexisted) {
            let prefix = format!("{}/", record.path);
            let has_files = self.files.keys().any(|path| path.starts_with(&prefix));
            let has_directories = self
                .directories
                .keys()
                .any(|path| path != &record.path && path.starts_with(&prefix));
            if !has_files && !has_directories {
                self.directories.remove(&record.path);
                self.transaction_created_directories.remove(&record.path);
            }
        }
        Ok(())
    }

    fn create_guard(
        &mut self,
        transaction_id: &str,
        expected: Option<&TransactionGuardIdentityV1>,
    ) -> SecurityResult<TransactionGuardIdentityV1> {
        self.events.push("guard:create".into());
        let bytes = TransactionGuardV1::new(transaction_id)
            .map_err(|error| SecurityError::operation(error.to_string()))?
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        match self.files.get(SECURITY_TRANSACTION_GUARD_PATH) {
            Some(file) if file.bytes == bytes => {
                let identity = TransactionGuardIdentityV1::new(
                    transaction_id,
                    file.observed().atomic_identity(),
                )
                .unwrap();
                if expected.is_some_and(|expected| expected != &identity) {
                    Err(SecurityError::Uncertain("replacement guard".into()))
                } else {
                    Ok(identity)
                }
            }
            Some(_) => Err(SecurityError::Uncertain("other guard".into())),
            None => {
                self.put(SECURITY_TRANSACTION_GUARD_PATH, &bytes, 0o600);
                let file = self.files[SECURITY_TRANSACTION_GUARD_PATH].observed();
                Ok(
                    TransactionGuardIdentityV1::new(transaction_id, file.atomic_identity())
                        .unwrap(),
                )
            }
        }
    }

    fn remove_guard(
        &mut self,
        transaction_id: &str,
        expected: &TransactionGuardIdentityV1,
    ) -> SecurityResult<()> {
        self.events.push("guard:remove".into());
        expected.validate(transaction_id).unwrap();
        let live = self
            .files
            .get(SECURITY_TRANSACTION_GUARD_PATH)
            .ok_or_else(|| SecurityError::Uncertain("guard disappeared".into()))?;
        if live.observed().atomic_identity() != expected.file
            || live.bytes != expected.content.deterministic_bytes().unwrap()
        {
            return Err(SecurityError::Uncertain("replacement guard".into()));
        }
        self.remove(SECURITY_TRANSACTION_GUARD_PATH);
        self.fail_after("guard-remove")
    }

    fn load_journal(&mut self) -> SecurityResult<Option<ObservedFile>> {
        Ok(self
            .files
            .get(SECURITY_JOURNAL_PATH)
            .map(FakeFile::observed))
    }

    fn persist_journal(
        &mut self,
        prior: Option<&ObservedFile>,
        bytes: &[u8],
    ) -> SecurityResult<ObservedFile> {
        self.events.push("journal:sync".into());
        let live = self
            .files
            .get(SECURITY_JOURNAL_PATH)
            .map(FakeFile::observed);
        if live.as_ref() != prior {
            return Err(SecurityError::Uncertain(
                "journal prior identity mismatch".into(),
            ));
        }
        let bound_prior = ProvisioningJournalV1::parse(bytes)
            .ok()
            .and_then(|journal| journal.prior_journal_identity)
            .or_else(|| {
                PlaintextProvisioningJournalV1::parse(bytes)
                    .ok()
                    .and_then(|journal| journal.prior_journal_identity)
            })
            .or_else(|| {
                SupervisorJournalV1::parse(bytes)
                    .ok()
                    .and_then(|journal| journal.prior_journal_identity)
            });
        if bound_prior != prior.map(ObservedFile::atomic_identity) {
            return Err(SecurityError::Uncertain(
                "journal did not bind the exact prior identity".into(),
            ));
        }
        if let Ok(journal) = SupervisorJournalV1::parse(bytes) {
            self.events
                .push(format!("supervisor-phase:{:?}", journal.phase));
        }
        self.put(SECURITY_JOURNAL_PATH, bytes, 0o600);
        if SupervisorJournalV1::parse(bytes)
            .is_ok_and(|journal| journal.phase == SupervisorPhaseV1::UnitsRestored)
        {
            self.fail_after("supervisor-restored")?;
        }
        if ProvisioningJournalV1::parse(bytes)
            .is_ok_and(|journal| journal.phase == JournalPhase::DisabledUnitsStarted)
        {
            self.fail_after("disabled-units-restored")?;
        }
        if PlaintextProvisioningJournalV1::parse(bytes)
            .is_ok_and(|journal| journal.phase == PlaintextJournalPhase::UnitsStarted)
        {
            self.fail_after("plaintext-units-started")?;
        }
        Ok(self.files[SECURITY_JOURNAL_PATH].observed())
    }

    fn remove_journal(
        &mut self,
        transaction_id: &str,
        expected: &ObservedFile,
    ) -> SecurityResult<()> {
        self.events.push("journal:remove".into());
        let transaction_matches = ProvisioningJournalV1::parse(&expected.bytes)
            .is_ok_and(|journal| journal.transaction_id == transaction_id)
            || PlaintextProvisioningJournalV1::parse(&expected.bytes)
                .is_ok_and(|journal| journal.transaction_id == transaction_id)
            || SupervisorJournalV1::parse(&expected.bytes)
                .is_ok_and(|journal| journal.transaction_id == transaction_id);
        if !transaction_matches {
            return Err(SecurityError::Uncertain(
                "journal removal transaction mismatch".into(),
            ));
        }
        if self
            .files
            .get(SECURITY_JOURNAL_PATH)
            .map(FakeFile::observed)
            .as_ref()
            != Some(expected)
        {
            return Err(SecurityError::Uncertain(
                "journal removal identity mismatch".into(),
            ));
        }
        self.remove(SECURITY_JOURNAL_PATH);
        Ok(())
    }

    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation> {
        self.events.push(format!("show:{unit:?}"));
        Ok(match unit {
            UnitKind::Service => self.service,
            UnitKind::Socket => self.socket,
        })
    }

    fn effective_unit_observation(
        &mut self,
        unit: UnitKind,
    ) -> SecurityResult<EffectiveUnitObservationV1> {
        self.events.push(format!("effective:{unit:?}"));
        let units = self
            .effective_override
            .as_ref()
            .unwrap_or(&self.effective_units);
        Ok(match unit {
            UnitKind::Service => units.service.clone(),
            UnitKind::Socket => units.socket.clone(),
        })
    }

    fn host_secret_preexisting_secure(&mut self) -> SecurityResult<bool> {
        self.events.push("host-secret".into());
        Ok(self.host_secret_secure)
    }

    fn resolve_key_selection(&mut self, requested: KeySelection) -> SecurityResult<KeySelection> {
        self.events.push("resolve-key-selection".into());
        Ok(match requested {
            KeySelection::Auto if self.auto_tpm2_available => KeySelection::Tpm2,
            KeySelection::Auto => KeySelection::Host,
            explicit => explicit,
        })
    }

    fn daemon_verifier_identity(&mut self) -> SecurityResult<DaemonVerifierIdentityV1> {
        Ok(fake_daemon_identity())
    }

    fn monotonic_millis(&mut self) -> u64 {
        self.monotonic_millis
    }

    fn settle_step(&mut self) -> SecurityResult<()> {
        self.events.push("settle".into());
        self.monotonic_millis += 100;
        if self.settle_units {
            self.service.active_state = UnitActiveState::Inactive;
            self.service.sub_state = UnitSubState::Dead;
            self.service.has_queued_job = false;
            self.socket.active_state = UnitActiveState::Inactive;
            self.socket.sub_state = UnitSubState::Dead;
            self.socket.has_queued_job = false;
            self.settle_units = false;
        }
        Ok(())
    }

    fn stop_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        self.events.push(format!("stop:{unit:?}"));
        let state = match unit {
            UnitKind::Service => &mut self.service,
            UnitKind::Socket => &mut self.socket,
        };
        state.active_state = UnitActiveState::Inactive;
        state.sub_state = UnitSubState::Dead;
        self.status_available = false;
        Ok(())
    }

    fn start_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        self.events.push(format!("start:{unit:?}"));
        let service_was_inactive =
            unit == UnitKind::Service && self.service.active_state != UnitActiveState::Active;
        let disabled_service = unit == UnitKind::Service
            && self
                .files
                .get(howy_common::paths::CONFIG_FILE)
                .and_then(|file| std::str::from_utf8(&file.bytes).ok())
                .and_then(|source| toml::from_str::<HowyConfig>(source).ok())
                .is_some_and(|config| config.core.disabled);
        let state = match unit {
            UnitKind::Service => &mut self.service,
            UnitKind::Socket => &mut self.socket,
        };
        state.active_state = UnitActiveState::Active;
        state.sub_state = match unit {
            UnitKind::Service => UnitSubState::Running,
            UnitKind::Socket => UnitSubState::Listening,
        };
        if self.service.active_state == UnitActiveState::Active
            && self.socket.active_state == UnitActiveState::Active
        {
            self.status_available = true;
        }
        if service_was_inactive && !self.preserve_invocation_on_start {
            self.invocation_counter = self.invocation_counter.wrapping_add(1).max(1);
        }
        if disabled_service {
            self.service.active_state = UnitActiveState::Inactive;
            self.service.sub_state = UnitSubState::Dead;
            self.status_available = false;
        }
        match unit {
            UnitKind::Socket => self.fail_after("socket-start"),
            UnitKind::Service => self.fail_after("service-start"),
        }
    }

    fn daemon_reload(&mut self) -> SecurityResult<()> {
        self.events.push("daemon-reload".into());
        self.effective_units = effective_units_for_dropin(self.files.get(MODE1_DROPIN_PATH));
        Ok(())
    }

    fn transient_exists(&mut self, _unit: &str) -> SecurityResult<bool> {
        Ok(self.transient_exists)
    }

    fn stop_and_kill_transient(&mut self, _unit: &str) -> SecurityResult<()> {
        self.events.push("transient:stop-kill".into());
        self.transient_killed = true;
        self.transient_exists = false;
        Ok(())
    }

    fn encrypt_credential(
        &mut self,
        command: &CommandSpec,
        plaintext: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        self.events.push("systemd-creds".into());
        self.commands.push(command.clone());
        self.credential_input_lengths.push(plaintext.len());
        if let Some(error) = self.encrypt_error.clone() {
            return Err(error);
        }
        Ok(self.envelope.clone())
    }

    fn run_readiness(&mut self, command: &CommandSpec) -> SecurityResult<Vec<u8>> {
        self.events.push("systemd-run".into());
        self.readiness_calls += 1;
        self.commands.push(command.clone());
        if let Some(error) = self.readiness_error.clone() {
            return Err(error);
        }
        if self.malformed_readiness {
            return Ok(b"{malformed".to_vec());
        }
        let config_path = command.arguments.last_chunk::<4>().unwrap()[2].clone();
        let config = self
            .files
            .get(&config_path)
            .ok_or_else(|| SecurityError::operation("candidate config missing"))?;
        let output = self
            .verifier_for(&config.bytes)
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))?;
        let mutation = self.mutate_after_readiness.take().or_else(|| {
            self.mutate_on_readiness_call
                .filter(|(call, _)| *call == self.readiness_calls)
                .map(|(_, mutation)| mutation)
        });
        if let Some(mutation) = mutation {
            self.mutate_on_readiness_call = None;
            match mutation {
                "artifact" => self.put(MODE1_CREDENTIAL_PATH, b"changed", 0o600),
                "config" => self.put(howy_common::paths::CONFIG_FILE, b"changed", 0o600),
                "dropin" => self.put(MODE1_DROPIN_PATH, b"[Service]\n", 0o600),
                "namespace" => self.namespace_nonempty = !self.namespace_nonempty,
                _ => unreachable!(),
            }
        }
        Ok(output)
    }

    fn preview_verifier(&mut self, config: &[u8]) -> SecurityResult<VerifierResultV1> {
        self.events.push("preview-verifier".into());
        Ok(self.verifier_for(config))
    }

    fn namespace_nonempty(&mut self) -> SecurityResult<bool> {
        self.events.push("namespace".into());
        Ok(self.namespace_nonempty)
    }

    fn security_info(&mut self) -> SecurityResult<Option<SecurityInfoResult>> {
        self.events.push("security-info".into());
        let status = self.status();
        self.fail_after("status")?;
        Ok(status)
    }

    fn daemon_info(&mut self) -> SecurityResult<Option<DaemonInfo>> {
        self.events.push("daemon-info".into());
        Ok(self.status().map(|status| {
            let mut info = DaemonInfo {
                provider: "CPU".into(),
                detector_model: String::new(),
                recognizer_model: String::new(),
                embedding_dim: 512,
                uptime_secs: 1,
                active_security_mode: status.active_security_mode,
                prompt_required: status.prompt_required,
                storage_ready: status.storage_ready,
            };
            match self.public_status_mutation {
                Some("mode") => info.active_security_mode ^= 1,
                Some("prompt") => info.prompt_required = !info.prompt_required,
                Some("ready") => info.storage_ready = false,
                Some("malformed") => info.provider = "bad\nprovider".into(),
                None => {}
                Some(_) => unreachable!(),
            }
            info
        }))
    }

    fn quarantine_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        if self.files.contains_key(quarantine_path) {
            return Err(SecurityError::operation("fake quarantine occupied"));
        }
        let current = self
            .files
            .get(MODE1_CREDENTIAL_PATH)
            .ok_or_else(|| SecurityError::operation("artifact absent"))?
            .observed();
        if current.inode != expected.inode || current.sha256() != expected.sha256 {
            return Err(SecurityError::operation("artifact changed"));
        }
        self.events.push("artifact:quarantine".into());
        let file = self.files.remove(MODE1_CREDENTIAL_PATH).unwrap();
        self.files.insert(quarantine_path.into(), file);
        Ok(())
    }

    fn restore_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        self.events.push("artifact:restore".into());
        if self.files.contains_key(MODE1_CREDENTIAL_PATH) {
            let file = self.files.get(MODE1_CREDENTIAL_PATH).unwrap();
            return if !self.files.contains_key(quarantine_path)
                && file.inode == expected.inode
                && file.observed().sha256() == expected.sha256
            {
                Ok(())
            } else {
                Err(SecurityError::Uncertain("fake restore occupied".into()))
            };
        }
        let file = self
            .files
            .get(quarantine_path)
            .ok_or_else(|| SecurityError::Uncertain("fake quarantine absent".into()))?;
        if file.inode != expected.inode || file.observed().sha256() != expected.sha256 {
            return Err(SecurityError::Uncertain("fake quarantine changed".into()));
        }
        let file = self.files.remove(quarantine_path).unwrap();
        self.files.insert(MODE1_CREDENTIAL_PATH.into(), file);
        self.fail_after("quarantine-restore-fsynced")
    }

    fn unlink_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        self.events.push("quarantine:unlink".into());
        let Some(file) = self.files.get(quarantine_path) else {
            return if self.files.contains_key(MODE1_CREDENTIAL_PATH) {
                Err(SecurityError::Uncertain(
                    "fake artifact reappeared during unlink".into(),
                ))
            } else {
                Ok(())
            };
        };
        if file.inode != expected.inode || file.observed().sha256() != expected.sha256 {
            return Err(SecurityError::Uncertain("fake quarantine changed".into()));
        }
        self.remove(quarantine_path);
        self.fail_after("quarantine-unlink-fsynced")
    }

    fn boundary(&mut self, name: &'static str) -> SecurityResult<()> {
        self.boundary_count += 1;
        self.events.push(format!("boundary:{name}"));
        if name == "supervisor-prepared"
            && let Some(mutation) = self.cleanup_pre_guard_mutation.take()
        {
            match mutation {
                "active" => self.service = unit(UnitKind::Service, true),
                "reference" => {
                    let mut config = HowyConfig::secure_bootstrap_template();
                    config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
                    config.security.key_epoch = 1;
                    config.security.cached.credential_name = MODE1_CREDENTIAL_NAME.into();
                    let bytes = toml::to_string_pretty(&config).unwrap();
                    self.put(howy_common::paths::CONFIG_FILE, bytes.as_bytes(), 0o600);
                }
                _ => unreachable!(),
            }
        }
        if name == "artifact-quarantined"
            && let Some(mutation) = self.cleanup_mutation.take()
        {
            match mutation {
                "config-malformed" => {
                    self.put(howy_common::paths::CONFIG_FILE, b"not = [toml", 0o600)
                }
                "receipt-malformed" => self.put(SECURITY_RECEIPT_PATH, b"{bad", 0o600),
                "dropin-malformed" => self.put(MODE1_DROPIN_PATH, b"[broken", 0o600),
                "journal-replaced" => self.put(SECURITY_JOURNAL_PATH, b"{replaced", 0o600),
                "guard-replaced" => self.put(
                    SECURITY_TRANSACTION_GUARD_PATH,
                    b"txn-ffffffffffffffffffffffffffffffff",
                    0o600,
                ),
                "queued-job" => self.socket.has_queued_job = true,
                "repopulate" => self.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600),
                "quarantine-swap" => {
                    let path = self
                        .files
                        .keys()
                        .find(|path| path.ends_with(".quarantine"))
                        .cloned()
                        .unwrap();
                    self.put(&path, b"swapped", 0o600);
                }
                "manifest-replaced" => {
                    let path = self
                        .files
                        .keys()
                        .find(|path| {
                            path.starts_with(SECURITY_UNADOPTED_DIRECTORY)
                                && path.ends_with(".json")
                        })
                        .cloned()
                        .unwrap();
                    self.put(&path, b"{\"replacement\":true}\n", 0o600);
                }
                "adopt-config" => {
                    let mut config = HowyConfig::secure_bootstrap_template();
                    config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
                    config.security.key_epoch = 1;
                    config.security.cached.credential_name = MODE1_CREDENTIAL_NAME.into();
                    let bytes = toml::to_string_pretty(&config).unwrap();
                    self.put(howy_common::paths::CONFIG_FILE, bytes.as_bytes(), 0o600);
                }
                _ => unreachable!(),
            }
        }
        if self.crash_at == Some(self.boundary_count) || self.crash_name == Some(name) {
            Err(SecurityError::InjectedCrash(format!(
                "injected crash at {name}"
            )))
        } else {
            Ok(())
        }
    }
}

fn journal_contains_atomic_plan(bytes: &[u8], plan: &AtomicWritePlanV1) -> bool {
    if let Ok(journal) = ProvisioningJournalV1::parse(bytes) {
        return journal
            .atomic_writes
            .iter()
            .any(|record| record.plan == *plan);
    }
    if let Ok(journal) = PlaintextProvisioningJournalV1::parse(bytes) {
        return journal
            .atomic_writes
            .iter()
            .any(|record| record.plan == *plan);
    }
    if let Ok(journal) = SupervisorJournalV1::parse(bytes) {
        return journal
            .atomic_writes
            .iter()
            .any(|record| record.plan == *plan);
    }
    false
}

fn unit(kind: UnitKind, active: bool) -> UnitObservation {
    UnitObservation {
        unit_kind: kind,
        load_state: UnitLoadState::Loaded,
        active_state: if active {
            UnitActiveState::Active
        } else {
            UnitActiveState::Inactive
        },
        sub_state: match (kind, active) {
            (UnitKind::Service, true) => UnitSubState::Running,
            (UnitKind::Socket, true) => UnitSubState::Listening,
            (_, false) => UnitSubState::Dead,
        },
        unit_file_state: UnitFileState::Enabled,
        has_queued_job: false,
    }
}

fn metadata(length: usize, permissions: u32) -> FileMetadataSnapshotV1 {
    FileMetadataSnapshotV1 {
        schema_version: 1,
        object_type: FileObjectType::RegularFile,
        uid: 0,
        gid: 0,
        permissions,
        link_count: 1,
        link_policy: FileLinkPolicy::ExactlyOne,
        byte_length: length as u64,
        restorable_timestamps: RestorableFileTimestampsV1 {
            access: FileTimestampV1 {
                seconds: 1_700_000_001,
                nanoseconds: 0,
            },
            modification: FileTimestampV1 {
                seconds: 1_700_000_002,
                nanoseconds: 0,
            },
        },
    }
}

fn effective_metadata(length: usize, permissions: u32) -> EffectiveFileMetadataV1 {
    EffectiveFileMetadataV1 {
        object_type: FileObjectType::RegularFile,
        uid: 0,
        gid: 0,
        permissions,
        link_count: 1,
        byte_length: length as u64,
    }
}

fn effective_file(path: &str, bytes: &[u8], permissions: u32) -> EffectiveUnitFileV1 {
    EffectiveUnitFileV1 {
        path: path.into(),
        sha256: Sha256Digest::from_bytes(bytes),
        metadata: effective_metadata(bytes.len(), permissions),
    }
}

fn fake_daemon_identity() -> DaemonVerifierIdentityV1 {
    DaemonVerifierIdentityV1 {
        version: env!("CARGO_PKG_VERSION").into(),
        build_identity: "howy-test-build".into(),
        binary_absolute_path: "/usr/bin/howyd".into(),
        binary_sha256: Sha256Digest::from_bytes(b"fake-howyd"),
    }
}

fn base_effective_units() -> EffectiveUnitSetV1 {
    let service_bytes = b"[Service]\nExecStart=/usr/bin/howyd\n";
    let socket_bytes = b"[Socket]\nListenStream=/run/howy/howy.sock\n";
    EffectiveUnitSetV1 {
        service: EffectiveUnitObservationV1 {
            unit_kind: UnitKind::Service,
            fragment: effective_file(BASE_SERVICE_UNIT_PATH, service_bytes, 0o644),
            dropins: Vec::new(),
            conditions: required_unit_conditions().into(),
            load_credential_encrypted: vec![EffectiveCredentialLoadV1 {
                name: MODE1_CREDENTIAL_NAME.into(),
                source: String::new(),
            }],
            set_credential: Vec::new(),
            exec_start: vec![vec!["/usr/bin/howyd".into()]],
            hardening: required_service_hardening(),
        },
        socket: EffectiveUnitObservationV1 {
            unit_kind: UnitKind::Socket,
            fragment: effective_file(BASE_SOCKET_UNIT_PATH, socket_bytes, 0o644),
            dropins: Vec::new(),
            conditions: required_unit_conditions().into(),
            load_credential_encrypted: Vec::new(),
            set_credential: Vec::new(),
            exec_start: Vec::new(),
            hardening: BTreeMap::new(),
        },
    }
}

fn effective_units_for_dropin(dropin: Option<&FakeFile>) -> EffectiveUnitSetV1 {
    let mut units = base_effective_units();
    let Some(dropin) = dropin else {
        return units;
    };
    units.service.dropins = vec![effective_file(
        MODE1_DROPIN_PATH,
        &dropin.bytes,
        dropin.metadata.permissions,
    )];
    if dropin.bytes == MODE1_DROPIN_BYTES {
        units.service.load_credential_encrypted = vec![EffectiveCredentialLoadV1 {
            name: MODE1_CREDENTIAL_NAME.into(),
            source: MODE1_CREDENTIAL_PATH.into(),
        }];
        units.service.set_credential = vec![EffectiveSetCredentialV1 {
            name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.into(),
            value: MODE1_CREDENTIAL_PATH.into(),
        }];
    } else if dropin.bytes == MODE0_DROPIN_BYTES {
        units.service.load_credential_encrypted.clear();
        units.service.set_credential.clear();
    }
    units
}

fn base64_encode(bytes: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[(first >> 2) as usize]);
        output.push(TABLE[(((first & 3) << 4) | (second >> 4)) as usize]);
        output.push(if chunk.len() > 1 {
            TABLE[(((second & 15) << 2) | (third >> 6)) as usize]
        } else {
            b'='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(third & 63) as usize]
        } else {
            b'='
        });
    }
    output
}

fn host_envelope_text() -> Vec<u8> {
    let hex = include_str!("../../../howy-common/testdata/systemd-v261/host.hex").trim();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    base64_encode(&bytes)
}

fn provision(runtime: &mut FakeRuntime) -> SecurityResult<SecurityOutcome> {
    SecurityEngine::new(runtime).provision(ProvisionRequest {
        mode: ProvisionMode::CachedAead,
        with_key: KeySelection::Host,
        adopt_existing: false,
        confirmed: true,
    })
}

#[test]
fn mode2_refuses_before_lock_or_any_persistent_side_effect() {
    let mut runtime = FakeRuntime::fresh();
    let result = SecurityEngine::new(&mut runtime).provision(ProvisionRequest {
        mode: ProvisionMode::EphemeralAead,
        with_key: KeySelection::Auto,
        adopt_existing: false,
        confirmed: true,
    });
    assert!(matches!(result, Err(SecurityError::Refused(_))));
    assert_eq!(runtime.events, ["require-root"]);
    assert!(!runtime.locked);
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn fresh_mode1_provisions_exact_disabled_objects_without_secret_records() {
    let mut runtime = FakeRuntime::fresh();
    let outcome = provision(&mut runtime).unwrap();
    assert!(
        outcome
            .messages
            .iter()
            .any(|message| message.contains("disabled"))
    );
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert_eq!(runtime.files[MODE1_DROPIN_PATH].bytes, MODE1_DROPIN_BYTES);
    let config: HowyConfig = toml::from_str(
        std::str::from_utf8(&runtime.files[howy_common::paths::CONFIG_FILE].bytes).unwrap(),
    )
    .unwrap();
    assert!(config.core.disabled);
    assert_eq!(
        config.security.embedding_mode,
        EmbeddingSecurityMode::AeadCached
    );
    assert_eq!(config.security.key_epoch, 1);
    assert_eq!(
        config.presence.mode,
        howy_common::config::PresenceMode::Confirm
    );
    assert_eq!(runtime.receipt().state, ReceiptState::ProvisionedDisabled);
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.service.sub_state, UnitSubState::Dead);
    assert_eq!(runtime.service.unit_file_state, UnitFileState::Enabled);
    assert!(runtime.events.iter().any(|event| event == "daemon-info"));
    assert_eq!(runtime.credential_input_lengths, [32]);
    assert_eq!(runtime.transaction_id_counter, 1);
    assert!(runtime.commands.iter().all(|command| {
        command.clear_environment
            && command
                .arguments
                .iter()
                .all(|argument| !argument.contains("ZZZZZZZZ"))
    }));
    assert!(
        runtime
            .events
            .iter()
            .position(|event| event == "guard:create")
            .unwrap()
            < runtime
                .events
                .iter()
                .position(|event| event == "stop:Socket")
                .unwrap()
    );
    assert!(
        runtime
            .events
            .iter()
            .position(|event| event == "stop:Socket")
            .unwrap()
            < runtime
                .events
                .iter()
                .position(|event| event == "stop:Service")
                .unwrap()
    );
    assert_eq!(runtime.service.unit_file_state, UnitFileState::Enabled);
    assert_eq!(runtime.socket.unit_file_state, UnitFileState::Enabled);
    assert!(runtime.events.iter().all(|event| {
        !event.starts_with("enable:")
            && !event.starts_with("disable:")
            && !event.starts_with("mask:")
            && !event.starts_with("unmask:")
    }));
}

#[test]
fn guarded_snapshot_precedes_stop_and_units_stopped_precedes_directory_creation() {
    let mut runtime = FakeRuntime::fresh();
    runtime.service = unit(UnitKind::Service, true);
    runtime.socket = unit(UnitKind::Socket, true);
    runtime.service.unit_file_state = UnitFileState::Disabled;
    runtime.socket.unit_file_state = UnitFileState::Disabled;
    runtime.status_available = true;

    provision(&mut runtime).unwrap();

    let guarded = runtime
        .events
        .iter()
        .position(|event| event == "supervisor-phase:Guarded")
        .unwrap();
    let socket_stop = runtime
        .events
        .iter()
        .position(|event| event == "stop:Socket")
        .unwrap();
    let service_stop = runtime
        .events
        .iter()
        .position(|event| event == "stop:Service")
        .unwrap();
    let stopped = runtime
        .events
        .iter()
        .position(|event| event == "supervisor-phase:UnitsStopped")
        .unwrap();
    let socket_settled = runtime
        .events
        .iter()
        .position(|event| event == "boundary:socket-settled-inactive")
        .unwrap();
    let service_settled = runtime
        .events
        .iter()
        .position(|event| event == "boundary:service-settled-inactive")
        .unwrap();
    let directories = runtime
        .events
        .iter()
        .position(|event| event.starts_with("directory:ensure:"))
        .unwrap();
    assert!(guarded < socket_stop && socket_stop < service_stop);
    assert!(service_stop < socket_settled && socket_settled < service_settled);
    assert!(service_settled < stopped && stopped < directories);
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.service.sub_state, UnitSubState::Dead);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Active);
    assert_eq!(runtime.socket.sub_state, UnitSubState::Listening);
    assert_eq!(runtime.service.unit_file_state, UnitFileState::Disabled);
    assert_eq!(runtime.socket.unit_file_state, UnitFileState::Disabled);
}

#[test]
fn abrupt_recovery_from_every_pre_stopped_boundary_guards_stops_and_restores_snapshot() {
    for boundary in [
        "supervisor-prepared",
        "guard-created",
        "supervisor-guarded-snapshot",
        "socket-stopped",
        "service-stopped",
        "socket-settled-inactive",
        "service-settled-inactive",
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.service = unit(UnitKind::Service, true);
        runtime.socket = unit(UnitKind::Socket, true);
        runtime.status_available = true;
        runtime.crash_name = Some(boundary);
        assert!(provision(&mut runtime).is_err(), "boundary {boundary}");
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        let journal = &runtime.files[SECURITY_JOURNAL_PATH].bytes;
        if SupervisorJournalV1::parse(journal)
            .is_ok_and(|journal| journal.phase == SupervisorPhaseV1::UnitsStopped)
        {
            assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
            assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        }

        runtime.crash_name = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert_eq!(runtime.service.active_state, UnitActiveState::Active);
        assert_eq!(runtime.service.sub_state, UnitSubState::Running);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Active);
        assert_eq!(runtime.socket.sub_state, UnitSubState::Listening);
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    }
}

#[test]
fn fresh_directory_metadata_is_exact_and_rollback_removes_only_created_empty_paths() {
    let mut success = FakeRuntime::fresh();
    provision(&mut success).unwrap();
    for (path, permissions) in howy_common::provisioning::REQUIRED_SECURITY_DIRECTORIES {
        assert_eq!(success.directories[path].1, permissions);
    }
    assert_eq!(
        success.files[howy_common::paths::CONFIG_FILE]
            .metadata
            .permissions,
        0o600
    );

    let mut rollback = FakeRuntime::fresh();
    rollback.put(howy_common::paths::CONFIG_FILE, b"invalid = [", 0o600);
    assert!(
        SecurityEngine::new(&mut rollback)
            .provision(ProvisionRequest {
                mode: ProvisionMode::Plaintext,
                with_key: KeySelection::Auto,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    rollback.remove(howy_common::paths::CONFIG_FILE);
    SecurityEngine::new(&mut rollback).recover().unwrap();
    assert!(rollback.directories.is_empty());

    let mut preserve = FakeRuntime::fresh();
    preserve.next_inode += 1;
    preserve.directories.insert(
        howy_common::provisioning::HOWY_CONFIG_DIRECTORY.into(),
        (preserve.next_inode, 0o700),
    );
    preserve.put(howy_common::paths::CONFIG_FILE, b"user-data", 0o600);
    assert!(
        SecurityEngine::new(&mut preserve)
            .provision(ProvisionRequest {
                mode: ProvisionMode::Plaintext,
                with_key: KeySelection::Auto,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    assert!(
        preserve
            .directories
            .contains_key(howy_common::provisioning::HOWY_CONFIG_DIRECTORY)
    );
    assert_eq!(
        preserve.files[howy_common::paths::CONFIG_FILE].bytes,
        b"user-data"
    );
}

#[test]
fn crash_after_mkdir_before_observation_recovers_from_durable_absence_intent() {
    let mut runtime = FakeRuntime::fresh();
    runtime.crash_name = Some("directory-created-before-observation");
    assert!(provision(&mut runtime).is_err());

    let journal = SupervisorJournalV1::parse(&runtime.files[SECURITY_JOURNAL_PATH].bytes).unwrap();
    assert_eq!(journal.phase, SupervisorPhaseV1::UnitsStopped);
    assert_eq!(journal.security_directories.len(), 1);
    let intent = &journal.security_directories[0];
    assert!(!intent.preexisted);
    assert!(intent.expected_directory.is_none());
    assert!(intent.observed_directory.is_none());
    assert!(runtime.directories.contains_key(&intent.path));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));

    runtime.crash_name = None;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    assert!(runtime.directories.is_empty());
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn recovery_rejects_required_directory_identity_or_policy_changes() {
    for mutation in ["inode", "mode"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.crash_name = Some("credential-ready");
        assert!(provision(&mut runtime).is_err());
        runtime.crash_name = None;
        let directory = runtime
            .directories
            .get_mut(howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY)
            .unwrap();
        match mutation {
            "inode" => directory.0 += 1,
            "mode" => directory.1 = 0o755,
            _ => unreachable!(),
        }
        assert!(SecurityEngine::new(&mut runtime).recover().is_err());
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }
}

#[test]
fn provision_then_enable_reruns_readiness_patches_one_token_and_validates_status() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    let disabled = runtime.files[howy_common::paths::CONFIG_FILE].bytes.clone();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();
    let invocation_before = runtime.invocation_counter;
    SecurityEngine::new(&mut runtime).enable().unwrap();
    let enabled = &runtime.files[howy_common::paths::CONFIG_FILE].bytes;
    assert_eq!(enabled.len(), disabled.len() + 1);
    let config: HowyConfig = toml::from_str(std::str::from_utf8(enabled).unwrap()).unwrap();
    assert!(!config.core.disabled);
    assert_eq!(runtime.receipt().state, ReceiptState::Enabled);
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        readiness_before + 1
    );
    assert!(runtime.service.active_state == UnitActiveState::Active);
    assert!(runtime.socket.active_state == UnitActiveState::Active);
    assert!(runtime.invocation_counter > invocation_before);
    let service_start = runtime
        .events
        .iter()
        .rposition(|event| event == "start:Service")
        .unwrap();
    let root_status = runtime
        .events
        .iter()
        .rposition(|event| event == "security-info")
        .unwrap();
    let public_status = runtime
        .events
        .iter()
        .rposition(|event| event == "daemon-info")
        .unwrap();
    assert!(service_start < root_status && root_status < public_status);
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
}

#[test]
fn activation_rejects_every_malformed_or_mismatched_public_status() {
    let mut prepared = FakeRuntime::fresh();
    provision(&mut prepared).unwrap();
    for mutation in ["mode", "prompt", "ready", "malformed"] {
        let mut runtime = prepared.clone();
        runtime.public_status_mutation = Some(mutation);
        assert!(matches!(
            SecurityEngine::new(&mut runtime).enable(),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
    }

    let mut mode0 = FakeRuntime::fresh();
    mode0.public_status_mutation = Some("prompt");
    assert!(matches!(
        SecurityEngine::new(&mut mode0).provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        }),
        Err(SecurityError::Uncertain(_))
    ));
}

#[test]
fn disabled_reprovision_is_idempotent_strong_reverification_without_replacement() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    let config = runtime.files[howy_common::paths::CONFIG_FILE].clone();
    let artifact = runtime.files[MODE1_CREDENTIAL_PATH].clone();
    let receipt = runtime.files[SECURITY_RECEIPT_PATH].clone();
    let creds_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-creds")
        .count();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();

    let outcome = provision(&mut runtime).unwrap();
    assert!(outcome.messages[0].contains("reverified"));
    assert_eq!(
        runtime.files[howy_common::paths::CONFIG_FILE].bytes,
        config.bytes
    );
    assert_eq!(runtime.files[MODE1_CREDENTIAL_PATH].bytes, artifact.bytes);
    assert_eq!(runtime.files[SECURITY_RECEIPT_PATH].bytes, receipt.bytes);
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-creds")
            .count(),
        creds_before
    );
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        readiness_before + 2
    );
}

#[test]
fn final_disabled_namespace_mismatch_reguards_stops_and_retains_recovery() {
    let mut runtime = FakeRuntime::fresh();
    runtime.mutate_on_readiness_call = Some((2, "namespace"));

    assert!(matches!(
        provision(&mut runtime),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
    let journal =
        ProvisioningJournalV1::parse(&runtime.files[SECURITY_JOURNAL_PATH].bytes).unwrap();
    assert_eq!(journal.phase, JournalPhase::DisabledUnitsStarted);
}

#[test]
fn readiness_failure_rolls_back_and_retains_descriptor_bound_unadopted_artifact() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness timeout"));
    let error = provision(&mut runtime).unwrap_err().to_string();
    assert!(error.contains("uncertain security state"));
    assert!(runtime.transient_killed);
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
    runtime.readiness_error = None;
    let outcome = SecurityEngine::new(&mut runtime).recover().unwrap();
    assert!(outcome.cleanup_command.is_some());
    let manifest_path =
        format!("{SECURITY_UNADOPTED_DIRECTORY}/txn-0123456789abcdef0123456789abcdef.json");
    let manifest = UnadoptedArtifactV1::parse(&runtime.files[&manifest_path].bytes).unwrap();
    assert_eq!(
        manifest.identity.descriptor.inode,
        runtime.files[MODE1_CREDENTIAL_PATH].inode
    );
}

#[test]
fn cleanup_revalidates_manifest_descriptor_and_never_uses_raw_rm() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
    assert!(provision(&mut runtime).is_err());
    runtime.readiness_error = None;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    let artifact_hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    let outcome = SecurityEngine::new(&mut runtime)
        .cleanup_unadopted(CleanupRequest {
            transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
            artifact_sha256: artifact_hash,
        })
        .unwrap();
    assert!(outcome.cleanup_command.is_none());
    assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(
        runtime
            .events
            .iter()
            .any(|event| event == "artifact:quarantine")
    );
    assert!(runtime.events.iter().all(|event| !event.contains("rm ")));
}

#[test]
fn cleanup_refuses_path_replacement_between_admission_and_unlink() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
    assert!(provision(&mut runtime).is_err());
    runtime.readiness_error = None;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    runtime.artifact_read_count = 0;
    runtime.swap_artifact_on_read = Some(2);
    let result = SecurityEngine::new(&mut runtime).cleanup_unadopted(CleanupRequest {
        transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
        artifact_sha256: hash,
    });
    assert!(result.is_err());
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn explicit_mode0_is_transactional_keyless_and_preserves_encrypted_artifact() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600);
    runtime.put(MODE1_DROPIN_PATH, MODE1_DROPIN_BYTES, 0o600);
    let artifact_before = runtime.files[MODE1_CREDENTIAL_PATH].bytes.clone();
    let outcome = SecurityEngine::new(&mut runtime)
        .provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        })
        .unwrap();
    assert!(outcome.messages[0].contains("plaintext"));
    assert_eq!(runtime.files[MODE1_CREDENTIAL_PATH].bytes, artifact_before);
    assert_eq!(runtime.files[MODE1_DROPIN_PATH].bytes, MODE0_DROPIN_BYTES);
    let config: HowyConfig = toml::from_str(
        std::str::from_utf8(&runtime.files[howy_common::paths::CONFIG_FILE].bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(
        config.security.embedding_mode,
        EmbeddingSecurityMode::Plaintext
    );
    assert!(!config.core.disabled);
    assert!(runtime.commands.is_empty());
}

#[test]
fn explicit_mode0_refuses_unsafe_config_metadata_before_journaling() {
    let mut runtime = FakeRuntime::fresh();
    let config = toml::to_string_pretty(&HowyConfig::legacy_defaults()).unwrap();
    runtime.put(howy_common::paths::CONFIG_FILE, config.as_bytes(), 0o644);

    let result = SecurityEngine::new(&mut runtime).provision(ProvisionRequest {
        mode: ProvisionMode::Plaintext,
        with_key: KeySelection::Auto,
        adopt_existing: false,
        confirmed: true,
    });

    assert!(result.is_err());
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
}

#[test]
fn unsafe_oversized_and_malformed_snapshots_have_no_guard_or_unit_side_effects() {
    let valid_config = toml::to_string_pretty(&HowyConfig::legacy_defaults()).unwrap();
    for (label, configure) in [
        (
            "unsafe-config",
            Box::new(move |runtime: &mut FakeRuntime| {
                runtime.put(
                    howy_common::paths::CONFIG_FILE,
                    valid_config.as_bytes(),
                    0o644,
                );
            }) as Box<dyn Fn(&mut FakeRuntime)>,
        ),
        (
            "oversized-config",
            Box::new(|runtime: &mut FakeRuntime| {
                runtime.put(
                    howy_common::paths::CONFIG_FILE,
                    &vec![b' '; MAX_CONFIG_BYTES + 1],
                    0o600,
                );
            }),
        ),
        (
            "malformed-config",
            Box::new(|runtime: &mut FakeRuntime| {
                runtime.put(howy_common::paths::CONFIG_FILE, b"not = [toml", 0o600);
            }),
        ),
        (
            "malformed-dropin",
            Box::new(|runtime: &mut FakeRuntime| {
                runtime.put(MODE1_DROPIN_PATH, b"[Service]\nUser=nobody\n", 0o600);
            }),
        ),
        (
            "malformed-receipt",
            Box::new(|runtime: &mut FakeRuntime| {
                runtime.put(SECURITY_RECEIPT_PATH, b"{malformed", 0o600);
            }),
        ),
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.service = unit(UnitKind::Service, true);
        runtime.socket = unit(UnitKind::Socket, true);
        runtime.status_available = true;
        configure(&mut runtime);
        assert!(provision(&mut runtime).is_err(), "{label}");
        assert!(
            !runtime.files.contains_key(SECURITY_JOURNAL_PATH),
            "{label}"
        );
        assert!(
            !runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH),
            "{label}"
        );
        assert_eq!(
            runtime.service.active_state,
            UnitActiveState::Active,
            "{label}"
        );
        assert_eq!(
            runtime.socket.active_state,
            UnitActiveState::Active,
            "{label}"
        );
        assert!(
            runtime
                .events
                .iter()
                .all(|event| !event.starts_with("stop:")),
            "{label}"
        );
    }
}

#[test]
fn active_prior_service_requires_root_invocation_before_journal_or_guard() {
    let mut runtime = FakeRuntime::fresh();
    runtime.service = unit(UnitKind::Service, true);
    runtime.socket = unit(UnitKind::Socket, true);
    runtime.status_available = false;

    assert!(provision(&mut runtime).is_err());
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Active);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Active);
}

fn assert_invalid_invocation_journal_is_retained_before_data_mutation(
    runtime: &mut FakeRuntime,
    bytes: Vec<u8>,
) {
    runtime.put(SECURITY_JOURNAL_PATH, &bytes, 0o600);
    let before = [
        howy_common::paths::CONFIG_FILE,
        MODE1_DROPIN_PATH,
        SECURITY_RECEIPT_PATH,
        MODE1_CREDENTIAL_PATH,
    ]
    .into_iter()
    .map(|path| (path, runtime.files.get(path).map(|file| file.bytes.clone())))
    .collect::<Vec<_>>();
    assert!(SecurityEngine::new(runtime).recover().is_err());
    assert_eq!(runtime.files[SECURITY_JOURNAL_PATH].bytes, bytes);
    for (path, expected) in before {
        assert_eq!(
            runtime.files.get(path).map(|file| file.bytes.clone()),
            expected,
            "recovery mutated {path} before rejecting invocation presence"
        );
    }
}

#[test]
fn recovery_rejects_invocation_presence_mismatches_for_every_journal_schema() {
    let mut supervisor_runtime = FakeRuntime::fresh();
    supervisor_runtime.crash_name = Some("supervisor-prepared");
    assert!(provision(&mut supervisor_runtime).is_err());
    supervisor_runtime.crash_name = None;
    let mut supervisor =
        SupervisorJournalV1::parse(&supervisor_runtime.files[SECURITY_JOURNAL_PATH].bytes).unwrap();
    supervisor.service_unit_state.as_mut().unwrap().active_state = UnitActiveState::Active;
    supervisor.service_unit_state.as_mut().unwrap().sub_state = UnitSubState::Running;
    supervisor.prior_daemon_invocation_id = None;
    assert_invalid_invocation_journal_is_retained_before_data_mutation(
        &mut supervisor_runtime,
        serde_json::to_vec(&supervisor).unwrap(),
    );

    let mut mode1_runtime = FakeRuntime::fresh();
    mode1_runtime.crash_name = Some("mode1-planned");
    assert!(provision(&mut mode1_runtime).is_err());
    mode1_runtime.crash_name = None;
    let mut mode1 =
        ProvisioningJournalV1::parse(&mode1_runtime.files[SECURITY_JOURNAL_PATH].bytes).unwrap();
    mode1.prior_daemon_invocation_id = Some("ab".repeat(32));
    assert_invalid_invocation_journal_is_retained_before_data_mutation(
        &mut mode1_runtime,
        serde_json::to_vec(&mode1).unwrap(),
    );

    let mut mode0_runtime = FakeRuntime::fresh();
    mode0_runtime.crash_name = Some("atomic-plan-synced");
    assert!(
        SecurityEngine::new(&mut mode0_runtime)
            .provision(ProvisionRequest {
                mode: ProvisionMode::Plaintext,
                with_key: KeySelection::Auto,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    mode0_runtime.crash_name = None;
    let mut mode0 =
        PlaintextProvisioningJournalV1::parse(&mode0_runtime.files[SECURITY_JOURNAL_PATH].bytes)
            .unwrap();
    mode0.service_unit_state.active_state = UnitActiveState::Active;
    mode0.service_unit_state.sub_state = UnitSubState::Running;
    mode0.prior_daemon_invocation_id = None;
    assert_invalid_invocation_journal_is_retained_before_data_mutation(
        &mut mode0_runtime,
        serde_json::to_vec(&mode0).unwrap(),
    );
}

#[test]
fn nonempty_namespace_without_artifact_refuses_before_rng_or_journal() {
    let mut runtime = FakeRuntime::fresh();
    runtime.namespace_nonempty = true;
    let result = provision(&mut runtime);
    assert!(matches!(result, Err(SecurityError::Uncertain(_))));
    assert!(!runtime.events.iter().any(|event| event == "rng-mlock"));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
}

#[test]
fn existing_artifact_requires_explicit_adoption() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600);
    let result = provision(&mut runtime);
    assert!(matches!(result, Err(SecurityError::Uncertain(_))));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));

    SecurityEngine::new(&mut runtime).recover().unwrap();

    let result = SecurityEngine::new(&mut runtime).provision(ProvisionRequest {
        mode: ProvisionMode::CachedAead,
        with_key: KeySelection::Host,
        adopt_existing: true,
        confirmed: true,
    });
    assert!(result.is_ok());
    assert!(!runtime.events.iter().any(|event| event == "systemd-creds"));
}

#[test]
fn different_mode_artifact_never_bypasses_explicit_adoption_and_readiness() {
    let mut runtime = FakeRuntime::fresh();
    let mode0 = toml::to_string_pretty(&HowyConfig::legacy_defaults()).unwrap();
    runtime.put(howy_common::paths::CONFIG_FILE, mode0.as_bytes(), 0o600);
    runtime.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600);

    assert!(provision(&mut runtime).is_err());
    assert!(!runtime.events.iter().any(|event| event == "systemd-run"));
    SecurityEngine::new(&mut runtime).recover().unwrap();

    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();
    SecurityEngine::new(&mut runtime)
        .provision(ProvisionRequest {
            mode: ProvisionMode::CachedAead,
            with_key: KeySelection::Host,
            adopt_existing: true,
            confirmed: true,
        })
        .unwrap();
    assert!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count()
            > readiness_before
    );
}

#[test]
fn different_mode_receipt_alone_is_not_live_binding_or_implicit_adoption() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    let mode0 = toml::to_string_pretty(&HowyConfig::legacy_defaults()).unwrap();
    runtime.put(howy_common::paths::CONFIG_FILE, mode0.as_bytes(), 0o600);
    let receipt_before = runtime.files[SECURITY_RECEIPT_PATH].bytes.clone();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();

    assert!(provision(&mut runtime).is_err());
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        readiness_before
    );
    SecurityEngine::new(&mut runtime).recover().unwrap();
    assert_eq!(runtime.files[SECURITY_RECEIPT_PATH].bytes, receipt_before);

    SecurityEngine::new(&mut runtime)
        .provision(ProvisionRequest {
            mode: ProvisionMode::CachedAead,
            with_key: KeySelection::Host,
            adopt_existing: true,
            confirmed: true,
        })
        .unwrap();
    assert!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count()
            > readiness_before
    );
}

#[test]
fn rng_mlock_and_pipe_failures_have_no_durable_transaction() {
    for configure in [
        |runtime: &mut FakeRuntime| runtime.rng_error = true,
        |runtime: &mut FakeRuntime| {
            runtime.encrypt_error = Some(SecurityError::operation("EPIPE or child timeout"))
        },
    ] {
        let mut runtime = FakeRuntime::fresh();
        configure(&mut runtime);
        assert!(provision(&mut runtime).is_err());
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    }
}

#[test]
fn engine_persists_every_atomic_name_before_creation_and_cleans_terminal_backups() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    assert!(
        runtime
            .events
            .iter()
            .any(|event| event.starts_with("atomic-create:"))
    );
    assert_no_atomic_stages(&runtime);
}

#[test]
fn every_injected_boundary_crash_is_recoverable_or_prejournal() {
    let mut baseline = FakeRuntime::fresh();
    provision(&mut baseline).unwrap();
    let boundaries = baseline.boundary_count;
    assert!(boundaries >= 12);
    for crash_at in 1..=boundaries {
        let mut runtime = FakeRuntime::fresh();
        runtime.crash_at = Some(crash_at);
        let result = provision(&mut runtime);
        assert!(result.is_err());
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
        runtime.crash_at = None;
        let recovery = SecurityEngine::new(&mut runtime).recover();
        if let Ok(outcome) = recovery {
            assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
            assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
            let manifest_path =
                format!("{SECURITY_UNADOPTED_DIRECTORY}/txn-0123456789abcdef0123456789abcdef.json");
            if runtime.files.contains_key(&manifest_path) {
                assert!(outcome.cleanup_command.is_some());
            }
            assert_no_atomic_stages(&runtime);
        } else {
            assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
            assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        }
    }
}

#[test]
fn every_enable_boundary_crash_recovers_to_exact_disabled_or_enabled_state() {
    let mut prepared = FakeRuntime::fresh();
    provision(&mut prepared).unwrap();
    prepared.events.clear();
    prepared.boundary_count = 0;
    let mut baseline = prepared.clone();
    SecurityEngine::new(&mut baseline).enable().unwrap();
    let boundaries = baseline.boundary_count;
    assert!(boundaries >= 10);

    for crash_at in 1..=boundaries {
        let mut runtime = prepared.clone();
        runtime.crash_at = Some(crash_at);
        let result = SecurityEngine::new(&mut runtime).enable();
        assert!(result.is_err());
        runtime.crash_at = None;
        if SecurityEngine::new(&mut runtime).recover().is_ok() {
            assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
            assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
            let config: HowyConfig = toml::from_str(
                std::str::from_utf8(&runtime.files[howy_common::paths::CONFIG_FILE].bytes).unwrap(),
            )
            .unwrap();
            let receipt = runtime.receipt();
            assert!(
                (config.core.disabled && receipt.state == ReceiptState::ProvisionedDisabled)
                    || (!config.core.disabled && receipt.state == ReceiptState::Enabled)
            );
            assert_no_atomic_stages(&runtime);
        } else {
            assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        }
    }
}

fn assert_no_atomic_stages(runtime: &FakeRuntime) {
    assert!(runtime.files.keys().all(|path| {
        !path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(".howy-txn-") && name.ends_with(".stage"))
    }));
}

#[test]
fn every_mode0_boundary_crash_recovers_without_deleting_encrypted_data() {
    let mut prepared = FakeRuntime::fresh();
    prepared.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600);
    prepared.put(MODE1_DROPIN_PATH, MODE1_DROPIN_BYTES, 0o600);
    let mut baseline = prepared.clone();
    SecurityEngine::new(&mut baseline)
        .provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        })
        .unwrap();
    let boundaries = baseline.boundary_count;
    assert!(boundaries >= 6);
    for crash_at in 1..=boundaries {
        let mut runtime = prepared.clone();
        runtime.crash_at = Some(crash_at);
        let result = SecurityEngine::new(&mut runtime).provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        });
        assert!(result.is_err());
        runtime.crash_at = None;
        let _ = SecurityEngine::new(&mut runtime).recover();
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    }
}

#[test]
fn cleanup_refuses_active_units_and_queued_jobs() {
    for configure in [
        |runtime: &mut FakeRuntime| runtime.service = unit(UnitKind::Service, true),
        |runtime: &mut FakeRuntime| runtime.socket.has_queued_job = true,
        |runtime: &mut FakeRuntime| runtime.transient_exists = true,
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.events.clear();
        configure(&mut runtime);
        let result = SecurityEngine::new(&mut runtime).cleanup_unadopted(CleanupRequest {
            transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
            artifact_sha256: hash,
        });
        assert!(result.is_err());
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(runtime.events.iter().all(|event| {
            event != "guard:create"
                && event != "journal:sync"
                && event != "transient:stop-kill"
                && !event.starts_with("stop:")
        }));
    }
}

#[test]
fn cleanup_race_after_pre_admission_is_guarded_stopped_and_non_destructive() {
    for mutation in ["active", "reference"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.events.clear();
        runtime.cleanup_pre_guard_mutation = Some(mutation);

        assert!(matches!(
            SecurityEngine::new(&mut runtime).cleanup_unadopted(CleanupRequest {
                transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                artifact_sha256: hash,
            }),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
        assert!(
            !runtime
                .events
                .iter()
                .any(|event| event == "artifact:quarantine")
        );
        let journal = SupervisorJournalV1::parse(&runtime.files[SECURITY_JOURNAL_PATH].bytes)
            .expect("guarded cleanup journal");
        let pre_admission = journal
            .cleanup_pre_admission
            .expect("cleanup pre-admission snapshot");
        assert_eq!(
            pre_admission.service.active_state,
            UnitActiveState::Inactive
        );
        assert!(!pre_admission.service.has_queued_job);
        assert!(!pre_admission.readiness_transient_exists);
        assert!(!pre_admission.daemon_responded);
        assert_eq!(pre_admission.references, Default::default());
    }
}

#[test]
fn activation_and_restore_failures_always_reguard_stop_and_retain_the_journal() {
    let mut prepared = FakeRuntime::fresh();
    provision(&mut prepared).unwrap();
    for point in [
        "guard-remove",
        "socket-start",
        "service-start",
        "status",
        "receipt-write",
    ] {
        let mut runtime = prepared.clone();
        runtime.fail_after = Some(point);
        assert!(matches!(
            SecurityEngine::new(&mut runtime).enable(),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
        let journal = ProvisioningJournalV1::parse(&runtime.files[SECURITY_JOURNAL_PATH].bytes)
            .expect("fail-closed activation journal");
        let live_guard = runtime.files[SECURITY_TRANSACTION_GUARD_PATH]
            .observed()
            .atomic_identity();
        assert_eq!(
            journal.guard.as_ref().map(|guard| &guard.file),
            Some(&live_guard)
        );
        let removed = runtime
            .events
            .iter()
            .rposition(|event| event == "guard:remove")
            .unwrap();
        let recreated = runtime.events[removed + 1..]
            .iter()
            .position(|event| event == "guard:create")
            .map(|offset| removed + 1 + offset)
            .unwrap();
        let transitioned = runtime.events[recreated + 1..]
            .iter()
            .position(|event| event == "journal:sync")
            .map(|offset| recreated + 1 + offset)
            .unwrap();
        let stopped = runtime.events[recreated + 1..]
            .iter()
            .position(|event| event.starts_with("stop:"))
            .map(|offset| recreated + 1 + offset)
            .unwrap();
        assert!(transitioned < stopped, "point {point}");
        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }

    let mut restoring = FakeRuntime::fresh();
    restoring.service = unit(UnitKind::Service, true);
    restoring.socket = unit(UnitKind::Socket, true);
    restoring.status_available = true;
    restoring.fail_after = Some("socket-start");
    assert!(matches!(
        provision(&mut restoring),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(
        restoring
            .files
            .contains_key(SECURITY_TRANSACTION_GUARD_PATH)
    );
    assert!(restoring.files.contains_key(SECURITY_JOURNAL_PATH));
    assert_eq!(restoring.service.active_state, UnitActiveState::Inactive);
    assert_eq!(restoring.socket.active_state, UnitActiveState::Inactive);

    let mut mode0 = FakeRuntime::fresh();
    mode0.fail_after = Some("status");
    assert!(matches!(
        SecurityEngine::new(&mut mode0).provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        }),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(mode0.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(mode0.files.contains_key(SECURITY_JOURNAL_PATH));
    assert_eq!(mode0.service.active_state, UnitActiveState::Inactive);
    assert_eq!(mode0.socket.active_state, UnitActiveState::Inactive);
}

#[test]
fn terminal_unit_restore_journals_recover_idempotently_before_removal() {
    let mut mode1 = FakeRuntime::fresh();
    mode1.service = unit(UnitKind::Service, true);
    mode1.socket = unit(UnitKind::Socket, true);
    mode1.status_available = true;
    mode1.fail_after = Some("disabled-units-restored");
    assert!(matches!(
        provision(&mut mode1),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(mode1.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(mode1.files.contains_key(SECURITY_JOURNAL_PATH));
    let journal = ProvisioningJournalV1::parse(&mode1.files[SECURITY_JOURNAL_PATH].bytes).unwrap();
    assert_eq!(
        journal.post_provision_service_target.rollback_target(),
        Some(StableRollbackTarget::InactiveDead)
    );
    assert_eq!(
        journal.post_provision_service_target.unit_file_state,
        UnitFileState::Enabled
    );
    assert_eq!(
        journal.post_provision_socket_target.rollback_target(),
        Some(StableRollbackTarget::ActiveListening)
    );
    SecurityEngine::new(&mut mode1).recover().unwrap();
    assert_eq!(mode1.service.active_state, UnitActiveState::Inactive);
    assert_eq!(mode1.socket.active_state, UnitActiveState::Active);
    assert!(!mode1.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(!mode1.files.contains_key(SECURITY_JOURNAL_PATH));

    let mut mode0 = FakeRuntime::fresh();
    mode0.fail_after = Some("plaintext-units-started");
    assert!(matches!(
        SecurityEngine::new(&mut mode0).provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        }),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(mode0.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(mode0.files.contains_key(SECURITY_JOURNAL_PATH));
    SecurityEngine::new(&mut mode0).recover().unwrap();
    assert_eq!(mode0.service.active_state, UnitActiveState::Active);
    assert_eq!(mode0.socket.active_state, UnitActiveState::Active);
    assert!(!mode0.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(!mode0.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn malformed_active_journal_is_never_rewritten_or_started() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(SECURITY_JOURNAL_PATH, b"{malformed", 0o600);
    runtime.service = unit(UnitKind::Service, true);
    runtime.socket = unit(UnitKind::Socket, true);
    runtime.status_available = true;

    assert!(matches!(
        SecurityEngine::new(&mut runtime).recover(),
        Err(SecurityError::Uncertain(_))
    ));
    assert_eq!(runtime.files[SECURITY_JOURNAL_PATH].bytes, b"{malformed");
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
}

#[test]
fn orphan_guard_forces_unit_quiescence_and_manual_recovery() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(
        SECURITY_TRANSACTION_GUARD_PATH,
        b"txn-orphan-0123456789",
        0o600,
    );
    runtime.service = unit(UnitKind::Service, true);
    runtime.socket = unit(UnitKind::Socket, true);
    runtime.status_available = true;

    assert!(matches!(
        SecurityEngine::new(&mut runtime).recover(),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
}

#[test]
fn post_guard_unit_transition_settles_before_any_key_or_credential_work() {
    let mut runtime = FakeRuntime::fresh();
    runtime.service.active_state = UnitActiveState::Activating;
    runtime.service.sub_state = UnitSubState::StartPre;
    runtime.service.has_queued_job = true;
    runtime.settle_units = true;
    provision(&mut runtime).unwrap();

    let guard = runtime
        .events
        .iter()
        .position(|event| event == "guard:create")
        .unwrap();
    let settle = runtime
        .events
        .iter()
        .position(|event| event == "settle")
        .unwrap();
    let key = runtime
        .events
        .iter()
        .position(|event| event == "rng-mlock")
        .unwrap();
    assert!(settle < guard && guard < key);
}

#[test]
fn stale_receipt_never_grants_implicit_adoption_or_skips_strong_verification() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();
    let mut stale = runtime.receipt();
    stale.artifact.sha256 = Sha256Digest::from_bytes(b"stale-artifact");
    runtime.put(
        SECURITY_RECEIPT_PATH,
        &stale.deterministic_bytes().unwrap(),
        0o600,
    );

    assert!(matches!(
        provision(&mut runtime),
        Err(SecurityError::Uncertain(_))
    ));
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        readiness_before
    );
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
}

#[test]
fn enabled_idempotent_path_performs_strong_readiness_effective_and_status_checks() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    SecurityEngine::new(&mut runtime).enable().unwrap();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();
    let credentials_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-creds")
        .count();
    let status_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "security-info")
        .count();
    let mut post_readiness_mutation = runtime.clone();
    post_readiness_mutation.mutate_after_readiness = Some("artifact");

    let outcome = provision(&mut runtime).unwrap();
    assert!(outcome.messages[0].contains("strongly reverified"));
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        readiness_before + 1
    );
    assert_eq!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-creds")
            .count(),
        credentials_before
    );
    assert!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "security-info")
            .count()
            > status_before
    );
    assert_eq!(runtime.service.active_state, UnitActiveState::Active);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Active);

    assert!(matches!(
        provision(&mut post_readiness_mutation),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(
        post_readiness_mutation
            .files
            .contains_key(SECURITY_TRANSACTION_GUARD_PATH)
    );
}

#[test]
fn enabled_idempotent_never_commits_without_public_root_status_and_new_invocation() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    SecurityEngine::new(&mut runtime).enable().unwrap();
    runtime.service = unit(UnitKind::Service, false);
    runtime.socket = unit(UnitKind::Socket, false);
    runtime.status_available = false;

    assert!(matches!(
        provision(&mut runtime),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
}

#[test]
fn active_reverification_and_mode0_reject_an_old_daemon_invocation() {
    let mut enabled = FakeRuntime::fresh();
    provision(&mut enabled).unwrap();
    SecurityEngine::new(&mut enabled).enable().unwrap();

    let mut idempotent = enabled.clone();
    idempotent.preserve_invocation_on_start = true;
    assert!(matches!(
        provision(&mut idempotent),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(idempotent.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(
        idempotent
            .files
            .contains_key(SECURITY_TRANSACTION_GUARD_PATH)
    );

    let mut mode0 = enabled;
    mode0.preserve_invocation_on_start = true;
    assert!(matches!(
        SecurityEngine::new(&mut mode0).provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        }),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(mode0.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(mode0.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
}

#[test]
fn effective_service_or_socket_shadowing_fails_closed_before_commit() {
    for mutation in ["socket-dropin", "socket-guard", "service-exec", "hardening"] {
        let mut runtime = FakeRuntime::fresh();
        let mut shadowed = base_effective_units();
        match mutation {
            "socket-dropin" => shadowed.socket.dropins.push(effective_file(
                "/etc/systemd/system/howy.socket.d/99-shadow.conf",
                b"[Socket]\n",
                0o600,
            )),
            "socket-guard" => {
                shadowed.socket.conditions.remove(0);
            }
            "service-exec" => {
                shadowed.service.exec_start = vec![vec!["/usr/local/bin/howyd".into()]]
            }
            "hardening" => {
                shadowed.service.hardening.remove("NoNewPrivileges");
            }
            _ => unreachable!(),
        }
        runtime.effective_override = Some(shadowed);
        assert!(matches!(
            provision(&mut runtime),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_RECEIPT_PATH));
    }
}

#[test]
fn every_post_readiness_mutation_is_detected_and_namespace_changes_restart_verification() {
    for mutation in ["artifact", "config", "dropin"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.mutate_after_readiness = Some(mutation);
        assert!(matches!(
            provision(&mut runtime),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
    }

    let mut namespace = FakeRuntime::fresh();
    namespace.mutate_after_readiness = Some("namespace");
    assert!(matches!(
        provision(&mut namespace),
        Err(SecurityError::Uncertain(_))
    ));
    assert_eq!(
        namespace
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count(),
        2
    );
    assert!(
        namespace
            .files
            .contains_key(SECURITY_TRANSACTION_GUARD_PATH)
    );
}

#[test]
fn recovery_revalidates_disabled_artifacts_after_rerunning_readiness() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    runtime.crash_name = Some("enabled-config-installed");
    assert!(SecurityEngine::new(&mut runtime).enable().is_err());
    runtime.crash_name = None;
    runtime.mutate_after_readiness = Some("artifact");
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();

    assert!(matches!(
        SecurityEngine::new(&mut runtime).recover(),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(
        runtime
            .events
            .iter()
            .filter(|event| event.as_str() == "systemd-run")
            .count()
            > readiness_before
    );
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn cleanup_requeries_and_refuses_malformed_concurrent_references() {
    for mutation in ["config-malformed", "receipt-malformed", "dropin-malformed"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.cleanup_mutation = Some(mutation);
        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }
}

#[test]
fn cleanup_treats_any_valid_receipt_path_as_reference_regardless_of_hash_or_state() {
    let mut receipted = FakeRuntime::fresh();
    provision(&mut receipted).unwrap();
    let mut unrelated_receipt = receipted.receipt();
    unrelated_receipt.artifact.sha256 = Sha256Digest::from_bytes(b"different-valid-artifact");
    let unrelated_receipt_bytes = unrelated_receipt.deterministic_bytes().unwrap();

    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
    assert!(provision(&mut runtime).is_err());
    runtime.readiness_error = None;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    let artifact_hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    runtime.put(SECURITY_RECEIPT_PATH, &unrelated_receipt_bytes, 0o600);

    assert!(
        SecurityEngine::new(&mut runtime)
            .cleanup_unadopted(CleanupRequest {
                transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                artifact_sha256: artifact_hash,
            })
            .is_err()
    );
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
}

#[test]
fn cleanup_restores_no_replace_but_retains_changed_controls_or_queued_jobs() {
    for mutation in ["journal-replaced", "guard-replaced", "queued-job"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.cleanup_mutation = Some(mutation);

        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }
}

#[test]
fn quarantine_cleanup_handles_concurrent_adoption_repopulation_and_path_swap() {
    for mutation in [
        "adopt-config",
        "repopulate",
        "quarantine-swap",
        "manifest-replaced",
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.cleanup_mutation = Some(mutation);

        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        match mutation {
            "adopt-config" => {
                assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
                assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
            }
            "repopulate" | "quarantine-swap" | "manifest-replaced" => {
                assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
                assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn cleanup_recovery_reconciles_unlink_and_terminal_restore_crash_windows() {
    for failure in [
        "quarantine-unlink-fsynced",
        "quarantine-unlinked",
        "supervisor-restored",
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        if failure == "quarantine-unlinked" {
            runtime.crash_name = Some(failure);
        } else {
            runtime.fail_after = Some(failure);
        }
        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));

        runtime.crash_name = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let manifest =
            format!("{SECURITY_UNADOPTED_DIRECTORY}/txn-0123456789abcdef0123456789abcdef.json");
        assert!(!runtime.files.contains_key(&manifest));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);
    }
}

#[test]
fn cleanup_recovery_reconciles_restore_rename_before_state_sync() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
    assert!(provision(&mut runtime).is_err());
    runtime.readiness_error = None;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    runtime.cleanup_mutation = Some("adopt-config");
    runtime.fail_after = Some("quarantine-restore-fsynced");

    assert!(
        SecurityEngine::new(&mut runtime)
            .cleanup_unadopted(CleanupRequest {
                transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                artifact_sha256: hash,
            })
            .is_err()
    );
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));

    SecurityEngine::new(&mut runtime).recover().unwrap();
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn cleanup_recovery_covers_rename_recheck_and_restore_boundaries() {
    for boundary in ["artifact-quarantined", "cleanup-final-recheck"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.crash_name = Some(boundary);
        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        runtime.crash_name = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }

    for boundary in ["cleanup-restore-requested", "cleanup-quarantine-restored"] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        runtime.cleanup_mutation = Some("adopt-config");
        runtime.crash_name = Some(boundary);
        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
                    artifact_sha256: hash,
                })
                .is_err()
        );
        runtime.crash_name = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    }
}

#[test]
fn mode0_clears_credentials_without_parsing_or_deleting_a_corrupt_mode1_artifact() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(MODE1_CREDENTIAL_PATH, b"not-a-systemd-credential", 0o600);
    let artifact = runtime.files[MODE1_CREDENTIAL_PATH].clone();
    SecurityEngine::new(&mut runtime)
        .provision(ProvisionRequest {
            mode: ProvisionMode::Plaintext,
            with_key: KeySelection::Auto,
            adopt_existing: false,
            confirmed: true,
        })
        .unwrap();
    assert_eq!(runtime.files[MODE1_CREDENTIAL_PATH].bytes, artifact.bytes);
    assert_eq!(runtime.files[MODE1_DROPIN_PATH].bytes, MODE0_DROPIN_BYTES);
    runtime
        .effective_units
        .validate_mode0(&Sha256Digest::from_bytes(MODE0_DROPIN_BYTES))
        .unwrap();
}

#[test]
fn missing_host_secret_refuses_only_after_durable_guard_and_before_rng_or_creds() {
    let mut runtime = FakeRuntime::fresh();
    runtime.host_secret_secure = false;
    assert!(matches!(
        provision(&mut runtime),
        Err(SecurityError::Uncertain(_))
    ));
    let guard = runtime
        .events
        .iter()
        .position(|event| event == "guard:create")
        .unwrap();
    let host = runtime
        .events
        .iter()
        .position(|event| event == "host-secret")
        .unwrap();
    assert!(guard < host);
    assert!(!runtime.events.iter().any(|event| event == "rng-mlock"));
    assert!(!runtime.events.iter().any(|event| event == "systemd-creds"));
    assert!(runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn malformed_readiness_rolls_back_and_masked_units_refuse_without_mutation() {
    let mut malformed = FakeRuntime::fresh();
    malformed.malformed_readiness = true;
    assert!(provision(&mut malformed).is_err());
    assert!(malformed.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(
        malformed
            .files
            .contains_key(SECURITY_TRANSACTION_GUARD_PATH)
    );
    malformed.malformed_readiness = false;
    SecurityEngine::new(&mut malformed).recover().unwrap();
    assert!(
        !malformed
            .files
            .contains_key(howy_common::paths::CONFIG_FILE)
    );

    let mut masked = FakeRuntime::fresh();
    masked.service.unit_file_state = UnitFileState::Masked;
    assert!(provision(&mut masked).is_err());
    assert!(!masked.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(!masked.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    assert!(!masked.events.iter().any(|event| event == "systemd-creds"));
}

#[test]
fn repository_units_have_the_exact_ordered_start_conditions() {
    for unit in [
        include_str!("../../../../systemd/howy.service"),
        include_str!("../../../../systemd/howy.socket"),
    ] {
        let conditions: Vec<_> = unit
            .lines()
            .filter(|line| line.starts_with("ConditionPathExists="))
            .collect();
        assert_eq!(
            conditions,
            [
                "ConditionPathExists=!/var/lib/howy-security-transaction.guard",
                "ConditionPathExists=/var/lib/howy-package-bootstrap.complete",
            ]
        );
    }
}

#[test]
fn journal_files_remain_strictly_bounded_in_fake_crash_state() {
    let mut runtime = FakeRuntime::fresh();
    runtime.crash_at = Some(4);
    assert!(provision(&mut runtime).is_err());
    if let Some(journal) = runtime.files.get(SECURITY_JOURNAL_PATH) {
        assert!(journal.bytes.len() <= MAX_JOURNAL_BYTES);
        assert!(!journal.bytes.windows(32).any(|window| window == [0x5a; 32]));
    }
}
