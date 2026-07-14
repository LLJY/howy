use std::collections::BTreeMap;

use howy_common::config::{EmbeddingSecurityMode, HowyConfig};
use howy_common::protocol::{
    NamespaceDiagnostic, SecurityBackendStateV1, SecurityInfoResult, SecurityPoisonStateV1,
    SecurityReadinessStateV1,
};
use howy_common::provisioning::{
    BASE_SERVICE_UNIT_PATH, FileLinkPolicy, FileMetadataSnapshotV1, FileObjectType,
    FileTimestampV1, MAX_JOURNAL_BYTES, MODE1_CREDENTIAL_PATH, MODE1_DROPIN_PATH,
    MODE1_NAMESPACE_PATH, NamespaceFingerprintV1, ProvisioningReceiptV1, ReadinessResultV1,
    ReceiptState, RestorableFileTimestampsV1, SECURITY_JOURNAL_PATH, SECURITY_RECEIPT_PATH,
    SECURITY_TRANSACTION_GUARD_PATH, SECURITY_UNADOPTED_DIRECTORY, Sha256Digest,
    UnadoptedArtifactV1, UnitActiveState, UnitFileState, UnitKind, UnitLoadState, UnitObservation,
    UnitSubState, VerifierResultV1,
};

use super::command::{CommandSpec, KeySelection};
use super::engine::{
    AtomicWriteMode, CleanupRequest, MODE1_DROPIN_BYTES, ObservedFile, ProvisionMode,
    ProvisionRequest, SecretKeyMaterial, SecurityEngine, SecurityError, SecurityOutcome,
    SecurityResult, SecurityRuntime,
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
    boundary_count: usize,
    crash_at: Option<usize>,
    transient_killed: bool,
    transient_exists: bool,
    status_available: bool,
    invocation_counter: u8,
    artifact_read_count: usize,
    swap_artifact_on_read: Option<usize>,
    monotonic_millis: u64,
}

impl FakeRuntime {
    fn fresh() -> Self {
        let mut runtime = Self {
            files: BTreeMap::new(),
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
            boundary_count: 0,
            crash_at: None,
            transient_killed: false,
            transient_exists: false,
            status_available: false,
            invocation_counter: 1,
            artifact_read_count: 0,
            swap_artifact_on_read: None,
            monotonic_millis: 0,
        };
        runtime.put(
            BASE_SERVICE_UNIT_PATH,
            b"[Service]\nExecStart=/usr/bin/howyd\n",
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
        if !self.status_available
            || self.service.active_state != UnitActiveState::Active
            || self.socket.active_state != UnitActiveState::Active
        {
            return None;
        }
        let config_file = self.files.get(howy_common::paths::CONFIG_FILE)?;
        let config: HowyConfig =
            toml::from_str(std::str::from_utf8(&config_file.bytes).ok()?).ok()?;
        self.invocation_counter = self.invocation_counter.wrapping_add(1).max(1);
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
            config_sha256: config_file.observed().sha256().as_str().into(),
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
        Ok("txn-0123456789abcdef".into())
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

    fn write_file_atomic(
        &mut self,
        path: &str,
        bytes: &[u8],
        permissions: u32,
        mode: AtomicWriteMode,
    ) -> SecurityResult<()> {
        self.events.push(format!("write:{path}"));
        if mode == AtomicWriteMode::NoReplace && self.files.contains_key(path) {
            return Err(SecurityError::operation("no-replace collision"));
        }
        self.put(path, bytes, permissions);
        Ok(())
    }

    fn restore_file(
        &mut self,
        path: &str,
        snapshot: Option<&howy_common::provisioning::ExactFileSnapshot>,
    ) -> SecurityResult<()> {
        self.events.push(format!("restore:{path}"));
        match snapshot {
            Some(snapshot) => {
                let maximum = match path {
                    howy_common::paths::CONFIG_FILE => howy_common::provisioning::MAX_CONFIG_BYTES,
                    SECURITY_RECEIPT_PATH => howy_common::provisioning::MAX_RECEIPT_BYTES,
                    _ => howy_common::provisioning::MAX_DROPIN_BYTES,
                };
                let restored = snapshot
                    .reconstruct(maximum)
                    .map_err(|error| SecurityError::operation(error.to_string()))?;
                self.put(path, &restored.bytes, restored.metadata.permissions);
            }
            None => self.remove(path),
        }
        Ok(())
    }

    fn create_guard(&mut self, transaction_id: &str) -> SecurityResult<()> {
        self.events.push("guard:create".into());
        match self.files.get(SECURITY_TRANSACTION_GUARD_PATH) {
            Some(file) if file.bytes == transaction_id.as_bytes() => Ok(()),
            Some(_) => Err(SecurityError::Uncertain("other guard".into())),
            None => {
                self.put(
                    SECURITY_TRANSACTION_GUARD_PATH,
                    transaction_id.as_bytes(),
                    0o600,
                );
                Ok(())
            }
        }
    }

    fn remove_guard(&mut self) -> SecurityResult<()> {
        self.events.push("guard:remove".into());
        self.remove(SECURITY_TRANSACTION_GUARD_PATH);
        Ok(())
    }

    fn persist_journal(&mut self, bytes: &[u8]) -> SecurityResult<()> {
        self.events.push("journal:sync".into());
        self.put(SECURITY_JOURNAL_PATH, bytes, 0o600);
        Ok(())
    }

    fn remove_journal(&mut self) -> SecurityResult<()> {
        self.events.push("journal:remove".into());
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

    fn monotonic_millis(&mut self) -> u64 {
        self.monotonic_millis
    }

    fn settle_step(&mut self) -> SecurityResult<()> {
        self.events.push("settle".into());
        self.monotonic_millis += 100;
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
        Ok(())
    }

    fn daemon_reload(&mut self) -> SecurityResult<()> {
        self.events.push("daemon-reload".into());
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
        self.verifier_for(&config.bytes)
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))
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
        Ok(self.status())
    }

    fn unlink_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
    ) -> SecurityResult<()> {
        self.events.push("artifact:unlink".into());
        let current = self
            .files
            .get(MODE1_CREDENTIAL_PATH)
            .ok_or_else(|| SecurityError::operation("artifact absent"))?
            .observed();
        if current.inode != expected.inode || current.sha256() != expected.sha256 {
            return Err(SecurityError::operation("artifact changed"));
        }
        self.remove(MODE1_CREDENTIAL_PATH);
        Ok(())
    }

    fn boundary(&mut self, name: &'static str) -> SecurityResult<()> {
        self.boundary_count += 1;
        self.events.push(format!("boundary:{name}"));
        if self.crash_at == Some(self.boundary_count) {
            Err(SecurityError::InjectedCrash(format!(
                "injected crash at {name}"
            )))
        } else {
            Ok(())
        }
    }
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
    assert_eq!(runtime.credential_input_lengths, [32]);
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
fn provision_then_enable_reruns_readiness_patches_one_token_and_validates_status() {
    let mut runtime = FakeRuntime::fresh();
    provision(&mut runtime).unwrap();
    let disabled = runtime.files[howy_common::paths::CONFIG_FILE].bytes.clone();
    let readiness_before = runtime
        .events
        .iter()
        .filter(|event| event.as_str() == "systemd-run")
        .count();
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
    assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
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
        readiness_before + 1
    );
}

#[test]
fn readiness_failure_rolls_back_and_retains_descriptor_bound_unadopted_artifact() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness timeout"));
    let error = provision(&mut runtime).unwrap_err().to_string();
    assert!(error.contains("cleanup-unadopted"));
    assert!(runtime.transient_killed);
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(!runtime.files.contains_key(howy_common::paths::CONFIG_FILE));
    assert!(!runtime.files.contains_key(MODE1_DROPIN_PATH));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
    let manifest_path = format!("{SECURITY_UNADOPTED_DIRECTORY}/txn-0123456789abcdef.json");
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
    let artifact_hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    let outcome = SecurityEngine::new(&mut runtime)
        .cleanup_unadopted(CleanupRequest {
            transaction_id: "txn-0123456789abcdef".into(),
            artifact_sha256: artifact_hash,
        })
        .unwrap();
    assert!(outcome.cleanup_command.is_none());
    assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(
        runtime
            .events
            .iter()
            .any(|event| event == "artifact:unlink")
    );
    assert!(runtime.events.iter().all(|event| !event.contains("rm ")));
}

#[test]
fn cleanup_refuses_path_replacement_between_admission_and_unlink() {
    let mut runtime = FakeRuntime::fresh();
    runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
    assert!(provision(&mut runtime).is_err());
    runtime.readiness_error = None;
    let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
    runtime.artifact_read_count = 0;
    runtime.swap_artifact_on_read = Some(2);
    let result = SecurityEngine::new(&mut runtime).cleanup_unadopted(CleanupRequest {
        transaction_id: "txn-0123456789abcdef".into(),
        artifact_sha256: hash,
    });
    assert!(result.is_err());
    assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    assert!(
        !runtime
            .events
            .iter()
            .any(|event| event == "artifact:unlink")
    );
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
    assert!(!runtime.files.contains_key(MODE1_DROPIN_PATH));
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
}

#[test]
fn nonempty_namespace_without_artifact_refuses_before_rng_or_journal() {
    let mut runtime = FakeRuntime::fresh();
    runtime.namespace_nonempty = true;
    let result = provision(&mut runtime);
    assert!(matches!(result, Err(SecurityError::Refused(_))));
    assert!(!runtime.events.iter().any(|event| event == "rng-mlock"));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
}

#[test]
fn existing_artifact_requires_explicit_adoption() {
    let mut runtime = FakeRuntime::fresh();
    runtime.put(MODE1_CREDENTIAL_PATH, &host_envelope_text(), 0o600);
    let result = provision(&mut runtime);
    assert!(matches!(result, Err(SecurityError::Refused(_))));
    assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));

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
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(!runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    }
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
        assert!(matches!(result, Err(SecurityError::InjectedCrash(_))));
        runtime.crash_at = None;
        if runtime.files.contains_key(SECURITY_JOURNAL_PATH) {
            runtime.transient_exists = true;
            let outcome = SecurityEngine::new(&mut runtime).recover().unwrap();
            assert!(runtime.transient_killed);
            assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
            assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
            let manifest_path = format!("{SECURITY_UNADOPTED_DIRECTORY}/txn-0123456789abcdef.json");
            if runtime.files.contains_key(&manifest_path) {
                assert!(outcome.cleanup_command.is_some());
            }
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
        assert!(matches!(result, Err(SecurityError::InjectedCrash(_))));
        runtime.crash_at = None;
        SecurityEngine::new(&mut runtime)
            .recover()
            .unwrap_or_else(|error| panic!("enable crash {crash_at} recovery failed: {error}"));
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
    }
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
        assert!(matches!(result, Err(SecurityError::InjectedCrash(_))));
        runtime.crash_at = None;
        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_JOURNAL_PATH));
        assert!(!runtime.files.contains_key(SECURITY_TRANSACTION_GUARD_PATH));
    }
}

#[test]
fn cleanup_refuses_active_units_and_queued_jobs() {
    for configure in [
        |runtime: &mut FakeRuntime| runtime.service = unit(UnitKind::Service, true),
        |runtime: &mut FakeRuntime| runtime.socket.has_queued_job = true,
    ] {
        let mut runtime = FakeRuntime::fresh();
        runtime.readiness_error = Some(SecurityError::operation("readiness failed"));
        assert!(provision(&mut runtime).is_err());
        runtime.readiness_error = None;
        let hash = runtime.files[MODE1_CREDENTIAL_PATH].observed().sha256();
        configure(&mut runtime);
        let result = SecurityEngine::new(&mut runtime).cleanup_unadopted(CleanupRequest {
            transaction_id: "txn-0123456789abcdef".into(),
            artifact_sha256: hash,
        });
        assert!(matches!(result, Err(SecurityError::Refused(_))));
        assert!(runtime.files.contains_key(MODE1_CREDENTIAL_PATH));
    }
}

#[test]
fn malformed_readiness_rolls_back_and_masked_units_refuse_without_mutation() {
    let mut malformed = FakeRuntime::fresh();
    malformed.malformed_readiness = true;
    assert!(provision(&mut malformed).is_err());
    assert!(
        !malformed
            .files
            .contains_key(howy_common::paths::CONFIG_FILE)
    );

    let mut masked = FakeRuntime::fresh();
    masked.service.unit_file_state = UnitFileState::Masked;
    assert!(provision(&mut masked).is_err());
    assert!(!masked.files.contains_key(SECURITY_JOURNAL_PATH));
    assert!(!masked.events.iter().any(|event| event == "systemd-creds"));
}

#[test]
fn repository_units_have_the_same_persistent_negative_guard() {
    for unit in [
        include_str!("../../../../systemd/howy.service"),
        include_str!("../../../../systemd/howy.socket"),
    ] {
        assert_eq!(
            unit.lines()
                .filter(|line| *line == "ConditionPathExists=!/etc/howy/.security-transaction")
                .count(),
            1
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
