use super::*;

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn metadata_for(bytes: &[u8]) -> FileMetadataSnapshotV1 {
    FileMetadataSnapshotV1 {
        schema_version: 1,
        object_type: FileObjectType::RegularFile,
        uid: 0,
        gid: 0,
        permissions: 0o640,
        link_count: 1,
        link_policy: FileLinkPolicy::ExactlyOne,
        byte_length: bytes.len() as u64,
        restorable_timestamps: RestorableFileTimestampsV1 {
            access: FileTimestampV1 {
                seconds: 1_700_000_001,
                nanoseconds: 123_456_789,
            },
            modification: FileTimestampV1 {
                seconds: 1_700_000_002,
                nanoseconds: 987_654_321,
            },
        },
    }
}

fn guard_identity(transaction_id: &str) -> TransactionGuardIdentityV1 {
    let bytes = TransactionGuardV1::new(transaction_id)
        .unwrap()
        .deterministic_bytes()
        .unwrap();
    TransactionGuardIdentityV1::new(
        transaction_id,
        AtomicFileIdentityV1 {
            device_id: 8,
            inode: 77,
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions: 0o600,
            link_count: 1,
            byte_length: bytes.len() as u64,
            sha256: digest(&bytes),
        },
    )
    .unwrap()
}

fn prior_journal_identity(generation: u64) -> Option<AtomicFileIdentityV1> {
    (generation > 1).then(|| {
        let bytes = format!("prior-journal-generation-{}", generation - 1);
        AtomicFileIdentityV1 {
            device_id: 8,
            inode: 1_000 + generation,
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions: 0o600,
            link_count: 1,
            byte_length: bytes.len() as u64,
            sha256: digest(bytes.as_bytes()),
        }
    })
}

fn security_directories() -> Vec<SecurityDirectoryRecordV1> {
    REQUIRED_SECURITY_DIRECTORIES
        .iter()
        .enumerate()
        .map(|(index, (path, permissions))| {
            let identity = DirectoryIdentityV1 {
                path: (*path).to_owned(),
                object_type: FileObjectType::Directory,
                device_id: 8,
                inode: 100 + index as u64,
                uid: 0,
                gid: 0,
                permissions: *permissions,
                link_count: 2,
            };
            let preexisted = index % 2 == 0;
            SecurityDirectoryRecordV1 {
                path: (*path).to_owned(),
                uid: 0,
                gid: 0,
                permissions: *permissions,
                parent_directory: DirectoryIdentityV1 {
                    path: Path::new(path)
                        .parent()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    object_type: FileObjectType::Directory,
                    device_id: 8,
                    inode: 10 + index as u64,
                    uid: 0,
                    gid: 0,
                    permissions: 0o755,
                    link_count: 2,
                },
                expected_directory: preexisted.then(|| identity.clone()),
                observed_directory: Some(identity),
                preexisted,
            }
        })
        .collect()
}

fn effective_file(path: &str, label: &[u8], permissions: u32) -> EffectiveUnitFileV1 {
    EffectiveUnitFileV1 {
        path: path.to_owned(),
        sha256: digest(label),
        metadata: EffectiveFileMetadataV1 {
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions,
            link_count: 1,
            byte_length: label.len() as u64,
        },
    }
}

fn effective_units(dropin_sha256: Sha256Digest, mode1: bool) -> EffectiveUnitSetV1 {
    EffectiveUnitSetV1 {
        service: EffectiveUnitObservationV1 {
            unit_kind: UnitKind::Service,
            fragment: effective_file(BASE_SERVICE_UNIT_PATH, b"service", 0o644),
            dropins: vec![EffectiveUnitFileV1 {
                path: MODE1_DROPIN_PATH.to_owned(),
                sha256: dropin_sha256,
                metadata: EffectiveFileMetadataV1 {
                    object_type: FileObjectType::RegularFile,
                    uid: 0,
                    gid: 0,
                    permissions: 0o600,
                    link_count: 1,
                    byte_length: b"dropin".len() as u64,
                },
            }],
            conditions: required_unit_conditions().into(),
            load_credential_encrypted: mode1
                .then(|| EffectiveCredentialLoadV1 {
                    name: MODE1_CREDENTIAL_NAME.to_owned(),
                    source: MODE1_CREDENTIAL_PATH.to_owned(),
                })
                .into_iter()
                .collect(),
            set_credential: mode1
                .then(|| EffectiveSetCredentialV1 {
                    name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.to_owned(),
                    value: MODE1_CREDENTIAL_PATH.to_owned(),
                })
                .into_iter()
                .collect(),
            exec_start: vec![vec!["/usr/bin/howyd".to_owned()]],
            hardening: required_service_hardening(),
        },
        socket: EffectiveUnitObservationV1 {
            unit_kind: UnitKind::Socket,
            fragment: effective_file(BASE_SOCKET_UNIT_PATH, b"socket", 0o644),
            dropins: Vec::new(),
            conditions: required_unit_conditions().into(),
            load_credential_encrypted: Vec::new(),
            set_credential: Vec::new(),
            exec_start: Vec::new(),
            hardening: BTreeMap::new(),
        },
    }
}

fn file_snapshot(bytes: &[u8]) -> ExactFileSnapshot {
    ExactFileSnapshot::new(bytes, metadata_for(bytes)).unwrap()
}

fn active_unit() -> StableUnitState {
    StableUnitState {
        unit_kind: UnitKind::Service,
        load_state: UnitLoadState::Loaded,
        active_state: UnitActiveState::Active,
        sub_state: UnitSubState::Running,
        unit_file_state: UnitFileState::Enabled,
    }
}

fn inactive_unit(unit_kind: UnitKind) -> StableUnitState {
    StableUnitState {
        unit_kind,
        load_state: UnitLoadState::Loaded,
        active_state: UnitActiveState::Inactive,
        sub_state: UnitSubState::Dead,
        unit_file_state: UnitFileState::Disabled,
    }
}

fn journal_at(phase: JournalPhase) -> ProvisioningJournalV1 {
    let planned_hashes = PlannedObjectHashes {
        artifact_sha256: digest(b"artifact"),
        dropin_sha256: digest(b"dropin"),
        disabled_config_sha256: digest(b"disabled"),
        enabled_config_sha256: digest(b"enabled"),
        disabled_receipt_sha256: digest(b"disabled-receipt"),
        enabled_receipt_sha256: digest(b"enabled-receipt"),
    };
    let ordinal = phase.ordinal();
    let live_hashes = LiveObjectHashes {
        artifact_sha256: (ordinal >= JournalPhase::ArtifactCommitted.ordinal())
            .then(|| planned_hashes.artifact_sha256.clone()),
        dropin_sha256: (ordinal >= JournalPhase::DropinCommitted.ordinal())
            .then(|| planned_hashes.dropin_sha256.clone()),
        config_sha256: if ordinal < JournalPhase::DisabledConfigCommitted.ordinal() {
            None
        } else if ordinal < JournalPhase::EnabledConfigCommitted.ordinal() {
            Some(planned_hashes.disabled_config_sha256.clone())
        } else {
            Some(planned_hashes.enabled_config_sha256.clone())
        },
        disabled_receipt_sha256: (ordinal >= JournalPhase::DisabledReceiptCommitted.ordinal())
            .then(|| planned_hashes.disabled_receipt_sha256.clone()),
        enabled_receipt_sha256: (ordinal >= JournalPhase::EnabledReceiptCommitted.ordinal())
            .then(|| planned_hashes.enabled_receipt_sha256.clone()),
    };
    let service_unit_state = active_unit();
    let socket_unit_state = inactive_unit(UnitKind::Socket);
    let (post_provision_service_target, post_provision_socket_target) =
        disabled_post_provision_unit_targets(&service_unit_state, &socket_unit_state).unwrap();
    ProvisioningJournalV1 {
        schema_version: 1,
        transaction_id: "txn-0123456789abcdef0123456789abcdef".to_owned(),
        generation: ordinal as u64 + 1,
        prior_journal_identity: prior_journal_identity(ordinal as u64 + 1),
        journal_staging_path: canonical_journal_staging_path(
            "txn-0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        guard: (ordinal >= JournalPhase::Guarded.ordinal())
            .then(|| guard_identity("txn-0123456789abcdef0123456789abcdef")),
        phase,
        mode: 1,
        epoch: 1,
        credential_name: MODE1_CREDENTIAL_NAME.to_owned(),
        planned_hashes,
        live_hashes,
        transaction_owned_paths: vec![
            "/etc/howy/config.toml".to_owned(),
            canonical_journal_staging_path("txn-0123456789abcdef0123456789abcdef").unwrap(),
            SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
        ],
        atomic_writes: Vec::new(),
        security_directories: security_directories(),
        artifact_preexisted: false,
        transient_unit: "howy-readiness-0123456789abcdef.service".to_owned(),
        prior_config: Some(file_snapshot(b"[core]\ndisabled = false\n")),
        prior_dropin: None,
        prior_receipt: None,
        service_unit_state,
        socket_unit_state,
        post_provision_service_target,
        post_provision_socket_target,
        prior_daemon_invocation_id: Some("23".repeat(32)),
        prior_effective_units: effective_units(digest(b"prior-dropin"), false),
        effective_units: (ordinal >= JournalPhase::DropinCommitted.ordinal())
            .then(|| effective_units(digest(b"dropin"), true)),
        backup_hashes: BackupHashes {
            artifact_sha256: None,
            config_sha256: Some(digest(b"[core]\ndisabled = false\n")),
            dropin_sha256: None,
            receipt_sha256: None,
        },
        recovery_action: recovery_action_for_phase(phase),
        supervisor_failed: false,
    }
}

#[test]
fn journal_exact_phases_recovery_matrix_and_monotonic_transitions() {
    assert_eq!(JournalPhase::ALL.len(), 13);
    for (index, phase) in JournalPhase::ALL.into_iter().enumerate() {
        let journal = journal_at(phase);
        journal.validate().unwrap();
        assert_eq!(journal.recovery_action, recovery_action_for_phase(phase));
        if let Some(next_phase) = phase.next() {
            validate_journal_transition(&journal, &journal_at(next_phase)).unwrap();
        } else {
            assert_eq!(index, 12);
        }
    }

    assert!(
        validate_journal_transition(
            &journal_at(JournalPhase::Prepared),
            &journal_at(JournalPhase::UnitsStopped)
        )
        .is_err()
    );
    assert!(
        validate_journal_transition(
            &journal_at(JournalPhase::Guarded),
            &journal_at(JournalPhase::Prepared)
        )
        .is_err()
    );
}

#[test]
fn journal_is_strict_bounded_and_deterministic() {
    let journal = journal_at(JournalPhase::DisabledReceiptCommitted);
    let first = journal.deterministic_bytes().unwrap();
    let parsed = ProvisioningJournalV1::parse(&first).unwrap();
    assert_eq!(first, parsed.deterministic_bytes().unwrap());
    assert_eq!(
        journal.deterministic_sha256().unwrap(),
        parsed.deterministic_sha256().unwrap()
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&first).unwrap();
    unknown["plaintext_key"] = serde_json::Value::String("forbidden".to_owned());
    assert!(ProvisioningJournalV1::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut wrong_live = journal.clone();
    wrong_live.live_hashes.artifact_sha256 = None;
    assert!(wrong_live.validate().is_err());

    let mut wrong_action = journal;
    wrong_action.recovery_action = RecoveryAction::CompleteEnabledActivation;
    assert!(wrong_action.validate().is_err());

    assert_eq!(
        ProvisioningJournalV1::parse(&vec![b' '; MAX_JOURNAL_BYTES + 1]),
        Err(ProvisioningContractError::LimitExceeded("journal bytes"))
    );

    let mut too_many_paths = journal_at(JournalPhase::Prepared);
    too_many_paths.transaction_owned_paths = (0..=MAX_TRANSACTION_OWNED_PATHS)
        .map(|index| format!("/etc/howy/path-{index:03}"))
        .collect();
    assert!(too_many_paths.validate().is_err());
}

#[test]
fn journal_transition_binds_every_stable_field() {
    let current = journal_at(JournalPhase::Prepared);
    let mut next = journal_at(JournalPhase::Guarded);
    next.transaction_owned_paths.push("/etc/howy/z".to_owned());
    assert!(validate_journal_transition(&current, &next).is_err());

    let mut invalid_target = journal_at(JournalPhase::UnitsStopped);
    invalid_target.post_provision_service_target = active_unit();
    assert!(invalid_target.validate().is_err());
    let valid = journal_at(JournalPhase::UnitsStopped);
    assert_eq!(
        valid.post_provision_service_target.rollback_target(),
        Some(StableRollbackTarget::InactiveDead)
    );
    assert_eq!(
        valid.post_provision_service_target.unit_file_state,
        valid.service_unit_state.unit_file_state
    );
    assert_eq!(valid.post_provision_socket_target, valid.socket_unit_state);
}

#[test]
fn guarded_journal_allows_only_an_identity_bound_same_phase_guard_recreation() {
    let current = journal_at(JournalPhase::UnitsStarted);
    let mut next = current.clone();
    next.generation += 1;
    next.prior_journal_identity = prior_journal_identity(next.generation);
    next.guard.as_mut().unwrap().file.inode += 1;
    validate_journal_transition(&current, &next).unwrap();

    let mut combined = next.clone();
    combined.live_hashes.config_sha256 = Some(digest(b"other"));
    assert!(validate_journal_transition(&current, &combined).is_err());
}

fn atomic_parent(path: &str) -> DirectoryIdentityV1 {
    DirectoryIdentityV1 {
        path: path.to_owned(),
        object_type: FileObjectType::Directory,
        device_id: 8,
        inode: 42,
        uid: 0,
        gid: 0,
        permissions: 0o755,
        link_count: 2,
    }
}

fn atomic_identity(bytes: &[u8], inode: u64) -> AtomicFileIdentityV1 {
    AtomicFileIdentityV1 {
        device_id: 8,
        inode,
        object_type: FileObjectType::RegularFile,
        uid: 0,
        gid: 0,
        permissions: 0o600,
        link_count: 1,
        byte_length: bytes.len() as u64,
        sha256: digest(bytes),
    }
}

#[test]
fn atomic_write_plan_is_canonical_strict_and_cross_directory_safe() {
    let transaction = "txn-0123456789abcdef0123456789abcdef";
    let target = "/etc/howy/config.toml";
    let old = atomic_identity(b"old", 100);
    let plan = AtomicWritePlanV1::new(
        transaction,
        target,
        atomic_parent("/etc/howy"),
        AtomicExpectedTargetV1::Present(old),
        0,
        0,
        0o600,
        None,
        b"new",
        AtomicWriteKindV1::Exchange,
    )
    .unwrap();
    assert_eq!(
        plan.backup_path.as_deref(),
        Some(plan.staging_path.as_str())
    );
    assert!(
        plan.staging_path
            .starts_with("/etc/howy/.howy-txn-0123456789abcdef0123456789abcdef-config.toml-")
    );
    plan.validate().unwrap();

    let mut traversal = plan.clone();
    traversal.staging_path = "/etc/howy/../owned.stage".into();
    assert!(traversal.validate().is_err());
    let mut cross_directory = plan.clone();
    cross_directory.staging_path = "/tmp/owned.stage".into();
    cross_directory.backup_path = Some(cross_directory.staging_path.clone());
    assert!(cross_directory.validate().is_err());
    let mut unowned = plan.clone();
    unowned.staging_path = "/etc/howy/arbitrary.stage".into();
    unowned.backup_path = Some(unowned.staging_path.clone());
    assert!(unowned.validate().is_err());
    let mut malformed_transaction = plan.clone();
    malformed_transaction.transaction_id = "txn-../../escape".into();
    assert!(malformed_transaction.validate().is_err());

    let bytes = plan.clone();
    let mut unknown: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&bytes).unwrap()).unwrap();
    unknown["counter"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AtomicWritePlanV1>(unknown).is_err());
}

#[test]
fn atomic_write_records_advance_only_plan_commit_cleanup() {
    let plan = AtomicWritePlanV1::new(
        "txn-0123456789abcdef0123456789abcdef",
        "/etc/howy/config.toml",
        atomic_parent("/etc/howy"),
        AtomicExpectedTargetV1::Present(atomic_identity(b"old", 100)),
        0,
        0,
        0o600,
        None,
        b"new",
        AtomicWriteKindV1::Exchange,
    )
    .unwrap();
    let mut planned = journal_at(JournalPhase::Prepared);
    let initial = planned.clone();
    planned
        .transaction_owned_paths
        .push(plan.staging_path.clone());
    planned.transaction_owned_paths.sort();
    planned
        .atomic_writes
        .push(AtomicWriteRecordV1::planned(plan.clone()));
    planned.generation += 1;
    planned.prior_journal_identity = prior_journal_identity(planned.generation);
    validate_journal_transition(&initial, &planned).unwrap();

    let staged_identity = atomic_identity(b"new", 101);
    let mut staged = planned.clone();
    staged.atomic_writes[0].state = AtomicWriteStateV1::Staged {
        identity: staged_identity.clone(),
    };
    staged.generation += 1;
    staged.prior_journal_identity = prior_journal_identity(staged.generation);
    validate_journal_transition(&planned, &staged).unwrap();

    let observation = AtomicWriteObservationV1 {
        target: staged_identity,
        backup: Some(atomic_identity(b"old", 100)),
    };
    let mut committed = staged.clone();
    committed.atomic_writes[0].state = AtomicWriteStateV1::Committed {
        observation: observation.clone(),
    };
    committed.generation += 1;
    committed.prior_journal_identity = prior_journal_identity(committed.generation);
    validate_journal_transition(&staged, &committed).unwrap();
    let mut cleaned = committed.clone();
    cleaned.atomic_writes[0].state = AtomicWriteStateV1::BackupCleaned { observation };
    cleaned.generation += 1;
    cleaned.prior_journal_identity = prior_journal_identity(cleaned.generation);
    validate_journal_transition(&committed, &cleaned).unwrap();

    let mut skipped = planned;
    skipped.atomic_writes[0].state = AtomicWriteStateV1::BackupCleaned {
        observation: match &committed.atomic_writes[0].state {
            AtomicWriteStateV1::Committed { observation } => observation.clone(),
            _ => unreachable!(),
        },
    };
    assert!(validate_journal_transition(&initial, &skipped).is_err());
}

fn plaintext_journal_at(phase: PlaintextJournalPhase) -> PlaintextProvisioningJournalV1 {
    let enabled_config_sha256 = digest(b"explicit-mode0");
    PlaintextProvisioningJournalV1 {
        schema_version: 1,
        transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
        generation: phase.ordinal() as u64 + 1,
        prior_journal_identity: prior_journal_identity(phase.ordinal() as u64 + 1),
        journal_staging_path: canonical_journal_staging_path(
            "txn-0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        guard: (phase.ordinal() >= PlaintextJournalPhase::Guarded.ordinal())
            .then(|| guard_identity("txn-0123456789abcdef0123456789abcdef")),
        phase,
        enabled_config_sha256: enabled_config_sha256.clone(),
        live_config_sha256: (phase.ordinal()
            >= PlaintextJournalPhase::EnabledConfigCommitted.ordinal())
        .then_some(enabled_config_sha256),
        transaction_owned_paths: vec![
            "/etc/howy/config.toml".to_owned(),
            canonical_journal_staging_path("txn-0123456789abcdef0123456789abcdef").unwrap(),
            SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
        ],
        atomic_writes: Vec::new(),
        security_directories: security_directories(),
        prior_config: Some(file_snapshot(b"[core]\ndisabled = true\n")),
        prior_dropin: None,
        service_unit_state: inactive_unit(UnitKind::Service),
        socket_unit_state: inactive_unit(UnitKind::Socket),
        prior_daemon_invocation_id: None,
        prior_effective_units: effective_units(digest(b"prior-dropin"), true),
        effective_units: (phase.ordinal() >= PlaintextJournalPhase::DropinRemoved.ordinal())
            .then(|| effective_units(digest(b"mode0-dropin"), false)),
        dropin_sha256: digest(b"mode0-dropin"),
        recovery_action: plaintext_recovery_action_for_phase(phase),
        supervisor_failed: false,
    }
}

#[test]
fn plaintext_mode_has_a_strict_common_transaction_journal() {
    for phase in PlaintextJournalPhase::ALL {
        let journal = plaintext_journal_at(phase);
        let bytes = journal.deterministic_bytes().unwrap();
        assert_eq!(
            PlaintextProvisioningJournalV1::parse(&bytes).unwrap(),
            journal
        );
        if let Some(next) = phase.next() {
            validate_plaintext_journal_transition(&journal, &plaintext_journal_at(next)).unwrap();
        }
    }
    let mut unknown: serde_json::Value = serde_json::from_slice(
        &plaintext_journal_at(PlaintextJournalPhase::Prepared)
            .deterministic_bytes()
            .unwrap(),
    )
    .unwrap();
    unknown["plaintext_key"] = serde_json::json!("forbidden");
    assert!(PlaintextProvisioningJournalV1::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn supervisor_intent_is_strict_and_binds_post_guard_unit_targets() {
    let prepared = SupervisorJournalV1 {
        schema_version: 1,
        transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
        generation: 1,
        prior_journal_identity: None,
        journal_staging_path: canonical_journal_staging_path(
            "txn-0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        guard: None,
        operation: SupervisorOperationV1::ProvisionMode1,
        phase: SupervisorPhaseV1::Prepared,
        prior_config: Some(file_snapshot(b"[core]\ndisabled = false\n")),
        prior_dropin: None,
        prior_receipt: None,
        service_unit_state: Some(active_unit()),
        socket_unit_state: Some(inactive_unit(UnitKind::Socket)),
        prior_daemon_invocation_id: Some("23".repeat(32)),
        prior_effective_units: Some(effective_units(digest(b"prior"), false)),
        transaction_owned_paths: vec![
            "/etc/howy/config.toml".to_owned(),
            canonical_journal_staging_path("txn-0123456789abcdef0123456789abcdef").unwrap(),
            SECURITY_TRANSACTION_GUARD_PATH.to_owned(),
        ],
        atomic_writes: Vec::new(),
        security_directories: Vec::new(),
        cleanup_artifact: None,
        cleanup_manifest: None,
        cleanup_pre_admission: None,
        cleanup_quarantine: None,
        supervisor_failed: false,
    };
    let mut guarded = prepared.clone();
    guarded.phase = SupervisorPhaseV1::Guarded;
    guarded.generation += 1;
    guarded.prior_journal_identity = prior_journal_identity(guarded.generation);
    guarded.guard = Some(guard_identity(&guarded.transaction_id));
    validate_supervisor_journal_transition(&prepared, &guarded).unwrap();
    let mut stopped = guarded.clone();
    stopped.phase = SupervisorPhaseV1::UnitsStopped;
    stopped.generation += 1;
    stopped.prior_journal_identity = prior_journal_identity(stopped.generation);
    validate_supervisor_journal_transition(&guarded, &stopped).unwrap();

    let mut directories_planned = stopped.clone();
    for record in security_directories() {
        let mut intent = record.clone();
        intent.observed_directory = None;
        let current = directories_planned.clone();
        directories_planned.security_directories.push(intent);
        directories_planned.generation += 1;
        directories_planned.prior_journal_identity =
            prior_journal_identity(directories_planned.generation);
        validate_supervisor_journal_transition(&current, &directories_planned).unwrap();
        let current = directories_planned.clone();
        directories_planned
            .security_directories
            .last_mut()
            .unwrap()
            .observed_directory = record.observed_directory;
        directories_planned.generation += 1;
        directories_planned.prior_journal_identity =
            prior_journal_identity(directories_planned.generation);
        validate_supervisor_journal_transition(&current, &directories_planned).unwrap();
    }
    let mut directories_ready = directories_planned.clone();
    directories_ready.phase = SupervisorPhaseV1::DirectoriesReady;
    directories_ready.generation += 1;
    directories_ready.prior_journal_identity = prior_journal_identity(directories_ready.generation);
    validate_supervisor_journal_transition(&directories_planned, &directories_ready).unwrap();

    let mut failed = directories_ready.clone();
    failed.supervisor_failed = true;
    failed.generation += 1;
    failed.prior_journal_identity = prior_journal_identity(failed.generation);
    validate_supervisor_journal_transition(&directories_ready, &failed).unwrap();
    let bytes = failed.deterministic_bytes().unwrap();
    assert_eq!(SupervisorJournalV1::parse(&bytes).unwrap(), failed);

    let mut lost_target = directories_ready;
    lost_target.service_unit_state = None;
    assert!(lost_target.validate().is_err());
}

#[test]
fn every_journal_requires_exact_service_activity_and_invocation_presence() {
    let mut mode1_active_without_id = journal_at(JournalPhase::Guarded);
    mode1_active_without_id.prior_daemon_invocation_id = None;
    assert!(mode1_active_without_id.validate().is_err());

    let mut mode1_inactive_with_id = journal_at(JournalPhase::Guarded);
    mode1_inactive_with_id.service_unit_state = inactive_unit(UnitKind::Service);
    assert!(mode1_inactive_with_id.validate().is_err());

    let mut mode0_inactive_with_id = plaintext_journal_at(PlaintextJournalPhase::Guarded);
    mode0_inactive_with_id.prior_daemon_invocation_id = Some("ab".repeat(32));
    assert!(mode0_inactive_with_id.validate().is_err());

    let mut mode0_active_without_id = plaintext_journal_at(PlaintextJournalPhase::Guarded);
    mode0_active_without_id.service_unit_state = active_unit();
    assert!(mode0_active_without_id.validate().is_err());

    let mut supervisor_active_without_id = SupervisorJournalV1 {
        schema_version: 1,
        transaction_id: "txn-0123456789abcdef0123456789abcdef".into(),
        generation: 1,
        prior_journal_identity: None,
        journal_staging_path: canonical_journal_staging_path(
            "txn-0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
        guard: None,
        operation: SupervisorOperationV1::ProvisionMode1,
        phase: SupervisorPhaseV1::Prepared,
        prior_config: None,
        prior_dropin: None,
        prior_receipt: None,
        service_unit_state: Some(active_unit()),
        socket_unit_state: Some(inactive_unit(UnitKind::Socket)),
        prior_daemon_invocation_id: None,
        prior_effective_units: Some(effective_units(digest(b"prior"), false)),
        transaction_owned_paths: vec![
            canonical_journal_staging_path("txn-0123456789abcdef0123456789abcdef").unwrap(),
        ],
        atomic_writes: Vec::new(),
        security_directories: Vec::new(),
        cleanup_artifact: None,
        cleanup_manifest: None,
        cleanup_pre_admission: None,
        cleanup_quarantine: None,
        supervisor_failed: false,
    };
    assert!(supervisor_active_without_id.validate().is_err());
    supervisor_active_without_id.service_unit_state = Some(inactive_unit(UnitKind::Service));
    supervisor_active_without_id.prior_daemon_invocation_id = Some("cd".repeat(32));
    assert!(supervisor_active_without_id.validate().is_err());

    let mut uppercase = journal_at(JournalPhase::Guarded);
    uppercase.prior_daemon_invocation_id = Some("AB".repeat(32));
    assert!(uppercase.validate().is_err());
}

#[test]
fn effective_unit_policy_rejects_overrides_shadowing_and_missing_guards() {
    let mode1_hash = digest(b"dropin");
    let mode1 = effective_units(mode1_hash.clone(), true);
    mode1.validate_mode1(&mode1_hash).unwrap();

    let mut extra_dropin = mode1.clone();
    extra_dropin.service.dropins.push(effective_file(
        "/etc/systemd/system/howy.service.d/99-shadow.conf",
        b"shadow",
        0o600,
    ));
    assert!(extra_dropin.validate_mode1(&mode1_hash).is_err());

    let mut pathless_shadow = mode1.clone();
    pathless_shadow.service.load_credential_encrypted[0]
        .source
        .clear();
    assert!(pathless_shadow.validate_mode1(&mode1_hash).is_err());

    let mut missing_service_guard = mode1.clone();
    missing_service_guard.service.conditions.remove(0);
    assert!(missing_service_guard.validate_mode1(&mode1_hash).is_err());

    let mut missing_service_marker = mode1.clone();
    missing_service_marker.service.conditions.remove(1);
    assert!(missing_service_marker.validate_mode1(&mode1_hash).is_err());

    let mut missing_socket_guard = mode1.clone();
    missing_socket_guard.socket.conditions.remove(0);
    assert!(missing_socket_guard.validate_mode1(&mode1_hash).is_err());

    let mut reordered = mode1.clone();
    reordered.service.conditions.reverse();
    assert!(reordered.validate_mode1(&mode1_hash).is_err());

    let mut changed_exec = mode1.clone();
    changed_exec.service.exec_start = vec![vec!["/usr/local/bin/howyd".into()]];
    assert!(changed_exec.validate_mode1(&mode1_hash).is_err());

    let mode0_hash = digest(b"mode0-dropin");
    let mode0 = effective_units(mode0_hash.clone(), false);
    mode0.validate_mode0(&mode0_hash).unwrap();
    let mut credential_leak = mode0;
    credential_leak.service.set_credential = mode1.service.set_credential;
    assert!(credential_leak.validate_mode0(&mode0_hash).is_err());
}

#[test]
fn file_metadata_snapshot_is_canonical_bound_and_exactly_reconstructable() {
    let bytes = b"[core]\ndisabled = false\n";
    let snapshot = file_snapshot(bytes);
    let canonical = snapshot.metadata.deterministic_bytes().unwrap();
    assert!(canonical.starts_with(FILE_METADATA_DOMAIN));
    assert_eq!(
        snapshot.metadata_sha256.as_str(),
        "f15a0e35230c863cef8922580f1972818ea89974361f501f4366e1a767a2739c"
    );

    let reconstruction = snapshot.reconstruct(MAX_CONFIG_BYTES).unwrap();
    assert_eq!(reconstruction.bytes, bytes);
    assert_eq!(reconstruction.metadata, metadata_for(bytes));
    assert_eq!(
        reconstruction.metadata.object_type,
        FileObjectType::RegularFile
    );
    assert_eq!(
        reconstruction.metadata.link_policy,
        FileLinkPolicy::ExactlyOne
    );
    assert_eq!(reconstruction.metadata.link_count, 1);

    let mut wrong_hash = snapshot.clone();
    wrong_hash.metadata_sha256 = digest(b"wrong metadata");
    assert!(wrong_hash.reconstruct(MAX_CONFIG_BYTES).is_err());

    let mut wrong_size = snapshot.clone();
    wrong_size.metadata.byte_length += 1;
    assert!(wrong_size.reconstruct(MAX_CONFIG_BYTES).is_err());

    let mut wrong_type = snapshot.clone();
    wrong_type.metadata.object_type = FileObjectType::Directory;
    assert!(wrong_type.reconstruct(MAX_CONFIG_BYTES).is_err());

    let mut wrong_link = snapshot.clone();
    wrong_link.metadata.link_count = 2;
    assert!(wrong_link.reconstruct(MAX_CONFIG_BYTES).is_err());

    let mut wrong_timestamp = snapshot;
    wrong_timestamp
        .metadata
        .restorable_timestamps
        .modification
        .nanoseconds = 1_000_000_000;
    assert!(wrong_timestamp.reconstruct(MAX_CONFIG_BYTES).is_err());
}

#[test]
fn config_patch_is_exact_semantic_and_byte_preserving() {
    let disabled = br#"# disabled = true is only a comment
[ml]
provider = "the text [core] disabled = true is inert"

[core] # the active table
detection_notice = false
disabled 	= 	true # unique activation token
timeout_notice = true

[debug]
log_level = "info"
"#;
    let prepared = prepare_config_enable_patch(disabled).unwrap();
    let start = prepared.contract.byte_start as usize;
    let end = prepared.contract.byte_end as usize;
    assert_eq!(&disabled[start..end], b"true");
    assert_eq!(&prepared.enabled_bytes[start..start + 5], b"false");
    assert_eq!(&disabled[..start], &prepared.enabled_bytes[..start]);
    assert_eq!(&disabled[end..], &prepared.enabled_bytes[start + 5..]);
    assert_eq!(
        Sha256Digest::from_bytes(disabled),
        prepared.contract.disabled_sha256
    );
    assert_eq!(
        Sha256Digest::from_bytes(&prepared.enabled_bytes),
        prepared.contract.enabled_sha256
    );
    assert_eq!(
        apply_receipted_config_patch(disabled, &prepared.contract).unwrap(),
        prepared.enabled_bytes
    );
}

#[test]
fn config_patch_rejects_defaulted_duplicate_nonliteral_and_alternate_layouts() {
    for invalid in [
        "[core]\ntimeout_notice = true\n",
        "[core]\ndisabled = false\n",
        "core.disabled = true\n",
        "core = { disabled = true }\n",
        "[core]\n\"disabled\" = true\n",
        "[core]\ndisabled = 1\n",
        "[core]\ndisabled = true\ndisabled = true\n",
        "# [core]\n# disabled = true\n",
    ] {
        assert!(
            prepare_config_enable_patch(invalid.as_bytes()).is_err(),
            "unexpectedly accepted {invalid:?}"
        );
    }
    assert_eq!(
        prepare_config_enable_patch(b"[core]\r\ndisabled = true\r\n"),
        Err(ProvisioningContractError::InvalidConfigEncoding)
    );
    assert_eq!(
        prepare_config_enable_patch(b"[core]\ndisabled = true\n\xff"),
        Err(ProvisioningContractError::InvalidConfigEncoding)
    );
}

fn disabled_config_with_exact_length(length: usize) -> Vec<u8> {
    let mut bytes = b"[core]\ndisabled = true\n".to_vec();
    assert!(bytes.len() < length);
    bytes.push(b'#');
    bytes.resize(length, b' ');
    bytes
}

#[test]
fn config_patch_checks_enabled_length_boundary_and_overflow() {
    let exact = disabled_config_with_exact_length(MAX_CONFIG_BYTES - 1);
    let enabled = prepare_config_enable_patch(&exact).unwrap();
    assert_eq!(enabled.enabled_bytes.len(), MAX_CONFIG_BYTES);

    let too_large = disabled_config_with_exact_length(MAX_CONFIG_BYTES);
    assert_eq!(
        prepare_config_enable_patch(&too_large),
        Err(ProvisioningContractError::LimitExceeded(
            "enabled config bytes"
        ))
    );
    assert_eq!(
        checked_enabled_config_length(usize::MAX),
        Err(ProvisioningContractError::LimitExceeded(
            "enabled config bytes"
        ))
    );
}

fn base64_encode(bytes: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[usize::from(a >> 2)]);
        output.push(TABLE[usize::from(((a & 0x03) << 4) | (b >> 4))]);
        output.push(if chunk.len() > 1 {
            TABLE[usize::from(((b & 0x0f) << 2) | (c >> 6))]
        } else {
            b'='
        });
        output.push(if chunk.len() > 2 {
            TABLE[usize::from(c & 0x3f)]
        } else {
            b'='
        });
    }
    output
}

fn systemd_envelope_binary(id: [u8; 16], name: &str, tpm: Option<(u64, bool)>) -> Vec<u8> {
    let mut binary = Vec::new();
    binary.extend_from_slice(&id);
    binary.extend_from_slice(&32u32.to_le_bytes());
    binary.extend_from_slice(&1u32.to_le_bytes());
    binary.extend_from_slice(&12u32.to_le_bytes());
    binary.extend_from_slice(&16u32.to_le_bytes());
    binary.extend_from_slice(&[0x5a; 12]);
    binary.resize(binary.len().next_multiple_of(8), 0);
    if let Some((pcr_mask, public_header)) = tpm {
        binary.extend_from_slice(&pcr_mask.to_le_bytes());
        binary.extend_from_slice(&0x000bu16.to_le_bytes()); // TPM2_ALG_SHA256
        binary.extend_from_slice(&0x0023u16.to_le_bytes()); // TPM2_ALG_ECC
        binary.extend_from_slice(&4u32.to_le_bytes());
        binary.extend_from_slice(&32u32.to_le_bytes());
        binary.extend_from_slice(b"blob");
        binary.extend_from_slice(&[0x33; 32]);
        binary.resize(binary.len().next_multiple_of(8), 0);
        if public_header {
            binary.extend_from_slice(&0u64.to_le_bytes());
            binary.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    let metadata = (SYSTEMD_METADATA_HEADER_BYTES + name.len()).next_multiple_of(8);
    binary.resize(
        binary.len() + metadata + SYSTEMD_CREDENTIAL_PLAINTEXT_BYTES as usize,
        0xa5,
    );
    binary.extend_from_slice(&[0x77; SYSTEMD_AES_TAG_BYTES as usize]);
    binary
}

const HOST_ID: [u8; 16] = [
    0x5a, 0x1c, 0x6a, 0x86, 0xdf, 0x9d, 0x40, 0x96, 0xb1, 0xd5, 0xa6, 0x5e, 0x08, 0x62, 0xf1, 0x9a,
];
const TPM_ID: [u8; 16] = [
    0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91, 0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20, 0xfe,
];
const HOST_TPM_ID: [u8; 16] = [
    0x93, 0xa8, 0x94, 0x09, 0x48, 0x74, 0x44, 0x90, 0x90, 0xca, 0xf2, 0xfc, 0x93, 0xca, 0xb5, 0x53,
];

fn validation_for(binary: &[u8], name: &str) -> CredentialCryptographicValidation {
    CredentialCryptographicValidation {
        envelope_sha256: Sha256Digest::from_bytes(binary),
        embedded_name: name.to_owned(),
        plaintext_size: 32,
        authenticated: true,
        exact_consumption: true,
    }
}

fn decode_committed_fixture(contents: &str) -> Vec<u8> {
    let hex = contents.trim();
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

#[test]
fn committed_systemd_v261_source_derived_positive_fixtures_match_provenance() {
    let provenance = include_str!("../../testdata/systemd-v261/PROVENANCE.md");
    assert!(provenance.contains("not valid AES-GCM ciphertext/tag pairs"));
    for (contents, expected_length, expected_sha256, expected_key, expected_pcr) in [
        (
            include_str!("../../testdata/systemd-v261/host.hex"),
            144,
            "d457e84f151f179fabf344266e4a6132d6fcfe0a5eb8c3759ce0d77a5902a308",
            SystemdCredentialKeyId::Host,
            None,
        ),
        (
            include_str!("../../testdata/systemd-v261/tpm2-hmac-zero-pcr.hex"),
            208,
            "9e0ab4b339699bd62f5ffbf21682b8f27d30ca34b240caa2436589ad10ad6611",
            SystemdCredentialKeyId::Tpm2Hmac,
            Some(0),
        ),
        (
            include_str!("../../testdata/systemd-v261/host-tpm2-hmac-zero-pcr.hex"),
            208,
            "0bdcda758e9b230d9274590b7f29662507b61f3625f0ff8788f451c9f10b0e9d",
            SystemdCredentialKeyId::HostAndTpm2Hmac,
            Some(0),
        ),
    ] {
        let binary = decode_committed_fixture(contents);
        assert_eq!(binary.len(), expected_length);
        assert_eq!(Sha256Digest::from_bytes(&binary).as_str(), expected_sha256);
        assert!(provenance.contains(expected_sha256));
        let encoded = base64_encode(&binary);
        let inspected = inspect_systemd_credential_envelope(&encoded).unwrap();
        assert_eq!(inspected.actual_key_id, expected_key);
        assert_eq!(inspected.literal_pcr_mask, expected_pcr);
        assert_eq!(inspected.envelope_sha256.as_str(), expected_sha256);
    }
}

#[test]
fn systemd_policy_validation_accepts_exact_bound_verifier_evidence() {
    let binary = systemd_envelope_binary(HOST_TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, false)));
    let metadata = validate_systemd_credential_envelope(
        &base64_encode(&binary),
        CredentialSelector::HostAndTpm2,
        MODE1_CREDENTIAL_NAME,
        &validation_for(&binary, MODE1_CREDENTIAL_NAME),
    )
    .unwrap();
    assert_eq!(
        metadata.actual_key_id,
        SystemdCredentialKeyId::HostAndTpm2Hmac
    );
    assert_eq!(metadata.literal_pcr_mask, Some(0));
}

#[test]
fn systemd_envelope_rejects_name_trailing_pcr_pk_scope_null_and_padding_vectors() {
    let binary = systemd_envelope_binary(HOST_ID, MODE1_CREDENTIAL_NAME, None);
    let encoded = base64_encode(&binary);
    let mut wrong_name = validation_for(&binary, "howy.storage.mode1.epochX");
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &wrong_name,
        )
        .is_err()
    );
    let mut wrong_hash = validation_for(&binary, MODE1_CREDENTIAL_NAME);
    wrong_hash.envelope_sha256 = digest(b"wrong envelope");
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &wrong_hash,
        )
        .is_err()
    );
    let mut wrong_size = validation_for(&binary, MODE1_CREDENTIAL_NAME);
    wrong_size.plaintext_size = 31;
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &wrong_size,
        )
        .is_err()
    );
    wrong_name.embedded_name = MODE1_CREDENTIAL_NAME.to_owned();
    wrong_name.authenticated = false;
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &wrong_name,
        )
        .is_err()
    );
    wrong_name.authenticated = true;
    wrong_name.exact_consumption = false;
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &wrong_name,
        )
        .is_err()
    );
    assert!(
        validate_systemd_credential_envelope(
            &encoded,
            CredentialSelector::Tpm2,
            MODE1_CREDENTIAL_NAME,
            &validation_for(&binary, MODE1_CREDENTIAL_NAME),
        )
        .is_err()
    );

    let mut trailing = binary.clone();
    trailing.extend_from_slice(b"trailing");
    assert!(
        validate_systemd_credential_envelope(
            &base64_encode(&trailing),
            CredentialSelector::Host,
            MODE1_CREDENTIAL_NAME,
            &validation_for(&trailing, MODE1_CREDENTIAL_NAME),
        )
        .is_err()
    );

    let pcr = systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((1, false)));
    assert_eq!(
        inspect_systemd_credential_envelope(&base64_encode(&pcr)),
        Err(ProvisioningContractError::CredentialPolicyRejected)
    );

    // Public-key IDs, scoped IDs, null, and unknown IDs are outside policy.
    for rejected_id in [
        [
            0xfa, 0xf7, 0xeb, 0x93, 0x41, 0xe3, 0x41, 0x2c, 0xa1, 0xa4, 0x36, 0xf9, 0x5a, 0x29,
            0x36, 0x2f,
        ],
        [
            0x55, 0xb9, 0xed, 0x1d, 0x38, 0x59, 0x4d, 0x43, 0xa8, 0x31, 0x9d, 0x2e, 0xbb, 0x33,
            0x2a, 0xc6,
        ],
        [
            0x05, 0x84, 0x69, 0xda, 0xf6, 0xf5, 0x43, 0x24, 0x80, 0x05, 0x49, 0xda, 0x0f, 0x8e,
            0xa2, 0xfb,
        ],
        [0xff; 16],
    ] {
        let rejected = systemd_envelope_binary(rejected_id, MODE1_CREDENTIAL_NAME, None);
        assert!(inspect_systemd_credential_envelope(&base64_encode(&rejected)).is_err());
    }

    let extra_pk_header = systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, true)));
    assert!(
        validate_systemd_credential_envelope(
            &base64_encode(&extra_pk_header),
            CredentialSelector::Tpm2,
            MODE1_CREDENTIAL_NAME,
            &validation_for(&extra_pk_header, MODE1_CREDENTIAL_NAME),
        )
        .is_err()
    );

    let mut bad_padding = binary;
    bad_padding[44] = 1;
    assert!(inspect_systemd_credential_envelope(&base64_encode(&bad_padding)).is_err());

    for (offset, bad_value) in [(16, 31u32), (20, 16), (24, 13), (28, 15)] {
        let mut malformed = systemd_envelope_binary(HOST_ID, MODE1_CREDENTIAL_NAME, None);
        malformed[offset..offset + 4].copy_from_slice(&bad_value.to_le_bytes());
        assert!(inspect_systemd_credential_envelope(&base64_encode(&malformed)).is_err());
    }

    let mut malformed_tpm =
        systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, false)));
    malformed_tpm[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
    assert!(inspect_systemd_credential_envelope(&base64_encode(&malformed_tpm)).is_err());
    let mut malformed_tpm =
        systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, false)));
    malformed_tpm[64..68].copy_from_slice(&31u32.to_le_bytes());
    assert!(inspect_systemd_credential_envelope(&base64_encode(&malformed_tpm)).is_err());

    let mut overflowing_tpm =
        systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, false)));
    overflowing_tpm[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(inspect_systemd_credential_envelope(&base64_encode(&overflowing_tpm)).is_err());
    for truncated_length in [0, 15, 31, 43, 47, 67, 79] {
        let fixture = systemd_envelope_binary(TPM_ID, MODE1_CREDENTIAL_NAME, Some((0, false)));
        assert!(
            inspect_systemd_credential_envelope(&base64_encode(&fixture[..truncated_length]))
                .is_err()
        );
    }

    assert!(inspect_systemd_credential_envelope(b"AAAA=").is_err());
    assert!(inspect_systemd_credential_envelope(b"AB==").is_err());
    assert!(inspect_systemd_credential_envelope(b"AA=A").is_err());
    assert!(inspect_systemd_credential_envelope(b"AA$A").is_err());
    assert_eq!(
        inspect_systemd_credential_envelope(&vec![b'A'; SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX + 1]),
        Err(ProvisioningContractError::LimitExceeded(
            "credential text bytes"
        ))
    );
    let oversized_binary = vec![0u8; SYSTEMD_CREDENTIAL_ENCRYPTED_SIZE_MAX + 1];
    assert_eq!(
        inspect_systemd_credential_envelope(&base64_encode(&oversized_binary)),
        Err(ProvisioningContractError::LimitExceeded(
            "credential envelope bytes"
        ))
    );
}

#[test]
fn official_systemd_documented_fixture_is_current_format_and_nonzero_pcr_is_refused() {
    // systemd.io/CREDENTIALS SetCredentialEncrypted example. Its first ID is
    // CRED_AES256_GCM_BY_HOST_AND_TPM2_HMAC and carries a nonzero literal PCR
    // policy, which Howy's explicit empty --tpm2-pcrs= policy must reject.
    let official = b"k6iUCUh0RJCQyvL8k8q1UyAAAAABAAAADAAAABAAAAC1lFmbWAqWZ8dCCQkAAAAAgAAAAAAAAAALACMA0AAAACAAAAAAfgAg9uNpGmj8LL2nHE0ixcycvM3XkpOCaf+9rwGscwmqRJcAEO24kB08FMtd/hfkZBX8PqoHd/yPTzRxJQBoBsvo9VqolKdy9Wkvih0HQnQ6NkTKEdPHQ08+x8sv5sr+Mkv4ubp3YT1Jvv7CIPCbNhFtag1n5y9J7bTOKt2SQwBOAAgACwAAABIAID8H3RbsT7rIBH02CIgm/Gv1ukSXO3DMHmVQkDG0wEciABAAII6LvrmL60uEZcp5qnEkxSuhUjsDoXrJs0rfSWX4QAx5PwfdFuxPusgEfTYIiCb8a/W6RJc7cMweZVCQMbTARyIAAAAAJt7Q9F/Gz0pBv1Lc4Dpn1WpebyBBm+vQ5N/lSKW2XSm8cONwCopxpDc7wJjXg7OTR6rxGCpIvGXLt3ibwJl81woLya2RRjIvc/R2zNm/yWzZAjiOLPih4SuHthqiX98ey8PUmZJBVGXglCZFjBx+d7eCqTIdghtp5pkDGwMJT6pjw4FfyFK2nJPawFKPAqzw9DK2iYttFeXi519xCfLBH9NKS/idlYXrhp+XIEtsr26s4lx5y10Goyc3qDOR3RD2cuZj0gHwV35hhhhcCzJaYytef1X/YL+7fYH5kuE4rxSksoUuA/LhtjszBeGbcbIT+O8SuvBJHLKTSHxPL8FTyk3L4FSkEHs0rYwUIkKmnGohDdsYrMJ2fjH3yDNBP16aD1+f/Nuh75cjhUnGsDLt9K4hGg==";
    assert_eq!(
        inspect_systemd_credential_envelope(official),
        Err(ProvisioningContractError::CredentialPolicyRejected)
    );
}

fn sample_patch() -> ConfigPatchV1 {
    prepare_config_enable_patch(b"[core]\ndisabled = true\n")
        .unwrap()
        .contract
}

fn fingerprint_totals(entry_count: u64, ciphertext_bytes: u64) -> NamespaceFingerprintV1 {
    NamespaceFingerprintV1 {
        sha256: digest(b"namespace"),
        entry_count,
        ciphertext_bytes,
    }
}

fn sample_receipt(state: ReceiptState) -> ProvisioningReceiptV1 {
    let patch = sample_patch();
    let config_sha256 = match state {
        ReceiptState::ProvisionedDisabled => patch.disabled_sha256.clone(),
        ReceiptState::Enabled => patch.enabled_sha256.clone(),
    };
    let envelope_sha256 = digest(b"decoded-systemd-envelope");
    ProvisioningReceiptV1 {
        schema_version: 1,
        state,
        transaction_id: "txn-0123456789abcdef".to_owned(),
        mode: 1,
        epoch: 1,
        credential_name: MODE1_CREDENTIAL_NAME.to_owned(),
        artifact: ArtifactReceipt {
            path: MODE1_CREDENTIAL_PATH.to_owned(),
            sha256: digest(b"base64-artifact-file"),
            size: 256,
            uid: 0,
            gid: 0,
            mode: 0o600,
            nlink: 1,
            credential_policy: CredentialPolicyMetadata {
                requested_selector: CredentialSelector::HostAndTpm2,
                actual_key_id: SystemdCredentialKeyId::HostAndTpm2Hmac,
                system_scope: true,
                embedded_name: MODE1_CREDENTIAL_NAME.to_owned(),
                literal_pcr_mask: Some(0),
                public_key_policy: false,
                null_key: false,
                envelope_sha256,
                envelope_size: 192,
            },
        },
        config_patch: patch,
        unit_credential: UnitCredentialReceipt {
            base_unit_sha256: digest(b"base-unit"),
            dropin_sha256: digest(b"drop-in"),
            source_companion_name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.to_owned(),
            configured_credential_source: ConfiguredMode1CredentialSource::production(),
        },
        effective_units: effective_units(digest(b"drop-in"), true),
        verifier: VerifierReceipt::new(
            VerifierResultV1::new(
                config_sha256,
                DaemonVerifierIdentityV1 {
                    version: "0.1.0".to_owned(),
                    build_identity: "howy-0.1.0+build.123".to_owned(),
                    binary_absolute_path: "/usr/bin/howyd".to_owned(),
                    binary_sha256: digest(b"howyd"),
                },
                ReadinessResultV1::new_verified(fingerprint_totals(0, 0), None).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    }
}

#[test]
fn mode1_source_companion_is_exact_nonsecret_and_policy_bound() {
    let production = ConfiguredMode1CredentialSource::parse(
        MODE1_CREDENTIAL_PATH.as_bytes(),
        Mode1CredentialSourcePolicy::Production,
    )
    .unwrap();
    assert_eq!(production.as_str(), MODE1_CREDENTIAL_PATH);
    let candidate = "/etc/credstore.encrypted/.howy.storage.mode1.epoch1.candidate";
    assert_eq!(
        ConfiguredMode1CredentialSource::parse(
            candidate.as_bytes(),
            Mode1CredentialSourcePolicy::ReadinessCandidate,
        )
        .unwrap()
        .as_str(),
        candidate
    );
    assert!(
        ConfiguredMode1CredentialSource::parse(
            candidate.as_bytes(),
            Mode1CredentialSourcePolicy::Production,
        )
        .is_err()
    );
    for invalid in [
        b"".as_slice(),
        b"relative/path".as_slice(),
        b"/etc/credstore.encrypted/../shadow".as_slice(),
        b"/etc/credstore.encrypted//double".as_slice(),
        b"/tmp/howy.storage.mode1.epoch1".as_slice(),
        b"/etc/credstore.encrypted/name\n".as_slice(),
        b"/etc/credstore.encrypted/name with space".as_slice(),
        &[0xff],
    ] {
        assert!(
            ConfiguredMode1CredentialSource::parse(
                invalid,
                Mode1CredentialSourcePolicy::ReadinessCandidate,
            )
            .is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn readiness_totals_verified_count_and_model_identity_are_consistent() {
    for impossible in [
        fingerprint_totals(0, 1),
        fingerprint_totals(1, 0),
        fingerprint_totals(1, MAX_NAMESPACE_CIPHERTEXT_BYTES + 1),
        fingerprint_totals(u64::MAX, 1),
    ] {
        assert!(impossible.validate().is_err());
    }

    let recognizer = RecognizerIdentity {
        absolute_path: "/usr/share/howy/models/recognizer.onnx".to_owned(),
        sha256: digest(b"recognizer"),
    };
    let valid = ReadinessResultV1::new_verified(
        fingerprint_totals(2, MAX_NAMESPACE_CIPHERTEXT_BYTES + 1),
        Some(recognizer.clone()),
    )
    .unwrap();
    assert_eq!(valid.record_count, 2);
    assert_eq!(valid.verified_record_count, 2);
    assert_eq!(
        valid.key_record_compatibility,
        KeyRecordCompatibility::Verified
    );

    let mut too_few = valid.clone();
    too_few.verified_record_count = 1;
    assert!(too_few.validate().is_err());
    let mut too_many = valid.clone();
    too_many.verified_record_count = 3;
    assert!(too_many.validate().is_err());
    let mut wrong_count = valid.clone();
    wrong_count.record_count = 1;
    assert!(wrong_count.validate().is_err());
    let mut wrong_compatibility = valid.clone();
    wrong_compatibility.key_record_compatibility = KeyRecordCompatibility::EmptyNotApplicable;
    assert!(wrong_compatibility.validate().is_err());
    let mut missing_model = valid;
    missing_model.recognizer = None;
    assert!(missing_model.validate().is_err());
    assert!(ReadinessResultV1::new_verified(fingerprint_totals(0, 0), Some(recognizer)).is_err());

    let empty = ReadinessResultV1::new_verified(fingerprint_totals(0, 0), None).unwrap();
    assert_eq!(empty.record_count, 0);
    assert_eq!(empty.verified_record_count, 0);
    assert_eq!(empty.namespace.ciphertext_bytes, 0);
    assert_eq!(
        empty.key_record_compatibility,
        KeyRecordCompatibility::EmptyNotApplicable
    );
    assert!(empty.recognizer.is_none());

    let mut empty_claims_verified = empty;
    empty_claims_verified.key_record_compatibility = KeyRecordCompatibility::Verified;
    assert!(empty_claims_verified.validate().is_err());
}

#[test]
fn verifier_result_is_bounded_deterministic_and_strict() {
    let result = VerifierResultV1::new(
        digest(b"config"),
        DaemonVerifierIdentityV1 {
            version: "0.1.0".to_owned(),
            build_identity: "howy-0.1.0+test".to_owned(),
            binary_absolute_path: "/usr/bin/howyd".to_owned(),
            binary_sha256: digest(b"binary"),
        },
        ReadinessResultV1::new_verified(fingerprint_totals(0, 0), None).unwrap(),
    )
    .unwrap();
    let bytes = result.deterministic_bytes().unwrap();
    assert_eq!(VerifierResultV1::parse(&bytes).unwrap(), result);
    assert_eq!(
        result.deterministic_sha256().unwrap().as_str(),
        "b0945f6b93cf03c445c23263514fe4542ca758e71618a23eb4c50afc04c007d1"
    );

    let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    malformed["readiness"]["key_record_compatibility"] = serde_json::json!("unknown");
    assert!(VerifierResultV1::parse(&serde_json::to_vec(&malformed).unwrap()).is_err());
    malformed["readiness"]["key_record_compatibility"] = serde_json::json!("empty-not-applicable");
    malformed["unexpected"] = serde_json::json!(true);
    assert!(VerifierResultV1::parse(&serde_json::to_vec(&malformed).unwrap()).is_err());
    assert_eq!(
        VerifierResultV1::parse(&vec![b' '; MAX_VERIFIER_RESULT_BYTES + 1]),
        Err(ProvisioningContractError::LimitExceeded(
            "verifier result bytes"
        ))
    );

    let mut receipt = VerifierReceipt::new(result).unwrap();
    receipt.output.daemon.version.push('x');
    assert!(receipt.validate().is_err());
}

#[test]
fn receipt_is_strict_deterministic_nonsecret_and_transitions_exactly() {
    let disabled = sample_receipt(ReceiptState::ProvisionedDisabled);
    let enabled = sample_receipt(ReceiptState::Enabled);
    disabled.validate().unwrap();
    enabled.validate().unwrap();
    validate_receipt_transition(&disabled, &enabled).unwrap();
    let bytes = disabled.deterministic_bytes().unwrap();
    let golden = include_bytes!("../../testdata/provisioning-receipt-v1.golden.json")
        .strip_suffix(b"\n")
        .unwrap_or(include_bytes!(
            "../../testdata/provisioning-receipt-v1.golden.json"
        ));
    assert_eq!(bytes, golden);
    assert!(!bytes.windows(9).any(|window| window == b"plaintext"));
    assert_eq!(
        disabled.deterministic_sha256().unwrap().as_str(),
        "6dbe82988cb0db5dce5e354d9da8f949e0774962405b77f628a72d8edde767ac"
    );
    let parsed = ProvisioningReceiptV1::parse(&bytes).unwrap();
    assert_eq!(parsed, disabled);
    assert_eq!(parsed.deterministic_bytes().unwrap(), bytes);

    let mut secret: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    secret["rollback_config_bytes"] = serde_json::json!("forbidden");
    assert!(ProvisioningReceiptV1::parse(&serde_json::to_vec(&secret).unwrap()).is_err());

    let mut bad_transition = enabled.clone();
    bad_transition.artifact.size += 1;
    assert!(validate_receipt_transition(&disabled, &bad_transition).is_err());

    let mut bad_cache = disabled;
    bad_cache.verifier.output.readiness.cache_population_count = 1;
    assert!(bad_cache.validate().is_err());

    assert_eq!(
        ProvisioningReceiptV1::parse(&vec![b' '; MAX_RECEIPT_BYTES + 1]),
        Err(ProvisioningContractError::LimitExceeded("receipt bytes"))
    );
}

fn namespace_entry(name: &[u8], size: u64) -> NamespaceFingerprintEntry {
    let file_type = NamespaceFileType::Regular;
    let nlink = 1;
    NamespaceFingerprintEntry {
        name: name.to_vec(),
        file_type,
        uid: 0,
        gid: 0,
        mode: 0o600,
        nlink,
        size,
        ciphertext_sha256: digest(name),
        classification: classify_mode1_namespace_entry(name, file_type, nlink),
    }
}

fn inventory(entries: Vec<NamespaceFingerprintEntry>) -> NamespaceInventoryV1 {
    NamespaceInventoryV1 {
        directory: NamespaceDirectoryMetadata {
            path: MODE1_NAMESPACE_PATH.to_owned(),
            uid: 0,
            gid: 0,
            mode: 0o700,
            nlink: 2,
        },
        entries,
    }
}

#[test]
fn namespace_classifier_has_canonical_and_explicit_rejection_classes() {
    assert_eq!(
        classify_mode1_namespace_entry(b"alice.hye", NamespaceFileType::Regular, 1),
        NamespaceEntryClassification::Authoritative {
            username: "alice".to_owned()
        }
    );
    assert_eq!(
        classify_mode1_namespace_entry(b"alice.tmp.user.hye", NamespaceFileType::Regular, 1),
        NamespaceEntryClassification::Authoritative {
            username: "alice.tmp.user".to_owned()
        }
    );
    for (name, file_type, nlink, expected) in [
        (
            b".alice.hye.tmp.00112233445566778899aabbccddeeff".as_slice(),
            NamespaceFileType::Regular,
            1,
            NamespaceEntryClassification::Temporary,
        ),
        (
            b".alice.hye.staged.00112233445566778899aabbccddeeff".as_slice(),
            NamespaceFileType::Regular,
            1,
            NamespaceEntryClassification::Staged,
        ),
        (
            b"alice.bin".as_slice(),
            NamespaceFileType::Regular,
            1,
            NamespaceEntryClassification::Clear,
        ),
        (
            b".alice.hye.rollback.00112233445566778899aabbccddeeff".as_slice(),
            NamespaceFileType::Regular,
            1,
            NamespaceEntryClassification::Rollback,
        ),
        (
            b"alice.hye".as_slice(),
            NamespaceFileType::Symlink,
            1,
            NamespaceEntryClassification::Symlink,
        ),
        (
            b"alice.hye".as_slice(),
            NamespaceFileType::Directory,
            1,
            NamespaceEntryClassification::Directory,
        ),
        (
            b"alice.hye".as_slice(),
            NamespaceFileType::Regular,
            2,
            NamespaceEntryClassification::Hardlink,
        ),
        (
            b"alice.txt".as_slice(),
            NamespaceFileType::Regular,
            1,
            NamespaceEntryClassification::Unknown,
        ),
    ] {
        assert_eq!(
            classify_mode1_namespace_entry(name, file_type, nlink),
            expected
        );
    }
    assert_eq!(
        classify_mode1_namespace_entry(&[0xff], NamespaceFileType::Regular, 1),
        NamespaceEntryClassification::NonUtf8
    );
}

#[test]
fn mode1_transaction_artifact_names_match_exact_current_bounded_forms() {
    let suffix = "00112233445566778899aabbccddeeff";
    for (marker, expected) in [
        ("tmp", NamespaceEntryClassification::Temporary),
        ("staged", NamespaceEntryClassification::Staged),
        ("clear", NamespaceEntryClassification::Clear),
        ("rollback", NamespaceEntryClassification::Rollback),
    ] {
        let name = format!(".alice.hye.{marker}.{suffix}");
        assert_eq!(
            classify_mode1_namespace_entry(name.as_bytes(), NamespaceFileType::Regular, 1),
            expected
        );
        assert_eq!(
            classified_mode1_transaction_username(name.as_bytes(), &expected).as_deref(),
            Some("alice")
        );
        for invalid in [
            format!("alice.hye.{marker}.{suffix}"),
            format!(".alice.hye.{marker}.{}", &suffix[..31]),
            format!(".alice.hye.{marker}.{suffix}0"),
            format!(".alice.hye.{marker}.00112233445566778899AABBCCDDEEFF"),
            format!(".bad/name.hye.{marker}.{suffix}"),
        ] {
            assert_eq!(
                classify_mode1_namespace_entry(invalid.as_bytes(), NamespaceFileType::Regular, 1),
                NamespaceEntryClassification::Unknown,
                "unexpected classification for {invalid}"
            );
        }
    }
}

#[test]
fn namespace_fingerprint_is_framed_order_independent_and_ambiguous_inputs_diverge() {
    let first = inventory(vec![
        namespace_entry(b"alice.hye", 11),
        namespace_entry(b"bob.hye", 22),
    ]);
    let reversed = inventory(vec![
        namespace_entry(b"bob.hye", 22),
        namespace_entry(b"alice.hye", 11),
    ]);
    validate_readiness_inventory(&first).unwrap();
    assert_eq!(
        namespace_fingerprint(&first).unwrap(),
        namespace_fingerprint(&reversed).unwrap()
    );
    let frame = encode_namespace_fingerprint_frame(&first).unwrap();
    assert!(frame.starts_with(NAMESPACE_DOMAIN));
    let fingerprint = namespace_fingerprint(&first).unwrap();
    assert_eq!(fingerprint.entry_count, 2);
    assert_eq!(fingerprint.ciphertext_bytes, 33);
    assert_eq!(
        fingerprint.sha256.as_str(),
        "6d6b933fba523e50ea075df773350b59a5c4df27dc5aa7e4ad99bf65bdb340f0"
    );

    let structurally_different = inventory(vec![
        namespace_entry(b"ali.ce.hye", 1),
        namespace_entry(b"bob.hye", 32),
    ]);
    assert_ne!(
        namespace_fingerprint(&first).unwrap().sha256,
        namespace_fingerprint(&structurally_different)
            .unwrap()
            .sha256
    );
}

#[test]
fn namespace_bounds_duplicates_and_rejection_entries_fail_closed() {
    let too_long = vec![b'a'; MAX_NAMESPACE_NAME_BYTES + 1];
    assert!(namespace_fingerprint(&inventory(vec![namespace_entry(&too_long, 1)])).is_err());
    assert!(
        namespace_fingerprint(&inventory(vec![
            namespace_entry(b"alice.hye", 1),
            namespace_entry(b"alice.hye", 1),
        ]))
        .is_err()
    );
    let rejected = inventory(vec![namespace_entry(
        b".alice.hye.tmp.00112233445566778899aabbccddeeff",
        1,
    )]);
    namespace_fingerprint(&rejected).unwrap();
    assert!(validate_readiness_inventory(&rejected).is_err());

    let too_many = (0..=MAX_NAMESPACE_ENTRIES)
        .map(|index| namespace_entry(format!("user{index:04}.hye").as_bytes(), 1))
        .collect();
    assert!(namespace_fingerprint(&inventory(too_many)).is_err());

    let oversized = inventory(vec![namespace_entry(
        b"alice.hye",
        MAX_NAMESPACE_CIPHERTEXT_BYTES + 1,
    )]);
    assert!(namespace_fingerprint(&oversized).is_err());

    let total_too_large = (0..MAX_NAMESPACE_ENTRIES)
        .map(|index| {
            namespace_entry(
                format!("user{index:04}.hye").as_bytes(),
                MAX_NAMESPACE_TOTAL_BYTES / MAX_NAMESPACE_ENTRIES as u64 + 1,
            )
        })
        .collect();
    assert!(namespace_fingerprint(&inventory(total_too_large)).is_err());
}

#[test]
fn provisioning_state_table_is_total_and_nonempty_new_key_always_refuses() {
    let classify = |config, artifact, namespace_nonempty, new_key_requested| {
        classify_provisioning_state(ProvisioningStateInput {
            config,
            artifact,
            namespace_nonempty,
            new_key_requested,
            adopt_existing: false,
        })
    };
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Absent,
            ExistingProvisioningArtifact::Absent,
            false,
            false
        ),
        ProvisioningState::Fresh
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 },
            ExistingProvisioningArtifact::Verified,
            false,
            false
        ),
        ProvisioningState::Idempotent
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Absent,
            ExistingProvisioningArtifact::Verified,
            false,
            false
        ),
        ProvisioningState::Unadopted
    );
    assert_eq!(
        classify_provisioning_state(ProvisioningStateInput {
            config: ExistingProvisioningConfig::Absent,
            artifact: ExistingProvisioningArtifact::Verified,
            namespace_nonempty: false,
            new_key_requested: false,
            adopt_existing: true,
        }),
        ProvisioningState::Adopt
    );
    assert_eq!(
        classify_provisioning_state(ProvisioningStateInput {
            config: ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 },
            artifact: ExistingProvisioningArtifact::Unverified,
            namespace_nonempty: true,
            new_key_requested: false,
            adopt_existing: true,
        }),
        ProvisioningState::Adopt
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Explicit { mode: 1, epoch: 2 },
            ExistingProvisioningArtifact::Verified,
            false,
            false
        ),
        ProvisioningState::Mismatch
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 },
            ExistingProvisioningArtifact::Absent,
            false,
            false
        ),
        ProvisioningState::Missing
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 },
            ExistingProvisioningArtifact::Unverified,
            true,
            false
        ),
        ProvisioningState::Nonempty
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Absent,
            ExistingProvisioningArtifact::Absent,
            true,
            true
        ),
        ProvisioningState::NewKey
    );
    assert_eq!(
        classify(
            ExistingProvisioningConfig::Explicit { mode: 0, epoch: 1 },
            ExistingProvisioningArtifact::Verified,
            false,
            false
        ),
        ProvisioningState::DifferentMode(DifferentModeArtifactState::Receipted)
    );

    for config in [
        ExistingProvisioningConfig::Absent,
        ExistingProvisioningConfig::Explicit { mode: 1, epoch: 1 },
        ExistingProvisioningConfig::Explicit { mode: 0, epoch: 1 },
    ] {
        for artifact in [
            ExistingProvisioningArtifact::Absent,
            ExistingProvisioningArtifact::Verified,
            ExistingProvisioningArtifact::Unverified,
            ExistingProvisioningArtifact::Mismatch,
        ] {
            let expected = match config {
                ExistingProvisioningConfig::Explicit { mode: 0, .. } => {
                    ProvisioningState::DifferentMode(match artifact {
                        ExistingProvisioningArtifact::Absent => DifferentModeArtifactState::Absent,
                        ExistingProvisioningArtifact::Verified => {
                            DifferentModeArtifactState::Receipted
                        }
                        ExistingProvisioningArtifact::Unverified => {
                            DifferentModeArtifactState::Unadopted
                        }
                        ExistingProvisioningArtifact::Mismatch => {
                            DifferentModeArtifactState::Mismatch
                        }
                    })
                }
                _ => ProvisioningState::NewKey,
            };
            assert_eq!(classify(config, artifact, true, true), expected);
        }
    }
}

#[test]
fn different_mode_classifier_exhaustively_preserves_artifact_adoption_state() {
    let artifacts = [
        ExistingProvisioningArtifact::Absent,
        ExistingProvisioningArtifact::Verified,
        ExistingProvisioningArtifact::Unverified,
        ExistingProvisioningArtifact::Mismatch,
    ];
    for artifact in artifacts {
        for namespace_nonempty in [false, true] {
            for new_key_requested in [false, true] {
                for adopt_existing in [false, true] {
                    let actual = classify_provisioning_state(ProvisioningStateInput {
                        config: ExistingProvisioningConfig::Explicit { mode: 0, epoch: 1 },
                        artifact,
                        namespace_nonempty,
                        new_key_requested,
                        adopt_existing,
                    });
                    let expected = match artifact {
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
                    };
                    assert_eq!(actual, expected);
                    assert_ne!(actual, ProvisioningState::Idempotent);
                }
            }
        }
    }
}

fn observation(active_state: UnitActiveState, sub_state: UnitSubState) -> UnitObservation {
    UnitObservation {
        unit_kind: UnitKind::Service,
        load_state: UnitLoadState::Loaded,
        active_state,
        sub_state,
        unit_file_state: UnitFileState::Enabled,
        has_queued_job: false,
    }
}

#[test]
fn unit_admissibility_settles_refuses_and_never_changes_enablement() {
    assert_eq!(
        classify_unit_admissibility(observation(UnitActiveState::Active, UnitSubState::Running)),
        UnitAdmissibility::Admissible {
            rollback_target: StableRollbackTarget::ActiveRunning,
            mutate_enablement: false,
        }
    );
    assert_eq!(
        classify_unit_admissibility(observation(UnitActiveState::Inactive, UnitSubState::Dead)),
        UnitAdmissibility::Admissible {
            rollback_target: StableRollbackTarget::InactiveDead,
            mutate_enablement: false,
        }
    );
    let mut socket = observation(UnitActiveState::Active, UnitSubState::Listening);
    socket.unit_kind = UnitKind::Socket;
    assert_eq!(
        classify_unit_admissibility(socket),
        UnitAdmissibility::Admissible {
            rollback_target: StableRollbackTarget::ActiveListening,
            mutate_enablement: false,
        }
    );
    assert_eq!(
        classify_unit_admissibility(observation(
            UnitActiveState::Activating,
            UnitSubState::Start
        )),
        UnitAdmissibility::Settle
    );
    assert_eq!(
        classify_unit_admissibility(observation(UnitActiveState::Failed, UnitSubState::Failed)),
        UnitAdmissibility::RefuseFailed
    );
    let mut masked = observation(UnitActiveState::Inactive, UnitSubState::Dead);
    masked.unit_file_state = UnitFileState::Masked;
    assert_eq!(
        classify_unit_admissibility(masked),
        UnitAdmissibility::RefuseMasked
    );
}

fn cleanup_artifact_identity() -> CleanupArtifactIdentityV1 {
    CleanupArtifactIdentityV1 {
        transaction_id: "txn-0123456789abcdef0123456789abcdef".to_owned(),
        descriptor: ArtifactDescriptorIdentityV1 {
            path: MODE1_CREDENTIAL_PATH.to_owned(),
            device_id: 8,
            inode: 84,
            sha256: digest(b"credential artifact text"),
            byte_length: 256,
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions: 0o600,
            link_count: 1,
            parent_directory: DirectoryIdentityV1 {
                path: MODE1_CREDENTIAL_DIRECTORY.to_owned(),
                object_type: FileObjectType::Directory,
                device_id: 8,
                inode: 42,
                uid: 0,
                gid: 0,
                permissions: 0o700,
                link_count: 2,
            },
        },
        source: CredentialArtifactSourceIdentityV1 {
            credential_name: MODE1_CREDENTIAL_NAME.to_owned(),
            envelope_sha256: digest(b"decoded credential envelope"),
            envelope_size: 192,
            actual_key_id: SystemdCredentialKeyId::HostAndTpm2Hmac,
        },
    }
}

fn cleanup_input() -> CleanupStateInput {
    let mut socket = observation(UnitActiveState::Inactive, UnitSubState::Dead);
    socket.unit_kind = UnitKind::Socket;
    let identity = cleanup_artifact_identity();
    CleanupStateInput {
        expected_artifact: ExpectedCleanupArtifactIdentityV1(identity.clone()),
        observed_artifact: ObservedCleanupArtifactIdentityV1(identity),
        references: CleanupReferences::default(),
        service: observation(UnitActiveState::Inactive, UnitSubState::Dead),
        socket,
        readiness_transient_exists: false,
        daemon_responded: false,
    }
}

#[test]
fn cleanup_identity_rejects_swap_path_hash_metadata_and_adoption_races() {
    let mut input = cleanup_input();
    input.observed_artifact.0.transaction_id = "txn-ffffffffffffffffffffffffffffffff".to_owned();
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::TransactionMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.path =
        "/etc/credstore.encrypted/replaced-artifact".to_owned();
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::PathMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.inode += 1;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::ObjectIdentityMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.sha256 = digest(b"swapped bytes");
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::HashMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.byte_length += 1;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::LengthMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.object_type = FileObjectType::Symlink;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::TypeMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.uid = 1000;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::OwnershipMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.permissions = 0o640;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::ModeMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.link_count = 2;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::LinkMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.descriptor.parent_directory.inode += 1;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::DirectoryMismatch)
    );

    let mut input = cleanup_input();
    input.observed_artifact.0.source.envelope_sha256 = digest(b"adopted replacement");
    input.observed_artifact.0.source.actual_key_id = SystemdCredentialKeyId::Host;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::SourceMismatch)
    );
}

#[test]
fn unadopted_manifest_is_strict_bounded_and_descriptor_bound() {
    let manifest = UnadoptedArtifactV1::new(cleanup_artifact_identity()).unwrap();
    let bytes = manifest.deterministic_bytes().unwrap();
    assert_eq!(UnadoptedArtifactV1::parse(&bytes).unwrap(), manifest);

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["rm_command"] = serde_json::json!("rm /etc/credstore.encrypted/key");
    assert!(UnadoptedArtifactV1::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut invalid = manifest;
    invalid.identity.descriptor.link_count = 2;
    assert!(invalid.validate().is_err());
}

#[test]
fn cleanup_requires_no_references_jobs_transients_daemon_or_live_units() {
    assert_eq!(
        classify_cleanup_admissibility(cleanup_input()),
        CleanupAdmissibility::Admissible
    );
    let mut input = cleanup_input();
    input.references.receipt = true;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::ReceiptReference)
    );
    let mut input = cleanup_input();
    input.socket.has_queued_job = true;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::UnitJobQueued)
    );
    let mut input = cleanup_input();
    input.service = observation(UnitActiveState::Active, UnitSubState::Running);
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::UnitNotInactive)
    );
    let mut input = cleanup_input();
    input.readiness_transient_exists = true;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::ReadinessTransient)
    );
    let mut input = cleanup_input();
    input.daemon_responded = true;
    assert_eq!(
        classify_cleanup_admissibility(input),
        CleanupAdmissibility::Refuse(CleanupRefusal::DaemonReference)
    );
}
