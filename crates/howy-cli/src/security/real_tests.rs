use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};

use super::*;
use crate::security::engine::{
    CleanupRequest, ProvisionMode, ProvisionRequest, SecretKeyMaterial, SecurityEngine,
    SecurityRuntime,
};
use howy_common::config::EmbeddingSecurityMode;
use howy_common::provisioning::{JournalPhase, SECURITY_RECEIPT_PATH};

const VALID_TRANSACTION: &str = "txn-0123456789abcdef0123456789abcdef";
const VALID_UNIT: &str = "howy-readiness-txn-0123456789abcdef0123456789abcdef.service";
const PERL: &str = "/usr/bin/perl";

fn perl_spec(
    script: &str,
    stdin_bytes: usize,
    stdout_cap: usize,
    stderr_cap: usize,
    deadline: Duration,
) -> CommandSpec {
    CommandSpec {
        executable: PERL.into(),
        arguments: vec!["-e".into(), script.into()],
        clear_environment: true,
        stdin_bytes,
        stdout_cap,
        stderr_cap,
        deadline,
    }
}

fn exited(code: i32, stdout: &[u8]) -> ProcessOutput {
    ProcessOutput {
        stdout: stdout.to_vec(),
        stderr: Vec::new(),
        status: ExitStatus::from_raw(code << 8),
    }
}

fn process_error(result: SecurityResult<ProcessOutput>) -> SecurityError {
    match result {
        Ok(_) => panic!("child transport unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn transient_output(load: &str, active: &str, sub: &str) -> Vec<u8> {
    format!("LoadState={load}\nActiveState={active}\nSubState={sub}\n").into_bytes()
}

#[test]
fn transient_unit_name_is_exactly_the_canonical_generated_form() {
    assert_eq!(command::readiness_unit_name(VALID_TRANSACTION), VALID_UNIT);
    assert!(valid_transient_unit_name(VALID_UNIT));

    for invalid in [
        "howy-readiness-txn-0123456789abcdef.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcde.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcdef0.service",
        "howy-readiness-TXN-0123456789abcdef0123456789abcdef.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcdeF.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcdeg.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcdef.service.extra",
        "howy-readiness-txn-0123456789abcdef/123456789abcdef.service",
        "howy-readiness-txn-0123456789abcdef\\123456789abcdef.service",
        "howy-readiness-txn-0123456789abcdef0123456789abcdeé.service",
    ] {
        assert!(!valid_transient_unit_name(invalid), "accepted {invalid:?}");
    }

    let spec = command::readiness_command(
        VALID_TRANSACTION,
        "/etc/howy/config.toml",
        MODE1_CREDENTIAL_PATH,
    );
    assert_eq!(readiness_unit_from_command(&spec).unwrap(), VALID_UNIT);
    let mut duplicate = spec.clone();
    duplicate.arguments.push(format!("--unit={VALID_UNIT}"));
    assert!(readiness_unit_from_command(&duplicate).is_err());
}

#[test]
fn transient_state_parser_accepts_only_exact_bounded_framing() {
    assert_eq!(
        parse_transient_state(&transient_output("not-found", "inactive", "dead")).unwrap(),
        TransientState {
            load: TransientLoadState::NotFound,
            active: TransientActiveState::Inactive,
            sub: TransientSubState::Dead,
        }
    );
    assert!(
        parse_transient_state(&transient_output("loaded", "deactivating", "stop-sigterm")).is_ok()
    );

    let malformed = [
        b"LoadState=loaded\nActiveState=inactive\nSubState=dead".to_vec(),
        b"LoadState=loaded\r\nActiveState=inactive\nSubState=dead\n".to_vec(),
        b"LoadState=loaded\nActiveState=inactive\nSubState=de\tad\n".to_vec(),
        b"LoadState=loaded\nActiveState=inactive\n".to_vec(),
        b"LoadState=loaded\nActiveState=inactive\nSubState=dead\nExtra=x\n".to_vec(),
        b"LoadState=loaded\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n".to_vec(),
        b"LoadState=loaded\nActiveState=unknown\nSubState=dead\n".to_vec(),
        b"LoadState=not-found\nActiveState=failed\nSubState=failed\n".to_vec(),
        vec![0xff, b'\n'],
        vec![b'x'; TRANSIENT_STATE_MAX + 1],
    ];
    for bytes in malformed {
        assert!(parse_transient_state(&bytes).is_err(), "accepted {bytes:?}");
    }
}

#[test]
fn transient_cleanup_uses_one_deadline_and_observes_exact_transitions() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut states = VecDeque::from([
        transient_output("loaded", "deactivating", "stop-sigterm"),
        transient_output("loaded", "inactive", "dead"),
    ]);
    let mut commands = Vec::new();
    cleanup_transient_with(VALID_UNIT, deadline, |arguments, operation_deadline| {
        assert_eq!(operation_deadline, deadline);
        commands.push(arguments.clone());
        if arguments.first().is_some_and(|argument| argument == "show") {
            Ok(exited(0, &states.pop_front().unwrap()))
        } else {
            Ok(exited(0, b""))
        }
    })
    .unwrap();

    assert_eq!(commands[0], ["--no-block", "stop", VALID_UNIT]);
    assert_eq!(commands[1][0], "kill");
    assert_eq!(commands[2], ["reset-failed", VALID_UNIT]);
    assert_eq!(
        commands
            .iter()
            .filter(|arguments| arguments.first().is_some_and(|value| value == "show"))
            .count(),
        2
    );
}

#[test]
fn transient_cleanup_does_not_hide_stop_failure_behind_loaded_dead_state() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut call = 0;
    let error = cleanup_transient_with(VALID_UNIT, deadline, |arguments, _| {
        call += 1;
        if call == 1 {
            Ok(exited(1, b""))
        } else if arguments.first().is_some_and(|argument| argument == "show") {
            Ok(exited(0, &transient_output("loaded", "inactive", "dead")))
        } else {
            Ok(exited(0, b""))
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("failed cleanup controls"));
}

#[test]
fn child_transport_is_exact_concurrent_and_environment_free() {
    let input = b"credential-input";
    let runtime = RealSecurityRuntime::new();
    let output = runtime
        .run(
            &perl_spec(
                "binmode STDIN; binmode STDOUT; local $/; my $x = <STDIN>; print STDOUT $x; print STDERR qq(redacted);",
                input.len(),
                input.len(),
                64,
                Duration::from_secs(2),
            ),
            input,
        )
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.into_stdout(), input);

    let environment = runtime
        .run(
            &perl_spec("print scalar(keys %ENV);", 0, 8, 8, Duration::from_secs(2)),
            b"",
        )
        .unwrap()
        .into_stdout();
    assert_eq!(environment, b"0");
}

#[test]
fn child_transport_enforces_cap_plus_one_and_both_flood_caps_while_running() {
    let runtime = RealSecurityRuntime::new();
    let error = process_error(runtime.run(
        &perl_spec(
            "syswrite STDOUT, q(x) x 17; select undef, undef, undef, 5;",
            0,
            16,
            16,
            Duration::from_secs(2),
        ),
        b"",
    ));
    assert!(error.to_string().contains("hard cap"));

    let error = process_error(runtime.run(
        &perl_spec(
            "syswrite STDERR, q(e) x 17; select undef, undef, undef, 5;",
            0,
            16,
            16,
            Duration::from_secs(2),
        ),
        b"",
    ));
    assert!(error.to_string().contains("hard cap"));

    let started = Instant::now();
    let error = process_error(runtime.run(
            &perl_spec(
                "my $p = fork(); if ($p == 0) { while (1) { print STDOUT q(o) x 4096; } } else { while (1) { print STDERR q(e) x 4096; } }",
                0,
                1_024,
                1_024,
                Duration::from_secs(2),
            ),
            b"",
        ));
    assert!(error.to_string().contains("hard cap"));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn child_transport_reports_stdin_epipe_without_waiting_for_deadline() {
    let input = vec![0x5a; 1024 * 1024];
    let started = Instant::now();
    let error = process_error(RealSecurityRuntime::new().run(
        &perl_spec(
            "close STDIN; select undef, undef, undef, 5;",
            input.len(),
            0,
            0,
            Duration::from_secs(2),
        ),
        &input,
    ));
    assert!(error.to_string().contains("closed key input early"));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn child_transport_kills_descendant_that_retains_captured_descriptors() {
    let started = Instant::now();
    let output = RealSecurityRuntime::new()
        .run(
            &perl_spec(
                "my $p = fork(); if ($p == 0) { sleep 30; exit 0; } print qq($p\\n); exit 0;",
                0,
                64,
                64,
                Duration::from_secs(2),
            ),
            b"",
        )
        .unwrap()
        .into_stdout();
    assert!(started.elapsed() < Duration::from_secs(1));
    let pid: libc::pid_t = std::str::from_utf8(&output)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_ne!(unsafe { libc::kill(pid, 0) }, 0);
}

#[test]
fn child_transport_deadline_and_signal_paths_are_bounded() {
    let runtime = RealSecurityRuntime::new();
    for _ in 0..5 {
        let started = Instant::now();
        let error = process_error(runtime.run(
            &perl_spec(
                "select undef, undef, undef, 10;",
                0,
                0,
                0,
                Duration::from_millis(80),
            ),
            b"",
        ));
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(750));
    }

    let error = process_error(runtime.run(
        &perl_spec(
            "kill 15, $$; select undef, undef, undef, 1;",
            0,
            0,
            0,
            Duration::from_secs(2),
        ),
        b"",
    ));
    assert!(error.to_string().contains("status"));
}

#[test]
fn child_transport_rejects_nonabsolute_or_unvalidated_executables() {
    let mut spec = perl_spec("exit 0;", 0, 0, 0, Duration::from_secs(1));
    spec.executable = "perl".into();
    assert!(RealSecurityRuntime::new().run(&spec, b"").is_err());
}

fn service_show(dropins: &str) -> Vec<u8> {
    format!(
        "FragmentPath={BASE_SERVICE_UNIT_PATH}\n\
DropInPaths={dropins}\n\
NeedDaemonReload=no\n\
LimitCORE=0\n\
LimitMEMLOCK=65536\n\
LockPersonality=yes\n\
MemoryDenyWriteExecute=no\n\
NoNewPrivileges=yes\n\
PrivateTmp=yes\n\
ProtectControlGroups=yes\n\
ProtectHome=read-only\n\
ProtectKernelModules=yes\n\
ProtectKernelTunables=yes\n\
ProtectSystem=strict\n\
RestrictAddressFamilies=AF_UNIX\n\
RestrictNamespaces=yes\n\
RestrictRealtime=yes\n\
UMask=0077\n"
    )
    .into_bytes()
}

#[test]
fn effective_show_parser_is_strict_and_rejects_unknown_later_dropins() {
    let show = parse_effective_show(UnitKind::Service, &service_show(MODE1_DROPIN_PATH)).unwrap();
    assert_eq!(show.fragment_path, BASE_SERVICE_UNIT_PATH);
    assert_eq!(show.dropin_paths, [MODE1_DROPIN_PATH]);
    validate_effective_paths(UnitKind::Service, &show).unwrap();

    for malformed in [
        {
            let mut bytes = service_show(MODE1_DROPIN_PATH);
            bytes.pop();
            bytes
        },
        service_show("/etc/systemd/system/howy.service.d/../50-security.conf"),
        service_show("/etc/systemd/system/howy.service.d/50-security.conf\\x20"),
        {
            let mut bytes = service_show(MODE1_DROPIN_PATH);
            bytes.extend_from_slice(b"Unknown=value\n");
            bytes
        },
        {
            let mut bytes = service_show(MODE1_DROPIN_PATH);
            bytes.extend_from_slice(b"UMask=0077\n");
            bytes
        },
        {
            let mut bytes = service_show(MODE1_DROPIN_PATH);
            bytes[0] = 0xff;
            bytes
        },
    ] {
        assert!(parse_effective_show(UnitKind::Service, &malformed).is_err());
    }

    let unknown = EffectiveShow {
        fragment_path: BASE_SERVICE_UNIT_PATH.into(),
        dropin_paths: vec![
            MODE1_DROPIN_PATH.into(),
            "/etc/systemd/system/howy.service.d/99-shadow.conf".into(),
        ],
    };
    assert!(validate_effective_paths(UnitKind::Service, &unknown).is_err());
    let socket_override = EffectiveShow {
        fragment_path: BASE_SOCKET_UNIT_PATH.into(),
        dropin_paths: vec!["/etc/systemd/system/howy.socket.d/override.conf".into()],
    };
    assert!(validate_effective_paths(UnitKind::Socket, &socket_override).is_err());
}

#[test]
fn repository_units_and_exact_security_dropins_parse_to_reviewed_policy() {
    assert_eq!(
        Sha256Digest::from_bytes(BASE_SERVICE_UNIT_BYTES).as_str(),
        "f63421b404da8963892196f7d2711abfa715ae28efc243e34f56a843a55d7734"
    );
    assert_eq!(
        Sha256Digest::from_bytes(BASE_SOCKET_UNIT_BYTES).as_str(),
        "e76f8332c0ccb8d842acc81bd5f7e38c68f2d7a667cae228877cb78016eb7b85"
    );
    assert_eq!(
        Sha256Digest::from_bytes(MODE0_DROPIN_BYTES).as_str(),
        "167230a67d896d4f67380f837f680c6b157e934b7d516af90bbc43f60f63cf10"
    );
    assert_eq!(
        Sha256Digest::from_bytes(MODE1_DROPIN_BYTES).as_str(),
        "4d42d0000d5f3ff0a22c7b83ce4b7f9ade1a84f609a3539550d13ce29e93b42e"
    );
    let mut service = ParsedEffectivePolicy::default();
    parse_effective_file(
        UnitKind::Service,
        false,
        include_bytes!("../../../../systemd/howy.service"),
        &mut service,
    )
    .unwrap();
    assert_eq!(service.conditions, required_unit_conditions());
    assert_eq!(service.exec_start, [vec![String::from(command::HOWYD)]]);
    assert_eq!(service.hardening, required_service_hardening());
    assert!(service.load_credentials.is_empty());

    parse_effective_file(UnitKind::Service, true, MODE1_DROPIN_BYTES, &mut service).unwrap();
    assert_eq!(
        service.load_credentials,
        [EffectiveCredentialLoadV1 {
            name: MODE1_CREDENTIAL_NAME.into(),
            source: MODE1_CREDENTIAL_PATH.into(),
        }]
    );
    assert_eq!(
        service.set_credentials,
        [EffectiveSetCredentialV1 {
            name: MODE1_CREDENTIAL_SOURCE_COMPANION_NAME.into(),
            value: MODE1_CREDENTIAL_PATH.into(),
        }]
    );

    let mut socket = ParsedEffectivePolicy::default();
    parse_effective_file(
        UnitKind::Socket,
        false,
        include_bytes!("../../../../systemd/howy.socket"),
        &mut socket,
    )
    .unwrap();
    assert_eq!(socket.conditions, required_unit_conditions());
    assert!(socket.exec_start.is_empty());

    for malformed in [
        b"[Service]\nLoadCredentialEncrypted=\nLoadCredentialEncrypted=howy.storage.mode1.epoch1\nSetCredential=\n"
            .as_slice(),
        b"[Service]\nLoadCredentialEncrypted=howy.storage.mode1.epoch1:/tmp/key\nSetCredential=\n"
            .as_slice(),
        b"[Service]\nLoadCredentialEncrypted=\nSetCredential=\nExecStart=/bin/sh\n".as_slice(),
        b"[Service]\nLoadCredentialEncrypted=\nSetCredential=\nExecStartPre=/bin/sh\n".as_slice(),
        b"[Service]\nLoadCredentialEncrypted=\nSetCredential=\nNoNewPrivileges=no\n".as_slice(),
        b"[Service]\nLoadCredentialEncrypted=\nSetCredential=\nExecStart=/usr/bin/howyd\t\n"
            .as_slice(),
    ] {
        let mut policy = ParsedEffectivePolicy::default();
        assert!(parse_effective_file(UnitKind::Service, true, malformed, &mut policy).is_err());
    }

    for malicious in [
        b"\n[Service]\nEnvironment=LD_PRELOAD=/tmp/evil.so\n".as_slice(),
        b"\n[Service]\nUser=nobody\n".as_slice(),
        b"\n[Service]\nGroup=users\n".as_slice(),
        b"\n[Service]\nRootDirectory=/tmp/root\n".as_slice(),
        b"\n[Service]\nExecStart=\nExecStart=/bin/sh\n".as_slice(),
        b"\n[Service]\nNoNewPrivileges=\n".as_slice(),
        b"\n[Arbitrary]\nKey=value\n".as_slice(),
        b"\n# comment hiding a continuation \\\nUser=nobody\n".as_slice(),
        b"\n[Service]\nEnvironment=\"A=\\x2fbin\\x2fsh\"\n".as_slice(),
    ] {
        let mut bytes = BASE_SERVICE_UNIT_BYTES.to_vec();
        bytes.extend_from_slice(malicious);
        let mut policy = ParsedEffectivePolicy::default();
        assert!(parse_effective_file(UnitKind::Service, false, &bytes, &mut policy).is_err());
    }

    for malicious in [
        b"\n[Socket]\nAccept=yes\n".as_slice(),
        b"\n[Socket]\nService=evil.service\n".as_slice(),
        b"\n[Socket]\nListenStream=\nListenStream=/tmp/evil.sock\n".as_slice(),
        b"\n[Arbitrary]\nKey=value\n".as_slice(),
    ] {
        let mut bytes = BASE_SOCKET_UNIT_BYTES.to_vec();
        bytes.extend_from_slice(malicious);
        let mut policy = ParsedEffectivePolicy::default();
        assert!(parse_effective_file(UnitKind::Socket, false, &bytes, &mut policy).is_err());
    }

    for reviewed in [MODE0_DROPIN_BYTES, MODE1_DROPIN_BYTES] {
        let mut changed = reviewed.to_vec();
        changed.extend_from_slice(b"# semantically inert but not packaged\n");
        let mut policy = ParsedEffectivePolicy::default();
        assert!(parse_effective_file(UnitKind::Service, true, &changed, &mut policy).is_err());
    }
}

fn observed_file(bytes: &[u8], permissions: u32, inode: u64) -> ObservedFile {
    ObservedFile {
        bytes: bytes.to_vec(),
        metadata: FileMetadataSnapshotV1 {
            schema_version: 1,
            object_type: FileObjectType::RegularFile,
            uid: 0,
            gid: 0,
            permissions,
            link_count: 1,
            link_policy: FileLinkPolicy::ExactlyOne,
            byte_length: bytes.len() as u64,
            restorable_timestamps: RestorableFileTimestampsV1 {
                access: FileTimestampV1 {
                    seconds: 1,
                    nanoseconds: 0,
                },
                modification: FileTimestampV1 {
                    seconds: 2,
                    nanoseconds: 0,
                },
            },
        },
        device_id: 8,
        inode,
        parent_device_id: 8,
        parent_inode: 42,
        parent_uid: 0,
        parent_gid: 0,
        parent_permissions: 0o755,
        parent_link_count: 2,
    }
}

#[test]
fn effective_observation_binds_exact_file_order_hashes_and_metadata() {
    let fragment = include_bytes!("../../../../systemd/howy.service");
    let show = EffectiveShow {
        fragment_path: BASE_SERVICE_UNIT_PATH.into(),
        dropin_paths: vec![MODE1_DROPIN_PATH.into()],
    };
    let observed = build_effective_observation(
        UnitKind::Service,
        show.clone(),
        vec![
            (
                BASE_SERVICE_UNIT_PATH.into(),
                observed_file(fragment, 0o644, 10),
            ),
            (
                MODE1_DROPIN_PATH.into(),
                observed_file(MODE1_DROPIN_BYTES, 0o600, 11),
            ),
        ],
    )
    .unwrap();
    assert_eq!(observed.fragment.sha256, Sha256Digest::from_bytes(fragment));
    assert_eq!(observed.dropins[0].path, MODE1_DROPIN_PATH);
    assert_eq!(
        observed.dropins[0].sha256,
        Sha256Digest::from_bytes(MODE1_DROPIN_BYTES)
    );
    assert_eq!(observed.dropins[0].metadata.permissions, 0o600);

    let reversed = build_effective_observation(
        UnitKind::Service,
        show,
        vec![
            (
                MODE1_DROPIN_PATH.into(),
                observed_file(MODE1_DROPIN_BYTES, 0o600, 11),
            ),
            (
                BASE_SERVICE_UNIT_PATH.into(),
                observed_file(fragment, 0o644, 10),
            ),
        ],
    );
    assert!(reversed.is_err());
}

fn secure_host_secret_stat() -> libc::stat {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    stat.st_mode = libc::S_IFREG | 0o400;
    stat.st_uid = 0;
    stat.st_gid = 0;
    stat.st_nlink = 1;
    stat.st_size = 16 + 4096;
    stat.st_dev = 8;
    stat.st_ino = 42;
    stat.st_mtime = 10;
    stat.st_mtime_nsec = 20;
    stat.st_ctime = 30;
    stat.st_ctime_nsec = 40;
    stat
}

#[test]
fn host_secret_metadata_policy_covers_missing_secure_insecure_and_race() {
    assert!(!validate_host_secret_observations(None, &[]).unwrap());

    let secure = secure_host_secret_stat();
    assert!(validate_host_secret_observations(Some(&secure), &[&secure, &secure]).unwrap());

    for mutate in [
        |stat: &mut libc::stat| stat.st_mode = libc::S_IFREG | 0o600,
        |stat: &mut libc::stat| stat.st_uid = 1000,
        |stat: &mut libc::stat| stat.st_gid = 1000,
        |stat: &mut libc::stat| stat.st_nlink = 2,
        |stat: &mut libc::stat| stat.st_size = 4096,
        |stat: &mut libc::stat| stat.st_mode = libc::S_IFLNK | 0o400,
    ] {
        let mut insecure = secure_host_secret_stat();
        mutate(&mut insecure);
        assert!(validate_host_secret_observations(Some(&insecure), &[]).is_err());
    }

    let mut replaced = secure_host_secret_stat();
    replaced.st_ino += 1;
    assert!(validate_host_secret_observations(Some(&secure), &[&replaced]).is_err());

    let mut chmod_race = secure_host_secret_stat();
    chmod_race.st_mode = libc::S_IFREG | 0o600;
    assert!(validate_host_secret_observations(Some(&secure), &[&chmod_race]).is_err());
    assert!(validate_host_secret_observations(None, &[&secure]).is_err());
}

struct AtomicTempDir(PathBuf);

impl AtomicTempDir {
    fn new() -> Self {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("howy-atomic-test-{}", hex(&random)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for AtomicTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn atomic_plan(
    runtime: &mut RealSecurityRuntime,
    target: &Path,
    bytes: &[u8],
) -> AtomicWritePlanV1 {
    let target = target.to_str().unwrap();
    let observed = runtime.observe_atomic_target(target, 4096).unwrap();
    let (expected, operation) = match observed.target {
        Some(file) => (
            AtomicExpectedTargetV1::Present(file.atomic_identity()),
            AtomicWriteKindV1::Exchange,
        ),
        None => (AtomicExpectedTargetV1::Absent, AtomicWriteKindV1::NoReplace),
    };
    AtomicWritePlanV1::new(
        VALID_TRANSACTION,
        target,
        observed.parent_directory,
        expected,
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o600,
        None,
        bytes,
        operation,
    )
    .unwrap()
}

fn execute_atomic(
    runtime: &mut RealSecurityRuntime,
    plan: &AtomicWritePlanV1,
    bytes: &[u8],
) -> SecurityResult<AtomicWriteObservationV1> {
    let staged = runtime.create_atomic_stage(plan, bytes)?;
    runtime.commit_atomic_stage(plan, &staged)
}

#[test]
fn real_atomic_runtime_commits_absent_and_exchange_without_hidden_cleanup() {
    let root = AtomicTempDir::new();
    let mut runtime = RealSecurityRuntime::new();
    let absent = root.path("absent");
    let absent_plan = atomic_plan(&mut runtime, &absent, b"new");
    let absent_observation = execute_atomic(&mut runtime, &absent_plan, b"new").unwrap();
    assert_eq!(fs::read(&absent).unwrap(), b"new");
    assert!(absent_observation.backup.is_none());
    assert!(!Path::new(&absent_plan.staging_path).exists());

    let existing = root.path("existing");
    write_mode(&existing, b"old", 0o600);
    let exchange_plan = atomic_plan(&mut runtime, &existing, b"newer");
    let exchange_observation = execute_atomic(&mut runtime, &exchange_plan, b"newer").unwrap();
    assert_eq!(fs::read(&existing).unwrap(), b"newer");
    assert_eq!(
        fs::read(exchange_plan.backup_path.as_ref().unwrap()).unwrap(),
        b"old"
    );
    assert!(exchange_observation.backup.is_some());
    runtime
        .remove_atomic_backup(&exchange_plan, &exchange_observation)
        .unwrap();
    assert!(!Path::new(&exchange_plan.staging_path).exists());
}

#[test]
fn real_atomic_runtime_refuses_unsafe_targets_and_stage_collisions() {
    let root = AtomicTempDir::new();
    let mut runtime = RealSecurityRuntime::new();

    let symlink_path = root.path("symlink");
    symlink("missing", &symlink_path).unwrap();
    assert!(
        runtime
            .observe_atomic_target(symlink_path.to_str().unwrap(), 4096)
            .is_err()
    );

    let fifo = root.path("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    assert!(
        runtime
            .observe_atomic_target(fifo.to_str().unwrap(), 4096)
            .is_err()
    );

    let hard = root.path("hard");
    let hard_link = root.path("hard-link");
    write_mode(&hard, b"old", 0o600);
    fs::hard_link(&hard, &hard_link).unwrap();
    assert!(
        runtime
            .observe_atomic_target(hard.to_str().unwrap(), 4096)
            .is_err()
    );

    let unsafe_mode = root.path("unsafe-mode");
    write_mode(&unsafe_mode, b"old", 0o666);
    let observed = runtime
        .observe_atomic_target(unsafe_mode.to_str().unwrap(), 4096)
        .unwrap();
    assert!(
        AtomicWritePlanV1::new(
            VALID_TRANSACTION,
            unsafe_mode.to_str().unwrap(),
            observed.parent_directory,
            AtomicExpectedTargetV1::Present(observed.target.unwrap().atomic_identity()),
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o600,
            None,
            b"new",
            AtomicWriteKindV1::Exchange,
        )
        .is_err()
    );

    let collision = root.path("collision");
    let collision_plan = atomic_plan(&mut runtime, &collision, b"new");
    write_mode(Path::new(&collision_plan.staging_path), b"occupied", 0o600);
    assert!(execute_atomic(&mut runtime, &collision_plan, b"new").is_err());
    assert!(!collision.exists());
    assert_eq!(fs::read(&collision_plan.staging_path).unwrap(), b"occupied");
}

#[test]
fn real_atomic_runtime_detects_target_swaps_before_and_across_exchange() {
    let root = AtomicTempDir::new();
    let mut runtime = RealSecurityRuntime::new();
    let target = root.path("target");
    write_mode(&target, b"old", 0o600);
    let plan = atomic_plan(&mut runtime, &target, b"new");
    let replacement = root.path("replacement");
    write_mode(&replacement, b"attacker", 0o600);
    fs::rename(&replacement, &target).unwrap();
    assert!(execute_atomic(&mut runtime, &plan, b"new").is_err());
    assert_eq!(fs::read(&target).unwrap(), b"attacker");
    assert_eq!(fs::read(&plan.staging_path).unwrap(), b"new");
    fs::remove_file(&plan.staging_path).unwrap();

    write_mode(&target, b"old", 0o600);
    let plan = atomic_plan(&mut runtime, &target, b"new");
    let target_for_hook = target.clone();
    let replacement_for_hook = root.path("pre-exchange-replacement");
    runtime.atomic_pre_rename_hook = Some(Box::new(move |_| {
        write_mode(&replacement_for_hook, b"attacker", 0o600);
        fs::rename(&replacement_for_hook, &target_for_hook).unwrap();
    }));
    assert!(matches!(
        execute_atomic(&mut runtime, &plan, b"new"),
        Err(SecurityError::Uncertain(_))
    ));
    assert_eq!(fs::read(&target).unwrap(), b"new");
    assert_eq!(fs::read(&plan.staging_path).unwrap(), b"attacker");
}

#[test]
fn real_atomic_runtime_held_parent_is_not_redirected_by_path_replacement() {
    let root = AtomicTempDir::new();
    let parent = root.path("parent");
    fs::create_dir(&parent).unwrap();
    let target = parent.join("target");
    write_mode(&target, b"old", 0o600);
    let mut runtime = RealSecurityRuntime::new();
    let plan = atomic_plan(&mut runtime, &target, b"new");
    let moved = root.path("moved-parent");
    let replacement_parent = parent.clone();
    let original_parent = parent.clone();
    runtime.atomic_pre_rename_hook = Some(Box::new(move |_| {
        fs::rename(&original_parent, &moved).unwrap();
        fs::create_dir(&replacement_parent).unwrap();
    }));
    assert!(matches!(
        execute_atomic(&mut runtime, &plan, b"new"),
        Err(SecurityError::Uncertain(_))
    ));
    assert!(!target.exists());
    assert_eq!(fs::read(root.path("moved-parent/target")).unwrap(), b"new");
}

#[test]
fn real_atomic_runtime_failure_windows_reconcile_without_untracked_files() {
    for point in [
        "stage-create",
        "stage-write",
        "stage-fsync",
        "stage-fsynced",
        "rename",
        "renamed",
        "directory-fsync",
        "directory-fsynced",
    ] {
        let root = AtomicTempDir::new();
        let target = root.path("target");
        write_mode(&target, b"old", 0o600);
        let mut runtime = RealSecurityRuntime::new();
        let plan = atomic_plan(&mut runtime, &target, b"new");
        runtime.atomic_failure = Some(point);
        let staged = match runtime.create_atomic_stage(&plan, b"new") {
            Ok(staged) => {
                assert!(runtime.commit_atomic_stage(&plan, &staged).is_err());
                Some(staged)
            }
            Err(_) => None,
        };
        match runtime
            .reconcile_atomic_write(&plan, staged.as_ref())
            .unwrap()
        {
            AtomicWriteReconciliation::NotCommitted => {
                assert_eq!(fs::read(&target).unwrap(), b"old");
                assert!(!Path::new(&plan.staging_path).exists());
            }
            AtomicWriteReconciliation::Committed(observation) => {
                assert_eq!(fs::read(&target).unwrap(), b"new");
                runtime.remove_atomic_backup(&plan, &observation).unwrap();
                assert!(!Path::new(&plan.staging_path).exists());
            }
        }
    }
}

#[test]
fn real_atomic_recovery_removes_only_the_exact_durably_recorded_stage_identity() {
    let no_stage_root = AtomicTempDir::new();
    let no_stage_target = no_stage_root.path("target");
    write_mode(&no_stage_target, b"old", 0o600);
    let mut no_stage_runtime = RealSecurityRuntime::new();
    let no_stage_plan = atomic_plan(&mut no_stage_runtime, &no_stage_target, b"new");
    assert_eq!(
        no_stage_runtime
            .reconcile_atomic_write(&no_stage_plan, None)
            .unwrap(),
        AtomicWriteReconciliation::NotCommitted
    );

    for bytes in [b"".as_slice(), b"n".as_slice(), b"bad".as_slice()] {
        let root = AtomicTempDir::new();
        let target = root.path("target");
        write_mode(&target, b"old", 0o600);
        let mut runtime = RealSecurityRuntime::new();
        let plan = atomic_plan(&mut runtime, &target, b"new");
        write_mode(Path::new(&plan.staging_path), bytes, 0o600);
        assert!(runtime.reconcile_atomic_write(&plan, None).is_err());
        assert_eq!(fs::read(&plan.staging_path).unwrap(), bytes);
    }

    let replaced_root = AtomicTempDir::new();
    let replaced_target = replaced_root.path("target");
    write_mode(&replaced_target, b"old", 0o600);
    let mut replaced_runtime = RealSecurityRuntime::new();
    let replaced_plan = atomic_plan(&mut replaced_runtime, &replaced_target, b"new");
    let recorded = replaced_runtime
        .create_atomic_stage(&replaced_plan, b"new")
        .unwrap();
    let replacement = replaced_root.path("replacement-stage");
    write_mode(&replacement, b"new", 0o600);
    fs::rename(&replacement, &replaced_plan.staging_path).unwrap();
    assert!(
        replaced_runtime
            .reconcile_atomic_write(&replaced_plan, Some(&recorded))
            .is_err()
    );
    assert!(Path::new(&replaced_plan.staging_path).exists());
    assert_ne!(
        fs::metadata(&replaced_plan.staging_path).unwrap().ino(),
        recorded.inode
    );

    let owned_root = AtomicTempDir::new();
    let owned_target = owned_root.path("target");
    write_mode(&owned_target, b"old", 0o600);
    let mut owned_runtime = RealSecurityRuntime::new();
    let owned_plan = atomic_plan(&mut owned_runtime, &owned_target, b"new");
    let owned = owned_runtime
        .create_atomic_stage(&owned_plan, b"new")
        .unwrap();
    assert_eq!(
        owned_runtime
            .reconcile_atomic_write(&owned_plan, Some(&owned))
            .unwrap(),
        AtomicWriteReconciliation::NotCommitted
    );
    assert!(!Path::new(&owned_plan.staging_path).exists());
    assert_eq!(fs::read(&owned_target).unwrap(), b"old");
}

#[test]
fn real_atomic_runtime_backup_cleanup_failures_are_idempotently_recoverable() {
    for point in [
        "backup-unlink",
        "backup-unlinked",
        "backup-fsync",
        "backup-fsynced",
    ] {
        let root = AtomicTempDir::new();
        let target = root.path("target");
        write_mode(&target, b"old", 0o600);
        let mut runtime = RealSecurityRuntime::new();
        let plan = atomic_plan(&mut runtime, &target, b"new");
        let observation = execute_atomic(&mut runtime, &plan, b"new").unwrap();
        runtime.atomic_failure = Some(point);
        assert!(runtime.remove_atomic_backup(&plan, &observation).is_err());
        runtime.remove_atomic_backup(&plan, &observation).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert!(!Path::new(&plan.staging_path).exists());
    }
}

fn minimal_effective_unit(kind: UnitKind, path: &str) -> EffectiveUnitObservationV1 {
    EffectiveUnitObservationV1 {
        unit_kind: kind,
        fragment: EffectiveUnitFileV1 {
            path: path.into(),
            sha256: Sha256Digest::from_bytes(b"fragment"),
            metadata: EffectiveFileMetadataV1 {
                object_type: FileObjectType::RegularFile,
                uid: 0,
                gid: 0,
                permissions: 0o644,
                link_count: 1,
                byte_length: 8,
            },
        },
        dropins: Vec::new(),
        conditions: Vec::new(),
        load_credential_encrypted: Vec::new(),
        set_credential: Vec::new(),
        exec_start: Vec::new(),
        hardening: BTreeMap::new(),
    }
}

fn prepared_supervisor_journal() -> SupervisorJournalV1 {
    let transaction_id = VALID_TRANSACTION.to_owned();
    SupervisorJournalV1 {
        schema_version: 1,
        transaction_id: transaction_id.clone(),
        generation: 1,
        prior_journal_identity: None,
        journal_staging_path: howy_common::provisioning::canonical_journal_staging_path(
            &transaction_id,
        )
        .unwrap(),
        guard: None,
        operation: SupervisorOperationV1::ProvisionMode1,
        phase: SupervisorPhaseV1::Prepared,
        prior_config: None,
        prior_dropin: None,
        prior_receipt: None,
        service_unit_state: Some(howy_common::provisioning::StableUnitState {
            unit_kind: UnitKind::Service,
            load_state: UnitLoadState::Loaded,
            active_state: UnitActiveState::Inactive,
            sub_state: UnitSubState::Dead,
            unit_file_state: UnitFileState::Enabled,
        }),
        socket_unit_state: Some(howy_common::provisioning::StableUnitState {
            unit_kind: UnitKind::Socket,
            load_state: UnitLoadState::Loaded,
            active_state: UnitActiveState::Inactive,
            sub_state: UnitSubState::Dead,
            unit_file_state: UnitFileState::Enabled,
        }),
        prior_daemon_invocation_id: None,
        prior_effective_units: Some(howy_common::provisioning::EffectiveUnitSetV1 {
            service: minimal_effective_unit(UnitKind::Service, BASE_SERVICE_UNIT_PATH),
            socket: minimal_effective_unit(UnitKind::Socket, BASE_SOCKET_UNIT_PATH),
        }),
        transaction_owned_paths: vec![
            howy_common::provisioning::canonical_journal_staging_path(&transaction_id).unwrap(),
        ],
        atomic_writes: Vec::new(),
        security_directories: Vec::new(),
        cleanup_artifact: None,
        cleanup_manifest: None,
        cleanup_pre_admission: None,
        cleanup_quarantine: None,
        supervisor_failed: false,
    }
}

fn guarded_journal(
    mut prepared: SupervisorJournalV1,
    prior: &ObservedFile,
    guard: TransactionGuardIdentityV1,
) -> SupervisorJournalV1 {
    prepared.generation += 1;
    prepared.prior_journal_identity = Some(prior.atomic_identity());
    prepared.guard = Some(guard);
    prepared.phase = SupervisorPhaseV1::Guarded;
    prepared
}

fn rooted_journal_fixture(
    root: &Path,
) -> (
    RealSecurityRuntime,
    ObservedFile,
    SupervisorJournalV1,
    SupervisorJournalV1,
) {
    prepare_rooted_production_parents(root);
    let mut runtime = RealSecurityRuntime::rooted(root).unwrap();
    let prepared = prepared_supervisor_journal();
    let prepared_bytes = prepared.deterministic_bytes().unwrap();
    let prior = runtime.persist_journal(None, &prepared_bytes).unwrap();
    let guard = runtime.create_guard(VALID_TRANSACTION, None).unwrap();
    let guarded = guarded_journal(prepared.clone(), &prior, guard);
    (runtime, prior, prepared, guarded)
}

#[test]
fn real_guard_identity_rejects_same_content_replacement_without_unlinking() {
    if !run_root_owned_branch(
        "security::real::tests::real_guard_identity_rejects_same_content_replacement_without_unlinking",
    ) {
        return;
    }
    let root = AtomicTempDir::new();
    prepare_rooted_production_parents(&root.0);
    let mut runtime = RealSecurityRuntime::rooted(&root.0).unwrap();
    let expected = runtime.create_guard(VALID_TRANSACTION, None).unwrap();
    let path = runtime
        .paths
        .resolve(SECURITY_TRANSACTION_GUARD_PATH)
        .unwrap();
    let replacement = root.path("replacement-guard");
    write_mode(
        &replacement,
        &expected.content.deterministic_bytes().unwrap(),
        0o600,
    );
    fs::rename(&replacement, &path).unwrap();
    assert!(
        runtime
            .create_guard(VALID_TRANSACTION, Some(&expected))
            .is_err()
    );
    assert!(runtime.remove_guard(VALID_TRANSACTION, &expected).is_err());
    assert!(path.exists());
}

#[test]
fn real_journal_exchange_rejects_target_and_stage_replacement() {
    if !run_root_owned_branch(
        "security::real::tests::real_journal_exchange_rejects_target_and_stage_replacement",
    ) {
        return;
    }

    let target_root = AtomicTempDir::new();
    let (mut target_runtime, prior, _, guarded) = rooted_journal_fixture(&target_root.0);
    let target_path = target_runtime.paths.resolve(SECURITY_JOURNAL_PATH).unwrap();
    let replacement = target_root.path("replacement-journal");
    write_mode(&replacement, &prior.bytes, 0o600);
    target_runtime.journal_pre_exchange_hook = Some(Box::new(move || {
        fs::rename(&replacement, &target_path).unwrap();
    }));
    assert!(
        target_runtime
            .persist_journal(Some(&prior), &guarded.deterministic_bytes().unwrap())
            .is_err()
    );
    assert!(
        target_runtime
            .paths
            .resolve(&guarded.journal_staging_path)
            .unwrap()
            .exists()
    );

    let stage_root = AtomicTempDir::new();
    let (mut stage_runtime, prior, _, guarded) = rooted_journal_fixture(&stage_root.0);
    stage_runtime.force_named_journal_staging = true;
    stage_runtime.atomic_failure = Some("journal-stage-linked");
    let guarded_bytes = guarded.deterministic_bytes().unwrap();
    assert!(
        stage_runtime
            .persist_journal(Some(&prior), &guarded_bytes)
            .is_err()
    );
    let stage_path = stage_runtime
        .paths
        .resolve(&guarded.journal_staging_path)
        .unwrap();
    let replacement = stage_root.path("replacement-stage");
    write_mode(&replacement, &guarded_bytes, 0o600);
    fs::rename(&replacement, &stage_path).unwrap();
    assert!(stage_runtime.load_journal().is_err());
    assert!(stage_path.exists());

    let backup_root = AtomicTempDir::new();
    let (mut backup_runtime, prior, _, guarded) = rooted_journal_fixture(&backup_root.0);
    backup_runtime.force_named_journal_staging = true;
    backup_runtime.atomic_failure = Some("journal-exchanged");
    assert!(
        backup_runtime
            .persist_journal(Some(&prior), &guarded.deterministic_bytes().unwrap())
            .is_err()
    );
    let backup_path = backup_runtime
        .paths
        .resolve(&guarded.journal_staging_path)
        .unwrap();
    let replacement = backup_root.path("replacement-exchanged-backup");
    write_mode(&replacement, &prior.bytes, 0o600);
    fs::rename(&replacement, &backup_path).unwrap();
    assert!(backup_runtime.load_journal().is_err());
    assert!(backup_path.exists());
}

#[test]
fn real_journal_recovers_only_exact_post_exchange_backup_and_rejects_generation_rollback() {
    if !run_root_owned_branch(
        "security::real::tests::real_journal_recovers_only_exact_post_exchange_backup_and_rejects_generation_rollback",
    ) {
        return;
    }
    for failure in ["journal-exchanged", "journal-before-backup-unlink"] {
        let root = AtomicTempDir::new();
        let (mut runtime, prior, prepared, guarded) = rooted_journal_fixture(&root.0);
        runtime.force_named_journal_staging = true;
        runtime.atomic_failure = Some(failure);
        let guarded_bytes = guarded.deterministic_bytes().unwrap();
        assert!(
            runtime
                .persist_journal(Some(&prior), &guarded_bytes)
                .is_err()
        );
        let recovered = runtime.load_journal().unwrap().unwrap();
        assert_eq!(recovered.bytes, guarded_bytes);
        assert!(
            !runtime
                .paths
                .resolve(&guarded.journal_staging_path)
                .unwrap()
                .exists()
        );

        let mut rollback = prepared;
        rollback.generation = guarded.generation;
        rollback.prior_journal_identity = Some(recovered.atomic_identity());
        assert!(
            runtime
                .persist_journal(Some(&recovered), &rollback.deterministic_bytes().unwrap())
                .is_err()
        );
        let journal_path = runtime.paths.resolve(SECURITY_JOURNAL_PATH).unwrap();
        let replacement = root.path("replacement-before-final-remove");
        write_mode(&replacement, &recovered.bytes, 0o600);
        fs::rename(&replacement, &journal_path).unwrap();
        assert!(
            runtime
                .remove_journal(VALID_TRANSACTION, &recovered)
                .is_err()
        );
        assert!(journal_path.exists());
    }
}

fn prepare_rooted_production_parents(root: &Path) {
    for path in [
        "etc",
        "etc/systemd",
        "etc/systemd/system",
        "var",
        "var/lib",
        "run",
        "run/lock",
        "usr",
        "usr/lib",
        "usr/lib/systemd",
        "usr/lib/systemd/system",
    ] {
        let path = root.join(path);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn run_root_owned_branch(test_name: &str) -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    let executable = std::env::current_exe().expect("current test executable");
    let status = std::process::Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user"])
        .arg(executable)
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .status()
        .expect("execute rooted test in a user namespace");
    assert!(status.success(), "rooted user-namespace test failed");
    false
}

#[test]
fn rooted_security_paths_are_strict_and_keep_production_names_in_journals() {
    let root = AtomicTempDir::new();
    let paths = SecurityPaths::rooted(&root.0).unwrap();
    assert_eq!(
        paths.resolve(MODE1_CREDENTIAL_PATH).unwrap(),
        root.0
            .join("etc/credstore.encrypted/howy.storage.mode1.epoch1")
    );
    assert!(paths.resolve("relative/path").is_err());
    assert!(paths.resolve("/etc/howy/../escape").is_err());
    assert_eq!(
        howy_common::provisioning::canonical_journal_staging_path(VALID_TRANSACTION).unwrap(),
        format!(
            "{}/.howy-{VALID_TRANSACTION}-transaction-v1.json-journal.stage",
            howy_common::provisioning::SECURITY_JOURNAL_DIRECTORY
        )
    );
}

#[test]
fn rooted_real_directory_lifecycle_uses_production_no_follow_methods() {
    if !run_root_owned_branch(
        "security::real::tests::rooted_real_directory_lifecycle_uses_production_no_follow_methods",
    ) {
        return;
    }
    let root = AtomicTempDir::new();
    prepare_rooted_production_parents(&root.0);
    let mut runtime = RealSecurityRuntime::rooted(&root.0).unwrap();
    runtime.acquire_lock().unwrap();
    let prior_umask = unsafe { libc::umask(0o077) };
    let mut records = Vec::new();
    for (path, permissions) in howy_common::provisioning::REQUIRED_SECURITY_DIRECTORIES {
        let mut intent = runtime.plan_security_directory(path, permissions).unwrap();
        let observed = runtime.ensure_security_directory(&intent).unwrap();
        intent.observed_directory = Some(observed);
        records.push(intent);
    }
    unsafe { libc::umask(prior_umask) };
    assert!(records.iter().all(|record| !record.preexisted));
    for record in &records {
        let path = runtime.paths.resolve(&record.path).unwrap();
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.gid(), 0);
        assert_eq!(metadata.mode() & 0o7777, record.permissions);
    }

    let config_path = runtime
        .paths
        .resolve(howy_common::paths::CONFIG_FILE)
        .unwrap();
    let config_c = CString::new(config_path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(config_c.as_ptr(), 0o600) }, 0);
    assert!(
        runtime
            .observe_atomic_target(howy_common::paths::CONFIG_FILE, 4096)
            .is_err()
    );
    fs::remove_file(&config_path).unwrap();

    let artifact = runtime.paths.resolve(MODE1_CREDENTIAL_PATH).unwrap();
    symlink("missing", &artifact).unwrap();
    assert!(runtime.read_file(MODE1_CREDENTIAL_PATH, 4096).is_err());
    fs::remove_file(&artifact).unwrap();
    write_mode(&artifact, b"hard-linked", 0o600);
    let artifact_link = artifact.with_extension("link");
    fs::hard_link(&artifact, &artifact_link).unwrap();
    assert!(runtime.read_file(MODE1_CREDENTIAL_PATH, 4096).is_err());
    fs::remove_file(&artifact_link).unwrap();
    fs::remove_file(&artifact).unwrap();

    write_mode(&artifact, b"quarantine-identity", 0o600);
    let expected = runtime
        .read_file(MODE1_CREDENTIAL_PATH, 4096)
        .unwrap()
        .unwrap()
        .cleanup_descriptor();
    let quarantine = format!(
        "{}/.howy-{VALID_TRANSACTION}.quarantine",
        howy_common::provisioning::MODE1_CREDENTIAL_DIRECTORY
    );
    runtime.atomic_failure = Some("quarantine-rename-fsynced");
    assert!(
        runtime
            .quarantine_artifact_exact(&expected, &quarantine)
            .is_err()
    );
    runtime.atomic_failure = Some("quarantine-restore-fsynced");
    assert!(
        runtime
            .restore_quarantined_artifact_exact(&expected, &quarantine)
            .is_err()
    );
    runtime.atomic_failure = None;
    runtime
        .restore_quarantined_artifact_exact(&expected, &quarantine)
        .unwrap();
    runtime
        .quarantine_artifact_exact(&expected, &quarantine)
        .unwrap();
    runtime.atomic_failure = Some("quarantine-unlink-fsynced");
    assert!(
        runtime
            .unlink_quarantined_artifact_exact(&expected, &quarantine)
            .is_err()
    );
    runtime.atomic_failure = None;
    runtime
        .unlink_quarantined_artifact_exact(&expected, &quarantine)
        .unwrap();
    assert!(!artifact.exists());

    let retained = runtime
        .paths
        .resolve(MODE1_NAMESPACE_PATH)
        .unwrap()
        .join("user.hye");
    write_mode(&retained, b"user-data", 0o600);
    runtime.rollback_security_directories(&records).unwrap();
    assert!(retained.exists());
    fs::remove_file(&retained).unwrap();
    runtime.rollback_security_directories(&records).unwrap();
    assert!(
        !runtime
            .paths
            .resolve(MODE1_NAMESPACE_PATH)
            .unwrap()
            .exists()
    );

    let bad_root = AtomicTempDir::new();
    prepare_rooted_production_parents(&bad_root.0);
    symlink("missing", bad_root.0.join("etc/howy")).unwrap();
    let mut bad = RealSecurityRuntime::rooted(&bad_root.0).unwrap();
    assert!(bad.plan_security_directory("/etc/howy", 0o700).is_err());
}

struct RootedTestKey([u8; 32]);

impl SecretKeyMaterial for RootedTestKey {
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for RootedTestKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct RootedEngineRuntime {
    fs: RealSecurityRuntime,
    service: UnitObservation,
    socket: UnitObservation,
    monotonic: u64,
    invocation: u8,
    readiness_failure: bool,
    boundary_name: Option<&'static str>,
    fail_after: Option<&'static str>,
    events: Vec<String>,
    last_created_guard: Option<TransactionGuardIdentityV1>,
    removed_guard: Option<TransactionGuardIdentityV1>,
    transient_present: bool,
    pre_guard_mutation: Option<&'static str>,
    fail_guard_transition_journal: bool,
}

impl RootedEngineRuntime {
    fn new(root: &Path) -> Self {
        Self {
            fs: RealSecurityRuntime::rooted(root).unwrap(),
            service: rooted_unit(UnitKind::Service, false),
            socket: rooted_unit(UnitKind::Socket, false),
            monotonic: 0,
            invocation: 1,
            readiness_failure: false,
            boundary_name: None,
            fail_after: None,
            events: Vec::new(),
            last_created_guard: None,
            removed_guard: None,
            transient_present: false,
            pre_guard_mutation: None,
            fail_guard_transition_journal: false,
        }
    }

    fn inject_after(&mut self, point: &'static str) -> SecurityResult<()> {
        self.events.push(point.into());
        if self.fail_after == Some(point) {
            self.fail_after = None;
            Err(SecurityError::operation(format!(
                "rooted failure after {point}"
            )))
        } else {
            Ok(())
        }
    }

    fn effective(&mut self, kind: UnitKind) -> SecurityResult<EffectiveUnitObservationV1> {
        let (fragment_path, fragment_bytes) = match kind {
            UnitKind::Service => (
                BASE_SERVICE_UNIT_PATH,
                include_bytes!("../../../../systemd/howy.service").as_slice(),
            ),
            UnitKind::Socket => (
                BASE_SOCKET_UNIT_PATH,
                include_bytes!("../../../../systemd/howy.socket").as_slice(),
            ),
        };
        let fragment = self
            .fs
            .read_exact_file(fragment_path, MAX_DROPIN_BYTES)?
            .ok_or_else(|| SecurityError::operation("rooted fragment missing"))?;
        if fragment.bytes != fragment_bytes {
            return Err(SecurityError::operation("rooted fragment changed"));
        }
        let dropin = if kind == UnitKind::Service {
            self.fs
                .read_exact_file(MODE1_DROPIN_PATH, MAX_DROPIN_BYTES)?
        } else {
            None
        };
        let show = EffectiveShow {
            fragment_path: fragment_path.into(),
            dropin_paths: dropin
                .as_ref()
                .map(|_| vec![MODE1_DROPIN_PATH.into()])
                .unwrap_or_default(),
        };
        let mut files = vec![(fragment_path.into(), fragment)];
        if let Some(dropin) = dropin {
            files.push((MODE1_DROPIN_PATH.into(), dropin));
        }
        build_effective_observation(kind, show, files)
    }

    fn root_status(&mut self) -> SecurityResult<Option<SecurityInfoResult>> {
        if self.service.active_state != UnitActiveState::Active
            || self.socket.active_state != UnitActiveState::Active
        {
            return Ok(None);
        }
        let config = self
            .fs
            .read_exact_file(
                howy_common::paths::CONFIG_FILE,
                howy_common::provisioning::MAX_CONFIG_BYTES,
            )?
            .ok_or_else(|| SecurityError::operation("rooted config missing"))?;
        let parsed: HowyConfig = toml::from_str(
            std::str::from_utf8(&config.bytes)
                .map_err(|_| SecurityError::operation("rooted config is not UTF-8"))?,
        )
        .map_err(|_| SecurityError::operation("rooted config is invalid"))?;
        let daemon = self.fs.observe_daemon_identity()?;
        let mode = parsed.security.embedding_mode as u32;
        Ok(Some(SecurityInfoResult {
            detector_model: "/usr/share/howy/onnx-data/det_10g.onnx".into(),
            recognizer_model: "/usr/share/howy/onnx-data/w600k_r50.onnx".into(),
            active_security_mode: mode,
            key_epoch: parsed.security.key_epoch,
            storage_ready: true,
            prompt_required: parsed.presence.mode == howy_common::config::PresenceMode::Confirm,
            namespaces: [
                (0, "/etc/howy/models"),
                (1, MODE1_NAMESPACE_PATH),
                (2, "/etc/howy/models/mode2"),
            ]
            .into_iter()
            .map(
                |(namespace_mode, path)| howy_common::protocol::NamespaceDiagnostic {
                    mode: namespace_mode,
                    path: path.into(),
                    active: namespace_mode == mode,
                    implemented: namespace_mode < 2,
                },
            )
            .collect(),
            config_sha256: config.sha256().as_str().into(),
            credential_name: (mode == 1)
                .then_some(MODE1_CREDENTIAL_NAME)
                .unwrap_or_default()
                .into(),
            configured_credential_source: (mode == 1)
                .then_some(MODE1_CREDENTIAL_PATH)
                .unwrap_or_default()
                .into(),
            backend_state: howy_common::protocol::SecurityBackendStateV1::Ready as i32,
            readiness_state: howy_common::protocol::SecurityReadinessStateV1::Ready as i32,
            poison_state: howy_common::protocol::SecurityPoisonStateV1::NotPoisoned as i32,
            daemon_invocation_id: format!("{:02x}", self.invocation).repeat(32),
            daemon_version: daemon.version,
            build_identity: daemon.build_identity,
            binary_absolute_path: daemon.binary_absolute_path,
            binary_sha256: daemon.binary_sha256.as_str().into(),
        }))
    }
}

fn rooted_unit(kind: UnitKind, active: bool) -> UnitObservation {
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

impl SecurityRuntime for RootedEngineRuntime {
    fn require_root(&mut self) -> SecurityResult<()> {
        Ok(())
    }

    fn acquire_lock(&mut self) -> SecurityResult<()> {
        self.fs.acquire_lock()
    }

    fn require_systemd_261(&mut self) -> SecurityResult<()> {
        Ok(())
    }

    fn transaction_id(&mut self) -> SecurityResult<String> {
        Ok(VALID_TRANSACTION.into())
    }

    fn generate_key(&mut self) -> SecurityResult<Box<dyn SecretKeyMaterial>> {
        Ok(Box::new(RootedTestKey([0x5a; 32])))
    }

    fn read_file(&mut self, path: &str, maximum: usize) -> SecurityResult<Option<ObservedFile>> {
        self.fs.read_file(path, maximum)
    }

    fn observe_atomic_target(
        &mut self,
        path: &str,
        maximum: usize,
    ) -> SecurityResult<AtomicTargetObservation> {
        self.fs.observe_atomic_target(path, maximum)
    }

    fn create_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        bytes: &[u8],
    ) -> SecurityResult<AtomicFileIdentityV1> {
        self.fs.create_atomic_stage(plan, bytes)
    }

    fn commit_atomic_stage(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: &AtomicFileIdentityV1,
    ) -> SecurityResult<AtomicWriteObservationV1> {
        let observation = self.fs.commit_atomic_stage(plan, staged)?;
        if plan.target_path == SECURITY_RECEIPT_PATH {
            self.inject_after("receipt-write")?;
        }
        Ok(observation)
    }

    fn reconcile_atomic_write(
        &mut self,
        plan: &AtomicWritePlanV1,
        staged: Option<&AtomicFileIdentityV1>,
    ) -> SecurityResult<AtomicWriteReconciliation> {
        self.fs.reconcile_atomic_write(plan, staged)
    }

    fn remove_atomic_backup(
        &mut self,
        plan: &AtomicWritePlanV1,
        observation: &AtomicWriteObservationV1,
    ) -> SecurityResult<()> {
        self.fs.remove_atomic_backup(plan, observation)
    }

    fn remove_file_exact(
        &mut self,
        path: &str,
        expected: &AtomicFileIdentityV1,
    ) -> SecurityResult<()> {
        self.fs.remove_file_exact(path, expected)
    }

    fn plan_security_directory(
        &mut self,
        path: &str,
        permissions: u32,
    ) -> SecurityResult<SecurityDirectoryRecordV1> {
        self.fs.plan_security_directory(path, permissions)
    }

    fn ensure_security_directory(
        &mut self,
        intent: &SecurityDirectoryRecordV1,
    ) -> SecurityResult<DirectoryIdentityV1> {
        self.fs.ensure_security_directory(intent)
    }

    fn verify_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        self.fs.verify_security_directories(directories)
    }

    fn rollback_security_directories(
        &mut self,
        directories: &[SecurityDirectoryRecordV1],
    ) -> SecurityResult<()> {
        self.fs.rollback_security_directories(directories)
    }

    fn create_guard(
        &mut self,
        transaction_id: &str,
        expected: Option<&TransactionGuardIdentityV1>,
    ) -> SecurityResult<TransactionGuardIdentityV1> {
        let guard = self.fs.create_guard(transaction_id, expected)?;
        self.events.push("guard-create".into());
        self.last_created_guard = Some(guard.clone());
        Ok(guard)
    }

    fn remove_guard(
        &mut self,
        transaction_id: &str,
        expected: &TransactionGuardIdentityV1,
    ) -> SecurityResult<()> {
        self.fs.remove_guard(transaction_id, expected)?;
        self.removed_guard = Some(expected.clone());
        self.inject_after("guard-remove")
    }

    fn load_journal(&mut self) -> SecurityResult<Option<ObservedFile>> {
        self.fs.load_journal()
    }

    fn persist_journal(
        &mut self,
        prior: Option<&ObservedFile>,
        bytes: &[u8],
    ) -> SecurityResult<ObservedFile> {
        let guard_changed = prior.is_some_and(|prior| {
            let prior_guard = ProvisioningJournalV1::parse(&prior.bytes)
                .ok()
                .and_then(|journal| journal.guard);
            let next_guard = ProvisioningJournalV1::parse(bytes)
                .ok()
                .and_then(|journal| journal.guard);
            prior_guard.is_some() && next_guard.is_some() && prior_guard != next_guard
        });
        if self.fail_guard_transition_journal && guard_changed {
            self.fail_guard_transition_journal = false;
            self.fs.force_named_journal_staging = true;
            self.fs.atomic_failure = Some("journal-stage-linked");
        }
        let observation = self.fs.persist_journal(prior, bytes)?;
        self.events.push("journal-write-any".into());
        if ProvisioningJournalV1::parse(bytes)
            .is_ok_and(|journal| journal.phase == JournalPhase::UnitsStarted)
        {
            self.inject_after("journal-write")?;
        }
        Ok(observation)
    }

    fn remove_journal(
        &mut self,
        transaction_id: &str,
        expected: &ObservedFile,
    ) -> SecurityResult<()> {
        self.fs.remove_journal(transaction_id, expected)
    }

    fn unit_observation(&mut self, unit: UnitKind) -> SecurityResult<UnitObservation> {
        Ok(match unit {
            UnitKind::Service => self.service,
            UnitKind::Socket => self.socket,
        })
    }

    fn effective_unit_observation(
        &mut self,
        unit: UnitKind,
    ) -> SecurityResult<EffectiveUnitObservationV1> {
        self.effective(unit)
    }

    fn resolve_key_selection(&mut self, requested: KeySelection) -> SecurityResult<KeySelection> {
        Ok(match requested {
            KeySelection::Auto => KeySelection::Host,
            other => other,
        })
    }

    fn host_secret_preexisting_secure(&mut self) -> SecurityResult<bool> {
        Ok(true)
    }

    fn daemon_verifier_identity(&mut self) -> SecurityResult<DaemonVerifierIdentityV1> {
        self.fs.observe_daemon_identity()
    }

    fn monotonic_millis(&mut self) -> u64 {
        self.monotonic
    }

    fn settle_step(&mut self) -> SecurityResult<()> {
        self.monotonic += 100;
        Ok(())
    }

    fn stop_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        self.events.push(format!("stop-{unit:?}"));
        let state = match unit {
            UnitKind::Service => &mut self.service,
            UnitKind::Socket => &mut self.socket,
        };
        *state = rooted_unit(unit, false);
        Ok(())
    }

    fn start_unit(&mut self, unit: UnitKind) -> SecurityResult<()> {
        let disabled = unit == UnitKind::Service
            && self
                .fs
                .read_exact_file(
                    howy_common::paths::CONFIG_FILE,
                    howy_common::provisioning::MAX_CONFIG_BYTES,
                )?
                .and_then(|file| {
                    std::str::from_utf8(&file.bytes)
                        .ok()
                        .and_then(|source| toml::from_str::<HowyConfig>(source).ok())
                })
                .is_some_and(|config| config.core.disabled);
        if disabled {
            self.service = rooted_unit(UnitKind::Service, false);
        } else {
            match unit {
                UnitKind::Service => {
                    self.service = rooted_unit(UnitKind::Service, true);
                    self.invocation = self.invocation.wrapping_add(1).max(1);
                }
                UnitKind::Socket => self.socket = rooted_unit(UnitKind::Socket, true),
            }
        }
        match unit {
            UnitKind::Socket => self.inject_after("socket-start"),
            UnitKind::Service => self.inject_after("service-start"),
        }
    }

    fn daemon_reload(&mut self) -> SecurityResult<()> {
        Ok(())
    }

    fn transient_exists(&mut self, _unit: &str) -> SecurityResult<bool> {
        Ok(self.transient_present)
    }

    fn stop_and_kill_transient(&mut self, _unit: &str) -> SecurityResult<()> {
        self.events.push("transient-stop".into());
        self.transient_present = false;
        Ok(())
    }

    fn encrypt_credential(
        &mut self,
        _command: &CommandSpec,
        _plaintext: &[u8],
    ) -> SecurityResult<Vec<u8>> {
        Ok(
            include_str!("../../../howy-common/testdata/systemd-v261/host.hex")
                .trim()
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
                .chunks(3)
                .flat_map(|chunk| {
                    const TABLE: &[u8; 64] =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    let first = chunk[0];
                    let second = chunk.get(1).copied().unwrap_or(0);
                    let third = chunk.get(2).copied().unwrap_or(0);
                    [
                        TABLE[(first >> 2) as usize],
                        TABLE[(((first & 3) << 4) | (second >> 4)) as usize],
                        if chunk.len() > 1 {
                            TABLE[(((second & 15) << 2) | (third >> 6)) as usize]
                        } else {
                            b'='
                        },
                        if chunk.len() > 2 {
                            TABLE[(third & 63) as usize]
                        } else {
                            b'='
                        },
                    ]
                })
                .collect(),
        )
    }

    fn run_readiness(&mut self, command: &CommandSpec) -> SecurityResult<Vec<u8>> {
        if self.readiness_failure {
            return Err(SecurityError::operation("rooted readiness failure"));
        }
        let config_path = command.arguments.last_chunk::<4>().unwrap()[2].clone();
        let config = self
            .fs
            .read_exact_file(&config_path, howy_common::provisioning::MAX_CONFIG_BYTES)?
            .ok_or_else(|| SecurityError::operation("rooted readiness config missing"))?;
        self.preview_verifier(&config.bytes)?
            .deterministic_bytes()
            .map_err(|error| SecurityError::operation(error.to_string()))
    }

    fn preview_verifier(&mut self, config: &[u8]) -> SecurityResult<VerifierResultV1> {
        self.fs.preview_verifier(config)
    }

    fn namespace_nonempty(&mut self) -> SecurityResult<bool> {
        self.fs.namespace_nonempty()
    }

    fn security_info(&mut self) -> SecurityResult<Option<SecurityInfoResult>> {
        let status = self.root_status()?;
        if status.is_some() {
            self.inject_after("status")?;
        }
        Ok(status)
    }

    fn daemon_info(&mut self) -> SecurityResult<Option<DaemonInfo>> {
        Ok(self.root_status()?.map(|status| DaemonInfo {
            provider: "CPU".into(),
            detector_model: String::new(),
            recognizer_model: String::new(),
            embedding_dim: 512,
            uptime_secs: 1,
            active_security_mode: status.active_security_mode,
            prompt_required: status.prompt_required,
            storage_ready: status.storage_ready,
        }))
    }

    fn quarantine_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        self.fs.quarantine_artifact_exact(expected, quarantine_path)
    }

    fn restore_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        self.fs
            .restore_quarantined_artifact_exact(expected, quarantine_path)
    }

    fn unlink_quarantined_artifact_exact(
        &mut self,
        expected: &howy_common::provisioning::ArtifactDescriptorIdentityV1,
        quarantine_path: &str,
    ) -> SecurityResult<()> {
        self.fs
            .unlink_quarantined_artifact_exact(expected, quarantine_path)
    }

    fn boundary(&mut self, name: &'static str) -> SecurityResult<()> {
        if name == "supervisor-prepared"
            && let Some(mutation) = self.pre_guard_mutation.take()
        {
            match mutation {
                "active" => self.service = rooted_unit(UnitKind::Service, true),
                "reference" => {
                    let mut config = HowyConfig::secure_bootstrap_template();
                    config.security.embedding_mode = EmbeddingSecurityMode::AeadCached;
                    config.security.key_epoch = 1;
                    config.security.cached.credential_name = MODE1_CREDENTIAL_NAME.into();
                    let bytes = toml::to_string_pretty(&config).unwrap();
                    let path = self
                        .fs
                        .paths
                        .resolve(howy_common::paths::CONFIG_FILE)
                        .unwrap();
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700))
                        .unwrap();
                    write_mode(&path, bytes.as_bytes(), 0o600);
                }
                _ => unreachable!(),
            }
        }
        if self.boundary_name == Some(name) {
            Err(SecurityError::InjectedCrash(format!(
                "rooted crash at {name}"
            )))
        } else {
            Ok(())
        }
    }
}

fn prepare_rooted_engine(root: &Path) -> RootedEngineRuntime {
    prepare_rooted_production_parents(root);
    for path in ["usr/bin", "var/lib/systemd"] {
        let path = root.join(path);
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    write_mode(
        &root.join(BASE_SERVICE_UNIT_PATH.trim_start_matches('/')),
        include_bytes!("../../../../systemd/howy.service"),
        0o644,
    );
    write_mode(
        &root.join(BASE_SOCKET_UNIT_PATH.trim_start_matches('/')),
        include_bytes!("../../../../systemd/howy.socket"),
        0o644,
    );
    write_mode(&root.join("usr/bin/howyd"), b"rooted-fake-howyd", 0o755);
    RootedEngineRuntime::new(root)
}

fn prepare_rooted_unadopted(root: &Path) -> (RootedEngineRuntime, Sha256Digest) {
    let mut runtime = prepare_rooted_engine(root);
    runtime.readiness_failure = true;
    assert!(
        SecurityEngine::new(&mut runtime)
            .provision(ProvisionRequest {
                mode: ProvisionMode::CachedAead,
                with_key: KeySelection::Host,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    runtime.readiness_failure = false;
    SecurityEngine::new(&mut runtime).recover().unwrap();
    let hash = runtime
        .fs
        .read_file(
            MODE1_CREDENTIAL_PATH,
            howy_common::provisioning::SYSTEMD_CREDENTIAL_TEXT_SIZE_MAX,
        )
        .unwrap()
        .unwrap()
        .sha256();
    (runtime, hash)
}

#[test]
fn rooted_activation_failures_recreate_and_rejournal_the_exact_guard_before_recovery() {
    if !run_root_owned_branch(
        "security::real::tests::rooted_activation_failures_recreate_and_rejournal_the_exact_guard_before_recovery",
    ) {
        return;
    }
    for point in [
        "guard-remove",
        "socket-start",
        "service-start",
        "status",
        "receipt-write",
        "journal-write",
    ] {
        let root = AtomicTempDir::new();
        let mut runtime = prepare_rooted_engine(&root.0);
        SecurityEngine::new(&mut runtime)
            .provision(ProvisionRequest {
                mode: ProvisionMode::CachedAead,
                with_key: KeySelection::Host,
                adopt_existing: false,
                confirmed: true,
            })
            .unwrap();
        runtime.fail_after = Some(point);
        assert!(matches!(
            SecurityEngine::new(&mut runtime).enable(),
            Err(SecurityError::Uncertain(_))
        ));

        let removed = runtime
            .removed_guard
            .as_ref()
            .expect("activation removed guard");
        let recreated = runtime
            .last_created_guard
            .as_ref()
            .expect("fail-closed recreated guard");
        assert_ne!(removed.file.inode, recreated.file.inode, "point {point}");
        let journal_file = runtime
            .fs
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
            .unwrap()
            .unwrap();
        let journal = ProvisioningJournalV1::parse(&journal_file.bytes).unwrap();
        assert_eq!(journal.guard.as_ref(), Some(recreated), "point {point}");
        let live_guard = runtime
            .fs
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)
            .unwrap()
            .unwrap();
        assert_eq!(
            live_guard.atomic_identity(),
            recreated.file,
            "point {point}"
        );
        assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
        assert_eq!(runtime.socket.active_state, UnitActiveState::Inactive);

        SecurityEngine::new(&mut runtime).recover().unwrap();
        assert!(
            runtime
                .fs
                .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
                .unwrap()
                .is_none(),
            "point {point}"
        );
        assert!(
            runtime
                .fs
                .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)
                .unwrap()
                .is_none(),
            "point {point}"
        );
    }

    let blocked_root = AtomicTempDir::new();
    let mut blocked = prepare_rooted_engine(&blocked_root.0);
    SecurityEngine::new(&mut blocked)
        .provision(ProvisionRequest {
            mode: ProvisionMode::CachedAead,
            with_key: KeySelection::Host,
            adopt_existing: false,
            confirmed: true,
        })
        .unwrap();
    blocked.fail_after = Some("guard-remove");
    blocked.fail_guard_transition_journal = true;
    assert!(matches!(
        SecurityEngine::new(&mut blocked).enable(),
        Err(SecurityError::Uncertain(_))
    ));
    let removed = blocked.removed_guard.clone().unwrap();
    let recreated = blocked.last_created_guard.clone().unwrap();
    assert_ne!(removed.file.inode, recreated.file.inode);
    let retained_journal = blocked
        .fs
        .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
        .unwrap()
        .unwrap();
    let retained_journal = ProvisioningJournalV1::parse(&retained_journal.bytes).unwrap();
    assert_eq!(retained_journal.guard.as_ref(), Some(&removed));
    assert!(
        blocked
            .fs
            .read_file(&retained_journal.journal_staging_path, MAX_JOURNAL_BYTES)
            .unwrap()
            .is_some()
    );
    assert_eq!(blocked.service.active_state, UnitActiveState::Inactive);
    assert_eq!(blocked.socket.active_state, UnitActiveState::Inactive);
    assert!(SecurityEngine::new(&mut blocked).recover().is_err());
    assert!(
        blocked
            .fs
            .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)
            .unwrap()
            .is_some()
    );
    assert!(
        blocked
            .fs
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
            .unwrap()
            .is_some()
    );
}

#[test]
fn rooted_cleanup_pre_admission_has_zero_control_mutation_and_guards_a_late_race() {
    if !run_root_owned_branch(
        "security::real::tests::rooted_cleanup_pre_admission_has_zero_control_mutation_and_guards_a_late_race",
    ) {
        return;
    }
    for state in ["active", "queued", "transient"] {
        let root = AtomicTempDir::new();
        let (mut runtime, hash) = prepare_rooted_unadopted(&root.0);
        runtime.events.clear();
        match state {
            "active" => runtime.service = rooted_unit(UnitKind::Service, true),
            "queued" => runtime.socket.has_queued_job = true,
            "transient" => runtime.transient_present = true,
            _ => unreachable!(),
        }
        assert!(
            SecurityEngine::new(&mut runtime)
                .cleanup_unadopted(CleanupRequest {
                    transaction_id: VALID_TRANSACTION.into(),
                    artifact_sha256: hash,
                })
                .is_err(),
            "state {state}"
        );
        assert!(
            runtime
                .fs
                .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .fs
                .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
                .unwrap()
                .is_none()
        );
        assert!(runtime.events.iter().all(|event| {
            event != "guard-create"
                && event != "journal-write-any"
                && event != "transient-stop"
                && !event.starts_with("stop-")
        }));
    }

    for mutation in ["active", "reference"] {
        let race_root = AtomicTempDir::new();
        let (mut race, hash) = prepare_rooted_unadopted(&race_root.0);
        race.events.clear();
        race.pre_guard_mutation = Some(mutation);
        assert!(matches!(
            SecurityEngine::new(&mut race).cleanup_unadopted(CleanupRequest {
                transaction_id: VALID_TRANSACTION.into(),
                artifact_sha256: hash,
            }),
            Err(SecurityError::Uncertain(_))
        ));
        assert!(
            race.fs
                .read_file(MODE1_CREDENTIAL_PATH, 4096)
                .unwrap()
                .is_some()
        );
        assert!(
            race.fs
                .read_file(SECURITY_TRANSACTION_GUARD_PATH, 256)
                .unwrap()
                .is_some()
        );
        let journal = race
            .fs
            .read_file(SECURITY_JOURNAL_PATH, MAX_JOURNAL_BYTES)
            .unwrap()
            .unwrap();
        let journal = SupervisorJournalV1::parse(&journal.bytes).unwrap();
        assert!(journal.cleanup_pre_admission.is_some());
        assert_eq!(race.service.active_state, UnitActiveState::Inactive);
        assert_eq!(race.socket.active_state, UnitActiveState::Inactive);
        assert!(race.events.iter().any(|event| event.starts_with("stop-")));
    }
}

#[test]
fn full_engine_uses_rooted_real_filesystem_with_fake_transport() {
    if !run_root_owned_branch(
        "security::real::tests::full_engine_uses_rooted_real_filesystem_with_fake_transport",
    ) {
        return;
    }
    let root = AtomicTempDir::new();
    let mut runtime = prepare_rooted_engine(&root.0);
    SecurityEngine::new(&mut runtime)
        .provision(ProvisionRequest {
            mode: ProvisionMode::CachedAead,
            with_key: KeySelection::Host,
            adopt_existing: false,
            confirmed: true,
        })
        .unwrap();
    assert_eq!(runtime.service.active_state, UnitActiveState::Inactive);
    assert!(
        runtime
            .fs
            .paths
            .resolve(MODE1_CREDENTIAL_PATH)
            .unwrap()
            .exists()
    );
    assert_eq!(
        fs::metadata(
            runtime
                .fs
                .paths
                .resolve(howy_common::paths::CONFIG_FILE)
                .unwrap()
        )
        .unwrap()
        .mode()
            & 0o7777,
        0o600
    );
    SecurityEngine::new(&mut runtime).enable().unwrap();
    assert_eq!(runtime.service.active_state, UnitActiveState::Active);
    assert_eq!(runtime.socket.active_state, UnitActiveState::Active);

    for boundary in [
        "supervisor-prepared",
        "guard-created",
        "supervisor-guarded-snapshot",
        "socket-stopped",
        "service-stopped",
        "socket-settled-inactive",
        "service-settled-inactive",
        "directory-created-before-observation",
        "disabled-config-installed",
    ] {
        let crash_root = AtomicTempDir::new();
        let mut crash = prepare_rooted_engine(&crash_root.0);
        crash.boundary_name = Some(boundary);
        assert!(
            SecurityEngine::new(&mut crash)
                .provision(ProvisionRequest {
                    mode: ProvisionMode::CachedAead,
                    with_key: KeySelection::Host,
                    adopt_existing: false,
                    confirmed: true,
                })
                .is_err(),
            "boundary {boundary}"
        );
        crash.boundary_name = None;
        SecurityEngine::new(&mut crash).recover().unwrap();
    }

    let cleanup_root = AtomicTempDir::new();
    let mut cleanup = prepare_rooted_engine(&cleanup_root.0);
    cleanup.readiness_failure = true;
    assert!(
        SecurityEngine::new(&mut cleanup)
            .provision(ProvisionRequest {
                mode: ProvisionMode::CachedAead,
                with_key: KeySelection::Host,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    cleanup.readiness_failure = false;
    let outcome = SecurityEngine::new(&mut cleanup).recover().unwrap();
    let command = outcome.cleanup_command.unwrap();
    let hash = command.rsplit(' ').next().unwrap().to_owned();
    cleanup.fs.atomic_failure = Some("quarantine-unlink-fsynced");
    assert!(
        SecurityEngine::new(&mut cleanup)
            .cleanup_unadopted(CleanupRequest {
                transaction_id: VALID_TRANSACTION.into(),
                artifact_sha256: Sha256Digest::parse(hash).unwrap(),
            })
            .is_err()
    );
    cleanup.fs.atomic_failure = None;
    SecurityEngine::new(&mut cleanup).recover().unwrap();
    assert!(
        !cleanup
            .fs
            .paths
            .resolve(MODE1_CREDENTIAL_PATH)
            .unwrap()
            .exists()
    );

    let replacement_root = AtomicTempDir::new();
    let mut replacement = prepare_rooted_engine(&replacement_root.0);
    replacement.readiness_failure = true;
    assert!(
        SecurityEngine::new(&mut replacement)
            .provision(ProvisionRequest {
                mode: ProvisionMode::CachedAead,
                with_key: KeySelection::Host,
                adopt_existing: false,
                confirmed: true,
            })
            .is_err()
    );
    replacement.readiness_failure = false;
    let outcome = SecurityEngine::new(&mut replacement).recover().unwrap();
    let hash = outcome
        .cleanup_command
        .unwrap()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_owned();
    replacement.fs.atomic_failure = Some("quarantine-unlink-fsynced");
    assert!(
        SecurityEngine::new(&mut replacement)
            .cleanup_unadopted(CleanupRequest {
                transaction_id: VALID_TRANSACTION.into(),
                artifact_sha256: Sha256Digest::parse(hash).unwrap(),
            })
            .is_err()
    );
    replacement.fs.atomic_failure = None;
    let manifest_path = replacement
        .fs
        .paths
        .resolve(&format!(
            "{SECURITY_UNADOPTED_DIRECTORY}/{VALID_TRANSACTION}.json"
        ))
        .unwrap();
    fs::remove_file(&manifest_path).unwrap();
    write_mode(&manifest_path, b"{\"replacement\":true}\n", 0o600);
    assert!(SecurityEngine::new(&mut replacement).recover().is_err());
    assert!(
        replacement
            .fs
            .paths
            .resolve(SECURITY_TRANSACTION_GUARD_PATH)
            .unwrap()
            .exists()
    );
    assert!(
        replacement
            .fs
            .paths
            .resolve(SECURITY_JOURNAL_PATH)
            .unwrap()
            .exists()
    );
}
