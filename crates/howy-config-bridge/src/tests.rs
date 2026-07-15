use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::*;

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "howy-config-bridge-v2-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        for (relative, mode) in [
            ("etc", 0o755),
            ("etc/howy", 0o700),
            ("etc/howy/models", 0o700),
            ("etc/howy/models/mode1", 0o700),
            ("etc/systemd", 0o755),
            ("etc/systemd/system", 0o755),
            ("usr", 0o755),
            ("usr/bin", 0o755),
            ("usr/lib", 0o755),
            ("usr/lib/security", 0o755),
            ("usr/lib/sysusers.d", 0o755),
            ("usr/share", 0o755),
            ("usr/share/howy", 0o755),
            ("usr/share/libalpm", 0o755),
            ("usr/share/libalpm/hooks", 0o755),
            ("var", 0o755),
            ("var/lib", 0o755),
            ("var/lib/howy", 0o700),
            ("var/lib/howy/security-state", 0o700),
            ("var/lib/howy/security-state/unadopted", 0o700),
            ("var/lib/howy/config-bridge", 0o700),
            ("var/cache", 0o755),
            ("var/cache/howy", 0o700),
            ("var/log", 0o755),
            ("var/log/howy", 0o700),
            ("run", 0o755),
            ("run/lock", 0o755),
        ] {
            let directory = path.join(relative);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(mode)).unwrap();
        }
        write_mode(
            &path.join("usr/share/howy/config.bootstrap.toml"),
            BOOTSTRAP_BYTES,
            0o644,
        );
        Self(path)
    }

    fn path(&self, production: &str) -> PathBuf {
        self.0.join(production.trim_start_matches('/'))
    }

    fn install_legacy(&self) {
        write_mode(&self.path(CONFIG_PATH), LEGACY_BYTES, 0o644);
    }

    fn manifest(&self) -> StashManifest {
        serde_json::from_slice(&fs::read(self.path(MANIFEST_PATH)).unwrap()).unwrap()
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn assert_marker(root: &TestRoot) {
    let path = root.path(MARKER_PATH);
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let marker: BootstrapMarker = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    validate_marker(&marker).unwrap();
}

fn assert_bootstrap(root: &TestRoot) {
    let path = root.path(CONFIG_PATH);
    assert_eq!(fs::read(&path).unwrap(), BOOTSTRAP_BYTES);
    let metadata = fs::symlink_metadata(path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_marker(root);
}

#[test]
fn pinned_fixtures_and_secure_semantics_are_exact() {
    assert_eq!(LEGACY_BYTES, include_bytes!("../../../config.toml"));
    assert_eq!(LEGACY_BYTES.len() as u64, LEGACY_SIZE);
    assert_eq!(sha256(LEGACY_BYTES), LEGACY_SHA256);
    assert_eq!(BOOTSTRAP_BYTES.len() as u64, BOOTSTRAP_SIZE);
    assert_eq!(sha256(BOOTSTRAP_BYTES), BOOTSTRAP_SHA256);
    assert_eq!(
        HowyConfig::secure_bootstrap_template_toml().as_bytes(),
        BOOTSTRAP_BYTES
    );
    validate_bootstrap_semantics(BOOTSTRAP_BYTES).unwrap();
}

#[test]
fn fresh_bootstrap_commits_marker_only_after_exact_target() {
    let root = TestRoot::new();
    root.install_legacy();
    assert_eq!(
        ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap(),
        BootstrapOutcome::Installed
    );
    assert_bootstrap(&root);
    assert!(!root.path(JOURNAL_PATH).exists());
    assert_eq!(
        ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap(),
        BootstrapOutcome::Installed
    );
}

#[test]
fn bootstrap_failure_leaves_positive_marker_absent() {
    let root = TestRoot::new();
    root.install_legacy();
    let mut bridge = ConfigBridge::rooted(&root.0).fail_at("bootstrap-journal-published");
    assert!(bridge.bootstrap_release_n().is_err());
    drop(bridge);
    assert!(!root.path(MARKER_PATH).exists());
    ConfigBridge::rooted(&root.0).recover().unwrap();
    assert_bootstrap(&root);
}

#[test]
fn create_if_absent_is_distinct_and_never_replaces_occupied_objects() {
    let root = TestRoot::new();
    assert_eq!(
        ConfigBridge::rooted(&root.0).create_if_absent().unwrap(),
        CreateOutcome::Created
    );
    assert_eq!(fs::read(root.path(CONFIG_PATH)).unwrap(), BOOTSTRAP_BYTES);

    for kind in ["regular", "symlink", "fifo", "directory"] {
        let root = TestRoot::new();
        let target = root.path(CONFIG_PATH);
        match kind {
            "regular" => write_mode(&target, b"administrator\n", 0o600),
            "symlink" => symlink("dangling", &target).unwrap(),
            "fifo" => {
                let name = CString::new(target.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "directory" => fs::create_dir(&target).unwrap(),
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&target).unwrap();
        assert_eq!(
            ConfigBridge::rooted(&root.0).create_if_absent().unwrap(),
            CreateOutcome::Occupied,
            "kind={kind}"
        );
        let after = fs::symlink_metadata(&target).unwrap();
        assert_eq!(before.ino(), after.ino(), "kind={kind}");
    }
}

#[test]
fn present_stash_restores_absent_legacy_or_exact_stashed_target() {
    for target_state in ["absent", "legacy", "stashed"] {
        let root = TestRoot::new();
        let config = root.path(CONFIG_PATH);
        write_mode(&config, b"administrator=true\n", 0o640);
        let original = fs::symlink_metadata(&config).unwrap();
        assert_eq!(
            ConfigBridge::rooted(&root.0).stash_release_n().unwrap(),
            StashOutcome::Created
        );
        let manifest = root.manifest();
        assert!(matches!(
            manifest.active.state,
            GenerationState::PresentStashed { .. }
        ));
        match target_state {
            "absent" => fs::remove_file(&config).unwrap(),
            "legacy" => {
                fs::remove_file(&config).unwrap();
                root.install_legacy();
            }
            "stashed" => {}
            _ => unreachable!(),
        }
        assert_eq!(
            ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap(),
            BootstrapOutcome::RestoredStash,
            "state={target_state}"
        );
        assert_eq!(fs::read(&config).unwrap(), b"administrator=true\n");
        let restored = fs::symlink_metadata(&config).unwrap();
        assert_eq!(restored.mode() & 0o7777, original.mode() & 0o7777);
        assert_eq!(restored.uid(), original.uid());
        assert_eq!(restored.gid(), original.gid());
        assert_eq!(restored.mtime(), original.mtime());
        assert_eq!(restored.mtime_nsec(), original.mtime_nsec());
        assert!(matches!(
            root.manifest().active.state,
            GenerationState::Restored { .. }
        ));
        assert_marker(&root);
    }
}

#[test]
fn present_stash_refuses_every_other_target_untouched() {
    let root = TestRoot::new();
    write_mode(&root.path(CONFIG_PATH), b"captured=true\n", 0o600);
    ConfigBridge::rooted(&root.0).stash_release_n().unwrap();
    write_mode(&root.path(CONFIG_PATH), b"intruder=true\n", 0o600);
    let before = fs::read(root.path(CONFIG_PATH)).unwrap();
    assert!(ConfigBridge::rooted(&root.0).bootstrap_release_n().is_err());
    assert_eq!(fs::read(root.path(CONFIG_PATH)).unwrap(), before);
    assert!(!root.path(MARKER_PATH).exists());
}

#[test]
fn absent_stash_restores_absence_from_absent_or_exact_legacy_only() {
    for target_state in ["absent", "legacy"] {
        let root = TestRoot::new();
        assert_eq!(
            ConfigBridge::rooted(&root.0).stash_release_n().unwrap(),
            StashOutcome::Created
        );
        assert!(matches!(
            root.manifest().active.state,
            GenerationState::Absent { .. }
        ));
        if target_state == "legacy" {
            root.install_legacy();
        }
        ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap();
        assert!(!root.path(CONFIG_PATH).exists(), "state={target_state}");
        assert_marker(&root);
    }

    let conflict = TestRoot::new();
    ConfigBridge::rooted(&conflict.0).stash_release_n().unwrap();
    write_mode(&conflict.path(CONFIG_PATH), b"unexpected\n", 0o600);
    assert!(
        ConfigBridge::rooted(&conflict.0)
            .bootstrap_release_n()
            .is_err()
    );
    assert_eq!(
        fs::read(conflict.path(CONFIG_PATH)).unwrap(),
        b"unexpected\n"
    );
}

#[test]
fn restored_generation_refreshes_to_current_administrator_config() {
    let root = TestRoot::new();
    write_mode(&root.path(CONFIG_PATH), b"generation=one\n", 0o640);
    ConfigBridge::rooted(&root.0).stash_release_n().unwrap();
    ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap();
    write_mode(&root.path(CONFIG_PATH), b"generation=two\n", 0o600);

    assert_eq!(
        ConfigBridge::rooted(&root.0).stash_release_n().unwrap(),
        StashOutcome::Refreshed
    );
    assert!(!root.path(MARKER_PATH).exists());
    let manifest = root.manifest();
    assert_eq!(manifest.active.generation, 2);
    assert!(matches!(
        manifest.active.state,
        GenerationState::PresentStashed { .. }
    ));
    assert_eq!(manifest.consumed_generations.len(), 1);
    assert!(matches!(
        manifest.consumed_generations[0].state,
        GenerationState::ConsumedRefreshable { .. }
    ));

    fs::remove_file(root.path(CONFIG_PATH)).unwrap();
    root.install_legacy();
    ConfigBridge::rooted(&root.0).bootstrap_release_n().unwrap();
    assert_eq!(
        fs::read(root.path(CONFIG_PATH)).unwrap(),
        b"generation=two\n"
    );
    assert_marker(&root);
}

#[test]
fn complete_upgrade_preserves_config_and_revalidates_marker() {
    let root = TestRoot::new();
    write_mode(&root.path(CONFIG_PATH), b"legacy-admin-config\n", 0o600);
    assert_eq!(
        ConfigBridge::rooted(&root.0).complete_release_n().unwrap(),
        BootstrapOutcome::VerifiedUpgrade
    );
    assert_eq!(
        fs::read(root.path(CONFIG_PATH)).unwrap(),
        b"legacy-admin-config\n"
    );
    assert_marker(&root);

    // Reinstall with the same config revalidates and preserves the existing marker.
    let marker_inode = fs::symlink_metadata(root.path(MARKER_PATH)).unwrap().ino();
    ConfigBridge::rooted(&root.0).complete_release_n().unwrap();
    assert_eq!(
        fs::symlink_metadata(root.path(MARKER_PATH)).unwrap().ino(),
        marker_inode
    );
}

#[test]
fn ensure_layout_creates_missing_leaves_and_refuses_symlink_traversal() {
    let root = TestRoot::new();
    fs::remove_dir(root.path("/etc/credstore.encrypted")).ok();
    ConfigBridge::rooted(&root.0).ensure_layout().unwrap();
    assert_eq!(
        fs::symlink_metadata(root.path("/etc/credstore.encrypted"))
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );

    let unsafe_root = TestRoot::new();
    fs::remove_dir(unsafe_root.path("/var/cache/howy")).unwrap();
    symlink("/tmp", unsafe_root.path("/var/cache/howy")).unwrap();
    assert!(
        ConfigBridge::rooted(&unsafe_root.0)
            .ensure_layout()
            .is_err()
    );
    assert!(
        fs::symlink_metadata(unsafe_root.path("/var/cache/howy"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn malformed_controls_and_orphan_stages_are_retained() {
    let root = TestRoot::new();
    root.install_legacy();
    write_mode(&root.path(JOURNAL_PATH), b"{not-json}\n", 0o600);
    assert!(ConfigBridge::rooted(&root.0).recover().is_err());
    assert_eq!(fs::read(root.path(JOURNAL_PATH)).unwrap(), b"{not-json}\n");

    fs::remove_file(root.path(JOURNAL_PATH)).unwrap();
    let orphan = root.path("/etc/howy/.howy-config-bridge-v2-deadbeef-orphan");
    write_mode(&orphan, b"administrator\n", 0o600);
    assert!(ConfigBridge::rooted(&root.0).recover().is_err());
    assert_eq!(fs::read(orphan).unwrap(), b"administrator\n");
}

#[test]
fn sigkill_at_control_and_stage_boundaries_recovers_exactly() {
    // Each child has an isolated root and process. SIGKILL cannot run Drop or
    // test cleanup in the child; the parent performs deterministic recovery.
    for point in [
        "journal-control-before-open",
        "private-control-before-write",
        "private-control-after-write",
        "private-control-after-fsync",
        "private-control-after-link-or-rename",
        "private-control-after-directory-fsync",
        "bootstrap-journal-published",
        "bootstrap-stage-before-open",
        "bootstrap-stage-created-and-synced",
        "bootstrap-exchange-before",
        "bootstrap-exchange-after-directory-fsync",
        "bootstrap-backup-before-unlink",
        "bootstrap-backup-after-directory-fsync",
        "journal-before-unlink",
        "journal-after-unlink-directory-fsync",
        "marker-control-before-open",
        "marker-control-after-directory-fsync",
    ] {
        let root = TestRoot::new();
        root.install_legacy();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _ = ConfigBridge::rooted(&root.0)
                .kill_at(point)
                .bootstrap_release_n();
            unsafe { libc::_exit(90) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFSIGNALED(status) || libc::WEXITSTATUS(status) == 90,
            "point={point} status={status}"
        );

        // A kill before any durable operation may simply leave the old state;
        // otherwise recover completes the journal. Then the idempotent package
        // command completes any marker-only tail.
        let _ = ConfigBridge::rooted(&root.0).recover();
        ConfigBridge::rooted(&root.0)
            .bootstrap_release_n()
            .unwrap_or_else(|error| panic!("point={point}: {error}"));
        assert_bootstrap(&root);
        assert!(!root.path(JOURNAL_PATH).exists(), "point={point}");
    }
}

#[test]
fn exchanged_legacy_stage_is_removed_before_restore_commit() {
    let root = TestRoot::new();
    write_mode(&root.path(CONFIG_PATH), b"administrator=exact\n", 0o640);
    ConfigBridge::rooted(&root.0).stash_release_n().unwrap();
    fs::remove_file(root.path(CONFIG_PATH)).unwrap();
    root.install_legacy();

    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let _ = ConfigBridge::rooted(&root.0)
            .kill_at("restore-exchange-after-directory-fsync")
            .bootstrap_release_n();
        unsafe { libc::_exit(90) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(
        fs::read(root.path(CONFIG_PATH)).unwrap(),
        b"administrator=exact\n"
    );

    ConfigBridge::rooted(&root.0).recover().unwrap();
    assert_eq!(
        fs::read(root.path(CONFIG_PATH)).unwrap(),
        b"administrator=exact\n"
    );
    assert_marker(&root);
    let names: Vec<_> = fs::read_dir(root.path("/etc/howy"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(
        !names
            .iter()
            .any(|name| { name.as_bytes().starts_with(CONFIG_STAGE_PREFIX.as_bytes()) })
    );
}

#[test]
fn sigkill_at_every_restore_manifest_marker_and_journal_boundary_recovers() {
    for point in [
        "restore-journal-published",
        "restore-stage-before-open",
        "restore-stage-created-and-synced",
        "restore-exchange-before",
        "restore-exchange-after-directory-fsync",
        "restore-backup-before-unlink",
        "restore-backup-after-directory-fsync",
        "manifest-stage-before-open",
        "manifest-stage-created-and-synced",
        "manifest-exchange-before",
        "manifest-exchange-after-directory-fsync",
        "manifest-backup-before-unlink",
        "manifest-backup-after-directory-fsync",
        "journal-before-unlink",
        "journal-after-unlink-directory-fsync",
        "marker-control-before-open",
        "marker-control-after-directory-fsync",
    ] {
        let root = TestRoot::new();
        write_mode(&root.path(CONFIG_PATH), b"administrator=restore\n", 0o640);
        ConfigBridge::rooted(&root.0).stash_release_n().unwrap();
        fs::remove_file(root.path(CONFIG_PATH)).unwrap();
        root.install_legacy();

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _ = ConfigBridge::rooted(&root.0)
                .kill_at(point)
                .bootstrap_release_n();
            unsafe { libc::_exit(90) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFSIGNALED(status),
            "restore boundary was not reached: {point}, status={status}"
        );

        let _ = ConfigBridge::rooted(&root.0).recover();
        ConfigBridge::rooted(&root.0)
            .bootstrap_release_n()
            .unwrap_or_else(|error| panic!("point={point}: {error}"));
        assert_eq!(
            fs::read(root.path(CONFIG_PATH)).unwrap(),
            b"administrator=restore\n"
        );
        assert_marker(&root);
        assert!(!root.path(JOURNAL_PATH).exists(), "point={point}");
    }
}

#[test]
fn sigkill_during_identity_checked_marker_refresh_fails_closed_and_recovers() {
    for point in [
        "marker-reset-before-unlink",
        "marker-reset-after-directory-fsync",
        "marker-control-before-open",
        "marker-control-after-directory-fsync",
    ] {
        let root = TestRoot::new();
        write_mode(&root.path(CONFIG_PATH), b"first\n", 0o600);
        ConfigBridge::rooted(&root.0).complete_release_n().unwrap();
        write_mode(&root.path(CONFIG_PATH), b"second\n", 0o600);

        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _ = ConfigBridge::rooted(&root.0)
                .kill_at(point)
                .complete_release_n();
            unsafe { libc::_exit(90) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status), "point={point} status={status}");
        ConfigBridge::rooted(&root.0).complete_release_n().unwrap();
        assert_eq!(fs::read(root.path(CONFIG_PATH)).unwrap(), b"second\n");
        assert_marker(&root);
    }
}
