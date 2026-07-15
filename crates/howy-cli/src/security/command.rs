use std::time::Duration;

use howy_common::provisioning::{MODE1_CREDENTIAL_NAME, MODE1_CREDENTIAL_SOURCE_COMPANION_NAME};

pub const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
pub const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const HOWYD: &str = "/usr/bin/howyd";

pub const CHILD_STDOUT_CAP: usize = 16_384;
pub const CHILD_STDERR_CAP: usize = 16_384;
pub const CREDENTIAL_DEADLINE: Duration = Duration::from_secs(30);
pub const READINESS_DEADLINE: Duration = Duration::from_secs(135);
pub const SYSTEMCTL_DEADLINE: Duration = Duration::from_secs(15);
pub const TPM2_PROBE_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelection {
    Auto,
    Host,
    Tpm2,
    HostAndTpm2,
}

impl KeySelection {
    pub const fn as_systemd_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Host => "host",
            Self::Tpm2 => "tpm2",
            Self::HostAndTpm2 => "host+tpm2",
        }
    }

    pub const fn may_use_host_secret(self) -> bool {
        matches!(self, Self::Auto | Self::Host | Self::HostAndTpm2)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub executable: String,
    pub arguments: Vec<String>,
    pub clear_environment: bool,
    pub stdin_bytes: usize,
    pub stdout_cap: usize,
    pub stderr_cap: usize,
    pub deadline: Duration,
}

/// The final `-` directs encrypted output to the production runner's bounded,
/// concurrently drained stdout pipe. The hard cap is enforced while the child
/// runs, before its output can accumulate without bound.
pub fn credential_encrypt_command(selector: KeySelection) -> CommandSpec {
    CommandSpec {
        executable: SYSTEMD_CREDS.into(),
        arguments: vec![
            "--no-ask-password".into(),
            "--refuse-null".into(),
            format!("--name={MODE1_CREDENTIAL_NAME}"),
            format!("--with-key={}", selector.as_systemd_value()),
            "--tpm2-pcrs=".into(),
            "encrypt".into(),
            "-".into(),
            "-".into(),
        ],
        clear_environment: true,
        stdin_bytes: 32,
        stdout_cap: 1_024,
        stderr_cap: CHILD_STDERR_CAP,
        deadline: CREDENTIAL_DEADLINE,
    }
}

pub fn readiness_unit_name(transaction_id: &str) -> String {
    format!("howy-readiness-{transaction_id}.service")
}

pub fn readiness_command(
    transaction_id: &str,
    config_path: &str,
    artifact_path: &str,
) -> CommandSpec {
    let unit = readiness_unit_name(transaction_id);
    let properties = [
        format!("LoadCredentialEncrypted={MODE1_CREDENTIAL_NAME}:{artifact_path}"),
        format!("SetCredential={MODE1_CREDENTIAL_SOURCE_COMPANION_NAME}:{artifact_path}"),
        "TimeoutStartSec=10s".into(),
        "RuntimeMaxSec=120s".into(),
        "TimeoutStopSec=10s".into(),
        "KillMode=control-group".into(),
        "SendSIGKILL=yes".into(),
        "MemoryMax=2G".into(),
        "TasksMax=256".into(),
        "LimitCORE=0".into(),
        "LimitMEMLOCK=64K".into(),
        "UMask=0077".into(),
        "NoNewPrivileges=yes".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "PrivateTmp=yes".into(),
        "PrivateDevices=yes".into(),
        "ProtectKernelTunables=yes".into(),
        "ProtectKernelModules=yes".into(),
        "ProtectControlGroups=yes".into(),
        "RestrictNamespaces=yes".into(),
        "RestrictRealtime=yes".into(),
        "RestrictSUIDSGID=yes".into(),
        "RestrictAddressFamilies=AF_UNIX".into(),
        "CapabilityBoundingSet=".into(),
        "AmbientCapabilities=".into(),
        "SystemCallArchitectures=native".into(),
        "LockPersonality=yes".into(),
        "MemoryDenyWriteExecute=no".into(),
    ];
    let mut arguments = vec![
        "--system".into(),
        "--wait".into(),
        "--collect".into(),
        "--pipe".into(),
        "--quiet".into(),
        "--no-ask-password".into(),
        "--service-type=exec".into(),
        "--expand-environment=no".into(),
        format!("--unit={unit}"),
    ];
    for property in properties {
        arguments.push(format!("--property={property}"));
    }
    arguments.extend([
        HOWYD.into(),
        "--storage-readiness-only".into(),
        "--config".into(),
        config_path.into(),
        "--verify-records".into(),
    ]);
    CommandSpec {
        executable: SYSTEMD_RUN.into(),
        arguments,
        clear_environment: true,
        stdin_bytes: 0,
        stdout_cap: CHILD_STDOUT_CAP,
        stderr_cap: CHILD_STDERR_CAP,
        deadline: READINESS_DEADLINE,
    }
}

pub fn systemctl_command(arguments: impl IntoIterator<Item = String>) -> CommandSpec {
    let mut exact = vec![
        "--system".into(),
        "--no-pager".into(),
        "--no-ask-password".into(),
    ];
    exact.extend(arguments);
    CommandSpec {
        executable: SYSTEMCTL.into(),
        arguments: exact,
        clear_environment: true,
        stdin_bytes: 0,
        stdout_cap: CHILD_STDOUT_CAP,
        stderr_cap: CHILD_STDERR_CAP,
        deadline: SYSTEMCTL_DEADLINE,
    }
}

pub fn tpm2_probe_command() -> CommandSpec {
    CommandSpec {
        executable: SYSTEMD_CREDS.into(),
        arguments: vec!["--quiet".into(), "has-tpm2".into()],
        clear_environment: true,
        stdin_bytes: 0,
        stdout_cap: 0,
        stderr_cap: CHILD_STDERR_CAP,
        deadline: TPM2_PROBE_DEADLINE,
    }
}

pub fn effective_unit_show_command(unit: &str) -> CommandSpec {
    let mut properties = vec![
        "FragmentPath",
        "DropInPaths",
        "NeedDaemonReload",
        "LimitCORE",
        "LimitMEMLOCK",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "NoNewPrivileges",
        "PrivateTmp",
        "ProtectControlGroups",
        "ProtectHome",
        "ProtectKernelModules",
        "ProtectKernelTunables",
        "ProtectSystem",
        "RestrictAddressFamilies",
        "RestrictNamespaces",
        "RestrictRealtime",
        "UMask",
    ];
    if unit.ends_with(".socket") {
        properties.truncate(3);
    }
    systemctl_command(
        ["show".to_owned(), unit.to_owned(), "--all".to_owned()]
            .into_iter()
            .chain(
                properties
                    .into_iter()
                    .map(|property| format!("--property={property}")),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_creds_argv_is_exact_and_contains_no_secret() {
        let spec = credential_encrypt_command(KeySelection::HostAndTpm2);
        assert_eq!(spec.executable, "/usr/bin/systemd-creds");
        assert_eq!(
            spec.arguments,
            [
                "--no-ask-password",
                "--refuse-null",
                "--name=howy.storage.mode1.epoch1",
                "--with-key=host+tpm2",
                "--tpm2-pcrs=",
                "encrypt",
                "-",
                "-",
            ]
        );
        assert!(spec.clear_environment);
        assert_eq!(spec.stdin_bytes, 32);
    }

    #[test]
    fn readiness_argv_is_absolute_no_shell_and_fully_bounded() {
        let spec = readiness_command(
            "txn-0123456789abcdef0123456789abcdef",
            "/etc/howy/config.toml",
            "/etc/credstore.encrypted/howy.storage.mode1.epoch1",
        );
        assert_eq!(spec.executable, "/usr/bin/systemd-run");
        for required in [
            "--system",
            "--wait",
            "--collect",
            "--pipe",
            "--quiet",
            "--no-ask-password",
            "--service-type=exec",
            "--expand-environment=no",
            "--property=TimeoutStartSec=10s",
            "--property=RuntimeMaxSec=120s",
            "--property=TimeoutStopSec=10s",
            "--property=KillMode=control-group",
            "--property=MemoryMax=2G",
            "--property=TasksMax=256",
            "--property=LimitCORE=0",
            "--property=LimitMEMLOCK=64K",
            "--property=UMask=0077",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
        ] {
            assert!(spec.arguments.iter().any(|argument| argument == required));
        }
        assert_eq!(spec.arguments[spec.arguments.len() - 5], HOWYD);
        assert_eq!(
            &spec.arguments[spec.arguments.len() - 4..],
            [
                "--storage-readiness-only",
                "--config",
                "/etc/howy/config.toml",
                "--verify-records",
            ]
        );
        assert!(spec.clear_environment);
    }
}
