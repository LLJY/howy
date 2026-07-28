use std::ffi::OsStr;

use howy_config_bridge::{BootstrapOutcome, ConfigBridge, CreateOutcome, StashOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgeCommand {
    EnsureLayout,
    BootstrapReleaseN,
    CompleteReleaseN,
    CompleteLocalInstall,
    CreateIfAbsent,
    StashReleaseN,
    Recover,
    ValidateCurrentMarker,
}

impl BridgeCommand {
    fn parse(command: &OsStr) -> Option<Self> {
        match command.to_str() {
            Some("ensure-layout") => Some(Self::EnsureLayout),
            Some("bootstrap-release-n") => Some(Self::BootstrapReleaseN),
            Some("complete-release-n") => Some(Self::CompleteReleaseN),
            Some("complete-local-install") => Some(Self::CompleteLocalInstall),
            Some("create-if-absent") => Some(Self::CreateIfAbsent),
            Some("stash-release-n") => Some(Self::StashReleaseN),
            Some("recover") => Some(Self::Recover),
            Some("validate-current-marker") => Some(Self::ValidateCurrentMarker),
            _ => None,
        }
    }
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        fail(
            "expected one command: ensure-layout, bootstrap-release-n, complete-release-n, complete-local-install, create-if-absent, stash-release-n, recover, or validate-current-marker",
        );
    };
    if arguments.next().is_some() {
        fail("bridge commands accept no additional arguments");
    }

    let mut bridge = ConfigBridge::new();
    let Some(command) = BridgeCommand::parse(&command) else {
        fail("unknown bridge command");
    };
    let result = match command {
        BridgeCommand::EnsureLayout => bridge
            .ensure_layout()
            .map(|()| "HOWY_LAYOUT_RESULT=Verified"),
        BridgeCommand::BootstrapReleaseN => {
            bridge.bootstrap_release_n().map(|outcome| match outcome {
                BootstrapOutcome::Installed => "HOWY_BOOTSTRAP_RESULT=Installed",
                BootstrapOutcome::RestoredStash => "HOWY_BOOTSTRAP_RESULT=RestoredStash",
                BootstrapOutcome::VerifiedUpgrade => "HOWY_BOOTSTRAP_RESULT=VerifiedUpgrade",
            })
        }
        BridgeCommand::CompleteReleaseN => {
            bridge.complete_release_n().map(|outcome| match outcome {
                BootstrapOutcome::Installed => "HOWY_BOOTSTRAP_RESULT=Installed",
                BootstrapOutcome::RestoredStash => "HOWY_BOOTSTRAP_RESULT=RestoredStash",
                BootstrapOutcome::VerifiedUpgrade => "HOWY_BOOTSTRAP_RESULT=VerifiedUpgrade",
            })
        }
        BridgeCommand::CompleteLocalInstall => bridge
            .complete_release_n()
            .map(|_| "HOWY_LOCAL_RESULT=Complete"),
        BridgeCommand::CreateIfAbsent => bridge.create_if_absent().map(|outcome| match outcome {
            CreateOutcome::Created => "HOWY_CONFIG_RESULT=Created",
            CreateOutcome::Occupied => "HOWY_CONFIG_RESULT=Occupied",
        }),
        BridgeCommand::StashReleaseN => bridge.stash_release_n().map(|outcome| match outcome {
            StashOutcome::Created => "HOWY_STASH_RESULT=Created",
            StashOutcome::Refreshed => "HOWY_STASH_RESULT=Refreshed",
            StashOutcome::AlreadyExact => "HOWY_STASH_RESULT=AlreadyExact",
        }),
        BridgeCommand::Recover => bridge.recover().map(|()| "HOWY_RECOVERY_RESULT=Complete"),
        BridgeCommand::ValidateCurrentMarker => bridge
            .validate_current_marker()
            .map(|()| "HOWY_MARKER_RESULT=Valid"),
    };

    match result {
        Ok(message) => println!("{message}"),
        Err(error) => fail(&error.to_string()),
    }
}

fn fail(message: &str) -> ! {
    eprintln!("howy-config-bridge: refusal: {message}");
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::BridgeCommand;

    #[test]
    fn command_surface_includes_exact_read_only_marker_validator() {
        for (name, expected) in [
            ("ensure-layout", BridgeCommand::EnsureLayout),
            ("bootstrap-release-n", BridgeCommand::BootstrapReleaseN),
            ("complete-release-n", BridgeCommand::CompleteReleaseN),
            (
                "complete-local-install",
                BridgeCommand::CompleteLocalInstall,
            ),
            ("create-if-absent", BridgeCommand::CreateIfAbsent),
            ("stash-release-n", BridgeCommand::StashReleaseN),
            ("recover", BridgeCommand::Recover),
            (
                "validate-current-marker",
                BridgeCommand::ValidateCurrentMarker,
            ),
        ] {
            assert_eq!(BridgeCommand::parse(OsStr::new(name)), Some(expected));
        }

        for unknown in [
            "validate_current_marker",
            "validate-marker",
            "current-marker",
            "recover-current-marker",
        ] {
            assert_eq!(BridgeCommand::parse(OsStr::new(unknown)), None);
        }
    }
}
