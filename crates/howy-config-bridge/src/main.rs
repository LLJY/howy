use std::ffi::OsStr;

use howy_config_bridge::{BootstrapOutcome, ConfigBridge, CreateOutcome, StashOutcome};

const COMMAND_GRAMMAR: &str = "expected one command: ensure-layout, bootstrap-release-n, complete-release-n, complete-local-install, create-if-absent, stash-release-n, recover, validate-current-marker, or validate-current-marker-structure";

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
    ValidateCurrentMarkerStructure,
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
            Some("validate-current-marker-structure") => Some(Self::ValidateCurrentMarkerStructure),
            _ => None,
        }
    }
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        fail(COMMAND_GRAMMAR);
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
        BridgeCommand::ValidateCurrentMarkerStructure => bridge
            .validate_current_marker_structure()
            .map(|()| "HOWY_MARKER_STRUCTURE_RESULT=Valid"),
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

    use super::{BridgeCommand, COMMAND_GRAMMAR};

    #[test]
    fn command_surface_includes_both_read_only_marker_validators() {
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
            (
                "validate-current-marker-structure",
                BridgeCommand::ValidateCurrentMarkerStructure,
            ),
        ] {
            assert_eq!(BridgeCommand::parse(OsStr::new(name)), Some(expected));
        }

        for unknown in [
            "validate_current_marker",
            "validate-marker",
            "current-marker",
            "recover-current-marker",
            "validate_current_marker_structure",
        ] {
            assert_eq!(BridgeCommand::parse(OsStr::new(unknown)), None);
        }
    }

    #[test]
    fn missing_command_help_lists_both_marker_validators() {
        assert!(COMMAND_GRAMMAR.contains("validate-current-marker,"));
        assert!(COMMAND_GRAMMAR.ends_with("validate-current-marker-structure"));
    }
}
