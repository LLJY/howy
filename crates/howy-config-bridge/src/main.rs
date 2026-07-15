use howy_config_bridge::{BootstrapOutcome, ConfigBridge, CreateOutcome, StashOutcome};

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        fail(
            "expected one command: ensure-layout, bootstrap-release-n, complete-release-n, complete-local-install, create-if-absent, stash-release-n, or recover",
        );
    };
    if arguments.next().is_some() {
        fail("bridge commands accept no additional arguments");
    }

    let mut bridge = ConfigBridge::new();
    let result = match command.to_str() {
        Some("ensure-layout") => bridge
            .ensure_layout()
            .map(|()| "HOWY_LAYOUT_RESULT=Verified"),
        Some("bootstrap-release-n") => bridge.bootstrap_release_n().map(|outcome| match outcome {
            BootstrapOutcome::Installed => "HOWY_BOOTSTRAP_RESULT=Installed",
            BootstrapOutcome::RestoredStash => "HOWY_BOOTSTRAP_RESULT=RestoredStash",
            BootstrapOutcome::VerifiedUpgrade => "HOWY_BOOTSTRAP_RESULT=VerifiedUpgrade",
        }),
        Some("complete-release-n") => bridge.complete_release_n().map(|outcome| match outcome {
            BootstrapOutcome::Installed => "HOWY_BOOTSTRAP_RESULT=Installed",
            BootstrapOutcome::RestoredStash => "HOWY_BOOTSTRAP_RESULT=RestoredStash",
            BootstrapOutcome::VerifiedUpgrade => "HOWY_BOOTSTRAP_RESULT=VerifiedUpgrade",
        }),
        Some("complete-local-install") => bridge
            .complete_release_n()
            .map(|_| "HOWY_LOCAL_RESULT=Complete"),
        Some("create-if-absent") => bridge.create_if_absent().map(|outcome| match outcome {
            CreateOutcome::Created => "HOWY_CONFIG_RESULT=Created",
            CreateOutcome::Occupied => "HOWY_CONFIG_RESULT=Occupied",
        }),
        Some("stash-release-n") => bridge.stash_release_n().map(|outcome| match outcome {
            StashOutcome::Created => "HOWY_STASH_RESULT=Created",
            StashOutcome::Refreshed => "HOWY_STASH_RESULT=Refreshed",
            StashOutcome::AlreadyExact => "HOWY_STASH_RESULT=AlreadyExact",
        }),
        Some("recover") => bridge.recover().map(|()| "HOWY_RECOVERY_RESULT=Complete"),
        _ => fail("unknown bridge command"),
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
