# Howy bounded Mode 0/1 package candidate

This package is a bounded **Mode 0/1 provisioning candidate**. It is not release
N and it is not a general fresh-install package. Building and structurally
checking the archive does not qualify an installation, authentication path,
camera, model, inference provider, or provisioning transaction.

One package supports explicit plaintext Mode 0 with presence off and receipted
cached-AEAD Mode 1 provisioning. Mode 1 presence is selected at provision time
with `howy security provision --mode 1 --presence off|confirm`; it is bound into
the receipted configuration and is not a runtime toggle. Mode 2 remains
unsupported. The installed default configuration remains explicit Mode 0 with
presence off. Any current live modified configuration mode must be handled
separately before provisioning.

The package owns `/etc/howy/config.toml` with pacman backup semantics. It never
owns model files, embedding records, model directories, data directories, or
other package-created security state. Existing deployment data must not be
adopted implicitly.

The package-owned `/var/lib/howy-package-bootstrap.complete` file is a static
provisioning capability and systemd start gate. It is not bridge JSON, a
transaction receipt, or proof that provisioning completed. A future bridge
package must transition this marker explicitly rather than treating its
presence as transaction evidence.

The archive owns `/usr/lib/security/pam_howy.so` and the compatibility alias
`pam_howdy.so -> pam_howy.so`. It replaces the legacy `howdy-git` package, but
does not own or modify any PAM policy. PAM policy remains an administrator-owned
choice. The package also does not enable or start its systemd units.

In Mode 0, the PAM module authenticates without emitting messages when an
application supplies `PAM_SILENT`, as sudo does by default. Mode 1 with presence
confirmation requires the administrator to permit PAM prompts. The Python
enroller continues to delegate storage changes to the daemon and is unaffected
by this package capability change.

Provisioning must have explicit rollback lanes before, during, and after the
transaction. Any deployment must use a separate, reviewed adoption and rollback
runbook that accounts for the existing configuration, models and records, PAM
policy, unit state, hardware-specific camera and ROCm device paths, and cache
lifecycle. Before removing this package, stop `howy.socket` and `howy.service`;
there is no package scriptlet or hook to stop them automatically.

Build without installing:

```sh
scripts/build-package-deploy.sh
```

Inspect the resulting archive without pacman or service activation:

```sh
scripts/tests/package-deploy-smoke.sh
```

All build, source, archive, log, extraction, and smoke-test work remains below
the ignored `target/package-deploy/` directory.
