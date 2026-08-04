# howy — Fast Linux Face Authentication in Rust

**howy** is a low-latency Linux face recognition daemon and PAM authentication
system written in Rust. It is a GPU-accelerated alternative to
[Howdy](https://github.com/boltgolt/howdy), with native AMD ROCm/MIGraphX
support, automatic CPU fallback, and guided multi-angle face enrollment.

> **Warning:** This is an experimental, vibe-coded security project. Precautions
> were taken and the code was reviewed, but you should keep an alternative
> authentication method available.

## Why howy?

- **Fast authentication** — approximately **230 ms end-to-end latency** on both
  CPU and GPU inference paths in current testing.
- **AMD GPU acceleration** — native MIGraphX support through ONNX Runtime for
  AMD ROCm systems, with support for CUDA, TensorRT, and OpenVINO providers.
- **Warm Rust daemon** — SCRFD and ArcFace models remain loaded between requests,
  avoiding a cold CNN startup on every `sudo`, login, or PAM authentication.
- **Face ID-inspired enrollment** — a smooth, pose-guided interface captures the
  center plus eight head directions for broader recognition coverage.
- **Linux-native integration** — V4L2 camera capture, Unix socket IPC, a PAM
  module, and a CLI for enrollment and model management.

## Performance

| Inference path | Observed end-to-end authentication latency |
|----------------|--------------------------------------------|
| CPU | ~230 ms |
| GPU | ~230 ms |

These are observed results from the current test setup, not a universal
guarantee. Camera startup, hardware, drivers, ONNX Runtime provider selection,
and system load can affect latency.

## Architecture

```
pam_howy.so  ──┐
howy CLI     ──┼──  Unix socket  ──  howyd (daemon)
enroll.py    ──┘                      ├── SCRFD (face detection)
                                      ├── ArcFace (face recognition)
                                      └── ONNX Runtime (MIGraphX/CUDA/CPU)
```

- **howyd**: Daemon that preloads ONNX models (SCRFD + ArcFace), keeps them hot, and cold-opens the camera only during auth/enrollment.
- **pam_howy.so**: Thin PAM module that connects to the daemon via Unix socket. Panic-safe, falls back gracefully.
- **howy**: CLI for managing face models (`add`, `enroll-batch`, `list`, `remove`, `clear`, `test`, `doctor`, `prewarm`).
- **howy-enroll**: Packaged Python frontend for pose-guided enrollment capture (runs via `uv`).

## Hardware Acceleration: AMD ROCm, CUDA, and CPU

| Provider | Status |
|----------|--------|
| MIGraphX (AMD ROCm) | Working, tested on RX 780M |
| CUDA | Supported via ONNX Runtime, untested |
| OpenVINO | Supported via ONNX Runtime, untested |
| TensorRT | Supported via ONNX Runtime, untested |
| CPU | Always works (final fallback) |

The `provider = "auto"` config discovers providers on every daemon start. A
registration+self-test result is not graph-placement evidence, so persistent
`provider-selection.txt` files are intentionally ignored until profiled
placement can justify provider pinning. MIGraphX may still reuse its separate
persistent `.mxr` compiled-model cache on subsequent boots.

## Install and Run on Arch Linux

The canonical release is the `2.0.1-1` Arch split package family:

| Intended ONNX Runtime path | Howy archive |
|----------------------------|--------------|
| CPU | `howy-cpu-2.0.1-1-x86_64.pkg.tar.zst` |
| ROCm/MIGraphX | `howy-rocm-2.0.1-1-x86_64.pkg.tar.zst` |
| CUDA | `howy-cuda-2.0.1-1-x86_64.pkg.tar.zst` |

Install or choose the desired system ONNX Runtime provider first. Every Howy
variant depends on the exact virtual capability `onnxruntime=1.28.0`; for
example, `onnxruntime-opt-rocm` version 1.28.0 provides that capability. The
exact dependency prevents a provider with incompatible versioned C API symbols
from silently replacing the library used to build Howy. The Howy variant name
records the intended provider but does not install, switch, or override the
provider in the installed ONNX Runtime library. Only one Howy variant can be
installed.

To build all three archives from a v2 release checkout, first install the chosen
ONNX Runtime provider and the build dependencies listed in `PKGBUILD`, then run
as a regular user:

```bash
makepkg --cleanbuild --clean
```

```bash
# Example: confirm the ROCm provider and required virtual capability, then install.
pacman -Q onnxruntime-opt-rocm
pacman -T 'onnxruntime=1.28.0'
sudo pacman -U ./howy-rocm-2.0.1-1-x86_64.pkg.tar.zst
```

Use `pacman -U` only for a fresh install with no existing Howy package/control
state. Substitute the archive matching the provider selected above.

### Supported updates

Do not update a predecessor or an installed v2 package with raw `pacman -U`.
Release-N and candidate predecessors do not contain the updater. For the first
v2 migration, run it from the checked-out v2 release or use the standalone
helper distributed beside the release archive:

```bash
# From the v2 release checkout:
sudo ./scripts/howy-v2-update ./howy-rocm-2.0.1-1-x86_64.pkg.tar.zst

# Or with the standalone helper beside the downloaded archive:
sudo ./howy-v2-update ./howy-rocm-2.0.1-1-x86_64.pkg.tar.zst
```

The installed v2.0.0 helper predates the v2.0.1 admission bridge. Use the
v2.0.1 checkout or standalone helper shown above for the first
`2.0.0-1` → `2.0.1-1` update. After v2.0.1 is installed, later same-v2
updates use the installed helper:

```bash
sudo howy-v2-update ./howy-rocm-2.0.1-1-x86_64.pkg.tar.zst
```

Verify downloaded helpers and archives against their published SHA-256
checksums before running them.

The helper accepts relative or absolute archive paths. It supports the exact
matching transition from release-N `howy-{cpu,rocm,cuda}-git`
`0.1.0.r26.g2dfe39e-1`, ROCm candidate `howy-rocm-mode0` revisions 4–7, or the
same installed stable v2 variant. Cross-variant, skipped, partial, and unknown
states are refused before pacman runs.

The helper verifies the package identity/version and archive SHA-256, preserves
configuration, receipt, data, and unit intent, supplies the expected conflict
answer to pacman, and reconciles security receipts against the installed v2
bytes. Transitional systemd states are normalized to stable active/inactive
intent rather than blocking recovery. Mode 1 reconciliation preserves the
existing authenticated AEAD evidence while rebinding package-derived daemon,
unit, and drop-in identities. Migrating legacy candidate Mode 0 atomically adds
only the explicit empty-credential drop-in; it does not change embedding mode or
migrate model or enrollment data.

Any failure after backup creation leaves the units stopped and retains
`/var/lib/howy/v2-update-backup-v1`. After inspecting the reported state, rerun
the updater with the exact same archive. The helper always reruns that exact
archive through pacman. If the predecessor remains installed, it repeats the
original transition and restores the backed-up config while verifying receipt
preservation. If the target is installed, it reruns a same-name stable update
and retains the live config and receipt rather than restoring stale snapshots.
Successful finalization removes the exact retained backup.

### Initial setup and daemon activation

Packages install a disabled bootstrap and do not enable the service or socket.
Install the models, review `/etc/howy/config.toml` (especially model paths and
camera device), and provision Mode 1 before enabling authentication:

```bash
sudo howy-download-models
sudo howy security provision --mode 1 --presence confirm
sudo howy security set-presence confirm
sudo howy security enable
```

Socket-only activation is the lower-resource, on-demand option. The first PAM
request starts the service, so that request includes daemon model/provider
initialization and warmup time:

```bash
sudo systemctl enable --now howy.socket
```

For the lowest first-auth latency, explicitly enable and start both units. This
starts `howyd` before PAM needs it, allowing provider/session initialization plus
the detector and recognizer warmups to finish ahead of authentication:

```bash
sudo systemctl enable --now howy.socket howy.service
```

Package and local development installs intentionally enable neither activation
policy automatically.

### Presence confirmation

Stable Mode 0 and Mode 1 installations can change the presence policy in both
enabled and disabled states without reprovisioning storage:

```bash
sudo howy security set-presence confirm
sudo howy security set-presence off
```

Selecting `confirm` ensures that `sudo` is in the presence PAM-service
allowlist and manages exactly `/etc/sudoers.d/90-howy-pam-prompt` as a
root-owned, single-link regular file with mode `0440` and these exact bytes:

```sudoers
Defaults !pam_silent
```

The command accepts only an absent managed path or that exact file. It creates
an absent file atomically without replacement, verifies it, and runs the full
`/usr/bin/visudo -cf /etc/sudoers` check before changing the Howy config or
receipt. A pre-existing exact file is retained and still validated. A missing
sudo/visudo installation, missing required sudoers path, validation failure, or
different content, ownership, mode, object type, or link state causes
confirmation to be refused without overwriting the path. If a later
confirmation change fails, Howy removes only the exact override it created for
that attempt; it never removes a pre-existing exact override on that failure.

Selecting `off` changes the Howy config/receipt first, then removes only the
exact managed file. An absent path succeeds. A differing path is retained and
reported as uncertain after presence has been set to off. Repeating either
command still performs these ensure/validate/remove checks.

Sudo 1.9.16 and newer enables `pam_silent` by default, which supplies
`PAM_SILENT` during PAM authentication. Howy deliberately cancels a required
confirmation under `PAM_SILENT` without opening the camera; the managed
`Defaults !pam_silent` setting permits sudo's PAM conversation to display the
prompt. Enter (an empty response) or exact uppercase `OK` confirms one scan;
any other response cancels and falls through to the next configured PAM method.
Password fallback still depends on the administrator's PAM stack.

Package installation and updates do not add/remove this sudoers file or edit
PAM policy. Only an explicit root `howy security set-presence confirm|off`
command manages it.

```bash
# Optional accelerator prewarm, then deployment check.
sudo howy prewarm
howy doctor
```

### Face Enrollment

The package installs `/usr/bin/howy-enroll` as the current PEP 723 script with
the `uv run --script` launcher. `uv` is an optional runtime dependency; install
it before enrollment. On launch, `uv` manages the Python environment and the
dependencies declared in the script. No separate Python environment is shipped
by Howy.

```bash
# Capture frames with pose guidance
howy-enroll --device /dev/video2 --user "$USER" --label default

# Enroll the captured frames
sudo howy enroll-batch --user "$USER" --session-dir /tmp/howy-enroll-XXXXX --label default --delete-on-success

# Test authentication
sudo howy test --user "$USER"
```

### Removal

Remove the installed variant by its exact package name:

```bash
sudo pacman -R howy-rocm
```

The package hook stops and disables both units. Package-owned files are removed,
while administrator configuration, security receipts, credentials, enrolled
records, model data, logs, and caches are preserved; pacman may retain the
managed config as `/etc/howy/config.toml.pacsave`.

### Linux PAM Integration

howy is designed as a drop-in replacement for howdy. The package and local
development installer place `pam_howy.so` but never edit PAM service
configuration; PAM integration remains an explicit administrator step.

The PAM service name and LOCAL/REMOTE origin are client-supplied policy context,
not attested identity. A same-UID custom client can claim an allowlisted service
and use the protocol without displaying the supported PAM UI. Confirmation
therefore proves user intent only in supported clients; it is not liveness/PAD
and does not provide a trusted-path UI.

## Development-only Source/Local Install

This is not a package update path. On Arch, `scripts/install-local.sh` checks all
artifact destinations with `pacman -Qo` before building and refuses to overwrite
any package-owned file. Use the package update/removal flow above first, or use
custom destinations on a development system. Non-Arch development hosts skip
the ownership check when `pacman` is unavailable.

Development prerequisites are a Rust toolchain, a system ONNX Runtime library,
SCRFD and ArcFace models, a V4L2 camera, and optionally FFmpeg for camera
fallback. The Rust daemon, CLI, and PAM module do not require system OpenCV.

```bash
# Build the worktree.
ORT_LIB_PATH=/usr/lib ORT_PREFER_DYNAMIC_LINK=1 cargo build --release

# Install local artifacts for development testing only.
sudo scripts/install-local.sh

# Remove only a local development install.
sudo scripts/uninstall-local.sh
```

`PKGBUILD` retains remote Git source semantics for committed package builds and
installs the canonical checked-in units from `systemd/`. Do not use that remote
source flow for uncommitted performance-test code. Build the worktree directly
and use `scripts/install-local.sh` (which prints and verifies installed SHA-256
hashes), or run the exact local artifacts directly and record their hashes.

## Project Structure

```
crates/
  howy-common/    # Shared types, config, IPC, face models
  howy-daemon/    # Daemon: inference, camera, server
  howy-pam/       # PAM module (cdylib)
  howy-cli/       # CLI tool
scripts/
  enroll.py       # Pose-guided enrollment frontend
  install-local.sh
  uninstall-local.sh
  download-models.sh
proto/
  howy.proto      # IPC schema (protobuf)
systemd/
  howy.service    # Systemd service unit
  howy.socket     # Systemd socket unit
docs/
  ENROLLMENT_DESIGN.md
  FP16_EXPERIMENT.md
  MIGRAPHX_DEPLOYMENT_NOTES.md
```

## License

GPL-2.0. See [LICENSE](LICENSE).
