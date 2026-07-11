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
- **enroll.py**: Python frontend for pose-guided enrollment capture (runs via `uv`).

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

## Install and Run howy on Linux

### Prerequisites

- Rust toolchain
- ONNX Runtime (system package, e.g. `onnxruntime-opt-rocm` on Arch)
- SCRFD and ArcFace ONNX models in `/usr/share/howy/onnx-data/`
- IR camera (or any V4L2 camera)
- FFmpeg (optional fallback when native V4L2 mmap capture fails)

`howyd`, the CLI, and the PAM module do not require system OpenCV. The optional
Python enrollment frontend runs `opencv-python` in its isolated `uv` environment.

### Build & Install

```bash
# Build
ORT_LIB_PATH=/usr/lib ORT_PREFER_DYNAMIC_LINK=1 cargo build --release

# Install (as root)
sudo scripts/install-local.sh

# Prewarm GPU cache (optional, recommended)
sudo howy prewarm

# Check deployment
howy doctor
```

### Daemon activation and first-auth latency

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

Packaging and local install scripts install/reload these units but intentionally
do not enable either activation policy automatically.

`PKGBUILD` retains remote Git source semantics for committed package builds and
installs the canonical checked-in units from `systemd/`. Do not use that remote
source flow for uncommitted performance-test code. Build the worktree directly
and use `scripts/install-local.sh` (which prints and verifies installed SHA-256
hashes), or run the exact local artifacts directly and record their hashes.

### Face Enrollment

```bash
# Capture frames with pose guidance
uv run scripts/enroll.py --device /dev/video2 --user $USER --label default

# Enroll the captured frames
sudo howy enroll-batch --user $USER --session-dir /tmp/howy-enroll-XXXXX --label default --delete-on-success

# Test authentication
sudo howy test --user $USER
```

### Linux PAM Integration

howy is designed as a drop-in replacement for howdy. The local installer places
`pam_howy.so` but never edits PAM service configuration; PAM integration remains
an explicit administrator step.

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
