# howy

> **Warning**: This is a vibe coded project. Precautions were taken and code was checked, however be warned.

I have always wanted to make an AMD compatible [howdy](https://github.com/boltgolt/howdy) that ran on the GPU, but upstream dlib refused to add support for ROCm.

So I took matters into my own hands.

## What is howy?

howy is a Linux face authentication daemon -- a drop-in replacement for howdy, written in Rust. It aims to solve the biggest pain points:

1. **AMD GPU support** -- Natively supports MIGraphX via ONNX Runtime. The ROCm stack is still finnicky, but it works. Falls back to CPU if GPU isn't available.
2. **Daemon architecture** -- Models stay warm and loaded in memory. No more cold-starting a CNN on every `sudo` like howdy does. Auth typically completes in ~500ms.
3. **\[WIP\] Proper enrollment flow** -- Apple FaceID-style pose-guided enrollment with MediaPipe face tracking. Captures multiple angles for better recognition.

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

## GPU Acceleration

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

## Quick Start

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

### Enrollment

```bash
# Capture frames with pose guidance
uv run scripts/enroll.py --device /dev/video2 --user $USER --label default

# Enroll the captured frames
sudo howy enroll-batch --user $USER --session-dir /tmp/howy-enroll-XXXXX --label default --delete-on-success

# Test authentication
sudo howy test --user $USER
```

### PAM Integration

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
