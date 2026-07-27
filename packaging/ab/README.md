# Howy package A/B benchmark

This directory defines a **build-only** comparison between two immutable Howy
revisions: `master` at `a7d187d723185742fb7cb9ef24e8af50d1e3890e` and
`hardened` at `0b76fa23ad3883ccfa8edd38210766f97cdbb71a`. Both recipes
use the same package name, ROCm runtime dependency, compiler settings, neutral
unit files, and payload layout. The comparison does not cover installation,
PAM behavior, camera capture, systemd activation, configuration migration, or
production authentication.

Build both archives without installing them:

```sh
scripts/build-package-ab.sh
```

Archives, source caches, and build logs stay under
`target/package-ab/{master,hardened}/`. Inspect both packages and run only the
extracted `howyd --help` and `howy --version` entry points with:

```sh
scripts/tests/package-ab-smoke.sh
```

Synthetic detector/recognizer inference is a separate, explicit opt-in. Supply
external model files; the harness creates only target-local symlinks and cache
directories:

```sh
scripts/bench-package-ab.sh --i-understand-this-runs-inference \
  --detector-model /path/to/det_10g.onnx \
  --recognizer-model /path/to/w600k_r50.onnx \
  --iterations 3 --cache-policy warm
```

The benchmark never installs an archive, starts a daemon, accesses a camera,
loads PAM, or invokes systemd. It uses synthetic image data and stores no face
embeddings. Raw logs and CSV results remain below `target/package-ab/benchmark/`.
The packaged `capture_bench` is retained only to compare matched revision
artifacts and is never executed by these scripts because it is camera-oriented.

`Provider: migraphx` reports execution-provider registration preference. It is
not evidence that graph nodes were placed on MIGraphX; graph/node placement
requires separate ONNX Runtime profiling and is outside this A/B slice.
