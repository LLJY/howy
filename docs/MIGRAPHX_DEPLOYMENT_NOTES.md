# MIGraphX Deployment Notes

This note captures what was required to get the live `howyd` daemon onto **MIGraphX** on this machine, and what must remain true for persistent cached startup.

## What was broken initially

- MIGraphX could see the GPU and begin compilation, but warmup failed with:

  ```text
  migraphx_save: Failure opening file: ""/....mxr
  ```

- The daemon then fell back to CPU.
- The failure was **not** the camera path or PAM path. It was specifically the MIGraphX compiled-model cache path handling.

## What fixed it

Two changes were required together:

1. **Stop using the old explicit save/load file-path API** in the Rust `ort` wrapper.
   - Do **not** force `with_save_model(...)` / `with_load_model(...)` for MIGraphX here.

2. **Use runtime cache environment variables instead**:

   ```ini
   ORT_MIGRAPHX_MODEL_CACHE_PATH=/var/cache/howy
   ORT_MIGRAPHX_CACHE_PATH=/var/cache/howy
   ```

On this machine we also needed:

```ini
HSA_OVERRIDE_GFX_VERSION=11.0.2
```

and systemd device access to:

- `/dev/kfd`
- `/dev/dri/renderD128`

## First-run behavior

- The first warmup is expensive.
- MIGraphX compiled the models and produced persistent `.mxr` files under:

  ```text
  /var/cache/howy/
  ```

- Observed cache artifacts were approximately:
  - detector: ~20 MB
  - recognizer: ~179 MB

After those files existed, daemon restart no longer needed a full compile and the service came up with:

```text
provider=migraphx
```

If the config uses `provider="auto"`, howyd also caches the first successfully
resolved provider in:

```text
/var/cache/howy/provider-selection.txt
```

That keeps later boots lean by retrying the known-good provider first. If that
cached provider later fails self-test, howyd falls back to rediscovering from
the full auto chain and rewrites the cache.

## Why this should be treated as cache, not immutable build output

`.mxr` files are environment-sensitive. They should be invalidated and regenerated when any of these change:

- ONNX model file changes
- ONNX Runtime version changes
- ROCm / MIGraphX version changes
- GPU architecture changes
- relevant provider compile settings change

So the correct mental model is:

- **persistent cache**: yes
- **forever stable artifact**: no

## Operational recommendation

- Keep **models hot** in memory.
- Keep **camera cold** until auth starts.
- Prewarm MIGraphX **once** after install or after cache invalidation.
- Use `howyd --prewarm-only` for that one-shot compile/warmup path; it loads config,
  warms inference, does not bind the Unix socket, and still preserves CPU fallback.
- Store compiled cache under `/var/cache/howy`.
- Preserve automatic CPU fallback if MIGraphX startup self-test fails.

## Practical cache invalidation reminder

- Treat `/var/cache/howy/*.mxr` as **persistent cache**, not a forever artifact.
- Treat `/var/cache/howy/provider-selection.txt` as a sticky preference cache for
  `provider="auto"`, not as a permanent truth.
- If the model, ONNX Runtime, ROCm/MIGraphX stack, or GPU architecture changes,
  clear those `.mxr` files, remove `/var/cache/howy/provider-selection.txt`, and
  rerun `howyd --prewarm-only`.
- A small `prewarm-status.txt` marker may exist in `/var/cache/howy` after a
  successful explicit prewarm; it is informational only.

## Current machine-specific working assumptions

- camera: `/dev/video2`
- provider target: `migraphx`
- override: `HSA_OVERRIDE_GFX_VERSION=11.0.2`
- cache dir: `/var/cache/howy`

These are deployment facts for this host, not guaranteed universal defaults.
