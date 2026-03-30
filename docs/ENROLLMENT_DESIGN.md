# Enrollment Design (Post-PAM Deployment)

This note captures the proposed direction for **guided face enrollment** now that the basic PAM path is working. It is intentionally focused on architecture and operator flow, not on implementation details yet.

## Goal

Build a simple enrollment frontend that:

- shows a live preview
- guides the user through a pose sequence
- captures multiple high-quality embeddings per user
- allows multiple registrations per user (for natural variation over time)
- reuses the existing howy inference backend wherever possible

The immediate target is **pose-guided enrollment**, not a full identity-management suite.

## What we want from enrollment

- Ask the user to:
  - look straight
  - turn left
  - turn right
  - look up slightly
  - look down slightly
  - optionally continue through a smooth rotation sweep
- Keep only frames that meet quality thresholds
- Store **multiple embeddings per user**, not a single template
- Allow multiple registration sessions per user, so real-world variation (glasses, hair, lighting, time) is naturally covered without special-case logic

That already handles “glasses/no glasses” better than a single-template design.

## Capture / inference model

The UI should **not** become the inference engine.

Recommended split:

- **Backend**
  - owns camera capture and inference
  - runs SCRFD + ArcFace repeatedly
  - estimates pose and quality
  - decides when a frame is accepted
- **Frontend**
  - renders preview and guide overlays
  - shows current target pose and progress
  - displays accepted captures / remaining steps

This keeps the hot path close to the current daemon architecture and avoids duplicating camera/inference logic inside the UI toolkit.

## Recommended handoff architecture

The cleanest near-term enrollment flow is:

1. **Frontend captures frames** into a temporary enrollment session directory
2. **Backend processes the session as a batch** using the same inference stack as auth
3. **Backend stores embeddings + metadata** for the user
4. **Temporary session images are deleted** after successful import

This keeps enrollment UX flexible while ensuring the backend remains the single source of truth for detection, alignment, embedding generation, and acceptance rules.

### Why use a temporary session directory

This is preferable to shoving a giant batch through IPC because:

- frame batches can exceed reasonable IPC payload sizes
- the backend can process incrementally or in batch without protocol complexity
- the frontend can be written in Python now and replaced later without changing backend semantics
- raw frames stay ephemeral and are easy to clean up

### Suggested session layout

Example temporary session directory:

```text
/run/user/$UID/howy-enroll/<session-id>/
  manifest.json
  frame_0001.png
  frame_0002.png
  ...
```

If root-owned backend access becomes simpler with a global spool, a system path like this is also viable:

```text
/var/lib/howy/enroll-spool/<session-id>/
```

### Suggested manifest contents

Keep the manifest lightweight. Useful fields:

- `session_id`
- `user`
- `label`
- `capture_device`
- `created_at`
- optional per-frame metadata:
  - pose target requested by the UI
  - capture order
  - timestamp

## Batch enrollment CLI shape

Recommended backend entry point:

```bash
howy enroll-batch \
  --user lucas \
  --session-dir /run/user/1000/howy-enroll/abc123 \
  --label default \
  --delete-on-success
```

Possible future flags:

- `--keep-input`
- `--max-frames 40`
- `--min-pose-buckets 5`
- `--dry-run`

### Backend responsibilities for `enroll-batch`

For each frame in the session directory, the backend should:

1. detect face
2. align face
3. generate embedding
4. estimate pose / quality
5. reject bad frames
6. dedupe near-identical accepted samples
7. store accepted embeddings and metadata under the target user

The backend should remain authoritative for what counts as an acceptable enrollment sample.

## Frontend recommendation

### Recommended: GTK4 + libadwaita

Reasoning:

- best fit for a Linux-native desktop app
- natural integration with GNOME-style UX and system themes
- good long-term packaging story on Linux
- easier to build a real enrollment window that feels native

Performance-wise, the frontend toolkit is **not** the bottleneck here. The expensive parts are:

- camera capture
- face detection
- embedding generation

So the right question is not “which GUI is fastest?”, but “which GUI fits the architecture best?”. GTK4 wins there.

### Not the first choice: egui

egui is viable, but it is less natural for a polished Linux-native enrollment tool.

Pros:

- pure Rust
- quick to prototype

Cons:

- less native look/feel
- immediate-mode redraw is not the problem, but it does not buy us anything important here
- camera-preview plumbing is still a custom job either way

### Practical conclusion

If we build an enrollment frontend, the best first serious implementation is:

- **GTK4/libadwaita frontend**
- backend-driven inference and pose/quality acceptance logic

### Prototype path

If speed of iteration matters more than polish for the first prototype, a **Python + OpenCV frontend** is reasonable **only for enrollment tooling**.

In that model:

- Python handles camera preview and guide overlays
- Python writes a temporary enrollment session directory
- Python invokes `howy enroll-batch ...`

This keeps Python out of the PAM/auth hot path while letting us prototype UX quickly.

## Pose guidance model

We already have 5-point landmarks from SCRFD. That is enough to add coarse pose estimation.

Near-term pose buckets:

- frontal
- left
- right
- up
- down

The frontend only needs to display the current target and some alignment hints.

Examples:

- draw a face oval / center box
- draw a horizontal eye line target
- show arrows like “turn left a little more”
- show “hold still” when pose + quality are acceptable

## Acceptance criteria per frame

Each captured enrollment frame should pass checks such as:

- one clear face only
- detection confidence above threshold
- face size above threshold
- brightness within acceptable range
- blur/sharpness acceptable
- pose falls into the desired bucket
- embedding is finite and normalized

Only accepted frames should be stored.

## Storage direction

Near-term:

- current JSON is acceptable for iteration

Better long-term:

- SQLite for registrations + metadata

Suggested metadata per accepted frame:

- user
- registration/session label
- timestamp
- detector score
- quality score
- pose bucket
- optional yaw/pitch/roll
- embedding

Raw input images should be treated as temporary enrollment material, not as the durable identity record.

At current scale, exact cosine matching is still sufficient.

## Matching implications

Multiple registrations per user should be treated as normal.

Recommended behavior:

- keep all accepted embeddings
- optionally group by registration session or pose bucket
- match exact cosine against all stored embeddings first

This naturally supports real-world variation like glasses/no-glasses without needing a special “glasses mode”.

No vector DB is required for initial deployment.

## Why not implement this immediately

The current win is that PAM deployment now works.

Enrollment should come next, but as a separate phase, because it adds:

- UI/toolkit decisions
- preview/rendering work
- pose estimation work
- persistence changes

That is a distinct problem from “make PAM face auth stable and fast”.

## Recommended implementation order

1. keep current PAM path stable
2. add `howy doctor` / `howy prewarm` / operational tooling
3. add `howy enroll-batch` backend command
4. implement temporary session-folder handoff
5. build frontend (Python prototype or GTK4 production path)
6. move persistence from JSON to SQLite if needed
