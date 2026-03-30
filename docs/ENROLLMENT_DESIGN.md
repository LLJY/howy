# Enrollment Design

Revised design for face enrollment. Supersedes the earlier over-engineered
version that pushed pose estimation and quality logic into the backend.

## Principle

**The backend is a dumb embedding store with a face gate.**

If SCRFD finds a face in an image, compute the ArcFace embedding and store it
under the target user. That's it. No pose estimation, no quality scoring, no
sharpness checks on the backend side. The frontend owns all enrollment UX
intelligence.

## Pipeline

```
Python frontend          CLI                     Daemon
 (camera + UX)     (enroll-batch)            (inference only)
     |                    |                        |
     |  capture frames    |                        |
     |  w/ pose guide     |                        |
     |  (Apple FaceID     |                        |
     |   style: "roll     |                        |
     |   your head")      |                        |
     |                    |                        |
     |  write frames to   |                        |
     |  temp session dir  |                        |
     |  (/tmp/howy-...)   |                        |
     | -----------------> |                        |
     |                    |  EnrollBatchReq        |
     |                    |  (session_dir, user,   |
     |                    |   label)               |
     |                    | ---------------------> |
     |                    |                        |
     |                    |  for each image:       |
     |                    |    load image          |
     |                    |    detect face (SCRFD) |
     |                    |    if face found:      |
     |                    |      encode (ArcFace)  |
     |                    |      append to store   |
     |                    |    else: skip          |
     |                    |                        |
     |                    |  EnrollBatchResult     |
     |                    | <--------------------- |
     |                    |                        |
     |  print summary     |                        |
     | <----------------- |                        |
```

## Components

### 1. Python enrollment frontend

- Opens the IR/webcam and shows a live preview
- Apple FaceID-style UX: "Look straight, now slowly roll your head around"
- Captures frames at intervals into a temporary session directory
- Writes standard image files (PNG) to: `/tmp/howy-enroll-<session-id>/`
- No inference, no embedding, no ONNX models in Python
- When capture is done, invokes `sudo howy enroll-batch`

### 2. `howy enroll-batch` CLI command

```bash
sudo howy enroll-batch \
  --user lucas \
  --session-dir /tmp/howy-enroll-abc123 \
  --label "laptop IR" \
  --delete-on-success
```

- Sends an `EnrollBatchReq` to the daemon via IPC
- Daemon processes each image file in the session directory
- Reports summary: N frames found, M accepted, K rejected
- Optionally deletes the session directory on success

### 3. Daemon `EnrollBatchReq` handler

For each image file in the session directory:
1. Read image, decode to BGR
2. Run SCRFD face detection
3. If exactly one face detected with reasonable confidence (>0.5):
   - Run ArcFace to get 512-dim embedding
   - Append a `FaceModel` to the user's `UserModels`
4. If no face or multiple faces: skip, record in rejection details
5. Save the updated `UserModels` to disk (bincode format)
6. Return `EnrollBatchResult` with counts and rejection details

**The daemon does NOT:**
- Estimate head pose
- Score frame quality (blur, brightness, sharpness)
- Deduplicate similar embeddings
- Validate pose coverage

All of that is the frontend's problem. The backend just asks: "is there a
face?" and if yes, stores the embedding.

### 4. Auth path (unchanged)

Load all embeddings for the user, brute-force cosine scan. At 200 embeddings
(~400KB of f32 data), this takes <0.1ms and fits in L2 cache.

## Storage

### Format: bincode

Switched from JSON to bincode (`bincode = "1"`). Same `UserModels` struct,
same atomic temp-file + rename write pattern.

- ~3x smaller than JSON for packed f32 arrays
- ~10x faster parse
- Zero overhead for float arrays (stored as raw bytes)
- JSON read fallback preserved for existing `.json` enrollments

File layout:
```
/etc/howy/models/
  lucas.bin          # bincode UserModels
  lucas.json         # legacy, read-only fallback
```

### Why not a vector DB?

At this scale (50-200 embeddings per user, one user at a time), brute-force
cosine scan is faster than any index. Vector DBs (FAISS, usearch, HNSW)
optimize for millions+ of vectors. At 200 vectors, the index construction
and lookup overhead exceeds a raw scan.

If the project ever needs to match across thousands of users with thousands
of embeddings each, migrating to SQLite with a vector extension or a proper
ANN index is straightforward. Not needed now.

## Session directory layout

```
/tmp/howy-enroll-<session-id>/
  frame_0001.png
  frame_0002.png
  ...
  frame_NNNN.png
```

No manifest file. The daemon just globs for image files (png/jpg/bmp) and
processes them in sorted order. Simplicity over ceremony.

## Future

- GTK4/libadwaita frontend to replace the Python prototype
- Multiple enrollment sessions per user (already supported by append semantics)
- Optional dedup at the frontend level before writing frames
- VitisAI / Ryzen AI NPU acceleration (exploration only)
