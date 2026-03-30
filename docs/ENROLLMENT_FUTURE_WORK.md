# Enrollment Future Work (Post-PAM)

This note captures the recommended direction for face enrollment **after** initial PAM deployment and real-world PAM testing. Enrollment quality matters, but the immediate priority is proving that the PAM path is stable, usable, and measurable end to end. Until PAM deployment is validated, enrollment changes should stay out of scope.

## Why defer enrollment now

- First PAM deployment is the critical milestone.
- Deployment/testing should tell us where failures actually occur before we redesign enrollment.
- Mixing PAM rollout work with enrollment changes would make debugging harder and slow validation.

## Recommended near-term enrollment design

- Capture **20-40 high-quality frames** per user, not hundreds.
- Use **pose and quality gating** so only good samples are kept.
- Store **multiple embeddings per user** rather than one averaged vector.
- Use **exact cosine matching** first; this should be sufficient for small user counts.

## Storage options

- Start with **JSON** if that keeps iteration simple.
- Move to **SQLite** later if we want cleaner persistence and querying.
- Keep **`sqlite-vec`** as a future option for vector search in SQLite, but it is probably unnecessary at small scale.

## Pose-aware future plan

- Estimate **yaw / pitch / roll** from face landmarks.
- Bucket stored embeddings by coarse pose.
- Optionally add **centroid templates** per pose bucket later.

## Scope note

This is **future work only** and is **not required for the first PAM deployment**.
