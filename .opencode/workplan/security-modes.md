# Security Modes

## Objective

Implement three configurable embedding-storage modes plus optional prompt confirmation. Users may explicitly select insecure operation; new installations receive a secure default. Existing installations are not silently migrated or overwritten.

| Mode | Name | Status | Key between authentications | Embedding plaintext |
|---:|---|---|---|---|
| 0 | Plaintext | Supported | None | Persistent record and daemon cache |
| 1 | AEAD cached | Production default | Guarded daemon memory from systemd TPM/host credential | Cached after authenticated load |
| 2 | AEAD ephemeral | Experimental, feasibility-gated | Private kernel `user` keyring; transient 32-byte read per auth | Request-local and zeroized |
| 3 | Hardware-isolated future | Reserved, unsupported | Undecided | Undecided |

Numbers are stable identifiers, not a strength ranking. Mode 2 narrows passive daemon-memory exposure but does not protect against daemon code execution, live root, or kernel compromise.

AF_ALG is rejected: upstream deprecates it as slower and higher risk than optimized userspace cryptography. Modes 1 and 2 both use userspace AES-256-GCM. TPM operations occur only at service/key activation.

Prompt confirmation is independent of storage mode:

```text
presence.mode = off | confirm
```

It provides a supported-client confirmation UX before camera capture. It is not liveness, PAD, or a trusted human-attestation channel.

## Defaults and Provenance

Three concepts must remain separate:

1. **Legacy field defaults:** existing configs missing the new sections deserialize to mode 0 and prompt off.
2. **Fresh templates:** once mode 1 is qualified, newly generated configs explicitly write mode 1 and prompt confirm.
3. **Provenance:** loaded config records whether each setting was explicit or defaulted so doctor/status can warn accurately.

A wholly missing daemon config fails with an instruction to generate/select a configuration. It does not silently choose a security mode.

Fresh installation provisions and verifies mode 1 before writing/enabling its config. Local reinstall and package upgrade preserve existing config byte-for-byte unless the administrator separately confirms migration. Explicit mode 0 remains valid and supported.

### Frozen configuration schema

```toml
[security]
embedding_mode = 0                 # integer: 0, 1, 2; 3 reserved
key_epoch = 1
max_embeddings_per_user = 1000
max_record_bytes = 2621440
max_plaintext_bytes = 134217728     # cache + active leases + transient buffers

[security.cached]
credential_name = "howy.storage.mode1.epoch1"
max_cached_users = 64
max_cache_bytes = 134217728
require_mlock = true

[security.ephemeral]
sealed_key_blob = "/var/lib/howy/keys/mode2-epoch1.blob"
key_description = "howy:storage:mode2:epoch1"
tpm_parent_handle = "0x81000001"

[presence]
mode = "off"                       # off | confirm
local_only = true
allowed_pam_services = ["sudo"]
prompt_timeout_ms = 30000
commit_to_camera_ms = 1000
scan_timeout_ms = 2000
max_pending_per_uid = 2
max_pending_global = 32
```

Legacy/default deserialization uses mode `0`, presence `off`, and the remaining values above as dormant defaults. `secure_bootstrap_template()` uses mode `1`, presence `confirm`, and `core.disabled = true`. `fresh_template()` is not switched to the secure bootstrap until mode 1 provisioning is qualified.

Validation is exact:

- mode accepts numeric `0..=3`; unknown values fail deserialization; mode 3 parses but validation returns reserved/unsupported;
- epoch is nonzero for encrypted modes;
- embeddings are `1..=1000`;
- record bytes are `4096..=2621440`;
- plaintext budget is at least one record and at most 1 GiB;
- cached users are `1..=4096`; cached bytes are at least one record and no greater than the global plaintext budget;
- credential names are 1..128 ASCII bytes in `[A-Za-z0-9._-]` with no slash;
- mode-2 blob path is absolute; key description is 1..128 printable ASCII bytes with no NUL/newline; TPM parent is exactly `0x` plus eight hex digits and is nonzero;
- presence mode is lowercase `off|confirm`;
- confirm requires at least one allowed PAM service; service names are unique, 1..64 ASCII bytes in `[A-Za-z0-9._-]`;
- prompt timeout is `1000..=300000` ms, commit-to-camera is `100..=10000` ms, scan timeout is `100..=30000` ms;
- pending-per-UID is `1..=16`; global pending is at least per-UID and no greater than 1024.

Mode-specific dormant tables are permitted so users can switch modes without losing configuration. Mode 0 ignores key fields; mode 1 validates cached fields and credential name; mode 2 validates ephemeral fields and is additionally runtime-gated by launcher/key readiness.

## Authorization Matrix

Authorization and target-user NSS resolution occur before storage, key, inference, or camera access. Root does not bypass target-user existence checks.

| Request | Matching UID | Root | Other UID | Exposed result |
|---|---:|---:|---:|---|
| `Ping` | yes | yes | yes | Pong only |
| Public `Info` | yes | yes | yes | Provider name, uptime, embedding dimension, active mode, prompt-required flag, storage-ready Boolean; no paths, usernames, epochs, key details, or migration inventory |
| `Authenticate` when confirmation is off | own user | any existing target | no | Authentication result |
| `BeginAuth` | own user | any existing target | no | Prompt transaction only |
| `CommitAuth` / `CancelAuth` | Same connection and peer as `BeginAuth` | Same | no | Active/cancel state only |
| Enrollment-presence check | own user | any existing target | no | Boolean only |
| `CheckCredential` | own user | any existing target | no | Boolean only |
| `RevokeCredential` | Any cached credential belonging to own canonical username | Any existing target username | no | Generic success/failure |
| Live enrollment | no | any existing target | no | Metadata/count only |
| Batch enrollment | no | any existing target | no | Counts/rejections only |
| Detect/preview | no | yes | no | Detection metadata, never embeddings |
| List enrollment metadata | no | yes | no | Stable IDs, labels, timestamps, generation |
| Remove / clear | no | yes | no | New generation or generic success |
| Root security info / inactive inventory | no | yes | no | Paths, epoch, migration state, key readiness; never key serial/key bytes |
| Reload storage/config | no | yes | no | Generic success/failure |
| Shutdown | no | yes | no | No sensitive payload |

`session_id` is a selector, not trusted proof of session ownership. A matching UID may revoke any cached credential for its own canonical username because revocation only removes privilege; it may not inspect or revoke another username. Unknown commands and wrong protocol phases fail without side effects. Mutations remain root-only because allowing an ordinary user process to enroll an attacker-controlled face would replace a privilege factor. Batch paths use descriptor-relative no-follow access and strict path, file-count, decoded-size, and format limits.

## Normative Storage Contract

### Exact namespaces

- A canonical user is the exact ASCII NSS `pw_name` returned by `getpwnam_r` after validating the request as 1..64 bytes matching `[A-Za-z0-9._-]+`. The request must equal that canonical `pw_name`; no case folding, Unicode normalization, aliases, slash, or traversal syntax is accepted.
- Mode 0 authoritative record: `/etc/howy/models/<canonical-user>.bin`; legacy read-only fallback: `/etc/howy/models/<canonical-user>.json`.
- Mode 1: `/etc/howy/models/mode1/<canonical-user>.hye`.
- Mode 2: `/etc/howy/models/mode2/<canonical-user>.hye`.
- `/etc/howy/models`, `mode1`, and `mode2` are root-owned mode `0700`; records are regular root-owned mode `0600` files.

The selected config mode activates only its namespace. Selecting another mode never imports, deletes, or overwrites inactive records. Selecting a previously used mode intentionally reactivates records that still authenticate under its current model digest and key epoch; doctor warns before the change. Administrators who require re-registration first run explicit root-only clear/purge for the target namespace. No cleanup occurs during startup or config parsing.

### HOWYENC1 encrypted envelope

The envelope has exact little-endian offsets:

```text
0x00  magic[8]                    = "HOWYENC1"
0x08  format_version u16          = 1
0x0a  algorithm_id u16            = 1 (AES-256-GCM)
0x0c  storage_mode u8             = 1 or 2
0x0d  flags u8                    = 0; reject unknown bits
0x0e  header_length u16           = 88 + username_length
0x10  key_epoch u64               = configured active epoch
0x18  record_generation u64       >= 1
0x20  plaintext_length u32
0x24  entry_count u32
0x28  embedding_dimension u16     = 512
0x2a  username_length u16         = 1..64
0x2c  recognizer_model_sha256[32] = SHA-256 of exact recognizer ONNX file bytes
0x4c  nonce[12]                   = fresh OS CSPRNG value
0x58  username[username_length]   = canonical UTF-8 username
      ciphertext[plaintext_length]
      tag[16]
```

AAD is every byte from offset `0x00` through the final username byte. The total file length must equal `header_length + plaintext_length + 16`; trailing bytes are rejected. Maximum plaintext and ciphertext length is 2,621,440 bytes, maximum entries is 1,000, and maximum label length is 256 UTF-8 bytes.

Canonical plaintext is:

```text
payload_version u16 LE = 1
reserved u16 LE        = 0
entry_count u32 LE
repeat entry_count times:
    enrollment_id[16]          # random, nonzero, unique within record
    created_unix_seconds u64 LE
    label_length u16 LE        # 0..256
    reserved u16 LE            # 0
    label[label_length]        # UTF-8
    embedding[512]             # IEEE-754 f32 bit patterns, little-endian
```

No padding is permitted and exact EOF is required. Every embedding value must be finite. Header and payload counts must match. New IDs come directly from the OS CSPRNG; RNG failure aborts the mutation.

AES-GCM uses a 32-byte key, 12-byte nonce generated independently from the OS CSPRNG, and 16-byte tag. Immediate in-process duplicate nonces are rejected. V1 intentionally has no claimed durable global invocation counter because a crash/rollback-safe per-key counter would require additional trusted state. Operators must rotate/re-register long before `2^32` writes under one key; Howy's expected enrollment write volume is many orders below that bound. Documentation must present this as an operational limit, not an enforced guarantee.

### HOWYPLN1 mode-0 record

New mode-0 writes keep the existing `.bin` path but use:

```text
magic[8]                    = "HOWYPLN1"
format_version u16 LE       = 1
flags u16 LE                = 0
record_generation u64 LE    >= 1
recognizer_model_sha256[32]
username_length u16 LE      = 1..64
username[username_length]
canonical_plaintext_payload
```

Unknown flags and trailing bytes are rejected. Existing bincode `.bin` and JSON files remain readable. Until first mutation, a legacy enrollment ID is the first 16 digest bytes of SHA-256 over this exact preimage:

```text
ASCII "howy-legacy-id-v1\0"
username_length u16 LE
canonical_username bytes
original_entry_ordinal u32 LE
created_unix_seconds u64 LE
label_length u16 LE
label UTF-8 bytes
embedding_dimension u16 LE = 512
512 × IEEE-754 f32 bits LE
```

If the first 16 digest bytes for a legacy enrollment ID are all zero, set byte 15 to `1`; this preserves the public nonzero-ID invariant deterministically. The legacy generation digest preimage is `ASCII "howy-legacy-generation-v1\0" || source_length u64 LE || complete_source_bytes`. Interpret digest chunks `[0..8]`, `[8..16]`, `[16..24]`, then `[24..32]` as little-endian u64 and select the first nonzero value; if all are zero, use `1`. First authorized mutation verifies that token and atomically writes HOWYPLN1 with generation 1.

### Mutation CAS table

| Operation | Expected generation | Commit behavior |
|---|---|---|
| First append to absent record | `0` | Create generation `1` |
| Live enrollment append | Generation captured before camera work | Reopen/verify at short commit; conflict if changed; append all accepted models and increment once |
| Batch append | Generation captured before image processing | Reopen/verify at short commit; conflict if changed; append batch and increment once |
| Remove | List generation + stable enrollment ID | Conflict if generation changed or ID absent; increment once |
| Clear | Current expected generation | Authenticate/verify record, unlink, fsync parent; return absent generation `0` |
| List | None | Return stable IDs and current generation; no mutation |
| Authenticate | None | Lease one coherent generation |

Generation increments with checked arithmetic; overflow fails closed. Mutations serialize per canonical username. Conflict never retries implicitly and never overwrites another writer.

### Epoch and durability

Each encrypted mode supports exactly one active epoch in v1, initially `1`. Changing the configured epoch makes prior records unreadable and requires re-registration. Multi-key reads and automatic re-encryption are deferred.

Writes create an unpredictable same-directory temporary file using `O_CREAT|O_EXCL|O_NOFOLLOW`, verify directory/file ownership and type, set mode `0600`, write completely, `fsync` the file, atomically rename over the active record, then `fsync` the parent directory. Any failure leaves either the previous complete record or the new complete record. Stale temp files are ignored and reported for root cleanup. Offline rollback to an older authentic record remains possible.

## Daemon-Owned Storage

One `StorageBackend` handles:

- enrollment presence;
- authentication load;
- live enrollment append;
- batch enrollment append;
- metadata list;
- stable-ID/generation remove;
- clear;
- explicit reload/health diagnostics.

All mutations serialize per user and commit durably before replacing cache state. Normal IPC never returns raw embeddings. Detect/preview remains root-only and loses embedding output unless separately justified.

Cached mode uses daemon-only coherence: no per-auth stat. CRUD updates cache synchronously; external root edits require restart/reload. One hard plaintext-memory budget includes cached entries, outstanding Arc leases, transient decode buffers, and mode-2 request leases. Admission fails before camera start if the budget cannot be reserved.

## Mode 1 — AEAD Cached

Lifecycle:

```text
systemd TPM+host encrypted credential
  → decrypted once at service activation
  → exact 32-byte key copied to guarded daemon allocation
  → decrypt/validate/flatten on first load or daemon CRUD
  → immutable bounded cache
  → warm auth uses Arc references only
```

Startup order is config validation, credential acquisition and hardening, storage readiness, inference initialization, then service readiness. Key memory requires zeroization, `mlock`, `MADV_DONTDUMP`, disabled core dumps, and explicit failure behavior.

No per-auth filesystem metadata, AEAD, HKDF, or TPM operation occurs on a warm cache hit. Mode 1 is the secure production default because it minimizes hot-path latency and avoids experimental keyring orchestration.

PCR binding defaults off. Optional signed-PCR provisioning may be documented after recovery tests; literal rolling-kernel PCR values are not the default. TPM clear, motherboard replacement, or host-secret loss may require re-registration. v1 key rotation requires re-registration.

## Mode 2 — AEAD Ephemeral

Mode 2 does not use AF_ALG and does not keep a long-lived key in howyd heap. “Private kernel keyring” means a `user`-type key linked only into the service-private **session keyring** (`KEY_SPEC_SESSION_KEYRING`), never the per-UID `KEY_SPEC_USER_KEYRING`.

```text
systemd KeyringMode=private
  → exec-style launcher TPM-unseals 32-byte key once
  → launcher inserts readable `user` key into private session keyring
  → desired key mask: KEY_POS_VIEW | KEY_POS_READ; owner/group/other zero
  → launcher zeroizes memory and execs howyd
  → launcher supplies exact decimal serial in a sanitized environment
  → howyd validates type, description, permissions and serial, then unsets it
```

Per authentication:

```text
valid optional prompt commit
  → camera admission
  ├─ camera startup/first-frame path
  └─ keyctl_read exact 32-byte key
       → userspace AES-GCM decrypt
       → zeroize key/cipher state
       → decode/validate/flatten request lease
  → join before matching
  → zeroize labels/embeddings on all exits
```

The launcher is the actual `ExecStart`; `ExecStartPre` cannot populate the private session inherited by the daemon. The serial is not secret, but malformed/out-of-range values, wrong key type/description, unexpected permissions, or ambient search results are rejected. The feasibility gate may widen the desired possessor-only mask only when exact kernel tests prove a narrowly required bit; owner/group/other rights remain zero.

Every daemon child process must call `keyctl_join_session_keyring(NULL)` in a fail-closed pre-exec hook, remove inherited serial metadata, and only then `exec`. This includes the FFmpeg fallback and all future external helpers. If detachment fails, the child is not launched.

The key is readable by howyd and therefore does not resist daemon code execution. It reduces passive long-lived heap exposure only. The key also exists briefly in the launcher and operation-local key buffer. A kernel `trusted` or `logon` key cannot be read for userspace AES-GCM.

### Mode 2 operation transactions

One operation-scoped transaction covers every record operation:

- Enrollment presence before prompting: bounded file existence plus syntactic outer-header checks only; it is reported as a candidate enrollment, not cryptographically verified. Authentication may still fail after confirmation if AEAD/semantic validation fails.
- Authentication: reserve memory, read key once, decrypt/validate/flatten once, zero key immediately, reuse request lease across frames, then zero lease.
- List: read/decrypt once, produce metadata only, zero key and record before response.
- Live enrollment: capture/infer without old record plaintext; at commit, read key once, decrypt current generation, CAS append, encrypt/write, zero all buffers.
- Batch enrollment: process images into bounded zeroizing new-entry buffers; perform one short generation-checked decrypt/append/encrypt commit.
- Remove: read/decrypt once, verify generation and stable ID, modify/encrypt/write, zero.
- Clear: read/decrypt once to authenticate expected generation, then unlink and fsync; zero.
- Public health: backend/launcher/key-serial metadata readiness only; no record access.
- Root reload: revalidate backend/key metadata and bounded outer headers only because mode 2 has no plaintext cache.
- Root security diagnostics: namespace inventory and outer-header syntax require no key; explicit `VerifyRecord` uses one transient authenticated transaction and returns metadata only.

No operation uses more than one key read unless an explicit retry starts a new transaction. Conflicts return to the caller instead of retaining plaintext while retrying.

### Feasibility gate

Before production code, a VM/vTPM or separately approved disposable host must prove:

- TPM sealed-object provisioning and unseal;
- insertion into a private kernel user keyring;
- exact serial availability after launcher `exec`;
- minimal permissions and sibling-unit isolation;
- key nonavailability to spawned helpers such as FFmpeg by replacing/emptying their keyring before exec;
- restart, revoke, launcher failure, and recovery behavior;
- negligible key-read latency;
- acceptable maintained TPM/keyring dependencies.

If any gate fails, mode 2 remains unavailable. No weakening of mode 0/1 units is permitted.

No plaintext is allocated while waiting for prompt or camera admission. After admission, decrypt runs once in parallel with camera startup and is reused across frames. Shared cancellation handles peer disconnect, timeout, shutdown, camera failure, decrypt failure, and memory-budget release.

PCR policy defaults off. Optional PCR binding remains experimental and must survive update/recovery testing before documentation as supported.

## Mode 3 — Reserved

TPM2 is not a practical bulk AEAD engine for multi-kilobyte records. Mode 3 is parsed as reserved and rejected with a clear unsupported error. Future candidates include TPM-assisted per-record DEK unwrap, a TEE, HSM, or maintained protected-key interface. Any such backend requires a new reviewed workplan.

## Prompt Confirmation

The supported PAM client uses a checked echo-on conversation before camera access:

```text
Face authentication requested. Press Enter or submit to allow one camera scan; cancel to use another method.
```

Protocol:

1. PAM opens one connection and sends `BeginAuth` with client nonce and policy context.
2. Daemon checks peer authorization, policy, backend/key readiness, bounded record existence, and outer-header syntax only. Mode 2 cannot prove record authenticity before decrypt.
3. Daemon returns a high-entropy one-use token bound to daemon instance, peer UID, username, client nonce, mode, and monotonic expiry.
4. PAM invokes `pam_conv` while camera remains untouched.
5. While pending, PAM sends exactly one `CommitAuth` or `CancelAuth` on the same connection. `CancelAuth` receives a cancellation response and closes the transaction.
6. `CommitAuth` atomically consumes pending state and starts active work. No further request frame is valid on that connection; unexpected data is a protocol violation that cancels active work.
7. The connection worker runs authentication in a subordinate task while independently monitoring socket HUP/EOF and daemon shutdown. HUP/EOF, shutdown, or machine deadline cancels camera and storage work.
8. Exactly one final authentication/error response owns the connection after commit. There is no post-commit `CancelAuth` message in v1; a client cancels active work by closing the connection.

### Frozen prompt protocol v1

Existing protobuf tags remain unchanged. Request oneof tags 18, 19, 20, and 21 are respectively `BeginAuthV1Req`, `CommitAuthV1Req`, `CancelAuthV1Req`, and `AuthenticateV1Req`. Response oneof tags 17 and 18 are respectively `PromptRequiredV1` and `AuthCancelledV1`. `PROMPT_PROTOCOL_VERSION` is 1; client nonces and transaction tokens are exactly 32 bytes and must never be logged or included in errors. Committed authentication reuses only existing `AuthSuccess`, `AuthFailed`, or `Error` terminal responses; `CredentialValid` is not valid after prompt commit in v1.

```protobuf
enum PromptOriginV1 {
  PROMPT_ORIGIN_V1_UNSPECIFIED = 0;
  PROMPT_ORIGIN_V1_LOCAL = 1;
  PROMPT_ORIGIN_V1_REMOTE = 2;
}

message PromptPolicyContextV1 {
  string pam_service = 1;
  reserved 2, 3;
  PromptOriginV1 origin = 4;
}

message BeginAuthV1Req {
  uint32 protocol_version = 1;
  string username = 2;
  reserved 3;
  bytes client_nonce = 4;
  PromptPolicyContextV1 policy = 5;
}

message PromptRequiredV1 {
  uint32 protocol_version = 1;
  bytes transaction_token = 2;
  bytes client_nonce = 3;
  uint32 prompt_timeout_ms = 4;
  uint32 commit_response_timeout_ms = 5;
}

message CommitAuthV1Req {
  uint32 protocol_version = 1;
  bytes transaction_token = 2;
  bytes client_nonce = 3;
}

message CancelAuthV1Req {
  uint32 protocol_version = 1;
  bytes transaction_token = 2;
  bytes client_nonce = 3;
}

message AuthCancelledV1 {
  uint32 protocol_version = 1;
  bytes client_nonce = 2;
}

message AuthenticateV1Req {
  uint32 protocol_version = 1;
  string username = 2;
  uint32 timeout = 3;
}
```

Username and `pam_service` are 1–64 ASCII bytes using `[A-Za-z0-9._-]`; the service allowlist match is exact and case-sensitive, and NSS canonicalization remains authoritative for the username. `policy` is required. Origin must be exactly LOCAL or REMOTE; zero and unknown values fail closed. The supported PAM client derives LOCAL only from null/empty `PAM_RHOST`; raw `PAM_RHOST` and `PAM_TTY` never cross IPC. REMOTE is rejected when `presence.local_only` is true. `prompt_timeout_ms` is `1000..=300000`; `commit_response_timeout_ms` is `1000..=120000`. Both are relative ceilings; no daemon clock value is exposed. Confirmed authentication uses daemon-owned presence/machine budgets and has no client timeout override.

Pending server state binds daemon instance, connection, peer UID, canonical username/UID, client nonce, token, normalized service/origin, security-policy generation, storage mode/epoch, and monotonic expiry. The pending deadline starts only after successful `PromptRequiredV1` transmission. Commit must fail closed if the security-relevant policy or storage identity changed. No wire-visible policy digest is used.

Error codes are frozen as follows: unsupported versions, Begin while prompt mode is off, and legacy Authenticate while confirmation is active use `prompt_protocol_incompatible`; malformed bounds/enums, wrong phase, unexpected/duplicate/post-commit frames use `prompt_protocol_violation`; policy/capacity/candidate/backend readiness failure uses `prompt_unavailable`; correctly shaped stale, mismatched, expired, restarted, or policy-invalidated transactions use `prompt_transaction_invalid`. Any terminal protocol error consumes/releases pending state and closes. Pending HUP/EOF/expiry releases state without requiring a response when the peer is gone.

After Commit, the connection supervisor is the sole response writer and authentication work returns a response value rather than writing. Extra request data cancels active work and makes one protocol-violation response the sole terminal attempt; HUP/EOF cancels with no response. At most one terminal response write is attempted. The prompt client applies the validated `commit_response_timeout_ms` plus a fixed 250 ms transport margin before waiting for the terminal response. `howy test` uses only request tag 21, which is unknown to legacy daemons and is accepted by current daemons only when confirmation is off; it never retries legacy tag 1. The supported PAM prompt flow uses Begin/Commit, while legacy tag 1 remains only for backward-compatible prompt-off PAM clients. The protocol slice proves no request-triggered camera/inference/authentication-load work before Commit; the later lazy-camera step separately proves no startup probe/open/configure/start/stream event.

Legacy one-shot auth is rejected when confirmation is enabled. Old/new PAM-daemon combinations fail to password-compatible PAM flow without camera access. `howy test` either performs its own checked prompt or refuses noninteractive use.

A same-UID malicious client can commit without displaying a prompt. Therefore the precise claim is: the supported PAM client requests confirmation and the daemon enforces commit-before-camera protocol ordering. It is not trusted-path human attestation.

Camera profile probing becomes lazy. Daemon startup, socket activation, pending prompts, cancellation, expiry, malformed commits, and restart perform no probe/open/configure/start operation.

Pending and active transactions are bounded. Pending work supports explicit `CancelAuth`; active work supports HUP/EOF, shutdown, and deadline cancellation. Machine deadlines separately cover admission, first frame, scan, storage, and cleanup; PAM read timeout includes those phases plus margin but human prompt dwell is excluded from performance measurements.

## Packaging and Upgrade

One root-only command owns activation transactions:

```text
howy security provision --mode 0|1|2
howy security enable
```

The disabled bootstrap contains `core.disabled = true`, explicit `[security] embedding_mode = 1`, `key_epoch = 1`, and `[presence] mode = "confirm"`. Mode 1 uses credential name `howy.storage.mode1.epoch1` at `/etc/credstore.encrypted/howy.storage.mode1.epoch1`. Mode 2 uses `/var/lib/howy/keys/mode2-epoch1.blob` and the explicitly configured TPM parent handle. Mode 2 artifacts are created only after its feasibility gate passes.

Provisioning state table:

| Existing state | Default behavior |
|---|---|
| No config, no key, empty target namespace | Create key artifact, verify, atomically install disabled candidate config |
| Same explicit mode/epoch and verified key artifact | Idempotent verification; do not replace key or config |
| Config exists, key missing/unreadable | Fail closed; never create a replacement key while target namespace is nonempty |
| Key exists, config absent/mismatched | Refuse implicit adoption; require explicit `--adopt-existing` after key/readiness verification |
| Target namespace contains records and `--new-key` requested | V1 always refuses before side effects. Rotation with retained inactive records requires a future epoch-2 format/policy; re-registration must use a separately reviewed archive/purge transaction. |
| Existing different mode | Preserve config and all namespaces until explicit migration confirmation |
| Candidate readiness failure | Restore prior config and service state; retain newly provisioned artifact as unadopted and report exact cleanup command |

Transaction order:

1. Lock security provisioning and snapshot config bytes plus socket/service active/enabled state.
2. Validate target namespace and idempotence/adoption/new-key flags.
3. Provision key artifact to an exclusive temporary path, fsync, atomically rename, and verify metadata.
4. Write disabled candidate config to a sibling temporary file, fsync, rename, and fsync `/etc/howy`; config is the final durable activation reference.
5. Stop active Howy units for the bounded readiness check. Mode 1 runs a transient systemd unit with the candidate `LoadCredentialEncrypted=` and `howyd --storage-readiness-only --config <candidate>`; mode 2 runs the candidate launcher with the same readiness-only daemon mode. Readiness performs no camera probe or inference.
6. If readiness succeeds, leave the candidate disabled and restore prior unit active/enabled state only when it does not expose the candidate as active authentication. The command reports `howy security enable` as the explicit next step.
7. `howy security enable` revalidates the same config/key identity, atomically changes only `core.disabled` to false, restarts socket/service, verifies public/root status, and rolls back config plus service state on failure.

Security migration and ordinary config replacement are separate confirmations. A candidate check never probes the already-running daemon and never treats old-daemon readiness as evidence for new state.

### Provisioning v1 transaction corrections

The following rules are normative and supersede any conflicting shorthand above:

- Provisioning and enable use a permanent root-owned no-follow lock plus a durable transaction journal written and directory-synced before the first durable mutation. The journal contains exact prior config/drop-in bytes and metadata plus exact unit `LoadState`, `ActiveState`, `SubState`, and `UnitFileState`; final receipts never contain rollback material. An interrupted transaction must recover deterministically on the next invocation or leave socket and service stopped with backups/journal retained for explicit recovery.
- Both `howy.socket` and `howy.service` carry a persistent start guard equivalent to `ConditionPathExists=!/etc/howy/.security-transaction`. Transaction order is journal `prepared` and synced → guard created and directory-synced → journal `guarded` → socket stopped first, then service, with stable inactivity confirmed → only then artifact/drop-in/config mutations. The guard remains across crashes/reboots and uncertain rollback. Journal phases are versioned and include `prepared`, `guarded`, `units-stopped`, `artifact-committed`, `dropin-committed`, `disabled-config-committed`, `readiness-verified`, `disabled-receipt-committed`, `enabled-config-committed`, `activation-committed`, `units-started`, and `enabled-receipt-committed`, with planned/live hashes, transaction-owned paths, artifact preexistence, transient unit name, backup hashes, and intended recovery action. Units may start only after `activation-committed`, guard removal and directory sync.
- The production Mode 1 service uses a transactionally installed drop-in that first clears inherited credential directives and then binds `howy.storage.mode1.epoch1` to the absolute `/etc/credstore.encrypted/howy.storage.mode1.epoch1` source. A pathless same-named credential must not shadow the receipted artifact. Mode 0 has no fatal absolute credential reference.
- V1 key creation is permitted only for an empty Mode 1 namespace. Existing nonempty namespaces require the already-verified epoch-1 artifact; `--new-key` always refuses. Implicit adoption is forbidden. `--adopt-existing` requires exact artifact verification and strong per-record readiness.
- `systemd-creds` is invoked by the root CLI only, with an exact absolute executable, no shell, bounded pipe/process deadlines, no plaintext argv/environment/file, `--no-ask-password`, `--refuse-null`, `--name=howy.storage.mode1.epoch1`, long-form `--with-key=...`, and empty literal `--tpm2-pcrs=`. The resulting envelope must be parsed and must use the expected non-scoped, non-null, non-PK key ID and embedded name. `auto` output selecting a signed-public-key policy is discarded and rerun with the corresponding explicit non-PK selector or refused; no automatic PCR/public-key policy is claimed.
- Generated and adopted systemd credential envelopes are strictly decoded. TPM-bearing non-PK IDs must also carry a literal PCR mask of exactly zero. Null, scoped, unknown, signed-public-key, additional public-key header, malformed size/padding, trailing-data and embedded-name mismatches are rejected before adoption.
- Strong provisioning readiness is a dedicated read-only daemon path. It opens and hashes the exact candidate config descriptor, loads the candidate credential, inventories the namespace under hard file/count/byte/name caps, and performs no cleanup/mutation/cache/camera/inference/listener work. An empty namespace succeeds without models. A nonempty namespace resolves only the pinned recognizer and decrypts/authenticates every authoritative record sequentially without cache publication. Unexpected entries are rejected or explicitly classified. The verifier emits one bounded versioned result containing config hash, namespace fingerprint, record counts/bytes, key-record compatibility, recognizer identity when applicable, and cache population count zero.
- Provisioning readiness succeeds only when every namespace entry is a canonical authoritative `<username>.hye` root-owned, single-link regular file with valid metadata. Symlinks, directories, hard links, non-UTF-8/unknown names, benign `.tmp` files, and all staged/clear/rollback artifacts are rejected with a cleanup/recovery instruction; readiness never cleans them. Production startup and readiness share the same entry classifier. Fingerprint encoding is domain-separated, tagged and length-prefixed (`HOWNAMESPACE-v1\0`, field tag, u64 little-endian length, bytes) so variable fields are unambiguous.
- Namespace fingerprints are versioned SHA-256 aggregates over a sorted, descriptor-bound inventory: namespace path/metadata policy; every entry name/type; authoritative owner/mode/link-count/size; exact ciphertext SHA-256; classified temporary/rollback artifacts; total count and bytes. Every file is no-follow opened, `fstat`ed before and after streaming, and bounded.
- Transient readiness uses a unique unit and exact `systemd-run --system --wait --collect --pipe --quiet --no-ask-password --service-type=exec` invocation, explicit absolute credential property, start/runtime/stop bounds, cgroup kill policy, hardening properties, bounded stdout/stderr capture, and an independent parent deadline that stops the unique unit on timeout.
- Provisioning writes a root-owned, mode-0600, versioned receipt only after disabled config/drop-in/artifact and strong readiness are durable. The receipt binds exact raw disabled and enabled config hashes plus one byte-range `true`→`false` patch, artifact path/hash/size/metadata/requested selector/actual key ID, exact drop-in and effective source, verifier binary/build identity, readiness protocol/result, recognizer identity when applicable, and namespace fingerprint. It is correlation data, not trusted state; enable revalidates every live object and always reruns strong readiness.
- `security enable` accepts only the exact receipted disabled bytes, applies the exact unique disabled-token byte patch, parses and validates the resulting exact enabled bytes, stops socket before service and waits for stable inactivity, reruns strong readiness, atomically exchanges and syncs config, starts controlled units without changing enablement, verifies a new daemon invocation/root status/config hash/mode/epoch/credential source, then atomically updates the receipt to `enabled`. Failure restores exact config/drop-in/unit state; uncertain rollback stops both units and retains journal/backups.
- Cleanup of an unadopted artifact is a locked reference-safe command bound to transaction ID and artifact hash. It deletes only when no config, receipt, drop-in, journal, or active transaction references that exact artifact. Printed raw `rm` commands are insufficient.
- Cleanup additionally refuses while service/socket is active, activating, deactivating or has a queued job; while a matching readiness transient unit exists; or while a live daemon reports the credential identity. Unit state and artifact descriptor/hash are revalidated immediately before unlink, followed by parent-directory fsync. The safe default is refusal whenever any Howy unit is active.
- Root status includes opened config SHA-256, explicit mode/epoch, credential name and effective absolute source, backend/readiness state, and daemon invocation/build identity. Public status remains non-sensitive.
- Provisioning requires systemd 261+ semantics. TPM-backed selectors declare the reviewed TPM runtime dependency; host-only provisioning remains usable without TPM packages.
- Unit preflight waits within a fixed bound for jobs and transitional states to settle, then resnapshots. It refuses unresolved transitions and masked required units, never invokes enable/disable/mask/unmask, and never changes `UnitFileState`. Successful enable targets both socket and service active while preserving prior enablement. Rollback restores only stable prior `active/running` or `inactive/dead` state; initially failed units are rejected rather than normalized implicitly.
- Bootstrap config creation provides a descriptor-safe `create_if_absent` operation. Every parent is opened without symlink following; any existing object, including a dangling symlink, FIFO or directory, is occupied. A root-owned exclusive sibling temporary is written, metadata-set, fsynced, installed with no-replace rename and parent-directory fsync. Collision never overwrites. Local reinstall decides config preservation before stopping units or replacing runtime artifacts.

### Arch package fresh install

- The package ownership transition for `/etc/howy/config.toml` uses a two-version bridge: pre-upgrade stashes exact config bytes/metadata durably and post-upgrade restores them before any bootstrap decision. Removing package ownership/`backup()` is forbidden until modified, unmodified, `.pacsave`, interrupted-upgrade, reinstall, and rollback tests prove byte preservation from the immediately previous release.
- The current release is bridge release N: it continues owning `etc/howy/config.toml`, retains `backup()`, and ships the `/etc` payload byte-identical to the immediately previous release. True fresh `post_install` uses a distinct locked `replace_exact_packaged_payload` operation: no-follow open; require the exact known packaged bytes/hash, root ownership, single-link regular type and expected metadata; journal a crash-recoverable exchange; write/fsync the disabled bootstrap sibling; atomically exchange; fsync the directory; and recover to either the exact prior payload or complete bootstrap. Any mismatch, symlink, FIFO, directory, hard link or metadata anomaly is untouched. Upgrades and reinstalls never invoke this replacement. Release N installs an ALPM `PreTransaction` hook with `AbortOnFail` and an already-installed helper that durably stashes exact config bytes/metadata before a later Howy upgrade. Ownership removal is deferred to release N+1 and is forbidden in this workplan execution. N+1 may restore from the N-created stash before bootstrap decisions only after real previous→N→N+1 modified/unmodified/interrupted/package-variant tests pass. A surviving bridge manifest always suppresses bootstrap installation; skipped-N upgrades remain unsupported until another bridge is designed.
- It installs a secure disabled mode-1 bootstrap/template under `/usr/share/howy/` and a package `.install` hook.
- On true fresh `post_install`, the hook runs only `replace_exact_packaged_payload` for the bridge-N owned legacy payload and prints the exact provisioning command. Generic absent-path creation uses `create_if_absent`; this bridge-N rule supersedes absent-only shorthand. Upgrades and reinstalls preserve existing config bytes.
- It does not enable face authentication or perform an interactive TPM operation inside pacman.
- Required mode-1 runtime dependencies and optional mode-2 TPM/keyutils dependencies are declared explicitly after current-documentation review.

### Arch package upgrade

- Existing `/etc/howy/config.toml` is never replaced, regardless of whether it matches an old packaged checksum.
- The hook reports missing new fields through `howy doctor`; absent fields retain mode 0/off.
- Explicit migration invokes the common provision command outside pacman.
- Rollback retains the prior config and all namespaces; binaries must continue parsing HOWYENC1/HOWYPLN1 once released.

### Local installer

- First install with no config offers the same mode-1 provisioning transaction or installs the disabled bootstrap when declined.
- Reinstall preserves existing config byte-for-byte by default; its current generic overwrite prompt no longer includes config.
- `--migrate-security` or an equivalent explicit action invokes the shared provision command.
- Installer mock tests inject failure after every key/config/readiness step and verify rollback.

### Explicit mode 0

Provisioning mode 0 writes an explicit enabled plaintext configuration after warning and confirmation; it requires no key. This remains a supported user choice, not an undocumented escape hatch.

Relevant packaging includes `config.toml`, `howy.config`, `PKGBUILD`, `.SRCINFO`, package install hooks, install scripts/tests, units, PAM examples, and mode-specific launcher/provisioning components.

## Performance Qualification

Use one recorded release build, baseline commit/config, fixed hardware/kernel/provider, warm-up count, sample count, and outlier/confidence policy. Never run a concurrent MIGraphX probe against production.

Measure separately:

- socket-activated startup and key activation;
- warm BeginAuth machine latency;
- prompt dwell (reported, excluded from machine regression);
- commit-to-camera-open and first frame;
- mode 1 cold load and warm hit;
- mode 2 key read, AEAD, decode/validate/flatten, overlap and memory pressure;
- post-first-frame inference/matching;
- total post-commit machine latency;
- concurrent CRUD/auth and queue pressure.

Mode 1 warm storage p99 target is `≤ max(0.25 ms, baseline + 5%)` with zero crypto events. Mode 2 must show typical storage completion within the measured first-frame window and controlled total regression; absolute results are qualification data, not universal promises.

## Execution Slices

Each slice is gated:

```text
code-writer implementation
  → targeted checks
  → adversarial code-checker
  → code-writer fixes
  → rerun evidence
  → no open blocker/critical/major
  → next slice
```

Slices execute in order:

1. Normative contracts and format.
2. Daemon-owned storage and mode 0.
3. Prompt confirmation and lazy camera.
4. Mode 1.
5. Mode 2 feasibility gate.
6. Mode 2 production implementation if gate passes.
7. Integration, packaging, claims, and final qualification.

Writers touching config, protocol, daemon server, PAM state, or packaging are not parallelized. Non-overlapping tests and research may run in parallel inside a slice.

## Required Validation

- Format golden vectors, NIST AES-GCM vectors, parser fuzzing, tamper/copy/size tests.
- All mode transitions and namespaces.
- Authorization before side effects.
- Live and batch enrollment, stable IDs, generation conflicts, list/remove/clear.
- Mode 1 cold/hit/cache budget and credential failures.
- Mode 2 launcher/keyring/isolation/transient key/zeroization/overlap in disposable environment.
- Prompt ABI, replay, compatibility, HUP, cancellation, deadlines, and zero camera events before commit.
- Modes 0/1/2 × prompt off/confirm matrix.
- Installer/package upgrade and rollback simulations.
- `systemd-analyze verify`, formatting, check, clippy, workspace/release tests, dependency/license/advisory review, bounded fuzzing, and performance suites.
- Exact unavailable hardware/PAM tests are reported, never marked passing.

## Security Claims and Recovery

Allowed claims:

- modes 1/2 encrypt records at rest;
- mode 1 removes storage crypto from warm authentication;
- mode 2 reduces long-lived userspace key and embedding residency;
- supported prompt clients require confirmation before camera commit;
- explicit mode 0 remains available.

Disallowed claims:

- higher mode number means stronger security;
- mode 2 defeats daemon code execution or live root;
- TPM decrypts embedding payloads;
- rollback protection exists;
- prompt confirmation proves liveness, PAD, trusted input, or blocks photos/masks/video;
- Howy guarantees password fallback independently of PAM configuration.

Recovery prioritizes password access and re-registration. TPM clear, board replacement, host-secret loss, sealed-object loss, or key epoch change may make encrypted records unrecoverable. No automatic plaintext fallback occurs; administrators may explicitly reconfigure mode 0.
