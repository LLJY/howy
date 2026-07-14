# systemd v261 credential envelope structural fixtures

These three fixtures are source-derived binary envelope fixtures for Howy's
pure outer-envelope parser. They are **not** outputs of live encryption, do not
contain a real credential, and are not valid AES-GCM ciphertext/tag pairs.

The layout and constants are independently transcribed from systemd tag
`v261`:

- `src/shared/creds-util.h`: the host, TPM2-HMAC, and host+TPM2-HMAC IDs and
  `CREDENTIAL_ENCRYPTED_SIZE_MAX`.
- `src/shared/creds-util.c`: packed `encrypted_credential_header`, packed
  `tpm2_credential_header`, eight-byte zero alignment, encrypted metadata, and
  AES-GCM construction order.
- `src/creds/creds.c`: base64 file output.

Each fixture uses key size 32, block size 1, IV size 12, tag size 16, and an
80-byte opaque ciphertext region: 48 bytes for the aligned encrypted metadata
shape of the 25-byte name `howy.storage.mode1.epoch1`, followed by a 32-byte
opaque payload shape. TPM fixtures use literal PCR mask zero, SHA-256 bank
`0x000b`, ECC primary algorithm `0x0023`, an eight-byte synthetic blob, and a
32-byte synthetic policy digest. IV, blob, policy, ciphertext and tag bytes are
deterministic counting patterns solely to expose offsets and padding.

Decoded fixture identities:

| Fixture | Bytes | SHA-256 |
|---|---:|---|
| `host.hex` | 144 | `d457e84f151f179fabf344266e4a6132d6fcfe0a5eb8c3759ce0d77a5902a308` |
| `tpm2-hmac-zero-pcr.hex` | 208 | `9e0ab4b339699bd62f5ffbf21682b8f27d30ca34b240caa2436589ad10ad6611` |
| `host-tpm2-hmac-zero-pcr.hex` | 208 | `0bdcda758e9b230d9274590b7f29662507b61f3625f0ff8788f451c9f10b0e9d` |

Tests verify these hashes before parsing. Cryptographic name authentication,
plaintext size and exact-consumption evidence remain a separate contract and
must come from the later side-effecting systemd/AES-GCM verifier; these files
must never be cited as proof of successful live decryption.
