# Vendored `aes-gcm` provenance and HOWY patch

- Upstream crate: `aes-gcm` 0.11.0, RustCrypto Developers.
- crates.io checksum: `fdf011db2e21ce0d575593d749db5554b47fed37aff429e4dc50bc91ac93a028`.
- Upstream repository: <https://github.com/RustCrypto/AEADs>.
- Release commit recorded by the crate: `a10b56f281e2d3770e86aec024ea735b2dfa566b` (`aes-gcm/`).

## HOWY delta

The `zeroize` feature now propagates to the optional AES dependency and GHASH.
The AES-derived GHASH key, encrypted J0 tag mask, and computed full tag are held
by private panic-safe guards. The tag mask and expected tag therefore wipe on
success, authentication error, and unwind; key-setup unwind wipes the GHASH-key
block while the separately patched AES schedule drops through its retained wipe.
Runtime tests force unwind immediately after GHASH-key and tag-mask derivation and
exercise the authentication-error path while observing zeroed guarded blocks.

No counter construction, GHASH input, constant-time comparison, ciphertext, tag,
or public API is changed. The enforceable clearing claim covers source-level
addressable guarded blocks. Compiler-introduced copies and values held solely in
CPU registers may not be cleared predictably and are explicitly outside it.
