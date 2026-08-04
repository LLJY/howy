# Vendored `polyval` provenance and HOWY patch

- Upstream crate: `polyval` 0.7.2, RustCrypto Developers.
- crates.io checksum: `b20f20e954175de5f463f67781b35583397d916b1d148738923711b2ad16bee8`.
- Upstream repository: <https://github.com/RustCrypto/universal-hashes>.
- Release commit recorded by the crate: `bf69453b78501703718072e39eb39e47fb1519f8` (`polyval/`).

## HOWY delta

The existing `zeroize` feature now gives `FieldElement` an explicit wipe and
places software hash-key conversion, intrinsic `ExpandedKey` construction, and
the addressable byte arrays used to transfer field elements to/from SIMD
registers in panic-safe guards. On AArch64, the complete addressable NEON
key-construction array and each conversion byte array are guarded. Completed
expanded keys move into the retained POLYVAL state. Drop now explicitly wipes
the retained expanded key/hash key and accumulator while leaving the nonsecret
CPU feature token alone, instead of treating the complete state as opaque flat
storage. A cfg-specific type assertion requires the AArch64 SIMD construction
array to remain accepted by the guard. A test checkpoint forces unwind after
actual software or runtime-selected intrinsic key setup and checks the guard
after zeroization; a separate test exercises the retained-state wipe.

No field arithmetic, dispatch rule, format, or public cryptographic operation is
changed. SIMD/scalar values that exist only as compiler/register temporaries may
be copied or spilled by the compiler and cannot be guaranteed cleared by Rust
source code; the patch's enforceable claim is limited to its addressable guarded
SIMD arrays, field elements, byte arrays, expanded-key structures, and explicit
retained key/accumulator fields.
