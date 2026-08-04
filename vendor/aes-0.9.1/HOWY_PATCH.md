# Vendored `aes` provenance and HOWY patch

- Upstream crate: `aes` 0.9.1, RustCrypto Developers.
- crates.io checksum: `f1fc76eaeac4c9164506c466d4ffdd8ec9d0c5bf57ee97177c4d8eceb3a0e138`.
- Upstream repository: <https://github.com/RustCrypto/block-ciphers>.
- Release commit recorded by the crate: `507938ca7c92da77a0ded6fe9d9df6f9be112dbb` (`aes/`).

## HOWY delta

With the existing `zeroize` feature enabled, addressable AES-NI and AArch64
round-key arrays, AES-192's padded input array, inverse-key arrays, and 32/64-bit
fixslice key schedule arrays (including the AES-192 temporary array) now enter a
private zeroizing guard before key expansion. A temporary encryption schedule
consumed while constructing an AArch64 inverse schedule is guarded as well. The
completed schedule is moved into the existing retained schedule while the
emptied guard wipes on success; panic and unwind wipe the populated guard.
Retained schedules keep their existing Drop wipe.

AArch64 composite construction additionally keeps the original private
encryption backend in an owner-classified, disarmable guard until both retained
encryption and inverse/decryption schedules are ready. Only then is the original
schedule moved into the completed public wrapper. The consumed encryption clone
and inverse output have independent guards, so an unwind during inverse
construction wipes both encryption owners and the partially populated inverse
array. This covers AES-128/192/256 direct construction, conversions from
encrypt-only wrappers, decrypt-only construction, and the corresponding
autodetect calls without giving the private backend a Drop implementation or
double-wiping retained public fields.

The optional `aes_backend="avx256"` and `aes_backend="avx512"` source paths use
guarded construction for their addressable broadcast-key arrays. Their lazy
cells are wrapped so an initialized YMM/ZMM broadcast schedule is explicitly
wiped on normal return or unwind. Cfg-specific type assertions require the
AArch64, AVX2, and AVX-512 schedule arrays to remain accepted by the private
guard when those source paths compile. Tests cover initialized lazy-cell Drop
and forced unwind during broadcast construction without requiring VAES for the
type/Drop check.

The arithmetic and dispatch are unchanged. The patch does not claim control of
compiler-created copies or values kept only in CPU registers, including SIMD or
scalar expression temporaries. It covers source-level addressable arrays and
initialized guarded lazy-cell storage; the compiler/register boundary remains
outside an enforceable Rust source guarantee. Unit instrumentation forces
unwind after software, x86 AES-NI, AArch64, and optional VAES construction where
the corresponding cfg and runtime instruction support are available, then
observes the guard after its wipe. AArch64 composite tests inject unwind at the
second checkpoint and distinguish owner wipes from expansion/inverse scratch
wipes; an additional test exercises the public autodetect `Aes256::new` wrapper.
