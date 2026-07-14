# Vendored `ghash` provenance

- Upstream crate: `ghash` 0.6.0, published by the RustCrypto Developers.
- crates.io checksum: `2eecf2d5dc9b66b732b97707a0210906b1d30523eb773193ab777c0c84b3e8d5`.
- Upstream repository: <https://github.com/RustCrypto/universal-hashes>.
- Upstream release commit recorded in the crate archive: `2ec214089615c06e19560cd1222366f5d7c79163` (`ghash/`).
- Source archive retrieved from crates.io by Cargo; only files required to build,
  attribute, and license the crate are retained here.
- Upstream tests, benches, changelog, generated lockfile, VCS metadata file, and
  the test-only `hex-literal` dependency are omitted from this minimal vendor.

## Howy delta

`src/lib.rs` changes `GHash::new` when the upstream `zeroize` feature is enabled.
The input field element, byte-reversed field element, multiplied field element,
and final transformed POLYVAL key each enter panic-safe zeroizing ownership before
the next operation. The pinned HOWY `polyval` 0.7.2 patch supplies the missing
`FieldElement: Zeroize` implementation. The existing feature still enables
`polyval/zeroize`, so retained `Polyval` state wipes on drop. `Cargo.toml` retains
the earlier optional feature-only `crypto-common/zeroize` dependency so its `Key`
alias implements `Zeroize`. Algorithm, public API, and feature names are otherwise
unchanged. The POLYVAL dependency is narrowed from upstream `0.7` to the exact
audited and root-lock-selected `=0.7.2` patch target.

Runtime instrumentation forces unwind after the complete transform and checks
all four guards after wiping. Compiler-created copies and values held only in
registers remain outside an enforceable source-level clearing claim; the guarded
addressable field elements and key blocks are the precise boundary.

The changed source file is prominently identified here to satisfy the Apache
2.0 modification-notice requirement. Re-evaluate and remove this patch when an
upstream `ghash` release provides an equivalent compiling fix.
