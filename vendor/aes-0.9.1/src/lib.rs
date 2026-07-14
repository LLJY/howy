//! Pure Rust implementation of the [Advanced Encryption Standard][AES]
//! (AES, a.k.a. Rijndael).
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! By default, it performs runtime detection of CPU intrinsics and uses them
//! if they are available.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [fixslicing], a more advanced form of bitslicing
//! implemented entirely in terms of bitwise arithmetic with no use of any
//! lookup tables or data-dependent branches.
//!
//! Enabling the `aes_compact` configuration flag will reduce the code size of this
//! backend at the cost of decreased performance (using a modified form of
//! the fixslicing technique called "semi-fixslicing").
//!
//! ## ARMv8 intrinsics (Rust 1.61+)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`,
//! support for using AES intrinsics provided by the ARMv8 Cryptography Extensions.
//!
//! On Linux and macOS, support for ARMv8 AES intrinsics is autodetected at
//! runtime. On other platforms the `aes` target feature must be enabled via
//! RUSTFLAGS.
//!
//! ## `x86`/`x86_64` intrinsics (AES-NI and VAES)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if AES-NI and VAES are available, and if they are
//! not, it will fallback to using a constant-time software implementation.
//!
//! Passing `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` explicitly at
//! compile-time will override runtime detection and ensure that AES-NI is
//! used or passing `RUSTFLAGS=-Ctarget-feature=+aes,+avx512f,+ssse3,+vaes`
//! will ensure that AESNI and VAES are always used.
//!
//! Note: Enabling VAES256 or VAES512 still requires specifying `--cfg
//! aes_backend = "avx256"` or `--cfg aes_backend = "avx512"` explicitly.
//!
//! Programs built in this manner will crash with an illegal instruction on
//! CPUs which do not have AES-NI and VAES enabled.
//!
//! Note: runtime detection is not possible on SGX targets. Please use the
//! aforementioned `RUSTFLAGS` to leverage AES-NI and VAES on these targets.
//!
//! # Examples
//! ```
//! use aes::Aes128;
//! use aes::cipher::{Array, BlockCipherEncrypt, BlockCipherDecrypt, KeyInit};
//!
//! let key = Array::from([0u8; 16]);
//! let mut block = Array::from([42u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Aes128::new(&key);
//!
//! let block_copy = block;
//!
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//!
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // Implementation supports parallel block processing. Number of blocks
//! // processed in parallel depends in general on hardware capabilities.
//! // This is achieved by instruction-level parallelism (ILP) on a single
//! // CPU core, which is different from multi-threaded parallelism.
//! let mut blocks = [block; 100];
//! cipher.encrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.decrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//!
//! // `decrypt_blocks` also supports parallel block processing.
//! cipher.decrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.encrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//! ```
//!
//! For implementation of block cipher modes of operation see
//! [`block-modes`] repository.
//!
//! # Configuration Flags
//!
//! You can modify crate using the following configuration flags:
//!
//! - `aes_backend`: explicitly select one of the following backends:
//!   - `soft`: force software backend
//!   - `avx256`: force AVX2 backend
//!   - `avx512`: force AVX-512 backend
//! - `aes_backend_soft`: modify software backend:
//!   - `compact`: use compact implementation (less performant, but results in a smaller binary)
//!
//! It can be enabled using `RUSTFLAGS` environment variable
//! (e.g. `RUSTFLAGS='--cfg aes_backend="soft"'`) or by modifying `.cargo/config`.
//!
//! [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//! [fixslicing]: https://eprint.iacr.org/2020/1123.pdf
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set
//! [`block-modes`]: https://github.com/RustCrypto/block-modes/

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "hazmat")]
pub mod hazmat;

#[macro_use]
mod macros;
mod soft;

// HOWY PATCH: panic-safe ownership for addressable, flat key-schedule scratch.
// See HOWY_PATCH.md for the exact claim boundary and upstream provenance.
#[cfg(feature = "zeroize")]
mod howy_zeroize {
    use core::ops::{Deref, DerefMut};

    pub(crate) trait Flat: Sized {
        fn zeroed() -> Self;
        fn wipe(&mut self);

        #[cfg(test)]
        fn is_zero(&self) -> bool;
    }

    macro_rules! impl_flat_array {
        ($element:ty) => {
            impl<const N: usize> Flat for [$element; N] {
                fn zeroed() -> Self {
                    [0; N]
                }

                fn wipe(&mut self) {
                    zeroize::Zeroize::zeroize(self);
                }

                #[cfg(test)]
                fn is_zero(&self) -> bool {
                    self.iter().all(|value| *value == 0)
                }
            }
        };
    }

    impl_flat_array!(u8);
    impl_flat_array!(u32);
    impl_flat_array!(u64);

    #[cfg(target_arch = "x86")]
    impl<const N: usize> Flat for [core::arch::x86::__m128i; N] {
        fn zeroed() -> Self {
            // SAFETY: an all-zero bit pattern is valid for `__m128i`.
            unsafe { core::mem::zeroed() }
        }

        fn wipe(&mut self) {
            // SAFETY: `[__m128i; N]` is flat data with no pointers or padding
            // whose validity depends on a nonzero bit pattern.
            unsafe { zeroize::zeroize_flat_type(self) }
        }

        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized flat
            // array exactly and is used only by wipe instrumentation tests.
            unsafe {
                core::slice::from_raw_parts(
                    self.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(self),
                )
                .iter()
                .all(|byte| *byte == 0)
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl<const N: usize> Flat for [core::arch::x86_64::__m128i; N] {
        fn zeroed() -> Self {
            // SAFETY: an all-zero bit pattern is valid for `__m128i`.
            unsafe { core::mem::zeroed() }
        }

        fn wipe(&mut self) {
            // SAFETY: `[__m128i; N]` is flat data with no pointers or padding
            // whose validity depends on a nonzero bit pattern.
            unsafe { zeroize::zeroize_flat_type(self) }
        }

        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized flat
            // array exactly and is used only by wipe instrumentation tests.
            unsafe {
                core::slice::from_raw_parts(
                    self.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(self),
                )
                .iter()
                .all(|byte| *byte == 0)
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl<const N: usize> Flat for [core::arch::aarch64::uint8x16_t; N] {
        fn zeroed() -> Self {
            // SAFETY: an all-zero bit pattern is valid for `uint8x16_t`.
            unsafe { core::mem::zeroed() }
        }

        fn wipe(&mut self) {
            zeroize::Zeroize::zeroize(self);
        }

        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized flat
            // array exactly and is used only by wipe instrumentation tests.
            unsafe {
                core::slice::from_raw_parts(
                    self.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(self),
                )
                .iter()
                .all(|byte| *byte == 0)
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl<const N: usize> Flat for [core::arch::x86_64::__m256i; N] {
        fn zeroed() -> Self {
            // SAFETY: an all-zero bit pattern is valid for `__m256i`.
            unsafe { core::mem::zeroed() }
        }

        fn wipe(&mut self) {
            zeroize::Zeroize::zeroize(self);
        }

        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized flat
            // array exactly and is used only by wipe instrumentation tests.
            unsafe {
                core::slice::from_raw_parts(
                    self.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(self),
                )
                .iter()
                .all(|byte| *byte == 0)
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    impl<const N: usize> Flat for [core::arch::x86_64::__m512i; N] {
        fn zeroed() -> Self {
            // SAFETY: an all-zero bit pattern is valid for `__m512i`.
            unsafe { core::mem::zeroed() }
        }

        fn wipe(&mut self) {
            zeroize::Zeroize::zeroize(self);
        }

        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized flat
            // array exactly and is used only by wipe instrumentation tests.
            unsafe {
                core::slice::from_raw_parts(
                    self.as_ptr().cast::<u8>(),
                    core::mem::size_of_val(self),
                )
                .iter()
                .all(|byte| *byte == 0)
            }
        }
    }

    pub(crate) struct Guard<T: Flat, const OWNER: bool = false>(T);

    impl<T: Flat> Guard<T> {
        pub(crate) fn new(value: T) -> Self {
            Self(value)
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl<T: Flat> Guard<T, true> {
        pub(crate) fn new_owner(value: T) -> Self {
            Self(value)
        }
    }

    impl<T: Flat, const OWNER: bool> Guard<T, OWNER> {
        pub(crate) fn take(&mut self) -> T {
            core::mem::replace(&mut self.0, T::zeroed())
        }
    }

    impl<T: Flat, const OWNER: bool> Deref for Guard<T, OWNER> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T: Flat, const OWNER: bool> DerefMut for Guard<T, OWNER> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<T: Flat, const OWNER: bool> Drop for Guard<T, OWNER> {
        fn drop(&mut self) {
            #[cfg(test)]
            let populated = !self.0.is_zero();
            self.0.wipe();
            #[cfg(test)]
            record_wipe(populated, self.0.is_zero(), OWNER);
        }
    }

    /// A lazily initialized flat value whose initialized contents wipe on drop.
    #[cfg(all(
        target_arch = "x86_64",
        any(aes_backend = "avx256", aes_backend = "avx512")
    ))]
    pub(crate) struct WipingOnceCell<T: Flat>(core::cell::OnceCell<T>);

    #[cfg(all(
        target_arch = "x86_64",
        any(aes_backend = "avx256", aes_backend = "avx512")
    ))]
    impl<T: Flat> WipingOnceCell<T> {
        pub(crate) const fn new() -> Self {
            Self(core::cell::OnceCell::new())
        }

        pub(crate) fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
            self.0.get_or_init(f)
        }
    }

    #[cfg(all(
        target_arch = "x86_64",
        any(aes_backend = "avx256", aes_backend = "avx512")
    ))]
    impl<T: Flat + Clone> Clone for WipingOnceCell<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    #[cfg(all(
        target_arch = "x86_64",
        any(aes_backend = "avx256", aes_backend = "avx512")
    ))]
    impl<T: Flat> Drop for WipingOnceCell<T> {
        fn drop(&mut self) {
            if let Some(value) = self.0.get_mut() {
                #[cfg(test)]
                let populated = !value.is_zero();
                value.wipe();
                #[cfg(test)]
                record_wipe(populated, value.is_zero(), false);
            }
        }
    }

    #[cfg(test)]
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(test)]
    std::thread_local! {
        static CHECKPOINTS_UNTIL_PANIC: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    #[cfg(test)]
    static WIPE_EVENTS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    static WIPE_FAILURES: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    static OWNER_POPULATED_WIPE_EVENTS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    static SCRATCH_POPULATED_WIPE_EVENTS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[inline]
    pub(crate) fn checkpoint() {
        #[cfg(test)]
        CHECKPOINTS_UNTIL_PANIC.with(|remaining| match remaining.get() {
            0 => {}
            1 => {
                remaining.set(0);
                panic!("HOWY AES key-expansion checkpoint");
            }
            count => remaining.set(count - 1),
        });
    }

    #[cfg(test)]
    fn record_wipe(populated: bool, wiped: bool, owner: bool) {
        WIPE_EVENTS.fetch_add(1, Ordering::SeqCst);
        if populated {
            if owner {
                OWNER_POPULATED_WIPE_EVENTS.fetch_add(1, Ordering::SeqCst);
            } else {
                SCRATCH_POPULATED_WIPE_EVENTS.fetch_add(1, Ordering::SeqCst);
            }
        }
        if !wiped {
            WIPE_FAILURES.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    pub(crate) fn arm_checkpoint() {
        arm_checkpoint_after(1);
    }

    #[cfg(test)]
    pub(crate) fn arm_checkpoint_after(checkpoints: usize) {
        assert!(checkpoints > 0);
        reset_wipe_counts();
        CHECKPOINTS_UNTIL_PANIC.with(|remaining| remaining.set(checkpoints));
    }

    #[cfg(test)]
    pub(crate) fn reset_wipe_counts() {
        WIPE_EVENTS.store(0, Ordering::SeqCst);
        WIPE_FAILURES.store(0, Ordering::SeqCst);
        OWNER_POPULATED_WIPE_EVENTS.store(0, Ordering::SeqCst);
        SCRATCH_POPULATED_WIPE_EVENTS.store(0, Ordering::SeqCst);
        CHECKPOINTS_UNTIL_PANIC.with(|remaining| remaining.set(0));
    }

    #[cfg(test)]
    pub(crate) fn wipe_counts() -> (usize, usize) {
        (
            WIPE_EVENTS.load(Ordering::SeqCst),
            WIPE_FAILURES.load(Ordering::SeqCst),
        )
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    pub(crate) fn ownership_wipe_counts() -> (usize, usize, usize) {
        (
            OWNER_POPULATED_WIPE_EVENTS.load(Ordering::SeqCst),
            SCRATCH_POPULATED_WIPE_EVENTS.load(Ordering::SeqCst),
            WIPE_FAILURES.load(Ordering::SeqCst),
        )
    }
}

cpubits::cfg_if! {
    if #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))] {
        mod armv8;
        mod autodetect;
        pub use autodetect::*;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(aes_backend = "soft")
    ))] {
        mod x86;
        mod autodetect;
        pub use autodetect::*;
    } else {
        pub use soft::*;
    }
}

pub use cipher;
use cipher::{array::Array, consts::U16};

/// 128-bit AES block
pub type Block = Array<u8, U16>;

#[cfg(all(test, feature = "zeroize"))]
mod howy_tests {
    use super::*;
    use cipher::{Key, KeyInit};

    #[test]
    fn software_aes256_expansion_wipes_addressable_scratch_on_unwind() {
        let _test_lock = howy_zeroize::TEST_LOCK.lock().unwrap();
        howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| {
            let key = Key::<soft::Aes256>::from([0x5a; 32]);
            let _ = soft::Aes256::new(&key);
        });
        assert!(result.is_err());
        let (events, failures) = howy_zeroize::wipe_counts();
        assert!(events >= 1);
        assert_eq!(failures, 0);
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(aes_backend = "soft")
    ))]
    #[test]
    fn aesni_aes256_expansion_wipes_addressable_scratch_on_unwind() {
        let _test_lock = howy_zeroize::TEST_LOCK.lock().unwrap();
        howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| {
            let key = Key::<x86::Aes256>::from([0xa5; 32]);
            let _ = x86::Aes256::new(&key);
        });
        assert!(result.is_err());
        let (events, failures) = howy_zeroize::wipe_counts();
        assert!(events >= 1);
        assert_eq!(failures, 0);
    }

    #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
    #[test]
    fn aarch64_autodetect_aes256_composite_wipes_both_owners_on_inverse_unwind() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return;
        }

        let _test_lock = howy_zeroize::TEST_LOCK.lock().unwrap();
        howy_zeroize::arm_checkpoint_after(2);
        let result = std::panic::catch_unwind(|| {
            let key = Key::<Aes256>::from([0x3c; 32]);
            let _ = Aes256::new(&key);
        });
        assert!(result.is_err());
        let (owners, scratch, failures) = howy_zeroize::ownership_wipe_counts();
        assert!(
            owners >= 2,
            "original and cloned encryption owners must wipe"
        );
        assert!(scratch >= 1, "populated inverse scratch must wipe");
        assert_eq!(failures, 0);
    }

    #[cfg(all(target_arch = "aarch64", not(aes_backend = "soft")))]
    #[test]
    fn aarch64_autodetect_decrypt_and_conversion_delegate_to_guarded_owners() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return;
        }

        let _test_lock = howy_zeroize::TEST_LOCK.lock().unwrap();

        howy_zeroize::arm_checkpoint_after(2);
        let result = std::panic::catch_unwind(|| {
            let key = Key::<Aes256Dec>::from([0x4d; 32]);
            let _ = Aes256Dec::new(&key);
        });
        assert!(result.is_err());
        let (owners, scratch, failures) = howy_zeroize::ownership_wipe_counts();
        assert!(owners >= 1, "autodetect decrypt source owner must wipe");
        assert!(scratch >= 1, "autodetect decrypt inverse scratch must wipe");
        assert_eq!(failures, 0);

        let key = Key::<Aes256Enc>::from([0x4e; 32]);
        let encrypt = Aes256Enc::new(&key);
        howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Aes256::from(&encrypt);
        }));
        assert!(result.is_err());
        let (owners, scratch, failures) = howy_zeroize::ownership_wipe_counts();
        assert!(owners >= 2, "autodetect conversion owners must wipe");
        assert!(
            scratch >= 1,
            "autodetect conversion inverse scratch must wipe"
        );
        assert_eq!(failures, 0);
    }
}
