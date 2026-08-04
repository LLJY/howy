#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "hazmat")]
pub mod hazmat;

mod backend;
mod field_element;

// HOWY PATCH: panic-safe ownership for addressable transformed-key scratch.
// See HOWY_PATCH.md for provenance and the compiler/register claim boundary.
#[cfg(feature = "zeroize")]
mod howy_zeroize {
    use core::ops::{Deref, DerefMut};
    use zeroize::Zeroize;

    pub(crate) trait Wipe: Zeroize {
        #[cfg(test)]
        fn is_zero(&self) -> bool;
    }

    impl<const N: usize> Wipe for [u8; N] {
        #[cfg(test)]
        fn is_zero(&self) -> bool {
            self.iter().all(|byte| *byte == 0)
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl<const N: usize> Wipe for [core::arch::aarch64::uint64x2_t; N] {
        #[cfg(test)]
        fn is_zero(&self) -> bool {
            // SAFETY: read-only byte inspection spans this initialized SIMD
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

    pub(crate) struct Guard<T: Wipe>(T);

    impl<T: Wipe> Guard<T> {
        pub(crate) fn new(value: T) -> Self {
            Self(value)
        }

        pub(crate) fn take(&mut self) -> T
        where
            T: Default,
        {
            core::mem::take(&mut self.0)
        }
    }

    impl<T: Wipe> Deref for Guard<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T: Wipe> DerefMut for Guard<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<T: Wipe> Drop for Guard<T> {
        fn drop(&mut self) {
            self.0.zeroize();
            #[cfg(test)]
            record_wipe(self.0.is_zero());
        }
    }

    #[cfg(test)]
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(test)]
    std::thread_local! {
        static PANIC_AT_CHECKPOINT: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    }
    #[cfg(test)]
    static WIPE_EVENTS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(test)]
    static WIPE_FAILURES: AtomicUsize = AtomicUsize::new(0);

    #[inline]
    pub(crate) fn checkpoint() {
        #[cfg(test)]
        if PANIC_AT_CHECKPOINT.with(|armed| armed.replace(false)) {
            panic!("HOWY POLYVAL key-setup checkpoint");
        }
    }

    #[cfg(test)]
    fn record_wipe(wiped: bool) {
        WIPE_EVENTS.fetch_add(1, Ordering::SeqCst);
        if !wiped {
            WIPE_FAILURES.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    pub(crate) fn arm_checkpoint() {
        WIPE_EVENTS.store(0, Ordering::SeqCst);
        WIPE_FAILURES.store(0, Ordering::SeqCst);
        PANIC_AT_CHECKPOINT.with(|armed| armed.set(true));
    }

    #[cfg(test)]
    pub(crate) fn wipe_counts() -> (usize, usize) {
        (
            WIPE_EVENTS.load(Ordering::SeqCst),
            WIPE_FAILURES.load(Ordering::SeqCst),
        )
    }
}

pub use universal_hash;

use crate::backend::State;
use core::fmt::{self, Debug};
use universal_hash::{
    KeyInit, Reset, UhfBackend, UhfClosure, UniversalHash,
    common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    consts::{U4, U16},
};

/// Size of a POLYVAL block in bytes
pub const BLOCK_SIZE: usize = 16;

/// Size of a POLYVAL key in bytes
pub const KEY_SIZE: usize = 16;

/// POLYVAL keys (16-bytes)
pub type Key = universal_hash::Key<Polyval>;

/// POLYVAL blocks (16-bytes)
pub type Block = universal_hash::Block<Polyval>;

/// POLYVAL parallel blocks (4 x 16-bytes)
pub type ParBlocks = universal_hash::ParBlocks<Polyval>;

/// POLYVAL tags (16-bytes)
pub type Tag = universal_hash::Block<Polyval>;

/// **POLYVAL**: GHASH-like universal hash over GF(2^128), but optimized for little-endian
/// architectures.
#[derive(Clone)]
pub struct Polyval {
    /// State of the internal hash being computed.
    state: State,
}

impl Polyval {
    /// Initialize POLYVAL with the given `H` field element (i.e. hash key).
    #[must_use]
    pub fn new(h: &Key) -> Self {
        Self {
            state: State::new(h),
        }
    }
}

impl KeyInit for Polyval {
    fn new(h: &Key) -> Self {
        Self::new(h)
    }
}

impl KeySizeUser for Polyval {
    type KeySize = U16;
}

impl BlockSizeUser for Polyval {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Polyval {
    type ParBlocksSize = U4;
}

impl UniversalHash for Polyval {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }

    fn finalize(self) -> Tag {
        self.state.finalize()
    }
}

impl UhfBackend for Polyval {
    fn proc_block(&mut self, block: &Block) {
        self.state.proc_block(block);
    }

    fn proc_par_blocks(&mut self, blocks: &ParBlocks) {
        self.state.proc_par_blocks(blocks);
    }
}

impl Reset for Polyval {
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl Debug for Polyval {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Polyval").finish_non_exhaustive()
    }
}

impl Drop for Polyval {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.state.zeroize_sensitive();
    }
}

#[cfg(test)]
mod tests {
    use crate::{BLOCK_SIZE, Polyval, universal_hash::UniversalHash};
    use hex_literal::hex;

    //
    // Test vectors for POLYVAL from RFC 8452 Appendix A
    // <https://tools.ietf.org/html/rfc8452#appendix-A>
    //

    const H: [u8; BLOCK_SIZE] = hex!("25629347589242761d31f826ba4b757b");
    const X_1: [u8; BLOCK_SIZE] = hex!("4f4f95668c83dfb6401762bb2d01a262");
    const X_2: [u8; BLOCK_SIZE] = hex!("d1a24ddd2721d006bbe45f20d3c9f362");

    /// POLYVAL(H, X_1, X_2)
    const POLYVAL_RESULT: [u8; BLOCK_SIZE] = hex!("f7a3b47b846119fae5b7866cf5e5b77e");

    #[test]
    fn polyval_test_vector() {
        let mut poly = Polyval::new(&H.into());
        poly.update(&[X_1.into(), X_2.into()]);

        let result = poly.finalize();
        assert_eq!(&POLYVAL_RESULT[..], result.as_slice());
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn key_setup_wipes_addressable_scratch_on_unwind() {
        crate::howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| {
            let _ = Polyval::new(&H.into());
        });
        assert!(result.is_err());
        let (events, failures) = crate::howy_zeroize::wipe_counts();
        assert!(events >= 1);
        assert_eq!(failures, 0);
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn retained_key_and_accumulator_are_explicitly_zeroized() {
        let mut poly = Polyval::new(&H.into());
        poly.update(&[X_1.into()]);
        poly.state.zeroize_sensitive();
        assert!(poly.state.sensitive_is_zero());
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(polyval_backend = "soft")
    ))]
    #[test]
    fn available_x86_intrinsics_backend_is_actually_selected() {
        if std::arch::is_x86_feature_detected!("avx")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
        {
            let poly = Polyval::new(&H.into());
            assert!(poly.state.has_intrinsics());
        }
    }
}
