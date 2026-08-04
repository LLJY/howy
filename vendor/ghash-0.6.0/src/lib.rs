#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

pub use polyval::universal_hash;

use polyval::{Polyval, hazmat::FieldElement};
use universal_hash::{
    KeyInit, UhfBackend, UhfClosure, UniversalHash,
    common::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser},
    consts::U16,
};

#[cfg(feature = "zeroize")]
mod howy_zeroize {
    use super::{FieldElement, Key};
    use core::ops::Deref;
    use zeroize::Zeroize;

    pub(super) trait Wipe: Zeroize {
        #[cfg(test)]
        fn is_zero(&self) -> bool;
    }

    impl Wipe for Key {
        #[cfg(test)]
        fn is_zero(&self) -> bool {
            self.iter().all(|byte| *byte == 0)
        }
    }

    impl Wipe for FieldElement {
        #[cfg(test)]
        fn is_zero(&self) -> bool {
            let bytes: [u8; 16] = (*self).into();
            bytes.iter().all(|byte| *byte == 0)
        }
    }

    pub(super) struct Guard<T: Wipe>(T);

    impl<T: Wipe> Guard<T> {
        pub(super) fn new(value: T) -> Self {
            Self(value)
        }
    }

    impl<T: Wipe> Deref for Guard<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.0
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
    pub(super) fn checkpoint() {
        #[cfg(test)]
        if PANIC_AT_CHECKPOINT.with(|armed| armed.replace(false)) {
            panic!("HOWY GHASH key-transform checkpoint");
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
    pub(super) fn arm_checkpoint() {
        WIPE_EVENTS.store(0, Ordering::SeqCst);
        WIPE_FAILURES.store(0, Ordering::SeqCst);
        PANIC_AT_CHECKPOINT.with(|armed| armed.set(true));
    }

    #[cfg(test)]
    pub(super) fn wipe_counts() -> (usize, usize) {
        (
            WIPE_EVENTS.load(Ordering::SeqCst),
            WIPE_FAILURES.load(Ordering::SeqCst),
        )
    }
}

/// GHASH keys (16-bytes)
pub type Key = universal_hash::Key<GHash>;

/// GHASH blocks (16-bytes)
pub type Block = universal_hash::Block<GHash>;

/// GHASH tags (16-bytes)
pub type Tag = universal_hash::Block<GHash>;

/// **GHASH**: universal hash over GF(2^128) used by AES-GCM.
///
/// GHASH is a universal hash function used for message authentication in the AES-GCM authenticated
/// encryption cipher.
#[derive(Clone)]
pub struct GHash(Polyval);

impl KeySizeUser for GHash {
    type KeySize = U16;
}

impl GHash {
    /// Initialize GHASH with the given `H` field element as the key.
    #[inline]
    pub fn new(h: &Key) -> Self {
        #[cfg(feature = "zeroize")]
        {
            // HOWY PATCH: every named, addressable field/key intermediate is
            // guarded before the next transformation can unwind.
            let h_field = howy_zeroize::Guard::new(FieldElement::from(*h));
            let h_reversed = howy_zeroize::Guard::new((*h_field).reverse());
            let h_mulx = howy_zeroize::Guard::new((*h_reversed).mulx());
            let h_polyval = howy_zeroize::Guard::new(Key::from(*h_mulx));
            howy_zeroize::checkpoint();
            return Self(Polyval::new(&h_polyval));
        }
        #[cfg(not(feature = "zeroize"))]
        let h_polyval = Key::from(FieldElement::from(*h).reverse().mulx());
        #[cfg(not(feature = "zeroize"))]
        Self(Polyval::new(&h_polyval))
    }
}

impl KeyInit for GHash {
    /// Initialize GHASH with the given `H` field element
    #[inline]
    fn new(h: &Key) -> Self {
        Self::new(h)
    }
}

struct GHashBackend<'b, B: UhfBackend>(&'b mut B);

impl<B: UhfBackend> BlockSizeUser for GHashBackend<'_, B> {
    type BlockSize = B::BlockSize;
}

impl<B: UhfBackend> ParBlocksSizeUser for GHashBackend<'_, B> {
    type ParBlocksSize = B::ParBlocksSize;
}

impl<B: UhfBackend> UhfBackend for GHashBackend<'_, B> {
    fn proc_block(&mut self, x: &universal_hash::Block<B>) {
        let mut x = x.clone();
        x.reverse();
        self.0.proc_block(&x);
    }

    fn proc_par_blocks(&mut self, par_blocks: &universal_hash::ParBlocks<B>) {
        let mut par_blocks = par_blocks.clone();
        for block in &mut par_blocks {
            block.reverse();
        }
        self.0.proc_par_blocks(&par_blocks);
    }
}

impl BlockSizeUser for GHash {
    type BlockSize = U16;
}

impl UniversalHash for GHash {
    fn update_with_backend(&mut self, f: impl UhfClosure<BlockSize = Self::BlockSize>) {
        struct GHashClosure<C: UhfClosure>(C);

        impl<C: UhfClosure> BlockSizeUser for GHashClosure<C> {
            type BlockSize = C::BlockSize;
        }

        impl<C: UhfClosure> UhfClosure for GHashClosure<C> {
            fn call<B: UhfBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
                self.0.call(&mut GHashBackend(backend));
            }
        }

        self.0.update_with_backend(GHashClosure(f));
    }

    /// Get GHASH output
    #[inline]
    fn finalize(self) -> Tag {
        let mut output = self.0.finalize();
        output.reverse();
        output
    }
}

impl core::fmt::Debug for GHash {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_tuple("GHash").finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod howy_tests {
    use super::*;

    #[test]
    fn transformed_key_guards_wipe_on_unwind() {
        howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| {
            let _ = GHash::new(&Key::from([0x3c; 16]));
        });
        assert!(result.is_err());
        let (events, failures) = howy_zeroize::wipe_counts();
        assert_eq!(events, 4);
        assert_eq!(failures, 0);
    }
}
