//! Portable software implementation written in terms of [`FieldElement`].
//!
//! This implementation is deliberately compact and simple, avoiding a large powers-of-H key state
//! in favor of reducing the memory footprint.

use crate::{Block, Key, ParBlocks, Tag, field_element::FieldElement};

/// State of a POLYVAL hash operation.
#[derive(Clone)]
#[allow(missing_copy_implementations)]
pub(crate) struct State {
    /// Hash key: fixed element of GF(2^128) that parameterizes the POLYVAL universal hash function.
    ///
    /// This is the multiplier that advances POLYVAL's state. Each message block is XORed into the
    /// accumulator and then multiplied by `H`.
    h: FieldElement,

    /// Accumulator for POLYVAL computation.
    y: FieldElement,
}

impl State {
    pub(crate) fn new(h: &Key) -> Self {
        #[cfg(feature = "zeroize")]
        let mut h = crate::howy_zeroize::Guard::new(FieldElement::from(*h));
        #[cfg(feature = "zeroize")]
        crate::howy_zeroize::checkpoint();

        Self {
            #[cfg(feature = "zeroize")]
            h: h.take(),
            #[cfg(not(feature = "zeroize"))]
            h: FieldElement::from(*h),
            y: FieldElement::default(),
        }
    }

    pub(crate) fn proc_block(&mut self, block: &Block) {
        self.y = (self.y + block.into()) * self.h;
    }

    pub(crate) fn proc_par_blocks(&mut self, par_blocks: &ParBlocks) {
        // Just process them in sequence since we don't support anything fancy
        for block in par_blocks {
            self.proc_block(block);
        }
    }

    pub(crate) fn finalize(&self) -> Tag {
        self.y.into()
    }

    pub(crate) fn reset(&mut self) {
        self.y = FieldElement::default();
    }

    #[cfg(feature = "zeroize")]
    pub(crate) fn zeroize_sensitive(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.h);
        zeroize::Zeroize::zeroize(&mut self.y);
    }

    #[cfg(all(test, feature = "zeroize"))]
    pub(crate) fn sensitive_is_zero(&self) -> bool {
        crate::howy_zeroize::Wipe::is_zero(&self.h) && crate::howy_zeroize::Wipe::is_zero(&self.y)
    }
}
