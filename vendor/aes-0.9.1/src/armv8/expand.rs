//! AES key expansion support.
#![allow(unsafe_op_in_unsafe_fn)]

use core::{arch::aarch64::*, mem, slice};

pub(super) type Aes128RoundKeys = [uint8x16_t; 11];
pub(super) type Aes192RoundKeys = [uint8x16_t; 13];
pub(super) type Aes256RoundKeys = [uint8x16_t; 15];

/// There are 4 AES words in a block.
const BLOCK_WORDS: usize = 4;

/// The AES (nee Rijndael) notion of a word is always 32-bits, or 4-bytes.
const WORD_SIZE: usize = 4;

/// AES round constants.
const ROUND_CONSTS: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES key expansion.
#[target_feature(enable = "aes")]
pub unsafe fn expand_key<const L: usize, const N: usize>(key: &[u8; L]) -> [uint8x16_t; N] {
    assert!((L == 16 && N == 11) || (L == 24 && N == 13) || (L == 32 && N == 15));

    #[cfg(feature = "zeroize")]
    let mut expanded_keys: crate::howy_zeroize::Guard<[uint8x16_t; N]> =
        crate::howy_zeroize::Guard::new(mem::zeroed());
    #[cfg(not(feature = "zeroize"))]
    let mut expanded_keys: [uint8x16_t; N] = mem::zeroed();

    // Sanity check, as this is required in order for the subsequent conversion to be sound.
    const _: () = assert!(mem::align_of::<uint8x16_t>() >= mem::align_of::<u32>());
    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = slice::from_raw_parts_mut(keys_ptr, N * BLOCK_WORDS);

    for (i, chunk) in key.chunks_exact(WORD_SIZE).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    // From "The Rijndael Block Cipher" Section 4.1:
    // > The number of columns of the Cipher Key is denoted by `Nk` and is
    // > equal to the key length divided by 32 [bits].
    let nk = L / WORD_SIZE;

    for i in nk..(N * BLOCK_WORDS) {
        let mut word = columns[i - 1];

        if i % nk == 0 {
            word = sub_word(word).rotate_right(8) ^ ROUND_CONSTS[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            word = sub_word(word);
        }

        columns[i] = columns[i - nk] ^ word;
    }

    #[cfg(feature = "zeroize")]
    {
        crate::howy_zeroize::checkpoint();
        expanded_keys.take()
    }
    #[cfg(not(feature = "zeroize"))]
    expanded_keys
}

/// Compute inverse expanded keys (for decryption).
///
/// This is the reverse of the encryption keys, with the Inverse Mix Columns
/// operation applied to all but the first and last expanded key.
#[target_feature(enable = "aes")]
pub(super) unsafe fn inv_expanded_keys<const N: usize>(keys: &[uint8x16_t; N]) -> [uint8x16_t; N] {
    assert!(N == 11 || N == 13 || N == 15);

    #[cfg(feature = "zeroize")]
    let mut inv_keys: crate::howy_zeroize::Guard<[uint8x16_t; N]> =
        crate::howy_zeroize::Guard::new(core::mem::zeroed());
    #[cfg(not(feature = "zeroize"))]
    let mut inv_keys: [uint8x16_t; N] = core::mem::zeroed();
    inv_keys[0] = keys[N - 1];
    for i in 1..N - 1 {
        inv_keys[i] = vaesimcq_u8(keys[N - 1 - i]);
    }
    inv_keys[N - 1] = keys[0];

    #[cfg(feature = "zeroize")]
    {
        crate::howy_zeroize::checkpoint();
        inv_keys.take()
    }
    #[cfg(not(feature = "zeroize"))]
    inv_keys
}

// Compile-time coverage: the largest ARMv8 round-key array must remain
// accepted by the panic-safe flat guard whenever this source path is selected.
#[cfg(feature = "zeroize")]
const _: () = {
    fn assert_flat<T: crate::howy_zeroize::Flat>() {}
    let _ = assert_flat::<Aes256RoundKeys>;
};

/// Sub bytes for a single AES word: used for key expansion.
#[inline]
#[target_feature(enable = "aes")]
unsafe fn sub_word(input: u32) -> u32 {
    let input = vreinterpretq_u8_u32(vdupq_n_u32(input));

    // AES single round encryption (with a "round" key of all zeros)
    let sub_input = vaeseq_u8(input, vdupq_n_u8(0));

    vgetq_lane_u32(vreinterpretq_u32_u8(sub_input), 0)
}

#[cfg(all(test, feature = "zeroize"))]
mod howy_tests {
    use super::*;

    #[test]
    fn aarch64_aes256_expansion_wipes_addressable_schedule_on_unwind() {
        let _test_lock = crate::howy_zeroize::TEST_LOCK.lock().unwrap();
        crate::howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| unsafe {
            let _ = expand_key::<32, 15>(&[0x5a; 32]);
        });
        assert!(result.is_err());
        let (events, failures) = crate::howy_zeroize::wipe_counts();
        assert!(events >= 1);
        assert_eq!(failures, 0);
    }

    #[test]
    fn aarch64_aes256_inverse_schedule_wipes_on_unwind() {
        let _test_lock = crate::howy_zeroize::TEST_LOCK.lock().unwrap();
        let keys = unsafe { expand_key::<32, 15>(&[0xa5; 32]) };
        crate::howy_zeroize::arm_checkpoint();
        let result = std::panic::catch_unwind(|| unsafe {
            let _ = inv_expanded_keys(&keys);
        });
        assert!(result.is_err());
        let (events, failures) = crate::howy_zeroize::wipe_counts();
        assert!(events >= 1);
        assert_eq!(failures, 0);
    }
}
