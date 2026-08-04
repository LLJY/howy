#![allow(unsafe_op_in_unsafe_fn)]

use crate::x86::{Block64, Simd128RoundKeys, Simd512RoundKeys, arch::*};
use cipher::inout::InOut;
use core::mem::MaybeUninit;

#[target_feature(enable = "avx512f")]
#[inline]
pub(crate) unsafe fn broadcast_keys<const KEYS: usize>(
    keys: &Simd128RoundKeys<KEYS>,
) -> Simd512RoundKeys<KEYS> {
    #[cfg(feature = "zeroize")]
    {
        // SAFETY: an all-zero bit pattern is valid for `__m512i`.
        let mut broadcast: crate::howy_zeroize::Guard<Simd512RoundKeys<KEYS>> =
            crate::howy_zeroize::Guard::new(unsafe { core::mem::zeroed() });
        for (out, key) in broadcast.iter_mut().zip(keys) {
            *out = _mm512_broadcast_i32x4(*key);
        }
        crate::howy_zeroize::checkpoint();
        broadcast.take()
    }
    #[cfg(not(feature = "zeroize"))]
    keys.map(|key| _mm512_broadcast_i32x4(key))
}

#[target_feature(enable = "avx512f,vaes")]
#[inline]
pub(crate) unsafe fn encrypt64<const KEYS: usize>(
    keys: &Simd512RoundKeys<KEYS>,
    blocks: InOut<'_, '_, Block64>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m512i>();
    let optr = optr.cast::<__m512i>();

    let mut data: [MaybeUninit<__m512i>; 16] = MaybeUninit::uninit().assume_init();

    (0..16).for_each(|i| {
        data[i].write(iptr.add(i).read_unaligned());
    });
    let mut data: [__m512i; 16] = unsafe { ::core::mem::transmute(data) };

    for vec in &mut data {
        *vec = _mm512_xor_si512(*vec, keys[0]);
    }
    for key in &keys[1..KEYS - 1] {
        for vec in &mut data {
            *vec = _mm512_aesenc_epi128(*vec, *key);
        }
    }
    for vec in &mut data {
        *vec = _mm512_aesenclast_epi128(*vec, keys[KEYS - 1]);
    }

    (0..16).for_each(|i| {
        optr.add(i).write_unaligned(data[i]);
    });
}

#[target_feature(enable = "avx512f,vaes")]
#[inline]
pub(crate) unsafe fn decrypt64<const KEYS: usize>(
    keys: &Simd512RoundKeys<KEYS>,
    blocks: InOut<'_, '_, Block64>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m512i>();
    let optr = optr.cast::<__m512i>();

    let mut data: [MaybeUninit<__m512i>; 16] = MaybeUninit::uninit().assume_init();

    (0..16).for_each(|i| {
        data[i].write(iptr.add(i).read_unaligned());
    });
    let mut data: [__m512i; 16] = unsafe { ::core::mem::transmute(data) };

    for vec in &mut data {
        *vec = _mm512_xor_si512(*vec, keys[0]);
    }
    for key in &keys[1..KEYS - 1] {
        for vec in &mut data {
            *vec = _mm512_aesdec_epi128(*vec, *key);
        }
    }
    for vec in &mut data {
        *vec = _mm512_aesdeclast_epi128(*vec, keys[KEYS - 1]);
    }

    (0..16).for_each(|i| {
        optr.add(i).write_unaligned(data[i]);
    });
}
