//! 1024-byte bit-planar blocks for the AVX512 XOR-JIT tier: 16 planes of
//! 64 bytes (512 words per block), plane `p` holding word-bit `15-p` — the
//! same plane↔bit contract as the 512-byte layout ([`super::transpose`]).
//!
//! Deliberate deviation from upstream: ParPar's `gf16_xor_avx512.c` has a
//! native vpmovb2m-based prepare, but the JIT multiply only requires that
//! prepare/finish agree and that the plane↔bit mapping holds — the intra-plane
//! word order is free (XOR is bitwise-parallel). So the wide block is composed
//! from two proven 512-byte AVX2 transposes with their half-planes
//! interleaved: plane `p` = [block-A plane `p` | block-B plane `p`]. This
//! keeps every piece testable on any AVX2 x86 host (vs a native vpmovb2m
//! port, which would need real AVX512 silicon), and prepare/finish cost is
//! amortized noise next to the multiply. Note that Rosetta 2 executes AVX2
//! but does not advertise it via CPUID, so the detection-gated tests here
//! skip under translation — real coverage needs native x86 hardware.
#![allow(unsafe_op_in_unsafe_fn)]

use super::transpose;

/// Bytes per wide bit-planar block (512 words × 2 bytes).
pub const BLOCK_BYTES: usize = 1024;
/// Words per block.
pub const BLOCK_WORDS: usize = 512;
/// Bytes per plane (512 bits).
pub const PLANE_BYTES: usize = 64;

const HALF: usize = transpose::BLOCK_BYTES;
const HALF_PLANE: usize = transpose::PLANE_BYTES;

/// Transpose one 1024-byte block of LE u16 words into the 16×64-byte plane
/// layout.
///
/// # Safety
/// Requires AVX2. `src`/`dst` are exactly [`BLOCK_BYTES`].
#[target_feature(enable = "avx2")]
pub unsafe fn prepare_block(src: &[u8; BLOCK_BYTES], dst: &mut [u8; BLOCK_BYTES]) {
    let mut half = [0u8; HALF];
    let a: &[u8; HALF] = src[..HALF].first_chunk().unwrap();
    transpose::prepare_block(a, &mut half);
    for p in 0..16 {
        dst[p * PLANE_BYTES..p * PLANE_BYTES + HALF_PLANE]
            .copy_from_slice(&half[p * HALF_PLANE..(p + 1) * HALF_PLANE]);
    }
    let b: &[u8; HALF] = src[HALF..].first_chunk().unwrap();
    transpose::prepare_block(b, &mut half);
    for p in 0..16 {
        dst[p * PLANE_BYTES + HALF_PLANE..(p + 1) * PLANE_BYTES]
            .copy_from_slice(&half[p * HALF_PLANE..(p + 1) * HALF_PLANE]);
    }
}

/// Inverse of [`prepare_block`], in place.
///
/// # Safety
/// Requires AVX2. `buf` is exactly [`BLOCK_BYTES`].
#[target_feature(enable = "avx2")]
pub unsafe fn finish_block(buf: &mut [u8; BLOCK_BYTES]) {
    let mut a = [0u8; HALF];
    let mut b = [0u8; HALF];
    for p in 0..16 {
        a[p * HALF_PLANE..(p + 1) * HALF_PLANE]
            .copy_from_slice(&buf[p * PLANE_BYTES..p * PLANE_BYTES + HALF_PLANE]);
        b[p * HALF_PLANE..(p + 1) * HALF_PLANE]
            .copy_from_slice(&buf[p * PLANE_BYTES + HALF_PLANE..(p + 1) * PLANE_BYTES]);
    }
    transpose::finish_block(&mut a);
    transpose::finish_block(&mut b);
    buf[..HALF].copy_from_slice(&a);
    buf[HALF..].copy_from_slice(&b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(seed: u64) -> [u8; BLOCK_BYTES] {
        let mut b = [0u8; BLOCK_BYTES];
        let mut s = seed.wrapping_add(0x9E37_79B9_7F4A_7C15) | 1;
        for byte in b.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *byte = (s >> 24) as u8;
        }
        b
    }

    #[test]
    fn prepare_finish_roundtrip_wide() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        for seed in 0..8u64 {
            let original = sample_block(seed);
            let mut planes = [0u8; BLOCK_BYTES];
            unsafe { prepare_block(&original, &mut planes) };
            let mut back = planes;
            unsafe { finish_block(&mut back) };
            assert_eq!(back, original, "roundtrip mismatch at seed {seed}");
        }
    }

    #[test]
    fn wide_plane_holds_word_bit_15_minus_p() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        for b in 0..16u32 {
            let mut src = [0u8; BLOCK_BYTES];
            for w in 0..BLOCK_WORDS {
                let v = (1u16 << b).to_le_bytes();
                src[w * 2] = v[0];
                src[w * 2 + 1] = v[1];
            }
            let mut planes = [0u8; BLOCK_BYTES];
            unsafe { prepare_block(&src, &mut planes) };
            let target = 15 - b as usize;
            for p in 0..16usize {
                let plane = &planes[p * PLANE_BYTES..(p + 1) * PLANE_BYTES];
                if p == target {
                    assert!(plane.iter().all(|&x| x == 0xff), "bit {b}: plane {p}");
                } else {
                    assert!(plane.iter().all(|&x| x == 0x00), "bit {b}: plane {p}");
                }
            }
        }
    }

    /// The wide planar muladd oracle agrees with the word-wise GF multiply
    /// through the wide transpose — the layout+deps contract at 64-byte
    /// planes (mirrors deps.rs::planar_muladd_matches_scalar_gf).
    #[test]
    fn wide_planar_muladd_matches_scalar_gf() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        use super::super::deps::{compute_deps, muladd_planar_sized};
        use crate::gf;
        for factor in [1u16, 2, 0x8000, 0xABCD, 0xFFFF, 0x2F1D] {
            let src = sample_block(factor as u64);
            let mut expected = [0u8; BLOCK_BYTES];
            for w in 0..BLOCK_WORDS {
                let sw = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
                let pb = gf::mul(factor, sw).to_le_bytes();
                expected[w * 2] = pb[0];
                expected[w * 2 + 1] = pb[1];
            }

            let mut src_planes = [0u8; BLOCK_BYTES];
            unsafe { prepare_block(&src, &mut src_planes) };
            let mut dst_planes = [0u8; BLOCK_BYTES];
            let deps = compute_deps(factor);
            muladd_planar_sized(
                &deps,
                &src_planes,
                &mut dst_planes,
                BLOCK_BYTES,
                PLANE_BYTES,
            );
            unsafe { finish_block(&mut dst_planes) };

            assert_eq!(dst_planes, expected, "factor {factor:#06x}");
        }
    }
}
