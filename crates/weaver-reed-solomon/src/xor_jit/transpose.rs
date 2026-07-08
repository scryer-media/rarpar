//! Bit-plane transpose for the XOR-JIT tier (see `scryer-docs/plans/125`).
//!
//! A block is [`BLOCK_BYTES`] = 512 bytes = 256 GF(2^16) words, stored
//! bit-planar as 16 planes of 256 bits (32 bytes each). Plane `p` lives at
//! byte offset `32*p` and holds word-bit `15-p` of every word (plane 0 = MSB,
//! plane 15 = LSB), matching ParPar's layout so the deps mapping lines up.
//!
//! [`prepare_block`] and [`finish_block`] are **faithful 1:1 AVX2 ports** of
//! ParPar's `gf16_xor_prepare_block` / `gf16_xor_finish_block_avx2`
//! (`gf16_xor_common_funcs.h`, `gf16_xor_avx2.c`) — the multiply consumes this
//! exact layout, so the transpose is not a place to substitute a simpler
//! structure. Correctness is pinned by a prepare→finish round-trip and the
//! end-to-end deps multiply test (both on real AVX2).
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::x86_64::*;

/// Bytes per bit-planar block (256 words × 2 bytes).
pub const BLOCK_BYTES: usize = 512;
/// Words per block.
pub const BLOCK_WORDS: usize = 256;
/// Bytes per plane (256 bits).
pub const PLANE_BYTES: usize = 32;

/// `_MM_SHUFFLE(z,y,x,w)`.
const fn mm_shuffle(z: i32, y: i32, x: i32, w: i32) -> i32 {
    (z << 6) | (y << 4) | (x << 2) | w
}

/// Transpose one 512-byte block of little-endian u16 words (`src`) into the
/// 16-plane layout (`dst`). Faithful port of `gf16_xor_prepare_block`.
///
/// # Safety
/// Requires AVX2. `src`/`dst` are exactly [`BLOCK_BYTES`].
#[target_feature(enable = "avx2")]
pub unsafe fn prepare_block(src: &[u8; BLOCK_BYTES], dst: &mut [u8; BLOCK_BYTES]) {
    // Per-128-lane byte de-interleave controls (gf16_xor_prep_split, AVX2 arm).
    let shuf_a = _mm256_set_epi32(
        0x0f0d0b09, 0x07050301, 0x0e0c0a08, 0x06040200, 0x0f0d0b09, 0x07050301, 0x0e0c0a08,
        0x06040200,
    );
    let shuf_b = _mm256_set_epi32(
        0x0e0c0a08, 0x06040200, 0x0f0d0b09, 0x07050301, 0x0e0c0a08, 0x06040200, 0x0f0d0b09,
        0x07050301,
    );
    let sp = src.as_ptr();
    let dp = dst.as_mut_ptr();
    for j in 0..8usize {
        let ta = _mm256_loadu_si256(sp.add(j * 64) as *const __m256i);
        let tb = _mm256_loadu_si256(sp.add(j * 64 + 32) as *const __m256i);
        let tmp1 = _mm256_shuffle_epi8(ta, shuf_a);
        let tmp2 = _mm256_shuffle_epi8(tb, shuf_b);
        // th = high bytes -> planes 0..7, tl = low bytes -> planes 8..15.
        let mut th = _mm256_blend_epi32::<0x33>(tmp1, tmp2);
        let mut tl = _mm256_blend_epi32::<0x33>(tmp2, tmp1);
        tl = _mm256_permute4x64_epi64::<{ mm_shuffle(3, 1, 2, 0) }>(tl);
        th = _mm256_permute4x64_epi64::<{ mm_shuffle(2, 0, 3, 1) }>(th);
        // prep_write: plane p's j-th u32 word at byte p*32 + j*4.
        prep_write(dp, j * 4, th); // planes 0..7
        prep_write(dp, 256 + j * 4, tl); // planes 8..15
    }
}

/// Bit-transpose one de-interleaved 32-byte vector into 8 planes: MSB via
/// `movemask`, then 7 per-byte left shifts (`add_epi8`). `base` is the byte
/// offset of plane 0's `j`-th word; plane `i` lands at `base + i*32`.
#[target_feature(enable = "avx2")]
unsafe fn prep_write(dp: *mut u8, base: usize, mut bytes: __m256i) {
    let m0 = _mm256_movemask_epi8(bytes) as u32;
    core::ptr::copy_nonoverlapping(m0.to_le_bytes().as_ptr(), dp.add(base), 4);
    for i in 1..8usize {
        bytes = _mm256_add_epi8(bytes, bytes);
        let m = _mm256_movemask_epi8(bytes) as u32;
        core::ptr::copy_nonoverlapping(m.to_le_bytes().as_ptr(), dp.add(base + i * 32), 4);
    }
}

/// Extract one nibble of bit-planes: 4 `movemask`s (with `add_epi8` doublings)
/// packed into a 128-bit lane `[mskA, mskB, mskC, mskD]`. Advances `*src`.
#[target_feature(enable = "avx2")]
unsafe fn extract_nibble(src: &mut __m256i) -> __m128i {
    let msk_d = _mm256_movemask_epi8(*src);
    *src = _mm256_add_epi8(*src, *src);
    let msk_c = _mm256_movemask_epi8(*src);
    *src = _mm256_add_epi8(*src, *src);
    let msk_b = _mm256_movemask_epi8(*src);
    *src = _mm256_add_epi8(*src, *src);
    let msk_a = _mm256_movemask_epi8(*src);
    let mut t = _mm_cvtsi32_si128(msk_a);
    t = _mm_insert_epi32::<1>(t, msk_b);
    t = _mm_insert_epi32::<2>(t, msk_c);
    t = _mm_insert_epi32::<3>(t, msk_d);
    t
}

/// `gf16_xor_finish_extract_bits`: rebuild interleaved words from a plane group
/// (first-pass form; result buffered by the caller).
#[target_feature(enable = "avx2")]
unsafe fn finish_extract_bits(mut src: __m256i) -> __m256i {
    let words1 = extract_nibble(&mut src);
    src = _mm256_add_epi8(src, src);
    let words2 = extract_nibble(&mut src);
    let words = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(words2), words1);
    let words = _mm256_shuffle_epi8(
        words,
        _mm256_set_epi32(
            0x0f0e0b0a, 0x07060302, 0x0d0c0908, 0x05040100, 0x0f0e0b0a, 0x07060302, 0x0d0c0908,
            0x05040100,
        ),
    );
    _mm256_permute4x64_epi64::<{ mm_shuffle(3, 1, 2, 0) }>(words)
}

/// `gf16_xor_finish_extract_bits_store`: second-pass form, writes 8 u32 words.
#[target_feature(enable = "avx2")]
unsafe fn finish_extract_bits_store(dst: *mut u32, src: __m256i) {
    let src_shifted = _mm256_add_epi8(src, src);
    let mut lane = _mm256_inserti128_si256::<1>(src_shifted, _mm256_castsi256_si128(src));
    write_u32(dst, 3, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 2, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 1, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 0, _mm256_movemask_epi8(lane));

    lane = _mm256_permute2x128_si256::<0x31>(src_shifted, src);
    write_u32(dst, 7, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 6, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 5, _mm256_movemask_epi8(lane));
    lane = _mm256_slli_epi16::<2>(lane);
    write_u32(dst, 4, _mm256_movemask_epi8(lane));
}

#[inline(always)]
unsafe fn write_u32(dst: *mut u32, idx: usize, val: i32) {
    dst.add(idx).write_unaligned(val as u32);
}

/// One `LOAD_HALVES(a, b, upper)`: two 128-bit reads assembled into a 256-bit
/// vector (low = plane-half `a`, high = plane-half `b`), reading the block in
/// ParPar's reverse plane order `120 + upper*4 - x*8` (u32 units).
#[target_feature(enable = "avx2")]
unsafe fn load_halves(src: *const u32, a: usize, b: usize, upper: usize) -> __m256i {
    let lo = _mm_loadu_si128(src.add(120 + upper * 4 - a * 8) as *const __m128i);
    let hi = _mm_loadu_si128(src.add(120 + upper * 4 - b * 8) as *const __m128i);
    _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi)
}

/// `LOAD_X4`: two `load_halves` + byte-unpack into two vectors.
#[target_feature(enable = "avx2")]
unsafe fn load_x4(src: *const u32, offs: usize, upper: usize) -> (__m256i, __m256i) {
    let in1 = load_halves(src, offs, offs + 8, upper);
    let in2 = load_halves(src, offs + 1, offs + 9, upper);
    (
        _mm256_unpacklo_epi8(in1, in2),
        _mm256_unpackhi_epi8(in1, in2),
    )
}

/// `UNPACK_VECTS`: the epi16/epi32 unpack ladder + `permute4x64` producing the
/// 8 fully interleaved word vectors from the 8 byte-unpacked inputs.
#[target_feature(enable = "avx2")]
unsafe fn unpack_vects(w: [__m256i; 8]) -> [__m256i; 8] {
    let d0a = _mm256_unpacklo_epi16(w[0], w[2]);
    let d0b = _mm256_unpackhi_epi16(w[0], w[2]);
    let d0c = _mm256_unpacklo_epi16(w[1], w[3]);
    let d0d = _mm256_unpackhi_epi16(w[1], w[3]);
    let d4a = _mm256_unpacklo_epi16(w[4], w[6]);
    let d4b = _mm256_unpackhi_epi16(w[4], w[6]);
    let d4c = _mm256_unpacklo_epi16(w[5], w[7]);
    let d4d = _mm256_unpackhi_epi16(w[5], w[7]);
    let mut q = [
        _mm256_unpacklo_epi32(d0a, d4a),
        _mm256_unpackhi_epi32(d0a, d4a),
        _mm256_unpacklo_epi32(d0b, d4b),
        _mm256_unpackhi_epi32(d0b, d4b),
        _mm256_unpacklo_epi32(d0c, d4c),
        _mm256_unpackhi_epi32(d0c, d4c),
        _mm256_unpacklo_epi32(d0d, d4d),
        _mm256_unpackhi_epi32(d0d, d4d),
    ];
    for qi in q.iter_mut() {
        *qi = _mm256_permute4x64_epi64::<{ mm_shuffle(3, 1, 2, 0) }>(*qi);
    }
    q
}

/// Inverse of [`prepare_block`], in place. Faithful port of
/// `gf16_xor_finish_block_avx2`.
///
/// # Safety
/// Requires AVX2. `buf` is exactly [`BLOCK_BYTES`].
#[target_feature(enable = "avx2")]
pub unsafe fn finish_block(buf: &mut [u8; BLOCK_BYTES]) {
    let dst = buf.as_mut_ptr() as *mut u32;
    let src = buf.as_ptr() as *const u32;

    // First half: load the 8 high planes' halves, unpack, extract, buffer.
    let (w0, w1) = load_x4(src, 0, 0);
    let (w2, w3) = load_x4(src, 2, 0);
    let (w4, w5) = load_x4(src, 4, 0);
    let (w6, w7) = load_x4(src, 6, 0);
    let q = unpack_vects([w0, w1, w2, w3, w4, w5, w6, w7]);
    let out = [
        finish_extract_bits(q[0]),
        finish_extract_bits(q[1]),
        finish_extract_bits(q[2]),
        finish_extract_bits(q[3]),
        finish_extract_bits(q[4]),
        finish_extract_bits(q[5]),
        finish_extract_bits(q[6]),
        finish_extract_bits(q[7]),
    ];

    // Load the second half interleaved with storing the buffered first half
    // (the stores would otherwise clobber not-yet-read source planes).
    let (w6b, w7b) = load_x4(src, 6, 1);
    _mm256_storeu_si256(dst.add(0) as *mut __m256i, out[0]);
    _mm256_storeu_si256(dst.add(8) as *mut __m256i, out[1]);
    let (w4b, w5b) = load_x4(src, 4, 1);
    _mm256_storeu_si256(dst.add(16) as *mut __m256i, out[2]);
    _mm256_storeu_si256(dst.add(24) as *mut __m256i, out[3]);
    let (w2b, w3b) = load_x4(src, 2, 1);
    _mm256_storeu_si256(dst.add(32) as *mut __m256i, out[4]);
    _mm256_storeu_si256(dst.add(40) as *mut __m256i, out[5]);
    let (w0b, w1b) = load_x4(src, 0, 1);
    _mm256_storeu_si256(dst.add(48) as *mut __m256i, out[6]);
    _mm256_storeu_si256(dst.add(56) as *mut __m256i, out[7]);

    let q2 = unpack_vects([w0b, w1b, w2b, w3b, w4b, w5b, w6b, w7b]);
    finish_extract_bits_store(dst.add(64), q2[0]);
    finish_extract_bits_store(dst.add(64 + 8), q2[1]);
    finish_extract_bits_store(dst.add(64 + 16), q2[2]);
    finish_extract_bits_store(dst.add(64 + 24), q2[3]);
    finish_extract_bits_store(dst.add(64 + 32), q2[4]);
    finish_extract_bits_store(dst.add(64 + 40), q2[5]);
    finish_extract_bits_store(dst.add(64 + 48), q2[6]);
    finish_extract_bits_store(dst.add(64 + 56), q2[7]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block(seed: u64) -> [u8; BLOCK_BYTES] {
        let mut b = [0u8; BLOCK_BYTES];
        let mut s = seed.wrapping_add(0x9E3779B97F4A7C15) | 1;
        for byte in b.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *byte = (s >> 24) as u8;
        }
        b
    }

    #[test]
    fn prepare_finish_roundtrip() {
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
    fn plane_holds_word_bit_15_minus_p() {
        // Every plane must be the XOR-reduction of exactly word-bit (15-p):
        // set word i = 1<<b for a chosen bit b, then only plane (15-b) is
        // nonzero. This pins the plane<->word-bit mapping the deps rely on,
        // independent of intra-plane word order.
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
                let all_set = plane.iter().all(|&x| x == 0xff);
                let all_clear = plane.iter().all(|&x| x == 0x00);
                if p == target {
                    assert!(all_set, "bit {b}: plane {p} should be all-set");
                } else {
                    assert!(all_clear, "bit {b}: plane {p} should be clear");
                }
            }
        }
    }
}
