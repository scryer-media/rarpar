//! A tiny `u32x4` SIMD abstraction with three interchangeable backends and a
//! single 4-way BLAKE2s compression kernel that runs on top of it.
//!
//! The point of this module is that ONE kernel body ([`compress4`]) serves the
//! NEON, wasm-`simd128`, and portable-scalar backends. Each backend is a
//! zero-sized marker type implementing the [`Simd`] trait; the kernel is
//! generic over that trait and monomorphizes into an architecture-specific
//! routine with no runtime dispatch.
//!
//! The vector convention throughout is: a [`Simd::Vec`] holds four lanes, and
//! lane `i` carries leaf `i`'s word. Four independent BLAKE2s instances are
//! advanced in lockstep, one per lane. Because the instances are independent
//! (BLAKE2sp's leaves never interact until the root), the 4-way compression
//! needs NO diagonalization shuffles — the standard column/row `G` mixing is
//! applied to whole vectors. See RFC 7693 §3.1-3.2 for the scalar `G` this
//! mirrors, and §2.1/§3 (tree hashing) plus the BLAKE2 spec §2.10 for the
//! BLAKE2sp leaf/root construction the caller drives.
//!
//! All weaver targets are little-endian, so message words are loaded straight
//! from memory with `u32::from_le_bytes` and lanes are stored with
//! `to_le_bytes`; no per-lane endian fixup is required.

/// BLAKE2s IV (RFC 7693 §2.6). Shared by every leaf and the root.
pub(super) const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// BLAKE2s message schedule SIGMA (RFC 7693 §2.7, 10 rounds for BLAKE2s).
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The abstraction seam: a 4-lane `u32` vector and the handful of operations
/// the BLAKE2s round needs. Implemented once per backend.
///
/// # Safety
///
/// Implementations may use target intrinsics that require specific CPU
/// features. Every method is only ever reached from [`compress4`], which is
/// itself invoked behind the same compile-time `cfg`/`target_feature` gate the
/// backend requires (NEON is baseline on `aarch64`; the wasm backend is gated
/// on `target_feature = "simd128"`). Callers must uphold that gate.
pub(super) trait Simd: Copy {
    /// The backend's native 4-lane vector.
    type Vec: Copy;

    /// Broadcast one `u32` into all four lanes.
    unsafe fn splat(x: u32) -> Self::Vec;

    /// Build a vector from four explicit lanes (lane 0 first).
    unsafe fn set(a: u32, b: u32, c: u32, d: u32) -> Self::Vec;

    /// Load four consecutive little-endian `u32` from 16 bytes (unaligned),
    /// lane 0 taking bytes `0..4`. Used to pull one 4-word tile out of a leaf's
    /// 64-byte block before transposing it into message vectors.
    unsafe fn load(bytes: &[u8; 16]) -> Self::Vec;

    /// Transpose a 4x4 `u32` matrix held in four vectors (one per row).
    ///
    /// Input row `i` is vector `[i]`; output row `j` (`[j]`) collects lane `j`
    /// of every input, i.e. `out[j]` lane `i` == `in[i]` lane `j`. So with
    /// `a,b,c,d` carrying leaves 0..4's words `[w0,w1,w2,w3]` of one tile, the
    /// result's vector `j` is `[a.w_j, b.w_j, c.w_j, d.w_j]` — exactly the
    /// message vector `m[tile*4 + j]` the kernel wants (lane `i` = leaf `i`).
    unsafe fn transpose4(a: Self::Vec, b: Self::Vec, c: Self::Vec, d: Self::Vec) -> [Self::Vec; 4];

    /// Wrapping lane-wise addition.
    unsafe fn add(a: Self::Vec, b: Self::Vec) -> Self::Vec;

    /// Lane-wise XOR.
    unsafe fn xor(a: Self::Vec, b: Self::Vec) -> Self::Vec;

    /// Lane-wise rotate-right by 16 (equals `u32::rotate_right(x, 16)`).
    unsafe fn rotr16(a: Self::Vec) -> Self::Vec;

    /// Lane-wise rotate-right by 12.
    unsafe fn rotr12(a: Self::Vec) -> Self::Vec;

    /// Lane-wise rotate-right by 8.
    unsafe fn rotr8(a: Self::Vec) -> Self::Vec;

    /// Lane-wise rotate-right by 7.
    unsafe fn rotr7(a: Self::Vec) -> Self::Vec;

    /// Store the four lanes to `out` (lane 0 first).
    unsafe fn store(a: Self::Vec, out: &mut [u32; 4]);
}

/// The BLAKE2s mixing function `G`, applied to whole vectors (RFC 7693 §3.1).
///
/// Operates on the 16-vector working state `v`, mixing four independent lanes
/// in parallel. `x`/`y` are the two scheduled message vectors for this call.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn g<S: Simd>(
    v: &mut [S::Vec; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: S::Vec,
    y: S::Vec,
) {
    // a = a + b + x; d = ror(d ^ a, 16); c = c + d; b = ror(b ^ c, 12);
    // a = a + b + y; d = ror(d ^ a,  8); c = c + d; b = ror(b ^ c,  7);
    // SAFETY: the backend intrinsics are gated by the caller's target
    // (see the `Simd` trait's safety note); every op here is lane-wise
    // arithmetic on already-initialized vectors.
    unsafe {
        v[a] = S::add(S::add(v[a], v[b]), x);
        v[d] = S::rotr16(S::xor(v[d], v[a]));
        v[c] = S::add(v[c], v[d]);
        v[b] = S::rotr12(S::xor(v[b], v[c]));
        v[a] = S::add(S::add(v[a], v[b]), y);
        v[d] = S::rotr8(S::xor(v[d], v[a]));
        v[c] = S::add(v[c], v[d]);
        v[b] = S::rotr7(S::xor(v[b], v[c]));
    }
}

/// One BLAKE2s round over vectors: mix the four columns, then the four rows.
///
/// Unlike a single-instance SIMD BLAKE2s (which rotates lanes to form
/// diagonals), the multi-way layout keeps every lane on its own instance, so
/// the "diagonal" step is just `G` on a different set of state indices — no
/// cross-lane shuffle is ever needed.
///
/// The round number is a *const generic* `R`, not a runtime argument, so the
/// message schedule `SIGMA[R]` resolves to sixteen literal indices at compile
/// time. Each `m[..]` then reads a compile-time-constant lane of the message
/// array, which lets the backend keep the 16 message vectors register-resident
/// across all ten rounds instead of reloading them (or the SIGMA table) from
/// the stack on the latency-critical `G` chain. This is pure codegen: the math
/// and evaluation order are identical to a runtime-`r` version.
#[inline(always)]
unsafe fn round<S: Simd, const R: usize>(m: &[S::Vec; 16], v: &mut [S::Vec; 16]) {
    const { assert!(R < 10, "BLAKE2s has 10 rounds") };
    // `SR` is this round's schedule, materialized as a named const so every
    // `SR[k] as usize` below is a compile-time-constant index into `m`.
    const SR: [[u8; 16]; 10] = SIGMA;
    // SAFETY: `g` is only unsafe because it forwards to backend intrinsics
    // gated by the caller's target; see the `Simd` trait's safety note.
    unsafe {
        // Columns.
        g::<S>(v, 0, 4, 8, 12, m[SR[R][0] as usize], m[SR[R][1] as usize]);
        g::<S>(v, 1, 5, 9, 13, m[SR[R][2] as usize], m[SR[R][3] as usize]);
        g::<S>(v, 2, 6, 10, 14, m[SR[R][4] as usize], m[SR[R][5] as usize]);
        g::<S>(v, 3, 7, 11, 15, m[SR[R][6] as usize], m[SR[R][7] as usize]);
        // Rows / "diagonals".
        g::<S>(v, 0, 5, 10, 15, m[SR[R][8] as usize], m[SR[R][9] as usize]);
        g::<S>(
            v,
            1,
            6,
            11,
            12,
            m[SR[R][10] as usize],
            m[SR[R][11] as usize],
        );
        g::<S>(v, 2, 7, 8, 13, m[SR[R][12] as usize], m[SR[R][13] as usize]);
        g::<S>(v, 3, 4, 9, 14, m[SR[R][14] as usize], m[SR[R][15] as usize]);
    }
}

/// Transpose four leaves' 64-byte blocks into the kernel's 16 message vectors:
/// `m[k]` lane `i` == leaf `i`'s message word `k`.
///
/// Done as four 4x4 `u32` SIMD transposes instead of a scalar per-word gather.
/// Each 64-byte block is 16 LE `u32`; tile `t` (words `4t..4t+4`) is the 16
/// bytes at offset `16*t`. For each tile we load one vector per leaf (`load`
/// handles the LE decode) — the four leaves' tiles, one row each — then
/// `transpose4` yields output vector `j` = `m[4t+j]`, whose lane `i` is leaf
/// `i`'s word `4t+j`. The leaves' blocks need not be contiguous (the finalize
/// path passes separate `padded` arrays), so each row is loaded independently
/// from its own `blocks[i]` slice.
#[inline(always)]
pub(super) unsafe fn transpose_block<S: Simd>(blocks: &[&[u8; 64]; 4]) -> [S::Vec; 16] {
    // SAFETY: the loads/permutes forward to backend intrinsics gated by the
    // caller's target; see the `Simd` trait safety note.
    unsafe {
        let mut m = [S::splat(0); 16];
        for t in 0..4 {
            let off = 16 * t;
            let tile = |b: &[u8; 64]| -> [u8; 16] {
                let mut s = [0u8; 16];
                s.copy_from_slice(&b[off..off + 16]);
                s
            };
            let rows = S::transpose4(
                S::load(&tile(blocks[0])),
                S::load(&tile(blocks[1])),
                S::load(&tile(blocks[2])),
                S::load(&tile(blocks[3])),
            );
            m[off / 4..off / 4 + 4].copy_from_slice(&rows);
        }
        m
    }
}

/// Advance four BLAKE2s leaves by one 64-byte block each.
///
/// * `h`      — the eight state vectors; `h[j]` lane `i` is leaf `i`'s word `j`.
///   Updated in place.
/// * `blocks` — four 64-byte message blocks, one per lane (`blocks[i]` feeds
///   lane `i`). Interpreted as 16 little-endian `u32` words each.
/// * `count`  — per-lane 64-bit block counter (bytes hashed *including* this
///   block). Split into `t0`/`t1` per lane.
/// * `f0`     — per-lane final-block flag word (`!0` on a leaf's last block).
/// * `f1`     — per-lane last-node flag word (`!0` only on leaf 7's last block).
///
/// This is a thin wrapper: it transposes `blocks` into the 16 message vectors
/// (see [`transpose_block`]) and runs the shared body [`compress4_transposed`].
/// The const generic `FINAL` picks the counter/flag build and is documented on
/// that body. A caller that wants to overlap the transpose of one block with
/// the round chain of another can call the two halves directly instead.
#[inline(always)]
pub(super) unsafe fn compress4<S: Simd, const FINAL: bool>(
    h: &mut [S::Vec; 8],
    blocks: &[&[u8; 64]; 4],
    count: [u64; 4],
    f0: [u32; 4],
    f1: [u32; 4],
) {
    // SAFETY: the transpose and kernel forward to backend intrinsics gated by
    // the caller's target; see the `Simd` trait safety note.
    unsafe {
        let m = transpose_block::<S>(blocks);
        compress4_transposed::<S, FINAL>(h, &m, count, f0, f1);
    }
}

/// The BLAKE2s 4-way compression body over an already-transposed message
/// (`m[k]` lane `i` = leaf `i`'s word `k`; see [`transpose_block`]). Split out
/// from [`compress4`] so a caller can hoist the message transpose ahead of the
/// round chain (e.g. transpose both leaf groups before compressing either).
///
/// The const generic `FINAL` selects one of two counter/flag builds that are
/// *numerically identical* for the inputs each caller actually passes — it only
/// changes how the `t0`/`t1`/`v[14]`/`v[15]` vectors are materialized:
///
/// * `FINAL == true` (tail / finalize path): the four leaves diverge — they can
///   finalize on different blocks and only leaf 7 is the last node — so the
///   counter and both flags are built per-lane from the full `count`/`f0`/`f1`
///   arrays, and the flags are XORed into `v[14]`/`v[15]`.
/// * `FINAL == false` (streaming bulk path, `compress_superblock`): every lane
///   shares one counter (each super-block advances all leaves by one block) and
///   both final flags are zero. The counter is then a single `splat`
///   of the shared low/high words (no 4-lane `set`), and the two flag XORs are
///   dropped entirely — `v[14]`/`v[15]` are plain `splat(IV[6])`/`splat(IV[7])`.
///   Callers in this mode may pass any `f0`/`f1` (they are ignored) but MUST
///   pass an all-equal `count` (only `count[0]` is read).
#[inline(always)]
pub(super) unsafe fn compress4_transposed<S: Simd, const FINAL: bool>(
    h: &mut [S::Vec; 8],
    m: &[S::Vec; 16],
    count: [u64; 4],
    f0: [u32; 4],
    f1: [u32; 4],
) {
    // SAFETY: every `S::*` call and the nested kernel functions are unsafe
    // only because they forward to backend intrinsics gated by the caller's
    // target (NEON is baseline on aarch64; the wasm backend is compiled under
    // `target_feature = "simd128"`). See the `Simd` trait's safety note. The
    // math below is pure lane-wise arithmetic on initialized vectors.
    unsafe {
        // Build the counter words (t0 = low 32 bits, t1 = high 32 bits) and the
        // two flag-carrying state words `v[14]`/`v[15]`. In the bulk path all
        // four lanes share one counter and both flags are zero, so we splat the
        // shared word and skip the flag XORs; in the finalize path each is built
        // per-lane. See the const-generic `FINAL` note on this function.
        let (t0, t1, v14, v15);
        if FINAL {
            t0 = S::set(
                count[0] as u32,
                count[1] as u32,
                count[2] as u32,
                count[3] as u32,
            );
            t1 = S::set(
                (count[0] >> 32) as u32,
                (count[1] >> 32) as u32,
                (count[2] >> 32) as u32,
                (count[3] >> 32) as u32,
            );
            let f0v = S::set(f0[0], f0[1], f0[2], f0[3]);
            let f1v = S::set(f1[0], f1[1], f1[2], f1[3]);
            v14 = S::xor(S::splat(IV[6]), f0v);
            v15 = S::xor(S::splat(IV[7]), f1v);
        } else {
            // All lanes share `count[0]`; both flags are zero.
            t0 = S::splat(count[0] as u32);
            t1 = S::splat((count[0] >> 32) as u32);
            v14 = S::splat(IV[6]);
            v15 = S::splat(IV[7]);
        }

        // v[0..8] = h; v[8..12] = IV[0..4];
        // v[12] = IV[4]^t0; v[13] = IV[5]^t1; v[14] = IV[6]^f0; v[15] = IV[7]^f1.
        let mut v = [
            h[0],
            h[1],
            h[2],
            h[3],
            h[4],
            h[5],
            h[6],
            h[7],
            S::splat(IV[0]),
            S::splat(IV[1]),
            S::splat(IV[2]),
            S::splat(IV[3]),
            S::xor(S::splat(IV[4]), t0),
            S::xor(S::splat(IV[5]), t1),
            v14,
            v15,
        ];

        round::<S, 0>(m, &mut v);
        round::<S, 1>(m, &mut v);
        round::<S, 2>(m, &mut v);
        round::<S, 3>(m, &mut v);
        round::<S, 4>(m, &mut v);
        round::<S, 5>(m, &mut v);
        round::<S, 6>(m, &mut v);
        round::<S, 7>(m, &mut v);
        round::<S, 8>(m, &mut v);
        round::<S, 9>(m, &mut v);

        // h[j] ^= v[j] ^ v[j+8].
        for j in 0..8 {
            h[j] = S::xor(h[j], S::xor(v[j], v[j + 8]));
        }
    }
}

// ===========================================================================
// Backend: portable scalar (arch-independent ground-truth oracle)
// ===========================================================================

/// Portable four-lane vector: a plain `[u32; 4]`. On the targets this module
/// compiles for (aarch64 / wasm-simd128) a real SIMD backend is always
/// selected, so `Scalar` exists purely as the arch-independent correctness
/// oracle exercised by the differential tests.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct Scalar;

#[cfg(test)]
impl Simd for Scalar {
    type Vec = [u32; 4];

    #[inline(always)]
    unsafe fn splat(x: u32) -> Self::Vec {
        [x; 4]
    }

    #[inline(always)]
    unsafe fn set(a: u32, b: u32, c: u32, d: u32) -> Self::Vec {
        [a, b, c, d]
    }

    #[inline(always)]
    unsafe fn load(bytes: &[u8; 16]) -> Self::Vec {
        [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        ]
    }

    #[inline(always)]
    unsafe fn transpose4(a: Self::Vec, b: Self::Vec, c: Self::Vec, d: Self::Vec) -> [Self::Vec; 4] {
        // out[j] lane i == in[i] lane j.
        [
            [a[0], b[0], c[0], d[0]],
            [a[1], b[1], c[1], d[1]],
            [a[2], b[2], c[2], d[2]],
            [a[3], b[3], c[3], d[3]],
        ]
    }

    #[inline(always)]
    unsafe fn add(a: Self::Vec, b: Self::Vec) -> Self::Vec {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }

    #[inline(always)]
    unsafe fn xor(a: Self::Vec, b: Self::Vec) -> Self::Vec {
        [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
    }

    #[inline(always)]
    unsafe fn rotr16(a: Self::Vec) -> Self::Vec {
        [
            a[0].rotate_right(16),
            a[1].rotate_right(16),
            a[2].rotate_right(16),
            a[3].rotate_right(16),
        ]
    }

    #[inline(always)]
    unsafe fn rotr12(a: Self::Vec) -> Self::Vec {
        [
            a[0].rotate_right(12),
            a[1].rotate_right(12),
            a[2].rotate_right(12),
            a[3].rotate_right(12),
        ]
    }

    #[inline(always)]
    unsafe fn rotr8(a: Self::Vec) -> Self::Vec {
        [
            a[0].rotate_right(8),
            a[1].rotate_right(8),
            a[2].rotate_right(8),
            a[3].rotate_right(8),
        ]
    }

    #[inline(always)]
    unsafe fn rotr7(a: Self::Vec) -> Self::Vec {
        [
            a[0].rotate_right(7),
            a[1].rotate_right(7),
            a[2].rotate_right(7),
            a[3].rotate_right(7),
        ]
    }

    #[inline(always)]
    unsafe fn store(a: Self::Vec, out: &mut [u32; 4]) {
        *out = a;
    }
}

// ===========================================================================
// Backend: aarch64 NEON
// ===========================================================================

#[cfg(target_arch = "aarch64")]
pub(super) use neon::Neon;

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::Simd;
    use core::arch::aarch64::*;

    /// NEON backend. NEON is mandatory in the ARMv8-A baseline, so no runtime
    /// feature detection is required on `aarch64`.
    #[derive(Clone, Copy)]
    pub(in crate::crypto::blake2sp_simd) struct Neon;

    // SAFETY (whole impl): every method forwards to an ARMv8-A NEON intrinsic.
    // NEON is part of the aarch64 baseline, so the required target feature is
    // always present; the raw-pointer loads/stores below only touch fixed-size
    // stack arrays that are fully initialized.
    impl Simd for Neon {
        type Vec = uint32x4_t;

        #[inline(always)]
        unsafe fn splat(x: u32) -> Self::Vec {
            unsafe { vdupq_n_u32(x) }
        }

        #[inline(always)]
        unsafe fn set(a: u32, b: u32, c: u32, d: u32) -> Self::Vec {
            let lanes = [a, b, c, d];
            unsafe { vld1q_u32(lanes.as_ptr()) }
        }

        /// Unaligned load of four LE `u32`. `vld1q_u32` needs no alignment and
        /// the targets are little-endian, so lanes come out `[w0,w1,w2,w3]`.
        #[inline(always)]
        unsafe fn load(bytes: &[u8; 16]) -> Self::Vec {
            unsafe { vld1q_u32(bytes.as_ptr() as *const u32) }
        }

        /// 4x4 `u32` transpose. Two `vtrnq_u32` passes interleave the even/odd
        /// `u32` lanes of each row pair; two `vtrnq_u64` passes (reinterpreting
        /// each vector as `u64x2`) then interleave the 64-bit halves, moving the
        /// second row-pair's words into place. Result: `out[j]` lane `i` ==
        /// `in[i]` lane `j`, i.e. `out[0] = [a0,b0,c0,d0]` (verified by the
        /// differential corpus and the scalar cross-check).
        #[inline(always)]
        unsafe fn transpose4(
            a: Self::Vec,
            b: Self::Vec,
            c: Self::Vec,
            d: Self::Vec,
        ) -> [Self::Vec; 4] {
            unsafe {
                // t0 = [a0,b0,a2,b2], t1 = [a1,b1,a3,b3],
                // t2 = [c0,d0,c2,d2], t3 = [c1,d1,c3,d3].
                let t0 = vtrn1q_u32(a, b);
                let t1 = vtrn2q_u32(a, b);
                let t2 = vtrn1q_u32(c, d);
                let t3 = vtrn2q_u32(c, d);
                // Interleave 64-bit halves: low halves -> words 0/1 rows,
                // high halves -> words 2/3 rows.
                let o0 = vreinterpretq_u32_u64(vtrn1q_u64(
                    vreinterpretq_u64_u32(t0),
                    vreinterpretq_u64_u32(t2),
                ));
                let o1 = vreinterpretq_u32_u64(vtrn1q_u64(
                    vreinterpretq_u64_u32(t1),
                    vreinterpretq_u64_u32(t3),
                ));
                let o2 = vreinterpretq_u32_u64(vtrn2q_u64(
                    vreinterpretq_u64_u32(t0),
                    vreinterpretq_u64_u32(t2),
                ));
                let o3 = vreinterpretq_u32_u64(vtrn2q_u64(
                    vreinterpretq_u64_u32(t1),
                    vreinterpretq_u64_u32(t3),
                ));
                [o0, o1, o2, o3]
            }
        }

        #[inline(always)]
        unsafe fn add(a: Self::Vec, b: Self::Vec) -> Self::Vec {
            unsafe { vaddq_u32(a, b) }
        }

        #[inline(always)]
        unsafe fn xor(a: Self::Vec, b: Self::Vec) -> Self::Vec {
            unsafe { veorq_u32(a, b) }
        }

        /// ror16 via a 16-bit element reverse within each 32-bit lane:
        /// reinterpret as `u16x8`, `vrev32q_u16` swaps the halfword pairs,
        /// which is exactly a rotate-right-by-16 of each `u32`.
        #[inline(always)]
        unsafe fn rotr16(a: Self::Vec) -> Self::Vec {
            unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(a))) }
        }

        /// ror12 = (x >> 12) | (x << 20), built from a right shift with a
        /// shift-left-and-insert so the two halves merge in one op.
        #[inline(always)]
        unsafe fn rotr12(a: Self::Vec) -> Self::Vec {
            unsafe {
                let r = vshrq_n_u32::<12>(a);
                vsliq_n_u32::<20>(r, a)
            }
        }

        /// ror8 via a byte-wise table permute: rotating each 32-bit lane right
        /// by one byte. The index table selects bytes [1,2,3,0] of each lane.
        ///
        /// A shift-insert form (`vshrq_n_u32::<8>` + `vsliq_n_u32::<24>`, the
        /// same shape as ror7/ror12) was benchmarked as an alternative: it frees
        /// the constant index register but costs one extra op per call, and it
        /// measured ~7% slower on this machine (best ~1790 vs ~1940 MB/s). The
        /// single-op byte permute wins, so it is kept.
        #[inline(always)]
        unsafe fn rotr8(a: Self::Vec) -> Self::Vec {
            // Per-lane byte indices for a right-rotate by 8 bits.
            const IDX: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
            unsafe {
                let tbl = vreinterpretq_u8_u32(a);
                let idx = vld1q_u8(IDX.as_ptr());
                vreinterpretq_u32_u8(vqtbl1q_u8(tbl, idx))
            }
        }

        /// ror7 = (x >> 7) | (x << 25), via shift-right then shift-left-insert.
        #[inline(always)]
        unsafe fn rotr7(a: Self::Vec) -> Self::Vec {
            unsafe {
                let r = vshrq_n_u32::<7>(a);
                vsliq_n_u32::<25>(r, a)
            }
        }

        #[inline(always)]
        unsafe fn store(a: Self::Vec, out: &mut [u32; 4]) {
            unsafe { vst1q_u32(out.as_mut_ptr(), a) }
        }
    }
}

// ===========================================================================
// Backend: wasm32 simd128
// ===========================================================================

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
pub(super) use wasm::Wasm;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod wasm {
    use super::Simd;
    use core::arch::wasm32::*;

    /// wasm `simd128` backend. Selected at compile time when the module is
    /// built with `target_feature = "simd128"`.
    #[derive(Clone, Copy)]
    pub(in crate::crypto::blake2sp_simd) struct Wasm;

    impl Simd for Wasm {
        type Vec = v128;

        #[inline(always)]
        unsafe fn splat(x: u32) -> Self::Vec {
            u32x4_splat(x)
        }

        #[inline(always)]
        unsafe fn set(a: u32, b: u32, c: u32, d: u32) -> Self::Vec {
            u32x4(a, b, c, d)
        }

        /// Unaligned 128-bit load; `v128_load` places bytes `0..4` in lane 0,
        /// and the target is little-endian, so lanes are `[w0,w1,w2,w3]`.
        #[inline(always)]
        unsafe fn load(bytes: &[u8; 16]) -> Self::Vec {
            // SAFETY: `v128_load` is unsafe only because it dereferences a raw
            // pointer; `bytes` is a 16-byte array, exactly one `v128` wide, and
            // `v128_load` permits an unaligned source.
            unsafe { v128_load(bytes.as_ptr() as *const v128) }
        }

        /// 4x4 `u32` transpose via `i32x4_shuffle`. The first four shuffles
        /// interleave row pairs into low/high halves; the last four combine the
        /// 64-bit halves so `out[j]` lane `i` == `in[i]` lane `j`, i.e.
        /// `out[0] = [a0,b0,c0,d0]` (verified by the differential corpus and the
        /// scalar cross-check). Shuffle indices 0..3 pick lanes of the first
        /// operand, 4..7 the second.
        #[inline(always)]
        unsafe fn transpose4(
            a: Self::Vec,
            b: Self::Vec,
            c: Self::Vec,
            d: Self::Vec,
        ) -> [Self::Vec; 4] {
            // ab_lo = [a0,b0,a1,b1], ab_hi = [a2,b2,a3,b3],
            // cd_lo = [c0,d0,c1,d1], cd_hi = [c2,d2,c3,d3].
            let ab_lo = i32x4_shuffle::<0, 4, 1, 5>(a, b);
            let ab_hi = i32x4_shuffle::<2, 6, 3, 7>(a, b);
            let cd_lo = i32x4_shuffle::<0, 4, 1, 5>(c, d);
            let cd_hi = i32x4_shuffle::<2, 6, 3, 7>(c, d);
            let o0 = i32x4_shuffle::<0, 1, 4, 5>(ab_lo, cd_lo);
            let o1 = i32x4_shuffle::<2, 3, 6, 7>(ab_lo, cd_lo);
            let o2 = i32x4_shuffle::<0, 1, 4, 5>(ab_hi, cd_hi);
            let o3 = i32x4_shuffle::<2, 3, 6, 7>(ab_hi, cd_hi);
            [o0, o1, o2, o3]
        }

        #[inline(always)]
        unsafe fn add(a: Self::Vec, b: Self::Vec) -> Self::Vec {
            u32x4_add(a, b)
        }

        #[inline(always)]
        unsafe fn xor(a: Self::Vec, b: Self::Vec) -> Self::Vec {
            v128_xor(a, b)
        }

        /// ror by n = (x >> n) | (x << (32 - n)); wasm has no rotate, so build
        /// each rotation from a logical right shift OR a left shift.
        #[inline(always)]
        unsafe fn rotr16(a: Self::Vec) -> Self::Vec {
            v128_or(u32x4_shr(a, 16), u32x4_shl(a, 16))
        }

        #[inline(always)]
        unsafe fn rotr12(a: Self::Vec) -> Self::Vec {
            v128_or(u32x4_shr(a, 12), u32x4_shl(a, 20))
        }

        #[inline(always)]
        unsafe fn rotr8(a: Self::Vec) -> Self::Vec {
            v128_or(u32x4_shr(a, 8), u32x4_shl(a, 24))
        }

        #[inline(always)]
        unsafe fn rotr7(a: Self::Vec) -> Self::Vec {
            v128_or(u32x4_shr(a, 7), u32x4_shl(a, 25))
        }

        #[inline(always)]
        unsafe fn store(a: Self::Vec, out: &mut [u32; 4]) {
            // Lane extraction is safe and avoids any alignment assumption on
            // `out` (a `[u32; 4]` is 4-aligned, but `v128` wants 16).
            out[0] = u32x4_extract_lane::<0>(a);
            out[1] = u32x4_extract_lane::<1>(a);
            out[2] = u32x4_extract_lane::<2>(a);
            out[3] = u32x4_extract_lane::<3>(a);
        }
    }
}
