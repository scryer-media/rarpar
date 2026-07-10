//! GF(2^16) multiply-by-factor as a bit-plane dependency matrix, plus a scalar
//! reference multiply, for the XOR-JIT tier.
//!
//! `output_plane[o] = XOR of input_plane[k]` over the set bits of row `o` of a
//! 16×16 GF(2) matrix — the same linear map the GFNI affine kernel and the
//! shuffle tables encode, in the bit-plane basis the JIT'd `vpxor` kernel
//! consumes. The matrix is fixed per factor (once-per-factor setup); ParPar
//! builds it with a SIMD generator, but the result is pure GF math, so it is
//! computed scalar here and validated byte-exact end to end.
//!
//! [`muladd_planar`] is the correctness oracle the JIT codegen must reproduce.

use super::transpose::{BLOCK_BYTES, PLANE_BYTES};
use crate::gf;

/// The 16×16 GF(2) dependency matrix for multiply-by-`factor`, plane-space.
/// `rows[o]` bit `k` set ⇒ output plane `o` receives (XORs in) input plane `k`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XorDeps {
    pub rows: [u16; 16],
}

/// Build the dependency matrix for `factor`.
///
/// Plane `p` holds word-bit `15-p`, so input plane `k` carries word-bit
/// `15-k`; its contribution to the product is `factor · 2^(15-k)`, whose bit
/// `15-o` lands in output plane `o`.
pub fn compute_deps(factor: u16) -> XorDeps {
    let mut rows = [0u16; 16];
    for k in 0..16usize {
        let contribution = gf::mul(factor, 1u16 << (15 - k));
        for (o, row) in rows.iter_mut().enumerate() {
            if (contribution >> (15 - o)) & 1 == 1 {
                *row |= 1 << k;
            }
        }
    }
    XorDeps { rows }
}

/// Scalar reference: `dst ^= factor · src` with both in bit-plane layout, over
/// a region of whole 512-byte blocks. The JIT'd kernel reproduces exactly this
/// XOR schedule; this is the byte-exact oracle it is validated against.
pub fn muladd_planar(deps: &XorDeps, src: &[u8], dst: &mut [u8]) {
    muladd_planar_sized(deps, src, dst, BLOCK_BYTES, PLANE_BYTES);
}

/// [`muladd_planar`] over an arbitrary plane geometry — the oracle for the
/// AVX512 tier's 1024-byte blocks (64-byte planes). The XOR schedule is
/// plane-size-independent; only the offsets scale.
pub fn muladd_planar_sized(
    deps: &XorDeps,
    src: &[u8],
    dst: &mut [u8],
    block_bytes: usize,
    plane_bytes: usize,
) {
    debug_assert_eq!(block_bytes, plane_bytes * 16);
    debug_assert_eq!(src.len(), dst.len());
    debug_assert_eq!(src.len() % block_bytes, 0);
    for blk in 0..(src.len() / block_bytes) {
        let base = blk * block_bytes;
        for (o, &row) in deps.rows.iter().enumerate() {
            let mut mask = row;
            while mask != 0 {
                let k = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                let src_plane = base + k * plane_bytes;
                let dst_plane = base + o * plane_bytes;
                for b in 0..plane_bytes {
                    dst[dst_plane + b] ^= src[src_plane + b];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xor_jit::transpose::{BLOCK_WORDS, finish_block, prepare_block};

    /// End-to-end scalar layout+deps contract on real AVX2: prepare (SIMD) ->
    /// planar muladd (scalar, deps) -> finish (SIMD) must equal the word-wise
    /// GF multiply. Isolates the layout+deps chain from the JIT codegen.
    #[test]
    fn planar_muladd_matches_scalar_gf() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        for factor in [
            0u16, 1, 2, 3, 0x8000, 0xABCD, 0xFFFF, 0x1234, 0x0101, 0x2F1D,
        ] {
            let mut src = [0u8; BLOCK_BYTES];
            let mut s = (factor as u64).wrapping_mul(0x9E3779B97F4A7C15) | 1;
            for byte in src.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *byte = (s >> 24) as u8;
            }

            // Reference: dst starts 0, dst[word] = factor * src[word].
            let mut expected = [0u8; BLOCK_BYTES];
            for w in 0..BLOCK_WORDS {
                let sw = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
                let pb = gf::mul(factor, sw).to_le_bytes();
                expected[w * 2] = pb[0];
                expected[w * 2 + 1] = pb[1];
            }

            // Planar path.
            let mut src_planes = [0u8; BLOCK_BYTES];
            unsafe { prepare_block(&src, &mut src_planes) };
            let mut dst_planes = [0u8; BLOCK_BYTES]; // planar zero == byte zero
            let deps = compute_deps(factor);
            muladd_planar(&deps, &src_planes, &mut dst_planes);
            unsafe { finish_block(&mut dst_planes) };

            assert_eq!(dst_planes, expected, "factor {factor:#06x}");
        }
    }

    #[test]
    fn deps_factor_one_is_identity() {
        // factor 1: output plane o == input plane o (identity map).
        let deps = compute_deps(1);
        for o in 0..16usize {
            assert_eq!(deps.rows[o], 1u16 << o, "row {o}");
        }
    }
}
