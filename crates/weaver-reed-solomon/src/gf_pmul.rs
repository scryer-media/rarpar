//! Element-wise GF(2^16) multiply: `dst[i] = a[i] * b[i]`.
//!
//! Port of ParPar's `gf16pmul` kernel family (par2cmdline-turbo
//! `parpar/gf16/gf16pmul.{h,cpp}`), used upstream to build recovery-matrix
//! rows with sequential exponents by iterated multiplication instead of a
//! log/antilog `pow` per element (`gfmat_inv.cpp` `Construct`, :506-554).
//!
//! The aarch64 kernel ports `gf16pmul_neon.c` structure-for-structure (with
//! two deliberate generalizations: a scalar tail for arbitrary even lengths
//! where upstream asserts 32-byte multiples, and a const-generic SHA3 flavor
//! where upstream uses per-file feature flags): per 32-byte
//! block, `vld2` splits both operands into even/odd byte planes, six PMULLs
//! form the Karatsuba partials with *both* multiplicands taken from memory,
//! and the same packed Barrett reduction as the input-batch CLMUL kernels
//! (`gf16_clmul_neon_reduction`) folds the product — note the plain-store
//! finish: pmul overwrites `dst`, it does not accumulate.
//!
//! The x86 variants (`gf16pmul_{sse,avx2,vpclmul,vpclgfni}.c`) are not yet
//! ported (deferred to the strict-parity completeness phase); non-NEON
//! targets use the scalar fallback.

use crate::gf;

/// `dst[i] = a[i] * b[i]` over LE u16 words.
///
/// # Panics
///
/// Panics if the slice lengths differ or are odd.
pub fn pmul_region(dst: &mut [u8], a: &[u8], b: &[u8]) {
    assert_eq!(a.len(), dst.len(), "operand lengths must match dst");
    assert_eq!(b.len(), dst.len(), "operand lengths must match dst");
    assert!(dst.len().is_multiple_of(2), "region length must be even");

    if dst.is_empty() {
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        // The SHA3 flavor only changes the reduction's internal ops (EOR3 vs
        // the vqtbl1q bit-fold), exactly as upstream's per-file feature flags
        // would; both are byte-identical in output.
        if std::arch::is_aarch64_feature_detected!("sha3") {
            unsafe { pmul_region_neon_sha3(dst, a, b) };
        } else {
            unsafe { pmul_region_neon(dst, a, b) };
        }
        return;
    }

    #[allow(unreachable_code)]
    pmul_region_scalar(dst, a, b);
}

/// Scalar reference/fallback: one `gf::mul` per word.
fn pmul_region_scalar(dst: &mut [u8], a: &[u8], b: &[u8]) {
    for w in 0..dst.len() / 2 {
        let av = u16::from_le_bytes([a[w * 2], a[w * 2 + 1]]);
        let bv = u16::from_le_bytes([b[w * 2], b[w * 2 + 1]]);
        let bytes = gf::mul(av, bv).to_le_bytes();
        dst[w * 2] = bytes[0];
        dst[w * 2 + 1] = bytes[1];
    }
}

/// Shared NEON body (upstream `gf16pmul_neon`, gf16pmul_neon.c:13-45).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn pmul_region_neon_body<const SHA3: bool>(dst: &mut [u8], a: &[u8], b: &[u8]) {
    use crate::gf_simd::{ClmulPartials, clmul_barrett_reduce};
    use std::arch::aarch64::*;

    let len = dst.len();
    let vec_len = len & !31;

    unsafe {
        let mut offset = 0usize;
        while offset < vec_len {
            let d1 = vld2q_u8(a.as_ptr().add(offset));
            let d2 = vld2q_u8(b.as_ptr().add(offset));
            let a_lo = vreinterpretq_p8_u8(d1.0);
            let a_hi = vreinterpretq_p8_u8(d1.1);
            let b_lo = vreinterpretq_p8_u8(d2.0);
            let b_hi = vreinterpretq_p8_u8(d2.1);
            let a_mid = vreinterpretq_p8_u8(veorq_u8(d1.0, d1.1));
            let b_mid = vreinterpretq_p8_u8(veorq_u8(d2.0, d2.1));

            let partials = ClmulPartials {
                low1: vmull_p8(vget_low_p8(a_lo), vget_low_p8(b_lo)),
                low2: vmull_high_p8(a_lo, b_lo),
                mid1: vmull_p8(vget_low_p8(a_mid), vget_low_p8(b_mid)),
                mid2: vmull_high_p8(a_mid, b_mid),
                high1: vmull_p8(vget_low_p8(a_hi), vget_low_p8(b_hi)),
                high2: vmull_high_p8(a_hi, b_hi),
            };
            let r = clmul_barrett_reduce::<SHA3>(partials);

            let out = uint8x16x2_t(veorq_u8(r[0], r[1]), veorq_u8(r[2], r[3]));
            vst2q_u8(dst.as_mut_ptr().add(offset), out);

            offset += 32;
        }
    }

    if vec_len < len {
        let (da, db) = (&a[vec_len..], &b[vec_len..]);
        pmul_region_scalar(&mut dst[vec_len..], da, db);
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn pmul_region_neon(dst: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe { pmul_region_neon_body::<false>(dst, a, b) }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn pmul_region_neon_sha3(dst: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe { pmul_region_neon_body::<true>(dst, a, b) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Oracle sweep: dispatched path and (on aarch64) both direct kernel
    /// flavors against a per-word `gf::mul` reference, across block-tail
    /// straddles and operand edge patterns.
    #[test]
    fn pmul_region_matches_gf_mul() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        for &len in &[2usize, 30, 32, 34, 64, 96, 4094, 4096] {
            for pattern in 0..3 {
                let gen_byte = |state: &mut u64, i: usize| -> u8 {
                    match pattern {
                        0 => xorshift(state) as u8,
                        1 => [0x00, 0x01, 0xFF][i % 3], // 0/1/edge words
                        _ => 0xFF,                      // all-ones saturation
                    }
                };
                let a: Vec<u8> = (0..len).map(|i| gen_byte(&mut state, i)).collect();
                let b: Vec<u8> = (0..len).map(|i| gen_byte(&mut state, i + 1)).collect();

                let mut reference = vec![0u8; len];
                pmul_region_scalar(&mut reference, &a, &b);

                let mut dispatched = vec![0u8; len];
                pmul_region(&mut dispatched, &a, &b);
                assert_eq!(dispatched, reference, "dispatched len={len} pat={pattern}");

                #[cfg(target_arch = "aarch64")]
                {
                    let mut plain = vec![0u8; len];
                    unsafe { pmul_region_neon(&mut plain, &a, &b) };
                    assert_eq!(plain, reference, "neon len={len} pat={pattern}");

                    if std::arch::is_aarch64_feature_detected!("sha3") {
                        let mut sha3 = vec![0u8; len];
                        unsafe { pmul_region_neon_sha3(&mut sha3, &a, &b) };
                        assert_eq!(sha3, reference, "sha3 len={len} pat={pattern}");
                    }
                }
            }
        }
    }

    /// The identity the matrix fast-fill relies on: c^e == c * c^(e-1),
    /// element-wise across a row.
    #[test]
    fn pmul_iterated_equals_pow() {
        let constants = gf::input_slice_constants(64);
        let base: Vec<u8> = constants.iter().flat_map(|c| c.to_le_bytes()).collect();
        let mut row: Vec<u8> = constants.iter().flat_map(|_| 1u16.to_le_bytes()).collect();

        for exp in 1u32..=40 {
            let prev = row.clone();
            pmul_region(&mut row, &prev, &base);
            let expected: Vec<u8> = constants
                .iter()
                .flat_map(|&c| gf::pow(c, exp).to_le_bytes())
                .collect();
            assert_eq!(row, expected, "exp={exp}");
        }
    }
}
