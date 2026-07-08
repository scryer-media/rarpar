//! Factor -> `vpxor` schedule codegen for the XOR-JIT tier
//! (see `scryer-docs/plans/125`).
//!
//! Generates a straight-line, fully-unrolled block loop that computes
//! `dst ^= factor · src` in bit-plane layout. The body follows ParPar's
//! register convention (`rax=src-384, rdx=dst-384, rcx=dst_end-384`); each
//! iteration advances one 512-byte block, holds source planes 3-15 resident in
//! `ymm3..15` (planes 0-2 stay in memory at `[rax-128/-96/-64]`), and for each
//! output plane XORs in the source planes named by its deps row.
//!
//! Output planes are processed in pairs with ParPar's common-subexpression
//! sharing: the source planes both rows of a pair need are XORed once into a
//! shared accumulator (`ymm2`) and folded into each output, so a plane common
//! to the pair costs one `vpxor` instead of two (~128 -> ~115 vpxor/block).

use super::deps::XorDeps;
use super::emit::{self, RAX, RCX, RDX};

/// Bytes per bit-planar block.
const BLOCK: i32 = 512;

/// Signed byte offset of plane `p` from the mid-block pointer (after the
/// `+512` advance, `rax`/`rdx` sit 128 bytes into the block).
#[inline]
fn plane_off(p: usize) -> i32 {
    (p as i32 - 4) * 32
}

/// Generate the muladd loop body for `deps`. `ymm0`/`ymm1` are the even/odd
/// output accumulators, `ymm2` the shared (CSE) accumulator; source planes 3-15
/// live in `ymm3..15`, planes 0-2 in memory.
pub fn generate_muladd(deps: &XorDeps) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1280);

    // Loop top: advance to this block, (re)load the resident source planes.
    emit::add_ri(&mut buf, RAX, BLOCK);
    emit::add_ri(&mut buf, RDX, BLOCK);
    for p in 3..16usize {
        emit::vmovdqu_load(&mut buf, p as u8, RAX, plane_off(p));
    }

    // `acc ^= source_plane[k]` (resident reg 3-15, or memory plane 0-2).
    let xor_plane = |buf: &mut Vec<u8>, acc: u8, k: usize| {
        if k >= 3 {
            emit::vpxor_rrr(buf, acc, acc, k as u8);
        } else {
            emit::vpxor_rrm(buf, acc, acc, RAX, plane_off(k));
        }
    };

    // Process output planes in pairs (2b, 2b+1). Planes both rows need are
    // XORed once into the shared accumulator ymm2 (CSE), then folded into each
    // output — halving the work on the planes the pair has in common.
    for b in 0..8usize {
        let (oe, oo) = (2 * b, 2 * b + 1);
        let common = deps.rows[oe] & deps.rows[oo];
        let only = [deps.rows[oe] & !common, deps.rows[oo] & !common];

        if common != 0 {
            // Seed ymm2 from the lowest shared plane, XOR in the rest.
            let first = common.trailing_zeros() as usize;
            if first >= 3 {
                emit::vmovdqa_rr(&mut buf, 2, first as u8);
            } else {
                emit::vmovdqu_load(&mut buf, 2, RAX, plane_off(first));
            }
            let mut rest = common & (common - 1);
            while rest != 0 {
                let k = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                xor_plane(&mut buf, 2, k);
            }
        }

        // Even output -> ymm0, odd output -> ymm1: dst ^ own planes ^ shared.
        for (acc, out) in [(0u8, oe), (1u8, oo)] {
            if deps.rows[out] == 0 {
                continue; // unchanged
            }
            emit::vmovdqu_load(&mut buf, acc, RDX, plane_off(out));
            let mut m = only[acc as usize];
            while m != 0 {
                let k = m.trailing_zeros() as usize;
                m &= m - 1;
                xor_plane(&mut buf, acc, k);
            }
            if common != 0 {
                emit::vpxor_rrr(&mut buf, acc, acc, 2); // ^= shared
            }
            emit::vmovdqu_store(&mut buf, RDX, plane_off(out), acc);
        }
    }

    // Back-edge: loop while rdx < rcx (dst_end), then return.
    emit::cmp_rr(&mut buf, RDX, RCX);
    emit::jl_to(&mut buf, 0);
    emit::ret(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::super::deps::{compute_deps, muladd_planar};
    use super::super::memory::JitCode;
    use super::*;

    fn sample(seed: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        let mut s = seed | 1;
        for byte in v.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *byte = (s >> 24) as u8;
        }
        v
    }

    /// The JIT'd muladd must reproduce the scalar `muladd_planar` XOR schedule
    /// byte-for-byte, over a multi-block region, on real AVX2. `muladd_planar`
    /// is separately proven to equal the GF multiply, so this closes the chain.
    #[test]
    fn jit_muladd_matches_planar() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        let blocks = 3usize;
        let len = blocks * 512;
        for factor in [
            1u16, 2, 3, 0x8000, 0xABCD, 0xFFFF, 0x1234, 0x0101, 0x2F1D, 0x4000,
        ] {
            // Arbitrary planar bytes: both paths apply the same XOR schedule,
            // so equality isolates the codegen (GF semantics covered by deps).
            let src = sample(factor as u64 * 0x9E3779B9, len);
            let deps = compute_deps(factor);

            let mut expected = vec![0u8; len];
            muladd_planar(&deps, &src, &mut expected);

            let code = generate_muladd(&deps);
            let jit = JitCode::new(&code).expect("jit alloc");
            let mut got = vec![0u8; len];
            unsafe { jit.run_muladd(src.as_ptr(), got.as_mut_ptr(), len) };

            assert_eq!(got, expected, "factor {factor:#06x}");
        }
    }

    /// A non-zeroed destination must accumulate (muladd, not overwrite).
    #[test]
    fn jit_muladd_accumulates_into_dst() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        let len = 512;
        let factor = 0xBEEFu16;
        let src = sample(0x1111, len);
        let deps = compute_deps(factor);

        let mut expected = sample(0x2222, len);
        muladd_planar(&deps, &src, &mut expected);

        let code = generate_muladd(&deps);
        let jit = JitCode::new(&code).expect("jit alloc");
        let mut got = sample(0x2222, len);
        unsafe { jit.run_muladd(src.as_ptr(), got.as_mut_ptr(), len) };

        assert_eq!(got, expected);
    }
}
