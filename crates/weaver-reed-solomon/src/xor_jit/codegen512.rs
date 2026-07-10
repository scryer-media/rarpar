//! Factor -> `vpternlogd`/`vpxord` schedule codegen for the AVX512 XOR-JIT
//! tier — the zmm widening of [`super::codegen`], porting the instruction
//! selection of ParPar's `gf16_xor_avx512.c` JIT.
//!
//! What carries over from upstream: 1024-byte blocks (16 planes × 64 B),
//! `vpternlogd imm8=0x96` folding TWO planes per instruction (halving the XOR
//! count vs the AVX2 tier), and exploiting the 32 zmm registers to keep a full
//! 16-plane set resident. Register-allocation nuance: upstream parks the 16
//! DST planes in `zmm16..31` (`xor_write_init_jit`, gf16_xor_avx512.c:17-26);
//! this port parks the 16 SRC planes there instead, mirroring the proven AVX2
//! codegen structure (`super::codegen`) — either allocation captures the
//! residency win, and this one lets the AVX2 CSE pair scheme carry over
//! unchanged (AVX2 can only keep 13 source planes resident).
//!
//! Deliberate deviations, documented once here:
//! - Upstream's JIT writer builds its instruction bytes with SIMD because it
//!   re-JITs per coefficient on every call; rarpar pre-JITs one body per
//!   factor and memoizes ([`crate::xor_jit::memory`]), so writer speed is
//!   irrelevant and the byte-formula emitter style of `emit.rs` is kept.
//! - Upstream's multi-region variant (one body over several sources,
//!   `gf16_xor_avx512.c:815`) is not ported: par2cmdline-turbo's SLIM build
//!   never selects the AVX512 JIT at all, and rarpar's streaming tier is
//!   per-source; the instruction-density win is captured without it.
//! - No `-384` pointer bias: EVEX compressed disp8 (×64) covers every plane
//!   offset directly (see `emit.rs`), so plane `p` sits at `[ptr + p*64]`.
//!
//! Register convention: `rax=src-1024, rdx=dst-1024, rcx=dst_end-1024`; each
//! iteration advances one block then addresses planes at `+p*64`. `zmm0`/
//! `zmm1` are the even/odd output accumulators, `zmm2` the shared (CSE)
//! accumulator, `zmm16+k` holds source plane `k`.

use super::deps::XorDeps;
use super::emit::{self, RAX, RCX, RDX};

/// Bytes per wide bit-planar block.
const BLOCK: i32 = 1024;

/// `prefetcht1` for the next block's src/dst first lines — the zmm twin of
/// `super::codegen::JIT_NEXT_BLOCK_PREFETCH`; same UNMEASURED/off-by-default
/// status and A/B protocol.
const JIT_NEXT_BLOCK_PREFETCH: bool = false;

/// Byte offset of plane `p` from the (advanced) block pointer.
#[inline]
fn plane_off(p: usize) -> i32 {
    (p as i32) * 64
}

/// zmm register holding source plane `k`.
#[inline]
fn src_reg(k: usize) -> u8 {
    16 + k as u8
}

/// Fold the planes of `mask` into `acc` two at a time via `vpternlogd 0x96`
/// (acc ^= a ^ b). An odd trailing plane is NOT emitted — it is returned so
/// the caller can pair it with whatever else it still has to fold (the shared
/// accumulator, when there is one) instead of spending a lone `vpxord`.
#[must_use]
fn fold_pairs(buf: &mut Vec<u8>, acc: u8, mut mask: u16) -> Option<usize> {
    while mask != 0 {
        let k1 = mask.trailing_zeros() as usize;
        mask &= mask - 1;
        if mask == 0 {
            return Some(k1);
        }
        let k2 = mask.trailing_zeros() as usize;
        mask &= mask - 1;
        emit::vpternlogd_xor3(buf, acc, src_reg(k1), src_reg(k2));
    }
    None
}

/// Generate the muladd loop body for `deps` (AVX512 flavor).
pub fn generate_muladd(deps: &XorDeps) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    // Loop top: advance to this block, load all 16 source planes.
    emit::add_ri(&mut buf, RAX, BLOCK);
    emit::add_ri(&mut buf, RDX, BLOCK);
    if JIT_NEXT_BLOCK_PREFETCH {
        // First line of the next block on each stream (bias 0: next block
        // starts exactly one BLOCK ahead).
        emit::prefetcht1(&mut buf, RAX, BLOCK);
        emit::prefetcht1(&mut buf, RDX, BLOCK);
    }
    for k in 0..16usize {
        emit::vmovdqu32_load(&mut buf, src_reg(k), RAX, plane_off(k));
    }

    // Output planes in pairs with the AVX2 codegen's CSE scheme: planes both
    // rows need are folded once into zmm2 and XORed into each output. When an
    // output's own-plane count is odd, the leftover plane and zmm2 fold in a
    // single `vpternlogd` instead of two `vpxord`s.
    for b in 0..8usize {
        let (oe, oo) = (2 * b, 2 * b + 1);
        let common = deps.rows[oe] & deps.rows[oo];
        let only = [deps.rows[oe] & !common, deps.rows[oo] & !common];

        if common != 0 {
            let first = common.trailing_zeros() as usize;
            emit::vmovdqa32_rr(&mut buf, 2, src_reg(first));
            if let Some(k) = fold_pairs(&mut buf, 2, common & (common - 1)) {
                emit::vpxord_rrr(&mut buf, 2, 2, src_reg(k));
            }
        }

        for (acc, out) in [(0u8, oe), (1u8, oo)] {
            if deps.rows[out] == 0 {
                continue; // unchanged
            }
            emit::vmovdqu32_load(&mut buf, acc, RDX, plane_off(out));
            let leftover = fold_pairs(&mut buf, acc, only[acc as usize]);
            match (leftover, common != 0) {
                // Odd own plane + shared accumulator: one ternlog folds both
                // (acc ^= plane ^ shared), saving the separate `vpxord`s.
                (Some(k), true) => emit::vpternlogd_xor3(&mut buf, acc, src_reg(k), 2),
                (Some(k), false) => emit::vpxord_rrr(&mut buf, acc, acc, src_reg(k)),
                (None, true) => emit::vpxord_rrr(&mut buf, acc, acc, 2), // ^= shared
                (None, false) => {}
            }
            emit::vmovdqu32_store(&mut buf, RDX, plane_off(out), acc);
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
    use super::super::deps::{compute_deps, muladd_planar_sized};
    use super::super::memory::JitCode;
    use super::super::transpose512::{BLOCK_BYTES, PLANE_BYTES};
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

    /// Structural invariants that need no AVX512 hardware: code is non-empty,
    /// single-`ret`-terminated, and its length stays within the JIT buffer
    /// budget for every factor.
    #[test]
    fn generated_code_shape() {
        for factor in [1u16, 2, 0x8000, 0xABCD, 0xFFFF, 0x2F1D, 0x0101] {
            let code = generate_muladd(&compute_deps(factor));
            assert_eq!(*code.last().unwrap(), 0xC3, "must end in ret");
            assert!(
                code.len() < 4096,
                "factor {factor:#06x}: {} bytes",
                code.len()
            );
        }
    }

    /// [`generated_code_shape`] swept over the full factor domain — cheap and
    /// hardware-free. Execution semantics are validated on real AVX512
    /// hardware by `jit512_muladd_matches_planar`.
    #[test]
    fn generated_code_shape_all_factors() {
        for factor in 1..=u16::MAX {
            let code = generate_muladd(&compute_deps(factor));
            assert_eq!(
                *code.last().unwrap(),
                0xC3,
                "factor {factor:#06x}: must end in ret"
            );
            assert!(
                code.len() < 4096,
                "factor {factor:#06x}: {} bytes",
                code.len()
            );
        }
    }

    /// On real AVX512 hardware: the JIT'd body must reproduce the wide planar
    /// oracle byte-for-byte over a multi-block region, including accumulation.
    /// (No-ops elsewhere — including under Rosetta 2, which lacks AVX512.)
    #[test]
    fn jit512_muladd_matches_planar() {
        if !is_x86_feature_detected!("avx512bw") || !is_x86_feature_detected!("avx512vl") {
            return;
        }
        let len = 3 * BLOCK_BYTES;
        for factor in [
            1u16, 2, 3, 0x8000, 0xABCD, 0xFFFF, 0x1234, 0x0101, 0x2F1D, 0x4000,
        ] {
            let src = sample(factor as u64 * 0x9E37_79B9, len);
            let deps = compute_deps(factor);

            let mut expected = sample(0x5150, len);
            let mut got = expected.clone();
            muladd_planar_sized(&deps, &src, &mut expected, BLOCK_BYTES, PLANE_BYTES);

            let code = generate_muladd(&deps);
            let jit = JitCode::new(&code).expect("jit alloc");
            unsafe { jit.run_muladd_512(src.as_ptr(), got.as_mut_ptr(), len) };

            assert_eq!(got, expected, "factor {factor:#06x}");
        }
    }
}
