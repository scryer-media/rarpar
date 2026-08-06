//! Factor -> `vpxor` schedule codegen for the XOR-JIT tier.
//!
//! Generates a straight-line, fully-unrolled block loop that computes
//! `dst ^= factor · src` in bit-plane layout. The body follows ParPar's
//! register convention (`rax=src-384, rdx=dst-384, rcx=dst_end-384`); each
//! iteration advances one 512-byte block, holds source planes 3-15 resident in
//! `ymm3..15` (planes 0-2 stay in memory at `[rax-128/-96/-64]`), and for each
//! output plane XORs in the source planes named by its deps row.
//!
//! Output planes are processed in pairs with common-subexpression sharing:
//! the source planes both rows of a pair need are XORed once into a shared
//! accumulator (`ymm2`) and folded into each output, so a plane common to the
//! pair costs one `vpxor` instead of two. The pairing, register roles, and
//! dst-load fusion (each output's dst load rides as the memory operand of its
//! first `vpxor` instead of a separate `vmovdqu`) are ParPar's; the CSE
//! EXTENT deliberately is not — ParPar shares only the lowest and highest
//! common bits of a pair (`common_elim`, gf16_xor_avx2.c:213-228, a limit of
//! its SIMD-generated writer) while this scheduler shares ALL common bits.
//! Net: mean ~104 vpxor/block here vs ~121 modeled for upstream's schedule
//! (mean deps set-bits 128); dst-load fusion eliminates essentially all 16
//! separate dst loads per block (mean total ~146 instructions vs ~162
//! unfused — only an output whose planes all sit in memory keeps its load).

use super::deps::XorDeps;
use super::emit::{self, RAX, RCX, RDX};

/// Bytes per bit-planar block.
const BLOCK: i32 = 512;

/// Keep the old next-block hints disabled. Turbo's controller-facing prefetch
/// body is emitted by `generate_muladd_prefetch` below and uses its dedicated
/// `rsi` stream instead of guessing from the source and destination pointers.
const JIT_NEXT_BLOCK_PREFETCH: bool = false;

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
    generate_muladd_mode(deps, PrefetchMode::None)
}

#[derive(Clone, Copy)]
enum PrefetchMode {
    None,
    Always,
    Optional,
}

/// Generate the Turbo-style body with an optional dedicated prefetch stream.
/// When enabled, `rsi` advances by 256 bytes per 512-byte block and issues the
/// four T1 hints used by `xor_write_jit_avx` (Turbo's
/// `gf16_xor_avx2.c:262-267`). The call trampoline initializes `rsi` to
/// `prefetch - 128`, matching `gf16_xor_jit_mul_avx2_base` at lines 403-408.
pub fn generate_muladd_with_prefetch(deps: &XorDeps, prefetch: bool) -> Vec<u8> {
    generate_muladd_mode(
        deps,
        if prefetch {
            PrefetchMode::Always
        } else {
            PrefetchMode::None
        },
    )
}

/// Generate one immutable packed body that accepts both trampoline shapes.
/// `rsi = 0` skips the dedicated prefetch stream; otherwise `rsi` follows the
/// same `prefetch - 128` convention as [`generate_muladd_with_prefetch`].
pub(crate) fn generate_muladd_optional_prefetch(deps: &XorDeps) -> Vec<u8> {
    generate_muladd_mode(deps, PrefetchMode::Optional)
}

fn generate_muladd_mode(deps: &XorDeps, prefetch: PrefetchMode) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1280);

    // Loop top: advance to this block, (re)load the resident source planes.
    emit::add_ri(&mut buf, RAX, BLOCK);
    emit::add_ri(&mut buf, RDX, BLOCK);
    if JIT_NEXT_BLOCK_PREFETCH {
        // First line of the next block on each stream (pointers sit at
        // block_start+128, so the next block's first byte is at +384).
        emit::prefetcht1(&mut buf, RAX, BLOCK - 128);
        emit::prefetcht1(&mut buf, RDX, BLOCK - 128);
    }
    let skip_prefetch = matches!(prefetch, PrefetchMode::Optional).then(|| {
        emit::test_rr(&mut buf, emit::RSI, emit::RSI);
        let jump_start = buf.len();
        emit::jz_rel32(&mut buf, 0);
        jump_start
    });
    if !matches!(prefetch, PrefetchMode::None) {
        emit::add_ri(&mut buf, emit::RSI, 256);
        for offset in [-128, -64, 0, 64] {
            emit::prefetcht1(&mut buf, emit::RSI, offset);
        }
    }
    if let Some(jump_start) = skip_prefetch {
        let jump_end = jump_start + 6;
        let relative = i32::try_from(buf.len() - jump_end).expect("prefetch block fits rel32");
        buf[jump_start + 2..jump_end].copy_from_slice(&relative.to_le_bytes());
    }
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
        // The dst load is fused into the output's first XOR (ParPar's trick):
        // `vpxor acc, reg, [rdx+off]` seeds acc with reg ^ dst in one
        // instruction, where reg is a resident own plane (3-15) or, failing
        // that, the shared accumulator ymm2. XOR commutes, so hoisting that
        // operand first leaves the result unchanged.
        for (acc, out) in [(0u8, oe), (1u8, oo)] {
            if deps.rows[out] == 0 {
                continue; // unchanged
            }
            let mut m = only[acc as usize];
            let mut fold_shared = common != 0;
            let resident = m & !0b111;
            if resident != 0 {
                let k = resident.trailing_zeros() as usize;
                m &= !(1 << k);
                emit::vpxor_rrm(&mut buf, acc, k as u8, RDX, plane_off(out));
            } else if fold_shared {
                fold_shared = false;
                emit::vpxor_rrm(&mut buf, acc, 2, RDX, plane_off(out));
            } else {
                // Own planes all live in memory (0-2) and nothing is shared:
                // a vpxor cannot take two memory operands, so keep the load.
                emit::vmovdqu_load(&mut buf, acc, RDX, plane_off(out));
            }
            while m != 0 {
                let k = m.trailing_zeros() as usize;
                m &= m - 1;
                xor_plane(&mut buf, acc, k);
            }
            if fold_shared {
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

    /// Structural invariants that need no AVX2 hardware, swept over the full
    /// factor domain: single trailing `ret`, length within the JIT buffer
    /// budget. Execution semantics are validated on real AVX2 hardware by
    /// `jit_muladd_matches_planar` below.
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

    #[test]
    fn optional_prefetch_body_supports_both_trampolines() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        let len = 3 * 512;
        let factor = 0xA53Cu16;
        let src = sample(0x5151, len);
        let deps = compute_deps(factor);
        let initial = sample(0x6262, len);
        let mut expected = initial.clone();
        muladd_planar(&deps, &src, &mut expected);

        let code = generate_muladd_optional_prefetch(&deps);
        let jit = JitCode::new(&code).expect("jit alloc");

        let mut without_prefetch = initial.clone();
        unsafe { jit.run_muladd(src.as_ptr(), without_prefetch.as_mut_ptr(), len) };
        assert_eq!(without_prefetch, expected);

        let prefetch = vec![0u8; len / 2];
        let mut with_prefetch = initial;
        unsafe {
            jit.run_muladd_prefetch(
                src.as_ptr(),
                with_prefetch.as_mut_ptr(),
                len,
                prefetch.as_ptr(),
            )
        };
        assert_eq!(with_prefetch, expected);
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
