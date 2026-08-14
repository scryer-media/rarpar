//! Factor-to-`vpternlogd`/`vpxord` schedule generation for the AVX-512
//! XOR-JIT tier.
//!
//! Bodies process 1024-byte blocks (16 planes of 64 bytes), fold two planes
//! per `vpternlogd imm8=0x96` instruction, and keep all 16 source planes in
//! `zmm16..31`. The packed form supports up to six source regions and shares
//! the finalized W^X arena used by single-factor bodies.
//!
//! EVEX compressed disp8 addressing covers every plane offset directly, so
//! plane `p` resides at `[ptr + p*64]` without a pointer bias.
//!
//! Register convention: `rax=src-1024, rdx=dst-1024, rcx=dst_end-1024`; each
//! iteration advances one block then addresses planes at `+p*64`. `zmm0`/
//! `zmm1` are the even/odd output accumulators, `zmm2` the shared (CSE)
//! accumulator, `zmm16+k` holds source plane `k`.

use super::deps::XorDeps;
use super::emit::{self, RAX, RCX, RDX};

/// Bytes per wide bit-planar block.
const BLOCK: i32 = 1024;

/// Keep next-block hints disabled. The controller-facing prefetch body below
/// uses a dedicated `rsi` stream instead.
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
    generate_muladd_with_prefetch(deps, false)
}

/// Generate the single-source AVX512 body, optionally adding a dedicated
/// prefetch stream. `rsi` advances by 512 bytes and receives eight T1 hints;
/// its trampoline seeds it at `prefetch - 384`.
pub fn generate_muladd_with_prefetch(deps: &XorDeps, prefetch: bool) -> Vec<u8> {
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
    if prefetch {
        emit::add_ri(&mut buf, emit::RSI, 512);
        for offset in [-128, -64, 0, 64, 128, 192, 256, 320] {
            emit::prefetcht1(&mut buf, emit::RSI, offset);
        }
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

/// Maximum number of packed source regions handled by one AVX512 body.
pub const MAX_PACKED_REGIONS: usize = 6;

/// Largest total dependency-row popcount any factor can produce, i.e. the
/// most `vpxord` instructions one source region can cost in
/// [`generate_muladd_multi`]. This is the exact maximum over the full GF(2^16)
/// factor domain (reached at factor `0x1AFF`), pinned by
/// `max_deps_popcount_is_pinned`; it is a property of the field polynomial,
/// not of any corpus.
pub const MAX_DEPS_TOTAL_POPCOUNT: usize = 188;

// Encoded instruction sizes the multi-body consists of, matching `emit`
// byte-for-byte. `multi_body_len_is_exactly_the_size_formula` locks them: if
// an emitter encoding changes, that test fails before any bound goes stale.
const EVEX_XOR_BYTES: usize = 6; // vpxord zmm,zmm,zmm
const PLANE_SET_BYTES: usize = 111; // 16 plane loads/stores: 6 + 15*7 (disp8)
const ADD_RI_BYTES: usize = 7; // add r64, imm32
const LOOP_TAIL_BYTES: usize = 10; // cmp_rr + jl_rel32 + ret

/// Exact byte length of [`generate_muladd_multi`] for the given dependency
/// list. The generator is a straight concatenation, so the length is a linear
/// function of the per-source dependency popcounts.
pub fn multi_body_len(deps: &[XorDeps]) -> usize {
    let per_source: usize = deps
        .iter()
        .map(|dep| {
            let popcount: usize = dep.rows.iter().map(|row| row.count_ones() as usize).sum();
            ADD_RI_BYTES + PLANE_SET_BYTES + EVEX_XOR_BYTES * popcount
        })
        .sum();
    ADD_RI_BYTES + PLANE_SET_BYTES + per_source + PLANE_SET_BYTES + LOOP_TAIL_BYTES
}

/// Upper bound on [`generate_muladd_multi`] output for `source_count` regions,
/// valid for every factor assignment. `239 + 1246 * source_count` today.
pub fn multi_body_bytes_upper_bound(source_count: usize) -> usize {
    let per_source_max = ADD_RI_BYTES + PLANE_SET_BYTES + EVEX_XOR_BYTES * MAX_DEPS_TOTAL_POPCOUNT;
    ADD_RI_BYTES
        + PLANE_SET_BYTES
        + PLANE_SET_BYTES
        + LOOP_TAIL_BYTES
        + source_count * per_source_max
}

#[inline]
fn source_base(index: usize) -> u8 {
    match index {
        0 => emit::RDX,
        1 => emit::RSI,
        2 => emit::RDI,
        3 => emit::R8,
        4 => emit::R9,
        5 => emit::R10,
        _ => unreachable!("packed AVX512 source register"),
    }
}

/// Generate the AVX512 backend's packed multi-source body. Destination planes
/// stay in `zmm0..15`; each source is loaded into `zmm16..31` and its
/// coefficient dependency rows are XORed into the destination before the
/// next source is loaded. The trampoline supplies source bases in the order
/// defined by [`source_base`].
pub fn generate_muladd_multi(deps: &[XorDeps]) -> Vec<u8> {
    assert!(!deps.is_empty() && deps.len() <= MAX_PACKED_REGIONS);
    let mut buf = Vec::with_capacity(4096);

    emit::add_ri(&mut buf, emit::RAX, BLOCK);
    for index in 0..deps.len() {
        emit::add_ri(&mut buf, source_base(index), BLOCK);
    }

    for plane in 0..16usize {
        emit::vmovdqu32_load(&mut buf, plane as u8, emit::RAX, plane_off(plane));
    }

    for (source, dep) in deps.iter().enumerate() {
        let base = source_base(source);
        for plane in 0..16usize {
            emit::vmovdqu32_load(&mut buf, src_reg(plane), base, plane_off(plane));
        }
        for (output, &row) in dep.rows.iter().enumerate() {
            let mut mask = row;
            while mask != 0 {
                let plane = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                emit::vpxord_rrr(&mut buf, output as u8, output as u8, src_reg(plane));
            }
        }
    }

    for plane in 0..16usize {
        emit::vmovdqu32_store(&mut buf, emit::RAX, plane_off(plane), plane as u8);
    }
    emit::cmp_rr(&mut buf, emit::RAX, emit::RCX);
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

    /// The size formula must match the generator byte-for-byte: any emitter
    /// encoding change that would silently invalidate
    /// [`multi_body_bytes_upper_bound`] fails here first. Covers every prefix
    /// length, dense and sparse factors, zero factors, and the popcount-worst
    /// factor 0x1AFF.
    #[test]
    fn multi_body_len_is_exactly_the_size_formula() {
        let pools: [&[u16]; 4] = [
            &[0x1AFF, 0x1AFF, 0x1AFF, 0x1AFF, 0x1AFF, 0x1AFF],
            &[1, 2, 3, 0x8000, 0xFFFF, 0x2F1D],
            &[0, 1, 0, 0xABCD, 0, 0x0101],
            &[0x1234, 0, 0x1AFF, 0x4000, 0xBEEF, 7],
        ];
        for pool in pools {
            for count in 1..=pool.len() {
                let deps = pool[..count]
                    .iter()
                    .copied()
                    .map(compute_deps)
                    .collect::<Vec<_>>();
                let code = generate_muladd_multi(&deps);
                assert_eq!(
                    code.len(),
                    multi_body_len(&deps),
                    "prefix {count} of {pool:04X?}"
                );
                assert!(code.len() <= multi_body_bytes_upper_bound(count));
            }
        }
    }

    /// [`MAX_DEPS_TOTAL_POPCOUNT`] is the exact maximum over the whole factor
    /// domain. Exhaustive and hardware-free; if the field polynomial or dep
    /// computation ever changes, this reports the new maximum to re-pin.
    #[test]
    fn max_deps_popcount_is_pinned() {
        let (max, argmax) = (1..=u16::MAX)
            .map(|factor| {
                let deps = compute_deps(factor);
                let popcount: usize = deps.rows.iter().map(|row| row.count_ones() as usize).sum();
                (popcount, factor)
            })
            .max()
            .unwrap();
        assert_eq!(
            max, MAX_DEPS_TOTAL_POPCOUNT,
            "true max popcount is {max} at factor {argmax:#06x}; re-pin MAX_DEPS_TOTAL_POPCOUNT"
        );
    }

    /// Every single-source multi body honors the per-source bound — the
    /// exhaustive anchor [`multi_body_bytes_upper_bound`] rests on, given the
    /// exact-formula lock above (lengths compose additively per source).
    #[test]
    fn multi_body_single_source_bound_holds_for_all_factors() {
        for factor in 1..=u16::MAX {
            let deps = [compute_deps(factor)];
            assert!(
                multi_body_len(&deps) <= multi_body_bytes_upper_bound(1),
                "factor {factor:#06x}"
            );
        }
    }

    #[test]
    fn packed_multi_shape_has_one_return_and_supports_all_prefixes() {
        let factors = [1u16, 2, 3, 0, 0x8000, 0xFFFF];
        for count in 1..=factors.len() {
            let deps = factors[..count]
                .iter()
                .copied()
                .map(compute_deps)
                .collect::<Vec<_>>();
            let code = generate_muladd_multi(&deps);
            assert_eq!(code.last(), Some(&0xC3));
            assert!(code.len() < 16 * 1024);
        }
    }

    #[test]
    fn dedicated_prefetch_stream_adds_the_reference_hint_sequence() {
        let deps = compute_deps(0x2F1D);
        let code = generate_muladd_with_prefetch(&deps, true);
        assert!(
            code.windows(2)
                .filter(|window| *window == [0x0F, 0x18])
                .count()
                >= 8
        );
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
    /// reference byte-for-byte over a multi-block region, including accumulation.
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
