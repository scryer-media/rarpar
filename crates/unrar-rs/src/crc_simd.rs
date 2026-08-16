//! SIMD CRC-32/ISO-HDLC tiers that fill the gaps `crc-fast` leaves.
//!
//! [`crate::crc`] delegates the bulk member-data checksum to `crc-fast`, whose
//! runtime dispatch is the right choice almost everywhere. It has one hole on
//! x86-64, and this module fills exactly that hole and nothing else.
//!
//! # The hole
//!
//! `crc-fast` 1.10's own feature detection reads (`src/feature_detection.rs`):
//!
//! ```text
//! let has_avx512vl   = has_pclmulqdq && is_x86_feature_detected!("avx512vl");
//! let has_vpclmulqdq = has_avx512vl  && is_x86_feature_detected!("vpclmulqdq");
//! ```
//!
//! Its 512-bit VPCLMULQDQ tier is therefore conditioned on AVX-512VL, not on
//! VPCLMULQDQ. A CPU that has VPCLMULQDQ but no AVX-512VL — every Intel client
//! part from Alder Lake through Arrow Lake, which is the bulk of consumer
//! silicon — does not merely lose the 512-bit tier: it falls all the way past
//! the AVX-512 tier to `X86_64SsePclmulqdq`, a 128-bit SSE fold. That is the
//! measured 1.51x gap this module closes with a 256-bit YMM fold.
//!
//! # Tier policy
//!
//! * **VPCLMULQDQ and no AVX-512VL** — this module's kernel runs. It is the
//!   only configuration where it runs by default.
//! * **VPCLMULQDQ and AVX-512VL** (Zen 4/5, Sapphire Rapids, Ice Lake server)
//!   — stand aside. `crc-fast` selects its 4x512-bit ZMM fold there, which
//!   processes 256 B/iteration with ternary-logic XOR3 and beats this 2x256-bit
//!   port. Engaging here would be a regression, so the default gate excludes it.
//! * **No VPCLMULQDQ**, and every non-x86-64 target — stand aside. `crc-fast`
//!   is already on the best kernel it has (SSE fold on older x86-64, PMULL or
//!   PMULL+SHA3 on aarch64, slice-by-16 elsewhere including wasm).
//!
//! The stand-aside cases cost one predictable branch per `update` call, on a
//! call that processes kilobytes. On targets with no tier at all, [`available`]
//! is a compile-time `false` and the branch disappears entirely.
//!
//! # Why there is no wasm tier here
//!
//! WebAssembly's `simd128` (and `relaxed-simd`) proposals expose no carry-less
//! multiply — there is no `clmul` equivalent of `PCLMULQDQ`/`PMULL`. A CRC fold
//! *is* carry-less multiplication by fixed constants, so the fold structure
//! below has no wasm translation at all.
//!
//! The only route would be to emulate a 64x64 carry-less multiply out of
//! `i32x4_mul` plus masking, at tens of instructions per 16-byte block. It
//! would be competing against `crc-fast`'s wasm fallback, which is not a naive
//! loop but `[[u32; 256]; 16]` slice-by-16 — about one table lookup and one XOR
//! per byte. Measured under wasmtime 47, that fallback runs at 3.70 GB/s
//! (`+simd128` changes it by 1-2%, which is the direct confirmation that
//! `crc-fast` has no wasm SIMD kernel to begin with). An emulation costing
//! 2.5-5 instructions per byte cannot reach a table lookup costing ~2. The
//! wasm lanes therefore stay on `crc-fast` deliberately, not by omission.
//!
//! # Provenance
//!
//! The fold constants and the fold/partial-fold/Barrett-reduce structure are
//! the classic zlib-ng 256-bit CRC folding formulation (itself derived from the
//! Intel "Fast CRC Computation Using PCLMULQDQ" white paper), reached here by
//! way of the same port that backs the yEnc CRC path in the sibling `weaver`
//! tree. Verbatim ports of published fold constants; the surrounding dispatch,
//! streaming state, and test matrix are this tree's own.

/// Smallest `update` the accelerated tier is entered for.
///
/// Below this the fixed cost of leaving and re-entering the `crc-fast` digest
/// (see [`crate::crc::Crc32`]) outweighs the fold's throughput advantage, and
/// `crc-fast`'s SSE tier is already good at short buffers. The kernel itself is
/// correct at every length from 0 up — the threshold is purely an economic
/// gate, and the test matrix drives the kernel directly at all lengths so the
/// short-length paths stay covered.
pub(crate) const MIN_UPDATE: usize = 256;

/// Whether an accelerated CRC tier is active for this build on this host.
///
/// Resolved once and cached. On targets with no tier this is a compile-time
/// `false`, so the dispatch in [`crate::crc::Crc32::update`] folds away.
#[inline]
pub(crate) fn available() -> bool {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    {
        x86_vpclmul::available()
    }
    #[cfg(not(all(target_arch = "x86_64", not(miri))))]
    {
        false
    }
}

/// Resume a CRC-32/ISO-HDLC over `data` from `initial`.
///
/// Both `initial` and the return value are in the **finalized (post-xor)**
/// domain — the domain of [`crc_fast::Digest::finalize`] and
/// [`crc_fast::crc32_iso_hdlc`] — so a carried value can be handed back and
/// forth with `crc-fast` without any domain conversion.
///
/// # Panics
///
/// Never. Calling this when [`available`] is `false` is a logic error, not
/// undefined behaviour: it debug-asserts and falls back to `crc-fast`.
#[inline]
pub(crate) fn update(initial: u32, data: &[u8]) -> u32 {
    debug_assert!(
        available(),
        "accelerated CRC tier entered while unavailable"
    );

    #[cfg(all(target_arch = "x86_64", not(miri)))]
    if x86_vpclmul::available() {
        // SAFETY: `available()` proved avx2 + pclmulqdq + sse4.1 + vpclmulqdq
        // are present on this CPU, which is exactly the target-feature set the
        // kernel is declared with.
        return unsafe { x86_vpclmul::update(initial, data) };
    }

    crc32_resume_reference(initial, data)
}

/// Seeded `crc-fast` resume, in the same finalized domain as [`update`].
///
/// This is the fallback for the unreachable "entered without a tier" case and
/// the oracle the tier is pinned against in tests.
#[inline]
pub(crate) fn crc32_resume_reference(initial: u32, data: &[u8]) -> u32 {
    let mut hasher = crc_fast::Digest::new_with_init_state(
        crc_fast::CrcAlgorithm::Crc32IsoHdlc,
        u64::from(!initial),
    );
    hasher.update(data);
    hasher.finalize() as u32
}

// ===========================================================================
// x86-64: 2x256-bit VPCLMULQDQ fold.
//
// The kernel below is duplicated verbatim into `par2-rs`'s `src/crc_simd.rs`.
// Both crates are published separately and CI enumerates the publishable crates
// by name, so a shared internal crate is not available to hold it once; the two
// copies are held byte-identical instead, by
// `shared_kernel_region_matches_the_par2_copy` in this module's tests. Edit one
// copy and that test fails until the other matches.
//
// Only the region between the two markers is compared, so the prose outside
// them (including this paragraph, which names the *other* crate) is free to
// differ. Nothing inside the markers may name either crate.
// ===========================================================================

// SHARED-KERNEL-BEGIN
#[cfg(all(target_arch = "x86_64", not(miri)))]
pub(crate) mod x86_vpclmul {
    // The kernel is a dense block of intrinsics whose whole body is one
    // contiguous unsafe region under a single precondition (the target features
    // proved by `available`). Per-intrinsic `unsafe` blocks would add hundreds
    // of tokens without adding a single distinct safety obligation, so the
    // module opts out of the per-operation requirement and documents the one
    // obligation at each `#[target_feature]` entry point instead. Same
    // convention as `reedsolomon-rs`'s `xor_jit` modules.
    #![allow(unsafe_op_in_unsafe_fn)]

    use std::arch::x86_64::*;
    use std::sync::OnceLock;

    /// Override knob for the tier gate, read once.
    ///
    /// * unset — the tier policy in the module docs (VPCLMULQDQ, no AVX-512VL).
    /// * `0` — never engage; pins `crc-fast` so the two can be A/B'd on the
    ///   same binary without a rebuild.
    /// * `1` — engage wherever the *instructions* exist, including alongside
    ///   AVX-512VL. This is the forced-tier A/B hook: it lets an AVX-512 host
    ///   (Zen 4/5, Sapphire Rapids) measure this kernel against `crc-fast`'s
    ///   ZMM tier, and lets any VPCLMULQDQ host run the differential suite
    ///   against the kernel it would not otherwise select.
    ///
    /// The ISA probe is never bypassed, in either direction. Forcing the tier
    /// onto a CPU that lacks VPCLMULQDQ would execute an undefined opcode, so
    /// `1` widens the *policy* and leaves the *capability* check intact. Same
    /// `OnceLock` + `WEAVER_*` escape-hatch shape as `WEAVER_GF16_CLMUL_BATCH`
    /// and `WEAVER_GF16_FOLDED_AVX512` in `reedsolomon-rs`.
    const FORCE_ENV: &str = "WEAVER_CRC32_VPCLMUL";

    pub(crate) fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            let forced = std::env::var_os(FORCE_ENV);
            if forced.as_deref().is_some_and(|value| value == "0") {
                return false;
            }

            // Capability floor. Never widened by the override: these are the
            // instructions the kernel actually issues.
            let capable = is_x86_feature_detected!("avx2")
                && is_x86_feature_detected!("pclmulqdq")
                && is_x86_feature_detected!("sse4.1")
                && is_x86_feature_detected!("vpclmulqdq");
            if !capable {
                return false;
            }

            if forced.as_deref().is_some_and(|value| value == "1") {
                return true;
            }

            // Default policy: only the gap. With AVX-512VL present `crc-fast`
            // runs its wider ZMM fold, which is the faster kernel.
            !is_x86_feature_detected!("avx512vl")
        })
    }

    /// Fold `data` into `initial` (finalized domain in, finalized domain out).
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2, PCLMULQDQ, SSE4.1 and VPCLMULQDQ. [`available`]
    /// establishes exactly that.
    #[target_feature(enable = "avx2,pclmulqdq,sse4.1,vpclmulqdq")]
    pub(crate) unsafe fn update(initial: u32, data: &[u8]) -> u32 {
        crc_fold_256(initial, data)
    }

    #[inline(always)]
    unsafe fn loadu256(data: &[u8]) -> __m256i {
        debug_assert!(data.len() >= 32);
        _mm256_loadu_si256(data.as_ptr() as *const __m256i)
    }

    /// Load a sub-32-byte tail through a zeroed stack buffer.
    ///
    /// Reading 32 bytes directly could cross into an unmapped page past the end
    /// of the caller's slice, so the tail is copied rather than over-read. The
    /// zero fill is not cosmetic: `partial_fold` folds the whole register and
    /// relies on the bytes beyond `len` being zero.
    #[inline(always)]
    unsafe fn load_partial256(data: &[u8]) -> __m256i {
        debug_assert!(data.len() < 32);
        let mut tmp = [0u8; 32];
        tmp[..data.len()].copy_from_slice(data);
        _mm256_loadu_si256(tmp.as_ptr() as *const __m256i)
    }

    #[inline(always)]
    unsafe fn zext128_256(value: __m128i) -> __m256i {
        _mm256_inserti128_si256::<0>(_mm256_setzero_si256(), value)
    }

    #[inline(always)]
    unsafe fn broadcast128(value: __m128i) -> __m256i {
        let out = _mm256_castsi128_si256(value);
        _mm256_inserti128_si256::<1>(out, value)
    }

    #[inline(always)]
    unsafe fn xor3_128(a: __m128i, b: __m128i, c: __m128i) -> __m128i {
        _mm_xor_si128(_mm_xor_si128(a, b), c)
    }

    #[inline(always)]
    unsafe fn setr_epi32(a: u32, b: u32, c: u32, d: u32) -> __m128i {
        _mm_set_epi32(d as i32, c as i32, b as i32, a as i32)
    }

    /// One 32-byte fold step: `data ^ (src * x^k)` in both 128-bit lanes.
    ///
    /// The constant pair is the standard 512-bit-distance fold
    /// (`x^544 mod P`, `x^480 mod P`), broadcast to both lanes so a single YMM
    /// `vpclmulqdq` advances two independent 128-bit fold streams.
    #[inline(always)]
    unsafe fn do_one_fold(src: __m256i, data: __m256i) -> __m256i {
        let fold4 = _mm256_set_epi32(
            0x0000_0001u32 as i32,
            0x5444_2bd4u32 as i32,
            0x0000_0001u32 as i32,
            0xc6e4_1596u32 as i32,
            0x0000_0001u32 as i32,
            0x5444_2bd4u32 as i32,
            0x0000_0001u32 as i32,
            0xc6e4_1596u32 as i32,
        );
        _mm256_xor_si256(
            _mm256_xor_si256(data, _mm256_clmulepi64_epi128::<0x01>(src, fold4)),
            _mm256_clmulepi64_epi128::<0x10>(src, fold4),
        )
    }

    /// Fold a `len < 32` tail in, shifting the accumulators right by `len`
    /// bytes so the tail lands at the stream's end without a separate pass.
    #[inline(always)]
    unsafe fn partial_fold(len: usize, crc0: &mut __m256i, crc1: &mut __m256i, crc_part: __m256i) {
        debug_assert!(len < 32);
        // A 32-entry identity ramp read at offset `len & 15` yields the
        // byte-rotate control for `pshufb`; entries >= 16 select the "came from
        // the neighbouring lane" case that `mask` then blends.
        const ROT_TABLE: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let shuf128 = _mm_loadu_si128(ROT_TABLE.as_ptr().add(len & 15) as *const __m128i);
        let shuf = broadcast128(shuf128);
        let mask = _mm256_cmpgt_epi8(shuf, _mm256_set1_epi8(15));

        *crc0 = _mm256_shuffle_epi8(*crc0, shuf);
        *crc1 = _mm256_shuffle_epi8(*crc1, shuf);
        let crc_part = _mm256_shuffle_epi8(crc_part, shuf);

        let mut crc_out = _mm256_permute2x128_si256::<0x08>(*crc0, *crc0);
        let crc01;
        let crc1p;
        if len >= 16 {
            crc_out = _mm256_blendv_epi8(crc_out, *crc0, mask);
            crc01 = *crc1;
            crc1p = crc_part;
            *crc0 = _mm256_permute2x128_si256::<0x21>(*crc0, *crc1);
            *crc1 = _mm256_permute2x128_si256::<0x21>(*crc1, crc_part);
        } else {
            crc_out = _mm256_and_si256(crc_out, mask);
            crc01 = _mm256_permute2x128_si256::<0x21>(*crc0, *crc1);
            crc1p = _mm256_permute2x128_si256::<0x21>(*crc1, crc_part);
        }

        *crc0 = _mm256_blendv_epi8(*crc0, crc01, mask);
        *crc1 = _mm256_blendv_epi8(*crc1, crc1p, mask);
        *crc1 = do_one_fold(crc_out, *crc1);
    }

    /// The kernel: seed, fold 64 B/iteration across two YMM accumulators,
    /// absorb the tail, then reduce 512 bits to 128 and Barrett-reduce to 32.
    #[inline(always)]
    unsafe fn crc_fold_256(initial: u32, mut data: &[u8]) -> u32 {
        if data.is_empty() {
            return initial;
        }

        // Lift the incoming finalized CRC into the fold domain. `!initial`
        // undoes the final xor-out; the multiply by `x^(-32) mod P` places the
        // 32-bit residue where a folded 128-bit block would sit.
        let xmm_t0 = _mm_clmulepi64_si128(
            _mm_cvtsi32_si128((!initial) as i32),
            _mm_cvtsi32_si128(0xdfde_d7ecu32 as i32),
            0,
        );
        let mut crc0 = zext128_256(xmm_t0);
        let mut crc1 = _mm256_setzero_si256();

        if data.len() < 32 {
            let part = load_partial256(data);
            partial_fold(data.len(), &mut crc0, &mut crc1, part);
        } else {
            while data.len() >= 64 {
                crc0 = do_one_fold(crc0, loadu256(data));
                crc1 = do_one_fold(crc1, loadu256(&data[32..]));
                data = &data[64..];
            }

            if data.len() >= 32 {
                // Odd 32-byte block: fold it into `crc0` and rotate the
                // accumulators so the fold distances stay consistent.
                let old = crc1;
                crc1 = do_one_fold(crc0, loadu256(data));
                crc0 = old;
                data = &data[32..];
            }

            if !data.is_empty() {
                let part = load_partial256(data);
                partial_fold(data.len(), &mut crc0, &mut crc1, part);
            }
        }

        // 4 x 128 -> 1 x 128, folding by x^128 each step.
        let mask = _mm_set_epi32(-1, -1, -1, 0);
        let mut xmm_crc0 = _mm256_castsi256_si128(crc0);
        let mut xmm_crc1 = _mm256_extracti128_si256::<1>(crc0);
        let mut xmm_crc2 = _mm256_castsi256_si128(crc1);
        let mut xmm_crc3 = _mm256_extracti128_si256::<1>(crc1);

        let mut fold = setr_epi32(0xccaa_009e, 0x0000_0000, 0x7519_97d0, 0x0000_0001);
        let tmp0 = _mm_clmulepi64_si128(xmm_crc0, fold, 0x10);
        xmm_crc0 = _mm_clmulepi64_si128(xmm_crc0, fold, 0x01);
        xmm_crc1 = xor3_128(xmm_crc1, tmp0, xmm_crc0);

        let tmp1 = _mm_clmulepi64_si128(xmm_crc1, fold, 0x10);
        xmm_crc1 = _mm_clmulepi64_si128(xmm_crc1, fold, 0x01);
        xmm_crc2 = xor3_128(xmm_crc2, tmp1, xmm_crc1);

        let tmp2 = _mm_clmulepi64_si128(xmm_crc2, fold, 0x10);
        xmm_crc2 = _mm_clmulepi64_si128(xmm_crc2, fold, 0x01);
        xmm_crc3 = xor3_128(xmm_crc3, tmp2, xmm_crc2);

        // 128 -> 64 -> 32 bits.
        fold = setr_epi32(0xccaa_009e, 0x0000_0000, 0x63cd_6124, 0x0000_0001);
        xmm_crc0 = xmm_crc3;
        xmm_crc3 = _mm_clmulepi64_si128(xmm_crc3, fold, 0);
        xmm_crc0 = _mm_srli_si128::<8>(xmm_crc0);
        xmm_crc3 = _mm_xor_si128(xmm_crc3, xmm_crc0);

        xmm_crc0 = xmm_crc3;
        xmm_crc3 = _mm_slli_si128::<4>(xmm_crc3);
        xmm_crc3 = _mm_clmulepi64_si128(xmm_crc3, fold, 0x10);
        xmm_crc0 = _mm_and_si128(xmm_crc0, mask);
        xmm_crc3 = _mm_xor_si128(xmm_crc3, xmm_crc0);

        // Barrett reduction by mu = x^64/P and P itself, then xor-out (the
        // `xor_si128` with `mask` supplies the final complement).
        fold = setr_epi32(0xf701_1641, 0x0000_0000, 0xdb71_0640, 0x0000_0001);
        xmm_crc1 = xmm_crc3;
        xmm_crc3 = _mm_clmulepi64_si128(xmm_crc3, fold, 0);
        xmm_crc3 = _mm_clmulepi64_si128(xmm_crc3, fold, 0x10);
        xmm_crc1 = _mm_xor_si128(xmm_crc1, mask);
        xmm_crc3 = _mm_xor_si128(xmm_crc3, xmm_crc1);

        _mm_extract_epi32::<2>(xmm_crc3) as u32
    }

    /// Drive the kernel directly, bypassing [`super::MIN_UPDATE`], for tests.
    ///
    /// Returns `None` when the tier is inactive so callers can report a visible
    /// skip instead of silently passing while executing nothing.
    #[cfg(test)]
    pub(crate) fn test_update_forced(initial: u32, data: &[u8]) -> Option<u32> {
        // SAFETY: guarded by the same capability probe the production path uses.
        available().then(|| unsafe { update(initial, data) })
    }
}
// SHARED-KERNEL-END

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* — reproducible, adds no dependency. Same
    /// generator as `crate::crc`'s tests.
    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            Self {
                state: seed | 0x9E37_79B9_7F4A_7C15,
            }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            let mut chunks = buf.chunks_exact_mut(8);
            for chunk in &mut chunks {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let bytes = self.next_u64().to_le_bytes();
                rem.copy_from_slice(&bytes[..rem.len()]);
            }
        }
    }

    /// The seeded-resume reference must agree with the one-shot checksum at
    /// seed 0, which is what makes it a usable oracle for the tier.
    #[test]
    fn resume_reference_at_zero_seed_matches_one_shot() {
        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0001);
        for len in [0usize, 1, 31, 32, 33, 255, 256, 4096, 100_003] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            assert_eq!(
                crc32_resume_reference(0, &data),
                crc_fast::crc32_iso_hdlc(&data),
                "len {len}"
            );
        }
    }

    /// Seeded resume chains: folding a split with the running value as the seed
    /// reproduces the whole-buffer CRC. This is the contract the tier's carried
    /// `u32` depends on.
    #[test]
    fn resume_reference_chains_across_splits() {
        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0002);
        let mut data = vec![0u8; 65_536];
        rng.fill(&mut data);
        let whole = crc_fast::crc32_iso_hdlc(&data);

        for split in [
            0usize, 1, 31, 32, 33, 255, 256, 4095, 32_768, 65_535, 65_536,
        ] {
            let (a, b) = data.split_at(split);
            let chained = crc32_resume_reference(crc32_resume_reference(0, a), b);
            assert_eq!(chained, whole, "split {split}");
        }
    }

    /// `update` must be usable whenever `available()` says so, and must agree
    /// with the reference. On a host with no tier this asserts the dispatch
    /// reports itself unavailable rather than silently doing nothing.
    #[test]
    fn dispatch_agrees_with_reference_or_reports_unavailable() {
        if !available() {
            eprintln!(
                "skipping dispatch_agrees_with_reference_or_reports_unavailable: \
                 no accelerated CRC tier on this host/build"
            );
            return;
        }

        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0003);
        let mut data = vec![0u8; 16_384];
        rng.fill(&mut data);
        for len in [0usize, 1, 256, 257, 4096, 16_384] {
            assert_eq!(
                update(0, &data[..len]),
                crc_fast::crc32_iso_hdlc(&data[..len]),
                "len {len}"
            );
        }
    }

    // =======================================================================
    // x86-64 tier: exhaustive byte-identity against `crc-fast`.
    // =======================================================================

    /// Exhaustive short lengths at every source alignment.
    ///
    /// The fold width is 64 bytes, so this sweeps 0..=192 (3x the fold width)
    /// at every start offset mod 64 — every combination of full 64-byte
    /// iterations, the odd 32-byte block, and the `partial_fold` tail, entered
    /// from every alignment the loader can see.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_matches_crc_fast_exhaustive_short_lengths() {
        if !x86_vpclmul::available() {
            eprintln!(
                "skipping vpclmul_matches_crc_fast_exhaustive_short_lengths: \
                 VPCLMULQDQ tier inactive (set WEAVER_CRC32_VPCLMUL=1 on a \
                 VPCLMULQDQ host to force it)"
            );
            return;
        }

        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0010);
        let mut backing = vec![0u8; 64 + 192 + 8];
        rng.fill(&mut backing);

        let mut cases = 0usize;
        for offset in 0..64usize {
            for len in 0..=192usize {
                let input = &backing[offset..offset + len];
                let expected = crc_fast::crc32_iso_hdlc(input);
                let actual = x86_vpclmul::test_update_forced(0, input)
                    .expect("tier availability was just checked");
                assert_eq!(actual, expected, "offset {offset} len {len}");
                cases += 1;
            }
        }

        assert_eq!(cases, 64 * 193, "expected the full offset x length sweep");
    }

    /// Non-zero initial values: the tier must implement the same resume
    /// semantics as a seeded `crc-fast` digest, at every length class.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_matches_crc_fast_for_arbitrary_initial_values() {
        if !x86_vpclmul::available() {
            eprintln!(
                "skipping vpclmul_matches_crc_fast_for_arbitrary_initial_values: \
                 VPCLMULQDQ tier inactive"
            );
            return;
        }

        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0011);
        let mut data = vec![0u8; 8192];
        rng.fill(&mut data);

        let mut cases = 0usize;
        for initial in [
            0u32,
            1,
            0xFFFF_FFFF,
            0x1234_5678,
            0xDEAD_BEEF,
            0x8000_0000,
            0x0000_0001,
        ] {
            for len in [
                0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 257, 1023, 4096,
                8192,
            ] {
                let input = &data[..len];
                let expected = crc32_resume_reference(initial, input);
                let actual = x86_vpclmul::test_update_forced(initial, input)
                    .expect("tier availability was just checked");
                assert_eq!(actual, expected, "initial {initial:#010x} len {len}");
                cases += 1;
            }
        }

        assert!(cases >= 100, "expected >= 100 resume cases, ran {cases}");
    }

    /// Streaming: an arbitrary chunking of a buffer, each chunk folded through
    /// the tier with the running value as the seed, must equal the one-shot
    /// CRC. This is the property the streaming wrapper relies on, exercised on
    /// the kernel itself so a wrapper bug and a kernel bug stay distinguishable.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_survives_arbitrary_streaming_splits() {
        if !x86_vpclmul::available() {
            eprintln!(
                "skipping vpclmul_survives_arbitrary_streaming_splits: \
                 VPCLMULQDQ tier inactive"
            );
            return;
        }

        let mut rng = XorShift64::new(0x0C3C_0DE0_0000_0012);
        let mut data = vec![0u8; 300_000];
        rng.fill(&mut data);
        let whole = crc_fast::crc32_iso_hdlc(&data);

        let mut cases = 0usize;
        for trial in 0..64u32 {
            let mut chunker = XorShift64::new(0xA5A5_0000_0000_0000 ^ u64::from(trial));
            let mut running = 0u32;
            let mut offset = 0usize;
            while offset < data.len() {
                // Bias towards the boundaries that matter: 0, 1, and multiples
                // of 32 and 64 either side of the fold width.
                let take = match chunker.next_u64() % 8 {
                    0 => 1,
                    1 => 31,
                    2 => 32,
                    3 => 33,
                    4 => 63,
                    5 => 64,
                    6 => 65,
                    _ => (chunker.next_u64() % 9973) as usize,
                }
                .min(data.len() - offset);
                let take = take.max(1).min(data.len() - offset);
                running = x86_vpclmul::test_update_forced(running, &data[offset..offset + take])
                    .expect("tier availability was just checked");
                offset += take;
            }
            assert_eq!(running, whole, "trial {trial}");
            cases += 1;
        }

        assert_eq!(cases, 64);
    }

    /// A zero-length update at any seed is the identity, at every entry point.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_empty_update_is_identity() {
        if !x86_vpclmul::available() {
            eprintln!("skipping vpclmul_empty_update_is_identity: VPCLMULQDQ tier inactive");
            return;
        }

        for initial in [0u32, 1, 0x1234_5678, 0xFFFF_FFFF] {
            assert_eq!(
                x86_vpclmul::test_update_forced(initial, &[]),
                Some(initial),
                "initial {initial:#010x}"
            );
            assert_eq!(crc32_resume_reference(initial, &[]), initial);
        }
    }

    /// The standard check vector, straight through the kernel.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_matches_the_standard_check_vector() {
        if !x86_vpclmul::available() {
            eprintln!("skipping vpclmul_matches_the_standard_check_vector: tier inactive");
            return;
        }
        assert_eq!(
            x86_vpclmul::test_update_forced(0, b"123456789"),
            Some(0xCBF4_3926)
        );
    }

    /// The duplication gate.
    ///
    /// The kernel is carried as two byte-identical copies rather than a shared
    /// internal crate, because both consumers are separately published and CI
    /// enumerates the publishable crates by name. That is only safe if the
    /// copies cannot drift, which is what this checks: the `SHARED-KERNEL`
    /// region of this file must match the same region of `par2-rs`'s copy,
    /// character for character.
    ///
    /// The sibling is read at run time through `CARGO_MANIFEST_DIR` rather than
    /// `include_str!`, so that a `.crate` tarball (which contains no sibling)
    /// still builds and this simply reports a visible skip. It skips the same
    /// way while the `par2-rs` copy has not landed yet.
    #[test]
    fn shared_kernel_region_matches_the_par2_copy() {
        const BEGIN: &str = "// SHARED-KERNEL-BEGIN";
        const END: &str = "// SHARED-KERNEL-END";

        fn shared_region(source: &str, label: &str) -> String {
            // Both marker strings also occur later in the file, as the literals
            // in this very test. `find` takes the first hit, which is the real
            // marker only as long as the kernel precedes the tests — so the
            // extracted region is anchored below rather than assumed.
            let start = source
                .find(BEGIN)
                .unwrap_or_else(|| panic!("{label} is missing {BEGIN}"));
            let end = source
                .find(END)
                .unwrap_or_else(|| panic!("{label} is missing {END}"));
            assert!(start < end, "{label} has the markers in the wrong order");
            let region = &source[start + BEGIN.len()..end];
            for anchor in [
                "mod x86_vpclmul",
                "unsafe fn crc_fold_256",
                "_mm256_clmulepi64_epi128",
            ] {
                assert!(
                    region.contains(anchor),
                    "{label}: the extracted SHARED-KERNEL region does not contain \
                     `{anchor}`, so the markers are not bracketing the kernel"
                );
            }
            region.to_string()
        }

        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let sibling = manifest
            .parent()
            .expect("crate dir has a parent")
            .join("par2-rs/src/crc_simd.rs");

        let Ok(sibling_source) = std::fs::read_to_string(&sibling) else {
            eprintln!(
                "skipping shared_kernel_region_matches_the_par2_copy: no sibling copy at \
                 {} (expected inside a packaged .crate, or before the par2-rs wiring lands)",
                sibling.display()
            );
            return;
        };

        let ours = shared_region(include_str!("crc_simd.rs"), "the unrar-rs copy");
        let theirs = shared_region(&sibling_source, "the par2-rs copy");
        assert_eq!(
            ours, theirs,
            "the shared CRC kernel has drifted between unrar-rs and par2-rs; \
             the two SHARED-KERNEL regions must stay byte-identical"
        );
    }

    /// The gate must never widen the ISA requirement: if the tier reports
    /// available, the instructions it issues must actually be present.
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    #[test]
    fn vpclmul_availability_never_outruns_the_isa() {
        if x86_vpclmul::available() {
            assert!(is_x86_feature_detected!("avx2"));
            assert!(is_x86_feature_detected!("pclmulqdq"));
            assert!(is_x86_feature_detected!("sse4.1"));
            assert!(
                is_x86_feature_detected!("vpclmulqdq"),
                "the tier engaged without VPCLMULQDQ; the override must widen \
                 policy, never capability"
            );
        }
    }
}
