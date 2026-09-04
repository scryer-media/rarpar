//! IEEE CRC-32 seam for the bulk member-data checksum.
//!
//! Extraction verifies every RAR member's payload against a stored CRC-32.
//! That bulk checksum is the *only* CRC on the hot data path (the tiny header
//! and probe CRCs stay on `crc-fast` directly — routing them across a wasm
//! boundary would add per-call cost for no benefit). This module wraps that one
//! bulk CRC behind a minimal [`Crc32`] type with two COMPILE-TIME backends:
//!
//!   * **default / native / portable** — wraps [`crc_fast::Digest`],
//!     using its runtime-selected CRC-32/ISO-HDLC implementation (this is the
//!     branch every non-wasm build
//!     and every plain-`crypto-rust` wasm build takes).
//!   * **`wasm32` + `crc-host`** — holds a running `u32` (IEEE reflected CRC,
//!     init 0) and delegates each [`update`](Crc32::update) to the embedder's
//!     `crc32` hook (see `crate::hooks`), threading the returned CRC
//!     forward. `finalize` returns the running value. This puts the bulk CRC
//!     on the host's (potentially hardware-accelerated) implementation,
//!     mirroring how the `crypto-host` backend delegates bulk AES.
//!
//! Because `crc32(A ++ B) == crc32(crc32(0, A), B)`, feeding the hook
//! successive chunks with the running CRC as the seed reproduces the
//! whole-stream CRC exactly. The native test below proves that chunk-chaining
//! equivalence, through the real hook registry, without a wasm host.
//!
//! ## The accelerated tier
//!
//! Orthogonal to the backend split above, the non-host backend consults
//! [`crate::crc_simd`], which supplies a CRC kernel for the one CPU class
//! `crc-fast` leaves on a slower tier than its instruction set allows. That
//! module owns the gate and the kernel; this one owns the streaming state that
//! hands buffers to it. Where no tier applies — which is every non-x86-64
//! target, all wasm, and any x86-64 host outside the gap — the seam is exactly
//! the `crc-fast` wrapper it was before.

use crate::crc_simd;

/// Fold `data` into the running CRC through the embedder-installed hook (see
/// `crate::hooks`). The seeded-resume contract is what makes the chunk
/// chaining this module depends on hold.
///
/// On a native target this is dead outside `#[cfg(test)]`: `Crc32` selects the
/// portable `crc-fast` wrapper there (only a wasm guest has a host to delegate
/// to), while the tests below still drive this function directly so the hook
/// path is proven without a wasm runtime.
#[cfg(feature = "crc-host")]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[inline]
fn crc32_update_host(running: u32, data: &[u8]) -> u32 {
    (crate::hooks::hooks().crc32)(running, data)
}

/// Native `#[cfg(test)]` reference stand-in for the hook: resume a
/// CRC-32/ISO-HDLC from `running` over `data` and return the updated value.
/// This is exactly what the hook promises (seeded IEEE CRC-32, chainable), so
/// the chaining test can drive the delegating `Crc32` seam shape WITHOUT
/// `crc-host` and prove the chunk-chaining equivalence.
///
/// Compiled only without `crc-host` — with the feature the chaining test drives
/// the embedder hook itself instead.
#[cfg(all(test, not(feature = "crc-host")))]
#[inline]
fn crc32_update_host(running: u32, data: &[u8]) -> u32 {
    let mut hasher = crc_fast::Digest::new_with_init_state(
        crc_fast::CrcAlgorithm::Crc32IsoHdlc,
        u64::from(!running),
    );
    hasher.update(data);
    hasher.finalize() as u32
}

// ---------------------------------------------------------------------------
// The active `Crc32` seam. Exactly one definition compiles:
//   * wasm32 + crc-host: the host-delegated running-`u32` implementation.
//   * everything else:    the portable `crc-fast` wrapper.
// ---------------------------------------------------------------------------

/// Incremental IEEE CRC-32 of a byte stream (host-delegated wasm build).
#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
#[derive(Clone)]
pub(crate) struct Crc32 {
    running: u32,
}

#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
impl Crc32 {
    /// A fresh CRC-32 state (running value 0).
    #[inline]
    pub(crate) fn new() -> Self {
        Self { running: 0 }
    }

    /// Fold `data` into the running CRC via the embedder hook.
    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.running = crc32_update_host(self.running, data);
    }

    /// Consume the hasher and return the final CRC-32.
    #[inline]
    pub(crate) fn finalize(self) -> u32 {
        self.running
    }
}

/// Incremental IEEE CRC-32 of a byte stream (portable / native build).
///
/// Wraps [`crc_fast::Digest`], with one detour: on hosts where
/// [`crate::crc_simd`] has a tier `crc-fast` does not (VPCLMULQDQ without
/// AVX-512VL — see that module for why the hole exists), updates at or above
/// [`crc_simd::MIN_UPDATE`] are folded by the local kernel instead.
///
/// While the kernel is carrying the stream, the authoritative value is the
/// plain `u32` in `accel` — which is in the finalized (post-xor) domain — and
/// `inner` is stale. `inner` is re-seeded from `accel` only when a
/// below-threshold update arrives, so the dominant "a few large updates then
/// finalize" shape (which is every bulk member-data CRC in this crate) touches
/// the digest exactly once, at construction.
///
/// Because `accel` is not a digest, [`crc_fast::Digest::get_amount`] and
/// [`crc_fast::Digest::combine`] would see a byte counter that stopped
/// advancing the moment the kernel engaged. Neither is surfaced through this
/// wrapper, and neither may be added without tracking the folded byte count
/// here first.
#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
#[derive(Clone)]
pub(crate) struct Crc32 {
    inner: crc_fast::Digest,
    /// Carried CRC in the finalized domain. `Some` means `inner` is stale.
    accel: Option<u32>,
    /// Resolved once per hasher rather than per update, so the hot path is a
    /// register test and not a `OnceLock` load. Always `false` on targets and
    /// hosts with no tier, where it constant-folds the branch away entirely.
    use_accel: bool,
}

#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
impl Crc32 {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32IsoHdlc),
            accel: None,
            use_accel: crc_simd::available(),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        if self.use_accel && data.len() >= crc_simd::MIN_UPDATE {
            // Both the kernel's input and its output are the finalized domain,
            // so consecutive folded updates just carry a `u32`.
            let initial = match self.accel {
                Some(crc) => crc,
                None => self.inner.finalize() as u32,
            };
            self.accel = Some(crc_simd::update(initial, data));
            return;
        }

        // Leaving the folding path: materialize the carried value back into the
        // resident digest exactly once, not once per update.
        if let Some(crc) = self.accel.take() {
            self.inner = crc_fast::Digest::new_with_init_state(
                crc_fast::CrcAlgorithm::Crc32IsoHdlc,
                u64::from(!crc),
            );
        }

        self.inner.update(data);
    }

    #[inline]
    pub(crate) fn finalize(self) -> u32 {
        match self.accel {
            Some(crc) => crc,
            None => self.inner.finalize() as u32,
        }
    }
}

/// One-shot IEEE CRC-32.
///
/// Takes the same accelerated tier as [`Crc32`] for buffers large enough to pay
/// for the dispatch; everything else goes straight to `crc-fast`. The header
/// and probe CRCs that dominate this function's call sites are tens of bytes,
/// so they take the second arm.
#[inline]
pub(crate) fn hash(data: &[u8]) -> u32 {
    if data.len() >= crc_simd::MIN_UPDATE && crc_simd::available() {
        return crc_simd::update(0, data);
    }
    crc_fast::crc32_iso_hdlc(data)
}

// ===========================================================================
// NATIVE seam byte-identity test: the `Crc32` seam, fed a stream in arbitrary
// chunk splits, must equal the one-shot CRC-32/ISO-HDLC result.
//
// Additionally, the `crc32_update_host` reference stand-in (the native twin of
// the wasm host import) is exercised across the same random splits, proving the
// seeded-resume chunk-chaining contract the host must satisfy:
//   crc32(crc32(0, A), B) == crc32(0, A ++ B).
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* PRNG — reproducible, adds no dependency.
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

        fn next_usize(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// A randomized sequence of chunk sizes (each >= 1) summing to `total`,
    /// including single-byte and larger spans, to stress the seam's update
    /// chaining across many boundaries.
    fn random_splits(total: usize, rng: &mut XorShift64) -> Vec<usize> {
        let mut remaining = total;
        let mut sizes = Vec::new();
        while remaining > 0 {
            let take = 1 + rng.next_usize(remaining.min(4096));
            sizes.push(take);
            remaining -= take;
        }
        sizes
    }

    /// Feed `data` through the `Crc32` seam in the given `splits`.
    fn seam_over_splits(data: &[u8], splits: &[usize]) -> u32 {
        let mut crc = Crc32::new();
        let mut offset = 0;
        for &size in splits {
            crc.update(&data[offset..offset + size]);
            offset += size;
        }
        assert_eq!(offset, data.len(), "splits must cover the whole buffer");
        crc.finalize()
    }

    /// The `Crc32` seam over randomized chunk splits (and the all-1-byte and
    /// whole-buffer extremes) must equal the one-shot checksum for every
    /// length. This is the load-bearing native byte-identity proof.
    #[test]
    fn crc32_seam_matches_one_shot_over_random_splits() {
        let mut rng = XorShift64::new(0x00C3_2000_ABCD_EF01_u64);
        let mut cases = 0usize;

        for &len in &[
            0usize, 1, 2, 15, 16, 17, 63, 64, 255, 256, 1023, 1024, 4095, 4096, 4097, 65_535,
            65_536, 65_537, 1_000_003,
        ] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let reference = hash(&data);

            let all_1: Vec<usize> = vec![1usize; len];
            let random = random_splits(len, &mut rng);
            let whole = if len == 0 { vec![] } else { vec![len] };

            for (label, splits) in [("all-1", &all_1), ("random", &random), ("whole", &whole)] {
                let got = seam_over_splits(&data, splits);
                assert_eq!(
                    got, reference,
                    "Crc32 seam diverged from one-shot CRC: len={len}, split={label}, sizes={splits:?}"
                );
            }

            cases += 1;
        }

        assert!(cases >= 10, "expected >= 10 CRC cases, ran {cases}");
    }

    /// Update sequences that bounce across [`crc_simd::MIN_UPDATE`] in both
    /// directions, checked at *every prefix* rather than only at the end, so a
    /// bad hand-off is attributed to the update that introduced it.
    ///
    /// This is the load-bearing test for the accelerated tier's interaction
    /// with the digest: entering the fold, leaving it, re-entering it, and the
    /// exact threshold boundary (255 vs 256). On a host with no tier it still
    /// runs and simply proves the seam unchanged, so it is never a silent skip.
    #[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
    #[test]
    fn crc32_seam_survives_updates_straddling_the_tier_threshold() {
        const LEN: usize = 64 * 1024;
        let mut rng = XorShift64::new(0x00C3_2000_5111_D001);
        let mut data = vec![0u8; LEN];
        rng.fill(&mut data);

        let min = crc_simd::MIN_UPDATE;
        let sequences: [&[usize]; 8] = [
            &[1, 64, 255, 256, 300, 4096, 7],
            &[4096, 7, 256, 1, 300, 255, 64],
            &[256, 256, 256, 1, 1, 1, 4096],
            &[7, 7, 7, 300, 7, 4096, 255, 256],
            &[300, 1, 4096, 64, 256, 255, 7, 256],
            &[4096, 4096, 1, 4096, 255, 300, 256],
            &[8192, 8192, 8192, 1],
            &[1, 8192, 1, 8192, 1],
        ];

        let mut prefixes = 0usize;
        for seq in sequences {
            assert!(
                seq.iter().any(|&len| len >= min) && seq.iter().any(|&len| len < min),
                "sequence {seq:?} must straddle MIN_UPDATE ({min}) to be useful"
            );
            let total: usize = seq.iter().sum();
            assert!(total <= LEN, "sequence {seq:?} exceeds the fixture");

            let mut crc = Crc32::new();
            let mut offset = 0usize;
            for &len in seq {
                crc.update(&data[offset..offset + len]);
                offset += len;
                assert_eq!(
                    crc.clone().finalize(),
                    hash(&data[..offset]),
                    "sequence {seq:?} diverged at prefix {offset}"
                );
                prefixes += 1;
            }
        }

        assert!(
            prefixes >= 50,
            "expected >= 50 prefix checks, ran {prefixes}"
        );
    }

    /// The one-shot [`hash`] helper takes a different arm above and below the
    /// tier threshold; both must agree with `crc-fast` at the boundary.
    #[test]
    fn crc32_one_shot_hash_matches_crc_fast_across_the_threshold() {
        let mut rng = XorShift64::new(0x00C3_2000_5111_D002);
        let mut data = vec![0u8; 8192];
        rng.fill(&mut data);

        let min = crc_simd::MIN_UPDATE;
        for len in [
            0,
            1,
            min.saturating_sub(2),
            min.saturating_sub(1),
            min,
            min + 1,
            min + 2,
            1024,
            8192,
        ] {
            assert_eq!(
                hash(&data[..len]),
                crc_fast::crc32_iso_hdlc(&data[..len]),
                "len {len}"
            );
        }
    }

    /// The `crc32_update_host` seam must satisfy the seeded-resume chaining
    /// contract the embedder's hook is required to meet: folding successive
    /// chunks with the running CRC as the seed equals the whole-stream CRC.
    ///
    /// With `crc-host` this drives the real hook registry (loaded with the
    /// reference hook pair) rather than the native stand-in, so it is also the
    /// delegating CRC seam's proof that a host reached through function
    /// pointers chains exactly like an in-process CRC.
    #[test]
    fn host_reference_crc_chains_like_whole_stream() {
        #[cfg(feature = "crc-host")]
        crate::hooks::install_reference_hooks_for_test();

        let mut rng = XorShift64::new(0x5EED_C0DE_1234_9001);
        for &len in &[0usize, 1, 16, 17, 4096, 100_003] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let reference = hash(&data);

            let splits = random_splits(len, &mut rng);
            let mut running = 0u32;
            let mut offset = 0;
            for &size in &splits {
                running = crc32_update_host(running, &data[offset..offset + size]);
                offset += size;
            }
            assert_eq!(offset, len);
            assert_eq!(
                running, reference,
                "host reference CRC failed to chain at len={len}, splits={splits:?}"
            );
        }
    }
}
