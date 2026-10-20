//! IEEE CRC-32 seam for the bulk member-data checksum.
//!
//! Extraction verifies every RAR member's payload against a stored CRC-32.
//! That bulk checksum is the *only* CRC on the hot data path (the tiny header
//! and probe CRCs stay on `crc-turbo` directly — routing them across a wasm
//! boundary would add per-call cost for no benefit). This module wraps that one
//! bulk CRC behind a minimal [`Crc32`] type with two COMPILE-TIME backends:
//!
//!   * **default / native / portable** — wraps [`crc_turbo::Digest`],
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

/// Fold `data` into the running CRC through the embedder-installed hook (see
/// `crate::hooks`). The seeded-resume contract is what makes the chunk
/// chaining this module depends on hold.
///
/// On a native target this is dead outside `#[cfg(test)]`: `Crc32` selects the
/// portable `crc-turbo` wrapper there (only a wasm guest has a host to delegate
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
    let mut hasher = crc_turbo::Digest::new_with_init_state(
        crc_turbo::CrcAlgorithm::Crc32IsoHdlc,
        u64::from(!running),
    );
    hasher.update(data);
    hasher.finalize() as u32
}

// ---------------------------------------------------------------------------
// The active `Crc32` seam. Exactly one definition compiles:
//   * wasm32 + crc-host: the host-delegated running-`u32` implementation.
//   * everything else:    the portable `crc-turbo` wrapper.
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
/// Wraps [`crc_turbo::Digest`], whose runtime dispatch picks the widest fold the
/// CPU supports, including the 256-bit VPCLMULQDQ tier for x86-64 parts without
/// AVX-512.
#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
#[derive(Clone)]
pub(crate) struct Crc32 {
    inner: crc_turbo::Digest,
}

#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
impl Crc32 {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: crc_turbo::Digest::new(crc_turbo::CrcAlgorithm::Crc32IsoHdlc),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    pub(crate) fn finalize(self) -> u32 {
        self.inner.finalize() as u32
    }
}

/// One-shot IEEE CRC-32.
#[inline]
pub(crate) fn hash(data: &[u8]) -> u32 {
    crc_turbo::crc32_iso_hdlc(data)
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
