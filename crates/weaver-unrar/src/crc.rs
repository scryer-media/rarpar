//! IEEE CRC-32 seam for the bulk member-data checksum.
//!
//! Extraction verifies every RAR member's payload against a stored CRC-32.
//! That bulk checksum is the *only* CRC on the hot data path (the tiny header
//! and probe CRCs stay on `crc32fast` directly — routing them across a wasm
//! boundary would add per-call cost for no benefit). This module wraps that one
//! bulk CRC behind a minimal [`Crc32`] type with two COMPILE-TIME backends:
//!
//!   * **default / native / portable** — wraps [`crc32fast::Hasher`] verbatim,
//!     so the CRC is byte-identical to the previous inline `crc32fast` usage and
//!     the native codegen is unchanged (this is the branch every non-wasm build
//!     and every plain-`crypto-rust` wasm build takes).
//!   * **`wasm32` + `crc-host`** — holds a running `u32` (IEEE reflected CRC,
//!     init 0) and delegates each [`update`](Crc32::update) to the host import
//!     `host_crc32`, threading the returned CRC forward. `finalize` returns the
//!     running value. This puts the bulk CRC on the host's (potentially
//!     hardware-accelerated) implementation, mirroring how the `crypto-host`
//!     backend delegates bulk AES.
//!
//! Because `crc32fast::hash(A ++ B) == crc32(crc32(0, A), B)`, feeding the host
//! import successive chunks with the running CRC as the seed reproduces the
//! whole-stream CRC exactly. The native reference stand-in below proves that
//! chunk-chaining equivalence without a wasm host.
//!
//! ## The host ABI (fixed contract, shared with the host side)
//!
//! Import module (namespace): `host` — embedder-neutral, satisfiable by any
//! wasm runtime that can register imports (wasmtime, wasmer, …). The
//! `host-abi-extism` feature switches only the namespace to
//! `extism:host/user`, for Extism SDKs whose user host functions are pinned
//! to that module; the function name and signature are identical in both.
//! One import is declared:
//!
//! ```text
//! host_crc32(seed, buf_ptr, buf_len) -> i64
//! ```
//!
//! All args/returns are raw `i64`/`u64`; `buf_ptr` is a byte offset into the
//! plugin's own linear memory which the host slices in place (READ-ONLY —
//! zero-copy, no marshalling). The CRC is IEEE CRC-32 reflected (polynomial
//! `0xEDB88320`, as used by RAR / ZIP / gzip). `seed` is the running CRC (0 to
//! start); the result is the updated CRC in the low 32 bits. It chains:
//! `crc32(crc32(0, A), B) == crc32(0, A ++ B)`. `buf_len` may be 0 (returns the
//! seed unchanged).

// Raw host import: a bare `#[link]` extern (no embedder SDK dependency), so
// any wasm runtime satisfies it by exposing a function of this name in the
// import namespace. The namespace is `host` unless `host-abi-extism` retargets
// it for Extism SDKs. (A `//` comment, not `///`: doc comments are not allowed
// on the items inside a `#[link]` extern block.)
#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
#[cfg_attr(
    feature = "host-abi-extism",
    link(wasm_import_module = "extism:host/user")
)]
#[cfg_attr(not(feature = "host-abi-extism"), link(wasm_import_module = "host"))]
unsafe extern "C" {
    fn host_crc32(seed: u64, buf_ptr: u64, buf_len: u64) -> i64;
}

/// Update the running CRC over `data` via the host, using the raw offset ABI
/// (zero-copy: the host reads the plugin's linear memory at this offset). The
/// host reads `data` read-only and returns the updated CRC in the low 32 bits.
#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
#[inline]
fn crc32_update_host(running: u32, data: &[u8]) -> u32 {
    // SAFETY: `data.as_ptr()`/`data.len()` are a valid read-only offset+length
    // into this module's own linear memory; the host slices them in place and
    // never retains them past the call.
    let rc = unsafe { host_crc32(running as u64, data.as_ptr() as u64, data.len() as u64) };
    // The contract returns the updated CRC in the low 32 bits; the high bits are
    // reserved and ignored here.
    rc as u64 as u32
}

/// Native `#[cfg(test)]` reference stand-in for the host import: resume a
/// `crc32fast` CRC from `running` over `data` and return the updated value. This
/// is exactly what the host promises (seeded IEEE CRC-32, chainable), so the
/// native chaining test can drive the wasm-shaped `Crc32` seam WITHOUT a wasm
/// host and prove the chunk-chaining equivalence.
#[cfg(all(test, not(all(target_arch = "wasm32", feature = "crc-host"))))]
#[inline]
fn crc32_update_host(running: u32, data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(running);
    hasher.update(data);
    hasher.finalize()
}

// ---------------------------------------------------------------------------
// The active `Crc32` seam. Exactly one definition compiles:
//   * wasm32 + crc-host: the host-delegated running-`u32` implementation.
//   * everything else:    the portable `crc32fast::Hasher` wrapper (byte-
//     identical to the previous inline usage; native codegen unchanged).
// ---------------------------------------------------------------------------

/// Incremental IEEE CRC-32 of a byte stream (host-delegated wasm build).
#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
pub(crate) struct Crc32 {
    running: u32,
}

#[cfg(all(target_arch = "wasm32", feature = "crc-host"))]
impl Crc32 {
    /// A fresh CRC-32 state (running value 0, matching `crc32fast::Hasher::new`).
    #[inline]
    pub(crate) fn new() -> Self {
        Self { running: 0 }
    }

    /// Fold `data` into the running CRC via the host import.
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

/// Incremental IEEE CRC-32 of a byte stream (portable / native build). Thin
/// wrapper over [`crc32fast::Hasher`] — byte-identical to calling it directly.
#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
pub(crate) struct Crc32 {
    inner: crc32fast::Hasher,
}

#[cfg(not(all(target_arch = "wasm32", feature = "crc-host")))]
impl Crc32 {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: crc32fast::Hasher::new(),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    #[inline]
    pub(crate) fn finalize(self) -> u32 {
        self.inner.finalize()
    }
}

// ===========================================================================
// NATIVE seam byte-identity test: the `Crc32` seam, fed a stream in arbitrary
// chunk splits, must equal `crc32fast::hash(whole)`. On a native `#[cfg(test)]`
// build the seam takes the portable `crc32fast::Hasher` branch, so this is a
// direct proof that the wrapper is byte-identical to the crate's reference CRC.
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
    /// whole-buffer extremes) must equal `crc32fast::hash(whole)` for every
    /// length. This is the load-bearing native byte-identity proof.
    #[test]
    fn crc32_seam_matches_crc32fast_over_random_splits() {
        let mut rng = XorShift64::new(0x00C3_2000_ABCD_EF01_u64);
        let mut cases = 0usize;

        for &len in &[
            0usize, 1, 2, 15, 16, 17, 63, 64, 255, 256, 1023, 1024, 4095, 4096, 4097, 65_535,
            65_536, 65_537, 1_000_003,
        ] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let reference = crc32fast::hash(&data);

            let all_1: Vec<usize> = vec![1usize; len];
            let random = random_splits(len, &mut rng);
            let whole = if len == 0 { vec![] } else { vec![len] };

            for (label, splits) in [("all-1", &all_1), ("random", &random), ("whole", &whole)] {
                let got = seam_over_splits(&data, splits);
                assert_eq!(
                    got, reference,
                    "Crc32 seam diverged from crc32fast: len={len}, split={label}, sizes={splits:?}"
                );
            }

            cases += 1;
        }

        assert!(cases >= 10, "expected >= 10 CRC cases, ran {cases}");
    }

    /// The `crc32_update_host` reference stand-in (native twin of the wasm host
    /// import) must satisfy the seeded-resume chaining contract the host side is
    /// required to meet: folding successive chunks with the running CRC as the
    /// seed equals the whole-stream CRC.
    #[test]
    fn host_reference_crc_chains_like_whole_stream() {
        let mut rng = XorShift64::new(0x5EED_C0DE_1234_9001);
        for &len in &[0usize, 1, 16, 17, 4096, 100_003] {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let reference = crc32fast::hash(&data);

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
