//! A multi-way SIMD implementation of BLAKE2sp for `aarch64` (NEON) and
//! `wasm32` (`simd128`).
//!
//! The upstream `blake2s_simd` crate only ships AVX2/SSE4.1/portable backends,
//! so on ARM and wasm its BLAKE2sp falls back to scalar. This module provides a
//! 4-wide vector kernel (see [`simd`]) plus the surrounding BLAKE2sp streaming
//! state machine, wired in behind the crate's existing `Blake2spHasher` /
//! `blake2sp_hash` public API on exactly those two targets. Everywhere else the
//! crate keeps calling `blake2s_simd` unchanged.
//!
//! ## BLAKE2sp construction (RFC 7693 tree hashing; BLAKE2 spec §2.10)
//!
//! BLAKE2sp has `DEGREE = 8` leaves. Input is split into 64-byte blocks and
//! distributed round-robin: block `b` (0-indexed over the whole input) feeds
//! leaf `b % 8`. Each leaf is an ordinary BLAKE2s with tree parameters
//! (`fanout = 8`, `max_depth = 2`, `node_offset = leaf_index`, `node_depth = 0`,
//! `inner_hash_length = 32`); only leaf 7 sets the `last_node` flag. Every leaf
//! always performs at least one compression — an empty leaf compresses a single
//! zero block with counter 0 and the final-block flag set. The 8 leaf digests
//! (32 bytes each) are concatenated into a 256-byte block and hashed by a
//! single root BLAKE2s (`node_depth = 1`, `node_offset = 0`, `last_node` set).
//!
//! The observable output is byte-identical to `blake2s_simd::blake2sp`; the
//! differential test module below proves it exhaustively.

pub(super) mod simd;

#[cfg(test)]
mod tests;

use simd::{IV, Simd, compress4};
// The portable scalar kernel is the arch-independent test oracle on these
// targets (the selected backend is always NEON or simd128), so it is only
// referenced from the differential tests.
#[cfg(test)]
use simd::Scalar;

/// BLAKE2s block size in bytes.
const BLOCK: usize = 64;
/// Number of leaves (BLAKE2sp degree).
const DEGREE: usize = 8;
/// One super-block feeds every leaf exactly one 64-byte block.
const SUPERBLOCK: usize = DEGREE * BLOCK; // 512

/// Minimum bytes that must follow a compressed super-block for it to be
/// non-final for *every* leaf: leaves `0..DEGREE-1` each need a full following
/// block and the last leaf needs at least one byte. This mirrors the reference
/// (`blake2s_simd::blake2sp`) buffering, which retains the same tail so no leaf
/// is finalized during bulk compression.
const NEEDED_TAIL: usize = (DEGREE - 1) * BLOCK + 1; // 449

/// Leaf output size in bytes.
const OUT: usize = 32;

/// Select the compile-time SIMD backend for this target.
///
/// - `aarch64` → NEON (baseline, no runtime detection).
/// - `wasm32 + simd128` → wasm `simd128`.
///
/// This module is only compiled/used on those targets (guarded by the caller in
/// `crypto::mod`), so no portable branch is needed here; the [`Scalar`] backend
/// is reserved for the differential tests.
#[cfg(target_arch = "aarch64")]
type Backend = simd::Neon;
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
type Backend = simd::Wasm;

/// Compute the eight leaf initial state words for `node_offset` / `node_depth`.
///
/// Mirrors `blake2s_simd::Params::to_words()` for the BLAKE2sp parameter set:
/// `hash_length = 32`, `key_length = 0`, `fanout = 8`, `max_depth = 2`,
/// `max_leaf_length = 0`, `inner_hash_length = 32`. The `last_node` flag is
/// deliberately NOT folded into the state words (it only affects the `f1`
/// finalization flag), matching the reference.
#[inline]
fn node_words(node_offset: u64, node_depth: u8) -> [u32; 8] {
    const HASH_LENGTH: u32 = OUT as u32;
    const FANOUT: u32 = DEGREE as u32;
    const MAX_DEPTH: u32 = 2;
    const INNER_HASH_LENGTH: u32 = OUT as u32;
    [
        IV[0] ^ HASH_LENGTH ^ (FANOUT << 16) ^ (MAX_DEPTH << 24),
        IV[1], // ^ max_leaf_length (0)
        IV[2] ^ (node_offset as u32),
        IV[3]
            ^ ((node_offset >> 32) as u32)
            ^ ((node_depth as u32) << 16)
            ^ (INNER_HASH_LENGTH << 24),
        IV[4],
        IV[5],
        IV[6],
        IV[7],
    ]
}

/// Streaming BLAKE2sp state.
///
/// Holds the eight leaves' running BLAKE2s state words (in the transposed
/// vector layout the kernel consumes) plus a byte buffer of not-yet-final
/// input. Complete non-final 512-byte super-blocks are compressed eagerly; the
/// trailing (up to 512) bytes are retained so [`Blake2spState::finalize`] can
/// apply the correct per-leaf final block, counter, and flags.
#[derive(Clone)]
pub struct Blake2spState {
    /// Leaf state, transposed: `h[j]` lane `i` is leaf `i`'s word `j`. Two
    /// vector groups: group 0 = leaves 0..4, group 1 = leaves 4..8.
    h: [[[u32; 4]; 8]; 2],
    /// Bytes buffered but not yet compressed (0..=`SUPERBLOCK` after each op,
    /// transiently larger inside `update`).
    buf: Vec<u8>,
    /// Per-leaf byte counter already folded into `h` (a multiple of `BLOCK`).
    /// Identical across leaves during streaming (each compressed super-block
    /// adds one block to every leaf), so a single scalar suffices.
    count: u64,
}

impl core::fmt::Debug for Blake2spState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Mirror `blake2s_simd::blake2sp::State`'s terse Debug: expose progress,
        // not the buffered bytes.
        f.debug_struct("Blake2spState")
            .field(
                "count",
                &(self.count.wrapping_mul(DEGREE as u64) + self.buf.len() as u64),
            )
            .finish()
    }
}

impl Default for Blake2spState {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2spState {
    /// Create a fresh BLAKE2sp state with the standard 32-byte parameters.
    pub fn new() -> Self {
        // Transpose the eight leaves' init words into the two vector groups.
        let mut h = [[[0u32; 4]; 8]; 2];
        for (group, group_h) in h.iter_mut().enumerate() {
            let base = (group * 4) as u64;
            let init: [[u32; 8]; 4] = [
                node_words(base, 0),
                node_words(base + 1, 0),
                node_words(base + 2, 0),
                node_words(base + 3, 0),
            ];
            for (word_idx, hj) in group_h.iter_mut().enumerate() {
                *hj = [
                    init[0][word_idx],
                    init[1][word_idx],
                    init[2][word_idx],
                    init[3][word_idx],
                ];
            }
        }
        Self {
            h,
            buf: Vec::with_capacity(2 * SUPERBLOCK),
            count: 0,
        }
    }

    /// Load a `[u32; 4]` array-of-lanes group into the backend vector type.
    #[inline(always)]
    unsafe fn load_group<S: Simd>(group: &[[u32; 4]; 8]) -> [S::Vec; 8] {
        // SAFETY: `S::splat`/`S::set` are gated by the caller's target; see the
        // `Simd` trait safety note. Delegated through `update`/`finalize`.
        unsafe {
            let mut v = [S::splat(0); 8];
            for (j, vj) in v.iter_mut().enumerate() {
                *vj = S::set(group[j][0], group[j][1], group[j][2], group[j][3]);
            }
            v
        }
    }

    /// Store a backend vector group back into the `[u32; 4]` array-of-lanes.
    #[inline(always)]
    unsafe fn store_group<S: Simd>(v: &[S::Vec; 8], group: &mut [[u32; 4]; 8]) {
        // SAFETY: see `load_group`.
        unsafe {
            for (j, vj) in v.iter().enumerate() {
                S::store(*vj, &mut group[j]);
            }
        }
    }

    /// Compress one complete, non-final 512-byte super-block through both leaf
    /// groups with `S`. `data` must be at least `SUPERBLOCK` bytes; only the
    /// first `SUPERBLOCK` are consumed.
    #[inline(always)]
    unsafe fn compress_superblock<S: Simd>(&mut self, data: &[u8]) {
        debug_assert!(data.len() >= SUPERBLOCK);
        let block = |i: usize| -> &[u8; BLOCK] {
            (&data[i * BLOCK..i * BLOCK + BLOCK])
                .try_into()
                .expect("block slice is 64 bytes")
        };
        let count = self.count.wrapping_add(BLOCK as u64);
        // Non-final super-block: every lane shares one counter and no
        // final/last-node flags are set. The `FINAL = false` kernel path reads
        // only `counts[0]` (all lanes equal here) and ignores the flag arrays,
        // so `zeros` is passed purely to satisfy the shared signature.
        let counts = [count; 4];
        let zeros = [0u32; 4];

        // SAFETY: the kernel calls are gated by the caller's target; see the
        // `Simd` trait safety note. `update` dispatches with the right backend.
        //
        // Both leaf groups' message transposes are hoisted ahead of either
        // round chain: the transpose uses the load/permute pipes while the round
        // `G` chain is integer/logic-bound, so exposing both independent
        // transposes lets the scheduler overlap group 1's load+transpose with
        // group 0's rounds (software pipelining across the two groups).
        unsafe {
            let blocks0 = [block(0), block(1), block(2), block(3)];
            let blocks1 = [block(4), block(5), block(6), block(7)];
            let m0 = simd::transpose_block::<S>(&blocks0);
            let m1 = simd::transpose_block::<S>(&blocks1);

            let mut g0 = Self::load_group::<S>(&self.h[0]);
            simd::compress4_transposed::<S, false>(&mut g0, &m0, counts, zeros, zeros);
            Self::store_group::<S>(&g0, &mut self.h[0]);

            let mut g1 = Self::load_group::<S>(&self.h[1]);
            simd::compress4_transposed::<S, false>(&mut g1, &m1, counts, zeros, zeros);
            Self::store_group::<S>(&g1, &mut self.h[1]);
        }

        self.count = count;
    }

    /// Feed input, compressing complete super-blocks that are guaranteed
    /// non-final for every leaf. Generic over the backend so the tests can
    /// drive the scalar kernel over the exact path the SIMD backends use.
    ///
    /// The invariant matches `blake2s_simd::blake2sp`: a super-block is only
    /// compressed here when at least [`NEEDED_TAIL`] bytes follow it, so no
    /// leaf's last block is ever compressed as non-final. Whatever remains
    /// (which can span up to two blocks per leaf) is buffered for
    /// [`finalize_with`](Self::finalize_with).
    #[inline(always)]
    unsafe fn update_with<S: Simd>(&mut self, mut input: &[u8]) {
        // Fast path: an empty buffer means `input` is aligned to a super-block
        // (leaf-0) boundary, so complete super-blocks can be compressed straight
        // from it while at least `NEEDED_TAIL` bytes remain afterward. This
        // avoids buffering the bulk of large inputs.
        if self.buf.is_empty() {
            while input.len() >= SUPERBLOCK + NEEDED_TAIL {
                // SAFETY: backend gated by the caller; see `Simd` safety note.
                unsafe { self.compress_superblock::<S>(input) };
                input = &input[SUPERBLOCK..];
            }
            self.buf.extend_from_slice(input);
            return;
        }

        // General path: append to the buffer, then compress leading super-blocks
        // while at least `NEEDED_TAIL` bytes still follow each (so it is
        // non-final for every leaf). The retained tail (< `SUPERBLOCK +
        // NEEDED_TAIL`) always starts on a super-block boundary.
        self.buf.extend_from_slice(input);
        let mut off = 0;
        while self.buf.len() - off >= SUPERBLOCK + NEEDED_TAIL {
            let mut sb = [0u8; SUPERBLOCK];
            sb.copy_from_slice(&self.buf[off..off + SUPERBLOCK]);
            // SAFETY: backend gated by the caller; see `Simd` safety note.
            unsafe { self.compress_superblock::<S>(&sb) };
            off += SUPERBLOCK;
        }
        if off > 0 {
            self.buf.drain(..off);
        }
    }

    /// Finalize the leaves over a copy of the state and return the root digest.
    /// Idempotent: the buffer and folded state are left untouched.
    ///
    /// The retained tail can span up to two blocks per leaf (the buffer is
    /// always shorter than `SUPERBLOCK + NEEDED_TAIL`, and starts on a
    /// super-block boundary). Because the round-robin distribution means block
    /// `s` of leaf `i` lives at buffer offset `i*BLOCK + s*SUPERBLOCK`, the tail
    /// is processed as at most two "steps" per group. Leaves that finish on the
    /// first step keep that result; leaves with a second block are advanced once
    /// more, and per-lane blending picks the correct final state for each.
    #[inline(always)]
    unsafe fn finalize_with<S: Simd>(&self) -> [u8; OUT] {
        let len = self.buf.len();
        debug_assert!(len < SUPERBLOCK + NEEDED_TAIL);

        let mut leaf_digests = [[0u32; 8]; DEGREE];

        for group in 0..2 {
            // Per-lane block geometry within this group.
            let mut nblocks = [0usize; 4];
            for (lane, nb) in nblocks.iter_mut().enumerate() {
                let leaf = group * 4 + lane;
                // Count real blocks at offsets leaf*BLOCK + s*SUPERBLOCK < len.
                let mut s = 0usize;
                while leaf * BLOCK + s * SUPERBLOCK < len {
                    s += 1;
                }
                // Every leaf always compresses at least one (possibly empty)
                // block.
                *nb = s.max(1);
            }
            let max_steps = *nblocks.iter().max().unwrap();

            // Build one step's blocks/counters/flags for the group.
            let build_step = |s: usize| -> ([[u8; BLOCK]; 4], [u64; 4], [u32; 4], [u32; 4]) {
                let mut padded = [[0u8; BLOCK]; 4];
                let mut counts = [0u64; 4];
                let mut f0 = [0u32; 4];
                let mut f1 = [0u32; 4];
                for lane in 0..4 {
                    let leaf = group * 4 + lane;
                    let off = leaf * BLOCK + s * SUPERBLOCK;
                    let real = if off < len { (len - off).min(BLOCK) } else { 0 };
                    if real > 0 {
                        padded[lane][..real].copy_from_slice(&self.buf[off..off + real]);
                    }
                    // Counter = folded super-block bytes + this leaf's bytes up
                    // to and including step `s`. Blocks before the last are full
                    // (64 bytes) because a leaf only has a later block when the
                    // earlier one was complete.
                    counts[lane] = self
                        .count
                        .wrapping_add((s as u64) * BLOCK as u64)
                        .wrapping_add(real as u64);
                    let is_last = s + 1 == nblocks[lane];
                    if is_last {
                        f0[lane] = !0;
                        // Only leaf 7 (lane 3 of group 1) is the last node.
                        if leaf == DEGREE - 1 {
                            f1[lane] = !0;
                        }
                    }
                }
                (padded, counts, f0, f1)
            };

            // Step 0 over the loaded group state.
            let (p0, c0, f0_0, f1_0) = build_step(0);
            let mut arr0 = [[0u32; 4]; 8];
            // SAFETY: the kernel calls are gated by the caller's target; see the
            // `Simd` trait safety note. `finalize` dispatches the right backend.
            unsafe {
                let mut hg = Self::load_group::<S>(&self.h[group]);
                let blocks = [&p0[0], &p0[1], &p0[2], &p0[3]];
                compress4::<S, true>(&mut hg, &blocks, c0, f0_0, f1_0);
                Self::store_group::<S>(&hg, &mut arr0);
            }

            // Optional step 1 for lanes that have a second block; other lanes'
            // results are computed but discarded by the per-lane blend below.
            let arr1 = if max_steps == 2 {
                let (p1, c1, f0_1, f1_1) = build_step(1);
                let mut arr1 = [[0u32; 4]; 8];
                // SAFETY: as above.
                unsafe {
                    let mut hg = Self::load_group::<S>(&arr0);
                    let blocks = [&p1[0], &p1[1], &p1[2], &p1[3]];
                    compress4::<S, true>(&mut hg, &blocks, c1, f0_1, f1_1);
                    Self::store_group::<S>(&hg, &mut arr1);
                }
                Some(arr1)
            } else {
                None
            };

            for lane in 0..4 {
                let src = match arr1 {
                    Some(ref a1) if nblocks[lane] == 2 => a1,
                    _ => &arr0,
                };
                for word_idx in 0..8 {
                    leaf_digests[group * 4 + lane][word_idx] = src[word_idx][lane];
                }
            }
        }

        // Root: single serial BLAKE2s over the 256-byte concatenation of the 8
        // leaf digests (little-endian words), with the last-node flag set.
        let mut root_block = [0u8; DEGREE * OUT];
        for (leaf, words) in leaf_digests.iter().enumerate() {
            for (w, word) in words.iter().enumerate() {
                let off = leaf * OUT + w * 4;
                root_block[off..off + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        root_compress(&root_block)
    }

    /// Add input to the hash (backend-dispatched).
    pub fn update(&mut self, input: &[u8]) {
        // SAFETY: `Backend` is chosen by the module's `cfg` gates to match the
        // compilation target (NEON is baseline on aarch64; the wasm backend is
        // only defined under `target_feature = "simd128"`), so its intrinsics
        // are always available here.
        unsafe { self.update_with::<Backend>(input) }
    }

    /// Finalize and return the 32-byte BLAKE2sp digest. Idempotent.
    pub fn finalize(&self) -> [u8; OUT] {
        // SAFETY: see `update`.
        unsafe { self.finalize_with::<Backend>() }
    }
}

/// One-shot BLAKE2sp over `data` using the SIMD backend.
pub fn hash(data: &[u8]) -> [u8; OUT] {
    let mut state = Blake2spState::new();
    state.update(data);
    state.finalize()
}

/// Outcome of [`differential_corpus`].
#[doc(hidden)]
pub struct CorpusReport {
    /// One-shot cases (every length `0..=1088` plus random large sizes) that
    /// matched the oracle.
    pub oneshot_ok: usize,
    /// Randomized streaming-split cases that matched the oracle.
    pub streaming_ok: usize,
    /// First mismatch as `(label, ours, oracle)`, if any.
    pub first_mismatch: Option<(String, [u8; OUT], [u8; OUT])>,
}

/// Run the BLAKE2sp differential corpus against the `blake2s_simd` oracle using
/// the compile-time SIMD backend, and return a summary.
///
/// This exists so the wasm harness (an example built for `wasm32-wasip1` with
/// `+simd128`) can exercise the `simd128` backend under `wasmtime` over the same
/// corpus the native tests use — without needing the oracle as a dev-dependency
/// of the example. On `aarch64` it drives the NEON backend and is used as an
/// extra smoke check. `#[doc(hidden)]`: not part of the public API.
#[doc(hidden)]
pub fn differential_corpus() -> CorpusReport {
    // Deterministic splitmix64 (no external deps, explicit seed).
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }

    let oracle = |data: &[u8]| -> [u8; OUT] { *blake2s_simd::blake2sp::blake2sp(data).as_array() };

    let mut report = CorpusReport {
        oneshot_ok: 0,
        streaming_ok: 0,
        first_mismatch: None,
    };

    // 1) Every length 0..=1088 one-shot.
    for len in 0..=1088usize {
        let mut data = vec![0u8; len];
        Rng(0xABCD_1234_5678_9F01 ^ len as u64).fill(&mut data);
        let expected = oracle(&data);
        let got = hash(&data);
        if got != expected {
            report.first_mismatch = Some((format!("oneshot len {len}"), got, expected));
            return report;
        }
        report.oneshot_ok += 1;
    }

    // 2) Random large one-shot sizes (incl. past several super-blocks).
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for &size in &[4_095usize, 4_096, 4_097, 100_000, 1_048_576] {
        let mut data = vec![0u8; size];
        rng.fill(&mut data);
        let expected = oracle(&data);
        let got = hash(&data);
        if got != expected {
            report.first_mismatch = Some((format!("oneshot large {size}"), got, expected));
            return report;
        }
        report.oneshot_ok += 1;
    }

    // 3) Randomized streaming splittings vs the one-shot oracle.
    let sizes = [
        0usize, 1, 63, 64, 65, 127, 128, 449, 511, 512, 513, 640, 960, 961, 1023, 1024, 1025, 2048,
        5000, 65_536,
    ];
    for &size in &sizes {
        let mut data = vec![0u8; size];
        rng.fill(&mut data);
        let expected = oracle(&data);
        for _ in 0..12 {
            let mut state = Blake2spState::new();
            let mut pos = 0;
            while pos < data.len() {
                let remaining = data.len() - pos;
                let max = remaining.min(if rng.below(4) == 0 { 1024 } else { 96 });
                let take = if max == 0 { 0 } else { 1 + rng.below(max) };
                state.update(&data[pos..pos + take]);
                pos += take;
            }
            let got = state.finalize();
            if got != expected {
                report.first_mismatch = Some((format!("streaming size {size}"), got, expected));
                return report;
            }
            report.streaming_ok += 1;
        }
    }

    report
}

// ---------------------------------------------------------------------------
// Root node: a single-instance scalar BLAKE2s over the 256-byte leaf block.
// ---------------------------------------------------------------------------

/// BLAKE2s message schedule SIGMA (same table as the kernel; kept local so the
/// root path is self-contained).
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Scalar BLAKE2s mixing function `G` (RFC 7693 §3.1).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn g_scalar(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
fn round_scalar(r: usize, m: &[u32; 16], v: &mut [u32; 16]) {
    let s = &SIGMA[r];
    g_scalar(v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
    g_scalar(v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
    g_scalar(v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
    g_scalar(v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);
    g_scalar(v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
    g_scalar(v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
    g_scalar(v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
    g_scalar(v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
}

/// One scalar BLAKE2s compression of a 64-byte block into `words`.
#[inline(always)]
fn compress1(words: &mut [u32; 8], block: &[u8; BLOCK], count: u64, f0: u32, f1: u32) {
    let mut v = [
        words[0],
        words[1],
        words[2],
        words[3],
        words[4],
        words[5],
        words[6],
        words[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        IV[4] ^ (count as u32),
        IV[5] ^ ((count >> 32) as u32),
        IV[6] ^ f0,
        IV[7] ^ f1,
    ];
    let mut m = [0u32; 16];
    for (k, mk) in m.iter_mut().enumerate() {
        let off = k * 4;
        *mk = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for r in 0..10 {
        round_scalar(r, &m, &mut v);
    }
    for j in 0..8 {
        words[j] ^= v[j] ^ v[j + 8];
    }
}

/// Hash the 256-byte concatenated leaf block with the BLAKE2sp root node and
/// return the final 32-byte digest.
fn root_compress(root_block: &[u8; DEGREE * OUT]) -> [u8; OUT] {
    let mut words = node_words(0, 1);
    // Four 64-byte blocks; counter accumulates real bytes. Only the last block
    // is final and last-node.
    let total = (DEGREE * OUT) as u64; // 256
    let blocks = total / BLOCK as u64; // 4
    let mut count = 0u64;
    for i in 0..blocks {
        let off = (i as usize) * BLOCK;
        let block: &[u8; BLOCK] = (&root_block[off..off + BLOCK]).try_into().unwrap();
        count = count.wrapping_add(BLOCK as u64);
        let last = i == blocks - 1;
        let f0 = if last { !0 } else { 0 };
        let f1 = f0; // root has last_node set, so f1 == f0 on the final block.
        compress1(&mut words, block, count, f0, f1);
    }
    let mut out = [0u8; OUT];
    for (w, word) in words.iter().enumerate() {
        out[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// The scalar kernel is exercised by the differential tests (arch-independent
// proof of the algorithm) via `update_with::<Scalar>` / `finalize_with::<Scalar>`.
#[cfg(test)]
impl Blake2spState {
    /// Test-only: run the streaming machine over the portable scalar kernel.
    pub(crate) fn update_scalar(&mut self, input: &[u8]) {
        // SAFETY: the Scalar backend uses no intrinsics.
        unsafe { self.update_with::<Scalar>(input) }
    }

    /// Test-only: finalize over the portable scalar kernel.
    pub(crate) fn finalize_scalar(&self) -> [u8; OUT] {
        // SAFETY: the Scalar backend uses no intrinsics.
        unsafe { self.finalize_with::<Scalar>() }
    }
}
