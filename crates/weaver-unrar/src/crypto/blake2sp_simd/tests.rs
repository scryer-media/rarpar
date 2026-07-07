//! Differential correctness tests for the multi-way BLAKE2sp kernel.
//!
//! The oracle for every check is `blake2s_simd`: the one-shot
//! `blake2sp::blake2sp` and the streaming `blake2sp::State`. We prove three
//! backends against it over the same corpus:
//!
//! * the portable [`Scalar`](super::simd::Scalar) kernel (arch-independent
//!   proof of the algorithm), via `update_scalar` / `finalize_scalar`;
//! * the compile-time [`Backend`](super::Backend) (NEON here on `aarch64`, or
//!   `simd128` under wasm), via the public `update` / `finalize`.
//!
//! The corpus covers every input length `0..=1088` exhaustively (empty,
//! sub-block, 64-block boundaries, 512-superblock boundaries, and past two
//! superblocks), random lengths up to 4 MiB, and ≥200 randomized streaming
//! chunk splittings. All randomness is a deterministic seeded splitmix64 — no
//! new dependencies, no entropy sources.

use super::Blake2spState;

/// Oracle: `blake2s_simd` one-shot BLAKE2sp.
fn oracle_oneshot(data: &[u8]) -> [u8; 32] {
    *blake2s_simd::blake2sp::blake2sp(data).as_array()
}

/// Oracle: `blake2s_simd` streaming BLAKE2sp over the given chunking.
fn oracle_streaming(chunks: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2s_simd::blake2sp::State::new();
    for chunk in chunks {
        state.update(chunk);
    }
    *state.finalize().as_array()
}

/// Our one-shot via the compile-time SIMD backend (public path).
fn ours_oneshot_simd(data: &[u8]) -> [u8; 32] {
    super::hash(data)
}

/// Our one-shot via the portable scalar kernel.
fn ours_oneshot_scalar(data: &[u8]) -> [u8; 32] {
    let mut state = Blake2spState::new();
    state.update_scalar(data);
    state.finalize_scalar()
}

/// Deterministic splitmix64 PRNG (no external deps, seeded explicitly).
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform-ish integer in `0..bound` (bound > 0).
    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// Fill `buf` with pseudo-random bytes.
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let tail = self.next_u64().to_le_bytes();
            let n = buf.len() - i;
            buf[i..].copy_from_slice(&tail[..n]);
        }
    }
}

/// Build a deterministic byte pattern of `len` bytes (distinct per index so
/// transpose/rotation bugs surface).
fn painted(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let mut rng = SplitMix64::new(0xABCD_1234_5678_9F01 ^ len as u64);
    for (i, b) in v.iter_mut().enumerate() {
        // Mix an index-dependent term with PRNG so both structured boundaries
        // and pseudo-random content are covered.
        *b = (i as u8) ^ (rng.next_u32() as u8);
    }
    v
}

/// Every length `0..=1088`, one-shot, scalar AND SIMD backends vs the oracle.
#[test]
fn exhaustive_lengths_oneshot() {
    let mut scalar_cases = 0usize;
    let mut simd_cases = 0usize;
    for len in 0..=1088usize {
        let data = painted(len);
        let expected = oracle_oneshot(&data);

        let got_scalar = ours_oneshot_scalar(&data);
        assert_eq!(
            got_scalar, expected,
            "scalar one-shot mismatch at len {len}"
        );
        scalar_cases += 1;

        let got_simd = ours_oneshot_simd(&data);
        assert_eq!(got_simd, expected, "SIMD one-shot mismatch at len {len}");
        simd_cases += 1;
    }
    assert_eq!(scalar_cases, 1089);
    assert_eq!(simd_cases, 1089);
}

/// Every length `0..=1088` fed one byte at a time (worst-case buffering path),
/// streaming, both backends vs the oracle streaming with the same split.
#[test]
fn exhaustive_lengths_streaming_one_byte() {
    for len in 0..=1088usize {
        let data = painted(len);
        let single: Vec<&[u8]> = data.chunks(1).collect();
        let expected = oracle_streaming(&single);

        // Scalar streaming, one byte per update.
        let mut s = Blake2spState::new();
        for chunk in &single {
            s.update_scalar(chunk);
        }
        assert_eq!(
            s.finalize_scalar(),
            expected,
            "scalar 1-byte streaming mismatch at len {len}"
        );

        // SIMD streaming, one byte per update.
        let mut h = Blake2spState::new();
        for chunk in &single {
            h.update(chunk);
        }
        assert_eq!(
            h.finalize(),
            expected,
            "SIMD 1-byte streaming mismatch at len {len}"
        );
    }
}

/// Randomized chunk splittings: ≥200 cases across a spread of sizes, comparing
/// our streaming SIMD result against the one-shot oracle.
#[test]
fn randomized_streaming_splits() {
    let mut rng = SplitMix64::new(0x0BAD_F00D_2545_F491);
    // Sizes chosen to straddle block (64) and super-block (512) boundaries and
    // to run well past two super-blocks.
    let sizes = [
        0usize, 1, 7, 63, 64, 65, 127, 128, 200, 448, 449, 511, 512, 513, 640, 1023, 1024, 1025,
        2048, 4096, 5000, 65_536, 131_072, 262_144,
    ];
    let mut cases = 0usize;
    for &size in &sizes {
        let mut data = vec![0u8; size];
        rng.fill(&mut data);
        // Several distinct random splittings per size.
        for _ in 0..10 {
            let mut chunks: Vec<&[u8]> = Vec::new();
            let mut pos = 0;
            while pos < data.len() {
                let remaining = data.len() - pos;
                // Chunk sizes biased small but occasionally large.
                let max = remaining.min(if rng.below(4) == 0 { 1024 } else { 96 });
                let take = if max == 0 { 0 } else { 1 + rng.below(max) };
                chunks.push(&data[pos..pos + take]);
                pos += take;
            }
            if chunks.is_empty() {
                chunks.push(&data[..]);
            }

            let expected = oracle_oneshot(&data);
            let expected_stream = oracle_streaming(&chunks);
            assert_eq!(
                expected, expected_stream,
                "oracle self-consistency (size {size})"
            );

            let mut h = Blake2spState::new();
            for chunk in &chunks {
                h.update(chunk);
            }
            assert_eq!(
                h.finalize(),
                expected,
                "SIMD streaming split mismatch (size {size})"
            );

            let mut s = Blake2spState::new();
            for chunk in &chunks {
                s.update_scalar(chunk);
            }
            assert_eq!(
                s.finalize_scalar(),
                expected,
                "scalar streaming split mismatch (size {size})"
            );

            cases += 1;
        }
    }
    assert!(
        cases >= 200,
        "expected >=200 randomized split cases, got {cases}"
    );
}

/// Random one-shot inputs up to 4 MiB, both backends vs the oracle.
#[test]
fn random_large_oneshot() {
    let mut rng = SplitMix64::new(0xDEAD_BEEF_CAFE_F00D);
    // A spread of sizes including up to 4 MiB.
    let sizes = [
        1_000usize,
        4_095,
        4_096,
        4_097,
        100_000,
        1_048_576,
        1_500_000,
        4 * 1024 * 1024,
    ];
    for &size in &sizes {
        let mut data = vec![0u8; size];
        rng.fill(&mut data);
        let expected = oracle_oneshot(&data);

        assert_eq!(
            ours_oneshot_simd(&data),
            expected,
            "SIMD large one-shot mismatch at size {size}"
        );
        assert_eq!(
            ours_oneshot_scalar(&data),
            expected,
            "scalar large one-shot mismatch at size {size}"
        );
    }
}

/// Idempotent finalize: calling `finalize` twice (and updating in between)
/// matches the oracle, mirroring `blake2s_simd`'s idempotency contract.
#[test]
fn finalize_is_idempotent() {
    let data = painted(1000);
    let (head, tail) = data.split_at(377);

    let mut h = Blake2spState::new();
    h.update(head);
    let mid = h.finalize();
    let mid_again = h.finalize();
    assert_eq!(mid, mid_again, "finalize not idempotent before more input");
    assert_eq!(mid, oracle_oneshot(head), "partial finalize mismatch");

    h.update(tail);
    let full = h.finalize();
    assert_eq!(
        full,
        h.finalize(),
        "finalize not idempotent after more input"
    );
    assert_eq!(full, oracle_oneshot(&data), "full finalize mismatch");
}

/// Known-answer vector from `blake2s_simd`'s own doctest, to catch any drift in
/// the whole pipeline independent of the oracle call.
#[test]
fn known_answer_foo() {
    // From blake2s_simd::blake2sp::blake2sp doc example.
    let expected_hex = "050dc5786037ea72cb9ed9d0324afcab03c97ec02e8c47368fc5dfb4cf49d8c9";
    let got = super::hash(b"foo");
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got_hex, expected_hex);

    let got_scalar = ours_oneshot_scalar(b"foo");
    let got_scalar_hex: String = got_scalar.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(got_scalar_hex, expected_hex);
}
