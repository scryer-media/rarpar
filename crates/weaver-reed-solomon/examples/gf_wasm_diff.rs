//! Differential validation harness for the wasm simd128 / relaxed-simd GF(2^16)
//! multiply-accumulate kernel.
//!
//! The wasm SIMD kernel (`mul_acc_region_wasm_simd128`) is only reachable on the
//! wasm target and cannot run natively, so this example is the sole way to
//! validate it. Build it for `wasm32-wasip1` and run under `wasmtime`:
//!
//! ```sh
//! # plain simd128 (i8x16_swizzle path)
//! RUSTFLAGS="-C target-feature=+simd128" \
//!   cargo build -p weaver-reed-solomon --example gf_wasm_diff --target wasm32-wasip1
//! wasmtime target/wasm32-wasip1/debug/examples/gf_wasm_diff.wasm
//!
//! # relaxed-simd (i8x16_relaxed_swizzle path)
//! RUSTFLAGS="-C target-feature=+simd128,+relaxed-simd" \
//!   cargo build -p weaver-reed-solomon --example gf_wasm_diff --target wasm32-wasip1
//! wasmtime target/wasm32-wasip1/debug/examples/gf_wasm_diff.wasm
//! ```
//!
//! `mul_acc_region` dispatches to the wasm kernel at compile time based on the
//! `target_feature` set, so the artifact flavor (swizzle vs relaxed_swizzle) is
//! whichever RUSTFLAGS built it. The harness compares that kernel byte-for-byte
//! against an independent scalar oracle built only from the public `gf` API. A
//! single mismatch is a real bug and aborts with the exact (factor, length,
//! offset).
//!
//! Also compiles and runs natively (where `mul_acc_region` uses the native
//! kernel) so the corpus itself stays exercised on CI without wasmtime, but the
//! wasm kernel is only meaningfully covered under wasmtime.
//!
//! Benchmarking note (not part of this correctness harness): the crate's GF
//! throughput benches live in `weaver-par2` (criterion, native-only). A wasm GF
//! timing harness does not fit criterion — the wasm kernel only runs under
//! wasmtime — so it would slot in as a sibling `examples/gf_wasm_bench.rs` here
//! that loops `mul_acc_region` over a large fixed buffer and reports bytes/sec,
//! run via `wasmtime` under both `+simd128` and `+simd128,+relaxed-simd`. Do NOT
//! add or run that here; the orchestrator runs benches separately.

use std::process::ExitCode;

use weaver_reed_solomon::gf;
use weaver_reed_solomon::gf_simd::mul_acc_region;

/// Independent scalar oracle: `dst[w] ^= gf_mul(src[w], factor)` per LE u16
/// word, using only the public field API. Mirrors the crate-private
/// `mul_acc_region_scalar` exactly, but is written from scratch here so the
/// differential does not lean on the same private code path it validates.
fn scalar_oracle(factor: u16, src: &[u8], dst: &mut [u8]) {
    if factor == 0 {
        return;
    }
    let word_count = src.len() / 2;
    for w in 0..word_count {
        let s = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
        let d = u16::from_le_bytes([dst[w * 2], dst[w * 2 + 1]]);
        let result = gf::add(d, gf::mul(s, factor));
        let bytes = result.to_le_bytes();
        dst[w * 2] = bytes[0];
        dst[w * 2 + 1] = bytes[1];
    }
}

/// Deterministic, dependency-free PRNG (SplitMix64). Seeded, so every run — and
/// both wasm flavors — sees the identical corpus.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let chunk = self.next_u64().to_le_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i + take].copy_from_slice(&chunk[..take]);
            i += take;
        }
    }

    /// Uniform-ish nonzero factor in 2..=0xFFFF (the values the SIMD kernel
    /// actually handles; 0 and 1 short-circuit before dispatch).
    fn next_factor(&mut self) -> u16 {
        let v = (self.next_u64() & 0xFFFF) as u16;
        if v < 2 { v + 2 } else { v }
    }
}

/// Compare the dispatched kernel against the scalar oracle over one buffer.
/// Returns Err with the first mismatching byte offset on failure.
fn check_one(factor: u16, src: &[u8], dst_init: &[u8]) -> Result<(), usize> {
    let mut dst_kernel = dst_init.to_vec();
    let mut dst_oracle = dst_init.to_vec();

    mul_acc_region(factor, src, &mut dst_kernel);
    scalar_oracle(factor, src, &mut dst_oracle);

    match dst_kernel
        .iter()
        .zip(dst_oracle.iter())
        .position(|(a, b)| a != b)
    {
        Some(off) => Err(off),
        None => Ok(()),
    }
}

fn main() -> ExitCode {
    let mut rng = SplitMix64::new(0x5EED_2016_0707_2016);
    let mut cases: u64 = 0;

    // --- Gate 1: ALL 65536 factors over a fixed pseudo-random 4096-byte buffer.
    {
        let mut src = vec![0u8; 4096];
        let mut seed = SplitMix64::new(0xABCD_1234_5678_9EF0);
        seed.fill_bytes(&mut src);
        // A fixed, non-trivial initial dst so the XOR-accumulate is exercised.
        let mut dst_init = vec![0u8; 4096];
        seed.fill_bytes(&mut dst_init);

        for factor in 0..=0xFFFFu16 {
            if let Err(off) = check_one(factor, &src, &dst_init) {
                eprintln!(
                    "MISMATCH (gate 1: all-factors): factor={factor:#06x} len=4096 offset={off}"
                );
                return ExitCode::FAILURE;
            }
            cases += 1;
        }
    }
    let gate1_cases = cases;
    println!("gate 1 (all 65536 factors, len=4096): {gate1_cases} cases OK");

    // --- Gate 2: random buffers across lengths that exercise the 16-byte main
    //     loop AND the scalar tail, with random factors. Lengths are always even
    //     (API contract). Each length is retried across several random factors
    //     and random buffer contents.
    let mut lengths: Vec<usize> = (0..=64).step_by(2).collect();
    lengths.extend_from_slice(&[18, 30, 62, 130, 1022, 4094, 64 * 1024, 1024 * 1024]);

    let gate2_start = cases;
    for &len in &lengths {
        // Multiple random (factor, buffer) trials per length. Fewer trials for
        // the two big buffers to keep the wasmtime run brisk while still
        // covering the main loop at scale.
        let trials = if len >= 64 * 1024 { 4 } else { 24 };
        for _ in 0..trials {
            let mut src = vec![0u8; len];
            let mut dst_init = vec![0u8; len];
            rng.fill_bytes(&mut src);
            rng.fill_bytes(&mut dst_init);
            let factor = rng.next_factor();

            if let Err(off) = check_one(factor, &src, &dst_init) {
                eprintln!(
                    "MISMATCH (gate 2: lengths): factor={factor:#06x} len={len} offset={off}"
                );
                return ExitCode::FAILURE;
            }
            cases += 1;
        }
    }
    println!(
        "gate 2 (random lengths incl. tail + large): {} cases OK over {} lengths",
        cases - gate2_start,
        lengths.len()
    );

    // --- Gate 2b: sweep offsets of the scalar tail explicitly. For a buffer of
    //     16*k + tail bytes, the tail is `tail` bytes at offset 16*k. Cover
    //     every even tail length 0..=14 on top of a couple of full main-loop
    //     iterations, so the boundary between vector body and scalar remainder
    //     is checked at each residue.
    let gate2b_start = cases;
    for k in 0..3usize {
        for tail in (0..16).step_by(2) {
            let len = 16 * k + tail;
            if len == 0 {
                // Still exercise the empty buffer once (no-op path).
                let factor = rng.next_factor();
                if check_one(factor, &[], &[]).is_err() {
                    eprintln!("MISMATCH (gate 2b: empty): factor={factor:#06x} len=0");
                    return ExitCode::FAILURE;
                }
                cases += 1;
                continue;
            }
            let mut src = vec![0u8; len];
            let mut dst_init = vec![0u8; len];
            rng.fill_bytes(&mut src);
            rng.fill_bytes(&mut dst_init);
            let factor = rng.next_factor();
            if let Err(off) = check_one(factor, &src, &dst_init) {
                eprintln!(
                    "MISMATCH (gate 2b: tail residue): factor={factor:#06x} len={len} offset={off}"
                );
                return ExitCode::FAILURE;
            }
            cases += 1;
        }
    }
    println!(
        "gate 2b (tail-residue boundary sweep): {} cases OK",
        cases - gate2b_start
    );

    // Report which flavor was compiled in, so the two wasmtime runs are
    // distinguishable in logs.
    let flavor = if cfg!(all(target_arch = "wasm32", target_feature = "relaxed-simd")) {
        "wasm simd128 + relaxed-simd (i8x16_relaxed_swizzle)"
    } else if cfg!(all(target_arch = "wasm32", target_feature = "simd128")) {
        "wasm simd128 (i8x16_swizzle)"
    } else if cfg!(all(target_arch = "wasm32", not(target_feature = "simd128"))) {
        "wasm scalar fallback (no simd128)"
    } else {
        "native kernel"
    };

    println!("PASS: {cases} total cases byte-exact vs scalar oracle [{flavor}]");
    ExitCode::SUCCESS
}
