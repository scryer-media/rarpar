//! Throughput bench for the GF(2^16) multiply-accumulate region kernel.
//!
//! `mul_acc_region` dispatches at compile time: on wasm32 with `+simd128` it uses
//! the wasm SIMD kernel, otherwise the scalar fallback; on native it uses NEON /
//! x86 kernels. Build for each target/flavor and run under `wasmtime` (or
//! natively) to compare. `std::time::Instant` works under wasip1.
//!
//! Build + run (wasm, both flavors) — the GF log tables need a larger stack:
//!   RUSTFLAGS="-C target-feature=+simd128 -C link-arg=-zstack-size=8388608" \
//!     cargo build --release --example gf_wasm_bench --target wasm32-wasip1 -p weaver-reed-solomon
//!   wasmtime run target/wasm32-wasip1/release/examples/gf_wasm_bench.wasm
//! Scalar flavor: drop `+simd128` from RUSTFLAGS (keep the stack-size arg).

use std::time::Instant;
use weaver_reed_solomon::gf_simd::mul_acc_region;

/// Region size per call (heap-allocated; large enough to amortize per-call table
/// precompute to negligible).
const REGION: usize = 16 * 1024 * 1024;
/// Total bytes processed per timed round (throughput = this / elapsed).
const TOTAL: usize = 2 * 1024 * 1024 * 1024;
const ITERS: usize = TOTAL / REGION;
const ROUNDS: usize = 3;
/// A non-trivial GF factor (not 0/1) so the real kernel path runs.
const FACTOR: u16 = 0xABCD;

fn main() {
    let src = vec![0x5Au8; REGION];
    let mut dst = vec![0u8; REGION];

    // Warm up (also forces the GF log-table LazyLock init out of the timed path).
    mul_acc_region(FACTOR, &src, &mut dst);

    let mut best_mbps = 0.0f64;
    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..ITERS {
            mul_acc_region(FACTOR, &src, &mut dst);
        }
        let secs = start.elapsed().as_secs_f64();
        let mbps = (ITERS * REGION) as f64 / secs / 1.0e6;
        if mbps > best_mbps {
            best_mbps = mbps;
        }
    }

    // Consume dst so the loop can't be optimized away.
    let sink = dst.iter().fold(0u8, |a, &b| a ^ b);
    println!("gf_mul_acc\t{best_mbps:.2}\t(sink={sink})");
}
