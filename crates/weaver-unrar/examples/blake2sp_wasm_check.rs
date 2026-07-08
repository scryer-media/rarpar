//! wasm32 validation harness for the BLAKE2sp `simd128` kernel.
//!
//! Runs the BLAKE2sp differential corpus (the same one the native unit tests
//! use) against the `blake2s_simd` oracle, driving whichever SIMD backend the
//! build selected. Built for `wasm32-wasip1` with `-Ctarget-feature=+simd128`
//! and run under `wasmtime`, it exercises the `simd128` backend byte-for-byte.
//!
//! Prints a one-line `PASS`/`FAIL` summary and exits non-zero on any mismatch,
//! so it doubles as a CI gate.
//!
//! Build & run (from the workspace root):
//!   RUSTFLAGS="-C target-feature=+simd128" \
//!     cargo build --release --example blake2sp_wasm_check \
//!       -p weaver-unrar --no-default-features --features crypto-rust \
//!       --target wasm32-wasip1
//!   wasmtime run target/wasm32-wasip1/release/examples/blake2sp_wasm_check.wasm

#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
))]
fn main() {
    let report = weaver_unrar::crypto::differential_corpus();
    match report.first_mismatch {
        None => {
            println!(
                "PASS blake2sp simd128 vs oracle: oneshot={} streaming={}",
                report.oneshot_ok, report.streaming_ok
            );
        }
        Some((label, ours, oracle)) => {
            let hex = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
            eprintln!(
                "FAIL blake2sp simd128 mismatch at {label}\n  ours  = {}\n  oracle= {}",
                hex(&ours),
                hex(&oracle)
            );
            std::process::exit(1);
        }
    }
}

#[cfg(not(any(
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
fn main() {
    eprintln!("SKIP blake2sp SIMD differential corpus is not built for this target");
}
