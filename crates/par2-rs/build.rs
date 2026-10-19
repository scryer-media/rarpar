//! Names the MD5 backends the crate compiles, so the source says it once.
//!
//! - `par2_md5_asm`: the in-crate assembly MD5 (`md5_asm`), on x86-64 and
//!   little-endian AArch64 with `crypto-native` on.
//! - `par2_md5_rustcrypto`: the RustCrypto `md-5` backend, with `crypto-rust`
//!   on or on any target the assembly does not cover.

use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(par2_bench_diagnostics)");
    println!("cargo::rustc-check-cfg=cfg(par2_md5_asm)");
    println!("cargo::rustc-check-cfg=cfg(par2_md5_rustcrypto)");
    println!("cargo::rerun-if-env-changed=PAR2_BENCH_DIAGNOSTICS");
    if env::var_os("PAR2_BENCH_DIAGNOSTICS").is_some() {
        println!("cargo::rustc-cfg=par2_bench_diagnostics");
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap_or_default();
    let asm_target = arch == "x86_64" || (arch == "aarch64" && endian == "little");
    let native = env::var_os("CARGO_FEATURE_CRYPTO_NATIVE").is_some();
    let rust = env::var_os("CARGO_FEATURE_CRYPTO_RUST").is_some();
    if asm_target && native {
        println!("cargo::rustc-cfg=par2_md5_asm");
    }
    if rust || !asm_target {
        println!("cargo::rustc-cfg=par2_md5_rustcrypto");
    }
}
