//! `par3_unoptimized` marks an opt-level 0 build, whose stack frames are far
//! larger than an optimised one's; `gf.rs` keys the grouped GF(2^16) kernel on
//! it rather than on debug assertions, which a profile can switch off
//! independently.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(par3_unoptimized)");
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo::rustc-cfg=par3_unoptimized");
    }
}
