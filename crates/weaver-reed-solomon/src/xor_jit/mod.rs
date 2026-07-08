//! XOR-JIT GF(2^16) multiply tier for pre-GFNI x86 (see `scryer-docs/plans/125`).
//!
//! Runtime-dispatched when AVX2 is present but GFNI is not. Reconstruction
//! multiply is JIT-generated as bit-plane XOR sequences, which run on the four
//! vector-ALU ports instead of the two shuffle ports that bound the shuffle2x
//! tier — matching the method ParPar/par2cmdline-turbo auto-selects on AMD.
//!
//! Build order (each phase validated before the next):
//! 1. [`emit`] — the x86-64 machine-code emitter (byte-exact unit tests).
//! 2. `memory` — W^X executable buffers.
//! 3. `transpose` — the 16-plane bit-transpose prepare/finish.
//! 4. `deps` + `codegen` — factor -> vpxor schedule.

pub mod codegen;
pub mod deps;
pub mod emit;
pub mod memory;
pub mod transpose;

/// Whether the XOR-JIT tier should run: AVX2 present but GFNI absent. GFNI
/// boxes use the faster affine folded kernel; this tier targets pre-GFNI x86
/// (Zen1/2, pre-Ice-Lake Intel), where it beats the shuffle2x tier ~1.4×.
pub fn supported() -> bool {
    std::is_x86_feature_detected!("avx2") && !std::is_x86_feature_detected!("gfni")
}

/// Build the JIT'd muladd code for `factor` (returns `None` for factor 0, which
/// contributes nothing). `Err` if executable memory could not be allocated —
/// callers fall back to the shuffle2x tier.
pub fn build_muladd(factor: u16) -> std::io::Result<Option<memory::JitCode>> {
    if factor == 0 {
        return Ok(None);
    }
    let code = codegen::generate_muladd(&deps::compute_deps(factor));
    Ok(Some(memory::JitCode::new(&code)?))
}
