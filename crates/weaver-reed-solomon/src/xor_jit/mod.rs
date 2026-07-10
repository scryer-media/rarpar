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
pub mod codegen512;
pub mod deps;
pub mod emit;
pub mod memory;
pub mod transpose;
pub mod transpose512;

/// JIT tier width: the AVX2 512-byte-block tier or the AVX512 1024-byte-block
/// tier ([`codegen512`]). Consumers (weaver-par2's streaming tier) hold one of
/// these and use its methods so the tier plumbing stays width-generic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JitWidth {
    Avx2,
    Avx512,
}

impl JitWidth {
    /// Pick the widest supported JIT tier, mirroring upstream's (non-SLIM)
    /// preference for the AVX512 JIT over the AVX2 one on AVX512-no-GFNI
    /// hardware (ParPar gf16mul.cpp default_method). Setting
    /// `WEAVER_GF16_XORJIT_512=0` pins the AVX2 tier so the two can be A/B'd
    /// (and the new tier disabled) without a rebuild — same escape-hatch
    /// pattern as `WEAVER_GF16_FOLDED_AVX512`.
    pub fn detect() -> Option<JitWidth> {
        if supported_512() && jit512_enabled() {
            Some(JitWidth::Avx512)
        } else if supported() {
            Some(JitWidth::Avx2)
        } else {
            None
        }
    }

    /// Planar block size this width consumes.
    pub const fn block_bytes(self) -> usize {
        match self {
            JitWidth::Avx2 => transpose::BLOCK_BYTES,
            JitWidth::Avx512 => transpose512::BLOCK_BYTES,
        }
    }

    /// Build the JIT'd muladd body for `factor` (None for factor 0).
    pub fn build_muladd(self, factor: u16) -> std::io::Result<Option<memory::JitCode>> {
        match self {
            JitWidth::Avx2 => build_muladd(factor),
            JitWidth::Avx512 => build_muladd_512(factor),
        }
    }

    /// Transpose one block (`block_bytes` long) into planar layout.
    ///
    /// # Safety
    /// AVX2 required; slice lengths must equal [`Self::block_bytes`].
    pub unsafe fn prepare_block(self, src: &[u8], dst: &mut [u8]) {
        unsafe {
            match self {
                JitWidth::Avx2 => transpose::prepare_block(
                    src.first_chunk().expect("src block size"),
                    dst.first_chunk_mut().expect("dst block size"),
                ),
                JitWidth::Avx512 => transpose512::prepare_block(
                    src.first_chunk().expect("src block size"),
                    dst.first_chunk_mut().expect("dst block size"),
                ),
            }
        }
    }

    /// Invert [`Self::prepare_block`] in place.
    ///
    /// # Safety
    /// AVX2 required; `buf` length must equal [`Self::block_bytes`].
    pub unsafe fn finish_block(self, buf: &mut [u8]) {
        unsafe {
            match self {
                JitWidth::Avx2 => {
                    transpose::finish_block(buf.first_chunk_mut().expect("block size"))
                }
                JitWidth::Avx512 => {
                    transpose512::finish_block(buf.first_chunk_mut().expect("block size"))
                }
            }
        }
    }

    /// Run a muladd body built by [`Self::build_muladd`] over `len` planar
    /// bytes (`len % block_bytes == 0`).
    ///
    /// # Safety
    /// Per [`memory::JitCode::run_muladd`] / [`memory::JitCode::run_muladd_512`]
    /// for the corresponding width.
    pub unsafe fn run_muladd(
        self,
        code: &memory::JitCode,
        src: *const u8,
        dst: *mut u8,
        len: usize,
    ) {
        unsafe {
            match self {
                JitWidth::Avx2 => code.run_muladd(src, dst, len),
                JitWidth::Avx512 => code.run_muladd_512(src, dst, len),
            }
        }
    }
}

/// `WEAVER_GF16_XORJIT_512=0` disables the AVX512 JIT tier (AVX2 tier and all
/// other tiers unaffected).
fn jit512_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("WEAVER_GF16_XORJIT_512").is_none_or(|v| v != "0"))
}

/// Whether the AVX512 XOR-JIT tier should run: AVX512BW+VL present, GFNI
/// absent (GFNI boxes use the affine kernels, which beat every XOR tier), not
/// under binary translation. Targets AVX512-without-GFNI silicon
/// (Skylake-X/-SP, Cascade Lake, Cannon Lake) — upstream's non-SLIM
/// default_method prefers the AVX512 JIT there; par2cmdline-turbo's SLIM
/// build compiles it out, so this tier goes beyond as-built upstream (like
/// rarpar's shuffle2x/affine2x ports already do).
pub fn supported_512() -> bool {
    // BW+VL is deliberately stricter than the kernel's AVX512F-only needs:
    // it matches the crate's other AVX512 gates and scopes the tier to
    // Skylake-X-class silicon (excluding AVX512F-only KNL/KNM, where this
    // schedule is untuned).
    std::is_x86_feature_detected!("avx512bw")
        && std::is_x86_feature_detected!("avx512vl")
        && !std::is_x86_feature_detected!("gfni")
        && !running_translated()
}

/// Build the AVX512 JIT'd muladd code for `factor` (`None` for factor 0).
pub fn build_muladd_512(factor: u16) -> std::io::Result<Option<memory::JitCode>> {
    if factor == 0 {
        return Ok(None);
    }
    let code = codegen512::generate_muladd(&deps::compute_deps(factor));
    Ok(Some(memory::JitCode::new(&code)?))
}

/// Whether the XOR-JIT tier should run: AVX2 present, GFNI absent, and not
/// running under binary translation. GFNI boxes use the faster affine folded
/// kernel; this tier targets pre-GFNI x86 (Zen1/2, pre-Ice-Lake Intel), where
/// it beats the shuffle2x tier ~1.4×.
///
/// The `!running_translated()` gate mirrors ParPar, which skips the JIT methods
/// when `isEmulated` (gf16mul.cpp:133-162): an x86_64 binary running under
/// Rosetta 2 on Apple Silicon would otherwise pick this tier and JIT native
/// x86 that the translator re-JITs on every emulated execution — catastrophic.
pub fn supported() -> bool {
    std::is_x86_feature_detected!("avx2")
        && !std::is_x86_feature_detected!("gfni")
        && !running_translated()
}

/// Whether this x86_64 process is executing under binary translation, in which
/// case the JIT tier must not be selected. Mirrors the Rosetta 2 arm of
/// ParPar's `isEmulated` check (gf16mul.cpp:133-162): translators re-JIT the
/// emitted native code on every emulated run, so the XOR-JIT / `canMemWX` fast
/// path becomes pathologically slow.
///
/// The result is cached: `supported()` may be called once per batch.
fn running_translated() -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::sync::OnceLock;

        static TRANSLATED: OnceLock<bool> = OnceLock::new();
        *TRANSLATED.get_or_init(|| {
            use std::os::raw::{c_char, c_int, c_void};

            // sysctlbyname(3) — declared locally so this crate keeps its
            // dependency-free surface (no libc). Read-only query, so newp/newlen
            // are null/0. Ref: Apple "About the Rosetta Translation Environment".
            unsafe extern "C" {
                fn sysctlbyname(
                    name: *const c_char,
                    oldp: *mut c_void,
                    oldlenp: *mut usize,
                    newp: *mut c_void,
                    newlen: usize,
                ) -> c_int;
            }

            let mut translated: c_int = 0;
            let mut size = std::mem::size_of::<c_int>();
            // NUL-terminated key name required by sysctlbyname.
            let name = c"sysctl.proc_translated";
            // SAFETY: `name` is a valid NUL-terminated C string; `oldp`/`oldlenp`
            // point at `translated` and its byte length; the query is read-only.
            let rc = unsafe {
                sysctlbyname(
                    name.as_ptr(),
                    (&raw mut translated).cast::<c_void>(),
                    &raw mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            // A non-zero return (ENOENT on a genuine pre-Rosetta Intel Mac, where
            // the key does not exist) means "not translated"; only
            // proc_translated == 1 signals a Rosetta 2 (translated) process.
            rc == 0 && translated == 1
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Only the Rosetta 2 case of ParPar's isEmulated is mirrored. User-mode
        // QEMU (the other x86-emulation vector, on Linux) is deliberately not
        // detected: reliable detection is fragile and the payoff is low.
        false
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_translated_probe_is_stable() {
        // This module is x86_64-only (see lib.rs), so this test only compiles
        // and runs on an x86_64 build. The probe result depends on the host —
        // an x86_64 test run on Apple Silicon executes under Rosetta 2 and
        // legitimately reports true — so assert the deterministic properties:
        // no panic, a cached/stable answer, and false where Rosetta cannot
        // exist.
        let first = running_translated();
        assert_eq!(first, running_translated());
        #[cfg(not(target_os = "macos"))]
        assert!(!first);
    }
}
