//! W^X executable memory + the non-standard-ABI call trampoline for the
//! XOR-JIT tier (see `scryer-docs/plans/125`).
//!
//! Generated code is written to a fresh anonymous mapping, then flipped to
//! read+execute before it is ever run — never simultaneously writable and
//! executable. The codegen input is only a u16 factor (no untrusted data), and
//! `memmap2` handles the platform specifics (Linux `mmap`/`mprotect`, Windows
//! `VirtualAlloc`/`VirtualProtect`).
//!
//! The JIT'd body uses ParPar's register convention (`rax`/`rcx`/`rdx`/`rsi`),
//! which matches no Rust extern ABI, so it is invoked via an `asm!` trampoline.
#![allow(unsafe_op_in_unsafe_fn)]

use memmap2::Mmap;

/// A block of finalized (read+execute) JIT'd machine code.
pub struct JitCode {
    /// Keeps the R+X mapping alive; `entry` points into it.
    _exec: Mmap,
    entry: *const u8,
}

// SAFETY: the code is immutable after construction and `entry` stays valid for
// the mapping's lifetime, so the handle is fine to share across threads.
unsafe impl Send for JitCode {}
unsafe impl Sync for JitCode {}

impl JitCode {
    /// Copy `code` into a fresh anonymous mapping and flip it to read+execute.
    pub fn new(code: &[u8]) -> std::io::Result<Self> {
        assert!(!code.is_empty(), "empty JIT code");
        let mut w = memmap2::MmapMut::map_anon(code.len())?;
        w.copy_from_slice(code);
        let exec = w.make_exec()?;
        let entry = exec.as_ptr();
        Ok(JitCode { _exec: exec, entry })
    }

    /// Execute the muladd body over the `len`-byte planar `src`/`dst` regions
    /// (`len` a multiple of 512). Convention: `rax=src-384, rdx=dst-384,
    /// rcx=dst_end-384`, `rsi` unused; the body advances one 512-byte block per
    /// iteration and `ret`s. `vzeroupper` clears the AVX upper state on return.
    ///
    /// # Safety
    /// `self` must hold a muladd body from [`super::codegen::generate_muladd`],
    /// AVX2 must be available, `src`/`dst` valid for `len` bytes, `len % 512 == 0`.
    pub unsafe fn run_muladd(&self, src: *const u8, dst: *mut u8, len: usize) {
        let rax = src.wrapping_sub(384);
        let rdx = dst.wrapping_sub(384);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(384);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) self.entry,
            inout("rax") rax => _,
            inout("rdx") rdx => _,
            inout("rsi") 0usize => _,
            in("rcx") rcx,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
        );
    }

    /// Execute an AVX512 muladd body ([`super::codegen512`]) over `len`-byte
    /// planar regions (`len` a multiple of 1024). Convention: `rax=src-1024,
    /// rdx=dst-1024, rcx=dst_end-1024` (no upstream `-384` bias — EVEX
    /// compressed disp8 covers the plane offsets); the body advances one
    /// 1024-byte block per iteration and `ret`s.
    ///
    /// # Safety
    /// `self` must hold a body from [`super::codegen512::generate_muladd`],
    /// AVX512BW+VL must be available, `src`/`dst` valid for `len` bytes,
    /// `len % 1024 == 0`.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn run_muladd_512(&self, src: *const u8, dst: *mut u8, len: usize) {
        let rax = src.wrapping_sub(1024);
        let rdx = dst.wrapping_sub(1024);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(1024);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) self.entry,
            inout("rax") rax => _,
            inout("rdx") rdx => _,
            inout("rsi") 0usize => _,
            in("rcx") rcx,
            out("zmm0") _, out("zmm1") _, out("zmm2") _, out("zmm3") _,
            out("zmm4") _, out("zmm5") _, out("zmm6") _, out("zmm7") _,
            out("zmm8") _, out("zmm9") _, out("zmm10") _, out("zmm11") _,
            out("zmm12") _, out("zmm13") _, out("zmm14") _, out("zmm15") _,
            out("zmm16") _, out("zmm17") _, out("zmm18") _, out("zmm19") _,
            out("zmm20") _, out("zmm21") _, out("zmm22") _, out("zmm23") _,
            out("zmm24") _, out("zmm25") _, out("zmm26") _, out("zmm27") _,
            out("zmm28") _, out("zmm29") _, out("zmm30") _, out("zmm31") _,
        );
    }
}
