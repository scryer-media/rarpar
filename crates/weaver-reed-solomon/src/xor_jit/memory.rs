//! W^X executable memory + the non-standard-ABI call trampoline for the
//! XOR-JIT tier.
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
use std::sync::Arc;

/// A block of finalized (read+execute) JIT'd machine code.
pub struct JitCode {
    /// Keeps the R+X mapping alive; `entry` points into it.
    _exec: Arc<Mmap>,
    entry: *const u8,
}

// SAFETY: the code is immutable after construction and `entry` stays valid for
// the mapping's lifetime, so the handle is fine to share across threads.
unsafe impl Send for JitCode {}
unsafe impl Sync for JitCode {}

impl Clone for JitCode {
    fn clone(&self) -> Self {
        Self {
            _exec: Arc::clone(&self._exec),
            entry: self.entry,
        }
    }
}

#[cfg(test)]
pub(crate) fn shares_mapping(left: &JitCode, right: &JitCode) -> bool {
    Arc::ptr_eq(&left._exec, &right._exec)
}

impl JitCode {
    /// Copy `code` into a fresh anonymous mapping and flip it to read+execute.
    pub fn new(code: &[u8]) -> std::io::Result<Self> {
        assert!(!code.is_empty(), "empty JIT code");
        let mut w = memmap2::MmapMut::map_anon(code.len())?;
        w.copy_from_slice(code);
        let exec = Arc::new(w.make_exec()?);
        let entry = exec.as_ptr();
        Ok(JitCode { _exec: exec, entry })
    }

    /// Pack several generated bodies into one mapping and finalize the whole
    /// arena with a single W-to-X transition. Entries are cache-line aligned;
    /// the returned handles share ownership of the immutable executable map.
    pub fn new_batch(codes: &[Vec<u8>]) -> std::io::Result<Vec<Self>> {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        assert!(codes.iter().all(|code| !code.is_empty()), "empty JIT code");

        const CODE_ALIGNMENT: usize = 64;
        let mut offsets = Vec::with_capacity(codes.len());
        let mut total = 0usize;
        for code in codes {
            total = total
                .checked_add(CODE_ALIGNMENT - 1)
                .map(|value| value & !(CODE_ALIGNMENT - 1))
                .and_then(|value| value.checked_add(code.len()))
                .ok_or_else(|| std::io::Error::other("JIT code arena size overflow"))?;
            offsets.push(total - code.len());
        }

        let mut writable = memmap2::MmapMut::map_anon(total)?;
        for (code, &offset) in codes.iter().zip(&offsets) {
            writable[offset..offset + code.len()].copy_from_slice(code);
        }
        let exec = Arc::new(writable.make_exec()?);
        let base = exec.as_ptr();
        Ok(offsets
            .into_iter()
            .map(|offset| Self {
                _exec: Arc::clone(&exec),
                // SAFETY: every offset was allocated within `exec`, and the
                // shared Arc keeps the mapping alive for every entry handle.
                entry: unsafe { base.add(offset) },
            })
            .collect())
    }

    /// Execute the muladd body over the `len`-byte planar `src`/`dst` regions
    /// (`len` a multiple of 512). Convention: `rax=src-384, rdx=dst-384,
    /// rcx=dst_end-384`, `rsi` is reserved for the optional dedicated
    /// prefetch stream; the body advances one 512-byte block per iteration
    /// and `ret`s. `vzeroupper` clears the AVX upper state on return.
    ///
    /// # Safety
    /// `self` must hold a muladd body from [`super::codegen::generate_muladd`]
    /// or the packed optional-prefetch generator, AVX2 must be available,
    /// `src`/`dst` valid for `len` bytes, and `len % 512 == 0`.
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

    /// Execute an AVX2 body generated with `prefetch = true`. Turbo's
    /// `gf16_xor_jit_mul_avx2_base` passes `prefetch - 128` in `rsi`; the body
    /// advances that stream by 256 bytes and emits four T1 hints per block.
    ///
    /// # Safety
    /// This handle must contain an AVX2 prefetch body or packed
    /// optional-prefetch body, and AVX2 must be available. `src` must be
    /// readable and `dst` writable for `len` non-overlapping bytes, with `len`
    /// a multiple of 512. `prefetch` must support every address hinted while
    /// processing those bytes.
    pub unsafe fn run_muladd_prefetch(
        &self,
        src: *const u8,
        dst: *mut u8,
        len: usize,
        prefetch: *const u8,
    ) {
        let rax = src.wrapping_sub(384);
        let rdx = dst.wrapping_sub(384);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(384);
        let rsi = prefetch.wrapping_sub(128);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) self.entry,
            inout("rax") rax => _,
            inout("rdx") rdx => _,
            inout("rsi") rsi => _,
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

    /// Execute an AVX512 single-source body with Turbo's dedicated prefetch
    /// stream. The body advances `rsi` by 512 bytes and uses the eight hints
    /// from `gf16_xor_avx512.c:262-268`; the trampoline seeds it at
    /// `prefetch - 384` as the oracle does at lines 751-761.
    ///
    /// # Safety
    /// This handle must contain an AVX512 prefetch body from
    /// [`super::codegen512::generate_muladd_with_prefetch`], and the selected
    /// AVX512F/BW/VL tier must be available. `src` must be readable and `dst`
    /// writable for `len` non-overlapping bytes, with `len` a multiple of
    /// 1024. `prefetch` must support every address hinted while processing
    /// those bytes.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn run_muladd_prefetch_512(
        &self,
        src: *const u8,
        dst: *mut u8,
        len: usize,
        prefetch: *const u8,
    ) {
        let rax = src.wrapping_sub(1024);
        let rdx = dst.wrapping_sub(1024);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(1024);
        let rsi = prefetch.wrapping_sub(384);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) self.entry,
            inout("rax") rax => _,
            inout("rdx") rdx => _,
            inout("rsi") rsi => _,
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

    /// Execute an AVX512 packed multi-source body. Source zero is in `rdx`,
    /// followed by `rsi`, `rdi`, `r8`, `r9`, and `r10`, matching Turbo's
    /// multi-region stub register order. The code itself is immutable RX.
    ///
    /// # Safety
    /// This handle must contain the AVX512 prefix body generated for exactly
    /// `sources.len()` entries by [`super::codegen512::generate_muladd_multi`],
    /// and the selected AVX512F/BW/VL tier must be available. There must be
    /// one to six sources; each must be readable for `len` bytes, `dst` must
    /// be writable for `len` bytes, all ranges must be non-overlapping, and
    /// `len` must be a multiple of 1024.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn run_muladd_multi_512(&self, sources: &[*const u8], dst: *mut u8, len: usize) {
        assert!(!sources.is_empty() && sources.len() <= 6);
        let rax = dst.wrapping_sub(1024);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(1024);
        let rdx = sources[0].wrapping_sub(1024);
        let rsi = sources
            .get(1)
            .copied()
            .unwrap_or(std::ptr::null())
            .wrapping_sub(1024);
        let rdi = sources
            .get(2)
            .copied()
            .unwrap_or(std::ptr::null())
            .wrapping_sub(1024);
        let r8 = sources
            .get(3)
            .copied()
            .unwrap_or(std::ptr::null())
            .wrapping_sub(1024);
        let r9 = sources
            .get(4)
            .copied()
            .unwrap_or(std::ptr::null())
            .wrapping_sub(1024);
        let r10 = sources
            .get(5)
            .copied()
            .unwrap_or(std::ptr::null())
            .wrapping_sub(1024);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) self.entry,
            inout("rax") rax => _,
            in("rcx") rcx,
            inout("rdx") rdx => _,
            inout("rsi") rsi => _,
            inout("rdi") rdi => _,
            inout("r8") r8 => _,
            inout("r9") r9 => _,
            inout("r10") r10 => _,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_entries_share_one_finalized_aligned_mapping() {
        let entries = JitCode::new_batch(&[vec![0xc3], vec![0x90, 0xc3]]).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(Arc::ptr_eq(&entries[0]._exec, &entries[1]._exec));
        assert_eq!((entries[0].entry as usize) % 64, 0);
        assert_eq!((entries[1].entry as usize) % 64, 0);
        assert!(entries[1].entry as usize >= entries[0].entry as usize + 64);
    }

    #[test]
    fn empty_batch_needs_no_executable_mapping() {
        assert!(JitCode::new_batch(&[]).unwrap().is_empty());
    }
}
