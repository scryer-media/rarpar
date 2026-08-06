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

use memmap2::{Mmap, MmapMut};
use std::sync::Arc;

/// Turbo reserves one 4 KiB mutable code page for each repair worker.  The
/// page is intentionally small enough to hold one bounded AVX2 body and its
/// fixed setup, rather than an archive-sized coefficient cache.
pub(crate) const WORKER_JIT_BYTES: usize = 4096;

/// Probe the strict W^X transition sequence used by repair workers.
///
/// The mapping is never writable and executable at the same time. Returning
/// to writable state matters because workers rotate through RW -> RX -> RW for
/// every generated coefficient body.
pub(crate) fn preflight_wx() -> std::io::Result<()> {
    let writable = MmapMut::map_anon(WORKER_JIT_BYTES)?;
    let executable = writable.make_exec()?;
    let _writable = executable.make_mut()?;
    Ok(())
}

/// A block of finalized (read+execute) JIT'd machine code.
pub struct JitCode {
    /// Keeps the R+X mapping alive; `entry` points into it.
    _exec: Arc<Mmap>,
    entry: *const u8,
}

/// One worker's rotating code page.
///
/// Turbo overwrites a worker-local scratch program for each multiply-add.
/// This stricter adaptation owns exactly one mapping and alternates its
/// protection between writable and executable states.  There is never a
/// writable executable alias, and a failed transition discards the mapping so
/// the next body can recover with a fresh anonymous page.
pub(crate) struct WorkerJitBuffer {
    writable: Option<MmapMut>,
    executable: Option<Mmap>,
    capacity: usize,
}

impl Default for WorkerJitBuffer {
    fn default() -> Self {
        Self::new(WORKER_JIT_BYTES)
    }
}

impl WorkerJitBuffer {
    pub(crate) const fn new(capacity: usize) -> Self {
        Self {
            writable: None,
            executable: None,
            capacity,
        }
    }

    fn writable_mapping(&mut self) -> std::io::Result<MmapMut> {
        if let Some(writable) = self.writable.take() {
            return Ok(writable);
        }
        if let Some(executable) = self.executable.take() {
            return executable.make_mut();
        }
        MmapMut::map_anon(self.capacity)
    }

    fn seal(&mut self, code: &[u8]) -> std::io::Result<*const u8> {
        if code.is_empty() || code.len() > self.capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "worker JIT body does not fit its bounded scratch page",
            ));
        }

        let mut writable = self.writable_mapping()?;
        writable[..code.len()].copy_from_slice(code);
        match writable.make_exec() {
            Ok(executable) => {
                let entry = executable.as_ptr();
                self.executable = Some(executable);
                Ok(entry)
            }
            Err(error) => {
                // `make_exec` consumes the writable handle. Do not retain a
                // partially transitioned mapping; a later request will map a
                // clean page and can retry independently.
                self.writable = None;
                self.executable = None;
                Err(error)
            }
        }
    }

    fn make_writable(&mut self) -> std::io::Result<()> {
        if self.writable.is_some() {
            return Ok(());
        }
        let Some(executable) = self.executable.take() else {
            return Ok(());
        };
        match executable.make_mut() {
            Ok(writable) => {
                self.writable = Some(writable);
                Ok(())
            }
            Err(error) => {
                self.writable = None;
                Err(error)
            }
        }
    }

    /// Execute one normal multiply-add body and return the page to its
    /// writable state before the worker accepts another coefficient.
    pub(crate) unsafe fn run_muladd(
        &mut self,
        code: &[u8],
        src: *const u8,
        dst: *mut u8,
        len: usize,
    ) -> std::io::Result<()> {
        let entry = self.seal(code)?;
        JitCode::run_muladd_entry(entry, src, dst, len);
        // This transition happens after the body has updated `dst`. Returning
        // its error is still important: the repair controller must abandon
        // the staged output rather than accept an operation whose JIT scratch
        // lifecycle became unhealthy. The failed mapping is already dropped,
        // so a later operation can acquire a fresh page.
        self.make_writable()
    }

    /// Execute one prefetching multiply-add body and return the page to RW.
    pub(crate) unsafe fn run_muladd_prefetch(
        &mut self,
        code: &[u8],
        src: *const u8,
        dst: *mut u8,
        len: usize,
        prefetch: *const u8,
    ) -> std::io::Result<()> {
        let entry = self.seal(code)?;
        JitCode::run_muladd_prefetch_entry(entry, src, dst, len, prefetch);
        self.make_writable()
    }

    #[cfg(test)]
    pub(crate) fn mapping_address(&self) -> Option<*const u8> {
        self.writable
            .as_ref()
            .map(|mapping| mapping.as_ptr())
            .or_else(|| self.executable.as_ref().map(|mapping| mapping.as_ptr()))
    }

    #[cfg(test)]
    pub(crate) fn is_writable(&self) -> bool {
        self.writable.is_some()
    }
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
        Ok(Self::new_batch_reusing(codes, None)?.0)
    }

    pub(crate) fn new_batch_reusing(
        codes: &[Vec<u8>],
        reusable: Option<MmapMut>,
    ) -> std::io::Result<(Vec<Self>, Option<Arc<Mmap>>)> {
        if codes.is_empty() {
            return Ok((Vec::new(), None));
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

        let mut bytes = vec![0u8; total];
        for (code, &offset) in codes.iter().zip(&offsets) {
            bytes[offset..offset + code.len()].copy_from_slice(code);
        }
        Self::new_arena_reusing(&bytes, &offsets, reusable)
    }

    pub(crate) fn new_arena_reusing(
        bytes: &[u8],
        offsets: &[usize],
        reusable: Option<MmapMut>,
    ) -> std::io::Result<(Vec<Self>, Option<Arc<Mmap>>)> {
        if offsets.is_empty() {
            return Ok((Vec::new(), None));
        }
        if bytes.is_empty() || offsets.iter().any(|&offset| offset >= bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid JIT code arena entries",
            ));
        }

        let mut writable = match reusable {
            Some(mapping) if mapping.len() >= bytes.len() => mapping,
            _ => MmapMut::map_anon(bytes.len())?,
        };
        writable[..bytes.len()].copy_from_slice(bytes);
        let exec = Arc::new(writable.make_exec()?);
        let base = exec.as_ptr();
        let entries = offsets
            .iter()
            .copied()
            .map(|offset| Self {
                _exec: Arc::clone(&exec),
                // SAFETY: every offset was allocated within `exec`, and the
                // shared Arc keeps the mapping alive for every entry handle.
                entry: unsafe { base.add(offset) },
            })
            .collect();
        Ok((entries, Some(exec)))
    }

    pub(crate) fn recover_batch_mapping(exec: Arc<Mmap>) -> std::io::Result<MmapMut> {
        Arc::try_unwrap(exec)
            .map_err(|_| std::io::Error::other("JIT arena still has executable references"))?
            .make_mut()
    }

    /// Execute the muladd body over the `len`-byte planar `src`/`dst` regions
    /// (`len` a multiple of 512). Convention: `rax=src-384, rdx=dst-384,
    /// rcx=dst_end-384`, `rsi` is reserved for the optional dedicated
    /// prefetch stream; the body advances one 512-byte block per iteration
    /// and `ret`s. `vzeroupper` clears the AVX upper state on return.
    ///
    /// # Safety
    /// `self` must hold a normal body from
    /// [`super::turbo_avx2::append_muladd_body`], AVX2 must be available,
    /// `src`/`dst` valid for `len` bytes, and `len` must be a non-zero multiple
    /// of 512.
    pub unsafe fn run_muladd(&self, src: *const u8, dst: *mut u8, len: usize) {
        Self::run_muladd_entry(self.entry, src, dst, len);
    }

    pub(crate) unsafe fn run_muladd_entry(
        entry: *const u8,
        src: *const u8,
        dst: *mut u8,
        len: usize,
    ) {
        assert!(len != 0 && len.is_multiple_of(512));
        let rax = src.wrapping_sub(384);
        let rdx = dst.wrapping_sub(384);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(384);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) entry,
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
    /// This handle must contain a prefetch body from
    /// [`super::turbo_avx2::append_muladd_body`] with prefetch enabled, and AVX2 must be
    /// available. `src` must be
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
        Self::run_muladd_prefetch_entry(self.entry, src, dst, len, prefetch);
    }

    pub(crate) unsafe fn run_muladd_prefetch_entry(
        entry: *const u8,
        src: *const u8,
        dst: *mut u8,
        len: usize,
        prefetch: *const u8,
    ) {
        assert!(len != 0 && len.is_multiple_of(512));
        let rax = src.wrapping_sub(384);
        let rdx = dst.wrapping_sub(384);
        let rcx = (dst as *const u8).wrapping_add(len).wrapping_sub(384);
        let rsi = prefetch.wrapping_sub(128);
        core::arch::asm!(
            "call {entry}",
            "vzeroupper",
            entry = in(reg) entry,
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

    #[test]
    fn worker_buffer_reuses_one_mapping_across_wx_transitions() {
        let mut worker = WorkerJitBuffer::default();
        let entry = worker.seal(&[0xc3]).unwrap();
        let mapping = worker.mapping_address().unwrap();
        assert_eq!(entry, mapping);
        assert!(!worker.is_writable());

        worker.make_writable().unwrap();
        assert!(worker.is_writable());
        assert_eq!(worker.mapping_address(), Some(mapping));

        let entry = worker.seal(&[0x90, 0xc3]).unwrap();
        assert_eq!(entry, mapping);
        worker.make_writable().unwrap();
        assert!(worker.is_writable());
    }

    #[test]
    fn worker_buffer_rejects_oversized_body_without_losing_reusable_page() {
        let mut worker = WorkerJitBuffer::new(8);
        worker.seal(&[0xc3]).unwrap();
        worker.make_writable().unwrap();
        let mapping = worker.mapping_address().unwrap();

        assert!(worker.seal(&[0x90; 9]).is_err());
        assert!(worker.is_writable());
        assert_eq!(worker.mapping_address(), Some(mapping));

        worker.seal(&[0xc3]).unwrap();
        assert_eq!(worker.mapping_address(), Some(mapping));
    }
}
