//! SME2 `BMOPA` GF(2) matrix-product kernels: a measurement lane, not a
//! shipped tier.
//!
//! Multiplying a GF(2^8) or GF(2^16) symbol by a constant is an 8x8 or 16x16
//! bit matrix over GF(2), so a whole Reed-Solomon product
//! `dst[r] ^= sum_s c[r][s] * src[s]` is one GF(2) matrix product whose
//! dimensions are 8x or 16x larger. SME2's `BMOPA` is an outer product of
//! 32-bit lanes, but it accumulates `popcount(XNOR(a, b))` as an integer
//! rather than XOR-accumulating `a AND b`. The parity is still there:
//!
//! `popcount(XNOR(a, b)) = 32 - pop(a) - pop(b) + 2 * pop(a AND b)`
//!
//! so bit 1 of `ZA + sum pop(a) + sum pop(b)` is the GF(2) dot product. The
//! per-row term `sum pop(a)` is made a multiple of four by a padding k-step
//! against a zero input. The per-column term `sum pop(b)` is added either by
//! an extra `BMOPA` against an all-ones row per k-step (cheap when there are
//! few row blocks) or by `CNT` over the packed input, folded into that same
//! padding step (cheap when there are many).
//!
//! Layout: a GF(2^8) lane packs four sources' bytes at one column, a GF(2^16)
//! lane two sources' words, by one `ZIP` in the kernel. A 16x16 tile covers
//! 16 output bit rows (two GF(2^8) recovery rows or one GF(2^16) row) by 16
//! columns, and four tiles cover 64 columns. The output side is what costs:
//! turning a tile's counts into packed bits takes a `MOVA` plus an `SLI` tree,
//! about as long as four `BMOPA`s per k-step when there are only 16 sources.
//!
//! Measured on Apple M5 Max (2026-10-06): faster than the NEON grouped
//! kernels on one thread once the product is wide (64+ sources per call),
//! slower at the 12- and 16-source groups the engines issue and at 8 or 18
//! workers, because one SME unit serves a whole core cluster. Hence no tier.
//!
//! Every kernel is one `asm!` block from `SMSTART` to `SMSTOP`, so no
//! compiler-generated code ever runs in streaming mode. Rust 1.97 has no SME
//! intrinsics. Callers supply whole 64-column chunks; there is no tail path.

use reedsolomon_rs::{gf, gf8};

/// Whether this host executes SME2 (`BMOPA` on 32-bit tiles is baseline
/// SME). `is_aarch64_feature_detected!("sme2")` is unstable in Rust 1.97, so
/// the OS is asked directly.
pub fn sme2_available() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        unsafe extern "C" {
            fn sysctlbyname(
                name: *const std::ffi::c_char,
                oldp: *mut std::ffi::c_void,
                oldlenp: *mut usize,
                newp: *mut std::ffi::c_void,
                newlen: usize,
            ) -> std::ffi::c_int;
        }
        let mut value: u32 = 0;
        let mut len = std::mem::size_of::<u32>();
        // SAFETY: a NUL-terminated name and an out-buffer of `len` bytes.
        let status = unsafe {
            sysctlbyname(
                c"hw.optional.arm.FEAT_SME2".as_ptr(),
                (&raw mut value).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        status == 0 && value != 0
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        unsafe extern "C" {
            fn getauxval(kind: std::ffi::c_ulong) -> std::ffi::c_ulong;
        }
        const AT_HWCAP2: std::ffi::c_ulong = 26;
        const HWCAP2_SME2: u64 = 1 << 37;
        // SAFETY: getauxval has no preconditions.
        (unsafe { getauxval(AT_HWCAP2) } as u64) & HWCAP2_SME2 != 0
    }
    #[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux"))))]
    {
        false
    }
}

/// Symbols one kernel pass covers per row: four 16-column tiles.
pub const CHUNK: usize = 64;

/// Bit-matrix words for one coefficient matrix: per 16-bit-row block, one
/// 16-word vector per k-step plus the padding step.
pub struct Plan {
    words: Vec<u32>,
    kw: usize,
    blocks: usize,
    rows: usize,
    sources: usize,
    wide: bool,
}

impl Plan {
    /// GF(2^8) (polynomial 0x11d): `coef[r][s]` multiplies source `s` into
    /// row `r`.
    pub fn gf8(coef: &[Vec<u8>]) -> Self {
        Self::build(
            coef.len(),
            coef.first().map_or(0, Vec::len),
            false,
            |r, s, t| gf8::mul(coef[r][s], 1 << t).into(),
        )
    }

    /// GF(2^16) (polynomial 0x1100b).
    pub fn gf16(coef: &[Vec<u16>]) -> Self {
        Self::build(
            coef.len(),
            coef.first().map_or(0, Vec::len),
            true,
            |r, s, t| gf::mul(coef[r][s], 1 << t),
        )
    }

    /// `image(r, s, t)`: the product of row `r`'s factor for source `s` and
    /// input bit `t` alone.
    fn build(
        rows: usize,
        sources: usize,
        wide: bool,
        image: impl Fn(usize, usize, usize) -> u16,
    ) -> Self {
        let (bits, per_lane) = if wide { (16, 2) } else { (8, 4) };
        let rows_per_block = 16 / bits;
        let kw = sources.div_ceil(per_lane).max(1);
        let blocks = rows.div_ceil(rows_per_block);
        let mut words = vec![0u32; blocks * (kw + 1) * 16];
        for block in 0..blocks {
            let mut ones = [0u32; 16];
            for k in 0..kw {
                for (lane, ones) in ones.iter_mut().enumerate() {
                    let row = block * rows_per_block + lane / bits;
                    let bit = lane % bits;
                    let mut word = 0u32;
                    if row < rows {
                        for slot in 0..per_lane {
                            let source = per_lane * k + slot;
                            if source >= sources {
                                continue;
                            }
                            for t in 0..bits {
                                if (image(row, source, t) >> bit) & 1 == 1 {
                                    word |= 1 << (bits * slot + t);
                                }
                            }
                        }
                    }
                    words[(block * (kw + 1) + k) * 16 + lane] = word;
                    *ones += word.count_ones();
                }
            }
            // Padding against a zero input: brings each row's popcount sum
            // to a multiple of four.
            for (lane, ones) in ones.iter().enumerate() {
                words[(block * (kw + 1) + kw) * 16 + lane] = (1u32 << ((4 - ones % 4) % 4)) - 1;
            }
        }
        Self {
            words,
            kw,
            blocks,
            rows,
            sources,
            wide,
        }
    }

    /// `dsts[r][x] ^= sum_s coef[r][s] * srcs[s][x]` for the symbols
    /// `[start, start + len)`; `len` is a multiple of [`CHUNK`]. `scratch` is
    /// reused between calls.
    ///
    /// # Panics
    ///
    /// When SME2 is absent, the shapes disagree with the plan, or the range
    /// is not whole chunks inside every slice.
    pub fn apply(
        &self,
        srcs: &[&[u8]],
        dsts: &mut [&mut [u8]],
        start: usize,
        len: usize,
        scratch: &mut Vec<u32>,
    ) {
        assert!(sme2_available(), "SME2 kernels need SME2");
        assert_eq!(srcs.len(), self.sources);
        assert_eq!(dsts.len(), self.rows);
        assert!(len.is_multiple_of(CHUNK) && len > 0);
        let symbol = if self.wide { 2 } else { 1 };
        let end = (start + len) * symbol;
        assert!(srcs.iter().all(|s| s.len() >= end) && dsts.iter().all(|d| d.len() >= end));
        let per_lane = if self.wide { 2 } else { 4 };
        // Slots past the last source carry zero factors; any readable
        // source stands in for them.
        let mut sp: Vec<*const u8> = srcs.iter().map(|s| s.as_ptr()).collect();
        sp.resize(self.kw * per_lane, srcs[0].as_ptr());
        let mut dp: Vec<*mut u8> = dsts.iter_mut().map(|d| d.as_mut_ptr()).collect();
        // An odd GF(2^8) row count leaves the last block a second row of
        // zero factors; it writes zeros XORed into a throwaway row.
        let mut spare = Vec::new();
        let rows_per_block = if self.wide { 1 } else { 2 };
        if dp.len() < self.blocks * rows_per_block {
            spare = vec![0u8; end];
            dp.push(spare.as_mut_ptr());
        }
        scratch.clear();
        scratch.resize(self.kw * CHUNK + CHUNK, 0);
        let args = GemmArgs {
            srcs: sp.as_ptr(),
            dsts: dp.as_ptr(),
            a: self.words.as_ptr(),
            scratch: scratch.as_mut_ptr(),
            kw: self.kw,
            rb: self.blocks,
            chunks: len / CHUNK,
            col: start,
        };
        // Below this many row blocks the extra all-ones outer products cost
        // less than counting the packed input (measured crossover).
        let count = self.blocks >= 16;
        // SAFETY: SME2 is present (asserted); every pointer covers
        // `[0, end)` bytes, the scratch holds `kw + 1` chunks of words, and
        // the plan matches `kw` and `rb`.
        unsafe {
            match (self.wide, count) {
                (false, false) => gf8_gemm_ones(&args),
                (true, false) => gf16_gemm_ones(&args),
                (false, true) => gf8_gemm_cnt(&args),
                (true, true) => gf16_gemm_cnt(&args),
            }
        }
        drop(spare);
    }
}

/// The scalar oracle: `dsts[r] ^= sum_s coef[r][s] * srcs[s]`, GF(2^8).
pub fn oracle8(coef: &[Vec<u8>], srcs: &[&[u8]], dsts: &mut [Vec<u8>]) {
    for (row, dst) in coef.iter().zip(dsts) {
        for (&factor, src) in row.iter().zip(srcs) {
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d ^= gf8::mul(factor, s);
            }
        }
    }
}

/// The scalar oracle for GF(2^16), little-endian words.
pub fn oracle16(coef: &[Vec<u16>], srcs: &[&[u8]], dsts: &mut [Vec<u8>]) {
    for (row, dst) in coef.iter().zip(dsts) {
        for (&factor, src) in row.iter().zip(srcs) {
            for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                let word = u16::from_le_bytes([d[0], d[1]])
                    ^ gf::mul(factor, u16::from_le_bytes([s[0], s[1]]));
                d.copy_from_slice(&word.to_le_bytes());
            }
        }
    }
}

/// Kernel arguments, read by the `asm!` blocks at fixed offsets.
#[repr(C)]
struct GemmArgs {
    /// `kw * lanes` source pointers.
    srcs: *const *const u8,
    /// One pointer per output row (two per GF(2^8) block).
    dsts: *const *mut u8,
    /// [`Plan::words`].
    a: *const u32,
    /// `(kw + 1) * CHUNK` words.
    scratch: *mut u32,
    kw: usize,
    rb: usize,
    chunks: usize,
    /// First symbol.
    col: usize,
}

/// One `SMSTART`/`SMSTOP` pair; nanoseconds per pair over `n` pairs is the
/// mode-switch cost.
///
/// # Safety
///
/// SME2 must be present.
pub unsafe fn mode_switch(n: u64) {
    let mut count = n.max(1);
    // SAFETY: SME is present per the contract; all vector and predicate
    // state is declared clobbered.
    unsafe {
        core::arch::asm!(
            ".arch_extension sme2",
            "2:",
            "smstart",
            "smstop",
            "subs {c}, {c}, #1",
            "b.ne 2b",
            c = inout(reg) count,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
            options(nostack)
        );
    }
    let _ = count;
}

/// `n` iterations of eight `BMOPA`s over four independent tiles.
///
/// # Safety
///
/// SME2 must be present.
pub unsafe fn bmopa_loop(n: u64) {
    let mut count = n.max(1);
    // SAFETY: as for `mode_switch`.
    unsafe {
        core::arch::asm!(
            ".arch_extension sme2",
            "smstart",
            "zero {{za}}",
            "ptrue p0.s",
            "2:",
            "bmopa za0.s, p0/m, p0/m, z0.s, z1.s",
            "bmopa za1.s, p0/m, p0/m, z2.s, z3.s",
            "bmopa za2.s, p0/m, p0/m, z4.s, z5.s",
            "bmopa za3.s, p0/m, p0/m, z6.s, z7.s",
            "bmopa za0.s, p0/m, p0/m, z8.s, z9.s",
            "bmopa za1.s, p0/m, p0/m, z10.s, z11.s",
            "bmopa za2.s, p0/m, p0/m, z12.s, z13.s",
            "bmopa za3.s, p0/m, p0/m, z14.s, z15.s",
            "subs {c}, {c}, #1",
            "b.ne 2b",
            "smstop",
            c = inout(reg) count,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
            options(nostack)
        );
    }
    let _ = count;
}

/// GF(2^8), column correction by an all-ones BMOPA per k-step.
///
/// # Safety
///
/// SME2 must be present and `args` must describe valid buffers (see
/// [`GemmArgs`]).
unsafe fn gf8_gemm_ones(args: &GemmArgs) {
    // SAFETY: the caller upholds the contract above; every register the
    // block writes, every vector and predicate register (zeroed by
    // SMSTART/SMSTOP) included, is declared clobbered.
    unsafe {
        core::arch::asm!(
        ".arch_extension sme2",
        "smstart",
        "ptrue p0.s",
        "ptrue p1.b",
        "ptrue pn8.b",
        "mov w12, #0",
        "mov w13, #4",
        "mov w14, #8",
        "mov w15, #12",
        "ldp x1, x2, [x0]",
        "ldp x3, x4, [x0, #16]",
        "ldp x5, x6, [x0, #32]",
        "ldp x7, x8, [x0, #48]",
        "1:",
        "mov x9, x1",
        "mov x10, x4",
        "mov x11, x5",
        "2:",
        "ldp x20, x21, [x9], #16",
        "ldp x22, x23, [x9], #16",
        "ld1b {{z0.b}}, p1/z, [x20, x8]",
        "ld1b {{z1.b}}, p1/z, [x21, x8]",
        "ld1b {{z2.b}}, p1/z, [x22, x8]",
        "ld1b {{z3.b}}, p1/z, [x23, x8]",
        "zip {{z4.b-z7.b}}, {{z0.b-z3.b}}",
        "st1w {{z4.s-z7.s}}, pn8, [x10]",
        "add x10, x10, #256",
        "subs x11, x11, #1",
        "b.ne 2b",
        "mov x9, x3",
        "mov x16, x2",
        "mov x17, x6",
        "3:",
        "zero {{za}}",
        "mov z31.s, #-1",
        "mov z30.s, #0",
        "mov x10, x4",
        "mov x11, x5",
        "4:",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "add x10, x10, #256",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "bmopa za0.s, p0/m, p0/m, z31.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z31.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z31.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z31.s, z15.s",
        "subs x11, x11, #1",
        "b.ne 4b",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "bmopa za0.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z30.s",
        "ldp x24, x25, [x16], #16",
        "add x24, x24, x8",
        "add x25, x25, x8",
        "mova {{z0.s-z3.s}}, za0h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za1h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za0h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za1h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za0h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za1h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za0h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za1h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1b {{z2.s}}, p0/z, [x24, #0, mul vl]",
        "ld1b {{z3.s}}, p0/z, [x25, #0, mul vl]",
        "ld1b {{z18.s}}, p0/z, [x24, #1, mul vl]",
        "ld1b {{z19.s}}, p0/z, [x25, #1, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "lsr z1.s, z1.s, #8",
        "st1b {{z2.s}}, p0, [x24, #0, mul vl]",
        "eor z3.d, z3.d, z1.d",
        "st1b {{z3.s}}, p0, [x25, #0, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "lsr z17.s, z17.s, #8",
        "st1b {{z18.s}}, p0, [x24, #1, mul vl]",
        "eor z19.d, z19.d, z17.d",
        "st1b {{z19.s}}, p0, [x25, #1, mul vl]",
        "mova {{z0.s-z3.s}}, za2h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za3h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za2h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za3h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za2h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za3h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za2h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za3h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1b {{z2.s}}, p0/z, [x24, #2, mul vl]",
        "ld1b {{z3.s}}, p0/z, [x25, #2, mul vl]",
        "ld1b {{z18.s}}, p0/z, [x24, #3, mul vl]",
        "ld1b {{z19.s}}, p0/z, [x25, #3, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "lsr z1.s, z1.s, #8",
        "st1b {{z2.s}}, p0, [x24, #2, mul vl]",
        "eor z3.d, z3.d, z1.d",
        "st1b {{z3.s}}, p0, [x25, #2, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "lsr z17.s, z17.s, #8",
        "st1b {{z18.s}}, p0, [x24, #3, mul vl]",
        "eor z19.d, z19.d, z17.d",
        "st1b {{z19.s}}, p0, [x25, #3, mul vl]",
        "subs x17, x17, #1",
        "b.ne 3b",
        "add x8, x8, #64",
        "subs x7, x7, #1",
        "b.ne 1b",
        "smstop",
        in("x0") args as *const GemmArgs,
        out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
        out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _, out("x17") _, out("x20") _, out("x21") _, out("x22") _, out("x23") _, out("x24") _, out("x25") _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
        options(nostack)
        );
    }
}

/// GF(2^16), column correction by an all-ones BMOPA per k-step.
///
/// # Safety
///
/// SME2 must be present and `args` must describe valid buffers (see
/// [`GemmArgs`]).
unsafe fn gf16_gemm_ones(args: &GemmArgs) {
    // SAFETY: the caller upholds the contract above; every register the
    // block writes, every vector and predicate register (zeroed by
    // SMSTART/SMSTOP) included, is declared clobbered.
    unsafe {
        core::arch::asm!(
        ".arch_extension sme2",
        "smstart",
        "ptrue p0.s",
        "ptrue p1.b",
        "ptrue pn8.b",
        "mov w12, #0",
        "mov w13, #4",
        "mov w14, #8",
        "mov w15, #12",
        "ldp x1, x2, [x0]",
        "ldp x3, x4, [x0, #16]",
        "ldp x5, x6, [x0, #32]",
        "ldp x7, x8, [x0, #48]",
        "1:",
        "mov x9, x1",
        "mov x10, x4",
        "mov x11, x5",
        "lsl x17, x8, #1",
        "2:",
        "ldp x20, x21, [x9], #16",
        "add x20, x20, x17",
        "add x21, x21, x17",
        "ld1h {{z0.h-z1.h}}, pn8/z, [x20]",
        "ld1h {{z2.h-z3.h}}, pn8/z, [x21]",
        "zip {{z4.h-z5.h}}, z0.h, z2.h",
        "zip {{z6.h-z7.h}}, z1.h, z3.h",
        "st1w {{z4.s-z7.s}}, pn8, [x10]",
        "add x10, x10, #256",
        "subs x11, x11, #1",
        "b.ne 2b",
        "mov x9, x3",
        "mov x16, x2",
        "mov x17, x6",
        "3:",
        "zero {{za}}",
        "mov z31.s, #-1",
        "mov z30.s, #0",
        "mov x10, x4",
        "mov x11, x5",
        "4:",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "add x10, x10, #256",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "bmopa za0.s, p0/m, p0/m, z31.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z31.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z31.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z31.s, z15.s",
        "subs x11, x11, #1",
        "b.ne 4b",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "bmopa za0.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z30.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z30.s",
        "ldr x24, [x16], #8",
        "add x24, x24, x8, lsl #1",
        "mova {{z0.s-z3.s}}, za0h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za1h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za0h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za1h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za0h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za1h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za0h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za1h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1h {{z2.s}}, p0/z, [x24, #0, mul vl]",
        "ld1h {{z18.s}}, p0/z, [x24, #1, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "st1h {{z2.s}}, p0, [x24, #0, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "st1h {{z18.s}}, p0, [x24, #1, mul vl]",
        "mova {{z0.s-z3.s}}, za2h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za3h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za2h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za3h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za2h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za3h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za2h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za3h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1h {{z2.s}}, p0/z, [x24, #2, mul vl]",
        "ld1h {{z18.s}}, p0/z, [x24, #3, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "st1h {{z2.s}}, p0, [x24, #2, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "st1h {{z18.s}}, p0, [x24, #3, mul vl]",
        "subs x17, x17, #1",
        "b.ne 3b",
        "add x8, x8, #64",
        "subs x7, x7, #1",
        "b.ne 1b",
        "smstop",
        in("x0") args as *const GemmArgs,
        out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
        out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _, out("x17") _, out("x20") _, out("x21") _, out("x22") _, out("x23") _, out("x24") _, out("x25") _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
        options(nostack)
        );
    }
}

/// GF(2^8), column correction by CNT over the packed input, folded into the
/// padding k-step.
///
/// # Safety
///
/// SME2 must be present and `args` must describe valid buffers (see
/// [`GemmArgs`]).
unsafe fn gf8_gemm_cnt(args: &GemmArgs) {
    // SAFETY: the caller upholds the contract above; every register the
    // block writes, every vector and predicate register (zeroed by
    // SMSTART/SMSTOP) included, is declared clobbered.
    unsafe {
        core::arch::asm!(
        ".arch_extension sme2",
        "smstart",
        "ptrue p0.s",
        "ptrue p1.b",
        "ptrue pn8.b",
        "mov w12, #0",
        "mov w13, #4",
        "mov w14, #8",
        "mov w15, #12",
        "ldp x1, x2, [x0]",
        "ldp x3, x4, [x0, #16]",
        "ldp x5, x6, [x0, #32]",
        "ldp x7, x8, [x0, #48]",
        "1:",
        "mov x9, x1",
        "mov x10, x4",
        "mov x11, x5",
        "mov z24.s, #0",
        "mov z25.s, #0",
        "mov z26.s, #0",
        "mov z27.s, #0",
        "2:",
        "ldp x20, x21, [x9], #16",
        "ldp x22, x23, [x9], #16",
        "ld1b {{z0.b}}, p1/z, [x20, x8]",
        "ld1b {{z1.b}}, p1/z, [x21, x8]",
        "ld1b {{z2.b}}, p1/z, [x22, x8]",
        "ld1b {{z3.b}}, p1/z, [x23, x8]",
        "zip {{z4.b-z7.b}}, {{z0.b-z3.b}}",
        "st1w {{z4.s-z7.s}}, pn8, [x10]",
        "add x10, x10, #256",
        "cnt z8.s, p0/m, z4.s",
        "cnt z9.s, p0/m, z5.s",
        "cnt z10.s, p0/m, z6.s",
        "cnt z11.s, p0/m, z7.s",
        "add z24.s, z24.s, z8.s",
        "add z25.s, z25.s, z9.s",
        "add z26.s, z26.s, z10.s",
        "add z27.s, z27.s, z11.s",
        "subs x11, x11, #1",
        "b.ne 2b",
        "subr z24.s, z24.s, #0",
        "and z24.s, z24.s, #3",
        "mov z8.s, #1",
        "lsl z8.s, p0/m, z8.s, z24.s",
        "sub z8.s, z8.s, #1",
        "lsl z8.s, z8.s, #16",
        "subr z25.s, z25.s, #0",
        "and z25.s, z25.s, #3",
        "mov z9.s, #1",
        "lsl z9.s, p0/m, z9.s, z25.s",
        "sub z9.s, z9.s, #1",
        "lsl z9.s, z9.s, #16",
        "subr z26.s, z26.s, #0",
        "and z26.s, z26.s, #3",
        "mov z10.s, #1",
        "lsl z10.s, p0/m, z10.s, z26.s",
        "sub z10.s, z10.s, #1",
        "lsl z10.s, z10.s, #16",
        "subr z27.s, z27.s, #0",
        "and z27.s, z27.s, #3",
        "mov z11.s, #1",
        "lsl z11.s, p0/m, z11.s, z27.s",
        "sub z11.s, z11.s, #1",
        "lsl z11.s, z11.s, #16",
        "st1w {{z8.s-z11.s}}, pn8, [x10]",
        "mov x9, x3",
        "mov x16, x2",
        "mov x17, x6",
        "3:",
        "zero {{za}}",
        "mov z31.s, #-1",
        "mov z30.s, #0",
        "mov x10, x4",
        "mov x11, x5",
        "4:",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "add x10, x10, #256",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "subs x11, x11, #1",
        "b.ne 4b",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "ldp x24, x25, [x16], #16",
        "add x24, x24, x8",
        "add x25, x25, x8",
        "mova {{z0.s-z3.s}}, za0h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za1h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za0h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za1h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za0h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za1h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za0h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za1h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1b {{z2.s}}, p0/z, [x24, #0, mul vl]",
        "ld1b {{z3.s}}, p0/z, [x25, #0, mul vl]",
        "ld1b {{z18.s}}, p0/z, [x24, #1, mul vl]",
        "ld1b {{z19.s}}, p0/z, [x25, #1, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "lsr z1.s, z1.s, #8",
        "st1b {{z2.s}}, p0, [x24, #0, mul vl]",
        "eor z3.d, z3.d, z1.d",
        "st1b {{z3.s}}, p0, [x25, #0, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "lsr z17.s, z17.s, #8",
        "st1b {{z18.s}}, p0, [x24, #1, mul vl]",
        "eor z19.d, z19.d, z17.d",
        "st1b {{z19.s}}, p0, [x25, #1, mul vl]",
        "mova {{z0.s-z3.s}}, za2h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za3h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za2h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za3h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za2h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za3h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za2h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za3h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1b {{z2.s}}, p0/z, [x24, #2, mul vl]",
        "ld1b {{z3.s}}, p0/z, [x25, #2, mul vl]",
        "ld1b {{z18.s}}, p0/z, [x24, #3, mul vl]",
        "ld1b {{z19.s}}, p0/z, [x25, #3, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "lsr z1.s, z1.s, #8",
        "st1b {{z2.s}}, p0, [x24, #2, mul vl]",
        "eor z3.d, z3.d, z1.d",
        "st1b {{z3.s}}, p0, [x25, #2, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "lsr z17.s, z17.s, #8",
        "st1b {{z18.s}}, p0, [x24, #3, mul vl]",
        "eor z19.d, z19.d, z17.d",
        "st1b {{z19.s}}, p0, [x25, #3, mul vl]",
        "subs x17, x17, #1",
        "b.ne 3b",
        "add x8, x8, #64",
        "subs x7, x7, #1",
        "b.ne 1b",
        "smstop",
        in("x0") args as *const GemmArgs,
        out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
        out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _, out("x17") _, out("x20") _, out("x21") _, out("x22") _, out("x23") _, out("x24") _, out("x25") _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
        options(nostack)
        );
    }
}

/// GF(2^16), column correction by CNT over the packed input, folded into the
/// padding k-step.
///
/// # Safety
///
/// SME2 must be present and `args` must describe valid buffers (see
/// [`GemmArgs`]).
unsafe fn gf16_gemm_cnt(args: &GemmArgs) {
    // SAFETY: the caller upholds the contract above; every register the
    // block writes, every vector and predicate register (zeroed by
    // SMSTART/SMSTOP) included, is declared clobbered.
    unsafe {
        core::arch::asm!(
        ".arch_extension sme2",
        "smstart",
        "ptrue p0.s",
        "ptrue p1.b",
        "ptrue pn8.b",
        "mov w12, #0",
        "mov w13, #4",
        "mov w14, #8",
        "mov w15, #12",
        "ldp x1, x2, [x0]",
        "ldp x3, x4, [x0, #16]",
        "ldp x5, x6, [x0, #32]",
        "ldp x7, x8, [x0, #48]",
        "1:",
        "mov x9, x1",
        "mov x10, x4",
        "mov x11, x5",
        "mov z24.s, #0",
        "mov z25.s, #0",
        "mov z26.s, #0",
        "mov z27.s, #0",
        "lsl x17, x8, #1",
        "2:",
        "ldp x20, x21, [x9], #16",
        "add x20, x20, x17",
        "add x21, x21, x17",
        "ld1h {{z0.h-z1.h}}, pn8/z, [x20]",
        "ld1h {{z2.h-z3.h}}, pn8/z, [x21]",
        "zip {{z4.h-z5.h}}, z0.h, z2.h",
        "zip {{z6.h-z7.h}}, z1.h, z3.h",
        "st1w {{z4.s-z7.s}}, pn8, [x10]",
        "add x10, x10, #256",
        "cnt z8.s, p0/m, z4.s",
        "cnt z9.s, p0/m, z5.s",
        "cnt z10.s, p0/m, z6.s",
        "cnt z11.s, p0/m, z7.s",
        "add z24.s, z24.s, z8.s",
        "add z25.s, z25.s, z9.s",
        "add z26.s, z26.s, z10.s",
        "add z27.s, z27.s, z11.s",
        "subs x11, x11, #1",
        "b.ne 2b",
        "subr z24.s, z24.s, #0",
        "and z24.s, z24.s, #3",
        "mov z8.s, #1",
        "lsl z8.s, p0/m, z8.s, z24.s",
        "sub z8.s, z8.s, #1",
        "lsl z8.s, z8.s, #16",
        "subr z25.s, z25.s, #0",
        "and z25.s, z25.s, #3",
        "mov z9.s, #1",
        "lsl z9.s, p0/m, z9.s, z25.s",
        "sub z9.s, z9.s, #1",
        "lsl z9.s, z9.s, #16",
        "subr z26.s, z26.s, #0",
        "and z26.s, z26.s, #3",
        "mov z10.s, #1",
        "lsl z10.s, p0/m, z10.s, z26.s",
        "sub z10.s, z10.s, #1",
        "lsl z10.s, z10.s, #16",
        "subr z27.s, z27.s, #0",
        "and z27.s, z27.s, #3",
        "mov z11.s, #1",
        "lsl z11.s, p0/m, z11.s, z27.s",
        "sub z11.s, z11.s, #1",
        "lsl z11.s, z11.s, #16",
        "st1w {{z8.s-z11.s}}, pn8, [x10]",
        "mov x9, x3",
        "mov x16, x2",
        "mov x17, x6",
        "3:",
        "zero {{za}}",
        "mov z31.s, #-1",
        "mov z30.s, #0",
        "mov x10, x4",
        "mov x11, x5",
        "4:",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "add x10, x10, #256",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "subs x11, x11, #1",
        "b.ne 4b",
        "ld1w {{z8.s}}, p0/z, [x9]",
        "add x9, x9, #64",
        "ld1w {{z12.s-z15.s}}, pn8/z, [x10]",
        "bmopa za0.s, p0/m, p0/m, z8.s, z12.s",
        "bmopa za1.s, p0/m, p0/m, z8.s, z13.s",
        "bmopa za2.s, p0/m, p0/m, z8.s, z14.s",
        "bmopa za3.s, p0/m, p0/m, z8.s, z15.s",
        "ldr x24, [x16], #8",
        "add x24, x24, x8, lsl #1",
        "mova {{z0.s-z3.s}}, za0h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za1h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za0h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za1h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za0h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za1h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za0h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za1h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1h {{z2.s}}, p0/z, [x24, #0, mul vl]",
        "ld1h {{z18.s}}, p0/z, [x24, #1, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "st1h {{z2.s}}, p0, [x24, #0, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "st1h {{z18.s}}, p0, [x24, #1, mul vl]",
        "mova {{z0.s-z3.s}}, za2h.s[w12, 0:3]",
        "mova {{z16.s-z19.s}}, za3h.s[w12, 0:3]",
        "mova {{z4.s-z7.s}}, za2h.s[w13, 0:3]",
        "mova {{z20.s-z23.s}}, za3h.s[w13, 0:3]",
        "mova {{z8.s-z11.s}}, za2h.s[w14, 0:3]",
        "mova {{z24.s-z27.s}}, za3h.s[w14, 0:3]",
        "mova {{z12.s-z15.s}}, za2h.s[w15, 0:3]",
        "mova {{z28.s-z31.s}}, za3h.s[w15, 0:3]",
        "sli z0.s, z1.s, #16",
        "sli z16.s, z17.s, #16",
        "sli z2.s, z3.s, #16",
        "sli z18.s, z19.s, #16",
        "sli z4.s, z5.s, #16",
        "sli z20.s, z21.s, #16",
        "sli z6.s, z7.s, #16",
        "sli z22.s, z23.s, #16",
        "sli z8.s, z9.s, #16",
        "sli z24.s, z25.s, #16",
        "sli z10.s, z11.s, #16",
        "sli z26.s, z27.s, #16",
        "sli z12.s, z13.s, #16",
        "sli z28.s, z29.s, #16",
        "sli z14.s, z15.s, #16",
        "sli z30.s, z31.s, #16",
        "sli z0.h, z2.h, #2",
        "sli z16.h, z18.h, #2",
        "sli z4.h, z6.h, #2",
        "sli z20.h, z22.h, #2",
        "sli z8.h, z10.h, #2",
        "sli z24.h, z26.h, #2",
        "sli z12.h, z14.h, #2",
        "sli z28.h, z30.h, #2",
        "sli z0.h, z4.h, #4",
        "sli z16.h, z20.h, #4",
        "sli z8.h, z12.h, #4",
        "sli z24.h, z28.h, #4",
        "sli z0.h, z8.h, #8",
        "sli z16.h, z24.h, #8",
        "lsr z1.s, z0.s, #16",
        "lsr z17.s, z16.s, #16",
        "usra z1.s, z0.s, #1",
        "usra z17.s, z16.s, #1",
        "ld1h {{z2.s}}, p0/z, [x24, #2, mul vl]",
        "ld1h {{z18.s}}, p0/z, [x24, #3, mul vl]",
        "eor z2.d, z2.d, z1.d",
        "st1h {{z2.s}}, p0, [x24, #2, mul vl]",
        "eor z18.d, z18.d, z17.d",
        "st1h {{z18.s}}, p0, [x24, #3, mul vl]",
        "subs x17, x17, #1",
        "b.ne 3b",
        "add x8, x8, #64",
        "subs x7, x7, #1",
        "b.ne 1b",
        "smstop",
        in("x0") args as *const GemmArgs,
        out("x1") _, out("x2") _, out("x3") _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _,
        out("x9") _, out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _, out("x17") _, out("x20") _, out("x21") _, out("x22") _, out("x23") _, out("x24") _, out("x25") _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _, out("v5") _, out("v6") _, out("v7") _, out("v8") _, out("v9") _, out("v10") _, out("v11") _, out("v12") _, out("v13") _, out("v14") _, out("v15") _, out("v16") _, out("v17") _, out("v18") _, out("v19") _, out("v20") _, out("v21") _, out("v22") _, out("v23") _, out("v24") _, out("v25") _, out("v26") _, out("v27") _, out("v28") _, out("v29") _, out("v30") _, out("v31") _, out("p0") _, out("p1") _, out("p2") _, out("p3") _, out("p4") _, out("p5") _, out("p6") _, out("p7") _, out("p8") _, out("p9") _, out("p10") _, out("p11") _, out("p12") _, out("p13") _, out("p14") _, out("p15") _,
        options(nostack)
        );
    }
}
