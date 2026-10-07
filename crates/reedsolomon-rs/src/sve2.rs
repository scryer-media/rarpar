//! SVE2 kernels for aarch64: the GF(2^8) and GF(2^16) region operations and
//! the FFT linear maps over scalable vectors.
//!
//! Every kernel is vector-length agnostic. A loop step covers one whole
//! vector (or one whole structure of two vectors), `whilelo` predicates the
//! final partial step, and nothing is left for a scalar tail: the same code
//! runs on a 128-bit implementation such as Neoverse V2 and on any wider one.
//!
//! The nibble tables are sixteen bytes. `ld1rqb` replicates them into every
//! 128-bit segment of a register and `tbl` indexes the whole vector, so a
//! nibble index (0..=15) always selects from the first segment, which holds
//! the table whatever the vector length.
//!
//! Rust 1.97 has no stable SVE intrinsics (`stdarch_aarch64_sve` is
//! unstable), so the kernels are whole loops in inline `asm!`, which is
//! stable. Scalable registers cannot be `asm!` operands and no Rust value can
//! live in one, so no state crosses an `asm!` block: each kernel loads its
//! tables, walks its rows and stores its results inside one block. Every
//! vector register a block writes is declared as a clobbered `vN`, which the
//! compiler treats as the whole `zN` (the upper bits of every `zN` are
//! caller-saved under AAPCS64, and Rust code never holds values there), and
//! every predicate register as a clobbered `pN`.
//!
//! Dispatch: [`enabled`] is true on a host that reports SVE2 unless
//! `WEAVER_SVE2=0` is set, which pins the NEON kernels so the two tiers can be
//! A/B'd without a rebuild. The variable is read once and never enables a
//! kernel the host lacks.

/// Whether the SVE2 kernels run on this host (see the module docs).
pub(crate) fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED
        .get_or_init(|| !std::env::var_os("WEAVER_SVE2").is_some_and(|v| v == "0") && detected())
}

/// Whether the host reports SVE2, ignoring the override.
pub(crate) fn detected() -> bool {
    std::arch::is_aarch64_feature_detected!("sve2")
}

/// `tbl dst, {table}, index` on byte lanes.
macro_rules! tbl {
    ($dst:literal, $table:literal, $index:literal) => {
        concat!("tbl ", $dst, ".b, {{", $table, ".b}}, ", $index, ".b\n")
    };
}

/// `dst ^= a ^ b` (`eor3` is destructive in its first operand).
macro_rules! eor3 {
    ($dst:literal, $a:literal, $b:literal) => {
        concat!("eor3 ", $dst, ".d, ", $dst, ".d, ", $a, ".d, ", $b, ".d\n")
    };
}

/// `dst ^= a`.
macro_rules! eor {
    ($dst:literal, $a:literal) => {
        concat!("eor ", $dst, ".d, ", $dst, ".d, ", $a, ".d\n")
    };
}

/// One byte map accumulated into `dst`: `dst ^= lo[v & 15] ^ hi[v >> 4]`,
/// with `mask` holding 0x0f in every byte and `t0`/`t1` as scratch.
macro_rules! map8_into {
    ($dst:literal, $v:literal, $lo:literal, $hi:literal, $mask:literal, $t0:literal, $t1:literal) => {
        concat!(
            "lsr ",
            $t1,
            ".b, ",
            $v,
            ".b, #4\n",
            "and ",
            $t0,
            ".d, ",
            $v,
            ".d, ",
            $mask,
            ".d\n",
            tbl!($t0, $lo, $t0),
            tbl!($t1, $hi, $t1),
            eor3!($dst, $t0, $t1),
        )
    };
}

/// One byte-map butterfly on registers `l`, `r`: forward `l ^= m(r); r ^= l`,
/// inverse `r ^= l; l ^= m(r)`. Scratch `z4`/`z5`, mask `z29`.
macro_rules! bfly8 {
    (false, $l:literal, $r:literal, $lo:literal, $hi:literal) => {
        concat!(
            map8_into!($l, $r, $lo, $hi, "z29", "z4", "z5"),
            eor!($r, $l)
        )
    };
    (true, $l:literal, $r:literal, $lo:literal, $hi:literal) => {
        concat!(
            eor!($r, $l),
            map8_into!($l, $r, $lo, $hi, "z29", "z4", "z5")
        )
    };
}

/// One 16-bit map of the byte planes `(rl, rh)` accumulated into the planes
/// `(ll, lh)`, with nibbles in `z8..z11`, scratch `z12`/`z13` and the eight
/// tables in the registers named by `t0..t7` (the order of `MulTables`).
macro_rules! map16_into {
    (
        $ll:literal, $lh:literal, $rl:literal, $rh:literal,
        [$t0:literal, $t1:literal, $t2:literal, $t3:literal,
         $t4:literal, $t5:literal, $t6:literal, $t7:literal]
    ) => {
        concat!(
            "lsr z9.b, ",
            $rl,
            ".b, #4\n",
            "and z8.d, ",
            $rl,
            ".d, z14.d\n",
            "lsr z11.b, ",
            $rh,
            ".b, #4\n",
            "and z10.d, ",
            $rh,
            ".d, z14.d\n",
            tbl!("z12", $t0, "z8"),
            tbl!("z13", $t2, "z9"),
            eor3!($ll, "z12", "z13"),
            tbl!("z12", $t4, "z10"),
            tbl!("z13", $t6, "z11"),
            eor3!($ll, "z12", "z13"),
            tbl!("z12", $t1, "z8"),
            tbl!("z13", $t3, "z9"),
            eor3!($lh, "z12", "z13"),
            tbl!("z12", $t5, "z10"),
            tbl!("z13", $t7, "z11"),
            eor3!($lh, "z12", "z13"),
        )
    };
}

/// Load the eight tables at `{t}` into `z16..z23`.
macro_rules! load16_tables {
    ($base:literal) => {
        concat!(
            "ld1rqb {{z16.b}}, p7/z, [{",
            $base,
            "}]\n",
            "ld1rqb {{z17.b}}, p7/z, [{",
            $base,
            "}, #16]\n",
            "ld1rqb {{z18.b}}, p7/z, [{",
            $base,
            "}, #32]\n",
            "ld1rqb {{z19.b}}, p7/z, [{",
            $base,
            "}, #48]\n",
            "ld1rqb {{z20.b}}, p7/z, [{",
            $base,
            "}, #64]\n",
            "ld1rqb {{z21.b}}, p7/z, [{",
            $base,
            "}, #80]\n",
            "ld1rqb {{z22.b}}, p7/z, [{",
            $base,
            "}, #96]\n",
            "ld1rqb {{z23.b}}, p7/z, [{",
            $base,
            "}, #112]\n",
        )
    };
}

// ---------------------------------------------------------------------------
// GF(2^8) and 8-bit linear maps: two 16-byte nibble tables per map.
// ---------------------------------------------------------------------------

/// `dst[i] ^= lo[src[i] & 15] ^ hi[src[i] >> 4]` for `i < n`.
///
/// # Safety
/// SVE2 must be available; `src` must be readable and `dst` writable for `n`
/// bytes; they must not overlap unless equal.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn map8_acc(
    lo: &[u8; 16],
    hi: &[u8; 16],
    src: *const u8,
    dst: *mut u8,
    n: usize,
) {
    // SAFETY: the caller's bounds; every access is predicated below `n`.
    unsafe {
        std::arch::asm!(
            "ptrue p7.b",
            "mov z29.b, #15",
            "ld1rqb {{z30.b}}, p7/z, [{lo}]",
            "ld1rqb {{z31.b}}, p7/z, [{hi}]",
            "mov {i}, #0",
            "whilelo p0.b, {i}, {n}",
            "b.none 3f",
            "2:",
            "ld1b {{z0.b}}, p0/z, [{s}, {i}]",
            "ld1b {{z1.b}}, p0/z, [{d}, {i}]",
            map8_into!("z1", "z0", "z30", "z31", "z29", "z2", "z3"),
            "st1b {{z1.b}}, p0, [{d}, {i}]",
            "incb {i}",
            "whilelo p0.b, {i}, {n}",
            "b.first 2b",
            "3:",
            lo = in(reg) lo.as_ptr(),
            hi = in(reg) hi.as_ptr(),
            s = in(reg) src,
            d = in(reg) dst,
            n = in(reg) n,
            i = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v29") _, out("v30") _, out("v31") _,
            out("p0") _, out("p7") _,
            options(nostack),
        );
    }
}

/// One additive-FFT butterfly per byte over `n` bytes of two rows: forward
/// `l ^= m(r); r ^= l`, inverse `r ^= l; l ^= m(r)`.
///
/// # Safety
/// SVE2 must be available; both rows must be writable for `n` bytes and must
/// not overlap.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn map8_butterfly<const INVERSE: bool>(
    lo: &[u8; 16],
    hi: &[u8; 16],
    left: *mut u8,
    right: *mut u8,
    n: usize,
) {
    macro_rules! kernel {
        ($inverse:tt) => {
            // SAFETY: the caller's bounds; every access is predicated below `n`.
            unsafe {
                std::arch::asm!(
                    "ptrue p7.b",
                    "mov z29.b, #15",
                    "ld1rqb {{z30.b}}, p7/z, [{lo}]",
                    "ld1rqb {{z31.b}}, p7/z, [{hi}]",
                    "mov {i}, #0",
                    "whilelo p0.b, {i}, {n}",
                    "b.none 3f",
                    "2:",
                    "ld1b {{z0.b}}, p0/z, [{l}, {i}]",
                    "ld1b {{z1.b}}, p0/z, [{r}, {i}]",
                    bfly8!($inverse, "z0", "z1", "z30", "z31"),
                    "st1b {{z0.b}}, p0, [{l}, {i}]",
                    "st1b {{z1.b}}, p0, [{r}, {i}]",
                    "incb {i}",
                    "whilelo p0.b, {i}, {n}",
                    "b.first 2b",
                    "3:",
                    lo = in(reg) lo.as_ptr(),
                    hi = in(reg) hi.as_ptr(),
                    l = in(reg) left,
                    r = in(reg) right,
                    n = in(reg) n,
                    i = out(reg) _,
                    out("v0") _, out("v1") _, out("v4") _, out("v5") _,
                    out("v29") _, out("v30") _, out("v31") _,
                    out("p0") _, out("p7") _,
                    options(nostack),
                );
            }
        };
    }
    if INVERSE {
        kernel!(true);
    } else {
        kernel!(false);
    }
}

/// Two butterfly stages per byte over four rows `[a, b, c, d]`, in the order
/// of `gf_simd::fused_radix4`: `outer` joins (a, c) and (b, d), `inner_a`
/// joins (a, b) and `inner_b` joins (c, d). Each map is `(lo, hi)`.
///
/// # Safety
/// SVE2 must be available; all four rows must be writable for `n` bytes and
/// must not overlap.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn map8_radix4<const INVERSE: bool>(
    maps: [(&[u8; 16], &[u8; 16]); 3],
    rows: [*mut u8; 4],
    n: usize,
) {
    let [outer, inner_a, inner_b] = maps;
    let [a, b, c, d] = rows;
    macro_rules! kernel {
        ($inverse:tt, $($step:expr),*) => {
            // SAFETY: the caller's bounds; every access is predicated below `n`.
            unsafe {
                std::arch::asm!(
                    "ptrue p7.b",
                    "mov z29.b, #15",
                    "ld1rqb {{z22.b}}, p7/z, [{ol}]",
                    "ld1rqb {{z23.b}}, p7/z, [{oh}]",
                    "ld1rqb {{z24.b}}, p7/z, [{al}]",
                    "ld1rqb {{z25.b}}, p7/z, [{ah}]",
                    "ld1rqb {{z26.b}}, p7/z, [{bl}]",
                    "ld1rqb {{z27.b}}, p7/z, [{bh}]",
                    "mov {i}, #0",
                    "whilelo p0.b, {i}, {n}",
                    "b.none 3f",
                    "2:",
                    "ld1b {{z0.b}}, p0/z, [{ra}, {i}]",
                    "ld1b {{z1.b}}, p0/z, [{rb}, {i}]",
                    "ld1b {{z2.b}}, p0/z, [{rc}, {i}]",
                    "ld1b {{z3.b}}, p0/z, [{rd}, {i}]",
                    $($step,)*
                    "st1b {{z0.b}}, p0, [{ra}, {i}]",
                    "st1b {{z1.b}}, p0, [{rb}, {i}]",
                    "st1b {{z2.b}}, p0, [{rc}, {i}]",
                    "st1b {{z3.b}}, p0, [{rd}, {i}]",
                    "incb {i}",
                    "whilelo p0.b, {i}, {n}",
                    "b.first 2b",
                    "3:",
                    ol = in(reg) outer.0.as_ptr(),
                    oh = in(reg) outer.1.as_ptr(),
                    al = in(reg) inner_a.0.as_ptr(),
                    ah = in(reg) inner_a.1.as_ptr(),
                    bl = in(reg) inner_b.0.as_ptr(),
                    bh = in(reg) inner_b.1.as_ptr(),
                    ra = in(reg) a,
                    rb = in(reg) b,
                    rc = in(reg) c,
                    rd = in(reg) d,
                    n = in(reg) n,
                    i = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _,
                    out("v22") _, out("v23") _, out("v24") _, out("v25") _,
                    out("v26") _, out("v27") _, out("v29") _,
                    out("p0") _, out("p7") _,
                    options(nostack),
                );
            }
        };
    }
    if INVERSE {
        kernel!(
            true,
            bfly8!(true, "z0", "z1", "z24", "z25"),
            bfly8!(true, "z2", "z3", "z26", "z27"),
            bfly8!(true, "z0", "z2", "z22", "z23"),
            bfly8!(true, "z1", "z3", "z22", "z23")
        );
    } else {
        kernel!(
            false,
            bfly8!(false, "z0", "z2", "z22", "z23"),
            bfly8!(false, "z1", "z3", "z22", "z23"),
            bfly8!(false, "z0", "z1", "z24", "z25"),
            bfly8!(false, "z2", "z3", "z26", "z27")
        );
    }
}

/// Most sources [`map8_batch`] folds per pass: eight table pairs fill
/// `z16..z31`.
pub(crate) const MAP8_BATCH: usize = 8;

/// One source of a [`map8_batch`] pass: the table pair at `{t}` (advanced by
/// 32 bytes) into `lo`/`hi`, then two vectors of the source accumulated.
macro_rules! batch8_tables {
    ($lo:literal, $hi:literal) => {
        concat!(
            "ld1rqb {{",
            $lo,
            ".b}}, p7/z, [{t}]\n",
            "ld1rqb {{",
            $hi,
            ".b}}, p7/z, [{t}, #16]\n",
            "add {t}, {t}, #32\n",
        )
    };
}

macro_rules! batch8_source {
    ($s:ident, $lo:literal, $hi:literal) => {
        concat!(
            "ld1b {{z1.b}}, p0/z, [{",
            stringify!($s),
            "}, {i}]\n",
            "ld1b {{z4.b}}, p1/z, [{",
            stringify!($s),
            "}, {j}]\n",
            "lsr z2.b, z1.b, #4\n",
            "lsr z5.b, z4.b, #4\n",
            "and z1.d, z1.d, z15.d\n",
            "and z4.d, z4.d, z15.d\n",
            tbl!("z1", $lo, "z1"),
            tbl!("z2", $hi, "z2"),
            tbl!("z4", $lo, "z4"),
            tbl!("z5", $hi, "z5"),
            eor3!("z0", "z1", "z2"),
            eor3!("z3", "z4", "z5"),
        )
    };
}

/// A grouped kernel for exactly the listed sources: the table pairs stay in
/// registers while two destination vectors take every source per step.
macro_rules! batch8_kernel {
    ($name:ident; $($s:ident, $lo:literal, $hi:literal);+) => {
        /// # Safety
        /// As [`map8_batch`], for exactly this many sources.
        #[target_feature(enable = "sve2")]
        unsafe fn $name(dst: *mut u8, n: usize, tables: *const [u8; 32], srcs: &[*const u8]) {
            let mut at = srcs.iter();
            $( let $s = *at.next().expect("one pointer per source"); )+
            // SAFETY: the caller's bounds; every access is predicated below `n`.
            unsafe {
                std::arch::asm!(
                    "ptrue p7.b",
                    "mov z15.b, #15",
                    $( batch8_tables!($lo, $hi), )+
                    "mov {i}, #0",
                    "whilelo p0.b, {i}, {n}",
                    "b.none 3f",
                    "2:",
                    "mov {j}, {i}",
                    "incb {j}",
                    "whilelo p1.b, {j}, {n}",
                    "ld1b {{z0.b}}, p0/z, [{d}, {i}]",
                    "ld1b {{z3.b}}, p1/z, [{d}, {j}]",
                    $( batch8_source!($s, $lo, $hi), )+
                    "st1b {{z0.b}}, p0, [{d}, {i}]",
                    "st1b {{z3.b}}, p1, [{d}, {j}]",
                    "incb {i}, all, mul #2",
                    "whilelo p0.b, {i}, {n}",
                    "b.first 2b",
                    "3:",
                    t = inout(reg) tables => _,
                    d = in(reg) dst,
                    n = in(reg) n,
                    $( $s = in(reg) $s, )+
                    i = out(reg) _,
                    j = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                    out("p0") _, out("p1") _, out("p7") _,
                    options(nostack),
                );
            }
        }
    };
}

batch8_kernel!(batch8_1; s0, "z16", "z17");
batch8_kernel!(batch8_2; s0, "z16", "z17"; s1, "z18", "z19");
batch8_kernel!(batch8_3; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21");
batch8_kernel!(batch8_4; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21"; s3, "z22", "z23");
batch8_kernel!(batch8_5; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21"; s3, "z22", "z23";
    s4, "z24", "z25");
batch8_kernel!(batch8_6; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21"; s3, "z22", "z23";
    s4, "z24", "z25"; s5, "z26", "z27");
batch8_kernel!(batch8_7; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21"; s3, "z22", "z23";
    s4, "z24", "z25"; s5, "z26", "z27"; s6, "z28", "z29");
batch8_kernel!(batch8_8; s0, "z16", "z17"; s1, "z18", "z19"; s2, "z20", "z21"; s3, "z22", "z23";
    s4, "z24", "z25"; s5, "z26", "z27"; s6, "z28", "z29"; s7, "z30", "z31");

/// `dst[i] ^= Σ_k lo_k[src_k[i] & 15] ^ hi_k[src_k[i] >> 4]` for `i < n`,
/// with `tables[k]` holding `lo_k` then `hi_k`. One pass over `dst` for
/// `1..=MAP8_BATCH` sources.
///
/// # Safety
/// SVE2 must be available; `tables` and `srcs` must have equal lengths in
/// `1..=MAP8_BATCH`; every source must be readable and `dst` writable for
/// `n` bytes, and no source may overlap `dst`.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn map8_batch(dst: *mut u8, n: usize, tables: &[[u8; 32]], srcs: &[*const u8]) {
    debug_assert_eq!(tables.len(), srcs.len());
    let t = tables.as_ptr();
    // SAFETY: the caller's contract, for the arm matching the source count.
    unsafe {
        match srcs.len() {
            1 => batch8_1(dst, n, t, srcs),
            2 => batch8_2(dst, n, t, srcs),
            3 => batch8_3(dst, n, t, srcs),
            4 => batch8_4(dst, n, t, srcs),
            5 => batch8_5(dst, n, t, srcs),
            6 => batch8_6(dst, n, t, srcs),
            7 => batch8_7(dst, n, t, srcs),
            8 => batch8_8(dst, n, t, srcs),
            count => unreachable!("map8_batch takes 1..=8 sources, got {count}"),
        }
    }
}

// ---------------------------------------------------------------------------
// GF(2^16) and 16-bit linear maps: eight nibble tables per map, symbols as
// little-endian byte pairs split into planes by `ld2b`/`st2b`.
// ---------------------------------------------------------------------------

/// `dst ^= map(src)` over `n` bytes (`n` even), with `tables` in the order of
/// `gf_simd::MulTables`.
///
/// # Safety
/// SVE2 must be available; `n` must be even; `src` must be readable and `dst`
/// writable for `n` bytes; they must not overlap unless equal.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn map16_acc(tables: &[[u8; 16]; 8], src: *const u8, dst: *mut u8, n: usize) {
    debug_assert!(n.is_multiple_of(2));
    // SAFETY: the caller's bounds; `whilelo` counts symbols, so every
    // structure access is predicated below `n / 2` symbols.
    unsafe {
        std::arch::asm!(
            "ptrue p7.b",
            "mov z14.b, #15",
            load16_tables!("t"),
            "mov {i}, #0",
            "mov {o}, #0",
            "whilelo p0.b, {i}, {np}",
            "b.none 3f",
            "2:",
            "ld2b {{z0.b, z1.b}}, p0/z, [{s}, {o}]",
            "ld2b {{z2.b, z3.b}}, p0/z, [{d}, {o}]",
            map16_into!("z2", "z3", "z0", "z1", ["z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23"]),
            "st2b {{z2.b, z3.b}}, p0, [{d}, {o}]",
            "incb {i}",
            "incb {o}, all, mul #2",
            "whilelo p0.b, {i}, {np}",
            "b.first 2b",
            "3:",
            t = in(reg) tables.as_ptr(),
            s = in(reg) src,
            d = in(reg) dst,
            np = in(reg) n / 2,
            i = out(reg) _,
            o = out(reg) _,
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("p0") _, out("p7") _,
            options(nostack),
        );
    }
}

/// One source of a [`gf16_batch_tables`] pass: its planes, nibbles in
/// `z0`/`z2`/`z1`/`z3`, eight resident tables, accumulated into `z6`/`z7`.
macro_rules! batch16_source {
    ($s:ident, [$t0:literal, $t1:literal, $t2:literal, $t3:literal,
                $t4:literal, $t5:literal, $t6:literal, $t7:literal]) => {
        concat!(
            "ld2b {{z0.b, z1.b}}, p0/z, [{",
            stringify!($s),
            "}, {o}]\n",
            "lsr z2.b, z0.b, #4\n",
            "and z0.b, z0.b, #15\n",
            "lsr z3.b, z1.b, #4\n",
            "and z1.b, z1.b, #15\n",
            tbl!("z4", $t0, "z0"),
            tbl!("z5", $t2, "z2"),
            eor3!("z6", "z4", "z5"),
            tbl!("z4", $t4, "z1"),
            tbl!("z5", $t6, "z3"),
            eor3!("z6", "z4", "z5"),
            tbl!("z4", $t1, "z0"),
            tbl!("z5", $t3, "z2"),
            eor3!("z7", "z4", "z5"),
            tbl!("z4", $t5, "z1"),
            tbl!("z5", $t7, "z3"),
            eor3!("z7", "z4", "z5"),
        )
    };
}

/// Load the eight tables at `{t}` (advanced by 128 bytes) into the named
/// registers.
macro_rules! batch16_tables {
    ([$t0:literal, $t1:literal, $t2:literal, $t3:literal,
      $t4:literal, $t5:literal, $t6:literal, $t7:literal]) => {
        concat!(
            "ld1rqb {{",
            $t0,
            ".b}}, p7/z, [{t}]\n",
            "ld1rqb {{",
            $t1,
            ".b}}, p7/z, [{t}, #16]\n",
            "ld1rqb {{",
            $t2,
            ".b}}, p7/z, [{t}, #32]\n",
            "ld1rqb {{",
            $t3,
            ".b}}, p7/z, [{t}, #48]\n",
            "ld1rqb {{",
            $t4,
            ".b}}, p7/z, [{t}, #64]\n",
            "ld1rqb {{",
            $t5,
            ".b}}, p7/z, [{t}, #80]\n",
            "ld1rqb {{",
            $t6,
            ".b}}, p7/z, [{t}, #96]\n",
            "ld1rqb {{",
            $t7,
            ".b}}, p7/z, [{t}, #112]\n",
            "add {t}, {t}, #128\n",
        )
    };
}

macro_rules! batch16_kernel {
    ($name:ident; $($s:ident, $regs:tt);+) => {
        /// # Safety
        /// As [`gf16_batch_tables`], for exactly this many sources.
        #[target_feature(enable = "sve2")]
        unsafe fn $name(dst: *mut u8, n: usize, tables: *const [[u8; 16]; 8], srcs: &[*const u8]) {
            let mut at = srcs.iter();
            $( let $s = *at.next().expect("one pointer per source"); )+
            // SAFETY: the caller's bounds; every access is predicated below
            // `n / 2` symbols.
            unsafe {
                std::arch::asm!(
                    "ptrue p7.b",
                    $( batch16_tables!($regs), )+
                    "mov {i}, #0",
                    "mov {o}, #0",
                    "whilelo p0.b, {i}, {np}",
                    "b.none 3f",
                    "2:",
                    "ld2b {{z6.b, z7.b}}, p0/z, [{d}, {o}]",
                    $( batch16_source!($s, $regs), )+
                    "st2b {{z6.b, z7.b}}, p0, [{d}, {o}]",
                    "incb {i}",
                    "incb {o}, all, mul #2",
                    "whilelo p0.b, {i}, {np}",
                    "b.first 2b",
                    "3:",
                    t = inout(reg) tables => _,
                    d = in(reg) dst,
                    np = in(reg) n / 2,
                    $( $s = in(reg) $s, )+
                    i = out(reg) _,
                    o = out(reg) _,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v29") _, out("v30") _, out("v31") _,
                    out("p0") _, out("p7") _,
                    options(nostack),
                );
            }
        }
    };
}

batch16_kernel!(batch16_1; s0, ["z8", "z9", "z10", "z11", "z12", "z13", "z14", "z15"]);
batch16_kernel!(batch16_2;
    s0, ["z8", "z9", "z10", "z11", "z12", "z13", "z14", "z15"];
    s1, ["z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23"]);
batch16_kernel!(batch16_3;
    s0, ["z8", "z9", "z10", "z11", "z12", "z13", "z14", "z15"];
    s1, ["z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23"];
    s2, ["z24", "z25", "z26", "z27", "z28", "z29", "z30", "z31"]);

/// Most sources [`gf16_batch_tables`] folds per pass: three sets of eight
/// resident tables fill `z8..z31`.
pub(crate) const GF16_TABLE_BATCH: usize = 3;

/// `dst ^= Σ_k map_k(src_k)` over `n` bytes (`n` even) for
/// `1..=GF16_TABLE_BATCH` sources, with `tables[k]` in the order of
/// `gf_simd::MulTables`.
///
/// # Safety
/// SVE2 must be available; `n` must be even; `tables` and `srcs` must have
/// equal lengths in `1..=GF16_TABLE_BATCH`; every source must be readable and
/// `dst` writable for `n` bytes, and no source may overlap `dst`.
#[target_feature(enable = "sve2")]
pub(crate) unsafe fn gf16_batch_tables(
    dst: *mut u8,
    n: usize,
    tables: &[[[u8; 16]; 8]],
    srcs: &[*const u8],
) {
    debug_assert!(n.is_multiple_of(2));
    debug_assert_eq!(tables.len(), srcs.len());
    let t = tables.as_ptr();
    // SAFETY: the caller's contract, for the arm matching the source count.
    unsafe {
        match srcs.len() {
            1 => batch16_1(dst, n, t, srcs),
            2 => batch16_2(dst, n, t, srcs),
            3 => batch16_3(dst, n, t, srcs),
            count => unreachable!("gf16_batch_tables takes 1..=3 sources, got {count}"),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Each kernel against a scalar oracle of the same tables: random tables
    //! and data, every source count, lengths around the vector and structure
    //! sizes of every vector length up to 2048 bits, and unaligned offsets.
    //! The dispatch-level tests of `gf8` and `gf_simd` cover the same kernels
    //! through their public entry points.

    use super::*;
    use crate::gf_simd::{fused_butterfly, fused_radix4};

    /// Byte lengths: zero, odd and even sizes around 16, 32, 64, 128 and 256
    /// bytes (one vector or one `ld2b` structure at each vector length), and
    /// long rows.
    const LENGTHS: [usize; 22] = [
        0, 1, 2, 3, 14, 15, 16, 17, 30, 32, 34, 62, 64, 66, 126, 128, 130, 254, 256, 258, 1000,
        4098,
    ];

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self, count: usize) -> Vec<u8> {
            (0..count).map(|_| self.next() as u8).collect()
        }

        fn table(&mut self) -> [u8; 16] {
            std::array::from_fn(|_| self.next() as u8)
        }

        fn tables16(&mut self) -> [[u8; 16]; 8] {
            std::array::from_fn(|_| self.table())
        }
    }

    /// Whether to run: SVE2 must be present, and a skip says so.
    fn present(test: &str) -> bool {
        if detected() {
            return true;
        }
        eprintln!("SKIP {test}: the host has no SVE2");
        false
    }

    fn apply8(lo: &[u8; 16], hi: &[u8; 16], value: u8) -> u8 {
        lo[usize::from(value & 15)] ^ hi[usize::from(value >> 4)]
    }

    fn apply16(tables: &[[u8; 16]; 8], value: u16) -> u16 {
        (0..4).fold(0, |product, nibble| {
            let index = usize::from((value >> (4 * nibble)) & 15);
            product ^ u16::from_le_bytes([tables[nibble * 2][index], tables[nibble * 2 + 1][index]])
        })
    }

    fn words(bytes: &[u8]) -> Vec<u16> {
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    }

    fn unwords(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// `count` rows of `len` bytes, each at byte offset `offset` inside its
    /// own buffer, so no vector access is aligned.
    fn rows(rng: &mut Rng, count: usize, len: usize, offset: usize) -> Vec<Vec<u8>> {
        (0..count).map(|_| rng.bytes(len + offset)).collect()
    }

    #[test]
    fn map8_kernels_match_the_scalar_oracle() {
        if !present("map8_kernels_match_the_scalar_oracle") {
            return;
        }
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for len in LENGTHS {
            for offset in 0..3 {
                let (lo, hi) = (rng.table(), rng.table());
                let mut data = rows(&mut rng, 4, len, offset);

                let source = data[0][offset..].to_vec();
                let mut expected = data[1][offset..].to_vec();
                for (to, from) in expected.iter_mut().zip(&source) {
                    *to ^= apply8(&lo, &hi, *from);
                }
                // SAFETY: SVE2 is present; distinct buffers of `len` bytes.
                unsafe {
                    map8_acc(
                        &lo,
                        &hi,
                        source.as_ptr(),
                        data[1][offset..].as_mut_ptr(),
                        len,
                    )
                };
                assert_eq!(
                    data[1][offset..],
                    expected,
                    "map8_acc len {len} offset {offset}"
                );

                let map = |m: (&[u8; 16], &[u8; 16]), value: u8| apply8(m.0, m.1, value);
                for inverse in [false, true] {
                    let (left, right) = (data[0][offset..].to_vec(), data[3][offset..].to_vec());
                    let (mut want_l, mut want_r) = (left.clone(), right.clone());
                    for (l, r) in want_l.iter_mut().zip(&mut want_r) {
                        let (mut x, mut y) = (*l, *r);
                        fused_butterfly!(inverse, x, y, (&lo, &hi), std::ops::BitXor::bitxor, map);
                        (*l, *r) = (x, y);
                    }
                    let (mut got_l, mut got_r) = (left, right);
                    // SAFETY: as above.
                    unsafe {
                        if inverse {
                            map8_butterfly::<true>(
                                &lo,
                                &hi,
                                got_l.as_mut_ptr(),
                                got_r.as_mut_ptr(),
                                len,
                            );
                        } else {
                            map8_butterfly::<false>(
                                &lo,
                                &hi,
                                got_l.as_mut_ptr(),
                                got_r.as_mut_ptr(),
                                len,
                            );
                        }
                    }
                    assert_eq!(
                        (got_l, got_r),
                        (want_l, want_r),
                        "map8_butterfly {inverse} len {len}"
                    );

                    let tables: [([u8; 16], [u8; 16]); 3] =
                        std::array::from_fn(|_| (rng.table(), rng.table()));
                    let [o, a, b] = tables.each_ref().map(|(l, h)| (l, h));
                    let mut want: Vec<Vec<u8>> =
                        data.iter().map(|row| row[offset..].to_vec()).collect();
                    let mut got = want.clone();
                    // One column across the four rows per step.
                    #[allow(clippy::needless_range_loop)]
                    for at in 0..len {
                        let [mut w, mut x, mut y, mut z] = [0, 1, 2, 3].map(|row| want[row][at]);
                        fused_radix4!(
                            inverse,
                            [w, x, y, z],
                            o,
                            a,
                            b,
                            std::ops::BitXor::bitxor,
                            map
                        );
                        for (row, value) in [w, x, y, z].into_iter().enumerate() {
                            want[row][at] = value;
                        }
                    }
                    let pointers: [*mut u8; 4] = std::array::from_fn(|row| got[row].as_mut_ptr());
                    // SAFETY: as above, four distinct rows.
                    unsafe {
                        if inverse {
                            map8_radix4::<true>([o, a, b], pointers, len);
                        } else {
                            map8_radix4::<false>([o, a, b], pointers, len);
                        }
                    }
                    assert_eq!(got, want, "map8_radix4 {inverse} len {len} offset {offset}");
                }
            }
        }
    }

    #[test]
    fn map8_batch_matches_the_scalar_sum_for_every_source_count() {
        if !present("map8_batch_matches_the_scalar_sum_for_every_source_count") {
            return;
        }
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for count in 1..=MAP8_BATCH {
            for len in LENGTHS {
                let offset = (count + len) % 3;
                let sources = rows(&mut rng, count, len, offset);
                let tables: Vec<[u8; 32]> = (0..count)
                    .map(|_| std::array::from_fn(|_| rng.next() as u8))
                    .collect();
                let mut destination = rng.bytes(len + offset);
                let mut expected = destination[offset..].to_vec();
                for (source, table) in sources.iter().zip(&tables) {
                    let (lo, hi) = table.split_at(16);
                    let (lo, hi): (&[u8; 16], &[u8; 16]) =
                        (lo.try_into().unwrap(), hi.try_into().unwrap());
                    for (to, from) in expected.iter_mut().zip(&source[offset..]) {
                        *to ^= apply8(lo, hi, *from);
                    }
                }
                let pointers: Vec<*const u8> = sources
                    .iter()
                    .map(|source| source[offset..].as_ptr())
                    .collect();
                // SAFETY: SVE2 is present; distinct buffers of `len` bytes.
                unsafe { map8_batch(destination[offset..].as_mut_ptr(), len, &tables, &pointers) };
                assert_eq!(
                    destination[offset..],
                    expected,
                    "map8_batch {count} sources len {len}"
                );
            }
        }
    }

    #[test]
    fn map16_acc_matches_the_scalar_oracle() {
        if !present("map16_acc_matches_the_scalar_oracle") {
            return;
        }
        let mut rng = Rng(0x0123_4567_89ab_cdef);
        for len in LENGTHS.map(|len| len & !1) {
            for offset in 0..3 {
                let tables = rng.tables16();
                let mut data = rows(&mut rng, 2, len, offset);
                let map = |t: &[[u8; 16]; 8], value: u16| apply16(t, value);

                let source = words(&data[0][offset..]);
                let mut expected = words(&data[1][offset..]);
                for (to, from) in expected.iter_mut().zip(&source) {
                    *to ^= map(&tables, *from);
                }
                // SAFETY: SVE2 is present; distinct buffers of `len` bytes.
                unsafe {
                    map16_acc(
                        &tables,
                        data[0][offset..].as_ptr(),
                        data[1][offset..].as_mut_ptr(),
                        len,
                    )
                };
                assert_eq!(data[1][offset..], unwords(&expected), "map16_acc len {len}");
            }
        }
    }

    /// Factors 0, 1, the top bit alone, all ones and random ones.
    fn factors(rng: &mut Rng, count: usize) -> Vec<u16> {
        const EDGES: [u16; 5] = [0, 1, 0x8000, 0xffff, 2];
        (0..count)
            .map(|at| match EDGES.get((at + count) % 9) {
                Some(edge) => *edge,
                None => rng.next() as u16,
            })
            .collect()
    }

    fn field_sum(
        factors: &[u16],
        sources: &[Vec<u8>],
        offset: usize,
        destination: &[u8],
    ) -> Vec<u8> {
        let mut expected = words(destination);
        for (factor, source) in factors.iter().zip(sources) {
            for (to, from) in expected.iter_mut().zip(words(&source[offset..])) {
                *to ^= crate::gf::mul(*factor, from);
            }
        }
        unwords(&expected)
    }

    #[test]
    fn gf16_batch_tables_matches_field_multiplication() {
        if !present("gf16_batch_tables_matches_field_multiplication") {
            return;
        }
        let mut rng = Rng(0x5851_f42d_4c95_7f2d);
        for count in 1..=20 {
            for len in LENGTHS.map(|len| len & !1) {
                let offset = (count + len / 2) % 3;
                let sources = rows(&mut rng, count, len, offset);
                let factors = factors(&mut rng, count);
                let pointers: Vec<*const u8> = sources
                    .iter()
                    .map(|source| source[offset..].as_ptr())
                    .collect();
                let mut destination = rng.bytes(len + offset);
                let expected = field_sum(&factors, &sources, offset, &destination[offset..]);

                for (group, factors) in pointers
                    .chunks(GF16_TABLE_BATCH)
                    .zip(factors.chunks(GF16_TABLE_BATCH))
                {
                    let tables: Vec<[[u8; 16]; 8]> = factors
                        .iter()
                        .map(|f| crate::gf_simd::precompute_mul_tables(*f).tables)
                        .collect();
                    // SAFETY: as above.
                    unsafe {
                        gf16_batch_tables(destination[offset..].as_mut_ptr(), len, &tables, group)
                    };
                }
                assert_eq!(
                    destination[offset..],
                    expected,
                    "gf16_batch_tables {count} sources len {len}"
                );
            }
        }
    }
}
