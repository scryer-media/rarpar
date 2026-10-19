//! ParPar's paired scalar MD5 assembly (Public Domain/CC0), ported to `asm!`.
//!
//! Instruction sources, pinned to the reference used for this port:
//! <https://github.com/animetosho/par2cmdline-turbo/tree/3e60f6fcfed52bf257e79c46deae616cb6135d59/parpar/hasher>
//! `md5x2-x86-asm.h` and `md5x2-arm-asm.h`; upstream licensing:
//! <https://github.com/animetosho/ParPar#license>.
//!
//! The instruction streams retain the two-chain scheduling and preloads.
//! Rust supplies registers, iteration and feed-forward. The x86 template's
//! assembler conditionals select the original baseline or BMI1 G/I rounds at
//! compile time. Only the BMI1 entry point needs an optional CPU feature;
//! AArch64 uses baseline integer instructions, without CRC, SHA3 or NEON.
//! SIMD x2 implementations and CPU-name heuristics are not part of dispatch.

use core::arch::asm;

/// Equal whole-block streams, possibly unaligned or sharing immutable bytes.
pub(crate) fn compress_pair(left: &mut [u32; 4], right: &mut [u32; 4], x: &[u8], y: &[u8]) {
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len() % 64, 0);
    if x.is_empty() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("bmi1") {
        // SAFETY: CPU detection establishes BMI1; slices establish the exact
        // readable bounds. Independent mutable states cannot alias inputs.
        unsafe { blocks_bmi1(left, right, x, y) };
    } else {
        // SAFETY: baseline x86-64 instructions; same slice bounds as above.
        unsafe { blocks_x86::<false>(left, right, x, y) };
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: the module is native little-endian AArch64 only. No optional
    // instructions are used; each load is within a complete 64-byte block.
    unsafe {
        blocks_aarch64(left, right, x, y)
    };
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi1")]
unsafe fn blocks_bmi1(left: &mut [u32; 4], right: &mut [u32; 4], x: &[u8], y: &[u8]) {
    // SAFETY: inherited whole-block bounds and this entry's BMI1 requirement.
    unsafe { blocks_x86::<true>(left, right, x, y) };
}

/// # Safety
/// Both slices must contain equally many complete blocks. BMI requires BMI1.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn blocks_x86<const BMI: bool>(
    left: &mut [u32; 4],
    right: &mut [u32; 4],
    x: &[u8],
    y: &[u8],
) {
    #[cfg(test)]
    record_execution(if BMI { 2 } else { 1 });
    let [mut a1, mut b1, mut c1, mut d1] = *left;
    let [mut a2, mut b2, mut c2, mut d2] = *right;
    for (x, y) in x.chunks_exact(64).zip(y.chunks_exact(64)) {
        let previous = [a1, b1, c1, d1, a2, b2, c2, d2];
        // SAFETY: only 32-bit loads at offsets 0..=60 of both blocks. Every
        // modified register is an early output or in/out operand, preventing
        // overlap with still-live input pointers. The template touches no
        // stack, calls no function and writes no memory. Rust preserves the
        // platform ABI's callee-saved registers, including Windows x64.
        unsafe {
            asm!(
                include_str!("md5_pair_x86.inc"),
                a1 = inout(reg) a1, b1 = inout(reg) b1,
                c1 = inout(reg) c1, d1 = inout(reg) d1,
                a2 = inout(reg) a2, b2 = inout(reg) b2,
                c2 = inout(reg) c2, d2 = inout(reg) d2,
                tmp1 = out(reg) _, tmp2 = out(reg) _,
                x = in(reg) x.as_ptr(), y = in(reg) y.as_ptr(),
                bmi1 = const BMI as u8,
                options(att_syntax, nostack, readonly),
            );
        }
        a1 = a1.wrapping_add(previous[0]);
        b1 = b1.wrapping_add(previous[1]);
        c1 = c1.wrapping_add(previous[2]);
        d1 = d1.wrapping_add(previous[3]);
        a2 = a2.wrapping_add(previous[4]);
        b2 = b2.wrapping_add(previous[5]);
        c2 = c2.wrapping_add(previous[6]);
        d2 = d2.wrapping_add(previous[7]);
    }
    *left = [a1, b1, c1, d1];
    *right = [a2, b2, c2, d2];
}

/// # Safety
/// Both slices must contain equally many complete blocks. Unaligned is valid.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn blocks_aarch64(left: &mut [u32; 4], right: &mut [u32; 4], x: &[u8], y: &[u8]) {
    #[cfg(test)]
    record_execution(0);
    let [mut a1, mut b1, mut c1, mut d1] = *left;
    let [mut a2, mut b2, mut c2, mut d2] = *right;
    for (x, y) in x.chunks_exact(64).zip(y.chunks_exact(64)) {
        let previous = [a1, b1, c1, d1, a2, b2, c2, d2];
        // SAFETY: only ordinary-memory 32-bit loads at offsets 0..=60. All
        // clobbers are declared; early outputs cannot overlap input pointers.
        // No hard-coded/reserved registers, stack, calls, writes or flag-
        // modifying instructions occur. Rust handles the platform ABI.
        unsafe {
            asm!(
                include_str!("md5_pair_aarch64.inc"),
                a1 = inout(reg) a1, b1 = inout(reg) b1,
                c1 = inout(reg) c1, d1 = inout(reg) d1,
                a2 = inout(reg) a2, b2 = inout(reg) b2,
                c2 = inout(reg) c2, d2 = inout(reg) d2,
                tmp1 = out(reg) _, tmp2 = out(reg) _,
                x = in(reg) x.as_ptr(), y = in(reg) y.as_ptr(),
                options(nostack, readonly, preserves_flags),
            );
        }
        a1 = a1.wrapping_add(previous[0]);
        b1 = b1.wrapping_add(previous[1]);
        c1 = c1.wrapping_add(previous[2]);
        d1 = d1.wrapping_add(previous[3]);
        a2 = a2.wrapping_add(previous[4]);
        b2 = b2.wrapping_add(previous[5]);
        c2 = c2.wrapping_add(previous[6]);
        d2 = d2.wrapping_add(previous[7]);
    }
    *left = [a1, b1, c1, d1];
    *right = [a2, b2, c2, d2];
}

#[cfg(test)]
std::thread_local! {
    static EXECUTIONS: std::cell::Cell<[usize; 3]> = const { std::cell::Cell::new([0; 3]) };
}

#[cfg(test)]
fn record_execution(backend: usize) {
    EXECUTIONS.with(|counts| {
        let mut value = counts.get();
        value[backend] += 1;
        counts.set(value);
    });
}

#[cfg(test)]
pub(crate) fn executions() -> [usize; 3] {
    EXECUTIONS.with(std::cell::Cell::get)
}

/// Exercise the baseline even when runtime detection selects BMI1.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn compress_baseline(left: &mut [u32; 4], right: &mut [u32; 4], x: &[u8], y: &[u8]) {
    assert_eq!(x.len(), y.len());
    assert_eq!(x.len() % 64, 0);
    // SAFETY: checked whole-block bounds and baseline x86-64 instructions.
    unsafe { blocks_x86::<false>(left, right, x, y) };
}
