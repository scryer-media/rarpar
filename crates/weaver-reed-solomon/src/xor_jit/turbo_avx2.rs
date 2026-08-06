//! Turbo-grounded AVX2 XOR-JIT body generator.
//!
//! This is a direct Rust port of the AVX2 `xor_write_jit_avx` generator in
//! par2cmdline-turbo. It keeps the oracle's factor decomposition, pairwise
//! common accumulator, 64-entry memory fragment table, and packed register
//! instruction encoding. The caller owns the RW-to-RX transition; this module
//! only emits bytes into ordinary writable memory.
//!
//! Turbo uses aligned `VMOVDQA` loads and stores because its internal planar
//! buffers have that contract. Weaver's public packed-JIT contract permits
//! unaligned planar pointers, so the three load/store forms below deliberately
//! use `VMOVDQU`. `VPXOR` memory operands are unaligned-safe already. This is
//! the only intentional instruction-level deviation from the oracle.

use std::{mem::MaybeUninit, sync::OnceLock};

/// Turbo's `XORDEP_JIT_CODE_SIZE` bound for one AVX2 generated body.
pub const MAX_BODY_BYTES: usize = 1280;

const BLOCK_BYTES: i32 = 512;
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RSI: u8 = 6;
const EVEN_ACC: u8 = 0;
const ODD_ACC: u8 = 1;
const COMMON_ACC: u8 = 2;
const MEMORY_FRAGMENT_BYTES: usize = 16;
const REGISTER_LUT_ENTRIES: usize = 128;

/// Failure while assembling one bounded AVX2 body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurboAvx2EmitError {
    /// The fixed Turbo-compatible body buffer was exhausted.
    BodyTooLarge,
}

impl std::fmt::Display for TurboAvx2EmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge => formatter.write_str("AVX2 XOR-JIT body exceeds 1280 bytes"),
        }
    }
}

impl std::error::Error for TurboAvx2EmitError {}

/// Append one Turbo MULADD program for `factor` with an explicit prefetch
/// lifecycle.
///
/// This matches Turbo's writer contract: the field coefficient is the input,
/// and the four nibble dependency lookups produce the generated schedule.
pub(crate) fn append_muladd_body(
    out: &mut Vec<u8>,
    factor: u16,
    prefetch: bool,
) -> Result<usize, TurboAvx2EmitError> {
    let rows = compose_factor_rows(factor);
    append_muladd_body_from_rows(out, &rows, prefetch)
}

/// Turbo's `gf16_bitdep_init256` creates four sixteen-entry groups. Each group
/// supplies the contribution of one factor nibble; the final 16 dependency
/// rows are four XORs. The native implementation stores those as 32-byte SIMD
/// lanes. The logical data here is identical and feeds the same extraction
/// schedule as `xor_write_jit_avx`.
type DependencyLut = [[[u16; 16]; 16]; 4];

fn dependency_lut() -> &'static DependencyLut {
    static LUT: OnceLock<DependencyLut> = OnceLock::new();
    LUT.get_or_init(|| {
        let mut entries = [[[0u16; 16]; 16]; 4];
        for (nibble, group) in entries.iter_mut().enumerate() {
            for (value, rows) in group.iter_mut().enumerate() {
                *rows = dependency_rows_for_factor((value as u16) << (nibble * 4));
            }
        }
        entries
    })
}

#[inline]
fn compose_factor_rows(factor: u16) -> [u16; 16] {
    let table = dependency_lut();
    let selectors = [
        usize::from(factor & 0x000f),
        usize::from((factor >> 4) & 0x000f),
        usize::from((factor >> 8) & 0x000f),
        usize::from((factor >> 12) & 0x000f),
    ];
    let mut rows = [0u16; 16];
    for row in 0..16 {
        rows[row] = table[0][selectors[0]][row]
            ^ table[1][selectors[1]][row]
            ^ table[2][selectors[2]][row]
            ^ table[3][selectors[3]][row];
    }
    rows
}

/// Logical form of `gf16_bitdep_init256`: expand multiplication by one factor
/// into the sixteen bit-plane dependencies using PAR2's 0x1100b polynomial.
/// The C routine materializes the same rows in its AVX2 lane arrangement.
fn dependency_rows_for_factor(factor: u16) -> [u16; 16] {
    let mut rows = [0u16; 16];
    for input_plane in 0..16usize {
        let contribution = gf16_mul(factor, 1u16 << (15 - input_plane));
        for (output_plane, row) in rows.iter_mut().enumerate() {
            if contribution & (1 << (15 - output_plane)) != 0 {
                *row |= 1 << input_plane;
            }
        }
    }
    rows
}

#[inline]
fn gf16_mul(mut left: u16, mut right: u16) -> u16 {
    let mut product = 0u16;
    while right != 0 {
        if right & 1 != 0 {
            product ^= left;
        }
        let carry = left & 0x8000 != 0;
        left <<= 1;
        if carry {
            left ^= 0x100b;
        }
        right >>= 1;
    }
    product
}

#[derive(Clone, Copy)]
struct Fragment {
    bytes: [u8; MEMORY_FRAGMENT_BYTES],
    len: u8,
}

impl Fragment {
    const EMPTY: Self = Self {
        bytes: [0; MEMORY_FRAGMENT_BYTES],
        len: 0,
    };

    #[cfg(test)]
    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Immutable versions of Turbo's code and operand lookup tables:
///
/// * `memory` is `xor256_jit_clut_code1` plus `xor256_jit_clut_info_mem`;
/// * `nums`, `rmask`, and `register_len` are the source-index and ModRM
///   tables consumed by `xor_write_avx_main_part`.
struct GeneratorLuts {
    memory: [Fragment; 64],
    nums: [[u8; 8]; REGISTER_LUT_ENTRIES],
    rmask: [[u8; 8]; REGISTER_LUT_ENTRIES],
    register_len: [u8; REGISTER_LUT_ENTRIES],
}

fn generator_luts() -> &'static GeneratorLuts {
    static LUTS: OnceLock<GeneratorLuts> = OnceLock::new();
    LUTS.get_or_init(GeneratorLuts::new)
}

impl GeneratorLuts {
    fn new() -> Self {
        let mut memory = [Fragment::EMPTY; 64];
        for (index, fragment) in memory.iter_mut().enumerate() {
            *fragment = memory_fragment(index as u8);
        }

        let mut nums = [[0xff; 8]; REGISTER_LUT_ENTRIES];
        let mut rmask = [[0u8; 8]; REGISTER_LUT_ENTRIES];
        let mut register_len = [0u8; REGISTER_LUT_ENTRIES];
        for mask in 0..REGISTER_LUT_ENTRIES {
            let mut position = 0usize;
            for source in 0..8usize {
                if mask & (1 << source) != 0 {
                    nums[mask][position] = source as u8;
                    // Turbo's `rmask` encodes `modrm - 0xb7`: 9 selects
                    // ymm0, 18 selects ymm1, and their OR selects ymm2.
                    rmask[mask][source] = 9;
                    position += 1;
                }
            }
            register_len[mask] = (position * 4) as u8;
        }

        Self {
            memory,
            nums,
            rmask,
            register_len,
        }
    }
}

/// Build one of Turbo's 64 memory-plane fragments. The index has three even
/// bits followed by three odd bits. `gf16_xor_avx2.c:34-53` interleaves them so
/// each plane chooses accumulator 0, 1, or 2 (both rows => common accumulator).
fn memory_fragment(index: u8) -> Fragment {
    let mut interleaved = (index & 1)
        | ((index & 8) >> 2)
        | ((index & 2) << 1)
        | ((index & 16) >> 1)
        | ((index & 4) << 2)
        | (index & 32);
    let mut writer = BodyWriter::new();
    for plane in 0..3usize {
        let selected = interleaved & 3;
        if selected != 0 {
            writer
                .vpxor_rrm(selected - 1, selected - 1, RAX, plane_offset(plane))
                .expect("fixed memory fragment fits");
        }
        interleaved >>= 2;
    }
    writer.into_fragment()
}

#[derive(Clone, Copy, Debug)]
struct PairPlan {
    even: u16,
    odd: u16,
    common_lowest: Option<u8>,
    common_highest: Option<u8>,
}

/// Match Turbo's common-mask extraction. The lowest and highest common source
/// are used to seed `ymm2`; every interior common source remains in both masks
/// so the memory/register fragment tables route it to `ymm2` as well.
#[inline]
fn pair_plan(even: u16, odd: u16) -> PairPlan {
    let common = even & odd;
    let common_lowest = lowest_bit(common);
    let without_lowest = common_lowest.map_or(common, |bit| common & !(1 << bit));
    let common_highest = highest_bit(without_lowest);
    let shared = common_lowest.map_or(0, |bit| 1 << bit) | common_highest.map_or(0, |bit| 1 << bit);
    PairPlan {
        even: even ^ shared,
        odd: odd ^ shared,
        common_lowest,
        common_highest,
    }
}

#[inline]
fn lowest_bit(mask: u16) -> Option<u8> {
    (mask != 0).then(|| mask.trailing_zeros() as u8)
}

#[inline]
fn highest_bit(mask: u16) -> Option<u8> {
    (mask != 0).then(|| 15 - mask.leading_zeros() as u8)
}

fn append_muladd_body_from_rows(
    out: &mut Vec<u8>,
    rows: &[u16; 16],
    prefetch: bool,
) -> Result<usize, TurboAvx2EmitError> {
    let luts = generator_luts();
    let mut writer = BodyWriter::new();

    // `xor_write_init_jit`: pointers arrive 384 bytes before a block. Move to
    // its 128-byte point, then retain planes 3..15 in ymm3..ymm15.
    writer.add_ri(RAX, BLOCK_BYTES)?;
    writer.add_ri(RDX, BLOCK_BYTES)?;
    for plane in 3..16usize {
        writer.vmovdqu_load(plane as u8, RAX, plane_offset(plane))?;
    }

    // Turbo emits distinct generated programs. The prefetch version advances
    // `rsi = prefetch - 128` and issues exactly its four T1 hints; the normal
    // version contains none of these instructions or a runtime branch.
    if prefetch {
        writer.add_ri(RSI, 256)?;
        for offset in [-128, -64, 0, 64] {
            writer.prefetcht1(RSI, offset)?;
        }
    }

    for pair in 0..8usize {
        let plan = pair_plan(rows[pair * 2], rows[pair * 2 + 1]);
        append_pair(&mut writer, luts, pair, plan)?;
    }

    writer.cmp_rr(RDX, RCX)?;
    writer.jl_to(0)?;
    writer.ret()?;

    let len = writer.len();
    out.extend_from_slice(writer.bytes());
    Ok(len)
}

fn append_pair(
    writer: &mut BodyWriter,
    luts: &GeneratorLuts,
    pair: usize,
    plan: PairPlan,
) -> Result<(), TurboAvx2EmitError> {
    let even_offset = plane_offset(pair * 2);
    let odd_offset = plane_offset(pair * 2 + 1);

    let (even_highest, even_rest) = split_highest(plan.even);
    let (odd_highest, odd_rest) = split_highest(plan.odd);
    append_muladd_output_seed(writer, EVEN_ACC, even_offset, even_highest)?;
    append_muladd_output_seed(writer, ODD_ACC, odd_offset, odd_highest)?;
    append_common_seed(writer, plan.common_lowest, plan.common_highest)?;

    // `memDeps` and `deps1`/`deps2` from Turbo are built only after removing
    // the top source that seeded each output accumulator.
    let memory_index = usize::from((even_rest & 0x0007) | ((odd_rest & 0x0007) << 3));
    writer.fragment(&luts.memory[memory_index])?;

    append_packed_register_xors(
        writer,
        luts,
        ((even_rest >> 3) & 0x007f) as u8,
        ((odd_rest >> 3) & 0x007f) as u8,
        3,
    )?;
    append_packed_register_xors(
        writer,
        luts,
        ((even_rest >> 10) & 0x003f) as u8,
        ((odd_rest >> 10) & 0x003f) as u8,
        10,
    )?;

    if plan.common_lowest.is_some() {
        writer.vpxor_rrr(EVEN_ACC, COMMON_ACC, EVEN_ACC)?;
        writer.vpxor_rrr(ODD_ACC, COMMON_ACC, ODD_ACC)?;
    }
    writer.vmovdqu_store(RDX, even_offset, EVEN_ACC)?;
    writer.vmovdqu_store(RDX, odd_offset, ODD_ACC)
}

#[inline]
fn split_highest(mask: u16) -> (Option<u8>, u16) {
    match highest_bit(mask) {
        Some(highest) => (Some(highest), mask & !(1 << highest)),
        None => (None, mask),
    }
}

/// Turbo's MULADD destination initialization from lines 302-316.
fn append_muladd_output_seed(
    writer: &mut BodyWriter,
    accumulator: u8,
    destination_offset: i32,
    highest: Option<u8>,
) -> Result<(), TurboAvx2EmitError> {
    match highest {
        Some(source) if source > 2 => {
            writer.vpxor_rrm(accumulator, source, RDX, destination_offset)
        }
        Some(source) => {
            writer.vmovdqu_load(accumulator, RDX, destination_offset)?;
            writer.vpxor_rrm(accumulator, accumulator, RAX, plane_offset(source as usize))
        }
        None => writer.vmovdqu_load(accumulator, RDX, destination_offset),
    }
}

/// Port of `xor_write_avx_load_part` for Turbo's common accumulator.
fn append_common_seed(
    writer: &mut BodyWriter,
    lowest: Option<u8>,
    highest: Option<u8>,
) -> Result<(), TurboAvx2EmitError> {
    let Some(lowest) = lowest else {
        return Ok(());
    };

    if lowest < 3 {
        match highest {
            Some(highest) if highest > 2 => {
                writer.vpxor_rrm(COMMON_ACC, highest, RAX, plane_offset(lowest as usize))
            }
            Some(highest) => {
                writer.vmovdqu_load(COMMON_ACC, RAX, plane_offset(highest as usize))?;
                writer.vpxor_rrm(COMMON_ACC, COMMON_ACC, RAX, plane_offset(lowest as usize))
            }
            None => writer.vmovdqu_load(COMMON_ACC, RAX, plane_offset(lowest as usize)),
        }
    } else {
        match highest {
            Some(highest) => writer.vpxor_rrr(COMMON_ACC, highest, lowest),
            None => writer.vmovdqa_rr(COMMON_ACC, lowest),
        }
    }
}

/// Scalar spelling of Turbo's AVX2 `xor_write_avx_main_part` byte formula.
///
/// The C implementation expands eight source records at once with AVX2, then
/// writes up to eight four-byte `VPXOR` instructions. The generated byte stream
/// is determined solely by `nums`, `rmask`, and the fixed `0xb7effdc5` base;
/// emitting those records directly is byte-for-byte equivalent while keeping
/// the generator portable to every host that can cross-compile this module.
fn append_packed_register_xors(
    writer: &mut BodyWriter,
    luts: &GeneratorLuts,
    even_mask: u8,
    odd_mask: u8,
    source_base: u8,
) -> Result<(), TurboAvx2EmitError> {
    let union = usize::from(even_mask | odd_mask);
    let instruction_count = usize::from(luts.register_len[union] / 4);
    for position in 0..instruction_count {
        let source_index = usize::from(luts.nums[union][position]);
        debug_assert!(source_index < 8);
        let role = luts.rmask[usize::from(even_mask)][source_index]
            | (luts.rmask[usize::from(odd_mask)][source_index] << 1);
        debug_assert!(matches!(role, 9 | 18 | 27));

        let source = source_base + source_index as u8;
        // `srcs ^ (regs + 0xb7effdc5)` in Turbo. `role` changes `0xb7` to
        // ModRM c0/c9/d2, selecting ymm0/ymm1/ymm2 for even/odd/common work.
        writer.extend(&[0xc5, 0xfd ^ (source << 3), 0xef, 0xb7 + role])?;
    }
    Ok(())
}

#[inline]
fn plane_offset(plane: usize) -> i32 {
    (plane as i32 - 4) * 32
}

/// Fixed-buffer x86-64 writer. The 1280-byte bound is enforced before a body
/// is appended to the caller's active RW W^X arena.
struct BodyWriter {
    bytes: [MaybeUninit<u8>; MAX_BODY_BYTES],
    len: usize,
}

impl BodyWriter {
    const fn new() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); MAX_BODY_BYTES],
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `push` and `extend` initialize every byte below `len`.
        unsafe { std::slice::from_raw_parts(self.bytes.as_ptr().cast(), self.len) }
    }

    fn into_fragment(self) -> Fragment {
        assert!(
            self.len <= MEMORY_FRAGMENT_BYTES,
            "Turbo memory fragment bound"
        );
        let mut bytes = [0u8; MEMORY_FRAGMENT_BYTES];
        bytes[..self.len].copy_from_slice(self.bytes());
        Fragment {
            bytes,
            len: self.len as u8,
        }
    }

    fn fragment(&mut self, fragment: &Fragment) -> Result<(), TurboAvx2EmitError> {
        self.extend(&fragment.bytes[..usize::from(fragment.len)])
    }

    fn push(&mut self, byte: u8) -> Result<(), TurboAvx2EmitError> {
        if self.len == MAX_BODY_BYTES {
            return Err(TurboAvx2EmitError::BodyTooLarge);
        }
        self.bytes[self.len].write(byte);
        self.len += 1;
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), TurboAvx2EmitError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|&end| end <= MAX_BODY_BYTES)
            .ok_or(TurboAvx2EmitError::BodyTooLarge)?;
        // SAFETY: the checked destination range is initialized from a distinct
        // immutable source slice.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.bytes.as_mut_ptr().add(self.len).cast(),
                bytes.len(),
            );
        }
        self.len = end;
        Ok(())
    }

    fn vex(
        &mut self,
        reg: u8,
        rm: u8,
        vvvv: u8,
        pp: u8,
        opcode: u8,
    ) -> Result<(), TurboAvx2EmitError> {
        let vvvv_inv = (!vvvv) & 0x0f;
        if rm < 8 {
            let r_inv = u8::from(reg < 8);
            self.extend(&[0xc5, (r_inv << 7) | (vvvv_inv << 3) | 0b100 | pp, opcode])
        } else {
            let r_inv = u8::from(reg < 8);
            let b_inv = u8::from(rm < 8);
            self.extend(&[
                0xc4,
                (r_inv << 7) | 0b0100_0001 | (b_inv << 5),
                (vvvv_inv << 3) | 0b100 | pp,
                opcode,
            ])
        }
    }

    fn modrm_reg(&mut self, reg: u8, rm: u8) -> Result<(), TurboAvx2EmitError> {
        self.push(0b11_000_000 | ((reg & 7) << 3) | (rm & 7))
    }

    fn modrm_mem(&mut self, reg: u8, base: u8, offset: i32) -> Result<(), TurboAvx2EmitError> {
        debug_assert!(base & 7 != 4, "rsp/r12 needs a SIB byte");
        let modrm = (reg & 7) << 3 | (base & 7);
        if offset == 0 {
            self.push(modrm)
        } else if (-128..=127).contains(&offset) {
            self.extend(&[0b01_000_000 | modrm, offset as i8 as u8])
        } else {
            self.push(0b10_000_000 | modrm)?;
            self.extend(&offset.to_le_bytes())
        }
    }

    fn vpxor_rrr(&mut self, dst: u8, left: u8, right: u8) -> Result<(), TurboAvx2EmitError> {
        self.vex(dst, right, left, 0b01, 0xef)?;
        self.modrm_reg(dst, right)
    }

    fn vpxor_rrm(
        &mut self,
        dst: u8,
        left: u8,
        base: u8,
        offset: i32,
    ) -> Result<(), TurboAvx2EmitError> {
        self.vex(dst, base, left, 0b01, 0xef)?;
        self.modrm_mem(dst, base, offset)
    }

    fn vmovdqa_rr(&mut self, dst: u8, src: u8) -> Result<(), TurboAvx2EmitError> {
        self.vex(dst, src, 0, 0b01, 0x6f)?;
        self.modrm_reg(dst, src)
    }

    fn vmovdqu_load(&mut self, dst: u8, base: u8, offset: i32) -> Result<(), TurboAvx2EmitError> {
        self.vex(dst, base, 0, 0b10, 0x6f)?;
        self.modrm_mem(dst, base, offset)
    }

    fn vmovdqu_store(&mut self, base: u8, offset: i32, src: u8) -> Result<(), TurboAvx2EmitError> {
        self.vex(src, base, 0, 0b10, 0x7f)?;
        self.modrm_mem(src, base, offset)
    }

    fn add_ri(&mut self, register: u8, immediate: i32) -> Result<(), TurboAvx2EmitError> {
        // `_jit_add_i` uses the shorter accumulator form for rax, preserving
        // Turbo's fixed body accounting.
        if register == RAX {
            self.extend(&[0x48, 0x05])?;
            self.extend(&immediate.to_le_bytes())
        } else if (-128..=127).contains(&immediate) {
            self.extend(&[
                0x48 | u8::from(register >= 8),
                0x83,
                0xc0 | (register & 7),
                immediate as i8 as u8,
            ])
        } else {
            self.extend(&[0x48 | u8::from(register >= 8), 0x81, 0xc0 | (register & 7)])?;
            self.extend(&immediate.to_le_bytes())
        }
    }

    fn cmp_rr(&mut self, left: u8, right: u8) -> Result<(), TurboAvx2EmitError> {
        self.extend(&[
            0x48 | (u8::from(right >= 8) << 2) | u8::from(left >= 8),
            0x39,
            0b11_000_000 | ((right & 7) << 3) | (left & 7),
        ])
    }

    fn prefetcht1(&mut self, base: u8, offset: i32) -> Result<(), TurboAvx2EmitError> {
        if base >= 8 {
            self.push(0x41)?;
        }
        self.extend(&[0x0f, 0x18])?;
        self.modrm_mem(2, base, offset)
    }

    fn jl_to(&mut self, target: usize) -> Result<(), TurboAvx2EmitError> {
        let end = self
            .len
            .checked_add(6)
            .ok_or(TurboAvx2EmitError::BodyTooLarge)?;
        let relative = i32::try_from(target as i64 - end as i64)
            .map_err(|_| TurboAvx2EmitError::BodyTooLarge)?;
        self.extend(&[0x0f, 0x8c])?;
        self.extend(&relative.to_le_bytes())
    }

    fn ret(&mut self) -> Result<(), TurboAvx2EmitError> {
        self.push(0xc3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xor_jit::{deps, deps::muladd_planar, memory::JitCode};

    fn sample(mut state: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        state |= 1;
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 24) as u8;
        }
        bytes
    }

    fn fixture_hash(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    #[test]
    fn nibble_dependency_composition_matches_every_factor() {
        for factor in 0..=u16::MAX {
            let expected = deps::compute_deps(factor);
            assert_eq!(
                compose_factor_rows(factor),
                expected.rows,
                "factor {factor:#06x}"
            );
        }
    }

    #[test]
    fn memory_lut_matches_turbo_interleaving_for_all_masks() {
        let luts = generator_luts();
        for index in 0u8..64 {
            let mut interleaved = (index & 1)
                | ((index & 8) >> 2)
                | ((index & 2) << 1)
                | ((index & 16) >> 1)
                | ((index & 4) << 2)
                | (index & 32);
            let mut expected = BodyWriter::new();
            for plane in 0..3usize {
                let selected = interleaved & 3;
                if selected != 0 {
                    expected
                        .vpxor_rrm(selected - 1, selected - 1, RAX, plane_offset(plane))
                        .unwrap();
                }
                interleaved >>= 2;
            }
            assert_eq!(luts.memory[usize::from(index)].bytes(), expected.bytes());
        }
    }

    #[test]
    fn packed_register_luts_match_turbo_nums_rmask_and_length() {
        let luts = generator_luts();
        for mask in 0..REGISTER_LUT_ENTRIES {
            let mut position = 0usize;
            for source in 0..8usize {
                if mask & (1 << source) != 0 {
                    assert_eq!(luts.nums[mask][position], source as u8);
                    assert_eq!(luts.rmask[mask][source], 9);
                    position += 1;
                } else {
                    assert_eq!(luts.rmask[mask][source], 0);
                }
            }
            assert!(
                luts.nums[mask][position..]
                    .iter()
                    .all(|&value| value == 0xff)
            );
            assert_eq!(usize::from(luts.register_len[mask]), position * 4);
        }
    }

    #[test]
    fn packed_register_encoding_matches_turbo_formula_exhaustively() {
        let luts = generator_luts();
        for source_base in [3u8, 10] {
            let width = if source_base == 3 { 128 } else { 64 };
            for even in 0..width {
                for odd in 0..width {
                    let mut actual = BodyWriter::new();
                    append_packed_register_xors(
                        &mut actual,
                        luts,
                        even as u8,
                        odd as u8,
                        source_base,
                    )
                    .unwrap();

                    let union = even | odd;
                    let mut expected = Vec::new();
                    for source in 0..8usize {
                        if union & (1 << source) == 0 {
                            continue;
                        }
                        let role = if even & (1 << source) != 0 { 9 } else { 0 }
                            | if odd & (1 << source) != 0 { 18 } else { 0 };
                        let register = source_base + source as u8;
                        expected.extend_from_slice(&[
                            0xc5,
                            0xfd ^ (register << 3),
                            0xef,
                            0xb7 + role,
                        ]);
                    }
                    assert_eq!(
                        actual.bytes(),
                        expected,
                        "base {source_base}, {even:#x}/{odd:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn pair_partition_routes_every_common_dependency_to_common_accumulator() {
        for factor in 0..=u16::MAX {
            let rows = compose_factor_rows(factor);
            for pair in 0..8usize {
                let even = rows[pair * 2];
                let odd = rows[pair * 2 + 1];
                let plan = pair_plan(even, odd);
                let shared = plan.common_lowest.map_or(0, |bit| 1 << bit)
                    | plan.common_highest.map_or(0, |bit| 1 << bit);
                assert_eq!(plan.even ^ shared, even);
                assert_eq!(plan.odd ^ shared, odd);
                assert_eq!(plan.even & plan.odd, (even & odd) & !shared);
            }
        }
    }

    #[test]
    fn all_factor_bodies_fit_turbo_bound() {
        let mut normal = Vec::with_capacity(MAX_BODY_BYTES);
        let mut prefetch = Vec::with_capacity(MAX_BODY_BYTES);
        for factor in 0..=u16::MAX {
            normal.clear();
            prefetch.clear();
            let normal_len = append_muladd_body(&mut normal, factor, false).unwrap();
            let prefetch_len = append_muladd_body(&mut prefetch, factor, true).unwrap();
            assert_eq!(normal_len, normal.len());
            assert_eq!(prefetch_len, prefetch.len());
            assert_eq!(normal.last(), Some(&0xc3));
            assert_eq!(prefetch.last(), Some(&0xc3));
            assert!(normal_len <= MAX_BODY_BYTES, "normal factor {factor:#06x}");
            assert!(
                prefetch_len <= MAX_BODY_BYTES,
                "prefetch factor {factor:#06x}"
            );
        }
    }

    #[test]
    fn generated_bodies_match_normalized_turbo_oracle_fixtures() {
        // Generated from par2cmdline-turbo 4db49ca45ab258c230061fb3f0d29273f7c524ea
        // with its actual AVX2 dependency initializer and writer. The oracle
        // bytes normalize only memory VMOVDQA to this crate's VMOVDQU contract.
        let fixtures = [
            (0x0001, false, 332, 0x775b_78fb_f25b_ce45),
            (0x0001, true, 354, 0x172b_5ff8_d928_71a1),
            (0x1234, false, 675, 0xdcd9_df98_3279_cfa1),
            (0x1234, true, 697, 0x2b08_72d7_6977_4041),
            (0xa53c, false, 697, 0x405f_81ac_572a_53a1),
            (0xa53c, true, 719, 0x6f75_8e27_51d2_e391),
            (0xffff, false, 751, 0x4bf8_a7f2_fc31_fef3),
            (0xffff, true, 773, 0x9bf6_f852_63b0_fb7e),
        ];

        for (factor, prefetch, expected_len, expected_hash) in fixtures {
            let mut body = Vec::new();
            append_muladd_body(&mut body, factor, prefetch).unwrap();
            assert_eq!(body.len(), expected_len, "factor {factor:#06x}");
            assert_eq!(fixture_hash(&body), expected_hash, "factor {factor:#06x}");
        }
    }

    #[test]
    fn prefetch_and_normal_programs_have_distinct_turbo_lifecycles() {
        let mut normal = Vec::new();
        let mut prefetch = Vec::new();
        append_muladd_body(&mut normal, 0xa53c, false).unwrap();
        append_muladd_body(&mut prefetch, 0xa53c, true).unwrap();

        assert_ne!(normal, prefetch);
        assert!(!normal.windows(3).any(|bytes| bytes == [0x48, 0x85, 0xf6]));
        assert!(!prefetch.windows(3).any(|bytes| bytes == [0x48, 0x85, 0xf6]));
        assert!(!normal.windows(3).any(|bytes| bytes == [0x0f, 0x18, 0x56]));
        assert!(prefetch.windows(3).any(|bytes| bytes == [0x0f, 0x18, 0x56]));
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn sampled_bodies_execute_like_scalar_oracle_with_and_without_prefetch() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        let mut factors = vec![0, 1, 2, 3, 0x0101, 0x1234, 0x4000, 0x8000, 0xabcd, 0xffff];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..96 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            factors.push(state as u16);
        }

        for factor in factors {
            let deps = deps::compute_deps(factor);
            let src = sample(u64::from(factor) * 0x9e37_79b9, BLOCK_BYTES as usize * 3);
            let initial = sample(u64::from(factor) * 0x85eb_ca6b, src.len());
            let mut expected = initial.clone();
            muladd_planar(&deps, &src, &mut expected);

            let mut normal_body = Vec::new();
            append_muladd_body(&mut normal_body, factor, false).unwrap();
            let normal_jit = JitCode::new(&normal_body).unwrap();

            let mut plain = initial.clone();
            unsafe { normal_jit.run_muladd(src.as_ptr(), plain.as_mut_ptr(), plain.len()) };
            assert_eq!(plain, expected, "plain factor {factor:#06x}");

            let mut prefetch_body = Vec::new();
            append_muladd_body(&mut prefetch_body, factor, true).unwrap();
            let prefetch_jit = JitCode::new(&prefetch_body).unwrap();
            let prefetch = vec![0u8; src.len()];
            let mut hinted = initial;
            unsafe {
                prefetch_jit.run_muladd_prefetch(
                    src.as_ptr(),
                    hinted.as_mut_ptr(),
                    hinted.len(),
                    prefetch.as_ptr(),
                )
            };
            assert_eq!(hinted, expected, "prefetch factor {factor:#06x}");
        }
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn one_block_misaligned_buffers_match_scalar_oracle() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let factor = 0xa53c;
        let deps = deps::compute_deps(factor);
        let len = BLOCK_BYTES as usize;
        let mut source_storage = sample(0x1111, len + 3);
        let source = &mut source_storage[1..1 + len];
        let initial = sample(0x2222, len);
        let mut expected = initial.clone();
        muladd_planar(&deps, source, &mut expected);

        for prefetch_enabled in [false, true] {
            let mut body = Vec::new();
            append_muladd_body(&mut body, factor, prefetch_enabled).unwrap();
            let jit = JitCode::new(&body).unwrap();
            let mut destination_storage = vec![0u8; len + 5];
            let destination = &mut destination_storage[3..3 + len];
            destination.copy_from_slice(&initial);

            unsafe {
                if prefetch_enabled {
                    let prefetch = vec![0u8; len];
                    jit.run_muladd_prefetch(
                        source.as_ptr(),
                        destination.as_mut_ptr(),
                        len,
                        prefetch.as_ptr(),
                    );
                } else {
                    jit.run_muladd(source.as_ptr(), destination.as_mut_ptr(), len);
                }
            }
            assert_eq!(destination, expected);
        }
    }
}
