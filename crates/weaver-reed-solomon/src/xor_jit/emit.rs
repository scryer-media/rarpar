//! Minimal x86-64 machine-code emitter for the XOR-JIT GF(2^16) multiply tier.
//!
//! Emits only the instruction subset the XOR reconstruction codegen needs
//! (see `scryer-docs/plans/125`): 256-bit `vpxor`/`vmovdqa`, and the scalar
//! `add`/`cmp`/`jl`/`ret`/`prefetcht1` for the block loop. The byte formulas
//! follow ParPar's `x86_jit.h` where an upstream counterpart exists; the
//! `vmovdqu` (F3-prefixed, unaligned) forms are rarpar additions — upstream
//! emits only `vmovdqa` because its buffers are alignment-guaranteed.
//!
//! Every function appends little-endian machine code to a `Vec<u8>`. Nothing
//! here executes code — that is the caller's job via a W^X buffer
//! ([`super::memory`]). Correctness is pinned by byte-exact unit tests.
//!
//! Encoding rules (AVX2, 256-bit, `W=0`, `pp=66`, map `0F`):
//! - 2-byte VEX (`C5`) when the ModRM.rm register/base is < 8; else 3-byte
//!   (`C4`). `VEX.R`/`VEX.B`/`VEX.vvvv` are stored inverted.
//! - Displacement: none when `off == 0`, `disp8` when it fits a signed byte,
//!   else `disp32`. The only base registers used (rax/rcx/rdx/rsi) are never
//!   rsp(4)/rbp(5), so no SIB byte and no `mod=00`/rbp special case arises.

/// General-purpose register encodings (low 8). These are the only GPRs the
/// generated code touches — as pointers and the loop counter.
pub const RAX: u8 = 0;
pub const RCX: u8 = 1;
pub const RDX: u8 = 2;
pub const RSI: u8 = 6;

/// Emit a VEX prefix + opcode for a 256-bit AVX instruction.
///
/// `reg` = ModRM.reg register (0-15), `rm` = ModRM.rm register or memory base
/// (0-15; bases are always < 8), `vvvv` = the non-destructive source operand
/// (0-15), or 0 for instructions without one (encoded as the mandatory 1111).
/// `pp` selects the mandatory prefix: `0b01` = `66` (vpxor, vmovdqa),
/// `0b10` = `F3` (vmovdqu).
fn emit_vex(buf: &mut Vec<u8>, reg: u8, rm: u8, vvvv: u8, pp: u8, opcode: u8) {
    let vvvv_inv = (!vvvv) & 0x0f;
    if rm < 8 {
        // 2-byte VEX: C5, [R:1 vvvv:4 L:1 pp:2]
        let r_inv: u8 = if reg >= 8 { 0 } else { 1 };
        let byte2 = (r_inv << 7) | (vvvv_inv << 3) | (1 << 2) | pp; // L=1
        buf.push(0xC5);
        buf.push(byte2);
    } else {
        // 3-byte VEX: C4, [R:1 X:1 B:1 mmmmm:5], [W:1 vvvv:4 L:1 pp:2]
        let r_inv: u8 = if reg >= 8 { 0 } else { 1 };
        let b_inv: u8 = if rm >= 8 { 0 } else { 1 };
        let byte2 = (r_inv << 7) | (1 << 6) | (b_inv << 5) | 0b0_0001; // X=1(inv), map=0F
        let byte3 = (vvvv_inv << 3) | (1 << 2) | pp; // W=0, L=1
        buf.push(0xC4);
        buf.push(byte2);
        buf.push(byte3);
    }
    buf.push(opcode);
}

/// Emit ModRM + displacement for a `reg, [base+off]` memory operand.
/// Bases are rax/rcx/rdx/rsi only (see module doc): no SIB (rsp/r12) or
/// mod=00 RIP-relative (rbp/r13) handling.
fn emit_modrm_mem(buf: &mut Vec<u8>, reg: u8, base: u8, off: i32) {
    debug_assert!(base & 7 != 4, "rsp/r12-class bases need a SIB byte");
    debug_assert!(
        base & 7 != 5 || off != 0,
        "rbp/r13-class base with offset 0 would encode RIP-relative"
    );
    let reg3 = reg & 7;
    let base3 = base & 7;
    if off == 0 {
        buf.push((reg3 << 3) | base3); // mod=00, no displacement
    } else if (-128..=127).contains(&off) {
        buf.push((0b01 << 6) | (reg3 << 3) | base3);
        buf.push(off as i8 as u8);
    } else {
        buf.push((0b10 << 6) | (reg3 << 3) | base3);
        buf.extend_from_slice(&off.to_le_bytes());
    }
}

/// Emit ModRM for a register-register operand (`mod=11`).
fn emit_modrm_reg(buf: &mut Vec<u8>, reg: u8, rm: u8) {
    buf.push((0b11 << 6) | ((reg & 7) << 3) | (rm & 7));
}

/// `VPXOR ymm[d], ymm[s1], ymm[s2]`
pub fn vpxor_rrr(buf: &mut Vec<u8>, d: u8, s1: u8, s2: u8) {
    emit_vex(buf, d, s2, s1, 0b01, 0xEF);
    emit_modrm_reg(buf, d, s2);
}

/// `VPXOR ymm[d], ymm[s1], [base+off]` (VEX memory operand — no alignment req).
pub fn vpxor_rrm(buf: &mut Vec<u8>, d: u8, s1: u8, base: u8, off: i32) {
    emit_vex(buf, d, base, s1, 0b01, 0xEF);
    emit_modrm_mem(buf, d, base, off);
}

/// `VMOVDQU ymm[d], [base+off]` (unaligned load — no 32-byte alignment req).
pub fn vmovdqu_load(buf: &mut Vec<u8>, d: u8, base: u8, off: i32) {
    emit_vex(buf, d, base, 0, 0b10, 0x6F);
    emit_modrm_mem(buf, d, base, off);
}

/// `VMOVDQU [base+off], ymm[s]` (unaligned store).
pub fn vmovdqu_store(buf: &mut Vec<u8>, base: u8, off: i32, s: u8) {
    emit_vex(buf, s, base, 0, 0b10, 0x7F);
    emit_modrm_mem(buf, s, base, off);
}

/// `VMOVDQA ymm[d], ymm[s]` (register move; alignment is irrelevant reg-to-reg)
pub fn vmovdqa_rr(buf: &mut Vec<u8>, d: u8, s: u8) {
    emit_vex(buf, d, s, 0, 0b01, 0x6F);
    emit_modrm_reg(buf, d, s);
}

/// `ADD r64, imm32` (`REX.W 81 /0 id`)
pub fn add_ri(buf: &mut Vec<u8>, reg: u8, imm: i32) {
    buf.push(0x48 | ((reg >= 8) as u8)); // REX.W (+B if reg>=8)
    buf.push(0x81);
    buf.push((0b11 << 6) | (reg & 7)); // /0, mod=11
    buf.extend_from_slice(&imm.to_le_bytes());
}

/// `CMP r64_a, r64_b` (`REX.W 39 /r`: compares rm=a against reg=b)
pub fn cmp_rr(buf: &mut Vec<u8>, a: u8, b: u8) {
    buf.push(0x48 | (((b >= 8) as u8) << 2) | ((a >= 8) as u8)); // REX.W (+R if b>=8, +B if a>=8)
    buf.push(0x39);
    buf.push((0b11 << 6) | ((b & 7) << 3) | (a & 7));
}

/// `JL rel32` (`0F 8C cd`). `rel` is relative to the end of this 6-byte
/// instruction. Use [`jl_to`] to target an absolute buffer offset.
pub fn jl_rel32(buf: &mut Vec<u8>, rel: i32) {
    buf.push(0x0F);
    buf.push(0x8C);
    buf.extend_from_slice(&rel.to_le_bytes());
}

/// `JL` to an absolute offset within `buf` (the loop back-edge targets 0).
pub fn jl_to(buf: &mut Vec<u8>, target: usize) {
    let end = buf.len() as i64 + 6; // this instruction is 6 bytes
    let rel = (target as i64) - end;
    jl_rel32(buf, rel as i32);
}

/// `RET`
pub fn ret(buf: &mut Vec<u8>) {
    buf.push(0xC3);
}

// ---------------------------------------------------------------------------
// EVEX (AVX-512, 512-bit, W=0) emitters for the XOR-JIT AVX512 tier.
//
// Byte layout: `62`, P0 = [R X B R' | m m m] (R/X/B/R' inverted; for reg-reg
// forms X/B carry ModRM.rm bits 4/3, for memory forms X=1 and B carries the
// base's bit 3), P1 = [W=0 | !vvvv:4 | 1 | pp], P2 = [z=0 L'L=10 b=0 | !V' |
// aaa=000] where V' is vvvv bit 4. Memory displacements use EVEX compressed
// disp8 (scale 64 for full-width zmm ops) — every plane offset the codegen
// uses is a multiple of 64 within disp8 range, so upstream's `-384` pointer
// bias trick (gf16_xor_common.h) is unnecessary here: bias 0, all disp8.
// Encodings pinned byte-exact against the system assembler in the tests.
// ---------------------------------------------------------------------------

/// An EVEX-encoded operation: mandatory prefix bits (`pp`, as VEX), opcode
/// map (`mm`: 0b001 = 0F, 0b011 = 0F3A), and the opcode byte.
#[derive(Clone, Copy)]
struct EvexOp {
    pp: u8,
    mm: u8,
    opcode: u8,
}

const EVEX_PXORD: EvexOp = EvexOp {
    pp: 0b01,
    mm: 0b001,
    opcode: 0xEF,
};
const EVEX_TERNLOGD: EvexOp = EvexOp {
    pp: 0b01,
    mm: 0b011,
    opcode: 0x25,
};
const EVEX_MOVDQU32_LOAD: EvexOp = EvexOp {
    pp: 0b10,
    mm: 0b001,
    opcode: 0x6F,
};
const EVEX_MOVDQU32_STORE: EvexOp = EvexOp {
    pp: 0b10,
    mm: 0b001,
    opcode: 0x7F,
};
const EVEX_MOVDQA32_RR: EvexOp = EvexOp {
    pp: 0b01,
    mm: 0b001,
    opcode: 0x6F,
};

/// EVEX prefix + opcode. `rm_high` carries ModRM.rm bits 4/3 for reg-reg
/// forms (register number), or the memory base register (always < 8 here)
/// for memory forms.
fn emit_evex(buf: &mut Vec<u8>, reg: u8, rm_high: u8, mem: bool, vvvv: u8, op: EvexOp) {
    let r_inv = (!(reg >> 3) & 1) << 7;
    let x_inv = if mem {
        1 << 6
    } else {
        (!(rm_high >> 4) & 1) << 6
    };
    let b_inv = (!(rm_high >> 3) & 1) << 5;
    let rp_inv = (!(reg >> 4) & 1) << 4;
    buf.push(0x62);
    buf.push(r_inv | x_inv | b_inv | rp_inv | op.mm);
    buf.push((((!vvvv) & 0x0f) << 3) | 0b100 | op.pp);
    buf.push(0x40 | ((!(vvvv >> 4) & 1) << 3)); // L'L=10 (512-bit)
    buf.push(op.opcode);
}

/// ModRM + displacement with EVEX compressed disp8 (N=64, full-width zmm).
///
/// Same base-register precondition as [`emit_modrm_mem`]: no SIB or
/// RIP-relative handling, so rsp/r12-class bases are unsupported and
/// rbp/r13-class bases cannot take offset 0.
fn emit_modrm_mem_c64(buf: &mut Vec<u8>, reg: u8, base: u8, off: i32) {
    debug_assert!(base & 7 != 4, "rsp/r12-class bases need a SIB byte");
    debug_assert!(
        base & 7 != 5 || off != 0,
        "rbp/r13-class base with offset 0 would encode RIP-relative"
    );
    let reg3 = reg & 7;
    let base3 = base & 7;
    if off == 0 {
        buf.push((reg3 << 3) | base3);
    } else if off % 64 == 0 && (-128..=127).contains(&(off / 64)) {
        buf.push((0b01 << 6) | (reg3 << 3) | base3);
        buf.push((off / 64) as i8 as u8);
    } else {
        buf.push((0b10 << 6) | (reg3 << 3) | base3);
        buf.extend_from_slice(&off.to_le_bytes());
    }
}

/// `VPXORD zmm[d], zmm[s1], zmm[s2]` (regs 0-31)
pub fn vpxord_rrr(buf: &mut Vec<u8>, d: u8, s1: u8, s2: u8) {
    emit_evex(buf, d, s2, false, s1, EVEX_PXORD);
    emit_modrm_reg(buf, d, s2);
}

/// `VPTERNLOGD zmm[d], zmm[s1], zmm[s2], 0x96` — 3-way XOR: `d ^= s1 ^ s2`.
pub fn vpternlogd_xor3(buf: &mut Vec<u8>, d: u8, s1: u8, s2: u8) {
    emit_evex(buf, d, s2, false, s1, EVEX_TERNLOGD);
    emit_modrm_reg(buf, d, s2);
    buf.push(0x96);
}

/// `VMOVDQU32 zmm[d], [base+off]`
pub fn vmovdqu32_load(buf: &mut Vec<u8>, d: u8, base: u8, off: i32) {
    emit_evex(buf, d, base, true, 0, EVEX_MOVDQU32_LOAD);
    emit_modrm_mem_c64(buf, d, base, off);
}

/// `VMOVDQU32 [base+off], zmm[s]`
pub fn vmovdqu32_store(buf: &mut Vec<u8>, base: u8, off: i32, s: u8) {
    emit_evex(buf, s, base, true, 0, EVEX_MOVDQU32_STORE);
    emit_modrm_mem_c64(buf, s, base, off);
}

/// `VMOVDQA32 zmm[d], zmm[s]` (register move)
pub fn vmovdqa32_rr(buf: &mut Vec<u8>, d: u8, s: u8) {
    emit_evex(buf, d, s, false, 0, EVEX_MOVDQA32_RR);
    emit_modrm_reg(buf, d, s);
}

/// `PREFETCHT1 [base+off]` (`0F 18 /2`)
pub fn prefetcht1(buf: &mut Vec<u8>, base: u8, off: i32) {
    if base >= 8 {
        buf.push(0x41); // REX.B
    }
    buf.push(0x0F);
    buf.push(0x18);
    emit_modrm_mem(buf, 2, base, off); // /2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emit<F: FnOnce(&mut Vec<u8>)>(f: F) -> Vec<u8> {
        let mut b = Vec::new();
        f(&mut b);
        b
    }

    #[test]
    fn vpxor_reg_reg() {
        // vpxor ymm0, ymm0, ymm0  -> C5 FD EF C0  (matches ParPar template)
        assert_eq!(emit(|b| vpxor_rrr(b, 0, 0, 0)), [0xC5, 0xFD, 0xEF, 0xC0]);
        // vpxor ymm1, ymm2, ymm3  -> C5 ED EF CB
        assert_eq!(emit(|b| vpxor_rrr(b, 1, 2, 3)), [0xC5, 0xED, 0xEF, 0xCB]);
        // second source >= 8 forces 3-byte VEX: vpxor ymm0, ymm0, ymm8 -> C4 C1 7D EF C0
        assert_eq!(
            emit(|b| vpxor_rrr(b, 0, 0, 8)),
            [0xC4, 0xC1, 0x7D, 0xEF, 0xC0]
        );
        // dest >= 8 keeps 2-byte VEX (R bit): vpxor ymm8, ymm0, ymm0 -> C5 7D EF C0
        assert_eq!(emit(|b| vpxor_rrr(b, 8, 0, 0)), [0xC5, 0x7D, 0xEF, 0xC0]);
        // vpxor ymm15, ymm14, ymm13 -> C4 41 0D EF FD (dest+rm >= 8)
        assert_eq!(
            emit(|b| vpxor_rrr(b, 15, 14, 13)),
            [0xC4, 0x41, 0x0D, 0xEF, 0xFD]
        );
    }

    #[test]
    fn vpxor_reg_mem() {
        // vpxor ymm0, ymm0, [rax-128] -> C5 FD EF 40 80
        assert_eq!(
            emit(|b| vpxor_rrm(b, 0, 0, RAX, -128)),
            [0xC5, 0xFD, 0xEF, 0x40, 0x80]
        );
        // vpxor ymm0, ymm0, [rax] -> C5 FD EF 00
        assert_eq!(
            emit(|b| vpxor_rrm(b, 0, 0, RAX, 0)),
            [0xC5, 0xFD, 0xEF, 0x00]
        );
    }

    #[test]
    fn vmovdqu_variants() {
        // vmovdqu ymm3, [rax-32] -> C5 FE 6F 58 E0 (pp=F3)
        assert_eq!(
            emit(|b| vmovdqu_load(b, 3, RAX, -32)),
            [0xC5, 0xFE, 0x6F, 0x58, 0xE0]
        );
        // vmovdqu ymm15, [rax+352] -> C5 7E 6F B8 60 01 00 00
        assert_eq!(
            emit(|b| vmovdqu_load(b, 15, RAX, 352)),
            [0xC5, 0x7E, 0x6F, 0xB8, 0x60, 0x01, 0x00, 0x00]
        );
        // vmovdqu [rdx-128], ymm0 -> C5 FE 7F 42 80
        assert_eq!(
            emit(|b| vmovdqu_store(b, RDX, -128, 0)),
            [0xC5, 0xFE, 0x7F, 0x42, 0x80]
        );
        // vmovdqa ymm5, ymm6 -> C5 FD 6F EE (reg-reg, pp=66)
        assert_eq!(emit(|b| vmovdqa_rr(b, 5, 6)), [0xC5, 0xFD, 0x6F, 0xEE]);
    }

    #[test]
    fn scalar_ops() {
        // add rax, 512 -> 48 81 C0 00 02 00 00
        assert_eq!(
            emit(|b| add_ri(b, RAX, 512)),
            [0x48, 0x81, 0xC0, 0x00, 0x02, 0x00, 0x00]
        );
        // add rdx, 512 -> 48 81 C2 00 02 00 00
        assert_eq!(
            emit(|b| add_ri(b, RDX, 512)),
            [0x48, 0x81, 0xC2, 0x00, 0x02, 0x00, 0x00]
        );
        // cmp rdx, rcx -> 48 39 CA  (matches ParPar back-edge)
        assert_eq!(emit(|b| cmp_rr(b, RDX, RCX)), [0x48, 0x39, 0xCA]);
        // ret -> C3
        assert_eq!(emit(ret), [0xC3]);
        // prefetcht1 [rsi] -> 0F 18 16  (/2, base rsi=6)
        assert_eq!(emit(|b| prefetcht1(b, RSI, 0)), [0x0F, 0x18, 0x16]);
    }

    /// Every expected byte sequence below was produced by assembling the
    /// corresponding Intel-syntax instruction with the system assembler
    /// (clang -target x86_64) and dumping the object bytes.
    #[test]
    fn evex_encodings_match_system_assembler() {
        // vmovdqu32 zmm16, [rax+64] -> 62 E1 7E 48 6F 40 01 (compressed disp8)
        assert_eq!(
            emit(|b| vmovdqu32_load(b, 16, RAX, 64)),
            [0x62, 0xE1, 0x7E, 0x48, 0x6F, 0x40, 0x01]
        );
        // vmovdqu32 zmm3, [rax] -> 62 F1 7E 48 6F 18
        assert_eq!(
            emit(|b| vmovdqu32_load(b, 3, RAX, 0)),
            [0x62, 0xF1, 0x7E, 0x48, 0x6F, 0x18]
        );
        // vmovdqu32 zmm31, [rax+960] -> 62 61 7E 48 6F 78 0F
        assert_eq!(
            emit(|b| vmovdqu32_load(b, 31, RAX, 960)),
            [0x62, 0x61, 0x7E, 0x48, 0x6F, 0x78, 0x0F]
        );
        // vmovdqu32 [rdx+128], zmm0 -> 62 F1 7E 48 7F 42 02
        assert_eq!(
            emit(|b| vmovdqu32_store(b, RDX, 128, 0)),
            [0x62, 0xF1, 0x7E, 0x48, 0x7F, 0x42, 0x02]
        );
        // vmovdqu32 [rdx+960], zmm17 -> 62 E1 7E 48 7F 4A 0F
        assert_eq!(
            emit(|b| vmovdqu32_store(b, RDX, 960, 17)),
            [0x62, 0xE1, 0x7E, 0x48, 0x7F, 0x4A, 0x0F]
        );
        // vpxord zmm0, zmm0, zmm16 -> 62 B1 7D 48 EF C0
        assert_eq!(
            emit(|b| vpxord_rrr(b, 0, 0, 16)),
            [0x62, 0xB1, 0x7D, 0x48, 0xEF, 0xC0]
        );
        // vpxord zmm2, zmm2, zmm31 -> 62 91 6D 48 EF D7
        assert_eq!(
            emit(|b| vpxord_rrr(b, 2, 2, 31)),
            [0x62, 0x91, 0x6D, 0x48, 0xEF, 0xD7]
        );
        // vpxord zmm1, zmm1, zmm7 -> 62 F1 75 48 EF CF
        assert_eq!(
            emit(|b| vpxord_rrr(b, 1, 1, 7)),
            [0x62, 0xF1, 0x75, 0x48, 0xEF, 0xCF]
        );
        // vpternlogd zmm0, zmm16, zmm31, 0x96 -> 62 93 7D 40 25 C7 96
        assert_eq!(
            emit(|b| vpternlogd_xor3(b, 0, 16, 31)),
            [0x62, 0x93, 0x7D, 0x40, 0x25, 0xC7, 0x96]
        );
        // vpternlogd zmm1, zmm2, zmm3, 0x96 -> 62 F3 6D 48 25 CB 96
        assert_eq!(
            emit(|b| vpternlogd_xor3(b, 1, 2, 3)),
            [0x62, 0xF3, 0x6D, 0x48, 0x25, 0xCB, 0x96]
        );
        // vpternlogd zmm2, zmm24, zmm17, 0x96 -> 62 B3 3D 40 25 D1 96
        assert_eq!(
            emit(|b| vpternlogd_xor3(b, 2, 24, 17)),
            [0x62, 0xB3, 0x3D, 0x40, 0x25, 0xD1, 0x96]
        );
        // vmovdqa32 zmm2, zmm19 -> 62 B1 7D 48 6F D3
        assert_eq!(
            emit(|b| vmovdqa32_rr(b, 2, 19)),
            [0x62, 0xB1, 0x7D, 0x48, 0x6F, 0xD3]
        );
        // vmovdqa32 zmm0, zmm5 -> 62 F1 7D 48 6F C5
        assert_eq!(
            emit(|b| vmovdqa32_rr(b, 0, 5)),
            [0x62, 0xF1, 0x7D, 0x48, 0x6F, 0xC5]
        );
    }

    #[test]
    fn jl_backedge() {
        // jl rel32 = -20 -> 0F 8C EC FF FF FF
        assert_eq!(
            emit(|b| jl_rel32(b, -20)),
            [0x0F, 0x8C, 0xEC, 0xFF, 0xFF, 0xFF]
        );
        // jl_to(0) after emitting some bytes: rel = 0 - (len + 6)
        let mut b = vec![0u8; 10];
        jl_to(&mut b, 0);
        let rel = i32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        assert_eq!(rel, -16); // 0 - (10 + 6)
    }
}
