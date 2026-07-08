//! Minimal x86-64 machine-code emitter for the XOR-JIT GF(2^16) multiply tier.
//!
//! Emits only the instruction subset the XOR reconstruction codegen needs
//! (see `scryer-docs/plans/125`): 256-bit `vpxor`/`vmovdqa`, and the scalar
//! `add`/`cmp`/`jl`/`ret`/`prefetcht1` for the block loop. This is a faithful,
//! dependency-free port of the byte formulas in ParPar's `x86_jit.h`.
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
fn emit_modrm_mem(buf: &mut Vec<u8>, reg: u8, base: u8, off: i32) {
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
