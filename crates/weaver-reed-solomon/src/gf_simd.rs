//! SIMD-accelerated GF(2^16) region operations.
//!
//! Provides a bulk multiply-accumulate operation over byte regions interpreted
//! as little-endian u16 words in GF(2^16):
//!
//! ```text
//! dst[i] ^= gf_mul(src[i], factor)    for each u16 word i
//! ```
//!
//! Three kernel families, selected at runtime by CPU capability:
//!
//! ## GFNI affine (Ice Lake+ / Zen 4+)
//!
//! GF(2^16) multiplication is linear over GF(2), so it's a 16×16 binary matrix.
//! Split into four 8×8 sub-matrices and apply with `gf2p8affineqb`, which does
//! 8×8 binary matrix × byte in a single instruction. 4 affine transforms + 2 XORs
//! replace 8 PSHUFB + 4 nibble extractions + 6 XORs — roughly half the instructions.
//!
//! ## Split-nibble shuffle (SSSE3 / AVX2 / NEON)
//!
//! 1. Precompute 8 tables of 16 bytes each. Each table maps a 4-bit nibble of
//!    the input to its contribution to one byte of the 16-bit product.
//! 2. Deinterleave input bytes (separate lo/hi bytes of each u16 word).
//! 3. For each nibble, do a PSHUFB/VTBL lookup. XOR the 4 contributions for
//!    the result low byte and the 4 for the result high byte.
//! 4. Reinterleave and XOR-accumulate into the destination.
//!
//! ## Scalar
//!
//! One word at a time via log/antilog tables.

use crate::gf;

/// Concurrent source read streams per destination pass in the grouped-input
/// kernels. Bounded by the line-fill buffers of the smallest supported cores;
/// larger groups stall on L1 misses instead of computing.
///
/// Deliberate deviations from ParPar's muladd_multi machinery, for the record:
/// this is a memory-stream bound over flat separate source slices, not
/// upstream's per-method register-interleave over a packed input layout
/// (`idealInputMultiple` = 3/2/1 per method, gf16mul.cpp:234-525), and
/// upstream's per-cacheline software prefetch (`_mm_prefetch`/`PREFETCH_MEM`
/// throughout its cores, plus the `_stridepf`/`_packpf` drivers) is not
/// carried over — modern large-core hardware prefetchers cover the flat
/// streaming pattern; revisit if small-core x86 profiles say otherwise.
/// On aarch64 an explicit source-stream prefetch experiment exists behind
/// [`NEON_SRC_PREFETCH`], currently off pending measurement.
#[cfg(target_arch = "x86_64")]
const SRC_STREAM_GROUP: usize = 8;

/// Software-prefetch experiment for the aarch64 streaming kernels — PRFM
/// PLDL1KEEP two 32-byte blocks ahead of each source stream in the NEON
/// region kernel and the CLMUL input-batch body.
///
/// UNMEASURED: off by default so behavior is unchanged until a dedicated
/// benchmark pass decides keep/revert. To A/B, flip to `true` and compare
/// `gf_kernel/mul_acc_region_64kb` and
/// `gf_kernel/mul_acc_input_batch_64kb_x8src`; keep only on a reproducible
/// ≥2% win (the SRC_STREAM_GROUP note above records why software prefetch
/// was originally dropped).
#[cfg(target_arch = "aarch64")]
const NEON_SRC_PREFETCH: bool = false;

/// PRFM PLDL1KEEP hint: pull the line holding `ptr` toward L1 ahead of the
/// streaming loads. A pure hint — never faults, any address is fine (callers
/// pass `wrapping_add` pointers that may run past the buffer end).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn prefetch_src_l1(ptr: *const u8) {
    unsafe {
        std::arch::asm!(
            "prfm pldl1keep, [{p}]",
            p = in(reg) ptr,
            options(nostack, preserves_flags, readonly)
        );
    }
}

/// Precomputed shuffle tables for a single GF(2^16) multiplication factor.
///
/// For a given `factor`, multiplying an arbitrary 16-bit input `x` by `factor`
/// can be decomposed as:
///
/// ```text
/// factor * x = factor*n0 ^ factor*(n1*16) ^ factor*(n2*256) ^ factor*(n3*4096)
/// ```
///
/// where n0..n3 are the 4 nibbles of x. Each partial product is a 16-bit value
/// with only 16 possible values (one per nibble value 0..15).
///
/// We store these as 8 byte-tables: for each nibble position (4), we store the
/// low byte and high byte of the partial product separately. This maps directly
/// to PSHUFB / VTBL which operate on bytes.
#[derive(Clone)]
pub struct MulTables {
    /// tables[0]: low byte of result contribution from nibble 0 (bits 0-3 of input low byte)
    /// tables[1]: high byte of result contribution from nibble 0
    /// tables[2]: low byte of result contribution from nibble 1 (bits 4-7 of input low byte)
    /// tables[3]: high byte of result contribution from nibble 1
    /// tables[4]: low byte of result contribution from nibble 2 (bits 0-3 of input high byte)
    /// tables[5]: high byte of result contribution from nibble 2
    /// tables[6]: low byte of result contribution from nibble 3 (bits 4-7 of input high byte)
    /// tables[7]: high byte of result contribution from nibble 3
    pub tables: [[u8; 16]; 8],
    /// The original factor, stored for scalar tail processing.
    pub factor: u16,
}

/// Precompute the 8 shuffle tables for a given GF(2^16) multiplication factor.
pub fn precompute_mul_tables(factor: u16) -> MulTables {
    let mut tables = [[0u8; 16]; 8];

    for nibble_val in 0u16..16 {
        // Nibble 0: bits 0-3 of low byte → value is nibble_val
        let prod0 = gf::mul(factor, nibble_val);
        tables[0][nibble_val as usize] = prod0 as u8;
        tables[1][nibble_val as usize] = (prod0 >> 8) as u8;

        // Nibble 1: bits 4-7 of low byte → value is nibble_val << 4
        let prod1 = gf::mul(factor, nibble_val << 4);
        tables[2][nibble_val as usize] = prod1 as u8;
        tables[3][nibble_val as usize] = (prod1 >> 8) as u8;

        // Nibble 2: bits 0-3 of high byte → value is nibble_val << 8
        let prod2 = gf::mul(factor, nibble_val << 8);
        tables[4][nibble_val as usize] = prod2 as u8;
        tables[5][nibble_val as usize] = (prod2 >> 8) as u8;

        // Nibble 3: bits 4-7 of high byte → value is nibble_val << 12
        let prod3 = gf::mul(factor, nibble_val << 12);
        tables[6][nibble_val as usize] = prod3 as u8;
        tables[7][nibble_val as usize] = (prod3 >> 8) as u8;
    }

    MulTables { tables, factor }
}

/// Precomputed 8×8 binary affine matrices for GFNI-accelerated GF(2^16) multiply.
///
/// GF(2^16) multiplication by a fixed factor is a linear map over GF(2),
/// representable as a 16×16 binary matrix. We partition it into four 8×8
/// sub-matrices:
///
/// ```text
/// [result_lo]   [m_ll  m_lh] [input_lo]
/// [result_hi] = [m_hl  m_hh] [input_hi]
/// ```
///
/// Each 8×8 matrix is packed into a `u64` in the format expected by
/// `gf2p8affineqb`: byte 7 = row 0, bit 7 of each byte = column 0.
#[derive(Clone)]
pub struct AffineMulMatrices {
    /// Maps input low byte → output low byte.
    pub m_ll: u64,
    /// Maps input high byte → output low byte.
    pub m_lh: u64,
    /// Maps input low byte → output high byte.
    pub m_hl: u64,
    /// Maps input high byte → output high byte.
    pub m_hh: u64,
    /// The original factor, for scalar tail processing.
    pub factor: u16,
}

/// Build the four 8×8 affine matrices for a given GF(2^16) factor.
///
/// For each input bit position, we evaluate `gf_mul(factor, 1 << bit)` and
/// record which output bits are set. The result is packed into the GFNI
/// row-major format.
pub fn precompute_affine_matrices(factor: u16) -> AffineMulMatrices {
    // Build the full 16×16 binary matrix: column `bit` = gf_mul(factor, 1 << bit).
    let mut cols = [0u16; 16];
    for bit in 0..16u32 {
        cols[bit as usize] = gf::mul(factor, 1 << bit);
    }

    // Extract four 8×8 sub-matrices and pack into GFNI format.
    //
    // GFNI gf2p8affineqb computes: result_bit[i] = popcount(row_i AND input) mod 2
    // where row_i is byte (7-i) of the matrix qword (row 0 at MSB byte).
    // The AND operates on matching bit positions: bit j of row ANDs with bit j
    // of input. In our le byte representation, bit 0 = LSB = GF bit 0.
    // So matrix column for GF input bit `col` maps to bit `col` in the row byte.
    let pack = |input_shift: usize, output_shift: usize| -> u64 {
        let mut matrix: u64 = 0;
        for row in 0..8u32 {
            let output_bit = output_shift as u32 + row;
            let mut row_byte: u8 = 0;
            for col in 0..8u32 {
                let input_bit = input_shift as u32 + col;
                if (cols[input_bit as usize] >> output_bit) & 1 == 1 {
                    row_byte |= 1 << col;
                }
            }
            matrix |= (row_byte as u64) << ((7 - row) * 8);
        }
        matrix
    };

    AffineMulMatrices {
        m_ll: pack(0, 0),
        m_lh: pack(8, 0),
        m_hl: pack(0, 8),
        m_hh: pack(8, 8),
        factor,
    }
}

/// Multiply each u16 word in `src` by `factor` in GF(2^16) and XOR-accumulate
/// into `dst`.
///
/// Both slices are byte slices interpreted as little-endian u16 words.
/// They must have the same length and that length must be even.
///
/// # Panics
///
/// Panics if `src.len() != dst.len()` or if the length is odd.
#[inline]
pub fn mul_acc_region(factor: u16, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len(), "src and dst must have equal length");
    assert!(src.len().is_multiple_of(2), "region length must be even");

    if factor == 0 || src.is_empty() {
        return;
    }

    if factor == 1 {
        // factor=1 is just XOR.
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("gfni")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
        {
            let matrices = precompute_affine_matrices(factor);
            unsafe { mul_acc_region_gfni_avx512(&matrices, src, dst) };
            return;
        }
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            let matrices = precompute_affine_matrices(factor);
            unsafe { mul_acc_region_gfni_avx2(&matrices, src, dst) };
            return;
        }
    }

    let tables = precompute_mul_tables(factor);

    // wasm dispatch is purely compile-time: the SIMD artifact is built with a
    // fixed `target_feature` set, so the flavor is selected here, not at
    // runtime. relaxed-simd takes precedence over plain simd128 (it is the
    // richer build); wasm without simd128 falls through to the scalar tail.
    #[cfg(all(target_arch = "wasm32", target_feature = "relaxed-simd"))]
    {
        unsafe { mul_acc_region_wasm_simd128::<true>(&tables, src, dst) };
        return;
    }
    #[cfg(all(
        target_arch = "wasm32",
        target_feature = "simd128",
        not(target_feature = "relaxed-simd")
    ))]
    {
        unsafe { mul_acc_region_wasm_simd128::<false>(&tables, src, dst) };
        return;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512bw") && is_x86_feature_detected!("avx512vl") {
            unsafe { mul_acc_region_avx512(&tables, src, dst) };
            return;
        }
        if is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_region_avx2(&tables, src, dst) };
            return;
        }
        if is_x86_feature_detected!("ssse3") {
            unsafe { mul_acc_region_ssse3(&tables, src, dst) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        unsafe { mul_acc_region_neon(&tables, src, dst) };
        return;
    }

    // On wasm without simd128 (and any other target with no SIMD kernel) the
    // scalar tail below consumes only `factor`; acknowledge the precomputed
    // tables so the unused fallback build stays warning-free.
    #[cfg(all(target_arch = "wasm32", not(target_feature = "simd128")))]
    let _ = &tables;

    #[allow(unreachable_code)]
    mul_acc_region_scalar(factor, src, dst);
}

/// Multiply each u16 word in `src` by multiple factors and XOR-accumulate into
/// corresponding destination buffers.
///
/// For each factor/dst pair, computes `dst[i] ^= gf_mul(src[i], factor)`.
/// Reads `src` once per SIMD chunk and applies all factors, reducing memory
/// bandwidth compared to calling `mul_acc_region` in a loop.
///
/// Pairs where `factor == 0` are skipped. All dst slices must have the same
/// length as `src`, and that length must be even.
///
/// # Panics
///
/// Panics if any `dst` length differs from `src`, or if lengths are odd.
pub fn mul_acc_multi_region(factors_and_dsts: &mut [FactorDst<'_>], src: &[u8]) {
    let len = src.len();
    assert!(len.is_multiple_of(2), "region length must be even");

    // Filter out zero factors.
    // (We can't actually filter the slice in place, so just skip in the loop.)
    if src.is_empty() {
        return;
    }

    for fd in factors_and_dsts.iter() {
        assert_eq!(fd.dst.len(), len, "all dst slices must match src length");
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_multi_region_gfni_avx2(factors_and_dsts, src) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Use CLMUL (PMULL) kernel when >2 non-zero factors — amortizes reduction cost.
        let nonzero_count = factors_and_dsts
            .iter()
            .filter(|fd| fd.factor != 0 && fd.factor != 1)
            .count();
        if nonzero_count > 2 {
            if clmul_sha3_available() {
                unsafe { mul_acc_multi_region_clmul_sha3(factors_and_dsts, src) };
            } else {
                unsafe { mul_acc_multi_region_clmul(factors_and_dsts, src) };
            }
        } else {
            unsafe { mul_acc_multi_region_neon(factors_and_dsts, src) };
        }
        return;
    }

    // Fallback: call single-region for each factor.
    #[allow(unreachable_code)]
    for fd in factors_and_dsts.iter_mut() {
        if fd.factor != 0 {
            mul_acc_region(fd.factor, src, fd.dst);
        }
    }
}

/// A (factor, destination) pair for multi-region multiply-accumulate.
pub struct FactorDst<'a> {
    pub factor: u16,
    pub dst: &'a mut [u8],
}

/// A (factor, source) pair for grouped-input multiply-accumulate into one destination.
pub struct FactorSrc<'a> {
    pub factor: u16,
    pub src: &'a [u8],
}

/// A precomputed multiply factor for grouped-input execution.
#[derive(Clone)]
pub struct PreparedInputFactor {
    pub factor: u16,
    #[cfg(target_arch = "x86_64")]
    x86: Option<PreparedX86Factor>,
    #[cfg(target_arch = "aarch64")]
    tables: Option<MulTables>,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
enum PreparedX86Factor {
    Gfni(AffineMulMatrices),
    Avx2(MulTables),
}

/// A prepared (factor, source) pair for grouped-input multiply-accumulate.
pub struct PreparedFactorSrc<'a> {
    pub prepared: &'a PreparedInputFactor,
    pub src: &'a [u8],
}

pub fn prepare_input_factor(factor: u16) -> PreparedInputFactor {
    PreparedInputFactor {
        factor,
        #[cfg(target_arch = "x86_64")]
        x86: if factor == 0 || factor == 1 {
            None
        } else if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            Some(PreparedX86Factor::Gfni(precompute_affine_matrices(factor)))
        } else if is_x86_feature_detected!("avx2") {
            Some(PreparedX86Factor::Avx2(precompute_mul_tables(factor)))
        } else {
            None
        },
        #[cfg(target_arch = "aarch64")]
        tables: (factor != 0 && factor != 1).then(|| precompute_mul_tables(factor)),
    }
}

/// Multiply multiple input regions by their corresponding factors and XOR-accumulate
/// the results into a single destination buffer.
///
/// For each factor/src pair, computes `dst[i] ^= gf_mul(src[i], factor)`.
/// Reads and writes `dst` once per SIMD chunk, which is a better fit for
/// grouped-input execution than repeatedly calling `mul_acc_region`.
pub fn mul_acc_input_batch(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    let len = dst.len();
    assert!(len.is_multiple_of(2), "region length must be even");

    if dst.is_empty() {
        return;
    }

    for fs in factors_and_srcs.iter() {
        assert_eq!(fs.src.len(), len, "all src slices must match dst length");
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("gfni")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
        {
            unsafe { mul_acc_input_batch_gfni_avx512(dst, factors_and_srcs) };
            return;
        }
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_input_batch_gfni_avx2(dst, factors_and_srcs) };
            return;
        }
        // Non-GFNI implied: execution fell past the GFNI arms above.
        if is_x86_feature_detected!("avx512bw") && is_x86_feature_detected!("avx512vl") {
            unsafe { mul_acc_input_batch_avx512(dst, factors_and_srcs) };
            return;
        }
        if is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_input_batch_avx2(dst, factors_and_srcs) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Mirror upstream method selection: CLMul over VTBL shuffle when the
        // input count exceeds 3 (ParPar gf16mul.cpp:1607-1626), SHA3 flavor
        // when FEAT_SHA3 is present.
        if factors_and_srcs.len() > 3 && clmul_batch_enabled() {
            if clmul_sha3_available() {
                unsafe { mul_acc_input_batch_clmul_sha3(dst, factors_and_srcs) };
            } else {
                unsafe { mul_acc_input_batch_clmul(dst, factors_and_srcs) };
            }
            return;
        }
        unsafe { mul_acc_input_batch_neon(dst, factors_and_srcs) };
        return;
    }

    #[allow(unreachable_code)]
    for fs in factors_and_srcs {
        if fs.factor != 0 {
            mul_acc_region(fs.factor, fs.src, dst);
        }
    }
}

/// Whether the split byte-plane fast path is available: buffers can be
/// converted to a per-register lo/hi plane layout so the folded kernels run
/// without any per-iteration deinterleave/interleave shuffles.
///
/// This is the AVX2 split *layout* gate. Both the GFNI folded kernel
/// ([`mul_acc_folded_group`]) and the non-GFNI shuffle2x kernel
/// ([`mul_acc_shuffle2x_group`]) consume the identical layout; which kernel
/// runs is chosen per group by [`folded_uses_gfni`].
pub fn altmap_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return is_x86_feature_detected!("avx2");
    }
    #[allow(unreachable_code)]
    false
}

/// Whether the folded split-layout path should use the GFNI affine kernel
/// (`gfni`+`avx2`) rather than the non-GFNI shuffle2x kernel. Only meaningful
/// when [`altmap_supported`] is true.
pub fn folded_uses_gfni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2");
    }
    #[allow(unreachable_code)]
    false
}

/// Whether the fused two-group 512-bit folded kernel can run. Setting
/// `WEAVER_GF16_FOLDED_AVX512=0` pins the 256-bit kernel so wide hardware can
/// A/B the two widths without a rebuild.
#[cfg(target_arch = "x86_64")]
fn folded_avx512_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        if std::env::var_os("WEAVER_GF16_FOLDED_AVX512").is_some_and(|v| v == "0") {
            return false;
        }
        is_x86_feature_detected!("gfni")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
    })
}

/// Bytes per split-layout block: one 256-bit register holding 16 GF(2^16)
/// words as [16 low bytes | 16 high bytes].
pub const SPLIT_BLOCK_BYTES: usize = 32;

/// Sources per folded-kernel group. Each source needs two matrix registers
/// (see `mul_acc_folded_group`), so six sources keep all twelve matrices plus
/// both accumulators and the data register inside the 16-entry ymm file.
pub const FOLDED_GROUP: usize = 6;

/// Convert the 32-byte-aligned prefix of `buf` to split layout in place:
/// each 32-byte block holds the low bytes of its 16 GF(2^16) words in the
/// first 16 bytes and the high bytes in the second 16. The tail past the
/// aligned prefix keeps the normal interleaved layout.
pub fn altmap_encode(buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if altmap_supported() {
        unsafe { split_encode_avx2(buf) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = buf;
}

/// Inverse of [`altmap_encode`].
pub fn altmap_decode(buf: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if altmap_supported() {
        unsafe { split_decode_avx2(buf) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = buf;
}

/// Encode `src` into split layout and scatter its blocks into `staging` as
/// lane `lane` of a `FOLDED_GROUP`-wide interleaved stream: block `k` of the
/// source lands at `staging[(k * FOLDED_GROUP + lane) * 32..]`. Interleaving
/// the group at block granularity means the multiply kernel walks one
/// sequential stream instead of `FOLDED_GROUP` parallel ones. The source tail
/// past the 32-byte prefix is not written; callers keep tails per source.
pub fn split_encode_scatter(src: &[u8], staging: &mut [u8], lane: usize) {
    debug_assert!(lane < FOLDED_GROUP);
    let vec_len = src.len() & !(SPLIT_BLOCK_BYTES - 1);
    debug_assert!(staging.len() >= vec_len * FOLDED_GROUP);
    #[cfg(target_arch = "x86_64")]
    if altmap_supported() {
        unsafe { split_encode_scatter_avx2(src, staging, lane, vec_len) };
        return;
    }
    let _ = (src, staging, lane, vec_len);
    unreachable!("split staging requires x86_64 AVX2 support");
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn split_block_avx2(data: std::arch::x86_64::__m256i) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;
    // Per 128-bit lane: even (low) bytes to the lower 8 bytes, odd (high)
    // bytes to the upper 8; then swap the middle 64-bit quarters so the
    // register reads [16 low bytes | 16 high bytes].
    let deint_128 = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0);
    let deint = _mm256_broadcastsi128_si256(deint_128);
    let lanes = _mm256_shuffle_epi8(data, deint);
    _mm256_permute4x64_epi64::<0b1101_1000>(lanes)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn unsplit_block_avx2(data: std::arch::x86_64::__m256i) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;
    // Inverse of `split_block_avx2`: un-swap the middle quarters, then
    // re-interleave low/high bytes within each lane.
    let int_128 = _mm_set_epi8(15, 7, 14, 6, 13, 5, 12, 4, 11, 3, 10, 2, 9, 1, 8, 0);
    let inter = _mm256_broadcastsi128_si256(int_128);
    let lanes = _mm256_permute4x64_epi64::<0b1101_1000>(data);
    _mm256_shuffle_epi8(lanes, inter)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn split_encode_avx2(buf: &mut [u8]) {
    use std::arch::x86_64::*;
    unsafe {
        let vec_len = buf.len() & !(SPLIT_BLOCK_BYTES - 1);
        let mut offset = 0usize;
        while offset < vec_len {
            let data = _mm256_loadu_si256(buf.as_ptr().add(offset) as *const __m256i);
            let split = split_block_avx2(data);
            _mm256_storeu_si256(buf.as_mut_ptr().add(offset) as *mut __m256i, split);
            offset += SPLIT_BLOCK_BYTES;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn split_decode_avx2(buf: &mut [u8]) {
    use std::arch::x86_64::*;
    unsafe {
        let vec_len = buf.len() & !(SPLIT_BLOCK_BYTES - 1);
        let mut offset = 0usize;
        while offset < vec_len {
            let data = _mm256_loadu_si256(buf.as_ptr().add(offset) as *const __m256i);
            let joined = unsplit_block_avx2(data);
            _mm256_storeu_si256(buf.as_mut_ptr().add(offset) as *mut __m256i, joined);
            offset += SPLIT_BLOCK_BYTES;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn split_encode_scatter_avx2(src: &[u8], staging: &mut [u8], lane: usize, vec_len: usize) {
    use std::arch::x86_64::*;
    unsafe {
        let mut offset = 0usize;
        let mut out = lane * SPLIT_BLOCK_BYTES;
        let stride = FOLDED_GROUP * SPLIT_BLOCK_BYTES;
        while offset < vec_len {
            let data = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let split = split_block_avx2(data);
            _mm256_storeu_si256(staging.as_mut_ptr().add(out) as *mut __m256i, split);
            offset += SPLIT_BLOCK_BYTES;
            out += stride;
        }
    }
}

/// Zero affine matrices: multiplying through them contributes nothing, which
/// lets partially filled groups run the uniform six-wide kernel.
pub const ZERO_AFFINE: AffineMulMatrices = AffineMulMatrices {
    m_ll: 0,
    m_lh: 0,
    m_hl: 0,
    m_hh: 0,
    factor: 0,
};

/// Precomputed 256-bit shuffle tables for the non-GFNI AVX2 "shuffle2x"
/// GF(2^16) multiply on the split byte-plane layout (a faithful port of
/// ParPar's `gf16_shuffle2x`). Each table is a full 32-byte `__m256i`: the low
/// 128-bit lane serves the low-byte plane, the high lane the high-byte plane,
/// so one `vpshufb` per table covers both planes at once.
///
/// The four tables are rearrangements of the eight [`MulTables`] nibble
/// byte-tables (`t[0..8]` = n0lo, n0hi, n1lo, n1hi, n2lo, n2hi, n3lo, n3hi):
/// `norm_lo=[n0lo|n2hi]`, `swap_lo=[n0hi|n2lo]`, `norm_hi=[n1lo|n3hi]`,
/// `swap_hi=[n1hi|n3lo]`. `norm` lookups land in the plane they belong to;
/// `swap` lookups land in the opposite plane and are folded in with one
/// `permute2x128` lane swap per destination block (see
/// [`mul_acc_shuffle2x_group`]). This mirrors the affine `norm=[ll|hh]`,
/// `swap=[hl|lh]` fold the GFNI kernel uses.
#[derive(Clone)]
pub struct Shuffle2xTables {
    pub norm_lo: [u8; 32],
    pub swap_lo: [u8; 32],
    pub norm_hi: [u8; 32],
    pub swap_hi: [u8; 32],
}

/// Zero shuffle2x tables: every lookup yields zero, so padding lanes of a
/// partially filled group contribute nothing (mirrors [`ZERO_AFFINE`]).
pub const ZERO_SHUFFLE2X: Shuffle2xTables = Shuffle2xTables {
    norm_lo: [0u8; 32],
    swap_lo: [0u8; 32],
    norm_hi: [0u8; 32],
    swap_hi: [0u8; 32],
};

/// Build the four shuffle2x tables for a GF(2^16) factor by rearranging the
/// eight nibble byte-tables from [`precompute_mul_tables`]. Byte-exact by
/// construction: the underlying products come from the shared scalar table
/// builder, so no new GF arithmetic is introduced.
pub fn precompute_shuffle2x_tables(factor: u16) -> Shuffle2xTables {
    let t = precompute_mul_tables(factor).tables;
    let cat = |lo: &[u8; 16], hi: &[u8; 16]| {
        let mut o = [0u8; 32];
        o[..16].copy_from_slice(lo);
        o[16..].copy_from_slice(hi);
        o
    };
    Shuffle2xTables {
        norm_lo: cat(&t[0], &t[5]),
        swap_lo: cat(&t[1], &t[4]),
        norm_hi: cat(&t[2], &t[7]),
        swap_hi: cat(&t[3], &t[6]),
    }
}

/// Multiply every six-source group of a batch into one split-layout
/// destination tile with a single call. `stagings[g]` is group `g`'s
/// interleaved stream sliced to this tile (each `dst.len() * FOLDED_GROUP`
/// bytes) and `matrices[g]` its six folded coefficient sets. One call per
/// (tile, output) amortizes call overhead across the whole batch, and a
/// small destination tile keeps the per-group dst reload in L1.
///
/// With 512-bit GFNI available, adjacent groups run fused two at a time: the
/// doubled register file holds both groups' folded matrices, so each
/// destination block is read and written once per twelve sources instead of
/// once per six. An odd trailing group falls back to the 256-bit kernel.
pub fn mul_acc_folded_batch(
    dst: &mut [u8],
    stagings: &[&[u8]],
    matrices: &[[&AffineMulMatrices; FOLDED_GROUP]],
) {
    assert_eq!(stagings.len(), matrices.len(), "one matrix set per group");
    #[cfg(target_arch = "x86_64")]
    if folded_avx512_enabled() {
        let len = dst.len();
        assert!(
            len.is_multiple_of(SPLIT_BLOCK_BYTES),
            "split dst length must be a multiple of {SPLIT_BLOCK_BYTES}"
        );
        for staging in stagings {
            assert!(
                staging.len() >= len * FOLDED_GROUP,
                "staging must cover the full group"
            );
        }
        let mut g = 0usize;
        while g + 1 < stagings.len() {
            unsafe {
                mul_acc_folded_pair_gfni_avx512(
                    dst,
                    stagings[g],
                    stagings[g + 1],
                    &matrices[g],
                    &matrices[g + 1],
                )
            };
            g += 2;
        }
        if g < stagings.len() {
            mul_acc_folded_group(dst, stagings[g], &matrices[g]);
        }
        return;
    }
    for (staging, group_matrices) in stagings.iter().zip(matrices.iter()) {
        mul_acc_folded_group(dst, staging, group_matrices);
    }
}

/// Multiply every six-source group of a batch into one split-layout
/// destination tile with the non-GFNI AVX2 shuffle2x kernel. The counterpart
/// of [`mul_acc_folded_batch`] for boxes with AVX2 but no GFNI; one call per
/// (tile, output) amortizes call overhead across the batch. `tables[g]` are
/// group `g`'s six coefficient table sets (padding lanes = [`ZERO_SHUFFLE2X`]).
pub fn mul_acc_shuffle2x_batch(
    dst: &mut [u8],
    stagings: &[&[u8]],
    tables: &[[&Shuffle2xTables; FOLDED_GROUP]],
) {
    assert_eq!(stagings.len(), tables.len(), "one table set per group");
    #[cfg(target_arch = "x86_64")]
    {
        let len = dst.len();
        assert!(
            len.is_multiple_of(SPLIT_BLOCK_BYTES),
            "split dst length must be a multiple of {SPLIT_BLOCK_BYTES}"
        );
        for staging in stagings {
            assert!(
                staging.len() >= len * FOLDED_GROUP,
                "staging must cover the full group"
            );
        }
        debug_assert!(altmap_supported());
        for (staging, group_tables) in stagings.iter().zip(tables.iter()) {
            unsafe { mul_acc_shuffle2x_group_avx2(dst, staging, group_tables) };
        }
        return;
    }
    #[allow(unreachable_code)]
    {
        let _ = (dst, stagings, tables);
        unreachable!("shuffle2x batch requires x86_64 AVX2 support");
    }
}

/// Multiply one interleaved six-source group into a split-layout destination.
///
/// `dst` is a split-layout region (length a multiple of 32); `staging` holds
/// the group's blocks interleaved at 32-byte granularity (block `k` of lane
/// `l` at offset `(k * FOLDED_GROUP + l) * 32`) and must span
/// `dst.len() * FOLDED_GROUP` bytes.
///
/// Each source's four 8×8 GF(2) matrices are folded into two lane-paired
/// registers — norm = [ll | hh], swap = [hl | lh] — so one affine per pair
/// produces both plane contributions and the twelve matrix registers for the
/// whole group stay resident while the loop streams the staging area. The
/// cross-plane terms accumulate separately and fold in with a single lane
/// swap per block.
///
/// Packing note: this adopts shuffle2x's full-register split layout
/// (all-lo | all-hi halves, `permute2x128` fold) rather than upstream
/// affine2x's per-128-lane [8lo|8hi] packing with a `shuffle_epi32(1,0,3,2)`
/// fold (gf16_affine2x_x86.h) — same norm/swap algebra, one staging layout
/// shared with the non-GFNI shuffle2x kernel.
pub fn mul_acc_folded_group(
    dst: &mut [u8],
    staging: &[u8],
    matrices: &[&AffineMulMatrices; FOLDED_GROUP],
) {
    let len = dst.len();
    assert!(
        len.is_multiple_of(SPLIT_BLOCK_BYTES),
        "split dst length must be a multiple of {SPLIT_BLOCK_BYTES}"
    );
    assert!(
        staging.len() >= len * FOLDED_GROUP,
        "staging must cover the full group"
    );

    #[cfg(target_arch = "x86_64")]
    {
        debug_assert!(folded_uses_gfni());
        unsafe { mul_acc_folded_group_gfni_avx2(dst, staging, matrices) };
        return;
    }

    #[allow(unreachable_code)]
    {
        let _ = matrices;
        unreachable!("folded group kernel requires x86_64 GFNI support");
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_acc_folded_group_gfni_avx2(
    dst: &mut [u8],
    staging: &[u8],
    matrices: &[&AffineMulMatrices; FOLDED_GROUP],
) {
    use std::arch::x86_64::*;

    unsafe {
        // norm = [ll | hh], swap = [hl | lh]: affine(data, norm) yields the
        // plane-aligned products in place, affine(data, swap) yields the
        // cross-plane products, folded in with one lane swap per block.
        macro_rules! fold {
            ($m:expr) => {
                (
                    _mm256_set_epi64x(
                        $m.m_hh as i64,
                        $m.m_hh as i64,
                        $m.m_ll as i64,
                        $m.m_ll as i64,
                    ),
                    _mm256_set_epi64x(
                        $m.m_lh as i64,
                        $m.m_lh as i64,
                        $m.m_hl as i64,
                        $m.m_hl as i64,
                    ),
                )
            };
        }
        let (n0, s0) = fold!(matrices[0]);
        let (n1, s1) = fold!(matrices[1]);
        let (n2, s2) = fold!(matrices[2]);
        let (n3, s3) = fold!(matrices[3]);
        let (n4, s4) = fold!(matrices[4]);
        let (n5, s5) = fold!(matrices[5]);

        let len = dst.len();
        let stride = FOLDED_GROUP * SPLIT_BLOCK_BYTES;
        let mut offset = 0usize;
        let mut src = 0usize;
        while offset < len {
            _mm_prefetch::<{ _MM_HINT_ET1 }>(dst.as_ptr().add(offset + 128) as *const i8);

            let mut acc1 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let mut acc2 = _mm256_setzero_si256();

            macro_rules! lane {
                ($idx:literal, $n:expr, $s:expr) => {
                    let data = _mm256_loadu_si256(
                        staging.as_ptr().add(src + $idx * SPLIT_BLOCK_BYTES) as *const __m256i,
                    );
                    acc1 = _mm256_xor_si256(acc1, _mm256_gf2p8affine_epi64_epi8::<0>(data, $n));
                    acc2 = _mm256_xor_si256(acc2, _mm256_gf2p8affine_epi64_epi8::<0>(data, $s));
                };
            }
            lane!(0, n0, s0);
            lane!(1, n1, s1);
            lane!(2, n2, s2);
            lane!(3, n3, s3);
            lane!(4, n4, s4);
            lane!(5, n5, s5);

            let crossed = _mm256_permute2x128_si256::<0x01>(acc2, acc2);
            acc1 = _mm256_xor_si256(acc1, crossed);
            _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, acc1);

            offset += SPLIT_BLOCK_BYTES;
            src += stride;
        }
    }
}

/// Multiply one interleaved six-source group into a split-layout destination
/// with ParPar's non-GFNI "shuffle2x" formulation — the AVX2 analog of
/// [`mul_acc_folded_group_gfni_avx2`], consuming the identical split staging.
///
/// Because the sources are already in split byte-plane layout, the hot loop
/// carries no per-block deinterleave. Each source costs four `vpshufb` — norm
/// and swap for the low nibble, norm and swap for the high nibble — half the
/// eight lookups the interleaved `mul_acc_input_batch_avx2_prepared` path
/// spends. `result` accumulates the plane-aligned (norm) products, `swapped`
/// the cross-plane (swap) products; one `permute2x128` lane swap per
/// destination block folds `swapped` into `result` for the whole group,
/// exactly as the GFNI kernel folds its `acc2`.
///
/// `tables[l]` are lane `l`'s shuffle2x tables (see [`Shuffle2xTables`]);
/// padding lanes use [`ZERO_SHUFFLE2X`].
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_acc_shuffle2x_group_avx2(
    dst: &mut [u8],
    staging: &[u8],
    tables: &[&Shuffle2xTables; FOLDED_GROUP],
) {
    use std::arch::x86_64::*;

    unsafe {
        let mask = _mm256_set1_epi8(0x0f);
        let len = dst.len();
        let stride = FOLDED_GROUP * SPLIT_BLOCK_BYTES;
        let mut offset = 0usize;
        let mut src = 0usize;
        while offset < len {
            _mm_prefetch::<{ _MM_HINT_ET1 }>(dst.as_ptr().add(offset + 128) as *const i8);

            let mut result = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let mut swapped = _mm256_setzero_si256();

            // norm lookups land in the same plane; swap lookups land in the
            // opposite plane and are folded by the single lane swap below.
            macro_rules! lane {
                ($idx:literal, $t:expr) => {
                    let data = _mm256_loadu_si256(
                        staging.as_ptr().add(src + $idx * SPLIT_BLOCK_BYTES) as *const __m256i,
                    );
                    let lo = _mm256_and_si256(data, mask);
                    let hi = _mm256_and_si256(_mm256_srli_epi16(data, 4), mask);
                    let nl = _mm256_loadu_si256($t.norm_lo.as_ptr() as *const __m256i);
                    let sl = _mm256_loadu_si256($t.swap_lo.as_ptr() as *const __m256i);
                    let nh = _mm256_loadu_si256($t.norm_hi.as_ptr() as *const __m256i);
                    let sh = _mm256_loadu_si256($t.swap_hi.as_ptr() as *const __m256i);
                    result = _mm256_xor_si256(result, _mm256_shuffle_epi8(nl, lo));
                    swapped = _mm256_xor_si256(swapped, _mm256_shuffle_epi8(sl, lo));
                    result = _mm256_xor_si256(result, _mm256_shuffle_epi8(nh, hi));
                    swapped = _mm256_xor_si256(swapped, _mm256_shuffle_epi8(sh, hi));
                };
            }
            lane!(0, tables[0]);
            lane!(1, tables[1]);
            lane!(2, tables[2]);
            lane!(3, tables[3]);
            lane!(4, tables[4]);
            lane!(5, tables[5]);

            let crossed = _mm256_permute2x128_si256::<0x01>(swapped, swapped);
            result = _mm256_xor_si256(result, crossed);
            _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, result);

            offset += SPLIT_BLOCK_BYTES;
            src += stride;
        }
    }
}

/// Multiply two interleaved six-source groups into a split-layout destination
/// with one pass over `dst`.
///
/// One 512-bit load spans two adjacent 32-byte split blocks of a group's
/// interleaved stream — two sources at the same block index — so each group
/// needs three data loads per destination block. Matrices fold per 128-bit
/// lane across the source pair: norm = [ll_x | hh_x | ll_y | hh_y], swap =
/// [hl_x | lh_x | hl_y | lh_y]. Twelve matrix registers cover both groups,
/// ternary-logic ops fuse the XOR reduction, and one 512→256 fold per block
/// (amortized over twelve sources) lands the accumulators on the 32-byte
/// destination block.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512bw,avx512vl")]
unsafe fn mul_acc_folded_pair_gfni_avx512(
    dst: &mut [u8],
    staging_a: &[u8],
    staging_b: &[u8],
    matrices_a: &[&AffineMulMatrices; FOLDED_GROUP],
    matrices_b: &[&AffineMulMatrices; FOLDED_GROUP],
) {
    use std::arch::x86_64::*;

    unsafe {
        // Fold two sources' matrices into one register pair: lanes 0-1 serve
        // source `x`, lanes 2-3 source `y`, matching the [lo_x hi_x lo_y hi_y]
        // lane order of a 64-byte load from the interleaved stream.
        macro_rules! fold2 {
            ($mx:expr, $my:expr) => {
                (
                    _mm512_set_epi64(
                        $my.m_hh as i64,
                        $my.m_hh as i64,
                        $my.m_ll as i64,
                        $my.m_ll as i64,
                        $mx.m_hh as i64,
                        $mx.m_hh as i64,
                        $mx.m_ll as i64,
                        $mx.m_ll as i64,
                    ),
                    _mm512_set_epi64(
                        $my.m_lh as i64,
                        $my.m_lh as i64,
                        $my.m_hl as i64,
                        $my.m_hl as i64,
                        $mx.m_lh as i64,
                        $mx.m_lh as i64,
                        $mx.m_hl as i64,
                        $mx.m_hl as i64,
                    ),
                )
            };
        }
        let (na0, sa0) = fold2!(matrices_a[0], matrices_a[1]);
        let (na1, sa1) = fold2!(matrices_a[2], matrices_a[3]);
        let (na2, sa2) = fold2!(matrices_a[4], matrices_a[5]);
        let (nb0, sb0) = fold2!(matrices_b[0], matrices_b[1]);
        let (nb1, sb1) = fold2!(matrices_b[2], matrices_b[3]);
        let (nb2, sb2) = fold2!(matrices_b[4], matrices_b[5]);

        let len = dst.len();
        let stride = FOLDED_GROUP * SPLIT_BLOCK_BYTES;
        let mut offset = 0usize;
        let mut src = 0usize;
        while offset < len {
            _mm_prefetch::<{ _MM_HINT_ET1 }>(dst.as_ptr().add(offset + 128) as *const i8);

            let da0 = _mm512_loadu_si512(staging_a.as_ptr().add(src) as *const __m512i);
            let da1 = _mm512_loadu_si512(staging_a.as_ptr().add(src + 64) as *const __m512i);
            let da2 = _mm512_loadu_si512(staging_a.as_ptr().add(src + 128) as *const __m512i);
            let db0 = _mm512_loadu_si512(staging_b.as_ptr().add(src) as *const __m512i);
            let db1 = _mm512_loadu_si512(staging_b.as_ptr().add(src + 64) as *const __m512i);
            let db2 = _mm512_loadu_si512(staging_b.as_ptr().add(src + 128) as *const __m512i);

            // acc = acc ^ p ^ q in one ternary-logic op per affine pair.
            let mut acc1 = _mm512_xor_si512(
                _mm512_gf2p8affine_epi64_epi8::<0>(da0, na0),
                _mm512_gf2p8affine_epi64_epi8::<0>(da1, na1),
            );
            acc1 = _mm512_ternarylogic_epi64::<0x96>(
                acc1,
                _mm512_gf2p8affine_epi64_epi8::<0>(da2, na2),
                _mm512_gf2p8affine_epi64_epi8::<0>(db0, nb0),
            );
            acc1 = _mm512_ternarylogic_epi64::<0x96>(
                acc1,
                _mm512_gf2p8affine_epi64_epi8::<0>(db1, nb1),
                _mm512_gf2p8affine_epi64_epi8::<0>(db2, nb2),
            );

            let mut acc2 = _mm512_xor_si512(
                _mm512_gf2p8affine_epi64_epi8::<0>(da0, sa0),
                _mm512_gf2p8affine_epi64_epi8::<0>(da1, sa1),
            );
            acc2 = _mm512_ternarylogic_epi64::<0x96>(
                acc2,
                _mm512_gf2p8affine_epi64_epi8::<0>(da2, sa2),
                _mm512_gf2p8affine_epi64_epi8::<0>(db0, sb0),
            );
            acc2 = _mm512_ternarylogic_epi64::<0x96>(
                acc2,
                _mm512_gf2p8affine_epi64_epi8::<0>(db1, sb1),
                _mm512_gf2p8affine_epi64_epi8::<0>(db2, sb2),
            );

            // Halves of each accumulator hold the two sources' contributions
            // to the same destination block: fold 512→256, swap the
            // cross-plane half, and land everything with one ternary-logic.
            let red1 = _mm256_xor_si256(
                _mm512_castsi512_si256(acc1),
                _mm512_extracti64x4_epi64::<1>(acc1),
            );
            let red2 = _mm256_xor_si256(
                _mm512_castsi512_si256(acc2),
                _mm512_extracti64x4_epi64::<1>(acc2),
            );
            let crossed = _mm256_permute2x128_si256::<0x01>(red2, red2);
            let prior = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let mixed = _mm256_ternarylogic_epi64::<0x96>(prior, red1, crossed);
            _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, mixed);

            offset += SPLIT_BLOCK_BYTES;
            src += stride;
        }
    }
}

/// Multiply multiple input regions by prepared factors and XOR-accumulate the
/// results into a single destination buffer.
pub fn mul_acc_input_batch_prepared(dst: &mut [u8], factors_and_srcs: &[PreparedFactorSrc<'_>]) {
    let len = dst.len();
    assert!(len.is_multiple_of(2), "region length must be even");

    if dst.is_empty() {
        return;
    }

    for fs in factors_and_srcs.iter() {
        assert_eq!(fs.src.len(), len, "all src slices must match dst length");
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("gfni")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
        {
            unsafe { mul_acc_input_batch_gfni_avx512_prepared(dst, factors_and_srcs) };
            return;
        }
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_input_batch_gfni_avx2_prepared(dst, factors_and_srcs) };
            return;
        }
        // Non-GFNI implied: execution fell past the GFNI arms above, so
        // `prepare_input_factor` built Avx2-table-flavored factors on this
        // machine — exactly what the 512-bit shuffle kernel consumes.
        if is_x86_feature_detected!("avx512bw") && is_x86_feature_detected!("avx512vl") {
            unsafe { mul_acc_input_batch_avx512_prepared(dst, factors_and_srcs) };
            return;
        }
        if is_x86_feature_detected!("avx2") {
            unsafe { mul_acc_input_batch_avx2_prepared(dst, factors_and_srcs) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // CLMUL preparation is six broadcasts — effectively free — so the
        // prepared path routes through the same upstream >3-inputs selection
        // using the raw factor carried by `PreparedInputFactor`.
        if factors_and_srcs.len() > 3 && clmul_batch_enabled() {
            if clmul_sha3_available() {
                unsafe { mul_acc_input_batch_clmul_sha3_prepared(dst, factors_and_srcs) };
            } else {
                unsafe { mul_acc_input_batch_clmul_prepared(dst, factors_and_srcs) };
            }
            return;
        }
        unsafe { mul_acc_input_batch_neon_prepared(dst, factors_and_srcs) };
        return;
    }

    #[allow(unreachable_code)]
    {
        let fallback_inputs: Vec<FactorSrc<'_>> = factors_and_srcs
            .iter()
            .map(|fs| FactorSrc {
                factor: fs.prepared.factor,
                src: fs.src,
            })
            .collect();
        mul_acc_input_batch(dst, &fallback_inputs);
    }
}

/// Scalar fallback: one word at a time using gf::mul + gf::add.
fn mul_acc_region_scalar(factor: u16, src: &[u8], dst: &mut [u8]) {
    let word_count = src.len() / 2;
    for w in 0..word_count {
        let s = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
        let d = u16::from_le_bytes([dst[w * 2], dst[w * 2 + 1]]);
        let result = gf::add(d, gf::mul(s, factor));
        let bytes = result.to_le_bytes();
        dst[w * 2] = bytes[0];
        dst[w * 2 + 1] = bytes[1];
    }
}

// ---------------------------------------------------------------------------
// GFNI + AVX2 kernel: 64 bytes (32 GF elements) per iteration
//
// Uses gf2p8affineqb to apply 8×8 binary matrix transforms instead of
// PSHUFB nibble lookups. Each 16-bit GF multiply decomposes into:
//
//   result_lo = affine(input_lo, M_ll) XOR affine(input_hi, M_lh)
//   result_hi = affine(input_lo, M_hl) XOR affine(input_hi, M_hh)
//
// This is 4 affine + 2 XOR vs. 8 PSHUFB + 4 AND + 4 SRLI + 6 XOR in the
// split-nibble approach — roughly half the instructions per element.
//
// Data marshalling is the same full-width pair deinterleave as
// `mul_acc_region_avx2`: two vectors fold into one full vector of lo bytes
// and one of hi bytes, so every gf2p8affineqb lane carries data (the old
// single-vector deinterleave left the upper 8 lanes per 128-bit lane zero,
// wasting half of each affine).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_acc_region_gfni_avx2(matrices: &AffineMulMatrices, src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        // Broadcast each 8×8 matrix (u64) into all four 64-bit lanes of a __m256i.
        let m_ll = _mm256_set1_epi64x(matrices.m_ll as i64);
        let m_lh = _mm256_set1_epi64x(matrices.m_lh as i64);
        let m_hl = _mm256_set1_epi64x(matrices.m_hl as i64);
        let m_hh = _mm256_set1_epi64x(matrices.m_hh as i64);

        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        while offset + 64 <= len {
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);

            // Deinterleave the pair into full lo/hi byte planes (per lane:
            // [plane(s0) | plane(s1)] qword halves).
            let a = _mm256_shuffle_epi8(s0, deint_pair);
            let b = _mm256_shuffle_epi8(s1, deint_pair);
            let lo_bytes = _mm256_unpacklo_epi64(a, b);
            let hi_bytes = _mm256_unpackhi_epi64(a, b);

            let result_lo = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, m_ll),
                _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, m_lh),
            );
            let result_hi = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, m_hl),
                _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, m_hh),
            );

            // Reinterleave within each lane: low qwords → s0's words, high
            // qwords → s1's words.
            let product0 = _mm256_unpacklo_epi8(result_lo, result_hi);
            let product1 = _mm256_unpackhi_epi8(result_lo, result_hi);

            // XOR-accumulate.
            let d0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let d1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset) as *mut __m256i,
                _mm256_xor_si256(d0, product0),
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset + 32) as *mut __m256i,
                _mm256_xor_si256(d1, product1),
            );

            offset += 64;
        }
    }

    // Tail: fall through to SSSE3 for a remaining full-width 32-byte block +
    // scalar (GFNI has no 128-bit kernel here; the shuffle tables are
    // byte-exact, so results are identical).
    if offset < len {
        let tables = precompute_mul_tables(matrices.factor);
        unsafe { mul_acc_region_ssse3(&tables, &src[offset..], &mut dst[offset..]) };
    }
}

// ---------------------------------------------------------------------------
// GFNI + AVX-512 kernel: 128 bytes (64 GF elements) per iteration
//
// Same algorithm as GFNI+AVX2 but 2× wider (512-bit registers), with the
// same full-width pair deinterleave as `mul_acc_region_avx512`: two 64-byte
// vectors fold into one full vector of lo bytes and one of hi bytes, so all
// gf2p8affineqb lanes carry data.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512bw,avx512vl")]
unsafe fn mul_acc_region_gfni_avx512(matrices: &AffineMulMatrices, src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        let m_ll = _mm512_set1_epi64(matrices.m_ll as i64);
        let m_lh = _mm512_set1_epi64(matrices.m_lh as i64);
        let m_hl = _mm512_set1_epi64(matrices.m_hl as i64);
        let m_hh = _mm512_set1_epi64(matrices.m_hh as i64);

        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm512_broadcast_i32x4(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        while offset + 128 <= len {
            let s0 = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
            let s1 = _mm512_loadu_si512(src.as_ptr().add(offset + 64) as *const __m512i);

            // Deinterleave the pair into full lo/hi byte planes (per lane:
            // [plane(s0) | plane(s1)] qword halves).
            let a = _mm512_shuffle_epi8(s0, deint_pair);
            let b = _mm512_shuffle_epi8(s1, deint_pair);
            let lo_bytes = _mm512_unpacklo_epi64(a, b);
            let hi_bytes = _mm512_unpackhi_epi64(a, b);

            let result_lo = _mm512_xor_si512(
                _mm512_gf2p8affine_epi64_epi8::<0>(lo_bytes, m_ll),
                _mm512_gf2p8affine_epi64_epi8::<0>(hi_bytes, m_lh),
            );
            let result_hi = _mm512_xor_si512(
                _mm512_gf2p8affine_epi64_epi8::<0>(lo_bytes, m_hl),
                _mm512_gf2p8affine_epi64_epi8::<0>(hi_bytes, m_hh),
            );

            // Reinterleave within each lane: low qwords → s0's words, high
            // qwords → s1's words.
            let product0 = _mm512_unpacklo_epi8(result_lo, result_hi);
            let product1 = _mm512_unpackhi_epi8(result_lo, result_hi);

            // XOR-accumulate.
            let d0 = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
            let d1 = _mm512_loadu_si512(dst.as_ptr().add(offset + 64) as *const __m512i);
            _mm512_storeu_si512(
                dst.as_mut_ptr().add(offset) as *mut __m512i,
                _mm512_xor_si512(d0, product0),
            );
            _mm512_storeu_si512(
                dst.as_mut_ptr().add(offset + 64) as *mut __m512i,
                _mm512_xor_si512(d1, product1),
            );

            offset += 128;
        }
    }

    // Tail: fall through to GFNI+AVX2 for 64-byte blocks, then SSSE3/scalar.
    if offset < len {
        unsafe { mul_acc_region_gfni_avx2(matrices, &src[offset..], &mut dst[offset..]) };
    }
}

// ---------------------------------------------------------------------------
// AVX-512 shuffle kernel: 128 bytes (64 GF elements) per iteration
//
// Same split-nibble algorithm as AVX2 but 2× wider (512-bit registers), with
// the same full-width pair deinterleave: VPSHUFB and the qword unpacks are
// per-128-bit-lane, so two 64-byte vectors fold into one full vector of lo
// bytes and one of hi bytes, and the eight lookups serve 64 words per round.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw,avx512vl")]
unsafe fn mul_acc_region_avx512(tables: &MulTables, src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        let mask_0f = _mm512_set1_epi8(0x0F);

        // Broadcast each 16-byte table into all four 128-bit lanes.
        let t0 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[0].as_ptr() as *const __m128i));
        let t1 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[1].as_ptr() as *const __m128i));
        let t2 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[2].as_ptr() as *const __m128i));
        let t3 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[3].as_ptr() as *const __m128i));
        let t4 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[4].as_ptr() as *const __m128i));
        let t5 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[5].as_ptr() as *const __m128i));
        let t6 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[6].as_ptr() as *const __m128i));
        let t7 =
            _mm512_broadcast_i32x4(_mm_loadu_si128(tables.tables[7].as_ptr() as *const __m128i));

        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm512_broadcast_i32x4(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        while offset + 128 <= len {
            let s0 = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
            let s1 = _mm512_loadu_si512(src.as_ptr().add(offset + 64) as *const __m512i);

            // Deinterleave the pair into full lo/hi byte planes (per lane:
            // [plane(s0) | plane(s1)] qword halves).
            let a = _mm512_shuffle_epi8(s0, deint_pair);
            let b = _mm512_shuffle_epi8(s1, deint_pair);
            let lo_bytes = _mm512_unpacklo_epi64(a, b);
            let hi_bytes = _mm512_unpackhi_epi64(a, b);

            let lo_n0 = _mm512_and_si512(lo_bytes, mask_0f);
            let lo_n1 = _mm512_and_si512(_mm512_srli_epi16(lo_bytes, 4), mask_0f);
            let hi_n0 = _mm512_and_si512(hi_bytes, mask_0f);
            let hi_n1 = _mm512_and_si512(_mm512_srli_epi16(hi_bytes, 4), mask_0f);

            // 8 lookups serving all 64 words.
            let p0_lo = _mm512_shuffle_epi8(t0, lo_n0);
            let p0_hi = _mm512_shuffle_epi8(t1, lo_n0);
            let p1_lo = _mm512_shuffle_epi8(t2, lo_n1);
            let p1_hi = _mm512_shuffle_epi8(t3, lo_n1);
            let p2_lo = _mm512_shuffle_epi8(t4, hi_n0);
            let p2_hi = _mm512_shuffle_epi8(t5, hi_n0);
            let p3_lo = _mm512_shuffle_epi8(t6, hi_n1);
            let p3_hi = _mm512_shuffle_epi8(t7, hi_n1);

            let result_lo = _mm512_xor_si512(
                _mm512_xor_si512(p0_lo, p1_lo),
                _mm512_xor_si512(p2_lo, p3_lo),
            );
            let result_hi = _mm512_xor_si512(
                _mm512_xor_si512(p0_hi, p1_hi),
                _mm512_xor_si512(p2_hi, p3_hi),
            );

            // Reinterleave within each lane: low qwords → s0's words, high
            // qwords → s1's words.
            let product0 = _mm512_unpacklo_epi8(result_lo, result_hi);
            let product1 = _mm512_unpackhi_epi8(result_lo, result_hi);

            let d0 = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
            let d1 = _mm512_loadu_si512(dst.as_ptr().add(offset + 64) as *const __m512i);
            _mm512_storeu_si512(
                dst.as_mut_ptr().add(offset) as *mut __m512i,
                _mm512_xor_si512(d0, product0),
            );
            _mm512_storeu_si512(
                dst.as_mut_ptr().add(offset + 64) as *mut __m512i,
                _mm512_xor_si512(d1, product1),
            );

            offset += 128;
        }
    }

    // Tail: fall through to AVX2 for 64-byte blocks, then SSSE3/scalar.
    if offset < len {
        unsafe { mul_acc_region_avx2(tables, &src[offset..], &mut dst[offset..]) };
    }
}

// ---------------------------------------------------------------------------
// SSSE3 kernel: 32 bytes (16 GF elements) per iteration
//
// Full-width lookups: two input vectors are deinterleaved into one FULL
// vector of lo bytes and one FULL vector of hi bytes, so every lane of the
// eight PSHUFB lookups carries data (a single-vector deinterleave would park
// the planes in the low halves and waste the upper lanes).
//
// Algorithm per 32-byte block:
//   1. Deinterleave pair: PSHUFB each vector to [8 lo | 8 hi], then
//      punpcklqdq/punpckhqdq to gather [16 lo] and [16 hi]
//   2. Extract 4 nibbles (2 per byte plane)
//   3. 8× PSHUFB lookups (4 nibbles × {result_lo, result_hi})
//   4. XOR contributions together
//   5. Reinterleave via unpacklo/unpackhi_epi8 (both halves carry data)
//   6. XOR-accumulate into dst
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn mul_acc_region_ssse3(tables: &MulTables, src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        let mask_0f = _mm_set1_epi8(0x0F);

        // Load the 8 shuffle tables into registers.
        let t0 = _mm_loadu_si128(tables.tables[0].as_ptr() as *const __m128i);
        let t1 = _mm_loadu_si128(tables.tables[1].as_ptr() as *const __m128i);
        let t2 = _mm_loadu_si128(tables.tables[2].as_ptr() as *const __m128i);
        let t3 = _mm_loadu_si128(tables.tables[3].as_ptr() as *const __m128i);
        let t4 = _mm_loadu_si128(tables.tables[4].as_ptr() as *const __m128i);
        let t5 = _mm_loadu_si128(tables.tables[5].as_ptr() as *const __m128i);
        let t6 = _mm_loadu_si128(tables.tables[6].as_ptr() as *const __m128i);
        let t7 = _mm_loadu_si128(tables.tables[7].as_ptr() as *const __m128i);

        // Pair deinterleave mask: even (lo) bytes to the low 8 positions, odd
        // (hi) bytes to the high 8 — [lo0..lo7 | hi0..hi7] per vector.
        let deint_pair = _mm_set_epi8(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0);

        while offset + 32 <= len {
            let s0 = _mm_loadu_si128(src.as_ptr().add(offset) as *const __m128i);
            let s1 = _mm_loadu_si128(src.as_ptr().add(offset + 16) as *const __m128i);

            // Deinterleave the pair into full lo/hi byte planes.
            let a = _mm_shuffle_epi8(s0, deint_pair); // [lo(s0) | hi(s0)]
            let b = _mm_shuffle_epi8(s1, deint_pair); // [lo(s1) | hi(s1)]
            let lo_bytes = _mm_unpacklo_epi64(a, b); // 16 lo bytes (words 0-15)
            let hi_bytes = _mm_unpackhi_epi64(a, b); // 16 hi bytes (words 0-15)

            // Extract nibbles.
            let lo_n0 = _mm_and_si128(lo_bytes, mask_0f);
            let lo_n1 = _mm_and_si128(_mm_srli_epi16(lo_bytes, 4), mask_0f);
            let hi_n0 = _mm_and_si128(hi_bytes, mask_0f);
            let hi_n1 = _mm_and_si128(_mm_srli_epi16(hi_bytes, 4), mask_0f);

            // 8 lookups serving all 16 words: each nibble contributes to both
            // result lo and hi bytes.
            let p0_lo = _mm_shuffle_epi8(t0, lo_n0);
            let p0_hi = _mm_shuffle_epi8(t1, lo_n0);
            let p1_lo = _mm_shuffle_epi8(t2, lo_n1);
            let p1_hi = _mm_shuffle_epi8(t3, lo_n1);
            let p2_lo = _mm_shuffle_epi8(t4, hi_n0);
            let p2_hi = _mm_shuffle_epi8(t5, hi_n0);
            let p3_lo = _mm_shuffle_epi8(t6, hi_n1);
            let p3_hi = _mm_shuffle_epi8(t7, hi_n1);

            // XOR contributions for result lo bytes and result hi bytes.
            let result_lo = _mm_xor_si128(_mm_xor_si128(p0_lo, p1_lo), _mm_xor_si128(p2_lo, p3_lo));
            let result_hi = _mm_xor_si128(_mm_xor_si128(p0_hi, p1_hi), _mm_xor_si128(p2_hi, p3_hi));

            // Reinterleave: low halves → words 0-7, high halves → words 8-15.
            let product0 = _mm_unpacklo_epi8(result_lo, result_hi);
            let product1 = _mm_unpackhi_epi8(result_lo, result_hi);

            // XOR-accumulate.
            let d0 = _mm_loadu_si128(dst.as_ptr().add(offset) as *const __m128i);
            let d1 = _mm_loadu_si128(dst.as_ptr().add(offset + 16) as *const __m128i);
            _mm_storeu_si128(
                dst.as_mut_ptr().add(offset) as *mut __m128i,
                _mm_xor_si128(d0, product0),
            );
            _mm_storeu_si128(
                dst.as_mut_ptr().add(offset + 16) as *mut __m128i,
                _mm_xor_si128(d1, product1),
            );

            offset += 32;
        }
    }

    // Scalar tail (< one 32-byte block; lengths 16..=31 land here too).
    if offset < len {
        mul_acc_region_scalar(tables.factor, &src[offset..], &mut dst[offset..]);
    }
}

// ---------------------------------------------------------------------------
// AVX2 kernel: 64 bytes (32 GF elements) per iteration
//
// Same full-width pair-deinterleave as SSSE3, per 128-bit lane: VPSHUFB and
// the qword unpacks operate within each lane independently, so lane k of
// lo_bytes/hi_bytes holds [plane(v0 lane k) | plane(v1 lane k)] and the
// epi8 unpacks re-emit v0's words from the low qwords and v1's words from
// the high qwords — full lane utilization with no cross-lane permutes.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_acc_region_avx2(tables: &MulTables, src: &[u8], dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        let mask_0f = _mm256_set1_epi8(0x0F);

        // Broadcast each 16-byte table into both 128-bit lanes.
        let t0 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[0].as_ptr() as *const __m128i
        ));
        let t1 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[1].as_ptr() as *const __m128i
        ));
        let t2 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[2].as_ptr() as *const __m128i
        ));
        let t3 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[3].as_ptr() as *const __m128i
        ));
        let t4 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[4].as_ptr() as *const __m128i
        ));
        let t5 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[5].as_ptr() as *const __m128i
        ));
        let t6 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[6].as_ptr() as *const __m128i
        ));
        let t7 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
            tables.tables[7].as_ptr() as *const __m128i
        ));

        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        while offset + 64 <= len {
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);

            // Deinterleave the pair into full lo/hi byte planes (per lane:
            // [plane(s0) | plane(s1)] qword halves).
            let a = _mm256_shuffle_epi8(s0, deint_pair);
            let b = _mm256_shuffle_epi8(s1, deint_pair);
            let lo_bytes = _mm256_unpacklo_epi64(a, b);
            let hi_bytes = _mm256_unpackhi_epi64(a, b);

            // Extract nibbles.
            let lo_n0 = _mm256_and_si256(lo_bytes, mask_0f);
            let lo_n1 = _mm256_and_si256(_mm256_srli_epi16(lo_bytes, 4), mask_0f);
            let hi_n0 = _mm256_and_si256(hi_bytes, mask_0f);
            let hi_n1 = _mm256_and_si256(_mm256_srli_epi16(hi_bytes, 4), mask_0f);

            // 8 lookups serving all 32 words.
            let p0_lo = _mm256_shuffle_epi8(t0, lo_n0);
            let p0_hi = _mm256_shuffle_epi8(t1, lo_n0);
            let p1_lo = _mm256_shuffle_epi8(t2, lo_n1);
            let p1_hi = _mm256_shuffle_epi8(t3, lo_n1);
            let p2_lo = _mm256_shuffle_epi8(t4, hi_n0);
            let p2_hi = _mm256_shuffle_epi8(t5, hi_n0);
            let p3_lo = _mm256_shuffle_epi8(t6, hi_n1);
            let p3_hi = _mm256_shuffle_epi8(t7, hi_n1);

            // XOR contributions.
            let result_lo = _mm256_xor_si256(
                _mm256_xor_si256(p0_lo, p1_lo),
                _mm256_xor_si256(p2_lo, p3_lo),
            );
            let result_hi = _mm256_xor_si256(
                _mm256_xor_si256(p0_hi, p1_hi),
                _mm256_xor_si256(p2_hi, p3_hi),
            );

            // Reinterleave within each lane: low qwords → s0's words, high
            // qwords → s1's words.
            let product0 = _mm256_unpacklo_epi8(result_lo, result_hi);
            let product1 = _mm256_unpackhi_epi8(result_lo, result_hi);

            // XOR-accumulate.
            let d0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let d1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset) as *mut __m256i,
                _mm256_xor_si256(d0, product0),
            );
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(offset + 32) as *mut __m256i,
                _mm256_xor_si256(d1, product1),
            );

            offset += 64;
        }
    }

    // Tail: fall through to SSSE3 for a remaining 32-byte block + scalar.
    if offset < len {
        unsafe { mul_acc_region_ssse3(tables, &src[offset..], &mut dst[offset..]) };
    }
}

// ---------------------------------------------------------------------------
// NEON kernel (aarch64): 32 bytes (16 GF elements) per iteration
//
// Full-width lookups: `vld2q_u8` loads a 32-byte block directly as separated
// even/odd byte planes (the same idiom as the CLMUL kernels), so every lane of
// the eight `vqtbl1q` lookups carries data — 16 words per lookup round instead
// of the 8 a single-vector `vuzp1q(s, s)` deinterleave would leave (upper
// halves discarded).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_region_neon(tables: &MulTables, src: &[u8], dst: &mut [u8]) {
    use std::arch::aarch64::*;

    let len = src.len();
    let mut offset = 0usize;

    unsafe {
        let mask_0f = vdupq_n_u8(0x0F);

        let t0 = vld1q_u8(tables.tables[0].as_ptr());
        let t1 = vld1q_u8(tables.tables[1].as_ptr());
        let t2 = vld1q_u8(tables.tables[2].as_ptr());
        let t3 = vld1q_u8(tables.tables[3].as_ptr());
        let t4 = vld1q_u8(tables.tables[4].as_ptr());
        let t5 = vld1q_u8(tables.tables[5].as_ptr());
        let t6 = vld1q_u8(tables.tables[6].as_ptr());
        let t7 = vld1q_u8(tables.tables[7].as_ptr());

        while offset + 32 <= len {
            if NEON_SRC_PREFETCH {
                prefetch_src_l1(src.as_ptr().wrapping_add(offset + 64));
            }

            // Deinterleaving load: .0 = lo bytes of 16 words, .1 = hi bytes.
            let s = vld2q_u8(src.as_ptr().add(offset));
            let lo_bytes = s.0;
            let hi_bytes = s.1;

            // Extract nibbles.
            let lo_n0 = vandq_u8(lo_bytes, mask_0f);
            let lo_n1 = vandq_u8(vshrq_n_u8(lo_bytes, 4), mask_0f);
            let hi_n0 = vandq_u8(hi_bytes, mask_0f);
            let hi_n1 = vandq_u8(vshrq_n_u8(hi_bytes, 4), mask_0f);

            // 8 lookups, all lanes live.
            let p0_lo = vqtbl1q_u8(t0, lo_n0);
            let p0_hi = vqtbl1q_u8(t1, lo_n0);
            let p1_lo = vqtbl1q_u8(t2, lo_n1);
            let p1_hi = vqtbl1q_u8(t3, lo_n1);
            let p2_lo = vqtbl1q_u8(t4, hi_n0);
            let p2_hi = vqtbl1q_u8(t5, hi_n0);
            let p3_lo = vqtbl1q_u8(t6, hi_n1);
            let p3_hi = vqtbl1q_u8(t7, hi_n1);

            // XOR contributions.
            let result_lo = veorq_u8(veorq_u8(p0_lo, p1_lo), veorq_u8(p2_lo, p3_lo));
            let result_hi = veorq_u8(veorq_u8(p0_hi, p1_hi), veorq_u8(p2_hi, p3_hi));

            // XOR-accumulate on the destination's byte planes; the
            // interleaving store puts the words back together.
            let mut d = vld2q_u8(dst.as_ptr().add(offset));
            d.0 = veorq_u8(d.0, result_lo);
            d.1 = veorq_u8(d.1, result_hi);
            vst2q_u8(dst.as_mut_ptr().add(offset), d);

            offset += 32;
        }
    }

    // Scalar tail (< one 32-byte block; lengths 16..=31 land here too).
    if offset < len {
        mul_acc_region_scalar(tables.factor, &src[offset..], &mut dst[offset..]);
    }
}

// ---------------------------------------------------------------------------
// wasm simd128 kernel: 16 bytes (8 GF elements) per iteration
//
// A near-mechanical port of the NEON split-nibble kernel above (see the
// module-level "Split-nibble shuffle" note). The same 8 precomputed 16-byte
// tables map each of the four input nibbles to its low/high product byte, and
// the eight table lookups are byte swizzles (wasm's PSHUFB/VTBL equivalent).
//
// Two flavors share one body via the `$lookup` macro parameter:
//   * `i8x16_swizzle` (simd128)            — out-of-range indices yield 0, but
//     our nibble indices are pre-masked to 0..=15 so no lane is ever cleared.
//   * `i8x16_relaxed_swizzle` (relaxed-simd) — identical here; it merely drops
//     the x86 lane-clamp that the plain form must emit, since we already
//     guarantee in-range indices. Same bytes out, fewer instructions in.
//
// Lane bookkeeping mirrors NEON exactly:
//   * deinterleave lo/hi bytes: `vuzp1q_u8`/`vuzp2q_u8(s, s)` become
//     `i8x16_shuffle` gathering the even/odd byte lanes into lanes 0..=7 (only
//     those eight are consumed downstream, one per GF word).
//   * reinterleave: `vzip1q_u8(lo, hi)` becomes an `i8x16_shuffle` weaving
//     result_lo[k]/result_hi[k] into [rlo0, rhi0, rlo1, rhi1, ...].
//   * `vshrq_n_u8(x, 4)` becomes `u8x16_shr(x, 4)` (logical, u8x16.shr_u).
//
// Dispatch is compile-time: the artifact is built with `+simd128` (and
// optionally `+relaxed-simd`), so there is no runtime feature detection.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
unsafe fn mul_acc_region_wasm_simd128<const RELAXED: bool>(
    tables: &MulTables,
    src: &[u8],
    dst: &mut [u8],
) {
    use core::arch::wasm32::*;

    let len = src.len();
    let mut offset = 0usize;

    // `i8x16_relaxed_swizzle` is only defined when the relaxed-simd feature is
    // enabled, so the `RELAXED` arm is compiled out entirely without it.
    macro_rules! lookup {
        ($table:expr, $idx:expr) => {{
            #[cfg(target_feature = "relaxed-simd")]
            {
                if RELAXED {
                    i8x16_relaxed_swizzle($table, $idx)
                } else {
                    i8x16_swizzle($table, $idx)
                }
            }
            #[cfg(not(target_feature = "relaxed-simd"))]
            {
                let _ = RELAXED;
                i8x16_swizzle($table, $idx)
            }
        }};
    }

    unsafe {
        let mask_0f = u8x16_splat(0x0F);

        let t0 = v128_load(tables.tables[0].as_ptr() as *const v128);
        let t1 = v128_load(tables.tables[1].as_ptr() as *const v128);
        let t2 = v128_load(tables.tables[2].as_ptr() as *const v128);
        let t3 = v128_load(tables.tables[3].as_ptr() as *const v128);
        let t4 = v128_load(tables.tables[4].as_ptr() as *const v128);
        let t5 = v128_load(tables.tables[5].as_ptr() as *const v128);
        let t6 = v128_load(tables.tables[6].as_ptr() as *const v128);
        let t7 = v128_load(tables.tables[7].as_ptr() as *const v128);

        while offset + 16 <= len {
            let s = v128_load(src.as_ptr().add(offset) as *const v128);
            let d = v128_load(dst.as_ptr().add(offset) as *const v128);

            // Deinterleave: gather even (lo) / odd (hi) bytes into lanes 0..=7.
            // Only the low eight lanes are consumed downstream, mirroring the
            // NEON `vuzp1q_u8`/`vuzp2q_u8(s, s)` pair.
            let lo_bytes =
                i8x16_shuffle::<0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14>(s, s);
            let hi_bytes =
                i8x16_shuffle::<1, 3, 5, 7, 9, 11, 13, 15, 1, 3, 5, 7, 9, 11, 13, 15>(s, s);

            // Extract nibbles.
            let lo_n0 = v128_and(lo_bytes, mask_0f);
            let lo_n1 = v128_and(u8x16_shr(lo_bytes, 4), mask_0f);
            let hi_n0 = v128_and(hi_bytes, mask_0f);
            let hi_n1 = v128_and(u8x16_shr(hi_bytes, 4), mask_0f);

            // 8 lookups.
            let p0_lo = lookup!(t0, lo_n0);
            let p0_hi = lookup!(t1, lo_n0);
            let p1_lo = lookup!(t2, lo_n1);
            let p1_hi = lookup!(t3, lo_n1);
            let p2_lo = lookup!(t4, hi_n0);
            let p2_hi = lookup!(t5, hi_n0);
            let p3_lo = lookup!(t6, hi_n1);
            let p3_hi = lookup!(t7, hi_n1);

            // XOR contributions.
            let result_lo = v128_xor(v128_xor(p0_lo, p1_lo), v128_xor(p2_lo, p3_lo));
            let result_hi = v128_xor(v128_xor(p0_hi, p1_hi), v128_xor(p2_hi, p3_hi));

            // Reinterleave: [rlo0, rhi0, rlo1, rhi1, ...] (lanes 16..=23 pick the
            // low bytes of result_hi), mirroring NEON `vzip1q_u8`.
            let product = i8x16_shuffle::<0, 16, 1, 17, 2, 18, 3, 19, 4, 20, 5, 21, 6, 22, 7, 23>(
                result_lo, result_hi,
            );

            // XOR-accumulate.
            let result = v128_xor(d, product);
            v128_store(dst.as_mut_ptr().add(offset) as *mut v128, result);

            offset += 16;
        }
    }

    // Scalar tail.
    if offset < len {
        mul_acc_region_scalar(tables.factor, &src[offset..], &mut dst[offset..]);
    }
}

// ---------------------------------------------------------------------------
// Multi-region GFNI + AVX2 kernel
//
// Reads src once per 64-byte block, applies all factors to all destinations.
// The full-width pair deinterleave (see `mul_acc_region_gfni_avx2`) is
// hoisted once per block: every factor reuses the same full lo/hi byte
// planes and costs only its four affines plus the per-destination
// unpack/XOR/store.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_acc_multi_region_gfni_avx2(factors_and_dsts: &mut [FactorDst<'_>], src: &[u8]) {
    use std::arch::x86_64::*;

    let len = src.len();

    struct BroadcastAffine {
        m_ll: __m256i,
        m_lh: __m256i,
        m_hl: __m256i,
        m_hh: __m256i,
        factor: u16,
        dst_idx: usize,
    }

    // Precompute affine matrices for all non-zero factors.
    let all_matrices: Vec<BroadcastAffine> = factors_and_dsts
        .iter()
        .enumerate()
        .filter(|(_, fd)| fd.factor != 0 && fd.factor != 1)
        .map(|(idx, fd)| {
            let matrices = precompute_affine_matrices(fd.factor);
            BroadcastAffine {
                m_ll: _mm256_set1_epi64x(matrices.m_ll as i64),
                m_lh: _mm256_set1_epi64x(matrices.m_lh as i64),
                m_hl: _mm256_set1_epi64x(matrices.m_hl as i64),
                m_hh: _mm256_set1_epi64x(matrices.m_hh as i64),
                factor: matrices.factor,
                dst_idx: idx,
            }
        })
        .collect();

    // Handle factor=1 (XOR-only) destinations.
    for fd in factors_and_dsts.iter_mut() {
        if fd.factor == 1 {
            for (d, s) in fd.dst.iter_mut().zip(src.iter()) {
                *d ^= *s;
            }
        }
    }

    if all_matrices.is_empty() {
        return;
    }

    unsafe {
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        let mut offset = 0usize;
        while offset + 64 <= len {
            let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let s1 = _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);

            // Full-width pair deinterleave, hoisted once per block (see
            // `mul_acc_region_gfni_avx2` for the lane mapping).
            let a = _mm256_shuffle_epi8(s0, deint_pair);
            let b = _mm256_shuffle_epi8(s1, deint_pair);
            let lo_bytes = _mm256_unpacklo_epi64(a, b);
            let hi_bytes = _mm256_unpackhi_epi64(a, b);

            for matrices in &all_matrices {
                let dst_ptr = factors_and_dsts[matrices.dst_idx].dst.as_ptr();
                let d0 = _mm256_loadu_si256(dst_ptr.add(offset) as *const __m256i);
                let d1 = _mm256_loadu_si256(dst_ptr.add(offset + 32) as *const __m256i);

                let result_lo = _mm256_xor_si256(
                    _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, matrices.m_ll),
                    _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, matrices.m_lh),
                );
                let result_hi = _mm256_xor_si256(
                    _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, matrices.m_hl),
                    _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, matrices.m_hh),
                );

                // Reinterleave within each lane: low qwords → s0's words,
                // high qwords → s1's words.
                let product0 = _mm256_unpacklo_epi8(result_lo, result_hi);
                let product1 = _mm256_unpackhi_epi8(result_lo, result_hi);

                let out = factors_and_dsts[matrices.dst_idx].dst.as_mut_ptr();
                _mm256_storeu_si256(
                    out.add(offset) as *mut __m256i,
                    _mm256_xor_si256(d0, product0),
                );
                _mm256_storeu_si256(
                    out.add(offset + 32) as *mut __m256i,
                    _mm256_xor_si256(d1, product1),
                );
            }

            offset += 64;
        }

        // Tail: scalar for remaining bytes.
        if offset < len {
            for matrices in &all_matrices {
                mul_acc_region_scalar(
                    matrices.factor,
                    &src[offset..],
                    &mut factors_and_dsts[matrices.dst_idx].dst[offset..],
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Grouped-input GFNI + AVX2 kernel
//
// Keeps one destination chunk hot in registers while accumulating multiple
// source regions into it. This mirrors ParPar's grouped-input execution shape
// more closely than repeatedly issuing single-input updates against the same
// destination buffer.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_acc_input_batch_gfni_avx2(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        m_ll: __m256i,
        m_lh: __m256i,
        m_hl: __m256i,
        m_hh: __m256i,
        factor: u16,
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor == 1)
        .map(|fs| fs.src)
        .collect();

    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor != 0 && fs.factor != 1)
        .map(|fs| {
            let matrices = precompute_affine_matrices(fs.factor);
            PreparedInput {
                m_ll: _mm256_set1_epi64x(matrices.m_ll as i64),
                m_lh: _mm256_set1_epi64x(matrices.m_lh as i64),
                m_hl: _mm256_set1_epi64x(matrices.m_hl as i64),
                m_hh: _mm256_set1_epi64x(matrices.m_hh as i64),
                factor: matrices.factor,
                src: fs.src,
            }
        })
        .collect();

    unsafe {
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Sources are walked in small groups, one full destination pass per
        // group: bounding the concurrent read streams keeps them within the
        // core's line-fill buffers. A single pass over a large batch turns
        // into 60+ interleaved streams and stalls on L1 misses.
        let vec_len = len & !63;
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 64 <= vec_len {
                let mut acc0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
                let mut acc1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
                        let s1 =
                            _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);
                        acc0 = _mm256_xor_si256(acc0, s0);
                        acc1 = _mm256_xor_si256(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm256_loadu_si256(input.src.as_ptr().add(offset) as *const __m256i);
                    let s1 =
                        _mm256_loadu_si256(input.src.as_ptr().add(offset + 32) as *const __m256i);

                    // Full-width pair deinterleave (see `mul_acc_region_gfni_avx2`).
                    let a = _mm256_shuffle_epi8(s0, deint_pair);
                    let b = _mm256_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm256_unpacklo_epi64(a, b);
                    let hi_bytes = _mm256_unpackhi_epi64(a, b);

                    let result_lo = _mm256_xor_si256(
                        _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_ll),
                        _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_lh),
                    );
                    let result_hi = _mm256_xor_si256(
                        _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_hl),
                        _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_hh),
                    );

                    acc0 = _mm256_xor_si256(acc0, _mm256_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm256_xor_si256(acc1, _mm256_unpackhi_epi8(result_lo, result_hi));
                }

                _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, acc0);
                _mm256_storeu_si256(dst.as_mut_ptr().add(offset + 32) as *mut __m256i, acc1);
                offset += 64;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }

        let offset = vec_len;
        if offset < len {
            let tail = &mut dst[offset..];
            for src in &xor_inputs {
                for (d, s) in tail.iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for input in &prepared {
                mul_acc_region_scalar(input.factor, &input.src[offset..], tail);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
unsafe fn mul_acc_input_batch_gfni_avx2_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        m_ll: __m256i,
        m_lh: __m256i,
        m_hl: __m256i,
        m_hh: __m256i,
        factor: u16,
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.prepared.factor == 1)
        .map(|fs| fs.src)
        .collect();

    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter_map(|fs| match fs.prepared.x86.as_ref() {
            Some(PreparedX86Factor::Gfni(matrices)) => Some(PreparedInput {
                m_ll: _mm256_set1_epi64x(matrices.m_ll as i64),
                m_lh: _mm256_set1_epi64x(matrices.m_lh as i64),
                m_hl: _mm256_set1_epi64x(matrices.m_hl as i64),
                m_hh: _mm256_set1_epi64x(matrices.m_hh as i64),
                factor: matrices.factor,
                src: fs.src,
            }),
            _ => None,
        })
        .collect();

    unsafe {
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Sources are walked in small groups, one full destination pass per
        // group: bounding the concurrent read streams keeps them within the
        // core's line-fill buffers. A single pass over a large batch turns
        // into 60+ interleaved streams and stalls on L1 misses.
        let vec_len = len & !63;
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 64 <= vec_len {
                let mut acc0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
                let mut acc1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
                        let s1 =
                            _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);
                        acc0 = _mm256_xor_si256(acc0, s0);
                        acc1 = _mm256_xor_si256(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm256_loadu_si256(input.src.as_ptr().add(offset) as *const __m256i);
                    let s1 =
                        _mm256_loadu_si256(input.src.as_ptr().add(offset + 32) as *const __m256i);

                    // Full-width pair deinterleave (see `mul_acc_region_gfni_avx2`).
                    let a = _mm256_shuffle_epi8(s0, deint_pair);
                    let b = _mm256_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm256_unpacklo_epi64(a, b);
                    let hi_bytes = _mm256_unpackhi_epi64(a, b);

                    let result_lo = _mm256_xor_si256(
                        _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_ll),
                        _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_lh),
                    );
                    let result_hi = _mm256_xor_si256(
                        _mm256_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_hl),
                        _mm256_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_hh),
                    );

                    acc0 = _mm256_xor_si256(acc0, _mm256_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm256_xor_si256(acc1, _mm256_unpackhi_epi8(result_lo, result_hi));
                }

                _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, acc0);
                _mm256_storeu_si256(dst.as_mut_ptr().add(offset + 32) as *mut __m256i, acc1);
                offset += 64;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }

        let offset = vec_len;
        if offset < len {
            let tail = &mut dst[offset..];
            for src in &xor_inputs {
                for (d, s) in tail.iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for input in &prepared {
                mul_acc_region_scalar(input.factor, &input.src[offset..], tail);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Grouped-input GFNI + AVX-512 kernel
//
// 512-bit counterpart to the GFNI+AVX2 grouped-input path: each 128-byte dst
// strip is loaded and stored once while every prepared source in the batch
// is multiplied into it, with the full-width pair deinterleave of
// `mul_acc_input_batch_avx512_prepared` so all gf2p8affineqb lanes carry
// data.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512bw,avx512vl")]
unsafe fn mul_acc_input_batch_gfni_avx512_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        m_ll: __m512i,
        m_lh: __m512i,
        m_hl: __m512i,
        m_hh: __m512i,
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.prepared.factor == 1)
        .map(|fs| fs.src)
        .collect();

    // Prepared factors must be the GFNI flavor on this path (the dispatchers
    // guarantee it on-machine); a foreign Avx2-flavored factor would be
    // silently dropped here yet applied by the AVX2 tail delegate below.
    debug_assert!(
        factors_and_srcs.iter().all(|fs| matches!(
            fs.prepared.x86.as_ref(),
            None | Some(PreparedX86Factor::Gfni(_))
        )),
        "gfni avx512 batch requires GFNI-flavored prepared factors"
    );
    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter_map(|fs| match fs.prepared.x86.as_ref() {
            Some(PreparedX86Factor::Gfni(matrices)) => Some(PreparedInput {
                m_ll: _mm512_set1_epi64(matrices.m_ll as i64),
                m_lh: _mm512_set1_epi64(matrices.m_lh as i64),
                m_hl: _mm512_set1_epi64(matrices.m_hl as i64),
                m_hh: _mm512_set1_epi64(matrices.m_hh as i64),
                src: fs.src,
            }),
            _ => None,
        })
        .collect();

    let vec_len = len & !127;
    unsafe {
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm512_broadcast_i32x4(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Same source-group blocking as the 256-bit kernel: bound the
        // concurrent read streams per destination pass.
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 128 <= vec_len {
                let mut acc0 = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
                let mut acc1 = _mm512_loadu_si512(dst.as_ptr().add(offset + 64) as *const __m512i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
                        let s1 =
                            _mm512_loadu_si512(src.as_ptr().add(offset + 64) as *const __m512i);
                        acc0 = _mm512_xor_si512(acc0, s0);
                        acc1 = _mm512_xor_si512(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm512_loadu_si512(input.src.as_ptr().add(offset) as *const __m512i);
                    let s1 =
                        _mm512_loadu_si512(input.src.as_ptr().add(offset + 64) as *const __m512i);

                    // Full-width pair deinterleave — 4-lane word trace (zmm
                    // 128-bit lanes L0..L3; word w[i] = le u16 at strip byte
                    // 2i, so the 128-byte strip holds w[0..64)):
                    //   s0 = strip[0..64):   lane Lk = words w[8k..8k+8)
                    //   s1 = strip[64..128): lane Lk = words w[32+8k..32+8k+8)
                    //   a = shuffle(s0, deint_pair):
                    //     lane Lk = [lo(w[8k..8k+8)) | hi(w[8k..8k+8))]
                    //   b = shuffle(s1, deint_pair):
                    //     lane Lk = [lo(w[32+8k..)) | hi(w[32+8k..))]
                    //   lo_bytes = unpacklo_epi64(a, b):
                    //     lane Lk = [lo of s0's Lk words | lo of s1's Lk words]
                    //   hi_bytes = unpackhi_epi64(a, b): same with hi bytes.
                    //   gf2p8affineqb transforms bytes in place (the matrix is
                    //   broadcast to every qword), so result_lo/result_hi keep
                    //   that byte→word placement; then
                    //   unpacklo_epi8(result_lo, result_hi):
                    //     lane Lk = product words w[8k..8k+8) re-interleaved
                    //     → acc0 (dst strip bytes [0..64))
                    //   unpackhi_epi8(result_lo, result_hi):
                    //     lane Lk = product words w[32+8k..32+8k+8)
                    //     → acc1 (dst strip bytes [64..128)).
                    let a = _mm512_shuffle_epi8(s0, deint_pair);
                    let b = _mm512_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm512_unpacklo_epi64(a, b);
                    let hi_bytes = _mm512_unpackhi_epi64(a, b);

                    let result_lo = _mm512_xor_si512(
                        _mm512_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_ll),
                        _mm512_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_lh),
                    );
                    let result_hi = _mm512_xor_si512(
                        _mm512_gf2p8affine_epi64_epi8::<0>(lo_bytes, input.m_hl),
                        _mm512_gf2p8affine_epi64_epi8::<0>(hi_bytes, input.m_hh),
                    );

                    acc0 = _mm512_xor_si512(acc0, _mm512_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm512_xor_si512(acc1, _mm512_unpackhi_epi8(result_lo, result_hi));
                }

                _mm512_storeu_si512(dst.as_mut_ptr().add(offset) as *mut __m512i, acc0);
                _mm512_storeu_si512(dst.as_mut_ptr().add(offset + 64) as *mut __m512i, acc1);
                offset += 128;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }
    }

    // Tail: reuse the 256-bit prepared kernel for the remainder.
    if vec_len < len {
        let tail_srcs: Vec<PreparedFactorSrc<'_>> = factors_and_srcs
            .iter()
            .map(|fs| PreparedFactorSrc {
                prepared: fs.prepared,
                src: &fs.src[vec_len..],
            })
            .collect();
        unsafe { mul_acc_input_batch_gfni_avx2_prepared(&mut dst[vec_len..], &tail_srcs) };
    }
}

/// A GFNI-forced prepared factor for the unprepared 512-bit entry: inside a
/// `gfni`-gated kernel the affine variant is always the right one, so skip
/// `prepare_input_factor`'s runtime feature probe.
#[cfg(target_arch = "x86_64")]
fn prepare_input_factor_gfni(factor: u16) -> PreparedInputFactor {
    PreparedInputFactor {
        factor,
        x86: (factor > 1).then(|| PreparedX86Factor::Gfni(precompute_affine_matrices(factor))),
    }
}

/// Unprepared 512-bit GFNI grouped-input entry: computes the affine matrices
/// inline (batch-setup cost, amortized over the whole region — the same
/// trade the unprepared 256-bit kernel makes) and runs the prepared kernel.
/// This is what the tiled matrix elimination's rank-k apply reaches on
/// GFNI+AVX512 hardware; without it those solves ran the 256-bit kernel.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx512bw,avx512vl")]
unsafe fn mul_acc_input_batch_gfni_avx512(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    let prepared: Vec<PreparedInputFactor> = factors_and_srcs
        .iter()
        .map(|fs| prepare_input_factor_gfni(fs.factor))
        .collect();
    let pairs: Vec<PreparedFactorSrc<'_>> = prepared
        .iter()
        .zip(factors_and_srcs.iter())
        .map(|(prepared, fs)| PreparedFactorSrc {
            prepared,
            src: fs.src,
        })
        .collect();
    unsafe { mul_acc_input_batch_gfni_avx512_prepared(dst, &pairs) };
}

// ---------------------------------------------------------------------------
// Grouped-input AVX2 kernel
//
// Split-nibble counterpart to the GFNI grouped-input path. This keeps x86
// machines without GFNI from falling all the way back to repeated dst
// load/store cycles for every input region. Sources stream through the same
// full-width pair deinterleave as `mul_acc_region_avx2`, so the eight lookups
// per source serve all 32 words of a 64-byte destination strip.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_acc_input_batch_avx2(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        tables: [__m256i; 8],
        factor: u16,
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor == 1)
        .map(|fs| fs.src)
        .collect();

    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor != 0 && fs.factor != 1)
        .map(|fs| {
            let tables = precompute_mul_tables(fs.factor);
            let load_table = |idx: usize| unsafe {
                _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    tables.tables[idx].as_ptr() as *const __m128i
                ))
            };
            PreparedInput {
                tables: [
                    load_table(0),
                    load_table(1),
                    load_table(2),
                    load_table(3),
                    load_table(4),
                    load_table(5),
                    load_table(6),
                    load_table(7),
                ],
                factor: tables.factor,
                src: fs.src,
            }
        })
        .collect();

    unsafe {
        let mask_0f = _mm256_set1_epi8(0x0F);
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Same source-group blocking as the GFNI kernels: bound the
        // concurrent read streams per destination pass.
        let vec_len = len & !63;
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 64 <= vec_len {
                let mut acc0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
                let mut acc1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
                        let s1 =
                            _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);
                        acc0 = _mm256_xor_si256(acc0, s0);
                        acc1 = _mm256_xor_si256(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm256_loadu_si256(input.src.as_ptr().add(offset) as *const __m256i);
                    let s1 =
                        _mm256_loadu_si256(input.src.as_ptr().add(offset + 32) as *const __m256i);

                    // Full-width pair deinterleave (see `mul_acc_region_avx2`).
                    let a = _mm256_shuffle_epi8(s0, deint_pair);
                    let b = _mm256_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm256_unpacklo_epi64(a, b);
                    let hi_bytes = _mm256_unpackhi_epi64(a, b);

                    let lo_n0 = _mm256_and_si256(lo_bytes, mask_0f);
                    let lo_n1 = _mm256_and_si256(_mm256_srli_epi16(lo_bytes, 4), mask_0f);
                    let hi_n0 = _mm256_and_si256(hi_bytes, mask_0f);
                    let hi_n1 = _mm256_and_si256(_mm256_srli_epi16(hi_bytes, 4), mask_0f);

                    let p0_lo = _mm256_shuffle_epi8(input.tables[0], lo_n0);
                    let p0_hi = _mm256_shuffle_epi8(input.tables[1], lo_n0);
                    let p1_lo = _mm256_shuffle_epi8(input.tables[2], lo_n1);
                    let p1_hi = _mm256_shuffle_epi8(input.tables[3], lo_n1);
                    let p2_lo = _mm256_shuffle_epi8(input.tables[4], hi_n0);
                    let p2_hi = _mm256_shuffle_epi8(input.tables[5], hi_n0);
                    let p3_lo = _mm256_shuffle_epi8(input.tables[6], hi_n1);
                    let p3_hi = _mm256_shuffle_epi8(input.tables[7], hi_n1);

                    let result_lo = _mm256_xor_si256(
                        _mm256_xor_si256(p0_lo, p1_lo),
                        _mm256_xor_si256(p2_lo, p3_lo),
                    );
                    let result_hi = _mm256_xor_si256(
                        _mm256_xor_si256(p0_hi, p1_hi),
                        _mm256_xor_si256(p2_hi, p3_hi),
                    );

                    acc0 = _mm256_xor_si256(acc0, _mm256_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm256_xor_si256(acc1, _mm256_unpackhi_epi8(result_lo, result_hi));
                }

                _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, acc0);
                _mm256_storeu_si256(dst.as_mut_ptr().add(offset + 32) as *mut __m256i, acc1);
                offset += 64;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }
        let offset = vec_len;

        if offset < len {
            for src in &xor_inputs {
                for (d, s) in dst[offset..].iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for input in &prepared {
                mul_acc_region_scalar(input.factor, &input.src[offset..], &mut dst[offset..]);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul_acc_input_batch_avx2_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        tables: [__m256i; 8],
        factor: u16,
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.prepared.factor == 1)
        .map(|fs| fs.src)
        .collect();

    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter_map(|fs| match fs.prepared.x86.as_ref() {
            Some(PreparedX86Factor::Avx2(tables)) => {
                let load_table = |idx: usize| unsafe {
                    _mm256_broadcastsi128_si256(_mm_loadu_si128(
                        tables.tables[idx].as_ptr() as *const __m128i
                    ))
                };
                Some(PreparedInput {
                    tables: [
                        load_table(0),
                        load_table(1),
                        load_table(2),
                        load_table(3),
                        load_table(4),
                        load_table(5),
                        load_table(6),
                        load_table(7),
                    ],
                    factor: tables.factor,
                    src: fs.src,
                })
            }
            _ => None,
        })
        .collect();

    unsafe {
        let mask_0f = _mm256_set1_epi8(0x0F);
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm256_broadcastsi128_si256(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Same source-group blocking as the GFNI kernels: bound the
        // concurrent read streams per destination pass.
        let vec_len = len & !63;
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 64 <= vec_len {
                let mut acc0 = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
                let mut acc1 = _mm256_loadu_si256(dst.as_ptr().add(offset + 32) as *const __m256i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
                        let s1 =
                            _mm256_loadu_si256(src.as_ptr().add(offset + 32) as *const __m256i);
                        acc0 = _mm256_xor_si256(acc0, s0);
                        acc1 = _mm256_xor_si256(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm256_loadu_si256(input.src.as_ptr().add(offset) as *const __m256i);
                    let s1 =
                        _mm256_loadu_si256(input.src.as_ptr().add(offset + 32) as *const __m256i);

                    // Full-width pair deinterleave (see `mul_acc_region_avx2`).
                    let a = _mm256_shuffle_epi8(s0, deint_pair);
                    let b = _mm256_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm256_unpacklo_epi64(a, b);
                    let hi_bytes = _mm256_unpackhi_epi64(a, b);

                    let lo_n0 = _mm256_and_si256(lo_bytes, mask_0f);
                    let lo_n1 = _mm256_and_si256(_mm256_srli_epi16(lo_bytes, 4), mask_0f);
                    let hi_n0 = _mm256_and_si256(hi_bytes, mask_0f);
                    let hi_n1 = _mm256_and_si256(_mm256_srli_epi16(hi_bytes, 4), mask_0f);

                    let p0_lo = _mm256_shuffle_epi8(input.tables[0], lo_n0);
                    let p0_hi = _mm256_shuffle_epi8(input.tables[1], lo_n0);
                    let p1_lo = _mm256_shuffle_epi8(input.tables[2], lo_n1);
                    let p1_hi = _mm256_shuffle_epi8(input.tables[3], lo_n1);
                    let p2_lo = _mm256_shuffle_epi8(input.tables[4], hi_n0);
                    let p2_hi = _mm256_shuffle_epi8(input.tables[5], hi_n0);
                    let p3_lo = _mm256_shuffle_epi8(input.tables[6], hi_n1);
                    let p3_hi = _mm256_shuffle_epi8(input.tables[7], hi_n1);

                    let result_lo = _mm256_xor_si256(
                        _mm256_xor_si256(p0_lo, p1_lo),
                        _mm256_xor_si256(p2_lo, p3_lo),
                    );
                    let result_hi = _mm256_xor_si256(
                        _mm256_xor_si256(p0_hi, p1_hi),
                        _mm256_xor_si256(p2_hi, p3_hi),
                    );

                    acc0 = _mm256_xor_si256(acc0, _mm256_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm256_xor_si256(acc1, _mm256_unpackhi_epi8(result_lo, result_hi));
                }

                _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, acc0);
                _mm256_storeu_si256(dst.as_mut_ptr().add(offset + 32) as *mut __m256i, acc1);
                offset += 64;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }
        let offset = vec_len;

        if offset < len {
            for src in &xor_inputs {
                for (d, s) in dst[offset..].iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for input in &prepared {
                mul_acc_region_scalar(input.factor, &input.src[offset..], &mut dst[offset..]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Grouped-input AVX-512 kernel (non-GFNI)
//
// 512-bit counterpart to the split-nibble AVX2 grouped-input path, for
// AVX-512 boxes without GFNI: same SRC_STREAM_GROUP source blocking, tables
// broadcast per 128-bit lane (as in `mul_acc_region_avx512`), and the
// full-width pair deinterleave so the eight lookups per source serve all 64
// words of a 128-byte destination strip.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw,avx512vl")]
unsafe fn mul_acc_input_batch_avx512_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    use std::arch::x86_64::*;

    let len = dst.len();

    struct PreparedInput<'a> {
        tables: [__m512i; 8],
        src: &'a [u8],
    }

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.prepared.factor == 1)
        .map(|fs| fs.src)
        .collect();

    // Prepared factors must be the split-nibble (Avx2 table) flavor on this
    // path (the dispatchers guarantee it on-machine); a foreign GFNI-flavored
    // factor would be silently dropped here yet applied by the AVX2 tail
    // delegate below.
    debug_assert!(
        factors_and_srcs.iter().all(|fs| matches!(
            fs.prepared.x86.as_ref(),
            None | Some(PreparedX86Factor::Avx2(_))
        )),
        "avx512 shuffle batch requires Avx2-table-flavored prepared factors"
    );
    let prepared: Vec<PreparedInput<'_>> = factors_and_srcs
        .iter()
        .filter_map(|fs| match fs.prepared.x86.as_ref() {
            Some(PreparedX86Factor::Avx2(tables)) => {
                let load_table = |idx: usize| unsafe {
                    _mm512_broadcast_i32x4(_mm_loadu_si128(
                        tables.tables[idx].as_ptr() as *const __m128i
                    ))
                };
                Some(PreparedInput {
                    tables: [
                        load_table(0),
                        load_table(1),
                        load_table(2),
                        load_table(3),
                        load_table(4),
                        load_table(5),
                        load_table(6),
                        load_table(7),
                    ],
                    src: fs.src,
                })
            }
            _ => None,
        })
        .collect();

    let vec_len = len & !127;
    unsafe {
        let mask_0f = _mm512_set1_epi8(0x0F);
        // Pair deinterleave mask (same [evens | odds] pattern in each lane).
        let deint_pair = _mm512_broadcast_i32x4(_mm_set_epi8(
            15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0,
        ));

        // Same source-group blocking as the 256-bit kernel: bound the
        // concurrent read streams per destination pass.
        let mut first_pass = true;
        let mut group_start = 0usize;
        loop {
            let group_end = (group_start + SRC_STREAM_GROUP).min(prepared.len());
            let group = &prepared[group_start..group_end];

            let mut offset = 0usize;
            while offset + 128 <= vec_len {
                let mut acc0 = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);
                let mut acc1 = _mm512_loadu_si512(dst.as_ptr().add(offset + 64) as *const __m512i);

                if first_pass {
                    for src in &xor_inputs {
                        let s0 = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
                        let s1 =
                            _mm512_loadu_si512(src.as_ptr().add(offset + 64) as *const __m512i);
                        acc0 = _mm512_xor_si512(acc0, s0);
                        acc1 = _mm512_xor_si512(acc1, s1);
                    }
                }

                for input in group {
                    let s0 = _mm512_loadu_si512(input.src.as_ptr().add(offset) as *const __m512i);
                    let s1 =
                        _mm512_loadu_si512(input.src.as_ptr().add(offset + 64) as *const __m512i);

                    // Full-width pair deinterleave (see `mul_acc_region_avx512`).
                    let a = _mm512_shuffle_epi8(s0, deint_pair);
                    let b = _mm512_shuffle_epi8(s1, deint_pair);
                    let lo_bytes = _mm512_unpacklo_epi64(a, b);
                    let hi_bytes = _mm512_unpackhi_epi64(a, b);

                    let lo_n0 = _mm512_and_si512(lo_bytes, mask_0f);
                    let lo_n1 = _mm512_and_si512(_mm512_srli_epi16(lo_bytes, 4), mask_0f);
                    let hi_n0 = _mm512_and_si512(hi_bytes, mask_0f);
                    let hi_n1 = _mm512_and_si512(_mm512_srli_epi16(hi_bytes, 4), mask_0f);

                    let p0_lo = _mm512_shuffle_epi8(input.tables[0], lo_n0);
                    let p0_hi = _mm512_shuffle_epi8(input.tables[1], lo_n0);
                    let p1_lo = _mm512_shuffle_epi8(input.tables[2], lo_n1);
                    let p1_hi = _mm512_shuffle_epi8(input.tables[3], lo_n1);
                    let p2_lo = _mm512_shuffle_epi8(input.tables[4], hi_n0);
                    let p2_hi = _mm512_shuffle_epi8(input.tables[5], hi_n0);
                    let p3_lo = _mm512_shuffle_epi8(input.tables[6], hi_n1);
                    let p3_hi = _mm512_shuffle_epi8(input.tables[7], hi_n1);

                    let result_lo = _mm512_xor_si512(
                        _mm512_xor_si512(p0_lo, p1_lo),
                        _mm512_xor_si512(p2_lo, p3_lo),
                    );
                    let result_hi = _mm512_xor_si512(
                        _mm512_xor_si512(p0_hi, p1_hi),
                        _mm512_xor_si512(p2_hi, p3_hi),
                    );

                    acc0 = _mm512_xor_si512(acc0, _mm512_unpacklo_epi8(result_lo, result_hi));
                    acc1 = _mm512_xor_si512(acc1, _mm512_unpackhi_epi8(result_lo, result_hi));
                }

                _mm512_storeu_si512(dst.as_mut_ptr().add(offset) as *mut __m512i, acc0);
                _mm512_storeu_si512(dst.as_mut_ptr().add(offset + 64) as *mut __m512i, acc1);
                offset += 128;
            }

            first_pass = false;
            group_start = group_end;
            if group_start >= prepared.len() {
                break;
            }
        }
    }

    // Tail: reuse the 256-bit prepared kernel for the remainder.
    if vec_len < len {
        let tail_srcs: Vec<PreparedFactorSrc<'_>> = factors_and_srcs
            .iter()
            .map(|fs| PreparedFactorSrc {
                prepared: fs.prepared,
                src: &fs.src[vec_len..],
            })
            .collect();
        unsafe { mul_acc_input_batch_avx2_prepared(&mut dst[vec_len..], &tail_srcs) };
    }
}

/// An Avx2-table-forced prepared factor for the unprepared 512-bit shuffle
/// entry: inside the non-GFNI `avx512bw` kernel the split-nibble tables are
/// always the right flavor, so skip `prepare_input_factor`'s runtime feature
/// probe (which would build GFNI matrices on GFNI hardware and starve this
/// kernel — it consumes only the Avx2 table flavor).
#[cfg(target_arch = "x86_64")]
fn prepare_input_factor_shuffle(factor: u16) -> PreparedInputFactor {
    PreparedInputFactor {
        factor,
        x86: (factor > 1).then(|| PreparedX86Factor::Avx2(precompute_mul_tables(factor))),
    }
}

/// Unprepared 512-bit shuffle grouped-input entry: computes the nibble tables
/// inline (batch-setup cost, amortized over the whole region — the same trade
/// the unprepared 256-bit kernel makes) and runs the prepared kernel.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw,avx512vl")]
unsafe fn mul_acc_input_batch_avx512(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    let prepared: Vec<PreparedInputFactor> = factors_and_srcs
        .iter()
        .map(|fs| prepare_input_factor_shuffle(fs.factor))
        .collect();
    let pairs: Vec<PreparedFactorSrc<'_>> = prepared
        .iter()
        .zip(factors_and_srcs.iter())
        .map(|(prepared, fs)| PreparedFactorSrc {
            prepared,
            src: fs.src,
        })
        .collect();
    unsafe { mul_acc_input_batch_avx512_prepared(dst, &pairs) };
}

// ---------------------------------------------------------------------------
// Multi-region CLMUL kernel (aarch64)
//
// One source region × many (factor, dst) pairs. Karatsuba PMULL products per
// coefficient with the packed Barrett reduction shared with the input-batch
// CLMUL kernels ([`clmul_barrett_reduce`], upstream `gf16_clmul_neon_reduction`,
// poly 0x1100b) — the source's byte planes are deinterleaved once per 32-byte
// block and reused across every destination. The one-src-many-dst shape itself
// is rarpar-native (upstream's CLMUL kernels are grouped-input only).
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn mul_acc_multi_region_clmul_body<const SHA3: bool>(
    factors_and_dsts: &mut [FactorDst<'_>],
    src: &[u8],
) {
    use std::arch::aarch64::*;

    let len = src.len();

    // factor==1 destinations are a plain XOR.
    for fd in factors_and_dsts.iter_mut() {
        if fd.factor == 1 {
            for (d, s) in fd.dst.iter_mut().zip(src.iter()) {
                *d ^= *s;
            }
        }
    }

    let coeffs: Vec<(ClmulBatchCoeff, usize)> = unsafe {
        factors_and_dsts
            .iter()
            .enumerate()
            .filter(|(_, fd)| fd.factor > 1)
            .map(|(idx, fd)| (clmul_batch_coeff(fd.factor), idx))
            .collect()
    };
    if coeffs.is_empty() {
        return;
    }

    let vec_len = len & !31;
    unsafe {
        let mut offset = 0usize;
        while offset < vec_len {
            let planes = clmul_load_planes(src.as_ptr().add(offset));
            for (coeff, dst_idx) in &coeffs {
                let r = clmul_barrett_reduce::<SHA3>(clmul_partials(planes, coeff));
                let dst = factors_and_dsts[*dst_idx].dst.as_mut_ptr().add(offset);
                let mut vb = vld2q_u8(dst as *const u8);
                vb.0 = eor3q::<SHA3>(r[0], r[1], vb.0);
                vb.1 = eor3q::<SHA3>(r[2], r[3], vb.1);
                vst2q_u8(dst, vb);
            }
            offset += 32;
        }
    }

    // Scalar tail (< one 32-byte block).
    if vec_len < len {
        for &(_, dst_idx) in &coeffs {
            let factor = factors_and_dsts[dst_idx].factor;
            mul_acc_region_scalar(
                factor,
                &src[vec_len..],
                &mut factors_and_dsts[dst_idx].dst[vec_len..],
            );
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_multi_region_clmul(factors_and_dsts: &mut [FactorDst<'_>], src: &[u8]) {
    unsafe { mul_acc_multi_region_clmul_body::<false>(factors_and_dsts, src) }
}

/// EOR3-reduction flavor, selected when FEAT_SHA3 is detected.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn mul_acc_multi_region_clmul_sha3(factors_and_dsts: &mut [FactorDst<'_>], src: &[u8]) {
    unsafe { mul_acc_multi_region_clmul_body::<true>(factors_and_dsts, src) }
}

// ---------------------------------------------------------------------------
// Input-batch CLMUL kernels (aarch64)
//
// Faithful port of ParPar's grouped-input CLMul kernel family:
// `gf16_clmul_muladd_x` (gf16_clmul_neon_base.h), generated upstream as
// `gf16_clmul_muladd_*_neon` / `*_sha3` (gf16_clmul_sha3.c). Many sources
// accumulate into one destination; each 32-byte block runs one packed Barrett
// reduction (`gf16_clmul_neon_reduction`, gf16_clmul_neon.h:52-101, poly
// 0x1100b) shared by every source — the reason CLMul beats VTBL shuffle once
// the input count exceeds 3 (ParPar gf16mul.cpp:1607-1626 selection).
//
// Three accumulation flavors, mirroring upstream exactly:
//   - plain NEON (`_neon`): PMULL then EOR per partial (upstream `pmacl_*`).
//   - SHA3 non-Apple (`_sha3`, Neoverse V1/N2, Graviton3+): per-source product
//     sets merged with EOR3, two sources per merge (`gf16_clmul_sha3_merge2`).
//   - SHA3 Apple: PMULL+EOR kept adjacent via inline asm so Apple cores fuse
//     the pair; EOR3 is deliberately NOT used for accumulation
//     (gf16_clmul_sha3.c:19-45), though the reduction still uses it.
// Upstream processes at most 8 sources per pass (CLMUL_NUM_REGIONS, aarch64);
// larger batches make additional passes over dst.
// ---------------------------------------------------------------------------

/// Upstream compiles the Apple flavor with `__APPLE__`; mirror that at build
/// time. Only affects which SHA3 accumulation strategy is emitted.
#[cfg(target_arch = "aarch64")]
const CLMUL_APPLE_FUSION: bool = cfg!(target_vendor = "apple");

/// Sources per pass, = upstream CLMUL_NUM_REGIONS on aarch64.
#[cfg(target_arch = "aarch64")]
const CLMUL_SRC_GROUP: usize = 8;

/// Whether the input-batch dispatch may pick the CLMUL kernels. Setting
/// `WEAVER_GF16_CLMUL_BATCH=0` pins the VTBL shuffle path so the two can be
/// A/B'd without a rebuild (same escape-hatch pattern as
/// `WEAVER_GF16_FOLDED_AVX512`).
#[cfg(target_arch = "aarch64")]
fn clmul_batch_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("WEAVER_GF16_CLMUL_BATCH").is_none_or(|v| v != "0"))
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn clmul_sha3_available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha3")
}

/// Per-source broadcast coefficients: factor split into lo/hi bytes plus the
/// Karatsuba middle term (upstream builds the same triple per region,
/// gf16_clmul_neon_base.h:66-72).
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct ClmulBatchCoeff {
    lo: std::arch::aarch64::poly8x16_t,
    hi: std::arch::aarch64::poly8x16_t,
    mid: std::arch::aarch64::poly8x16_t,
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_batch_coeff(factor: u16) -> ClmulBatchCoeff {
    use std::arch::aarch64::*;
    let lo = (factor & 0xFF) as u8;
    let hi = (factor >> 8) as u8;
    unsafe {
        ClmulBatchCoeff {
            lo: vdupq_n_p8(lo),
            hi: vdupq_n_p8(hi),
            mid: vdupq_n_p8(lo ^ hi),
        }
    }
}

/// The six per-block partial products (upstream low1/low2/mid1/mid2/high1/high2).
/// Shared with `gf_pmul`, whose upstream kernel reuses the same reduction.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub(crate) struct ClmulPartials {
    pub(crate) low1: std::arch::aarch64::poly16x8_t,
    pub(crate) low2: std::arch::aarch64::poly16x8_t,
    pub(crate) mid1: std::arch::aarch64::poly16x8_t,
    pub(crate) mid2: std::arch::aarch64::poly16x8_t,
    pub(crate) high1: std::arch::aarch64::poly16x8_t,
    pub(crate) high2: std::arch::aarch64::poly16x8_t,
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn veorq_p16x(
    a: std::arch::aarch64::poly16x8_t,
    b: std::arch::aarch64::poly16x8_t,
) -> std::arch::aarch64::poly16x8_t {
    use std::arch::aarch64::*;
    unsafe {
        vreinterpretq_p16_u16(veorq_u16(
            vreinterpretq_u16_p16(a),
            vreinterpretq_u16_p16(b),
        ))
    }
}

/// 3-way XOR: EOR3 when the SHA3 flavor is active, EOR pair otherwise
/// (upstream `eor3q_u8` and its non-SHA3 fallback, gf16_clmul_neon.h:46-50).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn eor3q<const SHA3: bool>(
    a: std::arch::aarch64::uint8x16_t,
    b: std::arch::aarch64::uint8x16_t,
    c: std::arch::aarch64::uint8x16_t,
) -> std::arch::aarch64::uint8x16_t {
    use std::arch::aarch64::*;
    unsafe {
        if SHA3 {
            veor3q_u8(a, b, c)
        } else {
            veorq_u8(a, veorq_u8(b, c))
        }
    }
}

/// A 32-byte block's deinterleaved byte planes (`vld2`): the even (lo) and
/// odd (hi) bytes of the LE u16 words, plus their XOR (the Karatsuba middle
/// operand). Shared by the input-batch and multi-region CLMUL kernels so a
/// one-src-many-dst caller can deinterleave once per block.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct ClmulSrcPlanes {
    lo: std::arch::aarch64::poly8x16_t,
    hi: std::arch::aarch64::poly8x16_t,
    mid: std::arch::aarch64::poly8x16_t,
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_load_planes(src: *const u8) -> ClmulSrcPlanes {
    use std::arch::aarch64::*;
    unsafe {
        let data = vld2q_u8(src);
        ClmulSrcPlanes {
            lo: vreinterpretq_p8_u8(data.0),
            hi: vreinterpretq_p8_u8(data.1),
            mid: vreinterpretq_p8_u8(veorq_u8(data.0, data.1)),
        }
    }
}

/// The six Karatsuba products of loaded planes × broadcast coefficient
/// (the multiply half of upstream `gf16_clmul_neon_round1`).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_partials(d: ClmulSrcPlanes, c: &ClmulBatchCoeff) -> ClmulPartials {
    use std::arch::aarch64::*;
    unsafe {
        ClmulPartials {
            low1: vmull_p8(vget_low_p8(d.lo), vget_low_p8(c.lo)),
            low2: vmull_high_p8(d.lo, c.lo),
            mid1: vmull_p8(vget_low_p8(d.mid), vget_low_p8(c.mid)),
            mid2: vmull_high_p8(d.mid, c.mid),
            high1: vmull_p8(vget_low_p8(d.hi), vget_low_p8(c.hi)),
            high2: vmull_high_p8(d.hi, c.hi),
        }
    }
}

/// One source's six products for a 32-byte block (upstream
/// `gf16_clmul_neon_round1`): load the byte planes, multiply by the
/// broadcast coefficient.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_round1(src: *const u8, c: &ClmulBatchCoeff) -> ClmulPartials {
    unsafe { clmul_partials(clmul_load_planes(src), c) }
}

/// Accumulating round, plain-NEON flavor: six PMULL + six EOR (upstream
/// `gf16_clmul_neon_round` with intrinsic `pmacl_*`).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_round_acc(acc: &mut ClmulPartials, src: *const u8, c: &ClmulBatchCoeff) {
    unsafe {
        let p = clmul_round1(src, c);
        acc.low1 = veorq_p16x(acc.low1, p.low1);
        acc.low2 = veorq_p16x(acc.low2, p.low2);
        acc.mid1 = veorq_p16x(acc.mid1, p.mid1);
        acc.mid2 = veorq_p16x(acc.mid2, p.mid2);
        acc.high1 = veorq_p16x(acc.high1, p.high1);
        acc.high2 = veorq_p16x(acc.high2, p.high2);
    }
}

/// PMULL immediately followed by EOR, as one asm unit, so Apple cores fuse the
/// pair (upstream gf16_clmul_sha3.c:27-44). `out` (not `lateout`) keeps the
/// result register distinct from all inputs: it is written by the first
/// instruction while `sum` is still live.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn pmacl_low_fused(
    sum: std::arch::aarch64::poly16x8_t,
    a: std::arch::aarch64::poly8x16_t,
    b: std::arch::aarch64::poly8x16_t,
) -> std::arch::aarch64::poly16x8_t {
    use std::arch::aarch64::*;
    let result: uint16x8_t;
    unsafe {
        std::arch::asm!(
            "pmull {r:v}.8h, {a:v}.8b, {b:v}.8b",
            "eor {r:v}.16b, {r:v}.16b, {s:v}.16b",
            r = out(vreg) result,
            a = in(vreg) vreinterpretq_u8_p8(a),
            b = in(vreg) vreinterpretq_u8_p8(b),
            s = in(vreg) vreinterpretq_u16_p16(sum),
            options(pure, nomem, nostack),
        );
        vreinterpretq_p16_u16(result)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn pmacl_high_fused(
    sum: std::arch::aarch64::poly16x8_t,
    a: std::arch::aarch64::poly8x16_t,
    b: std::arch::aarch64::poly8x16_t,
) -> std::arch::aarch64::poly16x8_t {
    use std::arch::aarch64::*;
    let result: uint16x8_t;
    unsafe {
        std::arch::asm!(
            "pmull2 {r:v}.8h, {a:v}.16b, {b:v}.16b",
            "eor {r:v}.16b, {r:v}.16b, {s:v}.16b",
            r = out(vreg) result,
            a = in(vreg) vreinterpretq_u8_p8(a),
            b = in(vreg) vreinterpretq_u8_p8(b),
            s = in(vreg) vreinterpretq_u16_p16(sum),
            options(pure, nomem, nostack),
        );
        vreinterpretq_p16_u16(result)
    }
}

/// Accumulating round, Apple-fusion flavor.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_round_acc_fused(acc: &mut ClmulPartials, src: *const u8, c: &ClmulBatchCoeff) {
    use std::arch::aarch64::*;
    unsafe {
        let data = vld2q_u8(src);
        let d_lo = vreinterpretq_p8_u8(data.0);
        let d_hi = vreinterpretq_p8_u8(data.1);
        let d_mid = vreinterpretq_p8_u8(veorq_u8(data.0, data.1));
        acc.low1 = pmacl_low_fused(acc.low1, d_lo, c.lo);
        acc.low2 = pmacl_high_fused(acc.low2, d_lo, c.lo);
        acc.mid1 = pmacl_low_fused(acc.mid1, d_mid, c.mid);
        acc.mid2 = pmacl_high_fused(acc.mid2, d_mid, c.mid);
        acc.high1 = pmacl_low_fused(acc.high1, d_hi, c.hi);
        acc.high2 = pmacl_high_fused(acc.high2, d_hi, c.hi);
    }
}

/// Merge one source's product set into the accumulators with plain EOR
/// (upstream `gf16_clmul_sha3_merge1`).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_merge1(acc: &mut ClmulPartials, b: ClmulPartials) {
    unsafe {
        acc.low1 = veorq_p16x(acc.low1, b.low1);
        acc.low2 = veorq_p16x(acc.low2, b.low2);
        acc.mid1 = veorq_p16x(acc.mid1, b.mid1);
        acc.mid2 = veorq_p16x(acc.mid2, b.mid2);
        acc.high1 = veorq_p16x(acc.high1, b.high1);
        acc.high2 = veorq_p16x(acc.high2, b.high2);
    }
}

/// Merge two sources' product sets at once with EOR3 (upstream
/// `gf16_clmul_sha3_merge2`).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn clmul_merge2<const SHA3: bool>(
    acc: &mut ClmulPartials,
    b: ClmulPartials,
    c: ClmulPartials,
) {
    use std::arch::aarch64::*;
    unsafe {
        macro_rules! m {
            ($f:ident) => {
                acc.$f = vreinterpretq_p16_u8(eor3q::<SHA3>(
                    vreinterpretq_u8_p16(acc.$f),
                    vreinterpretq_u8_p16(b.$f),
                    vreinterpretq_u8_p16(c.$f),
                ));
            };
        }
        m!(low1);
        m!(low2);
        m!(mid1);
        m!(mid2);
        m!(high1);
        m!(high2);
    }
}

/// Packed Barrett reduction, verbatim port of `gf16_clmul_neon_reduction`
/// (gf16_clmul_neon.h:52-101), poly 0x1100b (first reduction coefficient
/// 0x1111a). Returns four byte-plane vectors; the block result's even plane is
/// `out[0]^out[1]`, the odd plane `out[2]^out[3]` — folded into dst by the
/// caller. The `SHA3` flavor replaces the non-SHA3 `vqtbl1q` bit-fold trick
/// with an extra term carried into the final EOR3 (upstream's
/// `__ARM_FEATURE_SHA3` branches at :73-80 and :95-99).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub(crate) unsafe fn clmul_barrett_reduce<const SHA3: bool>(
    p: ClmulPartials,
) -> [std::arch::aarch64::uint8x16_t; 4] {
    use std::arch::aarch64::*;
    unsafe {
        // put data in proper form
        let hib = vuzpq_u8(vreinterpretq_u8_p16(p.high1), vreinterpretq_u8_p16(p.high2));
        let lob = vuzpq_u8(vreinterpretq_u8_p16(p.low1), vreinterpretq_u8_p16(p.low2));
        // merge mid into high/low
        let midb = vuzpq_u8(vreinterpretq_u8_p16(p.mid1), vreinterpretq_u8_p16(p.mid2));
        let libytes = veorq_u8(hib.0, lob.1);
        let lob1 = eor3q::<SHA3>(libytes, lob.0, midb.0);
        let hib0 = eor3q::<SHA3>(libytes, hib.1, midb.1);

        // Barrett reduction: multiply the high half by 0x11110
        let th0 = vsriq_n_u8::<4>(vshlq_n_u8::<4>(hib.1), hib0);
        let th1 = veorq_u8(hib.1, vshrq_n_u8::<4>(hib.1));
        let th0 = eor3q::<SHA3>(th0, th1, hib0);

        // low bits of th0 are dead past this point; trim now for a shorter
        // dependency chain
        let th0_hi3 = vshrq_n_u8::<5>(th0);
        // non-SHA3: `th0_hi3 ^= th0_hi3 >> 2` in one table op; SHA3 carries
        // the `>> 2` term into the final EOR3 instead
        let (th0_hi3, th0_hi1) = if SHA3 {
            (th0_hi3, vshrq_n_u8::<2>(th0_hi3))
        } else {
            let tbl = vld1q_u8([0u8, 1, 2, 3, 5, 4, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0].as_ptr());
            (vqtbl1q_u8(tbl, th0_hi3), vdupq_n_u8(0))
        };

        // 0x1a's 0x10 part is handled above; shift in the 0x8 (hib.1 holds at
        // most 7 bits, so 0x18 behaves like 0x1a here)
        let th0 = veorq_u8(th0, vshrq_n_u8::<5>(hib.1));

        // multiply by polynomial 0x100b
        let red_l = vdupq_n_p8(0x0b);
        let hib1_new = vsliq_n_u8::<4>(th0_hi3, th0);
        let th1p = vreinterpretq_u8_p8(vmulq_p8(vreinterpretq_p8_u8(th1), red_l));
        let hib0_new = vreinterpretq_u8_p8(vmulq_p8(vreinterpretq_p8_u8(th0), red_l));

        let out_high1 = if SHA3 {
            eor3q::<SHA3>(hib1_new, th0_hi1, th1p)
        } else {
            veorq_u8(hib1_new, th1p)
        };
        [lob.0, hib0_new, out_high1, lob1]
    }
}

/// Shared body for the input-batch CLMUL kernels. `SHA3` selects the EOR3
/// reduction/merge flavor; `FUSED` selects Apple's PMULL+EOR-paired
/// accumulation (upstream: `FUSED` ≙ `__APPLE__`, where the merge rotation is
/// NOT used and the final dst fold stays a plain EOR pair).
///
/// Takes `(factor, src)` pairs as a cloneable iterator so both the raw and
/// prepared dispatch paths run allocation-free: sources are consumed in
/// fixed groups of [`CLMUL_SRC_GROUP`] through a stack buffer, one full pass
/// over `dst` per group (upstream makes one muladd_multi call per group).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn mul_acc_input_batch_clmul_body<'a, const SHA3: bool, const FUSED: bool>(
    dst: &mut [u8],
    inputs: impl Iterator<Item = (u16, &'a [u8])> + Clone,
) {
    use std::arch::aarch64::*;
    let len = dst.len();
    // The public dispatchers assert this; guard direct (test/future) callers
    // too — a short src would send vld2q/tail slicing out of bounds.
    debug_assert!(len.is_multiple_of(2), "region length must be even");

    // factor==1 is a plain XOR; fold those up front like the other kernels.
    for (factor, src) in inputs.clone() {
        debug_assert_eq!(src.len(), len, "src length must match dst");
        if factor == 1 {
            for (d, s) in dst.iter_mut().zip(src.iter()) {
                *d ^= *s;
            }
        }
    }

    let vec_len = len & !31;
    let mut it = inputs.filter(|&(factor, _)| factor > 1);
    loop {
        // Fill the next group of up to CLMUL_SRC_GROUP sources.
        let mut group: [Option<(u16, ClmulBatchCoeff, &[u8])>; CLMUL_SRC_GROUP] =
            [None; CLMUL_SRC_GROUP];
        let mut n = 0usize;
        for slot in group.iter_mut() {
            let Some((factor, src)) = it.next() else {
                break;
            };
            *slot = Some((factor, unsafe { clmul_batch_coeff(factor) }, src));
            n += 1;
        }
        if n == 0 {
            break;
        }
        let group = &group[..n];

        unsafe {
            let mut offset = 0usize;
            while offset < vec_len {
                if NEON_SRC_PREFETCH {
                    for e in group {
                        let (_, _, src) = e.unwrap();
                        prefetch_src_l1(src.as_ptr().wrapping_add(offset + 64));
                    }
                }

                let first = group[0].unwrap();
                let mut acc = clmul_round1(first.2.as_ptr().add(offset), &first.1);
                let rest = &group[1..];
                if SHA3 && !FUSED {
                    // EOR3 rotation: two fresh product sets per merge, odd
                    // leftover via plain merge (gf16_clmul_sha3.c:86-112).
                    let mut i = 0usize;
                    while i + 2 <= rest.len() {
                        let b = rest[i].unwrap();
                        let c = rest[i + 1].unwrap();
                        let pb = clmul_round1(b.2.as_ptr().add(offset), &b.1);
                        let pc = clmul_round1(c.2.as_ptr().add(offset), &c.1);
                        clmul_merge2::<SHA3>(&mut acc, pb, pc);
                        i += 2;
                    }
                    if i < rest.len() {
                        let b = rest[i].unwrap();
                        let pb = clmul_round1(b.2.as_ptr().add(offset), &b.1);
                        clmul_merge1(&mut acc, pb);
                    }
                } else {
                    for e in rest {
                        let e = e.unwrap();
                        if FUSED {
                            clmul_round_acc_fused(&mut acc, e.2.as_ptr().add(offset), &e.1);
                        } else {
                            clmul_round_acc(&mut acc, e.2.as_ptr().add(offset), &e.1);
                        }
                    }
                }

                let r = clmul_barrett_reduce::<SHA3>(acc);
                let mut vb = vld2q_u8(dst.as_ptr().add(offset));
                if SHA3 && !FUSED {
                    vb.0 = veor3q_u8(r[0], r[1], vb.0);
                    vb.1 = veor3q_u8(r[2], r[3], vb.1);
                } else {
                    vb.0 = veorq_u8(veorq_u8(r[0], r[1]), vb.0);
                    vb.1 = veorq_u8(veorq_u8(r[2], r[3]), vb.1);
                }
                vst2q_u8(dst.as_mut_ptr().add(offset), vb);

                offset += 32;
            }
        }

        // Scalar tail (< one 32-byte block) for this group's sources.
        if vec_len < len {
            for e in group {
                let (factor, _, src) = e.unwrap();
                mul_acc_region_scalar(factor, &src[vec_len..], &mut dst[vec_len..]);
            }
        }
    }
}

/// Input-batch CLMUL, plain-NEON flavor (upstream `gf16_clmul_muladd_*_neon`).
#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_input_batch_clmul(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    unsafe {
        mul_acc_input_batch_clmul_body::<false, false>(
            dst,
            factors_and_srcs.iter().map(|fs| (fs.factor, fs.src)),
        )
    }
}

/// Input-batch CLMUL, SHA3 flavor (upstream `gf16_clmul_muladd_*_sha3`):
/// EOR3 merges on non-Apple cores, fused PMULL+EOR pairs on Apple.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn mul_acc_input_batch_clmul_sha3(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    unsafe {
        mul_acc_input_batch_clmul_body::<true, CLMUL_APPLE_FUSION>(
            dst,
            factors_and_srcs.iter().map(|fs| (fs.factor, fs.src)),
        )
    }
}

/// Prepared-path entries: identical kernels fed straight from
/// `PreparedFactorSrc` (CLMUL preparation is six broadcasts — the raw factor
/// is all it needs), avoiding any conversion allocation in the dispatcher.
#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_input_batch_clmul_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    unsafe {
        mul_acc_input_batch_clmul_body::<false, false>(
            dst,
            factors_and_srcs
                .iter()
                .map(|fs| (fs.prepared.factor, fs.src)),
        )
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha3")]
unsafe fn mul_acc_input_batch_clmul_sha3_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    unsafe {
        mul_acc_input_batch_clmul_body::<true, CLMUL_APPLE_FUSION>(
            dst,
            factors_and_srcs
                .iter()
                .map(|fs| (fs.prepared.factor, fs.src)),
        )
    }
}

/// Test-only instantiation of the non-Apple EOR3 merge flavor so the
/// Neoverse/Graviton codepath is oracle-verified on Apple hardware too:
/// M-series has FEAT_SHA3, and upstream's Apple carve-out is a scheduling
/// preference, not a capability difference.
#[cfg(all(target_arch = "aarch64", test))]
#[target_feature(enable = "sha3")]
unsafe fn mul_acc_input_batch_clmul_sha3_unfused(
    dst: &mut [u8],
    factors_and_srcs: &[FactorSrc<'_>],
) {
    unsafe {
        mul_acc_input_batch_clmul_body::<true, false>(
            dst,
            factors_and_srcs.iter().map(|fs| (fs.factor, fs.src)),
        )
    }
}

// ---------------------------------------------------------------------------
// Multi-region NEON kernel (aarch64)
//
// Reads src once per 32-byte block, applies all factors to all destinations.
// The block's byte planes are deinterleaved once (`vld2q_u8`, full-width like
// the single-region kernel) and the nibble extraction is hoisted, so each
// factor costs just its 8 lookups + XOR fold per 16 words.
//
// Only serves batches with ≤2 non-trivial factors (the dispatcher hands
// larger fan-outs to the CLMUL kernels) — this is the matrix rank-1 update
// path for tiny batches.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_multi_region_neon(factors_and_dsts: &mut [FactorDst<'_>], src: &[u8]) {
    use std::arch::aarch64::*;

    let len = src.len();

    // Precompute shuffle tables for all non-zero/non-one factors.
    let all_tables: Vec<(MulTables, usize)> = factors_and_dsts
        .iter()
        .enumerate()
        .filter(|(_, fd)| fd.factor != 0 && fd.factor != 1)
        .map(|(idx, fd)| (precompute_mul_tables(fd.factor), idx))
        .collect();

    // Handle factor=1 (XOR-only) destinations.
    for fd in factors_and_dsts.iter_mut() {
        if fd.factor == 1 {
            for (d, s) in fd.dst.iter_mut().zip(src.iter()) {
                *d ^= *s;
            }
        }
    }

    if all_tables.is_empty() {
        return;
    }

    // Pre-load all table sets into NEON registers.
    struct NeonTableSet {
        t: [uint8x16_t; 8],
        dst_idx: usize,
    }

    let table_sets: Vec<NeonTableSet> = unsafe {
        all_tables
            .iter()
            .map(|(tables, dst_idx)| NeonTableSet {
                t: [
                    vld1q_u8(tables.tables[0].as_ptr()),
                    vld1q_u8(tables.tables[1].as_ptr()),
                    vld1q_u8(tables.tables[2].as_ptr()),
                    vld1q_u8(tables.tables[3].as_ptr()),
                    vld1q_u8(tables.tables[4].as_ptr()),
                    vld1q_u8(tables.tables[5].as_ptr()),
                    vld1q_u8(tables.tables[6].as_ptr()),
                    vld1q_u8(tables.tables[7].as_ptr()),
                ],
                dst_idx: *dst_idx,
            })
            .collect()
    };

    unsafe {
        let mask_0f = vdupq_n_u8(0x0F);
        let mut offset = 0usize;

        while offset + 32 <= len {
            // Deinterleave the block once (full-width byte planes), reuse the
            // nibble vectors for all factors.
            let s = vld2q_u8(src.as_ptr().add(offset));
            let lo_n0 = vandq_u8(s.0, mask_0f);
            let lo_n1 = vandq_u8(vshrq_n_u8(s.0, 4), mask_0f);
            let hi_n0 = vandq_u8(s.1, mask_0f);
            let hi_n1 = vandq_u8(vshrq_n_u8(s.1, 4), mask_0f);

            for ts in &table_sets {
                let p0_lo = vqtbl1q_u8(ts.t[0], lo_n0);
                let p0_hi = vqtbl1q_u8(ts.t[1], lo_n0);
                let p1_lo = vqtbl1q_u8(ts.t[2], lo_n1);
                let p1_hi = vqtbl1q_u8(ts.t[3], lo_n1);
                let p2_lo = vqtbl1q_u8(ts.t[4], hi_n0);
                let p2_hi = vqtbl1q_u8(ts.t[5], hi_n0);
                let p3_lo = vqtbl1q_u8(ts.t[6], hi_n1);
                let p3_hi = vqtbl1q_u8(ts.t[7], hi_n1);

                let result_lo = veorq_u8(veorq_u8(p0_lo, p1_lo), veorq_u8(p2_lo, p3_lo));
                let result_hi = veorq_u8(veorq_u8(p0_hi, p1_hi), veorq_u8(p2_hi, p3_hi));

                let dst_ptr = factors_and_dsts[ts.dst_idx].dst.as_mut_ptr().add(offset);
                let mut d = vld2q_u8(dst_ptr as *const u8);
                d.0 = veorq_u8(d.0, result_lo);
                d.1 = veorq_u8(d.1, result_hi);
                vst2q_u8(dst_ptr, d);
            }

            offset += 32;
        }

        // Scalar tail.
        if offset < len {
            for (tables, dst_idx) in &all_tables {
                mul_acc_region_scalar(
                    tables.factor,
                    &src[offset..],
                    &mut factors_and_dsts[*dst_idx].dst[offset..],
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Grouped-input NEON kernel (aarch64)
//
// Keeps the destination strip's byte planes in registers while accumulating
// multiple source regions. This is the ARM counterpart to the GFNI
// grouped-input path and avoids reloading/storing `dst` once per input
// region. Every source folds into the strip in a single destination pass —
// no SRC_STREAM_GROUP-style blocking — which stays within the line-fill
// buffers because dispatch hands batches of more than 3 sources to the CLMUL
// kernels.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_input_batch_neon(dst: &mut [u8], factors_and_srcs: &[FactorSrc<'_>]) {
    use std::arch::aarch64::*;

    let len = dst.len();

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor == 1)
        .map(|fs| fs.src)
        .collect();

    let all_tables: Vec<(MulTables, &[u8])> = factors_and_srcs
        .iter()
        .filter(|fs| fs.factor != 0 && fs.factor != 1)
        .map(|fs| (precompute_mul_tables(fs.factor), fs.src))
        .collect();

    if xor_inputs.is_empty() && all_tables.is_empty() {
        return;
    }

    struct NeonInputTableSet<'a> {
        t: [uint8x16_t; 8],
        factor: u16,
        src: &'a [u8],
    }

    let table_sets: Vec<NeonInputTableSet<'_>> = unsafe {
        all_tables
            .iter()
            .map(|(tables, src)| NeonInputTableSet {
                t: [
                    vld1q_u8(tables.tables[0].as_ptr()),
                    vld1q_u8(tables.tables[1].as_ptr()),
                    vld1q_u8(tables.tables[2].as_ptr()),
                    vld1q_u8(tables.tables[3].as_ptr()),
                    vld1q_u8(tables.tables[4].as_ptr()),
                    vld1q_u8(tables.tables[5].as_ptr()),
                    vld1q_u8(tables.tables[6].as_ptr()),
                    vld1q_u8(tables.tables[7].as_ptr()),
                ],
                factor: tables.factor,
                src,
            })
            .collect()
    };

    unsafe {
        let mask_0f = vdupq_n_u8(0x0F);
        let mut offset = 0usize;

        // Full-width strips (see `mul_acc_region_neon`): `vld2q_u8` loads a
        // 32-byte block directly as separated even/odd byte planes, so every
        // lane of the eight lookups carries data, and the destination
        // accumulates plane-wise with one interleaving `vst2q_u8` per strip.
        while offset + 32 <= len {
            let mut d = vld2q_u8(dst.as_ptr().add(offset));

            for src in &xor_inputs {
                let s = vld2q_u8(src.as_ptr().add(offset));
                d.0 = veorq_u8(d.0, s.0);
                d.1 = veorq_u8(d.1, s.1);
            }

            for ts in &table_sets {
                // Deinterleaving load: .0 = lo bytes of 16 words, .1 = hi.
                let s = vld2q_u8(ts.src.as_ptr().add(offset));
                let lo_n0 = vandq_u8(s.0, mask_0f);
                let lo_n1 = vandq_u8(vshrq_n_u8(s.0, 4), mask_0f);
                let hi_n0 = vandq_u8(s.1, mask_0f);
                let hi_n1 = vandq_u8(vshrq_n_u8(s.1, 4), mask_0f);

                let p0_lo = vqtbl1q_u8(ts.t[0], lo_n0);
                let p0_hi = vqtbl1q_u8(ts.t[1], lo_n0);
                let p1_lo = vqtbl1q_u8(ts.t[2], lo_n1);
                let p1_hi = vqtbl1q_u8(ts.t[3], lo_n1);
                let p2_lo = vqtbl1q_u8(ts.t[4], hi_n0);
                let p2_hi = vqtbl1q_u8(ts.t[5], hi_n0);
                let p3_lo = vqtbl1q_u8(ts.t[6], hi_n1);
                let p3_hi = vqtbl1q_u8(ts.t[7], hi_n1);

                let result_lo = veorq_u8(veorq_u8(p0_lo, p1_lo), veorq_u8(p2_lo, p3_lo));
                let result_hi = veorq_u8(veorq_u8(p0_hi, p1_hi), veorq_u8(p2_hi, p3_hi));
                d.0 = veorq_u8(d.0, result_lo);
                d.1 = veorq_u8(d.1, result_hi);
            }

            vst2q_u8(dst.as_mut_ptr().add(offset), d);
            offset += 32;
        }

        if offset < len {
            for src in &xor_inputs {
                for (d, s) in dst[offset..].iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for ts in &table_sets {
                mul_acc_region_scalar(ts.factor, &ts.src[offset..], &mut dst[offset..]);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn mul_acc_input_batch_neon_prepared(
    dst: &mut [u8],
    factors_and_srcs: &[PreparedFactorSrc<'_>],
) {
    use std::arch::aarch64::*;

    let len = dst.len();

    let xor_inputs: Vec<&[u8]> = factors_and_srcs
        .iter()
        .filter(|fs| fs.prepared.factor == 1)
        .map(|fs| fs.src)
        .collect();

    struct NeonInputTableSet<'a> {
        t: [uint8x16_t; 8],
        factor: u16,
        src: &'a [u8],
    }

    let table_sets: Vec<NeonInputTableSet<'_>> = unsafe {
        factors_and_srcs
            .iter()
            .filter(|fs| fs.prepared.factor != 0 && fs.prepared.factor != 1)
            .map(|fs| {
                let tables = fs
                    .prepared
                    .tables
                    .as_ref()
                    .expect("prepared ARM factor must include mul tables");
                NeonInputTableSet {
                    t: [
                        vld1q_u8(tables.tables[0].as_ptr()),
                        vld1q_u8(tables.tables[1].as_ptr()),
                        vld1q_u8(tables.tables[2].as_ptr()),
                        vld1q_u8(tables.tables[3].as_ptr()),
                        vld1q_u8(tables.tables[4].as_ptr()),
                        vld1q_u8(tables.tables[5].as_ptr()),
                        vld1q_u8(tables.tables[6].as_ptr()),
                        vld1q_u8(tables.tables[7].as_ptr()),
                    ],
                    factor: fs.prepared.factor,
                    src: fs.src,
                }
            })
            .collect()
    };

    if xor_inputs.is_empty() && table_sets.is_empty() {
        return;
    }

    unsafe {
        let mask_0f = vdupq_n_u8(0x0F);
        let mut offset = 0usize;

        // Full-width strips (see `mul_acc_region_neon`): `vld2q_u8` loads a
        // 32-byte block directly as separated even/odd byte planes, so every
        // lane of the eight lookups carries data, and the destination
        // accumulates plane-wise with one interleaving `vst2q_u8` per strip.
        while offset + 32 <= len {
            let mut d = vld2q_u8(dst.as_ptr().add(offset));

            for src in &xor_inputs {
                let s = vld2q_u8(src.as_ptr().add(offset));
                d.0 = veorq_u8(d.0, s.0);
                d.1 = veorq_u8(d.1, s.1);
            }

            for ts in &table_sets {
                // Deinterleaving load: .0 = lo bytes of 16 words, .1 = hi.
                let s = vld2q_u8(ts.src.as_ptr().add(offset));
                let lo_n0 = vandq_u8(s.0, mask_0f);
                let lo_n1 = vandq_u8(vshrq_n_u8(s.0, 4), mask_0f);
                let hi_n0 = vandq_u8(s.1, mask_0f);
                let hi_n1 = vandq_u8(vshrq_n_u8(s.1, 4), mask_0f);

                let p0_lo = vqtbl1q_u8(ts.t[0], lo_n0);
                let p0_hi = vqtbl1q_u8(ts.t[1], lo_n0);
                let p1_lo = vqtbl1q_u8(ts.t[2], lo_n1);
                let p1_hi = vqtbl1q_u8(ts.t[3], lo_n1);
                let p2_lo = vqtbl1q_u8(ts.t[4], hi_n0);
                let p2_hi = vqtbl1q_u8(ts.t[5], hi_n0);
                let p3_lo = vqtbl1q_u8(ts.t[6], hi_n1);
                let p3_hi = vqtbl1q_u8(ts.t[7], hi_n1);

                let result_lo = veorq_u8(veorq_u8(p0_lo, p1_lo), veorq_u8(p2_lo, p3_lo));
                let result_hi = veorq_u8(veorq_u8(p0_hi, p1_hi), veorq_u8(p2_hi, p3_hi));
                d.0 = veorq_u8(d.0, result_lo);
                d.1 = veorq_u8(d.1, result_hi);
            }

            vst2q_u8(dst.as_mut_ptr().add(offset), d);
            offset += 32;
        }

        if offset < len {
            for src in &xor_inputs {
                for (d, s) in dst[offset..].iter_mut().zip(src[offset..].iter()) {
                    *d ^= *s;
                }
            }
            for ts in &table_sets {
                mul_acc_region_scalar(ts.factor, &ts.src[offset..], &mut dst[offset..]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_matches_gf_mul_add() {
        let factor = 0x1234u16;
        let src: Vec<u8> = (0..64).collect();
        let mut dst_scalar = vec![0xABu8; 64];
        let mut dst_reference = dst_scalar.clone();

        // Reference: manual gf::mul + gf::add
        let word_count = src.len() / 2;
        for w in 0..word_count {
            let s = u16::from_le_bytes([src[w * 2], src[w * 2 + 1]]);
            let d = u16::from_le_bytes([dst_reference[w * 2], dst_reference[w * 2 + 1]]);
            let result = gf::add(d, gf::mul(s, factor));
            let bytes = result.to_le_bytes();
            dst_reference[w * 2] = bytes[0];
            dst_reference[w * 2 + 1] = bytes[1];
        }

        mul_acc_region_scalar(factor, &src, &mut dst_scalar);
        assert_eq!(dst_scalar, dst_reference);
    }

    #[test]
    fn mul_acc_region_factor_zero() {
        let src = vec![0xFF; 32];
        let mut dst = vec![0x42; 32];
        let original = dst.clone();
        mul_acc_region(0, &src, &mut dst);
        assert_eq!(dst, original, "factor=0 should be a no-op");
    }

    #[test]
    fn mul_acc_region_factor_one() {
        let src: Vec<u8> = (0..32).collect();
        let mut dst = vec![0; 32];
        mul_acc_region(1, &src, &mut dst);
        assert_eq!(dst, src, "factor=1 should XOR src into dst");
    }

    #[test]
    fn dispatched_matches_scalar_all_factors() {
        // Test a sweep of factor values, at sizes crossing the full-width
        // 64-byte (AVX2/GFNI-AVX2) and 128-byte (AVX-512) blocks; 130 walks
        // every tail width down to scalar.
        for size in [32usize, 64, 130] {
            let src: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            for factor in (0..=0xFFFFu16).step_by(257) {
                let mut dst_dispatched = vec![0xCDu8; size];
                let mut dst_scalar = dst_dispatched.clone();

                mul_acc_region(factor, &src, &mut dst_dispatched);
                if factor == 0 {
                    assert_eq!(dst_dispatched, dst_scalar);
                    continue;
                }
                mul_acc_region_scalar(factor, &src, &mut dst_scalar);
                assert_eq!(
                    dst_dispatched, dst_scalar,
                    "mismatch for factor={factor:#06x} size={size}"
                );
            }
        }
    }

    #[test]
    fn dispatched_matches_scalar_large_buffer() {
        // Test with a buffer large enough to exercise SIMD main loop + tail.
        let factor = 0xBEEFu16;
        let src: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        let mut dst_dispatched = vec![0x55u8; 8192];
        let mut dst_scalar = dst_dispatched.clone();

        mul_acc_region(factor, &src, &mut dst_dispatched);
        mul_acc_region_scalar(factor, &src, &mut dst_scalar);
        assert_eq!(dst_dispatched, dst_scalar);
    }

    #[test]
    fn dispatched_matches_scalar_odd_sizes() {
        // Sizes that aren't multiples of 16 or 32, plus the 64- and 128-byte
        // full-width block boundaries and their straddles.
        let factor = 0x4321u16;
        for size in [2, 4, 6, 14, 18, 30, 34, 50, 62, 64, 66, 126, 128, 130] {
            let src: Vec<u8> = (0..size).map(|i| (i * 7 % 256) as u8).collect();
            let mut dst_dispatched = vec![0xAAu8; size];
            let mut dst_scalar = dst_dispatched.clone();

            mul_acc_region(factor, &src, &mut dst_dispatched);
            mul_acc_region_scalar(factor, &src, &mut dst_scalar);
            assert_eq!(dst_dispatched, dst_scalar, "mismatch for size={size}");
        }
    }

    #[test]
    fn affine_matrices_match_scalar() {
        // Verify the affine matrix precomputation produces correct results
        // by checking against scalar gf::mul for a range of factors.
        for factor in [2u16, 0x1234, 0xABCD, 0xFFFF, 0x8000, 0x0001] {
            let matrices = precompute_affine_matrices(factor);

            // For each possible input byte pair, verify the matrix multiplication
            // matches the scalar result.
            for input in [0u16, 1, 0xFF, 0x100, 0xFFFF, 0x1234, 0x8000, 0x5555] {
                let expected = gf::mul(factor, input);
                let in_lo = (input & 0xFF) as u8;
                let in_hi = (input >> 8) as u8;

                // Simulate gf2p8affineqb: for each output bit j,
                // output[j] = popcount(row_j AND input_byte) mod 2
                // where row_j is byte (7-j) of the matrix u64.
                // The AND operates on matching bit positions.
                let apply_matrix = |matrix: u64, byte: u8| -> u8 {
                    let mut result: u8 = 0;
                    for j in 0..8u32 {
                        let row_byte = (matrix >> ((7 - j) * 8)) as u8;
                        let dot = (row_byte & byte).count_ones() & 1;
                        result |= (dot as u8) << j;
                    }
                    result
                };

                let result_lo =
                    apply_matrix(matrices.m_ll, in_lo) ^ apply_matrix(matrices.m_lh, in_hi);
                let result_hi =
                    apply_matrix(matrices.m_hl, in_lo) ^ apply_matrix(matrices.m_hh, in_hi);
                let result = result_lo as u16 | ((result_hi as u16) << 8);

                assert_eq!(
                    result, expected,
                    "affine matrix mismatch for factor={factor:#06x}, input={input:#06x}: \
                     got {result:#06x}, expected {expected:#06x}"
                );
            }
        }
    }

    #[test]
    fn precomputed_tables_correct() {
        let factor = 0xABCDu16;
        let tables = precompute_mul_tables(factor);

        // Verify a few table entries manually.
        for nibble_val in 0u16..16 {
            let prod0 = gf::mul(factor, nibble_val);
            assert_eq!(tables.tables[0][nibble_val as usize], prod0 as u8);
            assert_eq!(tables.tables[1][nibble_val as usize], (prod0 >> 8) as u8);

            let prod2 = gf::mul(factor, nibble_val << 8);
            assert_eq!(tables.tables[4][nibble_val as usize], prod2 as u8);
            assert_eq!(tables.tables[5][nibble_val as usize], (prod2 >> 8) as u8);
        }
    }

    #[test]
    fn exhaustive_factor_sweep() {
        // Test every factor on a small buffer to ensure SIMD matches scalar.
        // 64 bytes = exactly one full-width AVX2/GFNI-AVX2 block (two
        // full-width NEON/SSSE3 blocks), so every factor exercises the
        // pair-deinterleave main loop of the dispatched kernel.
        let src: Vec<u8> = (0..64).collect();

        for factor in 2..=0xFFFFu16 {
            let mut dst_dispatched = vec![0u8; 64];
            let mut dst_scalar = vec![0u8; 64];

            mul_acc_region(factor, &src, &mut dst_dispatched);
            mul_acc_region_scalar(factor, &src, &mut dst_scalar);
            assert_eq!(
                dst_dispatched, dst_scalar,
                "mismatch for factor={factor:#06x}"
            );
        }
    }

    #[test]
    fn multi_region_matches_single_region() {
        let src: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let factors = [0x1234u16, 0xBEEF, 0x0001, 0x0000, 0xFFFF, 0x8000];

        // Compute reference with single-region calls.
        let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x55u8; 256]).collect();
        for (i, &factor) in factors.iter().enumerate() {
            mul_acc_region(factor, &src, &mut reference[i]);
        }

        // Compute with multi-region.
        let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x55u8; 256]).collect();
        {
            let mut pairs: Vec<FactorDst<'_>> = factors
                .iter()
                .zip(multi.iter_mut())
                .map(|(&factor, dst)| FactorDst {
                    factor,
                    dst: dst.as_mut_slice(),
                })
                .collect();
            mul_acc_multi_region(&mut pairs, &src);
        }

        for (i, &factor) in factors.iter().enumerate() {
            assert_eq!(
                multi[i], reference[i],
                "multi-region mismatch for factor={factor:#06x}"
            );
        }
    }

    #[test]
    fn multi_region_large_buffer() {
        // Test with larger buffer to exercise SIMD main loop + tail.
        let src: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        let factors = [0xABCDu16, 0x1234, 0x5678];

        let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0xAAu8; 8192]).collect();
        for (i, &factor) in factors.iter().enumerate() {
            mul_acc_region(factor, &src, &mut reference[i]);
        }

        let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0xAAu8; 8192]).collect();
        {
            let mut pairs: Vec<FactorDst<'_>> = factors
                .iter()
                .zip(multi.iter_mut())
                .map(|(&factor, dst)| FactorDst {
                    factor,
                    dst: dst.as_mut_slice(),
                })
                .collect();
            mul_acc_multi_region(&mut pairs, &src);
        }

        for (i, &factor) in factors.iter().enumerate() {
            assert_eq!(
                multi[i], reference[i],
                "multi-region large mismatch for factor={factor:#06x}"
            );
        }
    }

    /// Small-batch multi-region oracle: with ≤2 non-trivial factors the
    /// aarch64 dispatcher stays on the VTBL shuffle kernel instead of CLMUL
    /// (the matrix rank-1 path), so this pins that kernel across lengths
    /// straddling its 32-byte block and the 0/1 factor edges.
    #[test]
    fn multi_region_small_batch_matches_scalar() {
        for factors in [
            vec![0x1234u16],
            vec![0x0001, 0xBEEF],
            vec![0x0000, 0x8000, 0x0001],
            vec![0xFFFF, 0x0001, 0x0000, 0x0002],
        ] {
            for &len in &[
                2usize, 16, 30, 32, 34, 62, 64, 66, 126, 128, 130, 4094, 4096,
            ] {
                let src: Vec<u8> = (0..len).map(|i| ((i * 29 + 7) % 253) as u8).collect();

                let mut reference: Vec<Vec<u8>> =
                    factors.iter().map(|_| vec![0x5Au8; len]).collect();
                for (i, &factor) in factors.iter().enumerate() {
                    mul_acc_region_scalar(factor, &src, &mut reference[i]);
                }

                let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x5Au8; len]).collect();
                {
                    let mut pairs: Vec<FactorDst<'_>> = factors
                        .iter()
                        .zip(multi.iter_mut())
                        .map(|(&factor, dst)| FactorDst {
                            factor,
                            dst: dst.as_mut_slice(),
                        })
                        .collect();
                    mul_acc_multi_region(&mut pairs, &src);
                }

                for (i, &factor) in factors.iter().enumerate() {
                    assert_eq!(
                        multi[i], reference[i],
                        "small batch mismatch len={len} factor={factor:#06x}"
                    );
                }
            }
        }
    }

    #[test]
    fn input_batch_matches_repeated_single_region() {
        let factors = [0x0001u16, 0x1234, 0x0000, 0xABCD, 0x8000];
        // Lengths cross the grouped kernels' full-width strips (64-byte
        // GFNI/AVX2, 128-byte AVX-512); 1026 leaves a 2-byte scalar tail.
        for &len in &[62usize, 64, 66, 126, 128, 130, 1026] {
            let inputs: Vec<Vec<u8>> = factors
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    (0..len)
                        .map(|i| ((i * (idx + 3) + 17) % 256) as u8)
                        .collect()
                })
                .collect();

            let mut reference = vec![0x5Au8; len];
            for (factor, input) in factors.iter().zip(inputs.iter()) {
                mul_acc_region(*factor, input, &mut reference);
            }

            let mut batched = vec![0x5Au8; len];
            let factor_srcs: Vec<FactorSrc<'_>> = factors
                .iter()
                .zip(inputs.iter())
                .map(|(&factor, input)| FactorSrc { factor, src: input })
                .collect();
            mul_acc_input_batch(&mut batched, &factor_srcs);

            assert_eq!(batched, reference, "input batch mismatch len={len}");
        }
    }

    #[test]
    fn prepared_input_batch_matches_repeated_single_region() {
        let factors = [0x0001u16, 0x1234, 0x0000, 0xABCD, 0x8000];
        let prepared: Vec<PreparedInputFactor> = factors
            .iter()
            .map(|&factor| prepare_input_factor(factor))
            .collect();
        // Lengths cross the grouped kernels' full-width strips (64-byte
        // GFNI/AVX2, 128-byte AVX-512); 1026 leaves a 2-byte scalar tail.
        for &len in &[62usize, 64, 66, 126, 128, 130, 1026] {
            let inputs: Vec<Vec<u8>> = factors
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    (0..len)
                        .map(|i| ((i * (idx + 5) + 29) % 256) as u8)
                        .collect()
                })
                .collect();

            let mut reference = vec![0x3Cu8; len];
            for (factor, input) in factors.iter().zip(inputs.iter()) {
                mul_acc_region(*factor, input, &mut reference);
            }

            let prepared_srcs: Vec<PreparedFactorSrc<'_>> = prepared
                .iter()
                .zip(inputs.iter())
                .map(|(prepared, input)| PreparedFactorSrc {
                    prepared,
                    src: input,
                })
                .collect();

            let mut batched = vec![0x3Cu8; len];
            mul_acc_input_batch_prepared(&mut batched, &prepared_srcs);

            assert_eq!(
                batched, reference,
                "prepared input batch mismatch len={len}"
            );
        }
    }

    /// Dispatch-level oracle across a batch WIDER than the stream group (8),
    /// so the group-boundary dst reload is exercised on every arch's grouped
    /// kernel (x86 SRC_STREAM_GROUP paths on x86 CI, CLMUL groups here).
    #[test]
    fn input_batch_multi_group_matches_scalar() {
        let count = 19usize; // 2 full groups + tail group on every path
        let factors: Vec<u16> = (0..count)
            .map(|i| match i {
                0 => 0,
                1 => 1,
                _ => (i * 2749 + 3) as u16,
            })
            .collect();
        let prepared: Vec<PreparedInputFactor> =
            factors.iter().map(|&f| prepare_input_factor(f)).collect();
        // Lengths straddle the 128-byte AVX-512 strip; 4094 leaves a
        // 62-byte multi-width tail after the 64-byte strips.
        for &len in &[126usize, 128, 130, 4094] {
            let srcs: Vec<Vec<u8>> = (0..count)
                .map(|i| (0..len).map(|b| ((b * (i + 5) + 31) % 249) as u8).collect())
                .collect();

            let mut reference = vec![0x33u8; len];
            for (&factor, src) in factors.iter().zip(srcs.iter()) {
                mul_acc_region_scalar(factor, src, &mut reference);
            }

            let pairs: Vec<FactorSrc<'_>> = factors
                .iter()
                .zip(srcs.iter())
                .map(|(&factor, src)| FactorSrc {
                    factor,
                    src: src.as_slice(),
                })
                .collect();
            let mut got = vec![0x33u8; len];
            mul_acc_input_batch(&mut got, &pairs);
            assert_eq!(got, reference, "multi-group batch mismatch len={len}");

            // Prepared path over the same wide batch.
            let prepared_pairs: Vec<PreparedFactorSrc<'_>> = prepared
                .iter()
                .zip(srcs.iter())
                .map(|(prepared, src)| PreparedFactorSrc {
                    prepared,
                    src: src.as_slice(),
                })
                .collect();
            let mut got_prepared = vec![0x33u8; len];
            mul_acc_input_batch_prepared(&mut got_prepared, &prepared_pairs);
            assert_eq!(
                got_prepared, reference,
                "multi-group prepared batch mismatch len={len}"
            );
        }
    }

    /// Direct oracle test for the unprepared 512-bit GFNI grouped-input entry
    /// (runs only on GFNI+AVX512 hardware; no-ops elsewhere, including under
    /// Rosetta 2). Lengths cross the full-width 128-byte strip and the
    /// AVX2/scalar tail chain (126/128/130 and 254/256/258 straddles).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn input_batch_gfni_avx512_matches_scalar() {
        if !is_x86_feature_detected!("gfni")
            || !is_x86_feature_detected!("avx512bw")
            || !is_x86_feature_detected!("avx512vl")
        {
            return;
        }
        for &len in &[2usize, 62, 64, 66, 126, 128, 130, 254, 256, 258, 4096, 4094] {
            let factors = [0u16, 1, 2, 0x8000, 0xFFFF, 0x1234, 0x2F1D];
            let srcs: Vec<Vec<u8>> = factors
                .iter()
                .enumerate()
                .map(|(i, _)| (0..len).map(|b| ((b * (i + 3) + 17) % 251) as u8).collect())
                .collect();

            let mut reference = vec![0x6Bu8; len];
            for (&factor, src) in factors.iter().zip(srcs.iter()) {
                mul_acc_region_scalar(factor, src, &mut reference);
            }

            let pairs: Vec<FactorSrc<'_>> = factors
                .iter()
                .zip(srcs.iter())
                .map(|(&factor, src)| FactorSrc {
                    factor,
                    src: src.as_slice(),
                })
                .collect();
            let mut got = vec![0x6Bu8; len];
            unsafe { mul_acc_input_batch_gfni_avx512(&mut got, &pairs) };
            assert_eq!(got, reference, "gfni avx512 batch len={len}");
        }
    }

    /// Direct oracle test for the non-GFNI 512-bit shuffle grouped-input
    /// entry and its prepared twin (runs on any AVX-512BW/VL hardware — GFNI
    /// or not, since the entry forces the Avx2 table flavor; no-ops
    /// elsewhere, including under Rosetta 2). Lengths straddle the 128-byte
    /// block and the AVX2/scalar tail chain; the 19-source case crosses the
    /// SRC_STREAM_GROUP boundary twice.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn input_batch_avx512_matches_scalar() {
        if !is_x86_feature_detected!("avx512bw") || !is_x86_feature_detected!("avx512vl") {
            return;
        }
        for &count in &[7usize, 19] {
            for &len in &[2usize, 62, 64, 66, 126, 128, 130, 4096, 4094] {
                let factors: Vec<u16> = (0..count)
                    .map(|i| match i {
                        0 => 0,
                        1 => 1,
                        2 => 0x8000,
                        3 => 0xFFFF,
                        _ => (i * 2749 + 3) as u16,
                    })
                    .collect();
                let srcs: Vec<Vec<u8>> = (0..count)
                    .map(|i| (0..len).map(|b| ((b * (i + 3) + 17) % 251) as u8).collect())
                    .collect();

                let mut reference = vec![0x6Bu8; len];
                for (&factor, src) in factors.iter().zip(srcs.iter()) {
                    mul_acc_region_scalar(factor, src, &mut reference);
                }

                let pairs: Vec<FactorSrc<'_>> = factors
                    .iter()
                    .zip(srcs.iter())
                    .map(|(&factor, src)| FactorSrc {
                        factor,
                        src: src.as_slice(),
                    })
                    .collect();
                let mut got = vec![0x6Bu8; len];
                unsafe { mul_acc_input_batch_avx512(&mut got, &pairs) };
                assert_eq!(
                    got, reference,
                    "avx512 shuffle batch count={count} len={len}"
                );

                // Prepared path: force the Avx2 table flavor so this also
                // runs (and asserts) on GFNI machines.
                let prepared: Vec<PreparedInputFactor> = factors
                    .iter()
                    .map(|&f| prepare_input_factor_shuffle(f))
                    .collect();
                let prepared_pairs: Vec<PreparedFactorSrc<'_>> = prepared
                    .iter()
                    .zip(srcs.iter())
                    .map(|(prepared, src)| PreparedFactorSrc {
                        prepared,
                        src: src.as_slice(),
                    })
                    .collect();
                let mut got_prepared = vec![0x6Bu8; len];
                unsafe { mul_acc_input_batch_avx512_prepared(&mut got_prepared, &prepared_pairs) };
                assert_eq!(
                    got_prepared, reference,
                    "avx512 shuffle batch prepared count={count} len={len}"
                );
            }
        }
    }

    /// Direct oracle test for both input-batch CLMUL flavors: source counts
    /// straddle the 8-source group (CLMUL_SRC_GROUP) and lengths straddle the
    /// 32-byte block, with factor edge cases (0, 1, 0x8000, 0xFFFF) mixed in.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn input_batch_clmul_kernels_match_scalar() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for &count in &[1usize, 2, 3, 4, 5, 7, 8, 9, 17] {
            for &len in &[2usize, 30, 32, 34, 64, 96, 4094, 4096] {
                let factors: Vec<u16> = (0..count)
                    .map(|i| match i {
                        0 => 1,
                        1 => 0,
                        2 => 0x8000,
                        3 => 0xFFFF,
                        _ => (next() >> 16) as u16,
                    })
                    .collect();
                let inputs: Vec<Vec<u8>> = (0..count)
                    .map(|_| (0..len).map(|_| next() as u8).collect())
                    .collect();
                let srcs: Vec<FactorSrc<'_>> = factors
                    .iter()
                    .zip(inputs.iter())
                    .map(|(&factor, input)| FactorSrc { factor, src: input })
                    .collect();

                let mut reference = vec![0xA7u8; len];
                for (&factor, input) in factors.iter().zip(inputs.iter()) {
                    mul_acc_region_scalar(factor, input, &mut reference);
                }

                let mut plain = vec![0xA7u8; len];
                unsafe { mul_acc_input_batch_clmul(&mut plain, &srcs) };
                assert_eq!(plain, reference, "plain clmul count={count} len={len}");

                if clmul_sha3_available() {
                    let mut sha3 = vec![0xA7u8; len];
                    unsafe { mul_acc_input_batch_clmul_sha3(&mut sha3, &srcs) };
                    assert_eq!(sha3, reference, "sha3 clmul count={count} len={len}");

                    let mut unfused = vec![0xA7u8; len];
                    unsafe { mul_acc_input_batch_clmul_sha3_unfused(&mut unfused, &srcs) };
                    assert_eq!(
                        unfused, reference,
                        "unfused sha3 clmul count={count} len={len}"
                    );
                }
            }
        }
    }

    /// Direct oracle test for the grouped-input VTBL NEON entries, raw and
    /// prepared (dispatch only routes batches of at most 3 sources here, so
    /// the wide dispatch-level tests never reach them). Lengths straddle the
    /// 32-byte full-width strip and its scalar tail; the factor rotation
    /// walks the edge cases (0, 1, 0x8000, 0xFFFF) through every source
    /// position with random factors mixed in.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn input_batch_neon_kernels_match_scalar() {
        let mut state = 0xB5AD_4ECE_DA1C_E2A9u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for &count in &[1usize, 2, 3] {
            for &len in &[2usize, 30, 32, 34, 62, 64, 66, 4094] {
                for round in 0..6usize {
                    let factors: Vec<u16> = (0..count)
                        .map(|i| match (round + i) % 6 {
                            0 => 0,
                            1 => 1,
                            2 => 0x8000,
                            3 => 0xFFFF,
                            _ => (next() >> 16) as u16,
                        })
                        .collect();
                    let inputs: Vec<Vec<u8>> = (0..count)
                        .map(|_| (0..len).map(|_| next() as u8).collect())
                        .collect();

                    let mut reference = vec![0x5Du8; len];
                    for (&factor, input) in factors.iter().zip(inputs.iter()) {
                        mul_acc_region_scalar(factor, input, &mut reference);
                    }

                    let srcs: Vec<FactorSrc<'_>> = factors
                        .iter()
                        .zip(inputs.iter())
                        .map(|(&factor, input)| FactorSrc { factor, src: input })
                        .collect();
                    let mut raw = vec![0x5Du8; len];
                    unsafe { mul_acc_input_batch_neon(&mut raw, &srcs) };
                    assert_eq!(
                        raw, reference,
                        "raw neon batch count={count} len={len} round={round}"
                    );

                    let prepared: Vec<PreparedInputFactor> =
                        factors.iter().map(|&f| prepare_input_factor(f)).collect();
                    let prepared_srcs: Vec<PreparedFactorSrc<'_>> = prepared
                        .iter()
                        .zip(inputs.iter())
                        .map(|(prepared, input)| PreparedFactorSrc {
                            prepared,
                            src: input,
                        })
                        .collect();
                    let mut prep = vec![0x5Du8; len];
                    unsafe { mul_acc_input_batch_neon_prepared(&mut prep, &prepared_srcs) };
                    assert_eq!(
                        prep, reference,
                        "prepared neon batch count={count} len={len} round={round}"
                    );
                }
            }
        }
    }

    #[test]
    fn altmap_roundtrip_and_kernel_match() {
        if !altmap_supported() {
            return;
        }
        // Roundtrip across aligned + tail sizes.
        for len in [0usize, 32, 64, 1024, 1026, 4096, 65536, 21826] {
            let original: Vec<u8> = (0..len).map(|i| (i * 31 % 256) as u8).collect();
            let mut buf = original.clone();
            altmap_encode(&mut buf);
            if len >= 32 {
                assert_ne!(buf, original, "encode must change aligned data (len {len})");
            }
            altmap_decode(&mut buf);
            assert_eq!(buf, original, "roundtrip mismatch at len {len}");
        }

        // The roundtrip above runs on any AVX2 box; the folded-group kernel
        // below is GFNI-only.
        if !folded_uses_gfni() {
            return;
        }

        // Folded-group kernel differential vs the scalar reference, including
        // zero-factor padding lanes and factor==1.
        let factor_sets: [[u16; FOLDED_GROUP]; 3] = [
            [0x0001, 0x1234, 0x0000, 0xABCD, 0x8000, 0x00FF],
            [0x7F7F, 0x0002, 0xFFFF, 0x0001, 0x4321, 0x0000],
            [0x1111, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000],
        ];
        for factors in factor_sets {
            for len in [32usize, 1024, 21824, 65536] {
                let inputs: Vec<Vec<u8>> = factors
                    .iter()
                    .enumerate()
                    .map(|(idx, _)| {
                        (0..len)
                            .map(|i| ((i * (idx + 7) + 13) % 256) as u8)
                            .collect()
                    })
                    .collect();

                let mut reference = vec![0x5Au8; len];
                for (factor, input) in factors.iter().zip(inputs.iter()) {
                    mul_acc_region(*factor, input, &mut reference);
                }

                let mut staging = vec![0u8; len * FOLDED_GROUP];
                for (lane, input) in inputs.iter().enumerate() {
                    split_encode_scatter(input, &mut staging, lane);
                }
                let matrices: Vec<AffineMulMatrices> = factors
                    .iter()
                    .map(|&f| precompute_affine_matrices(f))
                    .collect();
                let matrix_refs: [&AffineMulMatrices; FOLDED_GROUP] = [
                    &matrices[0],
                    &matrices[1],
                    &matrices[2],
                    &matrices[3],
                    &matrices[4],
                    &matrices[5],
                ];

                let mut dst = vec![0x5Au8; len];
                altmap_encode(&mut dst);
                mul_acc_folded_group(&mut dst, &staging, &matrix_refs);
                altmap_decode(&mut dst);

                assert_eq!(dst, reference, "folded kernel mismatch at len {len}");
            }
        }
    }

    #[test]
    fn folded_batch_kernel_match() {
        if !folded_uses_gfni() {
            return;
        }
        // Odd and even group counts cover the fused-pair path, the odd
        // trailing group, and the single-group case; factors mix zero
        // (padding lanes), one, and arbitrary values.
        for groups in [1usize, 2, 3, 5] {
            for len in [32usize, 4096, 21824] {
                let factor_sets: Vec<[u16; FOLDED_GROUP]> = (0..groups)
                    .map(|g| {
                        let mut set = [0u16; FOLDED_GROUP];
                        for (l, slot) in set.iter_mut().enumerate() {
                            *slot = match (g + l) % 5 {
                                0 => 0x0000,
                                1 => 0x0001,
                                _ => (0x2F1Du16)
                                    .wrapping_mul((g * FOLDED_GROUP + l + 1) as u16)
                                    .wrapping_add(0x0101),
                            };
                        }
                        set
                    })
                    .collect();
                let inputs: Vec<Vec<Vec<u8>>> = (0..groups)
                    .map(|g| {
                        (0..FOLDED_GROUP)
                            .map(|l| {
                                (0..len)
                                    .map(|i| ((i * (g * 7 + l + 3) + 29) % 256) as u8)
                                    .collect()
                            })
                            .collect()
                    })
                    .collect();

                let mut reference = vec![0xA5u8; len];
                for (set, group_inputs) in factor_sets.iter().zip(inputs.iter()) {
                    for (&factor, input) in set.iter().zip(group_inputs.iter()) {
                        mul_acc_region(factor, input, &mut reference);
                    }
                }

                let stagings: Vec<Vec<u8>> = inputs
                    .iter()
                    .map(|group_inputs| {
                        let mut staging = vec![0u8; len * FOLDED_GROUP];
                        for (lane, input) in group_inputs.iter().enumerate() {
                            split_encode_scatter(input, &mut staging, lane);
                        }
                        staging
                    })
                    .collect();
                let matrices: Vec<Vec<AffineMulMatrices>> = factor_sets
                    .iter()
                    .map(|set| set.iter().map(|&f| precompute_affine_matrices(f)).collect())
                    .collect();
                let matrix_sets: Vec<[&AffineMulMatrices; FOLDED_GROUP]> = matrices
                    .iter()
                    .map(|group| {
                        [
                            &group[0], &group[1], &group[2], &group[3], &group[4], &group[5],
                        ]
                    })
                    .collect();
                let staging_refs: Vec<&[u8]> = stagings.iter().map(|s| s.as_slice()).collect();

                let mut dst_batch = vec![0xA5u8; len];
                altmap_encode(&mut dst_batch);
                mul_acc_folded_batch(&mut dst_batch, &staging_refs, &matrix_sets);
                altmap_decode(&mut dst_batch);
                assert_eq!(
                    dst_batch, reference,
                    "batch kernel mismatch groups={groups} len={len}"
                );

                // The per-group kernel must agree with whatever width the
                // batch dispatch chose.
                let mut dst_seq = vec![0xA5u8; len];
                altmap_encode(&mut dst_seq);
                for (staging, set) in staging_refs.iter().zip(matrix_sets.iter()) {
                    mul_acc_folded_group(&mut dst_seq, staging, set);
                }
                altmap_decode(&mut dst_seq);
                assert_eq!(
                    dst_seq, reference,
                    "sequential kernel mismatch groups={groups} len={len}"
                );
            }
        }
    }

    #[test]
    fn shuffle2x_batch_kernel_match() {
        // Non-GFNI AVX2 shuffle2x kernel differential vs the scalar reference,
        // over the same split staging the GFNI folded path uses. Runs on any
        // AVX2 box — including GFNI boxes, where it still exercises the
        // shuffle2x fallback kernel end to end.
        if !altmap_supported() {
            return;
        }
        // Odd and even group counts, and factors mixing zero (padding lanes),
        // one (XOR passthrough), and arbitrary values.
        for groups in [1usize, 2, 3, 5] {
            for len in [32usize, 4096, 21824] {
                let factor_sets: Vec<[u16; FOLDED_GROUP]> = (0..groups)
                    .map(|g| {
                        let mut set = [0u16; FOLDED_GROUP];
                        for (l, slot) in set.iter_mut().enumerate() {
                            *slot = match (g + l) % 5 {
                                0 => 0x0000,
                                1 => 0x0001,
                                _ => (0x2F1Du16)
                                    .wrapping_mul((g * FOLDED_GROUP + l + 1) as u16)
                                    .wrapping_add(0x0101),
                            };
                        }
                        set
                    })
                    .collect();
                let inputs: Vec<Vec<Vec<u8>>> = (0..groups)
                    .map(|g| {
                        (0..FOLDED_GROUP)
                            .map(|l| {
                                (0..len)
                                    .map(|i| ((i * (g * 7 + l + 3) + 29) % 256) as u8)
                                    .collect()
                            })
                            .collect()
                    })
                    .collect();

                let mut reference = vec![0xA5u8; len];
                for (set, group_inputs) in factor_sets.iter().zip(inputs.iter()) {
                    for (&factor, input) in set.iter().zip(group_inputs.iter()) {
                        mul_acc_region(factor, input, &mut reference);
                    }
                }

                let stagings: Vec<Vec<u8>> = inputs
                    .iter()
                    .map(|group_inputs| {
                        let mut staging = vec![0u8; len * FOLDED_GROUP];
                        for (lane, input) in group_inputs.iter().enumerate() {
                            split_encode_scatter(input, &mut staging, lane);
                        }
                        staging
                    })
                    .collect();
                let tables: Vec<Vec<Shuffle2xTables>> = factor_sets
                    .iter()
                    .map(|set| {
                        set.iter()
                            .map(|&f| precompute_shuffle2x_tables(f))
                            .collect()
                    })
                    .collect();
                let table_sets: Vec<[&Shuffle2xTables; FOLDED_GROUP]> = tables
                    .iter()
                    .map(|group| {
                        [
                            &group[0], &group[1], &group[2], &group[3], &group[4], &group[5],
                        ]
                    })
                    .collect();
                let staging_refs: Vec<&[u8]> = stagings.iter().map(|s| s.as_slice()).collect();

                let mut dst = vec![0xA5u8; len];
                altmap_encode(&mut dst);
                mul_acc_shuffle2x_batch(&mut dst, &staging_refs, &table_sets);
                altmap_decode(&mut dst);
                assert_eq!(
                    dst, reference,
                    "shuffle2x batch mismatch groups={groups} len={len}"
                );
            }
        }
    }

    /// Test the CLMUL dispatch path specifically (>2 non-zero factors).
    #[test]
    fn multi_region_clmul_path() {
        // 8 factors ensures CLMUL is selected on aarch64 (threshold is >2).
        let src: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let factors = [
            0x1234u16, 0x5678, 0x9ABC, 0xDEF0, 0x1111, 0x2222, 0x3333, 0x4444,
        ];

        let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 4096]).collect();
        for (i, &factor) in factors.iter().enumerate() {
            mul_acc_region(factor, &src, &mut reference[i]);
        }

        let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 4096]).collect();
        {
            let mut pairs: Vec<FactorDst<'_>> = factors
                .iter()
                .zip(multi.iter_mut())
                .map(|(&factor, dst)| FactorDst {
                    factor,
                    dst: dst.as_mut_slice(),
                })
                .collect();
            mul_acc_multi_region(&mut pairs, &src);
        }

        for (i, &factor) in factors.iter().enumerate() {
            assert_eq!(
                multi[i], reference[i],
                "CLMUL path mismatch for factor={factor:#06x}"
            );
        }
    }

    /// Test CLMUL with all possible factor edge cases mixed in.
    #[test]
    fn multi_region_clmul_with_edge_factors() {
        let src: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        // Mix of: zero (skip), one (XOR), normal, and high-bit factors.
        let factors = [0x0000u16, 0x0001, 0xFFFF, 0x8000, 0x0002, 0x7FFF];

        let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x55u8; 256]).collect();
        for (i, &factor) in factors.iter().enumerate() {
            mul_acc_region(factor, &src, &mut reference[i]);
        }

        let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x55u8; 256]).collect();
        {
            let mut pairs: Vec<FactorDst<'_>> = factors
                .iter()
                .zip(multi.iter_mut())
                .map(|(&factor, dst)| FactorDst {
                    factor,
                    dst: dst.as_mut_slice(),
                })
                .collect();
            mul_acc_multi_region(&mut pairs, &src);
        }

        for (i, &factor) in factors.iter().enumerate() {
            assert_eq!(
                multi[i], reference[i],
                "CLMUL edge mismatch for factor={factor:#06x}"
            );
        }
    }

    /// Direct oracle test for both multi-region CLMUL flavors (plain and
    /// EOR3-reduction), across block-tail straddles and 0/1 factor edges.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn multi_region_clmul_flavors_match_scalar() {
        for &len in &[32usize, 94, 4096, 4094] {
            let src: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let factors = [0u16, 1, 2, 0x8000, 0xFFFF, 0x1234];

            let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x5Au8; len]).collect();
            for (i, &factor) in factors.iter().enumerate() {
                mul_acc_region_scalar(factor, &src, &mut reference[i]);
            }

            for sha3 in [false, true] {
                if sha3 && !clmul_sha3_available() {
                    continue;
                }
                let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0x5Au8; len]).collect();
                {
                    let mut pairs: Vec<FactorDst<'_>> = factors
                        .iter()
                        .zip(multi.iter_mut())
                        .map(|(&factor, dst)| FactorDst {
                            factor,
                            dst: dst.as_mut_slice(),
                        })
                        .collect();
                    if sha3 {
                        unsafe { mul_acc_multi_region_clmul_sha3(&mut pairs, &src) };
                    } else {
                        unsafe { mul_acc_multi_region_clmul(&mut pairs, &src) };
                    }
                }
                for (i, &factor) in factors.iter().enumerate() {
                    assert_eq!(
                        multi[i], reference[i],
                        "flavor sha3={sha3} len={len} factor={factor:#06x}"
                    );
                }
            }
        }
    }

    /// Exhaustive factor sweep for the CLMUL multi-region path.
    #[test]
    fn multi_region_clmul_factor_sweep() {
        let src: Vec<u8> = (0..32).collect();

        // Test groups of 4 factors at a time across the full range.
        for base in (2..=0xFFFCu16).step_by(1024) {
            let factors = [base, base + 1, base + 2, base + 3];

            let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 32]).collect();
            for (i, &factor) in factors.iter().enumerate() {
                mul_acc_region(factor, &src, &mut reference[i]);
            }

            let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 32]).collect();
            {
                let mut pairs: Vec<FactorDst<'_>> = factors
                    .iter()
                    .zip(multi.iter_mut())
                    .map(|(&factor, dst)| FactorDst {
                        factor,
                        dst: dst.as_mut_slice(),
                    })
                    .collect();
                mul_acc_multi_region(&mut pairs, &src);
            }

            for (i, &factor) in factors.iter().enumerate() {
                assert_eq!(
                    multi[i], reference[i],
                    "CLMUL sweep mismatch for factor={factor:#06x}"
                );
            }
        }
    }

    /// Verify the SSSE3 kernel in isolation by testing buffer sizes that are
    /// exactly 16 bytes (one SSSE3 iteration) and 16+tail. On x86 with AVX2,
    /// mul_acc_region dispatches to AVX2 which falls through to SSSE3 for
    /// the 16-byte remainder, so we test the SSSE3 path via the tail.
    #[test]
    fn ssse3_tail_matches_scalar() {
        // 48 bytes = one AVX2 iteration (32) + one SSSE3 iteration (16)
        // The SSSE3 path processes the remaining 16 bytes after AVX2.
        for size in [16, 48, 80] {
            for factor in [2u16, 0x1234, 0xABCD, 0xFFFF, 0x8000] {
                let src: Vec<u8> = (0..size).map(|i| (i * 13 % 256) as u8).collect();
                let mut dst_dispatched = vec![0x77u8; size];
                let mut dst_scalar = dst_dispatched.clone();

                mul_acc_region(factor, &src, &mut dst_dispatched);
                mul_acc_region_scalar(factor, &src, &mut dst_scalar);
                assert_eq!(
                    dst_dispatched, dst_scalar,
                    "SSSE3 tail mismatch for factor={factor:#06x}, size={size}"
                );
            }
        }
    }

    /// Large-buffer factor sweep: ensures SIMD main loop + tail handling
    /// is correct across many factors with a buffer large enough to exercise
    /// multiple SIMD iterations. 4094 bytes deliberately misses every block
    /// size, so each factor walks the full delegation chain (e.g. on x86:
    /// 128-byte AVX-512 blocks → one 64-byte AVX2 block → one 32-byte SSSE3
    /// block → scalar words; on aarch64: 32-byte NEON blocks → scalar).
    #[test]
    fn large_buffer_factor_sweep() {
        let src: Vec<u8> = (0..4094).map(|i| (i % 256) as u8).collect();

        for factor in (2..=0xFFFFu16).step_by(127) {
            let mut dst_dispatched = vec![0x33u8; 4094];
            let mut dst_scalar = dst_dispatched.clone();

            mul_acc_region(factor, &src, &mut dst_dispatched);
            mul_acc_region_scalar(factor, &src, &mut dst_scalar);
            assert_eq!(
                dst_dispatched, dst_scalar,
                "large buffer mismatch for factor={factor:#06x}"
            );
        }
    }

    /// Multi-region with many factors and large buffers — exercises the
    /// multi-region SIMD kernel's main loop across all dispatch paths.
    #[test]
    fn multi_region_large_factor_sweep() {
        let src: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

        for base in (2..=0xFFF0u16).step_by(4096) {
            let factors = [base, base + 1, base + 2, base + 3, base + 4, base + 5];

            let mut reference: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 4096]).collect();
            for (i, &factor) in factors.iter().enumerate() {
                mul_acc_region(factor, &src, &mut reference[i]);
            }

            let mut multi: Vec<Vec<u8>> = factors.iter().map(|_| vec![0u8; 4096]).collect();
            {
                let mut pairs: Vec<FactorDst<'_>> = factors
                    .iter()
                    .zip(multi.iter_mut())
                    .map(|(&factor, dst)| FactorDst {
                        factor,
                        dst: dst.as_mut_slice(),
                    })
                    .collect();
                mul_acc_multi_region(&mut pairs, &src);
            }

            for (i, &factor) in factors.iter().enumerate() {
                assert_eq!(
                    multi[i], reference[i],
                    "multi-region large sweep mismatch for factor={factor:#06x}"
                );
            }
        }
    }

    /// Verify dispatch with non-power-of-2 buffer sizes that stress tail
    /// handling across all SIMD widths (scalar remainder after 128/64/32-byte
    /// SIMD blocks).
    #[test]
    fn non_aligned_sizes_stress() {
        let factor = 0xCAFEu16;
        // Sizes straddling every kernel's block size (NEON/SSSE3 32, AVX2 64,
        // AVX-512 128) plus in-between remainders: 30/32/34 cross the 32-byte
        // block, 62/64/66 the 64-byte block, 126/128/130 the 128-byte block,
        // and 94/96/158/194/226/258 leave mixed multi-width tails.
        for size in [
            2, 6, 10, 14, 18, 22, 30, 32, 34, 46, 50, 62, 64, 66, 94, 96, 98, 126, 128, 130, 158,
            194, 226, 258,
        ] {
            let src: Vec<u8> = (0..size).map(|i| ((i * 31) % 256) as u8).collect();
            let mut dst_dispatched = vec![0xBBu8; size];
            let mut dst_scalar = dst_dispatched.clone();

            mul_acc_region(factor, &src, &mut dst_dispatched);
            mul_acc_region_scalar(factor, &src, &mut dst_scalar);
            assert_eq!(
                dst_dispatched, dst_scalar,
                "non-aligned size mismatch for size={size}"
            );
        }
    }
}
