//! Arithmetic in the binary Galois fields PAR3 computes recovery data in.
//!
//! A PAR3 set names its field in the Start packet: an element size in bytes and
//! a generator polynomial with its leading term removed. The reference
//! implementation writes only two of them — GF(2^8) with `0x11D` and GF(2^16)
//! with `0x1100B` — and this module implements exactly those two shapes, as
//! [`Gf8`] and [`Gf16`], behind the [`Field`] trait so that the codec in
//! [`crate::cauchy`] can be written once.
//!
//! ```
//! use par3_rs::gf::{Field, Gf8};
//!
//! # fn main() -> par3_rs::Result<()> {
//! let field = Gf8::new(0x11d)?;
//! assert_eq!(field.mul(2, 0x80), 0x1d);
//! assert_eq!(field.inv(0), None);
//!
//! let mut sum = vec![0u8; 4];
//! field.mul_acc(&mut sum, &[1, 2, 3, 4], 3);
//! assert_eq!(sum, [3, 6, 5, 12]);
//! # Ok(())
//! # }
//! ```
//!
//! # How the tables work
//!
//! Both fields are built the way the reference implementation builds them: the
//! element `2` is taken as a generator of the multiplicative group, and a
//! discrete-logarithm table plus its inverse turn a multiplication into two
//! lookups and an addition. That only works when `2` really does generate the
//! group, so [`Field::new`] rejects a polynomial under which it does not — see
//! [`Gf8::new`].
//!
//! # Byte layout
//!
//! GF(2^8) symbols are bytes. GF(2^16) symbols are **little-endian 16-bit
//! words**, because the reference implementation reads its block buffers through
//! a `uint16_t *` on little-endian hosts. A GF(2^16) region is therefore always
//! an even number of bytes.

use crate::error::{Par3Error, Result};
use crate::packet::GaloisField;

/// One of the binary Galois fields a PAR3 set can declare.
///
/// Addition is exclusive-or, so it never fails; multiplication and inversion go
/// through the tables an implementation builds in [`Field::new`]. The region
/// operations [`mul_acc`](Field::mul_acc) and [`mul_into`](Field::mul_into) are
/// where a codec spends its time, and each is free to build whatever per-call
/// table makes that fast.
pub trait Field: Clone {
    /// One field element: `u8` for GF(2^8), `u16` for GF(2^16).
    ///
    /// [`Default::default`] is the zero element.
    type Symbol: Copy + Eq + Default;

    /// Bytes one symbol occupies in a block.
    const SYMBOL_BYTES: usize;

    /// The largest value in the field, which is also the order of its
    /// multiplicative group: 255 or 65535. The Cauchy construction subtracts a
    /// recovery block index from it.
    const MAX: u64;

    /// Build the field for a generator polynomial, with its leading term
    /// present — `0x11D`, not the `0x1D` a Start packet stores.
    fn new(generator: u32) -> Result<Self>;

    /// The generator polynomial this field was built with, leading term and all.
    fn generator(&self) -> u32;

    /// The multiplicative identity.
    fn one(&self) -> Self::Symbol;

    /// Field addition, which in a binary field is exclusive-or.
    fn add(&self, a: Self::Symbol, b: Self::Symbol) -> Self::Symbol;

    /// Field multiplication.
    fn mul(&self, a: Self::Symbol, b: Self::Symbol) -> Self::Symbol;

    /// The multiplicative inverse, or `None` for zero.
    fn inv(&self, a: Self::Symbol) -> Option<Self::Symbol>;

    /// The symbol with this value, or `None` when the field cannot hold it.
    fn symbol(value: u64) -> Option<Self::Symbol>;

    /// `dst[i] ^= factor * src[i]`, over little-endian symbols.
    ///
    /// # Panics
    ///
    /// When `dst.len() != src.len()`, or when that length is not a whole number
    /// of [`SYMBOL_BYTES`](Field::SYMBOL_BYTES). Both are caller mistakes rather
    /// than damaged data: the codec sizes every buffer from the block size it
    /// validated when it was built, so it cannot reach either.
    fn mul_acc(&self, dst: &mut [u8], src: &[u8], factor: Self::Symbol);

    /// `dst[i] = factor * src[i]`, over little-endian symbols.
    ///
    /// # Panics
    ///
    /// Under the same conditions as [`mul_acc`](Field::mul_acc).
    fn mul_into(&self, dst: &mut [u8], src: &[u8], factor: Self::Symbol);
}

/// Check the shape of a region pair before either region operation touches it.
fn check_regions(dst: &[u8], src: &[u8], symbol_bytes: usize) {
    assert_eq!(
        dst.len(),
        src.len(),
        "a Galois-field region multiply needs equal-length regions"
    );
    assert!(
        dst.len().is_multiple_of(symbol_bytes),
        "a region of {} bytes is not a whole number of {symbol_bytes}-byte symbols",
        dst.len()
    );
}

/// Build the logarithm and antilogarithm tables for GF(2^`width`).
///
/// Returns `(log, exp)`, where `log[v]` is the power of two that equals `v` and
/// `exp[j]` is two to the power `j`. The antilogarithm table is written out
/// twice so that `exp[log[a] + log[b]]` needs no modular reduction.
///
/// The polynomial must have degree exactly `width` and must be *primitive*: the
/// powers of two have to run through every non-zero element before returning to
/// one. A merely irreducible polynomial is not enough — GF(2^8) with `0x11B`,
/// the AES field, is irreducible, but two has order 51 there, so a log table
/// built on it would leave four fifths of the field unreachable.
fn build_tables(generator: u32, width: u32) -> Result<(Vec<u32>, Vec<u32>)> {
    let order = 1u32 << width;
    let max = order - 1;
    if generator >> width != 1 {
        return Err(Par3Error::UnsupportedField {
            reason: format!(
                "generator polynomial {generator:#x} does not have degree {width}; \
                 it must lie between {order:#x} and {:#x}",
                order * 2 - 1
            ),
        });
    }

    let mut log = vec![0u32; order as usize];
    let mut exp = vec![0u32; 2 * max as usize];
    let mut value = 1u32;
    for power in 0..max {
        if power > 0 && value == 1 {
            return Err(Par3Error::UnsupportedField {
                reason: format!(
                    "generator polynomial {generator:#x} is not primitive: \
                     the powers of two return to one after {power} steps, not {max}"
                ),
            });
        }
        if value == 0 {
            return Err(Par3Error::UnsupportedField {
                reason: format!(
                    "generator polynomial {generator:#x} is not primitive: \
                     the powers of two reach zero after {power} steps"
                ),
            });
        }
        log[value as usize] = power;
        exp[power as usize] = value;
        value <<= 1;
        if value & order != 0 {
            value ^= generator;
        }
    }
    if value != 1 {
        return Err(Par3Error::UnsupportedField {
            reason: format!(
                "generator polynomial {generator:#x} is not primitive: \
                 two to the power {max} is {value}, not one"
            ),
        });
    }
    // A cycle of the right length still need not have visited every element if
    // the polynomial is reducible, so confirm the two tables really do invert
    // each other before anything relies on them.
    for v in 1..order {
        if exp[log[v as usize] as usize] != v {
            return Err(Par3Error::UnsupportedField {
                reason: format!(
                    "generator polynomial {generator:#x} is not primitive: \
                     the powers of two never reach {v:#x}"
                ),
            });
        }
    }
    let (low, high) = exp.split_at_mut(max as usize);
    high.copy_from_slice(low);
    Ok((log, exp))
}

/// GF(2^8): one byte per symbol.
///
/// The reference implementation uses this field when a set has 128 input blocks
/// or fewer and its input and recovery blocks together fit in 256; see
/// [`crate::cauchy::default_field`].
///
/// Its tables are under a kilobyte but still live on the heap, so that this type
/// and [`Gf16`] cost the same to move and [`AnyField`] is small either way.
#[derive(Debug, Clone)]
pub struct Gf8 {
    generator: u32,
    /// `log[v]` for every non-zero `v`; `log[0]` is never read.
    log: Box<[u8]>,
    /// Powers of two, written out twice so sums of logarithms need no reduction;
    /// 510 entries.
    exp: Box<[u8]>,
}

impl Gf8 {
    /// The generator polynomial the reference implementation uses, `0x11D`.
    pub const DEFAULT_GENERATOR: u32 = 0x11d;

    /// Regions at least this long are worth a 256-entry multiplication row.
    ///
    /// Below it the row costs more to build than the multiplications it saves,
    /// so short regions go through the logarithm tables instead.
    const TABLE_THRESHOLD: usize = 256;

    /// Build GF(2^8) for a generator polynomial with its leading term present.
    ///
    /// The polynomial must have degree 8 — that is, lie in `0x100..=0x1ff` — and
    /// must be primitive. `0x11B`, the AES field polynomial, is irreducible but
    /// not primitive, and is refused: the element two has order 51 under it, so
    /// its powers reach only 51 of the 255 non-zero elements.
    pub fn new(generator: u32) -> Result<Self> {
        Self::build(generator)
    }

    fn build(generator: u32) -> Result<Self> {
        let (log, exp) = build_tables(generator, 8)?;
        Ok(Self {
            generator,
            log: log.into_iter().map(|value| value as u8).collect(),
            exp: exp.into_iter().map(|value| value as u8).collect(),
        })
    }

    /// The row `factor * v` for every `v`, for a region multiply.
    fn row(&self, factor: u8) -> [u8; 256] {
        let mut row = [0u8; 256];
        let base = usize::from(self.log[usize::from(factor)]);
        for (value, slot) in row.iter_mut().enumerate().skip(1) {
            *slot = self.exp[base + usize::from(self.log[value])];
        }
        row
    }
}

impl Default for Gf8 {
    /// GF(2^8) with `0x11D`, the field the reference implementation writes.
    fn default() -> Self {
        Self::new(Self::DEFAULT_GENERATOR).expect("0x11d is primitive")
    }
}

impl Field for Gf8 {
    type Symbol = u8;
    const SYMBOL_BYTES: usize = 1;
    const MAX: u64 = 255;

    fn new(generator: u32) -> Result<Self> {
        Self::build(generator)
    }

    fn generator(&self) -> u32 {
        self.generator
    }

    fn one(&self) -> u8 {
        1
    }

    fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)])]
    }

    fn inv(&self, a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        Some(self.exp[255 - usize::from(self.log[usize::from(a)])])
    }

    fn symbol(value: u64) -> Option<u8> {
        u8::try_from(value).ok()
    }

    fn mul_acc(&self, dst: &mut [u8], src: &[u8], factor: u8) {
        check_regions(dst, src, 1);
        if self.generator == Self::DEFAULT_GENERATOR && dst.len() >= 128 {
            reedsolomon_rs::gf8::mul_acc_region(factor, src, dst);
            return;
        }
        match factor {
            0 => {}
            1 => {
                for (d, s) in dst.iter_mut().zip(src) {
                    *d ^= *s;
                }
            }
            _ if dst.len() >= Self::TABLE_THRESHOLD => {
                let row = self.row(factor);
                for (d, s) in dst.iter_mut().zip(src) {
                    *d ^= row[usize::from(*s)];
                }
            }
            _ => {
                for (d, s) in dst.iter_mut().zip(src) {
                    *d ^= self.mul(factor, *s);
                }
            }
        }
    }

    fn mul_into(&self, dst: &mut [u8], src: &[u8], factor: u8) {
        check_regions(dst, src, 1);
        match factor {
            0 => dst.fill(0),
            1 => dst.copy_from_slice(src),
            _ if dst.len() >= Self::TABLE_THRESHOLD => {
                let row = self.row(factor);
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = row[usize::from(*s)];
                }
            }
            _ => {
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = self.mul(factor, *s);
                }
            }
        }
    }
}

/// GF(2^16): two bytes per symbol, little-endian.
///
/// The tables are 256 KiB, so this type is deliberately not `Copy`: build one
/// per set and pass it by reference or move it into the codec.
#[derive(Debug, Clone)]
pub struct Gf16 {
    generator: u32,
    /// `log[v]` for every non-zero `v`; 65536 entries.
    log: Box<[u16]>,
    /// Powers of two, written out twice; 131070 entries.
    exp: Box<[u16]>,
}

impl Gf16 {
    /// The generator polynomial the reference implementation uses, `0x1100B`.
    pub const DEFAULT_GENERATOR: u32 = 0x1_100b;

    /// Regions of at least this many bytes are worth a pair of split tables.
    ///
    /// The two tables cost 512 multiplications to build, so they only pay for
    /// themselves once a region holds a few hundred symbols. The reference
    /// implementation draws the same line at a thousand symbols.
    const TABLE_THRESHOLD: usize = 2000;

    /// Build GF(2^16) for a generator polynomial with its leading term present.
    ///
    /// The polynomial must have degree 16 — that is, lie in `0x10000..=0x1ffff`
    /// — and must be primitive, in the sense [`Gf8::new`] describes.
    pub fn new(generator: u32) -> Result<Self> {
        Self::build(generator)
    }

    fn build(generator: u32) -> Result<Self> {
        let (log, exp) = build_tables(generator, 16)?;
        Ok(Self {
            generator,
            log: log.into_iter().map(|value| value as u16).collect(),
            exp: exp.into_iter().map(|value| value as u16).collect(),
        })
    }

    /// The two 256-entry tables that split a symbol into its low and high byte.
    ///
    /// Multiplication is linear over GF(2), so `factor * v` is
    /// `factor * (v & 0xff)` exclusive-or `factor * (v & 0xff00)`, and each half
    /// is one lookup.
    fn split_tables(&self, factor: u16) -> ([u16; 256], [u16; 256]) {
        let mut low = [0u16; 256];
        let mut high = [0u16; 256];
        for value in 1..256u16 {
            low[usize::from(value)] = self.mul(factor, value);
            high[usize::from(value)] = self.mul(factor, value << 8);
        }
        (low, high)
    }
}

impl Default for Gf16 {
    /// GF(2^16) with `0x1100B`, the field the reference implementation writes.
    fn default() -> Self {
        Self::new(Self::DEFAULT_GENERATOR).expect("0x1100b is primitive")
    }
}

/// Read one little-endian symbol out of a two-byte slice.
fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// Write one little-endian symbol into a two-byte slice.
fn put_word(bytes: &mut [u8], value: u16) {
    let stored = value.to_le_bytes();
    bytes[0] = stored[0];
    bytes[1] = stored[1];
}

impl Field for Gf16 {
    type Symbol = u16;
    const SYMBOL_BYTES: usize = 2;
    const MAX: u64 = 65535;

    fn new(generator: u32) -> Result<Self> {
        Self::build(generator)
    }

    fn generator(&self) -> u32 {
        self.generator
    }

    fn one(&self) -> u16 {
        1
    }

    fn add(&self, a: u16, b: u16) -> u16 {
        a ^ b
    }

    fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)])]
    }

    fn inv(&self, a: u16) -> Option<u16> {
        if a == 0 {
            return None;
        }
        Some(self.exp[65535 - usize::from(self.log[usize::from(a)])])
    }

    fn symbol(value: u64) -> Option<u16> {
        u16::try_from(value).ok()
    }

    fn mul_acc(&self, dst: &mut [u8], src: &[u8], factor: u16) {
        check_regions(dst, src, 2);
        if self.generator == Self::DEFAULT_GENERATOR {
            reedsolomon_rs::gf_simd::mul_acc_region(factor, src, dst);
            return;
        }
        match factor {
            0 => {}
            1 => {
                for (d, s) in dst.iter_mut().zip(src) {
                    *d ^= *s;
                }
            }
            _ if dst.len() >= Self::TABLE_THRESHOLD => {
                let (low, high) = self.split_tables(factor);
                for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                    let value = word(s);
                    if value != 0 {
                        let product =
                            high[usize::from(value >> 8)] ^ low[usize::from(value & 0xff)];
                        put_word(d, word(d) ^ product);
                    }
                }
            }
            _ => {
                for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                    let product = self.mul(factor, word(s));
                    put_word(d, word(d) ^ product);
                }
            }
        }
    }

    fn mul_into(&self, dst: &mut [u8], src: &[u8], factor: u16) {
        check_regions(dst, src, 2);
        match factor {
            0 => dst.fill(0),
            1 => dst.copy_from_slice(src),
            _ if dst.len() >= Self::TABLE_THRESHOLD => {
                let (low, high) = self.split_tables(factor);
                for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                    let value = word(s);
                    let product = if value == 0 {
                        0
                    } else {
                        high[usize::from(value >> 8)] ^ low[usize::from(value & 0xff)]
                    };
                    put_word(d, product);
                }
            }
            _ => {
                for (d, s) in dst.chunks_exact_mut(2).zip(src.chunks_exact(2)) {
                    put_word(d, self.mul(factor, word(s)));
                }
            }
        }
    }
}

/// Most source regions one grouped multiply-accumulate folds into its
/// destination at once: the widest pass the GF(2^16) grouped-input kernels
/// make, and the deepest group of source stripes a codec stages for one.
pub(crate) const BATCH_SOURCES: usize = 16;

/// Several sources folded into one destination by one call, so a codec that
/// holds a group of source stripes walks each destination once per group
/// instead of once per source. Addition is exclusive-or, so the bytes are the
/// ones a [`Field::mul_acc`] per source would leave, in any order.
pub(crate) trait MulAccBatch: Field {
    /// `dst[i] ^= factors[k] * sources[k][i]` for every `k`.
    ///
    /// # Panics
    ///
    /// When `sources` and `factors` differ in length, or under the conditions
    /// [`Field::mul_acc`] panics for any one source.
    fn mul_acc_batch(&self, dst: &mut [u8], sources: &[&[u8]], factors: &[Self::Symbol]);
}

impl MulAccBatch for Gf8 {
    fn mul_acc_batch(&self, dst: &mut [u8], sources: &[&[u8]], factors: &[u8]) {
        assert_eq!(sources.len(), factors.len(), "one factor per source");
        if sources.len() < 2 || self.generator != Self::DEFAULT_GENERATOR || dst.len() < 128 {
            for (src, factor) in sources.iter().zip(factors) {
                self.mul_acc(dst, src, *factor);
            }
            return;
        }
        for src in sources {
            check_regions(dst, src, 1);
        }
        use reedsolomon_rs::gf8::{MulPlan, PlanSrc, mul_acc_input_batch};
        let grouped = reedsolomon_rs::gf8::input_batch_width() >= 2;
        for (sources, factors) in sources
            .chunks(BATCH_SOURCES)
            .zip(factors.chunks(BATCH_SOURCES))
        {
            // A plan per source on the stack; the slots past a short chunk
            // repeat its last plan and are never visited.
            let last = sources.len() - 1;
            let plans: [MulPlan; BATCH_SOURCES] =
                std::array::from_fn(|k| MulPlan::new(factors[k.min(last)]));
            if grouped {
                let inputs: [PlanSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|k| PlanSrc {
                    plan: &plans[k.min(last)],
                    src: sources[k.min(last)],
                });
                mul_acc_input_batch(dst, &inputs[..sources.len()]);
                continue;
            }
            // No grouped kernel: fold the chunk one tile of the destination
            // at a time, so the tile stays in L1 while each source's
            // matching slice streams past it once.
            const TILE: usize = 8 << 10;
            for (tile, at) in dst.chunks_mut(TILE).zip((0..).step_by(TILE)) {
                for (plan, src) in plans.iter().zip(sources) {
                    plan.accumulate(&src[at..at + tile.len()], tile);
                }
            }
        }
    }
}

impl MulAccBatch for Gf16 {
    fn mul_acc_batch(&self, dst: &mut [u8], sources: &[&[u8]], factors: &[u16]) {
        assert_eq!(sources.len(), factors.len(), "one factor per source");
        // An unoptimised aarch64 build lays every temporary of the inlined
        // CLMUL batch kernel out in one frame, measured past the 256 KiB a pool
        // worker's stack holds (an optimised one fits in 16 KiB, and the x86
        // kernels fit in 256 KiB unoptimised), so it folds source by source
        // instead. The gate is the optimisation level, not debug assertions: a
        // profile can switch those off at opt-level 0. Where the field's
        // grouped kernel is slower than its single-source one (AVX-512 without
        // GFNI, AVX2 without GFNI: 0.70× and 0.9× at one worker), the width is
        // 1 and the sources also fold one at a time. The bytes are the same
        // either way.
        if sources.len() < 2
            || self.generator != Self::DEFAULT_GENERATOR
            || cfg!(all(par3_unoptimized, target_arch = "aarch64"))
            || reedsolomon_rs::gf_simd::input_batch_width() < 2
        {
            for (src, factor) in sources.iter().zip(factors) {
                self.mul_acc(dst, src, *factor);
            }
            return;
        }
        self.mul_acc_grouped(dst, sources, factors);
    }
}

impl Gf16 {
    /// [`MulAccBatch::mul_acc_batch`] through the grouped-input kernels, for
    /// the default polynomial they are built for.
    fn mul_acc_grouped(&self, dst: &mut [u8], sources: &[&[u8]], factors: &[u16]) {
        debug_assert_eq!(self.generator, Self::DEFAULT_GENERATOR);
        for src in sources {
            check_regions(dst, src, 2);
        }
        use reedsolomon_rs::gf_simd::{FactorSrc, mul_acc_input_batch};
        for (sources, factors) in sources
            .chunks(BATCH_SOURCES)
            .zip(factors.chunks(BATCH_SOURCES))
        {
            // Slots past the group repeat its last pair and are never passed.
            let last = sources.len() - 1;
            let pairs: [FactorSrc<'_>; BATCH_SOURCES] = std::array::from_fn(|k| FactorSrc {
                factor: factors[k.min(last)],
                src: sources[k.min(last)],
            });
            mul_acc_input_batch(dst, &pairs[..sources.len()]);
        }
    }
}

/// Either of the two fields, so that a caller can pick one from a Start packet
/// and dispatch on it once instead of at every multiplication.
#[derive(Debug, Clone)]
pub enum AnyField {
    /// GF(2^8).
    Gf8(Gf8),
    /// GF(2^16).
    Gf16(Gf16),
}

impl AnyField {
    /// Bytes one symbol occupies in a block.
    #[must_use]
    pub fn symbol_bytes(&self) -> usize {
        match self {
            Self::Gf8(_) => Gf8::SYMBOL_BYTES,
            Self::Gf16(_) => Gf16::SYMBOL_BYTES,
        }
    }

    /// The largest value in the field.
    #[must_use]
    pub fn max(&self) -> u64 {
        match self {
            Self::Gf8(_) => Gf8::MAX,
            Self::Gf16(_) => Gf16::MAX,
        }
    }

    /// The generator polynomial, with its leading term present.
    #[must_use]
    pub fn generator(&self) -> u32 {
        match self {
            Self::Gf8(field) => field.generator(),
            Self::Gf16(field) => field.generator(),
        }
    }
}

/// Peak heap bytes building one field's lookup tables costs.
///
/// Both fields are built the same way: [`build_tables`] fills a pair of `u32`
/// working tables sized by the field order, and each is then narrowed into a
/// boxed table of symbols. A working table's buffer is released only once the
/// table narrowed from it is finished, so the peak holds both working tables
/// and one narrowed table at the same time. Charging the retained tables alone
/// understates a GF(2^16) field by more than half a megabyte.
const fn construction_bytes(width: u32, symbol: usize) -> usize {
    let order = 1usize << width;
    let log_words = order * size_of::<u32>();
    let exp_words = 2 * (order - 1) * size_of::<u32>();
    let log_symbols = order * symbol;
    let exp_symbols = 2 * (order - 1) * symbol;
    // Narrowing `log` first, then `exp`.
    let first = log_words + exp_words + log_symbols;
    let second = exp_words + log_symbols + exp_symbols;
    if first > second { first } else { second }
}

impl Gf8 {
    /// Peak bytes [`Gf8::new`] allocates, tables and setup together.
    pub(crate) const CONSTRUCTION_BYTES: usize = construction_bytes(8, 1) + size_of::<Self>();

    /// Bytes this field's retained tables hold.
    #[cfg(test)]
    pub(crate) fn retained_table_bytes(&self) -> usize {
        size_of::<Self>() + self.log.len() + self.exp.len()
    }
}

impl Gf16 {
    /// Peak bytes [`Gf16::new`] allocates, tables and setup together.
    pub(crate) const CONSTRUCTION_BYTES: usize = construction_bytes(16, 2) + size_of::<Self>();

    /// Bytes this field's retained tables hold.
    #[cfg(test)]
    pub(crate) fn retained_table_bytes(&self) -> usize {
        size_of::<Self>() + (self.log.len() + self.exp.len()) * size_of::<u16>()
    }
}

/// Peak bytes constructing the field a set declares will cost.
///
/// A declared field this crate has no codec for still has to be admitted before
/// [`for_set`] can refuse it, so the widest supported field is quoted.
#[must_use]
pub(crate) fn construction_cost(field: &GaloisField) -> usize {
    match field.size {
        1 => Gf8::CONSTRUCTION_BYTES,
        _ => Gf16::CONSTRUCTION_BYTES,
    }
}

/// Build the field a set's Start packet declares.
///
/// Only the one- and two-byte fields have a codec here. A set that declares no
/// field at all — the reference implementation writes that when recovery data is
/// a plain exclusive-or sum — or one of the larger sizes the format reserves is
/// refused rather than approximated.
pub fn for_set(field: &GaloisField) -> Result<AnyField> {
    let polynomial = field
        .polynomial()
        .and_then(|value| u32::try_from(value).ok());
    match (field.size, polynomial) {
        (1, Some(polynomial)) => Ok(AnyField::Gf8(Gf8::new(polynomial)?)),
        (2, Some(polynomial)) => Ok(AnyField::Gf16(Gf16::new(polynomial)?)),
        (size, _) => Err(Par3Error::UnsupportedField {
            reason: format!("no codec for a Galois field of {size} bytes"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Carry-less multiplication reduced modulo the polynomial, written the
    /// slowest and most obvious way there is, as the standard the tables are
    /// checked against.
    fn schoolbook(polynomial: u32, width: u32, a: u32, b: u32) -> u32 {
        let overflow = 1u32 << width;
        let (mut shifted, mut remaining, mut product) = (a, b, 0u32);
        while remaining != 0 {
            if remaining & 1 != 0 {
                product ^= shifted;
            }
            remaining >>= 1;
            shifted <<= 1;
            if shifted & overflow != 0 {
                shifted ^= polynomial;
            }
        }
        product
    }

    /// A tiny xorshift, so the random tests need no dependency and repeat
    /// exactly on every run.
    struct Rng(u64);

    impl Rng {
        fn step(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.step() % bound
        }
    }

    #[test]
    fn the_default_fields_are_the_ones_the_reference_writes() {
        assert_eq!(Gf8::default().generator(), 0x11d);
        assert_eq!(Gf16::default().generator(), 0x1_100b);
        assert_eq!(Gf8::MAX, 255);
        assert_eq!(Gf16::MAX, 65535);
    }

    #[test]
    fn doubling_the_top_element_folds_in_the_polynomial() {
        assert_eq!(Gf8::default().mul(2, 0x80), 0x1d);
        assert_eq!(Gf16::default().mul(2, 0x8000), 0x100b);
    }

    #[test]
    fn gf8_multiplication_agrees_with_a_schoolbook_multiply() {
        let field = Gf8::default();
        let mut rng = Rng(0x2026_0905_0000_0001);
        for _ in 0..4000 {
            let a = rng.below(256) as u8;
            let b = rng.below(256) as u8;
            assert_eq!(
                u32::from(field.mul(a, b)),
                schoolbook(0x11d, 8, u32::from(a), u32::from(b)),
                "{a:#x} * {b:#x}"
            );
        }
        for value in 0..=255u8 {
            assert_eq!(field.mul(value, 1), value);
            assert_eq!(field.mul(1, value), value);
            assert_eq!(field.mul(value, 0), 0);
            assert_eq!(field.mul(0, value), 0);
        }
    }

    #[test]
    fn gf16_multiplication_agrees_with_a_schoolbook_multiply() {
        let field = Gf16::default();
        let mut rng = Rng(0x2026_0905_0000_0002);
        for _ in 0..4000 {
            let a = rng.below(65536) as u16;
            let b = rng.below(65536) as u16;
            assert_eq!(
                u32::from(field.mul(a, b)),
                schoolbook(0x1_100b, 16, u32::from(a), u32::from(b)),
                "{a:#x} * {b:#x}"
            );
        }
        for value in [0u16, 1, 2, 0x5a5a, 0xffff] {
            assert_eq!(field.mul(value, 1), value);
            assert_eq!(field.mul(value, 0), 0);
        }
    }

    #[test]
    fn every_non_zero_gf8_element_has_an_inverse() {
        let field = Gf8::default();
        assert_eq!(field.inv(0), None);
        for value in 1..=255u8 {
            let inverse = field.inv(value).expect("a non-zero element is invertible");
            assert_eq!(field.mul(value, inverse), 1, "1 / {value:#x}");
        }
    }

    #[test]
    fn every_non_zero_gf16_element_has_an_inverse() {
        let field = Gf16::default();
        assert_eq!(field.inv(0), None);
        for value in 1..=65535u16 {
            let inverse = field.inv(value).expect("a non-zero element is invertible");
            assert_eq!(field.mul(value, inverse), 1, "1 / {value:#x}");
        }
    }

    /// Multiply a region one symbol at a time, as the standard the region
    /// operations are checked against.
    fn scalar_region<F: Field>(
        field: &F,
        src: &[u8],
        factor: F::Symbol,
        accumulate: &[u8],
    ) -> Vec<u8>
    where
        F::Symbol: Into<u64>,
    {
        let mut out = accumulate.to_vec();
        for (index, chunk) in src.chunks_exact(F::SYMBOL_BYTES).enumerate() {
            let mut value = 0u64;
            for (step, byte) in chunk.iter().enumerate() {
                value |= u64::from(*byte) << (8 * step);
            }
            let symbol = F::symbol(value).expect("a symbol of the field's own width");
            let product: u64 = field.mul(factor, symbol).into();
            let at = index * F::SYMBOL_BYTES;
            for step in 0..F::SYMBOL_BYTES {
                out[at + step] ^= ((product >> (8 * step)) & 0xff) as u8;
            }
        }
        out
    }

    fn random_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
        (0..len).map(|_| rng.below(256) as u8).collect()
    }

    #[test]
    fn gf8_region_operations_agree_with_a_symbol_loop() {
        let field = Gf8::default();
        let mut rng = Rng(0x2026_0905_0000_0003);
        // One symbol, just under and just over the table threshold, and a long
        // odd length.
        for len in [1usize, 3, 255, 256, 257, 4097] {
            let src = random_bytes(&mut rng, len);
            let start = random_bytes(&mut rng, len);
            for factor in [0u8, 1, 2, 0x1d, 0xff, rng.below(256) as u8] {
                let mut accumulated = start.clone();
                field.mul_acc(&mut accumulated, &src, factor);
                assert_eq!(
                    accumulated,
                    scalar_region(&field, &src, factor, &start),
                    "mul_acc len {len} factor {factor:#x}"
                );

                let mut written = start.clone();
                field.mul_into(&mut written, &src, factor);
                assert_eq!(
                    written,
                    scalar_region(&field, &src, factor, &vec![0u8; len]),
                    "mul_into len {len} factor {factor:#x}"
                );
            }
        }
    }

    #[test]
    fn gf16_region_operations_agree_with_a_symbol_loop() {
        let field = Gf16::default();
        let mut rng = Rng(0x2026_0905_0000_0004);
        for symbols in [1usize, 3, 999, 1000, 1001, 4097] {
            let len = symbols * 2;
            let src = random_bytes(&mut rng, len);
            let start = random_bytes(&mut rng, len);
            for factor in [0u16, 1, 2, 0x100b, 0xffff, rng.below(65536) as u16] {
                let mut accumulated = start.clone();
                field.mul_acc(&mut accumulated, &src, factor);
                assert_eq!(
                    accumulated,
                    scalar_region(&field, &src, factor, &start),
                    "mul_acc {symbols} symbols factor {factor:#x}"
                );

                let mut written = start.clone();
                field.mul_into(&mut written, &src, factor);
                assert_eq!(
                    written,
                    scalar_region(&field, &src, factor, &vec![0u8; len]),
                    "mul_into {symbols} symbols factor {factor:#x}"
                );
            }
        }
    }

    /// A grouped multiply-accumulate leaves the bytes one `mul_acc` per source
    /// would, for every group width either side of the kernels' pass widths,
    /// lengths either side of the GF(2^8) tile, and a non-default polynomial.
    fn batch_agrees_with_single_sources<F: MulAccBatch>(
        field: &F,
        rng: &mut Rng,
        batch: impl Fn(&F, &mut [u8], &[&[u8]], &[F::Symbol]),
    ) where
        F::Symbol: Into<u64>,
    {
        for len in [2usize, 126, 128, 4098, (8 << 10) + 6, 20_000] {
            let len = len / F::SYMBOL_BYTES * F::SYMBOL_BYTES;
            for width in [1usize, 2, 3, 4, 8, 9, 16, 17, 33] {
                let sources: Vec<Vec<u8>> = (0..width).map(|_| random_bytes(rng, len)).collect();
                let factors: Vec<F::Symbol> = (0..width)
                    .map(|k| match k {
                        0 => F::symbol(0).unwrap(),
                        1 => field.one(),
                        _ => F::symbol(rng.below(F::MAX + 1)).unwrap(),
                    })
                    .collect();
                let start = random_bytes(rng, len);
                let mut expected = start.clone();
                for (src, factor) in sources.iter().zip(&factors) {
                    field.mul_acc(&mut expected, src, *factor);
                }
                let mut batched = start;
                let views: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
                batch(field, &mut batched, &views, &factors);
                assert_eq!(batched, expected, "{len} bytes, {width} sources");
            }
        }
    }

    #[test]
    fn grouped_multiply_accumulate_agrees_with_single_sources() {
        let mut rng = Rng(0x2026_1005_0000_0001);
        let batch = |field: &Gf8, dst: &mut [u8], sources: &[&[u8]], factors: &[u8]| {
            field.mul_acc_batch(dst, sources, factors);
        };
        batch_agrees_with_single_sources(&Gf8::default(), &mut rng, batch);
        batch_agrees_with_single_sources(&Gf8::new(0x12b).unwrap(), &mut rng, batch);
        let batch = |field: &Gf16, dst: &mut [u8], sources: &[&[u8]], factors: &[u16]| {
            field.mul_acc_batch(dst, sources, factors);
        };
        batch_agrees_with_single_sources(&Gf16::default(), &mut rng, batch);
        batch_agrees_with_single_sources(&Gf16::new(0x1_002d).unwrap(), &mut rng, batch);
        // The grouped kernels themselves, which an unoptimised aarch64 build
        // only reaches here, on a thread with a test's stack.
        batch_agrees_with_single_sources(&Gf16::default(), &mut rng, Gf16::mul_acc_grouped);
    }

    #[test]
    #[should_panic(expected = "equal-length regions")]
    fn a_region_multiply_refuses_regions_of_different_lengths() {
        Gf8::default().mul_acc(&mut [0u8; 4], &[0u8; 5], 2);
    }

    #[test]
    #[should_panic(expected = "not a whole number of 2-byte symbols")]
    fn a_gf16_region_multiply_refuses_an_odd_length() {
        Gf16::default().mul_acc(&mut [0u8; 3], &[0u8; 3], 2);
    }

    #[test]
    fn a_gf8_region_multiply_accepts_an_odd_length() {
        let mut odd = [0u8; 3];
        Gf8::default().mul_acc(&mut odd, &[1u8, 2, 3], 1);
        assert_eq!(odd, [1, 2, 3]);
    }

    #[test]
    fn a_non_primitive_generator_is_refused() {
        // 0x11B is the AES field polynomial: irreducible, but two has order 51
        // under it rather than 255, so its powers reach only 51 elements. The
        // order was checked by iterating the doubling sequence.
        let error = Gf8::new(0x11b).expect_err("0x11b is not primitive");
        assert!(
            error.to_string().contains("not primitive"),
            "unexpected error: {error}"
        );

        // Two polynomials whose doubling sequences close early in GF(2^16),
        // found the same way: 0x10003 after 255 steps, 0x10005 after 126.
        for generator in [0x1_0003u32, 0x1_0005] {
            let error = Gf16::new(generator).expect_err("not primitive");
            assert!(
                error.to_string().contains("not primitive"),
                "unexpected error: {error}"
            );
        }

        // x^8, whose powers of two collapse to zero.
        assert!(Gf8::new(0x100).is_err());
    }

    #[test]
    fn a_generator_of_the_wrong_degree_is_refused() {
        for generator in [0u32, 1, 0x1d, 0xff, 0x200, 0x1_100b] {
            assert!(
                Gf8::new(generator).is_err(),
                "GF(2^8) accepted {generator:#x}"
            );
        }
        for generator in [0u32, 0x11d, 0x100b, 0x2_0000] {
            assert!(
                Gf16::new(generator).is_err(),
                "GF(2^16) accepted {generator:#x}"
            );
        }
    }

    #[test]
    fn symbols_are_range_checked() {
        assert_eq!(Gf8::symbol(255), Some(255));
        assert_eq!(Gf8::symbol(256), None);
        assert_eq!(Gf16::symbol(65535), Some(65535));
        assert_eq!(Gf16::symbol(65536), None);
        assert_eq!(Gf8::symbol(u64::MAX), None);
    }

    #[test]
    fn a_set_start_packet_selects_the_field() {
        let gf8 = for_set(&GaloisField {
            size: 1,
            generator: 0x1d,
        })
        .expect("GF(2^8)");
        assert!(matches!(gf8, AnyField::Gf8(_)));
        assert_eq!(gf8.symbol_bytes(), 1);
        assert_eq!(gf8.max(), 255);
        assert_eq!(gf8.generator(), 0x11d);

        let gf16 = for_set(&GaloisField {
            size: 2,
            generator: 0x100b,
        })
        .expect("GF(2^16)");
        assert!(matches!(gf16, AnyField::Gf16(_)));
        assert_eq!(gf16.symbol_bytes(), 2);
        assert_eq!(gf16.max(), 65535);
        assert_eq!(gf16.generator(), 0x1_100b);

        // No field, a field this crate has no codec for, and a field whose
        // generator is not primitive.
        for field in [
            GaloisField {
                size: 0,
                generator: 0,
            },
            GaloisField {
                size: 4,
                generator: 1,
            },
            GaloisField {
                size: 1,
                generator: 0x1b,
            },
        ] {
            assert!(for_set(&field).is_err(), "accepted {field:?}");
        }
    }
}

/// The grouped multiply-accumulate against a symbol-at-a-time reference: 1 to
/// 40 sources, factors 0, 1, the largest and the top bit, lengths either side
/// of every vector width and tile, unaligned destinations and sources, and the
/// non-default generators. The grouped GF(2^16) kernels are also called
/// directly, so every build profile reaches them.
#[cfg(test)]
mod batch_sweep_tests {
    use super::*;

    fn bytes(state: &mut u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                (*state >> 24) as u8
            })
            .collect()
    }

    /// Symbol at a time through the log tables only, independent of every
    /// SIMD kernel.
    fn reference<F: Field>(field: &F, dst: &mut [u8], sources: &[&[u8]], factors: &[F::Symbol])
    where
        F::Symbol: Into<u64>,
    {
        for (src, factor) in sources.iter().zip(factors) {
            for (d, s) in dst
                .chunks_exact_mut(F::SYMBOL_BYTES)
                .zip(src.chunks_exact(F::SYMBOL_BYTES))
            {
                let mut v = 0u64;
                for (i, b) in s.iter().enumerate() {
                    v |= u64::from(*b) << (8 * i);
                }
                let p: u64 = field.mul(*factor, F::symbol(v).unwrap()).into();
                for (i, b) in d.iter_mut().enumerate() {
                    *b ^= (p >> (8 * i)) as u8;
                }
            }
        }
    }

    /// Every source count for the shortest lengths, the counts either side of
    /// each 8- and 16-wide group for the longer ones, and fewer still for the
    /// lengths past a tile, which keeps the sweep fast in an unoptimised build.
    fn counts(len: usize) -> Vec<usize> {
        match len {
            0..=130 => (1..=40).collect(),
            131..=1024 => vec![1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 40],
            _ => vec![1, 2, 15, 16, 17, 40],
        }
    }

    fn sweep<F: Field>(
        field: &F,
        lens: &[usize],
        batch: impl Fn(&F, &mut [u8], &[&[u8]], &[F::Symbol]),
    ) where
        F::Symbol: Into<u64>,
    {
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(field.generator());
        for &len in lens {
            for count in counts(len) {
                for dst_shift in [0usize, 1, 3] {
                    let src_shift = (count + dst_shift) % 5;
                    let backing: Vec<Vec<u8>> = (0..count)
                        .map(|_| bytes(&mut state, len + src_shift))
                        .collect();
                    let sources: Vec<&[u8]> = backing.iter().map(|b| &b[src_shift..]).collect();
                    let raw = bytes(&mut state, 8);
                    let factors: Vec<F::Symbol> = (0..count)
                        .map(|k| {
                            let v = match k % 7 {
                                0 => 0,
                                1 => 1,
                                2 => F::MAX,
                                3 => F::MAX.div_ceil(2),
                                _ => u64::from(raw[k % 8]) * 257 % (F::MAX + 1),
                            };
                            F::symbol(v).unwrap()
                        })
                        .collect();
                    let mut got = bytes(&mut state, len + dst_shift);
                    let mut expected = got.clone();
                    reference(field, &mut expected[dst_shift..], &sources, &factors);
                    batch(field, &mut got[dst_shift..], &sources, &factors);
                    assert!(
                        got == expected,
                        "generator {:#x}: len {len}, {count} sources, dst+{dst_shift}, src+{src_shift}",
                        field.generator()
                    );
                }
            }
        }
    }

    /// Either side of every vector width, and for GF(2^8) of its 8 KiB tile.
    /// A non-default generator folds source by source, so it takes only the
    /// lengths up to 258 bytes.
    const LENS8: &[usize] = &[
        0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 129, 191, 255, 256, 257, 1000, 8193,
    ];
    const SHORT8: usize = 16;
    const LENS16: &[usize] = &[
        0, 2, 30, 32, 34, 62, 64, 66, 126, 128, 130, 254, 256, 258, 1000, 4094, 8194,
    ];
    const SHORT16: usize = 14;

    #[test]
    fn gf8_batch_matches_symbol_reference() {
        let batch = |f: &Gf8, d: &mut [u8], s: &[&[u8]], k: &[u8]| f.mul_acc_batch(d, s, k);
        sweep(&Gf8::default(), LENS8, batch);
        sweep(&Gf8::new(0x12b).unwrap(), &LENS8[..SHORT8], batch);
    }

    #[test]
    fn gf16_batch_matches_symbol_reference() {
        let batch = |f: &Gf16, d: &mut [u8], s: &[&[u8]], k: &[u16]| f.mul_acc_batch(d, s, k);
        sweep(&Gf16::default(), LENS16, batch);
        sweep(&Gf16::new(0x1_002d).unwrap(), &LENS16[..SHORT16], batch);
    }

    /// The grouped kernels directly, whatever the build profile.
    #[test]
    fn gf16_grouped_matches_symbol_reference() {
        sweep(&Gf16::default(), LENS16, Gf16::mul_acc_grouped);
    }

    #[test]
    #[should_panic(expected = "not a whole number of 2-byte symbols")]
    fn gf16_grouped_refuses_an_odd_length() {
        let s = [0u8; 33];
        Gf16::default().mul_acc_grouped(&mut [0u8; 33], &[&s, &s], &[2, 3]);
    }

    #[test]
    #[should_panic(expected = "one factor per source")]
    fn batch_refuses_mismatched_factors() {
        let s = [0u8; 256];
        Gf16::default().mul_acc_batch(&mut [0u8; 256], &[&s, &s], &[2]);
    }

    #[test]
    #[should_panic(expected = "equal-length regions")]
    fn gf8_batch_refuses_a_short_source() {
        let (a, b) = ([0u8; 256], [0u8; 255]);
        Gf8::default().mul_acc_batch(&mut [0u8; 256], &[&a, &b], &[2, 3]);
    }

    #[test]
    #[should_panic(expected = "equal-length regions")]
    fn gf16_grouped_refuses_a_short_source() {
        let (a, b) = ([0u8; 256], [0u8; 254]);
        Gf16::default().mul_acc_grouped(&mut [0u8; 256], &[&a, &b], &[2, 3]);
    }

    /// Sixteen sources through the `mul_acc_batch` entry the codecs use, on a
    /// thread with a pool worker's 256 KiB stack. Wherever the build takes the
    /// grouped kernel there, its frame has to fit.
    #[test]
    fn batch_runs_on_a_worker_stack() {
        std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(|| {
                let field = Gf16::default();
                let mut state = 7u64;
                let backing: Vec<Vec<u8>> = (0..16).map(|_| bytes(&mut state, 65_536)).collect();
                let sources: Vec<&[u8]> = backing.iter().map(Vec::as_slice).collect();
                let factors: Vec<u16> = (0..16u16).map(|k| k * 4099 + 3).collect();
                let mut dst = vec![0u8; 65_536];
                let mut expected = dst.clone();
                for (s, f) in sources.iter().zip(&factors) {
                    field.mul_acc(&mut expected, s, *f);
                }
                field.mul_acc_batch(&mut dst, &sources, &factors);
                assert!(dst == expected);
                let factors: Vec<u8> = (1..=16).collect();
                let mut got = vec![0u8; 65_536];
                let mut expected = got.clone();
                for (s, f) in sources.iter().zip(&factors) {
                    Gf8::default().mul_acc(&mut expected, s, *f);
                }
                Gf8::default().mul_acc_batch(&mut got, &sources, &factors);
                assert!(got == expected);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

#[cfg(test)]
mod charge_tests {
    use super::*;

    /// Building a field costs more than the tables that survive it: the `u32`
    /// working tables are still alive while the narrowed table is filled. The
    /// charge has to cover the peak, and must not be so much larger than the
    /// peak that a caller is refused for memory nobody ever wanted.
    #[test]
    fn field_table_charges_cover_construction_without_doubling_it() {
        let gf8 = Gf8::new(Gf8::DEFAULT_GENERATOR).unwrap();
        let gf16 = Gf16::new(Gf16::DEFAULT_GENERATOR).unwrap();
        let cases = [
            (
                "GF(2^8)",
                Gf8::CONSTRUCTION_BYTES,
                gf8.retained_table_bytes(),
                8,
            ),
            (
                "GF(2^16)",
                Gf16::CONSTRUCTION_BYTES,
                gf16.retained_table_bytes(),
                16,
            ),
        ];
        for (name, charge, retained, width) in cases {
            let order = 1usize << width;
            let symbol = width as usize / 8;
            // Measured from the tables that exist: `build_tables` fills `log`
            // and `exp` as `u32`, then each is narrowed in turn, so the live
            // set is both working tables plus whichever narrowed table is
            // being filled.
            let log_words = order * size_of::<u32>();
            let exp_words = 2 * (order - 1) * size_of::<u32>();
            let log_symbols = order * symbol;
            let exp_symbols = 2 * (order - 1) * symbol;
            let peak =
                (log_words + exp_words + log_symbols).max(exp_words + log_symbols + exp_symbols);
            assert!(
                charge >= peak,
                "{name} charges {charge} for a {peak} byte construction peak"
            );
            assert!(
                charge < peak * 2,
                "{name} charges {charge}, more than twice its {peak} byte peak"
            );
            assert!(
                retained <= log_symbols + exp_symbols + 128,
                "{name} retains {retained}, more than its {} bytes of tables",
                log_symbols + exp_symbols
            );
            assert!(
                charge > retained,
                "{name} charges {charge} but construction peaks above its {retained} retained bytes"
            );
        }
    }

    /// Declared-field admission is what decides whether a repair may build a
    /// field at all, so it must never quote less than the field it will build.
    #[test]
    fn declared_field_admission_matches_the_field_it_builds() {
        for (size, generator, expected) in [
            (
                1u8,
                u64::from(Gf8::DEFAULT_GENERATOR & 0xff),
                Gf8::CONSTRUCTION_BYTES,
            ),
            (
                2,
                u64::from(Gf16::DEFAULT_GENERATOR & 0xffff),
                Gf16::CONSTRUCTION_BYTES,
            ),
        ] {
            let field = GaloisField { size, generator };
            assert_eq!(construction_cost(&field), expected);
            assert!(for_set(&field).is_ok());
        }
        // A field this crate cannot build is still admitted before it is
        // refused, and must be quoted at the widest field it might have been.
        assert_eq!(
            construction_cost(&GaloisField {
                size: 4,
                generator: 0
            }),
            Gf16::CONSTRUCTION_BYTES
        );
    }
}
