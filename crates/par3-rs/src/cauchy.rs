//! The Cauchy Reed-Solomon codec PAR3 recovery data is built with.
//!
//! A PAR3 set numbers its input blocks `0, 1, …` and its recovery blocks from
//! the first recovery index the set was created with. Writing `MAX` for the
//! largest value of the set's Galois field — 255 or 65535 — the code matrix is
//!
//! ```text
//! element(I, R) = inv(I ^ (MAX - R))
//! ```
//!
//! and recovery block `R` is the sum, over every input block `I`, of
//! `element(I, R)` times block `I`, with multiplication applied symbol by symbol
//! and addition being exclusive-or. That is a Cauchy matrix with `x_I = I` and
//! `y_R = MAX - R`; it is invertible whenever the two value sets are disjoint,
//! which is what [`Geometry`] validation checks.
//!
//! [`Encoder`] computes recovery blocks; [`Decoder`] rebuilds lost input blocks
//! from the recovery blocks that survived. Both are streaming: they take one
//! block at a time, in any order, and hold only the recovery rows or syndromes
//! in memory.
//!
//! ```
//! use par3_rs::cauchy::{Decoder, Encoder, Geometry};
//! use par3_rs::gf::Gf8;
//!
//! # fn main() -> par3_rs::Result<()> {
//! let geometry = Geometry {
//!     block_size: 4,
//!     input_blocks: 3,
//!     recovery_blocks: 2,
//!     first_recovery: 0,
//! };
//! let blocks: [&[u8]; 3] = [b"abcd", b"efgh", b"ij"];
//!
//! let mut encoder = Encoder::new(Gf8::default(), geometry)?;
//! for (index, block) in blocks.iter().enumerate() {
//!     encoder.add_input_block(index as u64, block)?;
//! }
//! let recovery = encoder.finish();
//!
//! // Lose blocks 0 and 2, and rebuild them from both recovery blocks.
//! let mut decoder = Decoder::new(Gf8::default(), geometry, &[0, 2], &[0, 1])?;
//! decoder.add_input_block(1, blocks[1])?;
//! for row in &recovery {
//!     decoder.add_recovery_block(row.index(), row.data())?;
//! }
//! let rebuilt = decoder.solve()?;
//! assert_eq!(rebuilt[0].data(), b"abcd");
//! assert_eq!(rebuilt[1].data(), b"ij\0\0");
//! # Ok(())
//! # }
//! ```
//!
//! Blocks shorter than the block size are zero-padded, exactly as the reference
//! implementation pads the block that holds a chunk tail; a rebuilt block comes
//! back at full block size, with that padding still on it.

use crate::error::{Par3Error, Result};
use crate::gf::Field;
use crate::packet::GaloisField;

/// Bounds on what a codec may allocate.
///
/// An encoder holds every recovery row it is building, and a decoder holds one
/// syndrome per lost block plus the matrix it inverts and the blocks it
/// rebuilds. All of that is sized from numbers a `.par3` file chose, so it is
/// metered rather than trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodecLimits {
    /// Most bytes of block and matrix buffers one codec may hold.
    pub max_buffer_bytes: u64,
}

impl CodecLimits {
    /// 1 GiB, which is 512 recovery blocks of two megabytes, or an entire
    /// 65536-block set at 16 KiB blocks.
    pub const DEFAULT_MAX_BUFFER_BYTES: u64 = 1 << 30;

    /// Limits allowing a codec `max_buffer_bytes` of block and matrix buffers.
    ///
    /// This type is `#[non_exhaustive]`, so a caller outside the crate cannot
    /// write it out as a struct literal; this is how to build one that is not
    /// the default.
    #[must_use]
    pub fn new(max_buffer_bytes: u64) -> Self {
        Self { max_buffer_bytes }
    }
}

impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            max_buffer_bytes: Self::DEFAULT_MAX_BUFFER_BYTES,
        }
    }
}

/// The shape of one set's recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Bytes in every input and recovery block.
    pub block_size: u64,
    /// Number of input blocks the set protects.
    pub input_blocks: u64,
    /// Number of recovery blocks the code produces.
    pub recovery_blocks: u64,
    /// Index of the first recovery block, which is `0` for a set created in one
    /// go and non-zero for recovery volumes created later.
    pub first_recovery: u64,
}

impl Geometry {
    /// Check that this geometry has a Cauchy matrix in `F`, and return the
    /// block size as a `usize`.
    ///
    /// The matrix element for input block `I` and recovery block `R` is
    /// `inv(I ^ (MAX - R))`, which exists only when `I` is never equal to
    /// `MAX - R`. The input values run over `0..input_blocks` and the row values
    /// over `MAX - first_recovery - recovery_blocks + 1 ..= MAX - first_recovery`,
    /// so the two are disjoint exactly when
    /// `input_blocks + first_recovery + recovery_blocks <= MAX + 1`. In GF(2^8)
    /// that allows 251 input blocks with 5 recovery blocks and refuses 252 with
    /// 5; in GF(2^16) the total is the format's own 65536-block ceiling.
    fn validate<F: Field>(&self) -> Result<usize> {
        if self.block_size == 0 {
            return Err(Par3Error::CodecGeometry {
                reason: "the block size is zero".to_string(),
            });
        }
        if !self.block_size.is_multiple_of(F::SYMBOL_BYTES as u64) {
            return Err(Par3Error::CodecGeometry {
                reason: format!(
                    "a block size of {} bytes is not a whole number of {}-byte field symbols",
                    self.block_size,
                    F::SYMBOL_BYTES
                ),
            });
        }
        let total = self
            .input_blocks
            .checked_add(self.first_recovery)
            .and_then(|sum| sum.checked_add(self.recovery_blocks))
            .ok_or_else(|| Par3Error::CodecGeometry {
                reason: "the block counts overflow a 64-bit total".to_string(),
            })?;
        if total > F::MAX + 1 {
            return Err(Par3Error::CodecGeometry {
                reason: format!(
                    "{} input blocks and recovery blocks {}..{} need more than the {} values \
                     the field holds",
                    self.input_blocks,
                    self.first_recovery,
                    self.first_recovery + self.recovery_blocks,
                    F::MAX + 1
                ),
            });
        }
        usize::try_from(self.block_size).map_err(|_| Par3Error::CodecGeometry {
            reason: format!(
                "a block size of {} bytes does not fit in memory",
                self.block_size
            ),
        })
    }
}

/// The Galois field the reference implementation would choose for a set.
///
/// It uses GF(2^16) with `0x1100B` when there are more than 128 input blocks, or
/// when the input and recovery blocks together exceed 256, and GF(2^8) with
/// `0x11D` otherwise. The reference has a third term for a declared maximum
/// recovery block count, an option this crate does not expose; it is treated as
/// zero here.
///
/// The reference also leaves the field unset for a set with no input blocks at
/// all, because there is then nothing to encode. This returns GF(2^8) for that
/// case rather than a fourth answer nobody can use.
#[must_use]
pub fn default_field(input_blocks: u64, recovery_blocks: u64, first_recovery: u64) -> GaloisField {
    let total = input_blocks
        .saturating_add(first_recovery)
        .saturating_add(recovery_blocks);
    if input_blocks > 128 || total > 256 {
        GaloisField {
            size: 2,
            generator: 0x100b,
        }
    } else {
        GaloisField {
            size: 1,
            generator: 0x1d,
        }
    }
}

/// The code matrix element for one input block and one recovery block.
///
/// `recovery` is the absolute recovery block index, not an offset from a set's
/// first recovery block. The element is `inv(input ^ (MAX - recovery))`, and it
/// exists only when those two values differ — see [`Geometry`] for when a whole
/// geometry guarantees that.
pub fn element<F: Field>(field: &F, input: u64, recovery: u64) -> Result<F::Symbol> {
    if recovery > F::MAX {
        return Err(Par3Error::CodecBlock {
            index: recovery,
            reason: format!(
                "recovery block index is beyond the field's largest value {}",
                F::MAX
            ),
        });
    }
    let row = F::MAX - recovery;
    let column = F::symbol(input).ok_or_else(|| Par3Error::CodecBlock {
        index: input,
        reason: format!(
            "input block index is beyond the field's largest value {}",
            F::MAX
        ),
    })?;
    let row = F::symbol(row).expect("MAX - recovery is a value of the field");
    let difference = field.add(column, row);
    field.inv(difference).ok_or(Par3Error::CodecGeometry {
        reason: format!(
            "input block {input} and recovery block {recovery} share the field value {row_value}",
            row_value = F::MAX - recovery
        ),
    })
}

/// One finished recovery block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRow {
    index: u64,
    data: Vec<u8>,
}

impl RecoveryRow {
    /// The absolute recovery block index this row is for.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The recovery block, always a full block size.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Take the recovery block, leaving the row behind.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

/// One rebuilt input block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredBlock {
    index: u64,
    data: Vec<u8>,
}

impl RecoveredBlock {
    /// The input block index this block belongs at.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The block, at full block size: a block that held a chunk tail comes back
    /// with the zero padding the encoder saw.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Take the block, leaving the wrapper behind.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

/// Charge a codec's buffers against its limits before allocating them.
fn charge(bytes: u64, limits: &CodecLimits, what: &str) -> Result<()> {
    if bytes > limits.max_buffer_bytes {
        return Err(Par3Error::CodecLimitExceeded {
            reason: format!(
                "{what} would need {bytes} bytes, over the {} byte budget",
                limits.max_buffer_bytes
            ),
        });
    }
    Ok(())
}

/// Multiply out the bytes a caller supplied for a block, padding with zeros.
///
/// A full-size block is used where it lies; a short one — the block that holds a
/// chunk tail — is copied into a scratch buffer whose tail is zeroed, because
/// the padding is part of what was encoded, and for GF(2^16) the symbol that
/// straddles the end of the data must be assembled before it can be multiplied.
fn accumulate<F: Field>(
    field: &F,
    row: &mut [u8],
    data: &[u8],
    scratch: &mut Vec<u8>,
    factor: F::Symbol,
) {
    if data.len() == row.len() {
        field.mul_acc(row, data, factor);
    } else {
        scratch.clear();
        scratch.extend_from_slice(data);
        scratch.resize(row.len(), 0);
        field.mul_acc(row, scratch, factor);
    }
}

/// Builds a set's recovery blocks, one input block at a time.
///
/// Input blocks may arrive in any order, but each exactly once: the encoder is
/// accumulating a sum, and it has no way to take a block back out. Every
/// recovery row is held in memory, so an encoder costs
/// `recovery_blocks × block_size` bytes plus one block of scratch.
#[derive(Debug, Clone)]
pub struct Encoder<F: Field> {
    field: F,
    geometry: Geometry,
    block_size: usize,
    rows: Vec<Vec<u8>>,
    seen: Vec<bool>,
    seen_count: u64,
    scratch: Vec<u8>,
}

impl<F: Field> Encoder<F> {
    /// Start an encoder under the default [`CodecLimits`].
    pub fn new(field: F, geometry: Geometry) -> Result<Self> {
        Self::with_limits(field, geometry, &CodecLimits::default())
    }

    /// Start an encoder under explicit limits.
    ///
    /// Fails when the geometry has no Cauchy matrix in `F`, or when the recovery
    /// rows would not fit inside `limits`.
    pub fn with_limits(field: F, geometry: Geometry, limits: &CodecLimits) -> Result<Self> {
        let block_size = geometry.validate::<F>()?;
        let buffers = geometry
            .recovery_blocks
            .checked_add(1)
            .and_then(|rows| rows.checked_mul(geometry.block_size))
            .ok_or_else(|| Par3Error::CodecLimitExceeded {
                reason: "the recovery rows overflow a 64-bit byte count".to_string(),
            })?;
        charge(buffers, limits, "the recovery rows")?;

        let rows = usize::try_from(geometry.recovery_blocks).map_err(|_| {
            Par3Error::CodecLimitExceeded {
                reason: format!(
                    "{} recovery rows do not fit in memory",
                    geometry.recovery_blocks
                ),
            }
        })?;
        let inputs =
            usize::try_from(geometry.input_blocks).map_err(|_| Par3Error::CodecLimitExceeded {
                reason: format!(
                    "{} input blocks do not fit in memory",
                    geometry.input_blocks
                ),
            })?;
        Ok(Self {
            field,
            geometry,
            block_size,
            rows: vec![vec![0u8; block_size]; rows],
            seen: vec![false; inputs],
            seen_count: 0,
            scratch: Vec::new(),
        })
    }

    /// The geometry this encoder was built for.
    #[must_use]
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Whether every input block has been supplied.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.seen_count == self.geometry.input_blocks
    }

    /// Input blocks still to come.
    #[must_use]
    pub fn missing_input_blocks(&self) -> u64 {
        self.geometry.input_blocks - self.seen_count
    }

    /// Add one input block, zero-padded to the block size if it is short.
    ///
    /// Fails when the index is not one of this geometry's input blocks, when the
    /// block has already been added, or when `data` is longer than the block
    /// size.
    pub fn add_input_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        let slot = self.check_input(index, data)?;
        self.seen[slot] = true;
        self.seen_count += 1;
        for (row, buffer) in self.rows.iter_mut().enumerate() {
            let recovery = self.geometry.first_recovery + row as u64;
            let factor = element(&self.field, index, recovery)?;
            accumulate(&self.field, buffer, data, &mut self.scratch, factor);
        }
        Ok(())
    }

    fn check_input(&self, index: u64, data: &[u8]) -> Result<usize> {
        if index >= self.geometry.input_blocks {
            return Err(Par3Error::CodecBlock {
                index,
                reason: format!("the set has {} input blocks", self.geometry.input_blocks),
            });
        }
        if data.len() > self.block_size {
            return Err(Par3Error::CodecBlock {
                index,
                reason: format!(
                    "{} bytes supplied for a {}-byte block",
                    data.len(),
                    self.block_size
                ),
            });
        }
        let slot = index as usize;
        if self.seen[slot] {
            return Err(Par3Error::CodecBlock {
                index,
                reason: "was already added; an encoder accumulates a sum and cannot take a \
                         block back out"
                    .to_string(),
            });
        }
        Ok(slot)
    }

    /// The recovery blocks, in ascending recovery index.
    ///
    /// An encoder that has not seen every input block returns the partial sums
    /// it has, which are not recovery data; check [`is_complete`](Self::is_complete)
    /// first when the caller cannot otherwise be sure.
    #[must_use]
    pub fn finish(self) -> Vec<RecoveryRow> {
        self.rows
            .into_iter()
            .enumerate()
            .map(|(row, data)| RecoveryRow {
                index: self.geometry.first_recovery + row as u64,
                data,
            })
            .collect()
    }
}

/// Rebuilds lost input blocks from the recovery blocks that survived.
///
/// Told which input blocks are lost and which recovery blocks are on hand, the
/// decoder takes every surviving input block once and each of the recovery
/// blocks it chose, then solves. It holds one syndrome per lost block plus the
/// square matrix over the lost columns, so it costs about
/// `2 × lost × block_size` bytes plus `2 × lost²` symbols — never the whole
/// `input_blocks × recovery_blocks` matrix.
#[derive(Debug, Clone)]
pub struct Decoder<F: Field> {
    field: F,
    geometry: Geometry,
    block_size: usize,
    /// Lost input block indices, ascending.
    lost: Vec<u64>,
    /// Absolute indices of the recovery blocks that will be used, ascending.
    rows: Vec<u64>,
    /// One syndrome per chosen row, in the same order.
    syndromes: Vec<Vec<u8>>,
    /// Which chosen rows have been supplied.
    seen_rows: Vec<bool>,
    /// Which input blocks are accounted for. A lost block starts out accounted
    /// for, because it is what the solve is going to produce.
    seen_inputs: Vec<bool>,
    scratch: Vec<u8>,
}

impl<F: Field> Decoder<F> {
    /// Start a decoder under the default [`CodecLimits`].
    pub fn new(
        field: F,
        geometry: Geometry,
        lost_inputs: &[u64],
        available_recovery: &[u64],
    ) -> Result<Self> {
        Self::with_limits(
            field,
            geometry,
            lost_inputs,
            available_recovery,
            &CodecLimits::default(),
        )
    }

    /// Start a decoder under explicit limits.
    ///
    /// `lost_inputs` are input block indices, `available_recovery` absolute
    /// recovery block indices; neither may repeat an index, and both must lie
    /// inside the geometry. The first `lost_inputs.len()` available recovery
    /// blocks in ascending order are the ones that will be used, and the rest
    /// are ignored — a caller that would rather use different rows should name
    /// only those.
    pub fn with_limits(
        field: F,
        geometry: Geometry,
        lost_inputs: &[u64],
        available_recovery: &[u64],
        limits: &CodecLimits,
    ) -> Result<Self> {
        let block_size = geometry.validate::<F>()?;
        let lost = sorted_distinct(lost_inputs, |index| {
            if index >= geometry.input_blocks {
                Some(format!(
                    "the set has {} input blocks",
                    geometry.input_blocks
                ))
            } else {
                None
            }
        })?;
        let first = geometry.first_recovery;
        let end = first + geometry.recovery_blocks;
        let available = sorted_distinct(available_recovery, |index| {
            if index < first || index >= end {
                Some(format!("the set's recovery blocks are {first}..{end}"))
            } else {
                None
            }
        })?;
        if available.len() < lost.len() {
            return Err(Par3Error::InsufficientRecovery {
                lost: lost.len() as u64,
                available: available.len() as u64,
            });
        }
        let rows: Vec<u64> = available.into_iter().take(lost.len()).collect();

        // Syndromes and rebuilt blocks, plus the matrix and its inverse.
        let count = rows.len() as u64;
        let buffers = count
            .checked_mul(2)
            .and_then(|blocks| blocks.checked_mul(geometry.block_size))
            .and_then(|bytes| bytes.checked_add(geometry.block_size))
            .and_then(|bytes| {
                let symbols = count.checked_mul(count)?.checked_mul(2)?;
                bytes.checked_add(symbols.checked_mul(F::SYMBOL_BYTES as u64)?)
            })
            .ok_or_else(|| Par3Error::CodecLimitExceeded {
                reason: "the syndromes and matrix overflow a 64-bit byte count".to_string(),
            })?;
        charge(buffers, limits, "the syndromes and the matrix")?;

        let inputs =
            usize::try_from(geometry.input_blocks).map_err(|_| Par3Error::CodecLimitExceeded {
                reason: format!(
                    "{} input blocks do not fit in memory",
                    geometry.input_blocks
                ),
            })?;
        let mut seen_inputs = vec![false; inputs];
        for index in &lost {
            seen_inputs[*index as usize] = true;
        }
        Ok(Self {
            field,
            geometry,
            block_size,
            syndromes: vec![vec![0u8; block_size]; rows.len()],
            seen_rows: vec![false; rows.len()],
            lost,
            rows,
            seen_inputs,
            scratch: Vec::new(),
        })
    }

    /// The geometry this decoder was built for.
    #[must_use]
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// The lost input block indices, ascending.
    #[must_use]
    pub fn lost_inputs(&self) -> &[u64] {
        &self.lost
    }

    /// The recovery blocks the decoder will use, ascending.
    #[must_use]
    pub fn recovery_rows(&self) -> &[u64] {
        &self.rows
    }

    /// Add one surviving input block, zero-padded to the block size if short.
    ///
    /// Fails when the index is not an input block of this geometry, when it is
    /// one of the lost blocks, when it has already been added, or when `data`
    /// is longer than the block size.
    pub fn add_input_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        if index >= self.geometry.input_blocks {
            return Err(Par3Error::CodecBlock {
                index,
                reason: format!("the set has {} input blocks", self.geometry.input_blocks),
            });
        }
        if data.len() > self.block_size {
            return Err(Par3Error::CodecBlock {
                index,
                reason: format!(
                    "{} bytes supplied for a {}-byte block",
                    data.len(),
                    self.block_size
                ),
            });
        }
        if self.lost.binary_search(&index).is_ok() {
            return Err(Par3Error::CodecBlock {
                index,
                reason: "was named as lost, so it cannot also be supplied".to_string(),
            });
        }
        if self.seen_inputs[index as usize] {
            return Err(Par3Error::CodecBlock {
                index,
                reason: "was already added".to_string(),
            });
        }
        self.seen_inputs[index as usize] = true;
        for (row, syndrome) in self.rows.iter().zip(&mut self.syndromes) {
            let factor = element(&self.field, index, *row)?;
            accumulate(&self.field, syndrome, data, &mut self.scratch, factor);
        }
        Ok(())
    }

    /// Add one recovery block, zero-padded to the block size if short.
    ///
    /// Only the rows [`recovery_rows`](Self::recovery_rows) names are wanted;
    /// any other index is refused rather than quietly ignored, so that a caller
    /// reading volumes off a disk finds out it is feeding the wrong ones.
    pub fn add_recovery_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        let Ok(row) = self.rows.binary_search(&index) else {
            return Err(Par3Error::CodecBlock {
                index,
                reason: "is not one of the recovery blocks this decoder chose".to_string(),
            });
        };
        if data.len() > self.block_size {
            return Err(Par3Error::CodecBlock {
                index,
                reason: format!(
                    "{} bytes supplied for a {}-byte block",
                    data.len(),
                    self.block_size
                ),
            });
        }
        if self.seen_rows[row] {
            return Err(Par3Error::CodecBlock {
                index,
                reason: "was already added".to_string(),
            });
        }
        self.seen_rows[row] = true;
        // The recovery block enters the syndrome with a factor of one, so this
        // is a plain exclusive-or.
        for (slot, byte) in self.syndromes[row].iter_mut().zip(data) {
            *slot ^= *byte;
        }
        Ok(())
    }

    /// Solve for the lost input blocks, in ascending input block index.
    ///
    /// Fails when a surviving input block or a chosen recovery block was never
    /// supplied — the sum would be wrong, and nothing in the result would say so
    /// — and when the matrix turns out not to be invertible.
    pub fn solve(self) -> Result<Vec<RecoveredBlock>> {
        let count = self.lost.len();
        if count == 0 {
            // Nothing was lost, so nothing had to be supplied either.
            return Ok(Vec::new());
        }
        if let Some(index) = self.seen_inputs.iter().position(|seen| !seen) {
            return Err(Par3Error::CodecBlock {
                index: index as u64,
                reason: "survived but was never supplied, so the syndromes are incomplete"
                    .to_string(),
            });
        }
        if let Some(row) = self.seen_rows.iter().position(|seen| !seen) {
            return Err(Par3Error::CodecBlock {
                index: self.rows[row],
                reason: "was chosen for the solve but never supplied".to_string(),
            });
        }

        // M[row][column] = element(lost[column], rows[row]), so that the
        // syndromes are M times the lost blocks.
        let mut matrix = Vec::with_capacity(count * count);
        for row in &self.rows {
            for column in &self.lost {
                matrix.push(element(&self.field, *column, *row)?);
            }
        }
        let inverse = invert(&self.field, matrix, count)?;

        let mut recovered = Vec::with_capacity(count);
        for (column, index) in self.lost.iter().enumerate() {
            let mut data = vec![0u8; self.block_size];
            for (row, syndrome) in self.syndromes.iter().enumerate() {
                let factor = inverse[column * count + row];
                self.field.mul_acc(&mut data, syndrome, factor);
            }
            recovered.push(RecoveredBlock {
                index: *index,
                data,
            });
        }
        Ok(recovered)
    }
}

/// Sort a list of block indices, refusing repeats and anything `check` rejects.
fn sorted_distinct(indices: &[u64], check: impl Fn(u64) -> Option<String>) -> Result<Vec<u64>> {
    let mut sorted = indices.to_vec();
    sorted.sort_unstable();
    let mut previous = None;
    for index in &sorted {
        if let Some(reason) = check(*index) {
            return Err(Par3Error::CodecBlock {
                index: *index,
                reason,
            });
        }
        if previous == Some(*index) {
            return Err(Par3Error::CodecBlock {
                index: *index,
                reason: "was named twice".to_string(),
            });
        }
        previous = Some(*index);
    }
    Ok(sorted)
}

/// Invert an `n × n` matrix, stored row by row, by Gauss-Jordan elimination.
///
/// A Cauchy matrix over distinct, disjoint row and column values is always
/// invertible, so a zero pivot means the caller's geometry was not what it
/// claimed; it is reported rather than assumed away.
fn invert<F: Field>(field: &F, mut matrix: Vec<F::Symbol>, n: usize) -> Result<Vec<F::Symbol>> {
    let zero = F::Symbol::default();
    let one = field.one();
    let mut inverse = vec![zero; n * n];
    for (row, cells) in inverse.chunks_exact_mut(n).enumerate() {
        cells[row] = one;
    }

    for column in 0..n {
        let pivot = (column..n)
            .find(|row| matrix[row * n + column] != zero)
            .ok_or(Par3Error::SingularSystem)?;
        if pivot != column {
            for index in 0..n {
                matrix.swap(column * n + index, pivot * n + index);
                inverse.swap(column * n + index, pivot * n + index);
            }
        }
        let scale = field
            .inv(matrix[column * n + column])
            .ok_or(Par3Error::SingularSystem)?;
        for index in 0..n {
            matrix[column * n + index] = field.mul(matrix[column * n + index], scale);
            inverse[column * n + index] = field.mul(inverse[column * n + index], scale);
        }
        for row in 0..n {
            if row == column {
                continue;
            }
            let factor = matrix[row * n + column];
            if factor == zero {
                continue;
            }
            for index in 0..n {
                let from_matrix = field.mul(matrix[column * n + index], factor);
                matrix[row * n + index] = field.add(matrix[row * n + index], from_matrix);
                let from_inverse = field.mul(inverse[column * n + index], factor);
                inverse[row * n + index] = field.add(inverse[row * n + index], from_inverse);
            }
        }
    }
    Ok(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf::{Gf8, Gf16};

    fn geometry(block_size: u64, input_blocks: u64, recovery_blocks: u64) -> Geometry {
        Geometry {
            block_size,
            input_blocks,
            recovery_blocks,
            first_recovery: 0,
        }
    }

    #[test]
    fn the_field_rule_matches_the_reference() {
        let gf8 = GaloisField {
            size: 1,
            generator: 0x1d,
        };
        let gf16 = GaloisField {
            size: 2,
            generator: 0x100b,
        };

        // More than 128 input blocks moves to the wider field.
        assert_eq!(default_field(128, 1, 0), gf8);
        assert_eq!(default_field(129, 1, 0), gf16);
        // So does a total of more than 256 blocks.
        assert_eq!(default_field(100, 156, 0), gf8);
        assert_eq!(default_field(100, 157, 0), gf16);
        // The first recovery index counts towards that total.
        assert_eq!(default_field(100, 150, 6), gf8);
        assert_eq!(default_field(100, 150, 7), gf16);
        // Degenerate counts do not overflow into the wrong answer.
        assert_eq!(default_field(0, 0, 0), gf8);
        assert_eq!(default_field(u64::MAX, u64::MAX, u64::MAX), gf16);
    }

    #[test]
    fn the_matrix_element_is_the_reference_construction() {
        let field = Gf8::default();
        // element(I, R) = inv(I ^ (255 - R)).
        for (input, recovery) in [(0u64, 0u64), (3, 1), (4, 2)] {
            let expected = field
                .inv((input as u8) ^ (255 - recovery as u8))
                .expect("non-zero");
            assert_eq!(
                element(&field, input, recovery).expect("in range"),
                expected
            );
        }
        // The value a row and a column share has no inverse.
        assert!(element(&field, 255, 0).is_err());
        assert!(element(&field, 250, 5).is_err());
        // Out of the field entirely.
        assert!(element(&field, 256, 0).is_err());
        assert!(element(&field, 0, 256).is_err());
        assert!(element(&Gf16::default(), 0, 65536).is_err());
    }

    #[test]
    fn the_geometry_boundary_is_where_a_row_meets_a_column() {
        // 251 input blocks and 5 recovery blocks use all 256 values exactly.
        assert!(Encoder::new(Gf8::default(), geometry(8, 251, 5)).is_ok());
        assert!(Encoder::new(Gf8::default(), geometry(8, 252, 5)).is_err());
        // With a first recovery index of 1 the room shrinks by one.
        assert!(
            Encoder::new(
                Gf8::default(),
                Geometry {
                    block_size: 8,
                    input_blocks: 250,
                    recovery_blocks: 5,
                    first_recovery: 1,
                },
            )
            .is_ok()
        );
        assert!(
            Encoder::new(
                Gf8::default(),
                Geometry {
                    block_size: 8,
                    input_blocks: 251,
                    recovery_blocks: 5,
                    first_recovery: 1,
                },
            )
            .is_err()
        );
        // The wider field has room for the same shape and much more.
        assert!(Encoder::new(Gf16::default(), geometry(8, 252, 5)).is_ok());
        assert!(Encoder::new(Gf16::default(), geometry(8, 65_000, 536)).is_ok());
        assert!(Encoder::new(Gf16::default(), geometry(8, 65_000, 537)).is_err());
    }

    #[test]
    fn a_geometry_with_no_workable_block_size_is_refused() {
        assert!(Encoder::new(Gf8::default(), geometry(0, 4, 2)).is_err());
        // GF(2^16) blocks are whole 16-bit words.
        assert!(Encoder::new(Gf16::default(), geometry(3, 4, 2)).is_err());
        assert!(Encoder::new(Gf16::default(), geometry(2, 4, 2)).is_ok());
        // An odd block size is fine in GF(2^8).
        assert!(Encoder::new(Gf8::default(), geometry(3, 4, 2)).is_ok());
    }

    #[test]
    fn hostile_geometries_are_refused_rather_than_allocated() {
        // A block size that would exhaust memory long before the limit.
        let error = Encoder::new(Gf8::default(), geometry(u64::MAX, 4, 2))
            .expect_err("an impossible block size");
        assert!(
            matches!(error, Par3Error::CodecLimitExceeded { .. }),
            "unexpected error: {error}"
        );

        // Block counts no field can hold.
        assert!(Encoder::new(Gf8::default(), geometry(8, u64::MAX, 2)).is_err());
        assert!(Encoder::new(Gf16::default(), geometry(8, u64::MAX, 2)).is_err());
        assert!(
            Encoder::new(
                Gf16::default(),
                Geometry {
                    block_size: 8,
                    input_blocks: u64::MAX,
                    recovery_blocks: u64::MAX,
                    first_recovery: u64::MAX,
                },
            )
            .is_err()
        );

        // A geometry that fits the field but not the caller's budget.
        let limits = CodecLimits::new(1024);
        assert!(
            Encoder::with_limits(Gf8::default(), geometry(1000, 4, 8), &limits).is_err(),
            "eight one-kilobyte rows fit inside a kilobyte"
        );
        assert!(Encoder::with_limits(Gf8::default(), geometry(100, 4, 2), &limits).is_ok());
    }

    #[test]
    fn an_encoder_refuses_blocks_it_cannot_place() {
        let mut encoder = Encoder::new(Gf8::default(), geometry(4, 3, 2)).expect("a valid shape");
        assert!(
            encoder.add_input_block(3, &[0; 4]).is_err(),
            "beyond the set"
        );
        assert!(encoder.add_input_block(u64::MAX, &[0; 4]).is_err());
        assert!(encoder.add_input_block(0, &[0; 5]).is_err(), "over-long");
        assert!(
            encoder.add_input_block(0, &[1, 2, 3]).is_ok(),
            "short is padded"
        );
        assert!(encoder.add_input_block(0, &[0; 4]).is_err(), "twice");
        assert_eq!(encoder.missing_input_blocks(), 2);
        assert!(!encoder.is_complete());
    }

    #[test]
    fn a_decoder_refuses_lists_it_cannot_use() {
        let field = Gf8::default();
        let shape = geometry(4, 5, 2);
        // More lost blocks than recovery blocks.
        let error = Decoder::new(field.clone(), shape, &[0, 1, 2], &[0, 1])
            .expect_err("three lost blocks, two recovery blocks");
        assert!(
            matches!(
                error,
                Par3Error::InsufficientRecovery {
                    lost: 3,
                    available: 2
                }
            ),
            "unexpected error: {error}"
        );
        // Duplicates in either list.
        assert!(Decoder::new(field.clone(), shape, &[1, 1], &[0, 1]).is_err());
        assert!(Decoder::new(field.clone(), shape, &[1], &[0, 0]).is_err());
        // Indices outside the geometry.
        assert!(Decoder::new(field.clone(), shape, &[5], &[0, 1]).is_err());
        assert!(Decoder::new(field.clone(), shape, &[u64::MAX], &[0, 1]).is_err());
        assert!(Decoder::new(field.clone(), shape, &[1], &[2]).is_err());
        // Nothing lost is a valid, empty solve.
        let decoder = Decoder::new(field, shape, &[], &[]).expect("nothing to do");
        assert!(decoder.solve().expect("solves").is_empty());
    }

    #[test]
    fn a_decoder_refuses_blocks_it_did_not_ask_for() {
        let mut decoder =
            Decoder::new(Gf8::default(), geometry(4, 5, 2), &[2], &[1]).expect("a valid shape");
        assert_eq!(decoder.lost_inputs(), [2]);
        assert_eq!(decoder.recovery_rows(), [1]);
        assert!(
            decoder.add_input_block(2, &[0; 4]).is_err(),
            "that one is lost"
        );
        assert!(
            decoder.add_input_block(5, &[0; 4]).is_err(),
            "beyond the set"
        );
        assert!(decoder.add_input_block(0, &[0; 5]).is_err(), "over-long");
        assert!(decoder.add_input_block(0, &[0; 4]).is_ok());
        assert!(decoder.add_input_block(0, &[0; 4]).is_err(), "twice");
        assert!(
            decoder.add_recovery_block(0, &[0; 4]).is_err(),
            "row 0 was not chosen"
        );
        assert!(decoder.add_recovery_block(1, &[0; 5]).is_err(), "over-long");
        assert!(decoder.add_recovery_block(1, &[0; 4]).is_ok());
        assert!(decoder.add_recovery_block(1, &[0; 4]).is_err(), "twice");
        // Blocks 1, 3 and 4 were never supplied, so there is nothing to solve.
        let error = decoder.solve().expect_err("incomplete");
        assert!(
            matches!(error, Par3Error::CodecBlock { index: 1, .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_decoder_that_never_saw_its_recovery_block_refuses_to_solve() {
        let mut decoder =
            Decoder::new(Gf8::default(), geometry(4, 3, 2), &[1], &[0, 1]).expect("a valid shape");
        decoder.add_input_block(0, b"abcd").expect("added");
        decoder.add_input_block(2, b"efgh").expect("added");
        let error = decoder.solve().expect_err("no recovery block");
        assert!(
            matches!(error, Par3Error::CodecBlock { index: 0, .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_matrix_inverse_undoes_the_matrix() {
        let field = Gf8::default();
        let lost = [0u64, 2, 3];
        let rows = [0u64, 1, 2];
        let n = lost.len();
        let mut matrix = Vec::new();
        for row in rows {
            for column in lost {
                matrix.push(element(&field, column, row).expect("in range"));
            }
        }
        let inverse = invert(&field, matrix.clone(), n).expect("Cauchy matrices invert");
        for i in 0..n {
            for j in 0..n {
                let mut sum = 0u8;
                for k in 0..n {
                    sum ^= field.mul(matrix[i * n + k], inverse[k * n + j]);
                }
                assert_eq!(sum, u8::from(i == j), "product at ({i}, {j})");
            }
        }
    }

    #[test]
    fn a_singular_matrix_is_reported_rather_than_divided_by() {
        let field = Gf8::default();
        // Two identical rows cannot be inverted.
        let matrix = vec![1u8, 2, 1, 2];
        assert!(matches!(
            invert(&field, matrix, 2),
            Err(Par3Error::SingularSystem)
        ));
        // Nor can a zero column.
        let matrix = vec![0u8, 0, 3, 4];
        assert!(matches!(
            invert(&field, matrix, 2),
            Err(Par3Error::SingularSystem)
        ));
    }
}
