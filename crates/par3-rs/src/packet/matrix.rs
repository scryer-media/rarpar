//! Matrix packets: `PAR CAU\0`, `PAR SPA\0`, `PAR EXP\0` and `PAR FFT\0`.
//!
//! A matrix packet describes how recovery blocks were computed. This crate parses
//! all four, but computes nothing from them: PAR3 recovery is out of scope for
//! `0.1`.

use crate::error::Result;
use crate::packet::reader::BodyReader;

/// The half-open range of input blocks a matrix covers.
///
/// `first == 0 && end == 0` means "every input block": the specification says an
/// encoder that covers everything writes the values `0` and `0`, because the
/// maximum unsigned integer plus one rolls over to zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRange {
    /// Index of the first input block in the range.
    pub first: u64,
    /// Index of the last input block plus one.
    pub end: u64,
}

impl BlockRange {
    /// Whether this range is the "every input block" encoding.
    #[must_use]
    pub fn covers_all(&self) -> bool {
        self.first == 0 && self.end == 0
    }
}

/// The Cauchy Matrix packet: a Reed-Solomon code over the set's Galois field.
///
/// # Element definition
///
/// The published specification defines the non-zero element for input block `I`
/// and recovery block `R` as `inv(x_(I+1) - y_(MAX-R))`. The reference
/// implementation's appendix drops the `+1`, so the element is
/// `inv(x_I - y_(MAX-R))`. Anything computing recovery data from this packet must
/// follow the reference. Nothing in `0.1` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauchyMatrixPacket {
    /// Input blocks this matrix covers.
    pub range: BlockRange,
    /// Hint for the number of recovery blocks, or `0` when unknown.
    pub recovery_block_hint: u64,
}

impl CauchyMatrixPacket {
    /// Body length of a Cauchy Matrix packet.
    pub const BODY_LEN: usize = 24;

    /// Parse a Cauchy Matrix packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, "Cauchy Matrix");
        let range = BlockRange {
            first: reader.u64()?,
            end: reader.u64()?,
        };
        let recovery_block_hint = reader.u64()?;
        reader.finish()?;
        Ok(Self {
            range,
            recovery_block_hint,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.range.first.to_le_bytes());
        out.extend_from_slice(&self.range.end.to_le_bytes());
        out.extend_from_slice(&self.recovery_block_hint.to_le_bytes());
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

/// The Sparse Random Matrix packet.
///
/// The reference implementation does not write these; the layout is fixed and
/// cheap, so this crate parses them anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseRandomMatrixPacket {
    /// Input blocks this matrix covers.
    pub range: BlockRange,
    /// Maximum number of recovery blocks the matrix can produce.
    pub max_recovery_blocks: u64,
    /// Non-zero elements per input block.
    pub non_zero_per_input_block: u64,
    /// Seed for the PCG-XSL-RR generator that places the non-zero elements.
    pub seed: u64,
}

impl SparseRandomMatrixPacket {
    /// Body length of a Sparse Random Matrix packet.
    pub const BODY_LEN: usize = 40;

    /// Parse a Sparse Random Matrix packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, "Sparse Random Matrix");
        let range = BlockRange {
            first: reader.u64()?,
            end: reader.u64()?,
        };
        let max_recovery_blocks = reader.u64()?;
        let non_zero_per_input_block = reader.u64()?;
        let seed = reader.u64()?;
        reader.finish()?;
        Ok(Self {
            range,
            max_recovery_blocks,
            non_zero_per_input_block,
            seed,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.range.first.to_le_bytes());
        out.extend_from_slice(&self.range.end.to_le_bytes());
        out.extend_from_slice(&self.max_recovery_blocks.to_le_bytes());
        out.extend_from_slice(&self.non_zero_per_input_block.to_le_bytes());
        out.extend_from_slice(&self.seed.to_le_bytes());
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

/// One `(input block, factor)` pair of an Explicit Matrix packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplicitMatrixEntry {
    /// Index of the input block this factor applies to.
    pub block_index: u64,
    /// The Galois field factor, as stored (little-endian, field-size bytes).
    pub factor: u64,
}

/// The Explicit Matrix packet: one code-matrix row, listed element by element.
///
/// Element size comes from the set's Start packet, so this packet cannot be
/// parsed without one. The reference implementation does not write these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitMatrixPacket {
    /// Size of one factor in bytes, taken from the set's Galois field.
    pub factor_size: u8,
    /// The row's non-zero elements, in ascending block-index order.
    pub entries: Vec<ExplicitMatrixEntry>,
}

impl ExplicitMatrixPacket {
    /// Parse an Explicit Matrix packet body for a set whose field elements are
    /// `factor_size` bytes wide.
    pub fn parse(body: &[u8], factor_size: u8) -> Result<Self> {
        let reader = BodyReader::new(body, "Explicit Matrix");
        if factor_size == 0 || factor_size > 8 {
            return Err(reader.malformed(format!(
                "Galois field size {factor_size} cannot describe explicit factors"
            )));
        }
        let entry_len = 8 + usize::from(factor_size);
        if !body.len().is_multiple_of(entry_len) {
            return Err(reader.malformed(format!(
                "body of {} bytes is not a multiple of the {entry_len}-byte entry",
                body.len()
            )));
        }
        let mut reader = reader;
        // Bounded by the body length, not by a count read out of the packet.
        let mut entries = Vec::with_capacity(body.len() / entry_len);
        while reader.remaining() > 0 {
            let block_index = reader.u64()?;
            let mut factor = [0u8; 8];
            let stored = reader.take(usize::from(factor_size))?;
            factor[..stored.len()].copy_from_slice(stored);
            entries.push(ExplicitMatrixEntry {
                block_index,
                factor: u64::from_le_bytes(factor),
            });
        }
        Ok(Self {
            factor_size,
            entries,
        })
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        for entry in &self.entries {
            out.extend_from_slice(&entry.block_index.to_le_bytes());
            out.extend_from_slice(&entry.factor.to_le_bytes()[..usize::from(self.factor_size)]);
        }
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

/// The FFT Matrix packet, as written by the reference implementation for its
/// Leopard FFT Reed-Solomon codes.
///
/// No published specification defines this packet; its layout comes from the
/// reference implementation's own appendix. It is parsed here so that a set using
/// it can still be inspected and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FftMatrixPacket {
    /// Input blocks this matrix covers.
    pub range: BlockRange,
    /// Base-2 logarithm of the maximum recovery block count per cohort.
    ///
    /// A negative value selects the high-rate encoder, which the reference
    /// implementation does not implement and this crate does not interpret.
    pub max_recovery_blocks_log2: i8,
    /// Number of interleaved blocks, stored in as few little-endian bytes as it
    /// needs. The number of cohorts is this plus one.
    pub interleave: u64,
    /// How many bytes the interleave count occupied, so the packet can be written
    /// back byte for byte.
    pub interleave_len: u8,
}

impl FftMatrixPacket {
    /// Body length excluding the variable-length interleave count.
    pub const BODY_BASE_LEN: usize = 17;

    /// Parse an FFT Matrix packet body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut reader = BodyReader::new(body, "FFT Matrix");
        let range = BlockRange {
            first: reader.u64()?,
            end: reader.u64()?,
        };
        let max_recovery_blocks_log2 = reader.i8()?;
        let interleave_len = reader.remaining();
        if interleave_len > 8 {
            return Err(reader.malformed(format!(
                "interleave count of {interleave_len} bytes exceeds 8"
            )));
        }
        let mut interleave = [0u8; 8];
        interleave[..interleave_len].copy_from_slice(reader.take(interleave_len)?);
        Ok(Self {
            range,
            max_recovery_blocks_log2,
            interleave: u64::from_le_bytes(interleave),
            interleave_len: interleave_len as u8,
        })
    }

    /// Whether this packet selects the unimplemented high-rate encoder.
    #[must_use]
    pub fn is_high_rate(&self) -> bool {
        self.max_recovery_blocks_log2 < 0
    }

    /// Number of cohorts the interleaver splits input blocks into.
    #[must_use]
    pub fn cohort_count(&self) -> u64 {
        self.interleave.saturating_add(1)
    }

    /// Append the body bytes to `out`.
    pub fn write_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.range.first.to_le_bytes());
        out.extend_from_slice(&self.range.end.to_le_bytes());
        out.push(self.max_recovery_blocks_log2 as u8);
        out.extend_from_slice(&self.interleave.to_le_bytes()[..usize::from(self.interleave_len)]);
    }

    /// The body bytes as a fresh vector.
    #[must_use]
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_body(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cauchy_round_trips_the_oracle_body() {
        let body = [0u8; 24];
        let packet = CauchyMatrixPacket::parse(&body).expect("parses");
        assert!(packet.range.covers_all());
        assert_eq!(packet.recovery_block_hint, 0);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn cauchy_rejects_a_wrong_length() {
        assert!(CauchyMatrixPacket::parse(&[0u8; 23]).is_err());
        assert!(CauchyMatrixPacket::parse(&[0u8; 25]).is_err());
    }

    #[test]
    fn sparse_round_trips() {
        let mut body = Vec::new();
        for value in [1u64, 9, 4, 3, 0xdead_beef] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        let packet = SparseRandomMatrixPacket::parse(&body).expect("parses");
        assert_eq!(packet.range, BlockRange { first: 1, end: 9 });
        assert_eq!(packet.seed, 0xdead_beef);
        assert_eq!(packet.to_body_bytes(), body);
        assert!(SparseRandomMatrixPacket::parse(&body[..39]).is_err());
    }

    #[test]
    fn explicit_round_trips_for_a_two_byte_field() {
        let mut body = Vec::new();
        body.extend_from_slice(&5u64.to_le_bytes());
        body.extend_from_slice(&[0x34, 0x12]);
        body.extend_from_slice(&9u64.to_le_bytes());
        body.extend_from_slice(&[0x01, 0x00]);
        let packet = ExplicitMatrixPacket::parse(&body, 2).expect("parses");
        assert_eq!(packet.entries.len(), 2);
        assert_eq!(packet.entries[0].block_index, 5);
        assert_eq!(packet.entries[0].factor, 0x1234);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn explicit_rejects_a_field_free_set_and_a_ragged_body() {
        assert!(ExplicitMatrixPacket::parse(&[], 0).is_err());
        assert!(ExplicitMatrixPacket::parse(&[0u8; 9], 2).is_err());
        assert!(
            ExplicitMatrixPacket::parse(&[], 1)
                .expect("empty")
                .entries
                .is_empty()
        );
    }

    #[test]
    fn fft_round_trips_with_and_without_an_interleave_count() {
        let mut body = vec![0u8; 16];
        body.push(3);
        let packet = FftMatrixPacket::parse(&body).expect("parses");
        assert_eq!(packet.max_recovery_blocks_log2, 3);
        assert_eq!(packet.interleave, 0);
        assert_eq!(packet.cohort_count(), 1);
        assert!(!packet.is_high_rate());
        assert_eq!(packet.to_body_bytes(), body);

        body.extend_from_slice(&[0x02, 0x01]);
        let packet = FftMatrixPacket::parse(&body).expect("parses");
        assert_eq!(packet.interleave, 0x0102);
        assert_eq!(packet.cohort_count(), 0x0103);
        assert_eq!(packet.interleave_len, 2);
        assert_eq!(packet.to_body_bytes(), body);
    }

    #[test]
    fn fft_recognises_the_high_rate_encoder() {
        let mut body = vec![0u8; 16];
        body.push(0xff);
        let packet = FftMatrixPacket::parse(&body).expect("parses");
        assert_eq!(packet.max_recovery_blocks_log2, -1);
        assert!(packet.is_high_rate());
    }

    #[test]
    fn fft_rejects_a_short_body_and_an_oversized_interleave_count() {
        assert!(FftMatrixPacket::parse(&[0u8; 16]).is_err());
        assert!(FftMatrixPacket::parse(&[0u8; 26]).is_err());
    }
}
