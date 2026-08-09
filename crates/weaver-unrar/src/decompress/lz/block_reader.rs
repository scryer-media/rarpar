//! Bounded bit access for an already validated compressed block.
//!
//! The caller supplies a logical bit range followed by at least
//! [`LOOKAHEAD_BYTES`] readable bytes. The reader checks that contract once, then
//! exposes small infallible operations for the decode loop.  Operations may
//! inspect bytes after the logical block when peeking ahead. The caller validates
//! the final logical position after decoding.

use std::fmt;

/// Readable bytes required after the logical block for one complete symbol.
pub const LOOKAHEAD_BYTES: usize = 32;

/// Widest peek served by a single unaligned 32-bit load.
///
/// A load at `position >> 3` covers `32 - (position & 7)` valid bits, so 24
/// is the widest request that is always satisfied by one load.
const NARROW_PEEK_BITS: u8 = 24;

/// Failure returned while establishing or validating a bounded reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReaderError {
    InvalidRange {
        start_bit: usize,
        end_bit: usize,
    },
    RangeOutOfBounds {
        end_bit: usize,
        available_bits: usize,
    },
    MissingLookahead {
        required_end: usize,
        available: usize,
    },
    EndOvershoot {
        position: usize,
        end_bit: usize,
    },
}

impl fmt::Display for BlockReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange { start_bit, end_bit } => {
                write!(f, "invalid block bit range {start_bit}..{end_bit}")
            }
            Self::RangeOutOfBounds {
                end_bit,
                available_bits,
            } => write!(
                f,
                "block end bit {end_bit} exceeds available input bits {available_bits}"
            ),
            Self::MissingLookahead {
                required_end,
                available,
            } => write!(
                f,
                "block input needs {required_end} readable bytes, only {available} available"
            ),
            Self::EndOvershoot { position, end_bit } => {
                write!(f, "block ended at bit {position}, past its end {end_bit}")
            }
        }
    }
}

impl std::error::Error for BlockReaderError {}

/// A fast reader over one caller-validated bit range.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockReader<'a> {
    data: &'a [u8],
    end_bit: usize,
    position: usize,
}

impl<'a> BlockReader<'a> {
    /// Establish a reader over `start_bit..end_bit`.
    ///
    /// `data` must include enough readable bytes after the logical block for
    /// one complete symbol. These bytes can belong to the next compressed
    /// block; the logical end still controls what may be consumed.
    pub fn new(data: &'a [u8], start_bit: usize, end_bit: usize) -> Result<Self, BlockReaderError> {
        if start_bit > end_bit {
            return Err(BlockReaderError::InvalidRange { start_bit, end_bit });
        }

        let available_bits = data.len().saturating_mul(8);
        if end_bit > available_bits {
            return Err(BlockReaderError::RangeOutOfBounds {
                end_bit,
                available_bits,
            });
        }

        let guard_start = end_bit.saturating_add(7) / 8;
        let required_end = guard_start.saturating_add(LOOKAHEAD_BYTES);
        if required_end > data.len() {
            return Err(BlockReaderError::MissingLookahead {
                required_end,
                available: data.len(),
            });
        }

        Ok(Self {
            data,
            end_bit,
            position: start_bit,
        })
    }

    /// Return the logical end position supplied to the constructor.
    #[inline]
    pub fn end(&self) -> usize {
        self.end_bit
    }

    /// Return the current absolute bit position.
    #[inline]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Debug-only proof that a `width`-byte load at `byte` stays inside the
    /// staged source.
    ///
    /// Release builds carry no length compare: the constructor already proved
    /// `ceil(end_bit / 8) + LOOKAHEAD_BYTES <= data.len()`, and the decode loop
    /// re-tests `position < end` before every symbol while a single symbol
    /// consumes at most ~150 bits, so no load reaches past the staged guard.
    #[inline(always)]
    fn debug_check_load(&self, byte: usize, width: usize) {
        debug_assert!(
            byte + width <= self.data.len(),
            "block reader load of {width} bytes at byte {byte} exceeds {} staged bytes",
            self.data.len()
        );
    }

    /// Load the 32-bit window that starts at the current bit position.
    ///
    /// Mirrors UnRAR `getbits()` (getbits.hpp:34-46): one unaligned big-endian
    /// 32-bit load shifted so the current bit becomes the MSB. The top
    /// `32 - (position & 7)` bits are valid, hence [`NARROW_PEEK_BITS`].
    #[inline(always)]
    fn peek_window_u32(&self) -> u32 {
        let byte = self.position >> 3;
        let offset = (self.position & 7) as u32;
        self.debug_check_load(byte, 4);
        // SAFETY: `debug_check_load` documents the constructor contract that
        // keeps `byte + 4` inside `data`; the guard bytes after the logical
        // block are caller-supplied and readable.
        let raw = unsafe { load_be_u32(self.data, byte) };
        raw << offset
    }

    /// Peek at up to 64 MSB-first bits without advancing.
    ///
    /// This operation is intentionally not a logical-range check.  A decoder
    /// may use following staged bytes for lookahead, but it must finish at the
    /// logical boundary.
    #[inline(always)]
    pub fn peek_bits(&self, count: u8) -> u64 {
        debug_assert!(count <= 64);
        if count == 0 {
            return 0;
        }
        if count <= NARROW_PEEK_BITS {
            // One load covers the request; skip the wider two-load path.
            return u64::from(self.peek_window_u32() >> (32 - count as u32));
        }
        let value = self.peek_u64();
        if count == 64 {
            value
        } else {
            value >> (64 - count)
        }
    }

    /// Peek at the next 16 MSB-first bits as a big-endian value.
    #[inline(always)]
    pub fn peek_u16(&self) -> u16 {
        (self.peek_window_u32() >> 16) as u16
    }

    /// Peek at the next 32 MSB-first bits as a big-endian value.
    #[cfg(test)]
    #[inline(always)]
    pub fn peek_u32(&self) -> u32 {
        self.peek_bits(32) as u32
    }

    /// Peek at the next 64 MSB-first bits as a big-endian value.
    #[inline(always)]
    pub fn peek_u64(&self) -> u64 {
        let byte = self.position >> 3;
        let offset = self.position & 7;
        if offset == 0 {
            self.debug_check_load(byte, 8);
            // SAFETY: see `debug_check_load`; the constructor contract keeps
            // `byte + 8` inside the staged source.
            return unsafe { load_be_u64(self.data, byte) };
        }

        self.debug_check_load(byte, 9);
        // SAFETY: see `debug_check_load`; the constructor contract keeps
        // `byte + 9` inside the staged source for an unaligned window.
        let high = unsafe { load_be_u64(self.data, byte) };
        let low = unsafe { load_be_u64(self.data, byte + 1) };
        (high << offset) | (low >> (8 - offset))
    }

    /// Read and consume up to 64 MSB-first bits.
    #[inline(always)]
    pub fn read_bits(&mut self, count: u8) -> u64 {
        debug_assert!(count <= 64);
        let value = self.peek_bits(count);
        self.advance(count as usize);
        value
    }

    /// Read and consume 16 MSB-first bits.
    #[cfg(test)]
    #[inline(always)]
    pub fn read_u16(&mut self) -> u16 {
        let value = self.peek_u16();
        self.advance(16);
        value
    }

    /// Read and consume 32 MSB-first bits.
    #[cfg(test)]
    #[inline(always)]
    pub fn read_u32(&mut self) -> u32 {
        let value = self.peek_u32();
        self.advance(32);
        value
    }

    /// Advance by a number of bits. Final validation rejects logical overrun.
    #[inline(always)]
    pub fn advance(&mut self, count: usize) {
        self.position = self.position.saturating_add(count);
    }

    /// Validate that decoding stayed inside the logical block range.
    ///
    /// UnRAR ends a block as soon as the cursor reaches the block border and
    /// simply leaves whatever padding bits follow (unpack50mt.cpp:318-322), so
    /// only overshoot is a real failure. Undershoot is tolerated.
    #[inline]
    pub fn validate_end(&self) -> Result<(), BlockReaderError> {
        if self.position <= self.end_bit {
            Ok(())
        } else {
            Err(BlockReaderError::EndOvershoot {
                position: self.position,
                end_bit: self.end_bit,
            })
        }
    }

    /// Consume the reader and validate its final logical position.
    #[cfg(test)]
    #[inline]
    pub fn finish(self) -> Result<(), BlockReaderError> {
        self.validate_end()
    }
}

// The constructor proves that every load for one complete symbol remains in
// the supplied source. Unaligned reads avoid constructing temporary slices in
// the decode loop and are valid on every supported target.
//
// SAFETY (both helpers): callers must keep `byte + size_of::<T>() <=
// data.len()`. Every call site goes through `BlockReader::debug_check_load`,
// which asserts that in debug builds and documents why the constructor
// contract makes it hold in release builds.
#[inline(always)]
unsafe fn load_be_u32(data: &[u8], byte: usize) -> u32 {
    unsafe {
        u32::from_be(std::ptr::read_unaligned(
            data.as_ptr().add(byte) as *const u32
        ))
    }
}

#[inline(always)]
unsafe fn load_be_u64(data: &[u8], byte: usize) -> u64 {
    unsafe {
        u64::from_be(std::ptr::read_unaligned(
            data.as_ptr().add(byte) as *const u64
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockReader, BlockReaderError, LOOKAHEAD_BYTES};

    fn with_guard(mut data: Vec<u8>) -> Vec<u8> {
        data.resize(data.len() + LOOKAHEAD_BYTES, 0);
        data
    }

    fn model_peek(data: &[u8], position: usize, count: usize) -> u64 {
        let mut value = 0;
        for bit in position..position + count {
            value = (value << 1) | u64::from((data[bit / 8] >> (7 - bit % 8)) & 1);
        }
        value
    }

    #[test]
    fn aligned_peeks_and_reads_use_big_endian_order() {
        let data = with_guard(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        let mut reader = BlockReader::new(&data, 0, 64).unwrap();

        assert_eq!(reader.peek_u16(), 0x1234);
        assert_eq!(reader.peek_u32(), 0x1234_5678);
        assert_eq!(reader.peek_u64(), 0x1234_5678_9abc_def0);
        assert_eq!(reader.read_u16(), 0x1234);
        assert_eq!(reader.read_u32(), 0x5678_9abc);
        assert_eq!(reader.read_u16(), 0xdef0);
        reader.finish().unwrap();
    }

    #[test]
    fn unaligned_values_match_bit_order() {
        let data = with_guard(vec![0xa5, 0x3c, 0xf0, 0x19, 0x82, 0x77, 0x41, 0xe0]);
        let mut reader = BlockReader::new(&data, 3, 61).unwrap();

        assert_eq!(reader.peek_u16(), model_peek(&data, 3, 16) as u16);
        assert_eq!(reader.peek_u32(), model_peek(&data, 3, 32) as u32);
        assert_eq!(reader.peek_u64(), model_peek(&data, 3, 64));
        assert_eq!(reader.read_bits(7), model_peek(&data, 3, 7));
        assert_eq!(reader.read_u16(), model_peek(&data, 10, 16) as u16);
        reader.advance(28);
        assert_eq!(reader.position(), 54);
        assert_eq!(reader.read_bits(7), model_peek(&data, 54, 7));
        reader.finish().unwrap();
    }

    #[test]
    fn guard_reads_are_zero_without_advancing() {
        let data = with_guard(vec![0xff]);
        let reader = BlockReader::new(&data, 0, 8).unwrap();
        assert_eq!(reader.peek_u64(), 0xff00_0000_0000_0000);

        let reader = BlockReader::new(&data, 8, 8).unwrap();
        assert_eq!(reader.peek_u16(), 0);
        assert_eq!(reader.peek_u32(), 0);
        assert_eq!(reader.peek_u64(), 0);
        assert_eq!(reader.position(), 8);
    }

    #[test]
    fn constructor_rejects_invalid_ranges_and_guards() {
        let data = vec![0; 16];
        assert_eq!(
            BlockReader::new(&data, 9, 8),
            Err(BlockReaderError::InvalidRange {
                start_bit: 9,
                end_bit: 8
            })
        );
        assert!(matches!(
            BlockReader::new(&[0; 8], 0, 1),
            Err(BlockReaderError::MissingLookahead { .. })
        ));
        assert!(matches!(
            BlockReader::new(&[0; 8], 0, 65),
            Err(BlockReaderError::RangeOutOfBounds { .. })
        ));

        let mut following = vec![0; 1 + LOOKAHEAD_BYTES];
        following[1] = 1;
        assert!(BlockReader::new(&following, 0, 1).is_ok());
    }

    #[test]
    fn final_boundary_rejects_only_overshoot() {
        // UnRAR stops at the block border and tolerates trailing padding, so
        // an undershoot is valid and only passing the border is an error.
        let data = with_guard(vec![0xff, 0x00]);
        let mut reader = BlockReader::new(&data, 0, 12).unwrap();
        reader.advance(8);
        reader.validate_end().unwrap();
        reader.advance(4);
        reader.validate_end().unwrap();
        reader.advance(1);
        assert_eq!(
            reader.validate_end(),
            Err(BlockReaderError::EndOvershoot {
                position: 13,
                end_bit: 12
            })
        );

        let reader = BlockReader::new(&data, 0, 12).unwrap();
        reader.finish().unwrap();
    }

    #[test]
    fn reads_match_checked_model_at_many_offsets() {
        let source: Vec<u8> = (0..32)
            .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
            .collect();
        for start in 0usize..8 {
            let end = start + 8 * 23;
            let guard_start = end.div_ceil(8);
            let mut data = source[..guard_start].to_vec();
            data.resize(guard_start + LOOKAHEAD_BYTES, 0);
            let mut reader = BlockReader::new(&data, start, end).unwrap();
            let mut position = start;
            while position + 64 <= end {
                assert_eq!(
                    reader.peek_u64(),
                    model_peek(&data, position, 64),
                    "offset {position}"
                );
                assert_eq!(reader.read_bits(1), model_peek(&data, position, 1));
                position += 1;
                let count = position % 31 + 1;
                if position + count > end {
                    break;
                }
                assert_eq!(
                    reader.read_bits(count as u8),
                    model_peek(&data, position, count),
                    "offset {position}, count {count}"
                );
                position += count;
            }
            reader.advance(end - position);
            reader.finish().unwrap();
        }
    }

    #[test]
    fn narrow_peeks_match_checked_model_at_every_offset() {
        // The single-load path serves peek_u16 and every peek_bits/read_bits
        // request up to NARROW_PEEK_BITS. Walk every bit offset in a whole
        // byte-aligned run and compare against the bit-by-bit model.
        let source: Vec<u8> = (0..24)
            .map(|index| (index as u8).wrapping_mul(151).wrapping_add(7))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;

        for start in 0..end {
            let reader = BlockReader::new(&data, start, end).unwrap();
            assert_eq!(
                u64::from(reader.peek_u16()),
                model_peek(&data, start, 16),
                "peek_u16 at {start}"
            );
            for count in 0..=super::NARROW_PEEK_BITS {
                assert_eq!(
                    reader.peek_bits(count),
                    model_peek(&data, start, count as usize),
                    "peek_bits({count}) at {start}"
                );
            }
            // The wide path must agree with the narrow one where they overlap.
            for count in super::NARROW_PEEK_BITS..=64 {
                assert_eq!(
                    reader.peek_bits(count),
                    model_peek(&data, start, count as usize),
                    "wide peek_bits({count}) at {start}"
                );
            }
        }
    }

    #[test]
    fn narrow_reads_advance_and_match_model() {
        let source: Vec<u8> = (0..24)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(211))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;

        for count in 1..=super::NARROW_PEEK_BITS {
            let mut reader = BlockReader::new(&data, 0, end).unwrap();
            let mut position = 0usize;
            while position + count as usize <= end {
                assert_eq!(
                    reader.read_bits(count),
                    model_peek(&data, position, count as usize),
                    "read_bits({count}) at {position}"
                );
                position += count as usize;
                assert_eq!(reader.position(), position);
            }
            reader.validate_end().unwrap();
        }
    }
}
