//! Bounded bit access for an already validated compressed block.
//!
//! The caller supplies a logical bit range followed by at least
//! [`LOOKAHEAD_BYTES`] readable bytes. The reader checks that contract once, then
//! exposes small infallible operations for the decode loop.  Operations may
//! inspect bytes after the logical block when peeking ahead. The caller validates
//! the final logical position after decoding.
//!
//! Reads are served from a cached 64-bit window rather than one load per bit
//! field. Decoding a single match touches five bit fields — the length/literal
//! code, its length extra, the distance code, its distance extra and the
//! low-distance code — which used to be five unaligned loads of the same one or
//! two cache lines. The window is rebuilt by [`BlockReader::advance`] whenever
//! it falls below [`MIN_WINDOW_BITS`], so those five fields cost one or two
//! loads between them and every peek in between is a register shift.

use std::fmt;

/// Readable bytes required after the logical block for one complete symbol.
pub const LOOKAHEAD_BYTES: usize = 32;

/// Widest peek served by a single unaligned 32-bit load.
///
/// A load at `position >> 3` covers `32 - (position & 7)` valid bits, so 24
/// is the widest request that is always satisfied by one load.
const NARROW_PEEK_BITS: u8 = 24;

/// Bits the cached window is kept at or above.
///
/// A refill yields `64 - (position & 7)` bits, i.e. at least 57, so the window
/// is rebuilt at most once per 25 consumed bits. Any request up to this width —
/// every Huffman peek and every length or distance extra a RAR5 stream can
/// ask for — is therefore always answered from the register. Wider requests
/// fall through to the same direct loads this reader has always used.
const MIN_WINDOW_BITS: u8 = 32;

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
    /// The bits at `position`, left-aligned: bit 63 is the bit at `position`.
    ///
    /// Only the top `acc_bits` are data; everything below is shifted-in zero
    /// padding and is never served.
    acc: u64,
    /// Valid high bits of [`Self::acc`]. Zero means "no window": every read
    /// then takes the direct-load path, exactly as it did before the window
    /// existed.
    acc_bits: u8,
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

        let mut reader = Self {
            data,
            end_bit,
            position: start_bit,
            acc: 0,
            acc_bits: 0,
        };
        reader.refill();
        Ok(reader)
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
    /// [`Self::refill`] is bounded more tightly still — it never loads past
    /// `end_bit`, which the constructor contract alone puts inside `data`.
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

    /// Rebuild the cached window at the current position.
    ///
    /// One unaligned 64-bit load at the byte holding `position`, shifted so
    /// that bit becomes the MSB — the same primitive and the same MSB-first
    /// order as [`Self::peek_window_u32`], one size up. Discarding the partial
    /// leading byte leaves `64 - (position & 7)` valid bits, so a refill never
    /// needs the second load the unaligned [`Self::peek_u64`] path takes.
    ///
    /// Refills stop at the logical end. Within the block the load is covered by
    /// the constructor's proof — `ceil(end_bit / 8) + LOOKAHEAD_BYTES <=
    /// data.len()` puts `(position >> 3) + 8` at least 24 bytes inside `data`
    /// for every `position <= end_bit`. Past the end the window is dropped
    /// instead, which leaves the lookahead region reachable only through the
    /// direct loads below, whose bounds argument is unchanged: the decode loop
    /// re-tests `position < end` before every symbol and one symbol consumes at
    /// most ~150 bits, so no load reaches past the staged guard.
    #[inline(always)]
    fn refill(&mut self) {
        if self.position > self.end_bit {
            self.acc = 0;
            self.acc_bits = 0;
            return;
        }
        let byte = self.position >> 3;
        let offset = (self.position & 7) as u32;
        self.debug_check_load(byte, 8);
        // SAFETY: see the doc comment; `position <= end_bit` plus the
        // constructor contract keeps `byte + 8` inside the staged source.
        let raw = unsafe { load_be_u64(self.data, byte) };
        self.acc = raw << offset;
        self.acc_bits = 64 - offset as u8;
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
        if count <= self.acc_bits {
            // Served from the register. `count == 64` only reaches here with a
            // full window, where no shift is needed.
            return if count == 64 {
                self.acc
            } else {
                self.acc >> (64 - count)
            };
        }
        if count <= NARROW_PEEK_BITS {
            // One load covers the request; skip the wider two-load path.
            return u64::from(self.peek_window_u32() >> (32 - count as u32));
        }
        // Reaching here means `acc_bits < count <= 64`, so the window is never
        // wide enough to serve this and `peek_u64` goes straight to the loads.
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
        if self.acc_bits >= 16 {
            return (self.acc >> 48) as u16;
        }
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
        if self.acc_bits == 64 {
            return self.acc;
        }
        self.peek_u64_direct()
    }

    /// The pre-window 64-bit peek: one aligned load, or two unaligned ones.
    #[inline(always)]
    fn peek_u64_direct(&self) -> u64 {
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
    ///
    /// Consuming from the window is a shift; an advance that would leave fewer
    /// than [`MIN_WINDOW_BITS`] behind rebuilds it, and one wider than the
    /// window holds — a byte alignment, a skip over a whole payload — drops it
    /// and recomputes from `data`. `count` is unrestricted either way: the
    /// position arithmetic is still saturating and still the only thing
    /// [`Self::validate_end`] judges.
    #[inline(always)]
    pub fn advance(&mut self, count: usize) {
        self.position = self.position.saturating_add(count);
        if count < usize::from(self.acc_bits) {
            // `count < acc_bits <= 64` keeps the shift in range.
            self.acc <<= count;
            self.acc_bits -= count as u8;
            if self.acc_bits >= MIN_WINDOW_BITS {
                return;
            }
        } else {
            self.acc_bits = 0;
        }
        self.refill();
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

    /// The staged source this reader was built over.
    ///
    /// Returned with the source lifetime, not the borrow's, so a decode loop
    /// can hold the slice while it hands the reader back its cursor.
    #[inline(always)]
    pub(super) fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Copy the bit cursor out for a register-resident decode loop.
    ///
    /// See [`BitCursor`]: the loop drives the copy and writes it back once, so
    /// the three fields live in registers instead of being re-stored and
    /// re-loaded around every symbol.
    #[inline(always)]
    pub(super) fn export_cursor(&self) -> BitCursor {
        BitCursor {
            acc: self.acc,
            acc_bits: u32::from(self.acc_bits),
            pos: self.position,
        }
    }

    /// Install a cursor a decode loop advanced.
    ///
    /// A plain field write: the cursor operations maintain exactly the
    /// invariants [`Self::advance`] does, and logical-range judgement is still
    /// [`Self::validate_end`]'s alone — the caller's loop guard is what keeps
    /// `pos` monotonic.
    #[inline(always)]
    pub(super) fn import_cursor(&mut self, cursor: BitCursor) {
        debug_assert!(cursor.acc_bits <= 64);
        self.acc = cursor.acc;
        self.acc_bits = cursor.acc_bits as u8;
        self.position = cursor.pos;
    }
}

/// The mutable half of a [`BlockReader`], detached so it can live in registers.
///
/// A worker decode loop reaches its reader through a `&mut` its caller owns, so
/// LLVM has to treat `acc`/`acc_bits`/`position` as memory: every symbol stores
/// the shifted accumulator back and reloads it, and on x86-64 the narrow
/// `acc_bits` reload from the middle of the 8-byte accumulator slot adds a
/// store-forwarding stall on top. Measured on the RAR5 decode loop, that
/// round-trip was 42.6% of loop samples.
///
/// The loop instead exports this copy once, runs entirely on it through the
/// `cursor_*` functions below, and imports it back at every exit. The
/// operations are the [`BlockReader`] methods verbatim — same refill threshold,
/// same narrow/wide split, same drop-window-past-the-end rule, same
/// constructor-proven bounds contract — with the reader's fields replaced by
/// this struct plus the `data`/`end_bit` the caller passes in. `acc_bits` is
/// widened to `u32` purely to keep it a register-width field; every value it
/// takes is still `0..=64`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BitCursor {
    /// The bits at `pos`, left-aligned — [`BlockReader::acc`].
    pub acc: u64,
    /// Valid high bits of `acc` — [`BlockReader::acc_bits`], widened.
    pub acc_bits: u32,
    /// Absolute bit position — [`BlockReader::position`].
    pub pos: usize,
}

/// Debug-only proof that a `width`-byte load at `byte` stays inside `data`.
///
/// The cursor half of [`BlockReader::debug_check_load`], and the same argument:
/// release builds carry no length compare because the reader's constructor
/// already proved `ceil(end_bit / 8) + LOOKAHEAD_BYTES <= data.len()`, and a
/// cursor is only ever created from a constructed reader.
#[inline(always)]
fn debug_check_cursor_load(data: &[u8], byte: usize, width: usize) {
    debug_assert!(
        byte + width <= data.len(),
        "block cursor load of {width} bytes at byte {byte} exceeds {} staged bytes",
        data.len()
    );
}

/// Cursor form of [`BlockReader::peek_window_u32`].
#[inline(always)]
fn cursor_peek_window_u32(cursor: &BitCursor, data: &[u8]) -> u32 {
    let byte = cursor.pos >> 3;
    let offset = (cursor.pos & 7) as u32;
    debug_check_cursor_load(data, byte, 4);
    // SAFETY: as `BlockReader::peek_window_u32` — the constructor contract that
    // built this cursor's reader keeps `byte + 4` inside `data`.
    let raw = unsafe { load_be_u32(data, byte) };
    raw << offset
}

/// Cursor form of [`BlockReader::refill`].
#[inline(always)]
pub(super) fn cursor_refill(cursor: &mut BitCursor, data: &[u8], end_bit: usize) {
    if cursor.pos > end_bit {
        cursor.acc = 0;
        cursor.acc_bits = 0;
        return;
    }
    let byte = cursor.pos >> 3;
    let offset = (cursor.pos & 7) as u32;
    debug_check_cursor_load(data, byte, 8);
    // SAFETY: as `BlockReader::refill` — `pos <= end_bit` plus the constructor
    // contract keeps `byte + 8` inside the staged source.
    let raw = unsafe { load_be_u64(data, byte) };
    cursor.acc = raw << offset;
    cursor.acc_bits = 64 - offset;
}

/// Cursor form of [`BlockReader::peek_u64_direct`].
#[inline(always)]
fn cursor_peek_u64_direct(cursor: &BitCursor, data: &[u8]) -> u64 {
    let byte = cursor.pos >> 3;
    let offset = cursor.pos & 7;
    if offset == 0 {
        debug_check_cursor_load(data, byte, 8);
        // SAFETY: as `BlockReader::peek_u64_direct`.
        return unsafe { load_be_u64(data, byte) };
    }

    debug_check_cursor_load(data, byte, 9);
    // SAFETY: as `BlockReader::peek_u64_direct`.
    let high = unsafe { load_be_u64(data, byte) };
    let low = unsafe { load_be_u64(data, byte + 1) };
    (high << offset) | (low >> (8 - offset))
}

/// Cursor form of [`BlockReader::peek_u64`].
#[inline(always)]
pub(super) fn cursor_peek_u64(cursor: &BitCursor, data: &[u8]) -> u64 {
    if cursor.acc_bits == 64 {
        return cursor.acc;
    }
    cursor_peek_u64_direct(cursor, data)
}

/// Cursor form of [`BlockReader::peek_u16`].
#[inline(always)]
pub(super) fn cursor_peek_u16(cursor: &BitCursor, data: &[u8]) -> u16 {
    if cursor.acc_bits >= 16 {
        return (cursor.acc >> 48) as u16;
    }
    (cursor_peek_window_u32(cursor, data) >> 16) as u16
}

/// Cursor form of [`BlockReader::peek_bits`].
#[inline(always)]
pub(super) fn cursor_peek_bits(cursor: &BitCursor, data: &[u8], count: u8) -> u64 {
    debug_assert!(count <= 64);
    if count == 0 {
        return 0;
    }
    if u32::from(count) <= cursor.acc_bits {
        return if count == 64 {
            cursor.acc
        } else {
            cursor.acc >> (64 - count)
        };
    }
    if count <= NARROW_PEEK_BITS {
        return u64::from(cursor_peek_window_u32(cursor, data) >> (32 - u32::from(count)));
    }
    let value = cursor_peek_u64(cursor, data);
    if count == 64 {
        value
    } else {
        value >> (64 - count)
    }
}

/// Cursor form of [`BlockReader::advance`].
#[inline(always)]
pub(super) fn cursor_advance(cursor: &mut BitCursor, data: &[u8], end_bit: usize, count: usize) {
    cursor.pos = cursor.pos.saturating_add(count);
    if count < cursor.acc_bits as usize {
        // `count < acc_bits <= 64` keeps the shift in range.
        cursor.acc <<= count;
        cursor.acc_bits -= count as u32;
        if cursor.acc_bits >= u32::from(MIN_WINDOW_BITS) {
            return;
        }
    } else {
        cursor.acc_bits = 0;
    }
    cursor_refill(cursor, data, end_bit);
}

/// Cursor form of [`BlockReader::read_bits`].
#[inline(always)]
pub(super) fn cursor_read_bits(
    cursor: &mut BitCursor,
    data: &[u8],
    end_bit: usize,
    count: u8,
) -> u64 {
    debug_assert!(count <= 64);
    let value = cursor_peek_bits(cursor, data, count);
    cursor_advance(cursor, data, end_bit, count as usize);
    value
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
                // The cached window has to agree with the wide peek above at
                // whatever fill level the previous reads left it in.
                assert_eq!(
                    u64::from(reader.peek_u16()),
                    model_peek(&data, position, 16),
                    "peek_u16 at offset {position}"
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
                // Every narrow width is served from the cached window, at every
                // fill level a run of `count`-bit reads can produce.
                assert!(reader.acc_bits >= super::MIN_WINDOW_BITS);
                assert_eq!(
                    u64::from(reader.peek_u16()),
                    model_peek(&data, position, 16),
                    "peek_u16 before read_bits({count}) at {position}"
                );
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

    /// The window is rebuilt by `advance`, so what a peek reads depends on how
    /// much was consumed since the last refill. Walk every advance width and
    /// compare each peek against the bit-by-bit model.
    #[test]
    fn windowed_peeks_match_the_model_across_refill_boundaries() {
        let source: Vec<u8> = (0..96)
            .map(|index| (index as u8).wrapping_mul(97).wrapping_add(53))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;

        for step in 1..=64usize {
            let mut reader = BlockReader::new(&data, 0, end).unwrap();
            let mut position = 0usize;
            while position + 64 <= end {
                // Inside the block the window always covers a narrow request,
                // whatever the advance pattern was.
                assert!(
                    reader.acc_bits >= super::MIN_WINDOW_BITS,
                    "window collapsed at {position} with step {step}"
                );
                assert_eq!(
                    u64::from(reader.peek_u16()),
                    model_peek(&data, position, 16),
                    "peek_u16 at {position}, step {step}"
                );
                for count in [1u8, 7, 15, 16, 23, 24, 25, 31, 32, 33, 47, 57, 64] {
                    assert_eq!(
                        reader.peek_bits(count),
                        model_peek(&data, position, count as usize),
                        "peek_bits({count}) at {position}, step {step}"
                    );
                }
                assert_eq!(
                    reader.peek_u64(),
                    model_peek(&data, position, 64),
                    "peek_u64 at {position}, step {step}"
                );
                reader.advance(step);
                position += step;
                assert_eq!(reader.position(), position);
            }
            reader.advance(end - position);
            reader.finish().unwrap();
        }
    }

    /// One match reads five bit fields in a row — the length/literal code, its
    /// length extra, the distance code, its distance extra and the low-distance
    /// code. Refills land in the middle of that group, so walk the whole shape
    /// at every bit offset with a peek before each read.
    #[test]
    fn interleaved_reads_and_peeks_match_the_model() {
        let source: Vec<u8> = (0..64)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(131))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;
        let widths = [9u8, 5, 7, 34, 4];

        for start in 0..64 {
            let mut reader = BlockReader::new(&data, start, end).unwrap();
            let mut position = start;
            'block: while position + 64 <= end {
                for width in widths {
                    assert_eq!(
                        u64::from(reader.peek_u16()),
                        model_peek(&data, position, 16),
                        "peek_u16 before read_bits({width}) at {position}"
                    );
                    assert_eq!(
                        reader.read_bits(width),
                        model_peek(&data, position, width as usize),
                        "read_bits({width}) at {position}"
                    );
                    position += width as usize;
                    assert_eq!(reader.position(), position);
                    if position + 64 > end {
                        break 'block;
                    }
                }
            }
            reader.advance(end - position);
            reader.finish().unwrap();
        }
    }

    #[test]
    fn oversized_advance_rebuilds_the_window_from_data() {
        let source: Vec<u8> = (0..40)
            .map(|index| (index as u8).wrapping_mul(83).wrapping_add(11))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;
        let mut reader = BlockReader::new(&data, 0, end).unwrap();

        // Wider than the window holds: it is dropped and rebuilt at the new
        // position rather than shifted.
        reader.advance(64);
        assert_eq!(reader.position(), 64);
        assert_eq!(u64::from(reader.peek_u16()), model_peek(&data, 64, 16));
        assert_eq!(reader.peek_u64(), model_peek(&data, 64, 64));

        reader.advance(100);
        assert_eq!(reader.read_bits(24), model_peek(&data, 164, 24));
        assert_eq!(reader.position(), 188);

        reader.advance(end - 188);
        reader.finish().unwrap();
    }

    /// The cursor operations are the reader's, so every one of them has to
    /// return the same bits *and* leave the same window state — otherwise the
    /// fast decode loop would diverge from the checked one mid-block.
    #[test]
    fn cursor_operations_mirror_the_reader_state_for_state() {
        let source: Vec<u8> = (0..96)
            .map(|index| (index as u8).wrapping_mul(61).wrapping_add(17))
            .collect();
        let mut data = source.clone();
        data.resize(source.len() + LOOKAHEAD_BYTES, 0);
        let end = source.len() * 8;
        // Widths spanning the register path, the single-load narrow path and
        // the two-load wide path, plus the refill boundary in between.
        let widths = [1u8, 5, 9, 16, 23, 24, 25, 31, 32, 33, 47, 57, 64];

        for start in 0..16 {
            let mut reader = BlockReader::new(&data, start, end).unwrap();
            let mut cursor = reader.export_cursor();
            assert_eq!(
                (cursor.acc, cursor.acc_bits, cursor.pos),
                (reader.acc, u32::from(reader.acc_bits), reader.position())
            );

            let mut step = 0usize;
            // Run past the logical end so the drop-window rule and the guard
            // reads are compared too. The bound keeps the widest peek from the
            // last admitted position inside the staged guard.
            while cursor.pos <= end + 64 {
                assert_eq!(
                    super::cursor_peek_u16(&cursor, &data),
                    reader.peek_u16(),
                    "peek_u16 at {} (start {start})",
                    cursor.pos
                );
                assert_eq!(
                    super::cursor_peek_u64(&cursor, &data),
                    reader.peek_u64(),
                    "peek_u64 at {} (start {start})",
                    cursor.pos
                );
                for count in 0..=64u8 {
                    assert_eq!(
                        super::cursor_peek_bits(&cursor, &data, count),
                        reader.peek_bits(count),
                        "peek_bits({count}) at {} (start {start})",
                        cursor.pos
                    );
                }

                let width = widths[step % widths.len()];
                let cursor_value = super::cursor_read_bits(&mut cursor, &data, end, width);
                let reader_value = reader.read_bits(width);
                assert_eq!(
                    cursor_value, reader_value,
                    "read_bits({width}) (start {start})"
                );
                assert_eq!(
                    (cursor.acc, cursor.acc_bits, cursor.pos),
                    (reader.acc, u32::from(reader.acc_bits), reader.position()),
                    "state after read_bits({width}) (start {start})"
                );

                // An oversized advance drops the window on both sides.
                let skip = (step % 5) * 21;
                super::cursor_advance(&mut cursor, &data, end, skip);
                reader.advance(skip);
                assert_eq!(
                    (cursor.acc, cursor.acc_bits, cursor.pos),
                    (reader.acc, u32::from(reader.acc_bits), reader.position()),
                    "state after advance({skip}) (start {start})"
                );
                step += 1;
            }

            // Importing the cursor reproduces the reader it was exported from.
            let mut imported = BlockReader::new(&data, start, end).unwrap();
            imported.import_cursor(cursor);
            assert_eq!(imported, reader);
            assert_eq!(imported.validate_end(), reader.validate_end());
        }
    }

    #[test]
    fn peeks_past_the_logical_end_still_read_the_guard() {
        let data = with_guard(vec![0xff, 0xff]);
        let mut reader = BlockReader::new(&data, 0, 16).unwrap();

        // Consuming the whole block leaves the window sitting on guard bytes.
        reader.advance(16);
        assert_eq!(reader.peek_u16(), 0);
        assert_eq!(reader.peek_bits(24), 0);
        assert_eq!(reader.peek_u64(), 0);
        reader.validate_end().unwrap();

        // Overshooting drops the window; the direct loads still see the guard.
        reader.advance(40);
        assert_eq!(reader.acc_bits, 0);
        assert_eq!(reader.peek_u16(), 0);
        assert_eq!(reader.peek_bits(24), 0);
        assert_eq!(reader.peek_u64(), 0);
        assert!(reader.validate_end().is_err());
    }
}
