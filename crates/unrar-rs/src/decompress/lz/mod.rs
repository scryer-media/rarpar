//! LZ block decompression orchestrator for RAR5.
//!
//! RAR5 compressed data is organized into blocks, each with a byte-aligned
//! header followed by Huffman-encoded LZ data. Unlike RAR3, RAR5 uses only
//! LZ+Huffman compression (no PPMd blocks).
//!
//! Block header (byte-aligned):
//! - `flags` (1 byte): `bit_size[0:2]`, `byte_count[3:4]`, `is_last[6]`,
//!   `table_present[7]`
//! - `checksum` (1 byte): XOR of flags and all size bytes, must equal 0x5A
//! - `block_size_bytes` (1-3 bytes, LE): high part of block size
//! - Extra bits from bitstream: low part of block size (bit_size+1 bits)
//!
//! Symbol interpretation (NC table, 306 symbols):
//! - 0-255: literal bytes
//! - 256: filter marker
//! - 257: repeat previous match (same length, same `distance[0]`)
//! - 258-261: repeat distance cache references (length from RC table)
//! - 262-305: inline length codes with extra bits (distance from DC/LDC tables)

pub(super) mod batch_plan;
pub mod bitstream;
pub(super) mod block_reader;
pub mod filter;
pub mod huffman;
mod parallel;
pub(super) mod phase_diagnostics;
pub(super) mod staged_input;
pub mod window;

use std::io::{Read, Write};
use std::sync::Arc;

use tracing::trace;

use crate::error::{RarError, RarResult};
use crate::limits::{Limits, RAR_MIN_LZ_WINDOW_SIZE, RAR_UNPACK_MAX_DICT_SIZE};
use crate::types::CompressionInfo;
use bitstream::{BitRead, BitReader, StreamingBitReader};
use filter::{FilterType, PendingFilter};
use huffman::HuffmanTable;
use staged_input::StagedInput;
use window::Window;

/// Maximum number of length slots.
const NUM_LENGTH_SLOTS: usize = 44;

/// Number of entries in the last-distance cache.
const DIST_CACHE_SIZE: usize = 4;

/// Maximum number of pending filters to hold before treating the archive as invalid.
/// Defensive RAR filter queue bound.
const MAX_PENDING_FILTERS: usize = 8192;

/// Maximum filter block size accepted from the bitstream.
/// RAR filter blocks above this size are treated as invalid.
const MAX_FILTER_BLOCK_SIZE: usize = 0x400000;

/// Maximum number of bytes to accumulate before flushing decoded output.
const UNPACK_MAX_WRITE: usize = 0x400000;
const STREAMING_PARALLEL_MIN_PROCESS_SIZE: usize = 1024;
/// Trailing staged bytes treated as unreliable for header/table parsing while
/// more input may follow: a block header plus full Huffman tables fit well
/// within this margin, so anything parsed before it only touches real bits.
const STREAMING_HEADER_MARGIN: usize = 1024;
/// Bit margin the mid-block staged decode keeps in reserve so no symbol read
/// can reach the staging edge, where 16-bit peeks would otherwise fabricate
/// zero bits in place of real, not-yet-staged data.
/// The widest RAR5 symbol (code + length extra + distance code + high distance
/// bits + align code, or a filter descriptor) stays under 128 bits.
const STREAMING_SYMBOL_MARGIN_BITS: i64 = 512;
const STREAMING_LARGE_BLOCK_BYTES: i64 = 0x20000;
const MAX_INCREMENTAL_LZ_MATCH: u64 = 0x1004;

/// State for the LZ decompressor.
pub struct LzDecoder {
    /// Sliding window / ring buffer.
    window: Window,
    /// Last-distance cache (4 entries for repeat matches).
    dist_cache: [usize; DIST_CACHE_SIZE],
    /// Length of the last match (for symbol 257 repeat).
    last_length: usize,
    /// Current Huffman tables (kept across blocks when table_present is false).
    nc_table: Option<Arc<HuffmanTable>>,
    dc_table: Option<Arc<HuffmanTable>>,
    ldc_table: Option<Arc<HuffmanTable>>,
    rc_table: Option<Arc<HuffmanTable>>,
    /// Persistent code lengths for delta encoding across blocks.
    code_lengths: Vec<u8>,
    /// RAR7 uses larger distance tables and longer high-distance reads.
    extra_dist: bool,
    /// Number of compressed bits remaining in the current block.
    /// When 0, a new block header must be read.
    block_bits_remaining: i64,
    /// Whether the current block is the last one.
    is_last_block: bool,
    /// Filters pending application to ranges of the current output.
    ///
    /// Kept sorted by `block_start` by [`filter::push_pending_filter`], so the
    /// flush path can drain completed filters off the front without sorting.
    pending_filters: Vec<PendingFilter>,
    /// Precomputed absolute output offset at which the next write happens.
    ///
    /// RAR compares one precomputed `WriteBorder` per symbol instead of
    /// recomputing a threshold; the flush routines re-derive this after every
    /// write. See [`Self::recompute_flush_border`].
    flush_at: u64,
    /// Absolute output offset where the current file begins in the window.
    current_file_base_total: u64,
    /// `Unpack::WrittenFileSize` for the current file.
    ///
    /// The oracle's counter, not a count of emitted bytes: `UnpWriteData`
    /// advances it by the *full* span it was handed even when it clamped the
    /// write to the declared size, and stops advancing once it has reached that
    /// size (unpack50.cpp:538-548). It advances by filter block length even
    /// when an unsupported filter suppresses the output, and it is what the
    /// E8/ARM filters take their file offset from.
    current_file_written_size: u64,
    /// Bytes this member has actually handed to the writer.
    ///
    /// Differs from `current_file_written_size` on exactly the streams this
    /// bounding is about: a clamped raw span advances the counter without
    /// emitting, and a filtered block is emitted without being clamped.
    current_file_emitted: u64,
    /// The member's declared unpacked size, i.e. the oracle's `DestUnpSize`.
    current_file_unpacked_size: u64,
    /// Recycled decoded-item buffers for one bounded RAR5 controller batch.
    /// Workers fill these slots before the caller applies them in archive order.
    parallel_item_buffer_sets: Vec<Vec<Vec<parallel::DecodedItem>>>,
    /// Recycled per-batch controller bookkeeping (assignments, worker results).
    ///
    /// More than one is cached: the pipelined controller keeps one batch in
    /// flight on the pool while the previous batch is applied on its thread.
    parallel_batch_scratch: Vec<parallel::BatchScratch>,
    /// A large compressed block switches the remainder of the current file
    /// to inline decoding so decoded-item memory remains bounded.
    parallel_mode_exhausted: bool,
    /// Recycled input staging buffer for the streaming decode paths.
    ///
    /// Allocated on the first streaming decode and reset per member, so a
    /// multi-member archive pays for the staging area once rather than once
    /// per file.
    staged_input: Option<StagedInput>,
}

impl LzDecoder {
    /// Create a new LZ decoder with the specified dictionary size.
    pub fn new(dict_size: usize, version: u8) -> Self {
        Self::try_new(dict_size, version).expect("RAR5 LZ decoder allocation failed")
    }

    /// Map a RAR unpack version onto its distance-table width.
    ///
    /// RAR stores `ExtraDist` per file, so this is re-derived for every member
    /// that enters the decoder — at construction, on a solid continuation, and
    /// on a non-solid reuse.
    fn extra_dist_for_version(version: u8) -> RarResult<bool> {
        match version {
            0 => Ok(false),
            // RAR 7.0 LZ is stored as version 1.
            1 => Ok(true),
            _ => Err(RarError::UnsupportedCompression { method: 0, version }),
        }
    }

    /// Fallibly create a new LZ decoder with the specified dictionary size.
    pub fn try_new(dict_size: usize, version: u8) -> RarResult<Self> {
        let extra_dist = Self::extra_dist_for_version(version)?;
        let total_symbols = huffman::total_symbols(extra_dist);
        let mut decoder = Self {
            window: Window::try_new(dict_size)?,
            dist_cache: [usize::MAX; DIST_CACHE_SIZE],
            last_length: 0,
            nc_table: None,
            dc_table: None,
            ldc_table: None,
            rc_table: None,
            code_lengths: vec![0u8; total_symbols],
            extra_dist,
            block_bits_remaining: 0,
            is_last_block: false,
            pending_filters: Vec::new(),
            flush_at: 0,
            current_file_base_total: 0,
            current_file_written_size: 0,
            current_file_emitted: 0,
            // "No declared size yet": a decoder that has not begun a member
            // must not have its writes clamped to zero. `begin_file_decode`
            // installs the member's real `DestUnpSize`.
            current_file_unpacked_size: u64::MAX,
            parallel_item_buffer_sets: Vec::new(),
            parallel_batch_scratch: Vec::new(),
            parallel_mode_exhausted: false,
            staged_input: None,
        };
        decoder.recompute_flush_border();
        Ok(decoder)
    }

    fn flush_threshold(&self) -> usize {
        self.window.dict_size().clamp(1, UNPACK_MAX_WRITE)
    }

    /// Re-derive the write border after a flush.
    ///
    /// RAR sets `WriteBorder = UnpPtr + Min(MaxWinSize, UNPACK_MAX_WRITE)` and
    /// then pulls it back to the write pointer when that is nearer, so a write
    /// that could not drain the window (a pending filter still covers it) still
    /// forces a retry before the ring fills. Subtracting the widest single LZ
    /// item folds RAR's `<= MAX_INC_LZ_MATCH` slack into one comparison.
    fn recompute_flush_border(&mut self) {
        self.flush_at = Self::flush_border(
            self.window.total_written(),
            self.window.total_flushed(),
            self.window.dict_size(),
            self.flush_threshold(),
        );
    }

    fn flush_border(
        total_written: u64,
        total_flushed: u64,
        dict_size: usize,
        write_span: usize,
    ) -> u64 {
        let write_border = total_written.saturating_add(write_span as u64);
        let window_border = total_flushed.saturating_add(dict_size as u64);
        write_border
            .min(window_border)
            .saturating_sub(MAX_INCREMENTAL_LZ_MATCH)
    }

    fn begin_file_decode(&mut self, unpacked_size: u64) {
        self.pending_filters.clear();
        self.current_file_base_total = self.window.total_written();
        self.current_file_written_size = 0;
        self.current_file_emitted = 0;
        self.current_file_unpacked_size = unpacked_size;
        self.window.mark_flushed(self.current_file_base_total);
        self.parallel_mode_exhausted = false;
        self.recompute_flush_border();
    }

    #[inline]
    pub(super) fn insert_old_dist(&mut self, distance: usize) {
        self.dist_cache[3] = self.dist_cache[2];
        self.dist_cache[2] = self.dist_cache[1];
        self.dist_cache[1] = self.dist_cache[0];
        self.dist_cache[0] = distance;
    }

    #[inline]
    pub(super) fn promote_old_dist(&mut self, cache_idx: usize) -> RarResult<usize> {
        let distance = self.dist_cache[cache_idx];

        if cache_idx > 0 {
            // Explicit fixed rotations: a runtime-length shift loop here is
            // recognized by LLVM's loop-idiom pass and lowered to a libc
            // memmove call — 8-24 bytes through musl's backward `rep movsb`
            // path, which fleet profiling measured as the hottest
            // memmove caller in RAR extraction on musl builds.
            match cache_idx {
                1 => {
                    self.dist_cache[1] = self.dist_cache[0];
                }
                2 => {
                    self.dist_cache[2] = self.dist_cache[1];
                    self.dist_cache[1] = self.dist_cache[0];
                }
                _ => {
                    self.dist_cache[3] = self.dist_cache[2];
                    self.dist_cache[2] = self.dist_cache[1];
                    self.dist_cache[1] = self.dist_cache[0];
                }
            }
            self.dist_cache[0] = distance;
        }

        Ok(distance)
    }

    fn consume_staged_prefix(
        staged: &mut StagedInput,
        staged_base: &mut u64,
        count: usize,
    ) -> RarResult<()> {
        staged
            .consume_prefix(count)
            .map_err(|_| RarError::CorruptArchive {
                detail: "RAR5 staged input prefix consumption exceeded logical input".into(),
            })?;
        *staged_base += count as u64;
        if staged.logical_len() == 0 {
            staged.compact();
        }
        Ok(())
    }

    fn advance_staged_prefix(
        staged: &mut StagedInput,
        staged_base: &mut u64,
        bit_offset: &mut usize,
    ) -> RarResult<()> {
        let consumed_bytes = *bit_offset / 8;
        Self::consume_staged_prefix(staged, staged_base, consumed_bytes)?;
        *bit_offset %= 8;
        if staged.logical_len() == 0 {
            staged.compact();
            *bit_offset = 0;
        }
        Ok(())
    }

    fn compact_staged_buffer(staged: &mut StagedInput) {
        staged.compact();
    }

    /// Fill the staging buffer, not just the first short read.
    ///
    /// Readers layered over volumes, decryption, or pipes routinely hand back
    /// far less than the requested span. Dispatching a decode round on such a
    /// dribble costs a full scan/plan cycle for a fraction of a batch, so keep
    /// reading until the staging space is full or the source reports EOF.
    /// Returns the total bytes staged; a zero return still means EOF.
    fn refill_staged_input<Rd: Read>(input: &mut Rd, staged: &mut StagedInput) -> RarResult<usize> {
        let mut staged_bytes = 0usize;
        loop {
            let space = staged.read_space();
            if space.is_empty() {
                break;
            }
            let read = input.read(space).map_err(RarError::Io)?;
            if read == 0 {
                break;
            }
            staged
                .commit_read(read)
                .map_err(|_| RarError::CorruptArchive {
                    detail: "RAR5 staged input committed beyond read space".into(),
                })?;
            staged_bytes += read;
        }
        Ok(staged_bytes)
    }

    fn flush_unfiltered_stream_output<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
    ) -> RarResult<()> {
        let total_written = self.window.total_written();
        self.write_raw_span(total_written, writer)?;
        self.recompute_flush_border();
        Ok(())
    }

    /// `UnpWriteData` over the window span `[total_flushed, advance_to)`
    /// (unpack50.cpp:538-548, the routine v5 and v29 share).
    ///
    /// Nothing is emitted once `WrittenFileSize` has reached the declared size,
    /// the emitted part is clamped to what is left of it, and the counter
    /// advances by the whole span either way. The window's own border always
    /// advances by the whole span, because the oracle's `WrittenBorder` does.
    fn write_raw_span<W: Write + ?Sized>(
        &mut self,
        advance_to: u64,
        writer: &mut W,
    ) -> RarResult<()> {
        let border = self.window.total_flushed();
        let advance_to = advance_to.min(self.window.total_written());
        if advance_to <= border {
            return Ok(());
        }
        let span = advance_to - border;
        if self.current_file_written_size < self.current_file_unpacked_size {
            let left = self.current_file_unpacked_size - self.current_file_written_size;
            let emitted = self
                .window
                .flush_visible_until(border.saturating_add(span.min(left)), writer)
                .map_err(RarError::Io)?;
            self.current_file_emitted = self.current_file_emitted.saturating_add(emitted);
            self.current_file_written_size = self.current_file_written_size.saturating_add(span);
        }
        self.window.mark_flushed(advance_to);
        Ok(())
    }

    /// How far past the file start this member may decode.
    ///
    /// `Unpack5` has no size-driven decode bound (unpack50.cpp:20-60); its only
    /// size stop is `WrittenFileSize > DestUnpSize` after a write. Everything it
    /// decodes past the declared size is dropped by `UnpWriteData` — unless a
    /// filter covers it, because the filtered write has no clamp
    /// (unpack50.cpp:355-358). rarpar keeps the declared size as the bound, so a
    /// corrupt stream is never decoded for output nobody will see, and widens it
    /// to the reach of the blocks already queued: a block is written whole or
    /// not at all, so cutting the decode inside one would drop it. The reach is
    /// capped one dictionary past the declared size, the furthest the oracle can
    /// still apply a block before the ring overwrites the block's own bytes.
    fn decode_limit(&self) -> u64 {
        let base = self.current_file_base_total;
        let declared = self.current_file_unpacked_size;
        let mut limit = declared;
        for filter in &self.pending_filters {
            let end = filter
                .block_start
                .saturating_add(filter.block_length as u64);
            limit = limit.max(end.saturating_sub(base));
        }
        limit.min(declared.saturating_add(self.window.dict_size() as u64))
    }

    fn flush_stream_output<W: Write + ?Sized>(&mut self, writer: &mut W) -> RarResult<()> {
        if self.pending_filters.is_empty() {
            self.flush_unfiltered_stream_output(writer)?;
        } else {
            self.flush_filters_and_write(writer)?;
            if self.window.unflushed_bytes() as usize > self.window.dict_size() {
                return Err(RarError::CorruptArchive {
                    detail: "RAR5 pending filters exceeded dictionary window before flush".into(),
                });
            }
        }

        Ok(())
    }

    fn try_read_block_header_buffered(&mut self, reader: &mut BitReader<'_>) -> RarResult<bool> {
        let reader_checkpoint = reader.clone();
        let code_lengths_checkpoint = self.code_lengths.clone();
        let nc_table_checkpoint = self.nc_table.clone();
        let dc_table_checkpoint = self.dc_table.clone();
        let ldc_table_checkpoint = self.ldc_table.clone();
        let rc_table_checkpoint = self.rc_table.clone();
        let block_bits_remaining_checkpoint = self.block_bits_remaining;
        let is_last_block_checkpoint = self.is_last_block;
        let parallel_mode_exhausted_checkpoint = self.parallel_mode_exhausted;

        match self.read_block_header_bitreader(reader) {
            Ok(()) => Ok(true),
            Err(error) if parallel::is_truncated_input_error(&error) => {
                *reader = reader_checkpoint;
                self.code_lengths = code_lengths_checkpoint;
                self.nc_table = nc_table_checkpoint;
                self.dc_table = dc_table_checkpoint;
                self.ldc_table = ldc_table_checkpoint;
                self.rc_table = rc_table_checkpoint;
                self.block_bits_remaining = block_bits_remaining_checkpoint;
                self.is_last_block = is_last_block_checkpoint;
                self.parallel_mode_exhausted = parallel_mode_exhausted_checkpoint;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn read_block_header_bitreader(&mut self, reader: &mut BitReader<'_>) -> RarResult<()> {
        reader.align_byte();

        let flags = reader.read_bits(8)? as u8;
        let checksum = reader.read_bits(8)? as u8;

        let extra_bits = (flags & 0x07) as i64 + 1;
        let num_size_bytes = ((flags >> 3) & 0x03) + 1;
        if num_size_bytes > 3 {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 block header: invalid size byte count".into(),
            });
        }

        self.is_last_block = (flags & 0x40) != 0;
        let table_present = (flags & 0x80) != 0;

        let mut block_bytes: i64 = 0;
        let mut xor_sum = 0x5Au8 ^ flags;
        for i in 0..num_size_bytes {
            let b = reader.read_bits(8)? as u8;
            xor_sum ^= b;
            block_bytes |= (b as i64) << (i * 8);
        }

        if xor_sum != checksum {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "RAR5 block header checksum mismatch: expected {:#04x}, got {:#04x}",
                    checksum, xor_sum
                ),
            });
        }

        self.block_bits_remaining = if block_bytes == 0 {
            0
        } else {
            extra_bits + (block_bytes - 1) * 8
        };
        if self.block_bits_remaining > STREAMING_LARGE_BLOCK_BYTES * 8 {
            self.parallel_mode_exhausted = true;
        }

        if !table_present && self.nc_table.is_none() {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 first block is missing Huffman tables".into(),
            });
        }

        if table_present {
            let pos_before = reader.position();
            let (nc, dc, ldc, rc) =
                huffman::read_tables_bitreader(reader, &mut self.code_lengths, self.extra_dist)?;
            let bits_used = (reader.position() - pos_before) as i64;
            self.block_bits_remaining -= bits_used;
            self.nc_table = Some(Arc::new(nc));
            self.dc_table = Some(Arc::new(dc));
            self.ldc_table = Some(Arc::new(ldc));
            self.rc_table = Some(Arc::new(rc));
        }

        Ok(())
    }

    /// Read a RAR5 block header.
    ///
    /// The block header is byte-aligned:
    /// - flags (1 byte): bit_size[0:2], byte_count[3:4], is_last[6], table_present[7]
    /// - checksum (1 byte): must equal 0x5A ^ flags ^ size_byte_0 ^ ...
    /// - size bytes (1-3 bytes, LE): block byte count
    ///
    /// Block size in bits = byte_count * 8 + ((flags & 7) + 1).
    /// byte_count is full data bytes; the low 3 flag bits + 1 give additional valid bits.
    fn read_block_header<R: BitRead>(&mut self, reader: &mut R) -> RarResult<()> {
        // Block header is byte-aligned.
        reader.align_byte()?;

        let flags = reader.read_bits(8)? as u8;
        let checksum = reader.read_bits(8)? as u8;

        let extra_bits = (flags & 0x07) as i64 + 1; // valid bits in last byte (1-8)
        let num_size_bytes = ((flags >> 3) & 0x03) + 1;
        if num_size_bytes > 3 {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 block header: invalid size byte count".into(),
            });
        }

        self.is_last_block = (flags & 0x40) != 0;
        let table_present = (flags & 0x80) != 0;

        // Read block size bytes (little-endian) and validate checksum.
        let mut block_bytes: i64 = 0;
        let mut xor_sum = 0x5Au8 ^ flags;
        for i in 0..num_size_bytes {
            let b = reader.read_bits(8)? as u8;
            xor_sum ^= b;
            block_bytes |= (b as i64) << (i * 8);
        }

        if xor_sum != checksum {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "RAR5 block header checksum mismatch: expected {:#04x}, got {:#04x}",
                    checksum, xor_sum
                ),
            });
        }

        // Block size in bits = (block_bytes - 1) * 8 + extra_bits.
        // The block_bytes value includes the last partial byte; extra_bits gives
        // how many bits are valid in that last byte (1-8).
        self.block_bits_remaining = if block_bytes == 0 {
            0
        } else {
            extra_bits + (block_bytes - 1) * 8
        };

        if !table_present && self.nc_table.is_none() {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 first block is missing Huffman tables".into(),
            });
        }

        if table_present {
            let pos_before = reader.position();
            let (nc, dc, ldc, rc) =
                huffman::read_tables(reader, &mut self.code_lengths, self.extra_dist)?;
            let bits_used = (reader.position() - pos_before) as i64;
            self.block_bits_remaining -= bits_used;
            self.nc_table = Some(Arc::new(nc));
            self.dc_table = Some(Arc::new(dc));
            self.ldc_table = Some(Arc::new(ldc));
            self.rc_table = Some(Arc::new(rc));
        }

        Ok(())
    }

    /// Decompress all LZ-compressed data from the input into the output buffer.
    ///
    /// `input` is the raw compressed data (data area from the file header).
    /// `unpacked_size` is the expected uncompressed size.
    /// Returns the decompressed data.
    pub fn decompress(&mut self, input: &[u8], unpacked_size: u64) -> RarResult<Vec<u8>> {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        let capacity = usize::try_from(unpacked_size).unwrap_or_else(|_| self.window.dict_size());
        let capacity = capacity.min(self.window.dict_size());
        let mut output = Vec::with_capacity(capacity);
        self.decompress_to_writer(input, unpacked_size, &mut output)?;
        Ok(output)
    }

    #[cfg(test)]
    /// Apply pending filters to an in-memory output buffer using RAR write
    /// semantics: invalid filters suppress their covered block, but the logical
    /// `WrittenFileSize` used for later filters still advances by block length.
    fn apply_filters_to_vec(&mut self, output: Vec<u8>, base_offset: u64) -> Vec<u8> {
        if self.pending_filters.is_empty() {
            return output;
        }

        let total = base_offset + output.len() as u64;
        let mut filtered = Vec::with_capacity(output.len());
        let mut written_up_to = base_offset;
        let mut logical_written_size = 0u64;
        let mut pending_filters = std::mem::take(&mut self.pending_filters);
        pending_filters.sort_by_key(|filter| filter.block_start);

        for f in pending_filters {
            if f.block_start < written_up_to || f.block_start > total {
                continue;
            }
            if f.block_start > written_up_to {
                let rel_start = (written_up_to - base_offset) as usize;
                let rel_end = (f.block_start - base_offset) as usize;
                filtered.extend_from_slice(&output[rel_start..rel_end]);
                logical_written_size += f.block_start - written_up_to;
                written_up_to = f.block_start;
            }

            let block_end = f.block_start.saturating_add(f.block_length as u64);
            if block_end > total {
                continue;
            }

            let rel_start = (f.block_start - base_offset) as usize;
            let rel_end = (block_end - base_offset) as usize;
            let mut block = output[rel_start..rel_end].to_vec();
            let file_block_start = logical_written_size;
            match f.filter_type {
                FilterType::Delta => filter::apply_delta(&mut block, f.channels),
                FilterType::E8 => filter::apply_e8(&mut block, file_block_start),
                FilterType::E8E9 => filter::apply_e8e9(&mut block, file_block_start),
                FilterType::Arm => filter::apply_arm(&mut block, file_block_start),
                FilterType::Unsupported(_) => {}
            }
            if f.filter_type.emits_output() {
                filtered.extend_from_slice(&block);
            }
            logical_written_size += f.block_length as u64;
            written_up_to = block_end;
        }

        if written_up_to < total {
            let rel_start = (written_up_to - base_offset) as usize;
            filtered.extend_from_slice(&output[rel_start..]);
            logical_written_size += total - written_up_to;
        }

        self.pending_filters.clear();
        self.current_file_written_size = logical_written_size;
        filtered
    }

    /// Apply distance-based length adjustment per RAR5 spec.
    ///
    /// Longer distances get +1 to the match length at each threshold:
    /// - distance > 256 (0x100): +1
    /// - distance > 8192 (0x2000): +1
    /// - distance > 262144 (0x40000): +1
    fn adjust_length_for_distance(length: usize, distance: usize) -> usize {
        let mut len = length;
        if distance > 0x100 {
            len += 1;
        }
        if distance > 0x2000 {
            len += 1;
        }
        if distance > 0x40000 {
            len += 1;
        }
        len
    }

    /// Decode symbols from one LZ block.
    ///
    /// Returns the updated output_size.
    ///
    /// Hot loop optimized for the RAR5 unpacking layout:
    /// - Precompute block end position — compare against it instead of
    ///   decrementing block_bits_remaining per symbol
    /// - No range checks — ordered `if/else if` with simple comparisons
    ///   matching the format's frequency order (literal first, match >= 262 second)
    /// - `has_bits()` instead of `bits_remaining() < 1`
    fn decode_block<R: BitRead, W: Write + ?Sized>(
        &mut self,
        reader: &mut R,
        mut decode_limit: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<()> {
        // Precompute the bitstream position at which this block ends.
        // This replaces per-symbol block_bits_remaining decrement with a
        // single comparison per iteration.
        let block_end_pos = reader.position() as i64 + self.block_bits_remaining;

        // Hoist the per-block tables out of the symbol loop. Cloning the Arcs
        // (a refcount bump per block) keeps `self` free for mutable window and
        // filter calls without an Option check per symbol.
        let nc_table = Arc::clone(
            self.nc_table
                .as_ref()
                .ok_or_else(|| missing_table_error("literal/length"))?,
        );
        let dc_table = Arc::clone(
            self.dc_table
                .as_ref()
                .ok_or_else(|| missing_table_error("distance"))?,
        );
        let ldc_table = Arc::clone(
            self.ldc_table
                .as_ref()
                .ok_or_else(|| missing_table_error("low-distance"))?,
        );
        let rc_table = Arc::clone(
            self.rc_table
                .as_ref()
                .ok_or_else(|| missing_table_error("repeat-length"))?,
        );

        while *output_size < decode_limit && (reader.position() as i64) < block_end_pos {
            if !reader.has_bits() {
                break;
            }

            // One comparison per symbol against the precomputed border, as in
            // RAR's Unpack5 loop. The flush routines re-derive the border.
            if self.window.total_written() >= self.flush_at {
                self.flush_stream_output(writer)?;
            }

            let sym = nc_table.decode(reader)? as u32;

            if sym < 256 {
                // Literal byte (most common case — first).
                self.window.put_byte(sym as u8);
                *output_size += 1;
            } else if sym >= 262 {
                // Inline length-distance pair (second most common).
                let length_idx = (sym - 262) as usize;
                let mut length = Self::slot_to_length(reader, length_idx)?;
                let distance = self.decode_distance(reader, &dc_table, &ldc_table)?;
                length = Self::adjust_length_for_distance(length, distance);

                self.insert_old_dist(distance);

                self.last_length = length;
                self.window.copy(distance, length)?;
                *output_size += length as u64;
            } else if sym == 256 {
                // Filter marker: queue only — RAR writes at the border, at
                // filter-queue overflow, and at member end, never on registration.
                *output_size = self.handle_filter(reader, *output_size, writer)?;
                // The block just queued may reach past the declared size, and a
                // block is written whole or not at all, so the bound has to
                // cover it. Refreshed here rather than per symbol: only this arm
                // can move it.
                decode_limit = self.decode_limit();
            } else if sym == 257 {
                // Repeat previous match.
                if self.last_length != 0 {
                    let distance = self.dist_cache[0];
                    let length = self.last_length;
                    self.window.copy(distance, length)?;
                    *output_size += length as u64;
                }
            } else {
                // sym 258..=261: repeat distance from cache.
                let cache_idx = (sym - 258) as usize;
                let distance = self.promote_old_dist(cache_idx)?;

                let length = self.decode_rc_length(reader, &rc_table)?;

                self.last_length = length;
                self.window.copy(distance, length)?;
                *output_size += length as u64;
            }
        }

        // Update block_bits_remaining from final position.
        self.block_bits_remaining = block_end_pos - reader.position() as i64;

        Ok(())
    }

    /// Convert a length slot (0-43) to a match length.
    ///
    /// Uses the RAR SlotToLength formula:
    /// - Slots 0-7: length = 2 + slot, no extra bits
    /// - Slots 8+:  extra_bits = slot/4 - 1
    ///   length = 2 + (4 | (slot & 3)) << extra_bits + read_bits(extra_bits)
    fn slot_to_length<R: BitRead>(reader: &mut R, slot: usize) -> RarResult<usize> {
        // Both producers are bounded by their table size: sym-262 over the
        // 306-symbol NC table yields at most 43, and the RC table is built from
        // exactly NUM_LENGTH_SLOTS lengths. `HuffmanTable::decode` never returns
        // a symbol at or past `num_symbols`.
        debug_assert!(slot < NUM_LENGTH_SLOTS, "length slot out of range: {slot}");
        let (base, extra_bits) = if slot < 8 {
            (2 + slot, 0)
        } else {
            let lbits = slot / 4 - 1;
            (2 + ((4 | (slot & 3)) << lbits), lbits)
        };
        let extra_val = if extra_bits > 0 {
            reader.read_bits(extra_bits as u8)? as usize
        } else {
            0
        };
        Ok(base + extra_val)
    }

    /// Decode a length from the RC/LenDecoder table (used for symbols 256 and 258-261).
    fn decode_rc_length<R: BitRead>(&self, reader: &mut R, rc: &HuffmanTable) -> RarResult<usize> {
        let slot = rc.decode(reader)? as usize;
        Self::slot_to_length(reader, slot)
    }

    /// Decode a distance value from the DC and LDC (AlignDecoder) tables.
    ///
    /// RAR5 distance decoding:
    /// - dist_code < 4: distance = dist_code + 1
    /// - dist_code >= 4: base + extra bits, where extra bits may be split
    ///   between the bitstream (high) and AlignDecoder/LDC (low 4 bits)
    fn decode_distance<R: BitRead>(
        &self,
        reader: &mut R,
        dc: &HuffmanTable,
        ldc: &HuffmanTable,
    ) -> RarResult<usize> {
        let dist_code = dc.decode(reader)? as usize;
        // The DC table is built from exactly 64 (RAR5) or 80 (RAR7) code
        // lengths and `HuffmanTable::decode` cannot return a symbol at or past
        // `num_symbols`, so the slot is always within range.
        debug_assert!(
            dist_code <= if self.extra_dist { 79 } else { 63 },
            "distance code out of range: {dist_code}"
        );

        if dist_code < 4 {
            return Ok(dist_code + 1);
        }

        let num_bits = (dist_code >> 1) - 1;
        let distance = if num_bits >= 4 {
            // Split: high bits from bitstream, low 4 bits from AlignDecoder (LDC).
            let high = if num_bits > 4 {
                reader.read_bits64((num_bits - 4) as u8)? << 4
            } else {
                0
            };
            let low = ldc.decode(reader)? as u64;
            Self::distance_from_slot_parts(dist_code, num_bits, high, low)?
        } else {
            // All extra bits from bitstream.
            let extra = reader.read_bits64(num_bits as u8)?;
            Self::distance_from_slot_parts(dist_code, num_bits, extra, 0)?
        };

        Ok(distance)
    }

    fn distance_from_slot_parts(
        dist_code: usize,
        num_bits: usize,
        high_or_extra: u64,
        low: u64,
    ) -> RarResult<usize> {
        // Weaver is 64-bit only, so it accepts distances that would overflow
        // a 32-bit size_t sentinel. The widest slot (RAR7 code 79) gives
        // num_bits 38, so the terms are bounded by 3 << 38, (2^34 - 1) << 4,
        // 15 and 1 — u64 cannot overflow and no checked arithmetic is needed.
        debug_assert!(num_bits <= 38);
        let base = (2u64 | (dist_code as u64 & 1)) << num_bits;
        let distance = base + high_or_extra + low + 1;
        // 32-bit targets (wasm32) still need the narrowing check.
        usize::try_from(distance).map_err(|_| distance_out_of_range_error(distance))
    }

    /// Queue a pending filter, draining the queue first when it is full.
    ///
    /// Mirrors RAR's `AddFilter`: an overflowing queue triggers one write (which
    /// applies and retires every completed filter) and is only discarded when
    /// that write could not make room.
    pub(super) fn register_pending_filter<W: Write + ?Sized>(
        &mut self,
        filter: PendingFilter,
        writer: &mut W,
    ) -> RarResult<()> {
        if self.pending_filters.len() >= MAX_PENDING_FILTERS {
            self.flush_filters_and_write(writer)?;
            if self.pending_filters.len() >= MAX_PENDING_FILTERS {
                self.pending_filters.clear();
            }
        }
        filter::push_pending_filter(&mut self.pending_filters, filter);
        Ok(())
    }

    /// Handle a filter marker (symbol 256).
    ///
    /// Reads the full filter descriptor from the bitstream and pushes a
    /// [`PendingFilter`] for later application to the output.
    fn handle_filter<R: BitRead, W: Write + ?Sized>(
        &mut self,
        reader: &mut R,
        output_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        let block_start_delta = Self::read_filter_data(reader)? as u64;
        let block_start = self.current_file_base_total + output_size + block_start_delta;
        let mut block_length = Self::read_filter_data(reader)? as usize;
        let filter_code = reader.read_bits(3)? as u8;
        let filter_type = FilterType::from_code(filter_code);

        if block_length > MAX_FILTER_BLOCK_SIZE {
            block_length = 0;
        }

        let channels = if filter_type == FilterType::Delta {
            (reader.read_bits(5)? + 1) as u8
        } else {
            0
        };

        trace!(
            "filter at output offset {}: type={:?}, block_start={}, block_length={}, channels={}",
            output_size, filter_type, block_start, block_length, channels
        );

        self.register_pending_filter(
            PendingFilter {
                filter_type,
                block_start,
                block_length,
                channels,
            },
            writer,
        )?;

        Ok(self.current_file_emitted)
    }

    fn read_filter_data<R: BitRead>(reader: &mut R) -> RarResult<u32> {
        let byte_count = reader.read_bits(2)? as usize + 1;
        let mut data = 0u32;
        for index in 0..byte_count {
            data |= reader.read_bits(8)? << (index * 8);
        }
        Ok(data)
    }

    /// Streaming variant: decompress directly to a writer instead of a Vec.
    ///
    /// Periodically flushes the sliding window to the writer to keep memory
    /// usage bounded to the dictionary size. Filters are applied in-place
    /// to a temporary buffer before flushing.
    pub fn decompress_to_writer<W: Write>(
        &mut self,
        input: &[u8],
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        phase_diagnostics::emit_zero(phase_diagnostics::Phase::Staging);
        if unpacked_size == 0 {
            return Ok(0);
        }

        self.begin_file_decode(unpacked_size);
        // Try parallel decode if there are enough blocks.
        if self
            .try_decompress_parallel(input, unpacked_size, writer)?
            .is_some()
        {
            return Ok(self.current_file_emitted);
        }

        // Fall back to single-threaded decode.
        let mut reader = BitReader::new(input);
        let mut output_size: u64 = 0;

        while output_size < self.decode_limit() {
            if self.block_bits_remaining <= 0 {
                if reader.bits_remaining() < 16 {
                    break;
                }
                self.read_block_header(&mut reader)?;
            }

            // No trailing flush: the write border inside `decode_block` already
            // drives writes at RAR's ~UNPACK_MAX_WRITE cadence, and the final
            // flush below retires whatever is left.
            self.decode_block(&mut reader, self.decode_limit(), &mut output_size, writer)?;
        }

        // Apply any remaining filters and flush.
        self.flush_filters_and_write(writer)?;

        Ok(self.current_file_emitted)
    }

    pub fn decompress_reader_to_writer<Rd: std::io::Read, W: Write>(
        &mut self,
        mut input: Rd,
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        if unpacked_size == 0 {
            phase_diagnostics::emit_zero(phase_diagnostics::Phase::Staging);
            return Ok(0);
        }

        if !parallel::parallel_enabled() {
            return self.decompress_reader_to_writer_single_thread(input, unpacked_size, writer, 0);
        }

        let mut staged = self.take_staged_input();
        let result =
            self.decompress_reader_to_writer_staged(&mut input, unpacked_size, writer, &mut staged);
        self.recycle_staged_input(staged);
        result
    }

    /// Staged block-parallel decode over a caller-owned input buffer.
    ///
    /// Split out so the staging allocation lives in the decoder and survives
    /// both the happy path and any error return.
    fn decompress_reader_to_writer_staged<Rd: std::io::Read, W: Write>(
        &mut self,
        input: &mut Rd,
        unpacked_size: u64,
        writer: &mut W,
        staged: &mut StagedInput,
    ) -> RarResult<u64> {
        self.begin_file_decode(unpacked_size);
        let mut output_size = 0u64;
        let mut reached_eof = false;
        let mut staged_bit_offset = 0usize;
        let mut staged_base = 0u64;

        while output_size < self.decode_limit() {
            if staged.read_space_len() == 0 {
                phase_diagnostics::measure(phase_diagnostics::Phase::Staging, || {
                    Self::compact_staged_buffer(&mut *staged);
                });
            }

            if !reached_eof && staged.read_space_len() > 0 {
                let read = phase_diagnostics::measure(phase_diagnostics::Phase::Staging, || {
                    Self::refill_staged_input(&mut *input, &mut *staged)
                })?;
                if read == 0 {
                    reached_eof = true;
                }
            }

            // A finished block can end mid-byte; the remaining bits of that
            // byte belong to the finished block, and the next header starts at
            // the following byte boundary. Align here so the buffered header
            // parse below sees the true header start (and so this loop cannot
            // spin on a zero-length residual decode). The offset can span
            // multiple bytes when a header/table parse left no block data.
            if self.block_bits_remaining <= 0 && staged_bit_offset > 0 {
                let consumed_bytes = staged_bit_offset.div_ceil(8);
                Self::consume_staged_prefix(staged, &mut staged_base, consumed_bytes)?;
                staged_bit_offset = 0;
            }

            let staged_slice = staged.logical_input();
            if staged_slice.is_empty() {
                if reached_eof {
                    break;
                }
                continue;
            }

            let have_incomplete_block = self.block_bits_remaining > 0 || staged_bit_offset > 0;
            if have_incomplete_block {
                // Clamp the decode budget a symbol-width short of the staging
                // edge: 16-bit peeks fabricate zero bits past the slice end,
                // which can silently desync the stream when the real bits
                // arrive with the next refill.
                let avail_bits = (staged_slice.len() * 8).saturating_sub(staged_bit_offset) as i64;
                let usable_bits = if reached_eof {
                    avail_bits
                } else {
                    avail_bits - STREAMING_SYMBOL_MARGIN_BITS
                };
                if usable_bits <= 0 {
                    if reached_eof {
                        break;
                    }
                    continue;
                }

                let full_remaining = self.block_bits_remaining;
                self.block_bits_remaining = full_remaining.min(usable_bits);

                let mut reader = BitReader::new(staged.padded_input());
                if staged_bit_offset > 0 {
                    reader.skip_bits(staged_bit_offset as u32)?;
                }

                let decode_result =
                    self.decode_block(&mut reader, self.decode_limit(), &mut output_size, writer);
                let consumed_bits = (reader.position() - staged_bit_offset) as i64;
                self.block_bits_remaining = full_remaining - consumed_bits;

                match decode_result {
                    Ok(()) => {
                        self.flush_stream_output(writer)?;
                        staged_bit_offset = reader.position();
                        Self::advance_staged_prefix(
                            staged,
                            &mut staged_base,
                            &mut staged_bit_offset,
                        )?;
                        continue;
                    }
                    Err(error) if parallel::is_truncated_input_error(&error) && !reached_eof => {
                        staged_bit_offset = reader.position();
                        Self::advance_staged_prefix(
                            staged,
                            &mut staged_base,
                            &mut staged_bit_offset,
                        )?;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            // Only accept block headers that start clear of the unreliable
            // staging tail (header plus tables always fit in the margin).
            let header_limit = if reached_eof {
                staged_slice.len()
            } else {
                staged_slice.len().saturating_sub(STREAMING_HEADER_MARGIN)
            };
            let consumed = self.process_buffered_blocks(
                staged.padded_input(),
                staged.logical_len(),
                header_limit,
                unpacked_size,
                &mut output_size,
                writer,
            )?;
            if consumed > 0 {
                Self::consume_staged_prefix(staged, &mut staged_base, consumed)?;
                staged_bit_offset = 0;
                continue;
            }

            if !reached_eof && staged_slice.len() < STREAMING_PARALLEL_MIN_PROCESS_SIZE {
                continue;
            }

            // The next block is incomplete in the stage. Defer it whenever one
            // more compaction plus refill can complete it, so the fast
            // scan/batch path decodes it over the padded buffer next round
            // instead of the checked mid-block reader. Only a block that can
            // never be staged whole — the source is exhausted, or the stage is
            // already full — falls through to the streaming path below.
            // Deferring always makes progress: the loop head refills, and a
            // refill either stages bytes (bounded by the capacity that this
            // guard tests) or reports EOF.
            if !reached_eof && staged.read_space_len() > 0 {
                continue;
            }

            #[cfg(test)]
            parallel::note_streaming_block_fallback();

            let mut reader = BitReader::new(staged_slice);
            if !self.try_read_block_header_buffered(&mut reader)? {
                if reached_eof {
                    break;
                }
                // The deferral above means only a full stage gets here, so
                // waiting would re-read the same bytes forever. A header plus
                // its tables always fit well inside the staging capacity.
                return Err(RarError::CorruptArchive {
                    detail: "RAR5 block header did not fit a full input stage".into(),
                });
            }

            staged_bit_offset = reader.position();
        }

        self.flush_filters_and_write(writer)?;
        Ok(self.current_file_emitted)
    }

    fn decompress_reader_to_writer_single_thread<Rd: std::io::Read, W: Write>(
        &mut self,
        input: Rd,
        unpacked_size: u64,
        writer: &mut W,
        mut output_size: u64,
    ) -> RarResult<u64> {
        self.begin_file_decode(unpacked_size);
        let mut reader = StreamingBitReader::new(input);

        while output_size < self.decode_limit() {
            if self.block_bits_remaining <= 0 {
                if reader.bits_remaining() < 16 {
                    break;
                }
                self.read_block_header(&mut reader)?;
            }

            // Writes happen at the write border inside `decode_block`.
            self.decode_block(&mut reader, self.decode_limit(), &mut output_size, writer)?;
        }

        self.flush_filters_and_write(writer)?;
        Ok(self.current_file_emitted)
    }

    /// Chunked variant: decompress with output split at compressed byte boundaries.
    ///
    /// `boundaries` lists compressed byte offsets where volume transitions occur,
    /// paired with the new volume index. At each boundary crossing, the current
    /// writer is flushed and a new one is obtained from `writer_factory`.
    ///
    /// Returns a list of `(volume_index, bytes_written)` for each chunk. The first
    /// chunk starts at `first_volume_index`.
    pub fn decompress_to_writer_chunked<F>(
        &mut self,
        input: &[u8],
        unpacked_size: u64,
        first_volume_index: usize,
        boundaries: &[super::VolumeTransition],
        mut writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        self.begin_file_decode(unpacked_size);
        let mut reader = BitReader::new(input);
        let mut output_size: u64 = 0;
        let mut boundary_idx = 0;

        // Track per-chunk output.
        let mut chunks: Vec<(usize, u64)> = Vec::new();
        let mut current_vol = first_volume_index;
        let mut current_writer = writer_factory(current_vol)?;
        let mut chunk_bytes: u64 = 0;

        while output_size < self.decode_limit() {
            if self.block_bits_remaining <= 0 {
                if reader.bits_remaining() < 16 {
                    break;
                }
                self.read_block_header(&mut reader)?;
            }

            let prev_output = output_size;
            self.decode_block(
                &mut reader,
                unpacked_size,
                &mut output_size,
                &mut *current_writer,
            )?;
            let decoded_this_round = output_size - prev_output;

            // Check if we crossed a volume boundary in compressed space.
            let byte_pos = reader.byte_position() as u64;
            if boundary_idx < boundaries.len()
                && byte_pos >= boundaries[boundary_idx].compressed_offset
            {
                // Flush current writer and record chunk.
                self.flush_filters_and_write(&mut *current_writer)?;
                chunk_bytes += decoded_this_round;
                chunks.push((current_vol, chunk_bytes));

                // Switch to new volume's writer.
                current_vol = boundaries[boundary_idx].volume_index;
                boundary_idx += 1;
                current_writer = writer_factory(current_vol)?;
                chunk_bytes = 0;
            } else {
                // No trailing flush: writes happen at the write border inside
                // `decode_block`. Volume switches above still flush first, so
                // chunk attribution is unchanged.
                chunk_bytes += decoded_this_round;
            }
        }

        // Final flush.
        self.flush_filters_and_write(&mut *current_writer)?;
        if chunk_bytes > 0 || chunks.is_empty() {
            chunks.push((current_vol, chunk_bytes));
        }

        Ok(chunks)
    }

    pub fn decompress_reader_to_writer_chunked<Rd: std::io::Read, F>(
        &mut self,
        input: Rd,
        unpacked_size: u64,
        first_volume_index: usize,
        transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        if !parallel::parallel_enabled() {
            return self.decompress_reader_to_writer_chunked_single_thread(
                input,
                unpacked_size,
                first_volume_index,
                transitions,
                writer_factory,
            );
        }

        self.decompress_reader_to_writer_chunked_parallel(
            input,
            unpacked_size,
            first_volume_index,
            transitions,
            writer_factory,
        )
    }

    /// Staged block-parallel variant of the solid chunked decode: complete
    /// blocks before the next volume boundary fan out to rayon (same engine
    /// as `decompress_reader_to_writer`), while boundary-straddling blocks and
    /// writer switching stay on the sequential path at block granularity.
    fn decompress_reader_to_writer_chunked_parallel<Rd: std::io::Read, F>(
        &mut self,
        mut input: Rd,
        unpacked_size: u64,
        first_volume_index: usize,
        transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        let mut staged = self.take_staged_input();
        let result = self.decompress_reader_to_writer_chunked_staged(
            &mut input,
            unpacked_size,
            first_volume_index,
            transitions,
            writer_factory,
            &mut staged,
        );
        self.recycle_staged_input(staged);
        result
    }

    /// Chunked staged decode over a caller-owned input buffer.
    ///
    /// Split out for the same reason as
    /// [`Self::decompress_reader_to_writer_staged`]: the staging allocation
    /// belongs to the decoder and returns to it on every exit path.
    #[allow(clippy::too_many_arguments)]
    fn decompress_reader_to_writer_chunked_staged<Rd: std::io::Read, F>(
        &mut self,
        input: &mut Rd,
        unpacked_size: u64,
        first_volume_index: usize,
        transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        mut writer_factory: F,
        staged: &mut StagedInput,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        self.begin_file_decode(unpacked_size);

        let mut chunks: Vec<(usize, u64)> = Vec::new();
        let mut current_vol = first_volume_index;
        let mut current_writer = writer_factory(current_vol)?;
        let mut chunk_bytes: u64 = 0;
        let mut boundary_idx = 0usize;

        let mut output_size = 0u64;
        let mut reached_eof = false;
        let mut staged_bit_offset = 0usize;
        // Absolute compressed offset of staged.logical_input()[0].
        let mut staged_base: u64 = 0;

        let next_boundary = |boundary_idx: usize| -> RarResult<Option<super::VolumeTransition>> {
            let guard = transitions.lock().map_err(|_| RarError::CorruptArchive {
                detail: "RAR5 chunked transition state poisoned".into(),
            })?;
            Ok(guard.get(boundary_idx).cloned())
        };

        while output_size < self.decode_limit() {
            if staged.read_space_len() == 0 {
                Self::compact_staged_buffer(staged);
            }

            if !reached_eof && staged.read_space_len() > 0 {
                let read = Self::refill_staged_input(&mut *input, staged)?;
                if read == 0 {
                    reached_eof = true;
                }
            }

            // A finished block can end mid-byte; the residual bits belong to
            // the finished block and the next header starts at the following
            // byte boundary. The offset can span multiple bytes when a
            // header/table parse left no block data.
            if self.block_bits_remaining <= 0 && staged_bit_offset > 0 {
                let consumed_bytes = staged_bit_offset.div_ceil(8);
                Self::consume_staged_prefix(staged, &mut staged_base, consumed_bytes)?;
                staged_bit_offset = 0;
            }

            let staged_slice = staged.logical_input();
            if staged_slice.is_empty() {
                if reached_eof {
                    break;
                }
                continue;
            }

            // Absolute compressed byte offset of the decode cursor.
            let abs_cursor = staged_base + (staged_bit_offset / 8) as u64;
            let boundary = next_boundary(boundary_idx)?;

            // Writer switch once the cursor has reached a volume boundary and
            // no block is in flight (in-flight blocks finish on the old
            // writer, matching the sequential path's attribution).
            if let Some(ref b) = boundary
                && self.block_bits_remaining <= 0
                && staged_bit_offset == 0
                && abs_cursor >= b.compressed_offset
            {
                self.flush_filters_and_write(&mut *current_writer)?;
                chunks.push((current_vol, chunk_bytes));
                current_vol = b.volume_index;
                boundary_idx += 1;
                current_writer = writer_factory(current_vol)?;
                chunk_bytes = 0;
                continue;
            }

            // Finish an in-flight block sequentially, keeping the decode
            // budget a symbol-width short of the staging edge (peeks would
            // fabricate zero bits there while real data may follow).
            if self.block_bits_remaining > 0 || staged_bit_offset > 0 {
                let avail_bits = (staged_slice.len() * 8).saturating_sub(staged_bit_offset) as i64;
                let usable_bits = if reached_eof {
                    avail_bits
                } else {
                    avail_bits - STREAMING_SYMBOL_MARGIN_BITS
                };
                if usable_bits <= 0 {
                    if reached_eof {
                        break;
                    }
                    continue;
                }

                let full_remaining = self.block_bits_remaining;
                self.block_bits_remaining = full_remaining.min(usable_bits);

                let mut reader = BitReader::new(staged.padded_input());
                if staged_bit_offset > 0 {
                    reader.skip_bits(staged_bit_offset as u32)?;
                }

                let prev_output = output_size;
                let decode_result = self.decode_block(
                    &mut reader,
                    unpacked_size,
                    &mut output_size,
                    &mut *current_writer,
                );
                let consumed_bits = (reader.position() - staged_bit_offset) as i64;
                self.block_bits_remaining = full_remaining - consumed_bits;
                chunk_bytes += output_size - prev_output;

                match decode_result {
                    Ok(()) => {
                        self.flush_stream_output(&mut current_writer)?;
                        staged_bit_offset = reader.position();
                        Self::advance_staged_prefix(
                            staged,
                            &mut staged_base,
                            &mut staged_bit_offset,
                        )?;
                        continue;
                    }
                    Err(error) if parallel::is_truncated_input_error(&error) && !reached_eof => {
                        staged_bit_offset = reader.position();
                        Self::advance_staged_prefix(
                            staged,
                            &mut staged_base,
                            &mut staged_bit_offset,
                        )?;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }

            // Block-parallel decode of headers starting before the next
            // volume boundary and clear of the unreliable staging tail. A
            // block whose data crosses the boundary still decodes here and
            // attributes to the current volume, matching the sequential
            // path's switch-after-crossing behavior.
            let header_limit = if reached_eof {
                staged_slice.len()
            } else {
                staged_slice.len().saturating_sub(STREAMING_HEADER_MARGIN)
            };
            let span = boundary
                .as_ref()
                .map(|b| {
                    usize::try_from(b.compressed_offset.saturating_sub(abs_cursor))
                        .unwrap_or(usize::MAX)
                        .min(header_limit)
                })
                .unwrap_or(header_limit);
            if span > 0 {
                let prev_output = output_size;
                // Sequential batches, deliberately: this driver switches
                // `current_writer` and tallies per-volume bytes as apply
                // progresses, so decoding a batch ahead of the boundary check
                // would attribute output to the wrong volume.
                let consumed = self.process_buffered_blocks_sequential(
                    staged.padded_input(),
                    staged.logical_len(),
                    span,
                    unpacked_size,
                    &mut output_size,
                    &mut current_writer,
                )?;
                if consumed > 0 {
                    chunk_bytes += output_size - prev_output;
                    Self::consume_staged_prefix(staged, &mut staged_base, consumed)?;
                    staged_bit_offset = 0;
                    continue;
                }
            }

            if !reached_eof && staged_slice.len() < STREAMING_PARALLEL_MIN_PROCESS_SIZE {
                continue;
            }

            // Same deferral as the plain staged path: an incomplete block that
            // one more refill can finish belongs to the fast scan/batch path,
            // not the checked mid-block reader. The writer switch above already
            // ran for this cursor, so waiting for more input cannot skip a
            // volume boundary. Progress is guaranteed by the loop-head refill,
            // which either stages bytes or reports EOF.
            if !reached_eof && staged.read_space_len() > 0 {
                continue;
            }

            #[cfg(test)]
            parallel::note_streaming_block_fallback();

            // No complete block fits before the boundary (or within the
            // stage): read one header and decode that block sequentially via
            // the in-flight branch above.
            let mut reader = BitReader::new(staged_slice);
            if !self.try_read_block_header_buffered(&mut reader)? {
                if reached_eof {
                    break;
                }
                // Only a full stage gets here, so another round would re-read
                // the same bytes forever.
                return Err(RarError::CorruptArchive {
                    detail: "RAR5 block header did not fit a full input stage".into(),
                });
            }

            staged_bit_offset = reader.position();
        }

        self.flush_filters_and_write(&mut *current_writer)?;
        if chunk_bytes > 0 || chunks.is_empty() {
            chunks.push((current_vol, chunk_bytes));
        }

        Ok(chunks)
    }

    fn decompress_reader_to_writer_chunked_single_thread<Rd: std::io::Read, F>(
        &mut self,
        input: Rd,
        unpacked_size: u64,
        first_volume_index: usize,
        transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        mut writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        F: FnMut(usize) -> RarResult<Box<dyn Write>>,
    {
        self.begin_file_decode(unpacked_size);
        let mut reader = StreamingBitReader::new(input);
        let mut output_size: u64 = 0;
        let mut boundary_idx = 0;

        let mut chunks: Vec<(usize, u64)> = Vec::new();
        let mut current_vol = first_volume_index;
        let mut current_writer = writer_factory(current_vol)?;
        let mut chunk_bytes: u64 = 0;

        while output_size < self.decode_limit() {
            if self.block_bits_remaining <= 0 {
                if reader.bits_remaining() < 16 {
                    break;
                }
                self.read_block_header(&mut reader)?;
            }

            let prev_output = output_size;
            self.decode_block(
                &mut reader,
                unpacked_size,
                &mut output_size,
                &mut *current_writer,
            )?;
            let decoded_this_round = output_size - prev_output;

            let byte_pos = reader.byte_position() as u64;
            let boundary = {
                let guard = transitions.lock().map_err(|_| RarError::CorruptArchive {
                    detail: "RAR5 chunked transition state poisoned".into(),
                })?;
                guard.get(boundary_idx).cloned()
            };

            if let Some(boundary) = boundary
                && byte_pos >= boundary.compressed_offset
            {
                self.flush_filters_and_write(&mut *current_writer)?;
                chunk_bytes += decoded_this_round;
                chunks.push((current_vol, chunk_bytes));

                current_vol = boundary.volume_index;
                boundary_idx += 1;
                current_writer = writer_factory(current_vol)?;
                chunk_bytes = 0;
            } else {
                // Writes happen at the write border inside `decode_block`; the
                // volume switch above keeps its flush so chunk attribution and
                // the in-flight-block-finishes-first rule are unchanged.
                chunk_bytes += decoded_this_round;
            }
        }

        self.flush_filters_and_write(&mut *current_writer)?;
        if chunk_bytes > 0 || chunks.is_empty() {
            chunks.push((current_vol, chunk_bytes));
        }

        Ok(chunks)
    }

    /// Flush pending filters and remaining window data to a writer.
    ///
    /// The queue is kept sorted by `block_start` on insert, so this walks it
    /// from the front, retires each filter whose block is fully decoded, and
    /// stops at the first one that is not. Nothing is allocated when the head
    /// filter cannot complete yet, and only the retired prefix is removed.
    fn flush_filters_and_write<W: Write + ?Sized>(&mut self, writer: &mut W) -> RarResult<()> {
        if self.pending_filters.is_empty() {
            return self.flush_unfiltered_stream_output(writer);
        }

        let total = self.window.total_written();
        let mut written_up_to = self.window.total_flushed();
        let mut retired = 0usize;

        while retired < self.pending_filters.len() {
            let filter = &self.pending_filters[retired];
            let filter_type = filter.filter_type;
            let block_start = filter.block_start;
            let block_length = filter.block_length;
            let channels = filter.channels;

            if block_start < written_up_to {
                // Its bytes are already written, so RAR would never apply this
                // filter either. Drop it instead of failing the whole member.
                retired += 1;
                continue;
            }

            // Bytes before the filter belong to the unfiltered stream. This is
            // a no-op — and the cheap early-out — when the head filter starts
            // at the flushed border and cannot complete yet.
            let prefix_end = block_start.min(total);
            if prefix_end > written_up_to {
                self.write_raw_span(prefix_end, writer)?;
                written_up_to = prefix_end;
            }

            let block_end = block_start.saturating_add(block_length as u64);
            if block_end > total {
                // The head block is still open; every later filter starts at or
                // after it, so none of them can be applied yet either.
                break;
            }

            let file_block_start = self.current_file_written_size;
            let mut buf = self.window.try_copy_output(block_start, block_length)?;
            match filter_type {
                FilterType::Delta => filter::apply_delta(&mut buf, channels),
                FilterType::E8 => filter::apply_e8(&mut buf, file_block_start),
                FilterType::E8E9 => filter::apply_e8e9(&mut buf, file_block_start),
                FilterType::Arm => filter::apply_arm(&mut buf, file_block_start),
                FilterType::Unsupported(_) => {}
            }
            if filter_type.emits_output() {
                // No clamp: the oracle hands the whole block to `UnpWrite` and
                // adds all of it to `WrittenFileSize` (unpack50.cpp:355-360),
                // so a filtered block is emitted in full even when it carries
                // the member past its declared size.
                writer.write_all(&buf).map_err(RarError::Io)?;
                self.current_file_emitted = self
                    .current_file_emitted
                    .saturating_add(block_length as u64);
            }
            self.current_file_written_size += block_length as u64;
            written_up_to = block_end;
            self.window.mark_flushed(written_up_to);
            retired += 1;
        }

        if retired == self.pending_filters.len() {
            self.pending_filters.clear();
            if written_up_to < total {
                self.write_raw_span(total, writer)?;
                written_up_to = total;
            }
        } else if retired > 0 {
            self.pending_filters.drain(..retired);
        }

        self.window.mark_flushed(written_up_to);
        self.recompute_flush_border();

        Ok(())
    }

    /// Reset the decoder for a new file (non-solid mode).
    pub fn reset(&mut self) {
        self.window.reset();
        self.dist_cache = [usize::MAX; DIST_CACHE_SIZE];
        self.last_length = 0;
        self.nc_table = None;
        self.dc_table = None;
        self.ldc_table = None;
        self.rc_table = None;
        self.code_lengths.fill(0);
        self.block_bits_remaining = 0;
        self.is_last_block = false;
        self.pending_filters.clear();
        self.current_file_base_total = 0;
        self.current_file_written_size = 0;
        self.parallel_mode_exhausted = false;
        self.recompute_flush_border();
    }

    /// Prepare for the next member in a solid archive.
    ///
    /// In solid mode, the sliding window (dictionary) carries over between
    /// files, enabling cross-file back-references. The distance cache and
    /// Huffman tables also persist.
    pub fn prepare_solid_continuation(&mut self) {
        self.block_bits_remaining = 0;
        self.is_last_block = false;
        self.pending_filters.clear();
        self.current_file_base_total = self.window.total_written();
        self.current_file_written_size = 0;
        self.parallel_mode_exhausted = false;
        self.recompute_flush_border();
    }

    /// Align decoder state with the next solid member's compression parameters.
    ///
    /// RAR stores `ExtraDist` per file, so one solid stream may mix RAR5
    /// (version 0) and RAR7 (version 1) members; Huffman tables persist across
    /// the switch. The window cannot grow mid-solid-stream, so a member
    /// declaring a dictionary larger than the existing window is rejected.
    pub fn ensure_solid_member_compat(&mut self, dict_size: usize, version: u8) -> RarResult<()> {
        if dict_size > self.window.dict_size() {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "solid member declares {dict_size} byte dictionary but the solid stream window is {} bytes",
                    self.window.dict_size()
                ),
            });
        }
        let extra_dist = Self::extra_dist_for_version(version)?;
        if extra_dist != self.extra_dist {
            self.extra_dist = extra_dist;
            self.code_lengths.clear();
            self.code_lengths
                .resize(huffman::total_symbols(extra_dist), 0);
        }
        Ok(())
    }

    /// Reuse this decoder for the next **non-solid** member.
    ///
    /// RAR runs one `Unpack` object per command: `Init` re-points the window at
    /// the new file's dictionary size and keeps the existing allocation
    /// whenever it fits (unpack.cpp:107-157) without ever memsetting it, and
    /// `UnpInitData(false)` clears the per-file state. This is the same
    /// contract, so an archive pays for its window and input staging once
    /// instead of once per member.
    ///
    /// Unlike [`Self::ensure_solid_member_compat`], a larger dictionary is
    /// accepted: a non-solid member starts from an empty history, so the
    /// reallocation inside [`Window::ensure_capacity`] discards nothing the
    /// member could have referenced.
    pub fn prepare_reuse(&mut self, dict_size: usize, version: u8) -> RarResult<()> {
        // Validate before touching any state so a rejected member leaves the
        // decoder exactly as it was.
        let extra_dist = Self::extra_dist_for_version(version)?;

        // No memset: `reset_for_reuse` documents why the window's own
        // first-window guard makes leftover bytes unreachable.
        self.window.reset_for_reuse(dict_size)?;

        if extra_dist == self.extra_dist {
            self.code_lengths.fill(0);
        } else {
            self.extra_dist = extra_dist;
            self.code_lengths.clear();
            self.code_lengths
                .resize(huffman::total_symbols(extra_dist), 0);
        }

        self.dist_cache = [usize::MAX; DIST_CACHE_SIZE];
        self.last_length = 0;
        self.nc_table = None;
        self.dc_table = None;
        self.ldc_table = None;
        self.rc_table = None;
        self.block_bits_remaining = 0;
        self.is_last_block = false;
        self.pending_filters.clear();
        self.current_file_base_total = 0;
        self.current_file_written_size = 0;
        self.parallel_mode_exhausted = false;
        self.recompute_flush_border();
        Ok(())
    }

    /// Borrow the recycled input stage, or allocate it on first streaming use.
    fn take_staged_input(&mut self) -> StagedInput {
        match self.staged_input.take() {
            Some(mut staged) => {
                staged.reset();
                staged
            }
            None => StagedInput::new(),
        }
    }

    fn recycle_staged_input(&mut self, staged: StagedInput) {
        self.staged_input = Some(staged);
    }
}

/// Error construction kept out of the per-block table hoist.
#[cold]
#[inline(never)]
fn missing_table_error(what: &str) -> RarError {
    RarError::CorruptArchive {
        detail: format!("RAR5 LZ block is missing {what} table"),
    }
}

/// Error construction kept out of the per-symbol distance path.
#[cold]
#[inline(never)]
pub(super) fn distance_out_of_range_error(distance: u64) -> RarError {
    RarError::CorruptArchive {
        detail: format!("RAR5 distance {distance} does not fit in usize"),
    }
}

/// Decompress LZ-compressed data.
///
/// `input` is the compressed data area.
/// `unpacked_size` is the expected output size.
/// `info` provides compression parameters (dictionary size, solid flag, etc.).
///
/// Returns the decompressed data.
pub fn decompress_lz(
    input: &[u8],
    unpacked_size: u64,
    info: &CompressionInfo,
) -> RarResult<Vec<u8>> {
    decompress_lz_with_max_dict_size(input, unpacked_size, info, Limits::default().max_dict_size)
}

pub(crate) fn decompress_lz_with_max_dict_size(
    input: &[u8],
    unpacked_size: u64,
    info: &CompressionInfo,
    max_dict_size: u64,
) -> RarResult<Vec<u8>> {
    let dict_size = checked_lz_dict_size(info, max_dict_size)?;
    let mut decoder = LzDecoder::try_new(dict_size, info.version)?;
    decoder.decompress(input, unpacked_size)
}

/// Streaming variant: decompress LZ data directly to a writer.
///
/// Memory usage is bounded to the default dictionary limit instead of
/// accumulating the full output in memory.
pub fn decompress_lz_to_writer<W: Write>(
    input: &[u8],
    unpacked_size: u64,
    info: &CompressionInfo,
    writer: &mut W,
) -> RarResult<u64> {
    decompress_lz_to_writer_with_max_dict_size(
        input,
        unpacked_size,
        info,
        writer,
        Limits::default().max_dict_size,
    )
}

pub(crate) fn decompress_lz_to_writer_with_max_dict_size<W: Write>(
    input: &[u8],
    unpacked_size: u64,
    info: &CompressionInfo,
    writer: &mut W,
    max_dict_size: u64,
) -> RarResult<u64> {
    let dict_size = checked_lz_dict_size(info, max_dict_size)?;
    let mut decoder = LzDecoder::try_new(dict_size, info.version)?;
    decoder.decompress_to_writer(input, unpacked_size, writer)
}

pub fn decompress_lz_reader_to_writer<Rd: std::io::Read, W: Write>(
    input: Rd,
    unpacked_size: u64,
    info: &CompressionInfo,
    writer: &mut W,
) -> RarResult<u64> {
    decompress_lz_reader_to_writer_with_max_dict_size(
        input,
        unpacked_size,
        info,
        writer,
        Limits::default().max_dict_size,
    )
}

pub(crate) fn decompress_lz_reader_to_writer_with_max_dict_size<Rd: std::io::Read, W: Write>(
    input: Rd,
    unpacked_size: u64,
    info: &CompressionInfo,
    writer: &mut W,
    max_dict_size: u64,
) -> RarResult<u64> {
    let dict_size = checked_lz_dict_size(info, max_dict_size)?;
    let mut decoder = LzDecoder::try_new(dict_size, info.version)?;
    decoder.decompress_reader_to_writer(input, unpacked_size, writer)
}

pub fn decompress_lz_reader_to_writer_chunked<Rd: std::io::Read, F>(
    input: Rd,
    unpacked_size: u64,
    info: &CompressionInfo,
    first_volume_index: usize,
    transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
    writer_factory: F,
) -> RarResult<Vec<(usize, u64)>>
where
    F: FnMut(usize) -> RarResult<Box<dyn Write>>,
{
    decompress_lz_reader_to_writer_chunked_with_max_dict_size(
        input,
        unpacked_size,
        info,
        first_volume_index,
        transitions,
        writer_factory,
        Limits::default().max_dict_size,
    )
}

pub(crate) fn decompress_lz_reader_to_writer_chunked_with_max_dict_size<Rd: std::io::Read, F>(
    input: Rd,
    unpacked_size: u64,
    info: &CompressionInfo,
    first_volume_index: usize,
    transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
    writer_factory: F,
    max_dict_size: u64,
) -> RarResult<Vec<(usize, u64)>>
where
    F: FnMut(usize) -> RarResult<Box<dyn Write>>,
{
    let dict_size = checked_lz_dict_size(info, max_dict_size)?;
    let mut decoder = LzDecoder::try_new(dict_size, info.version)?;
    decoder.decompress_reader_to_writer_chunked(
        input,
        unpacked_size,
        first_volume_index,
        transitions,
        writer_factory,
    )
}

pub(crate) fn decompress_lz_to_writer_chunked_with_max_dict_size<F>(
    input: &[u8],
    unpacked_size: u64,
    info: &CompressionInfo,
    first_volume_index: usize,
    boundaries: &[super::VolumeTransition],
    writer_factory: F,
    max_dict_size: u64,
) -> RarResult<Vec<(usize, u64)>>
where
    F: FnMut(usize) -> RarResult<Box<dyn Write>>,
{
    let dict_size = checked_lz_dict_size(info, max_dict_size)?;
    let mut decoder = LzDecoder::try_new(dict_size, info.version)?;
    decoder.decompress_to_writer_chunked(
        input,
        unpacked_size,
        first_volume_index,
        boundaries,
        writer_factory,
    )
}

pub(crate) fn effective_lz_window_size(dict_size: u64) -> u64 {
    dict_size.max(RAR_MIN_LZ_WINDOW_SIZE)
}

pub(crate) fn checked_lz_dict_size(info: &CompressionInfo, max_dict_size: u64) -> RarResult<usize> {
    let dict_size = effective_lz_window_size(info.dict_size);
    if dict_size > RAR_UNPACK_MAX_DICT_SIZE {
        return Err(RarError::DictionaryTooLarge {
            size: dict_size,
            max: RAR_UNPACK_MAX_DICT_SIZE,
        });
    }
    if dict_size > max_dict_size {
        return Err(RarError::DictionaryTooLarge {
            size: dict_size,
            max: max_dict_size,
        });
    }

    usize::try_from(dict_size).map_err(|_| RarError::DictionaryTooLarge {
        size: dict_size,
        max: usize::MAX as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_border_reserves_maximum_incremental_match_margin() {
        let dict_size = 1 << 20;
        let write_span = 100_000usize;

        // Fully drained window: the border is one write span ahead, minus the
        // widest single LZ item.
        let border = LzDecoder::flush_border(4_000, 4_000, dict_size, write_span);
        assert_eq!(border, 4_000 + write_span as u64 - MAX_INCREMENTAL_LZ_MATCH);

        // A write that could not drain the window (a pending filter still
        // covers it) pulls the border back to the ring-full point so the retry
        // still happens before the dictionary overruns.
        let stalled = LzDecoder::flush_border(1_000_000, 0, dict_size, write_span);
        assert_eq!(stalled, dict_size as u64 - MAX_INCREMENTAL_LZ_MATCH);

        // Tiny dictionaries clamp to zero instead of wrapping, which makes the
        // gate fire on every item.
        assert_eq!(LzDecoder::flush_border(6, 6, 8, 8), 0);
    }

    #[test]
    fn write_border_advances_only_when_the_flush_routines_run() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        let write_span = decoder.flush_threshold() as u64;
        assert_eq!(decoder.flush_at, write_span - MAX_INCREMENTAL_LZ_MATCH);

        decoder.window.put_bytes(&[0u8; 4096]);
        assert_eq!(decoder.flush_at, write_span - MAX_INCREMENTAL_LZ_MATCH);

        let mut out = Vec::new();
        decoder.flush_stream_output(&mut out).unwrap();

        assert_eq!(out.len(), 4096);
        assert_eq!(
            decoder.flush_at,
            4096 + write_span - MAX_INCREMENTAL_LZ_MATCH
        );
    }

    #[test]
    fn border_flush_cadence_writes_once_per_border_not_per_block() {
        struct CountingWriter {
            writes: usize,
            bytes: usize,
        }

        impl Write for CountingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                self.bytes += buf.len();
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // A dictionary well under UNPACK_MAX_WRITE makes the border land after
        // `dict_size - MAX_INCREMENTAL_LZ_MATCH` bytes of output.
        let dict_size = 256 * 1024;
        let mut decoder = LzDecoder::new(dict_size, 0);
        let mut writer = CountingWriter {
            writes: 0,
            bytes: 0,
        };
        let mut output_size = 0u64;

        // Simulate many small "blocks": each round produces far less output
        // than one border span.
        let block_bytes = 4 * 1024;
        let rounds = 64;
        for _ in 0..rounds {
            for _ in 0..block_bytes {
                if decoder.window.total_written() >= decoder.flush_at {
                    decoder.flush_stream_output(&mut writer).unwrap();
                }
                decoder.window.put_byte(0xA5);
                output_size += 1;
            }
        }
        decoder.flush_filters_and_write(&mut writer).unwrap();

        let produced = (block_bytes * rounds) as u64;
        assert_eq!(output_size, produced);
        assert_eq!(writer.bytes as u64, produced);
        // Per-block cadence would be `rounds` writes. The border cadence emits
        // one span per border crossing plus the final drain, and each of those
        // can split at most once at the ring wrap.
        let border_span = dict_size as u64 - MAX_INCREMENTAL_LZ_MATCH;
        let border_crossings = produced.div_ceil(border_span) as usize + 1;
        assert!(
            writer.writes <= border_crossings * 2,
            "expected at most {} writes, saw {}",
            border_crossings * 2,
            writer.writes
        );
        assert!(writer.writes < rounds, "saw {} writes", writer.writes);
    }

    #[test]
    fn per_file_resets_clear_large_block_mode() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);

        decoder.parallel_mode_exhausted = true;
        decoder.reset();
        assert!(!decoder.parallel_mode_exhausted);

        decoder.parallel_mode_exhausted = true;
        decoder.prepare_solid_continuation();
        assert!(!decoder.parallel_mode_exhausted);
    }

    #[test]
    fn truncated_header_rollback_preserves_large_block_mode() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.parallel_mode_exhausted = true;
        let mut reader = BitReader::new(&[]);

        assert!(!decoder.try_read_block_header_buffered(&mut reader).unwrap());
        assert!(decoder.parallel_mode_exhausted);
    }

    #[test]
    fn test_slot_to_length_formula() {
        // Slots 0-7: base = 2 + slot, no extra bits
        let data = [0u8; 8]; // unused, no bits needed for slots 0-7
        for slot in 0..8 {
            let mut reader = BitReader::new(&data);
            let len = LzDecoder::slot_to_length(&mut reader, slot).unwrap();
            assert_eq!(len, 2 + slot, "slot {slot}");
        }
    }

    #[test]
    fn test_slot_to_length_groups_of_4() {
        // Verify extra bits group in 4s (not 3s): slots 8-11 all have 1 extra bit
        let data = [0xFF; 8]; // all 1s for extra bits
        for slot in 8..12 {
            let mut reader = BitReader::new(&data);
            let len = LzDecoder::slot_to_length(&mut reader, slot).unwrap();
            // With 1 extra bit = 1, check base + 1
            let lbits = slot / 4 - 1;
            let base = 2 + ((4 | (slot & 3)) << lbits);
            assert_eq!(lbits, 1, "slots 8-11 should have 1 extra bit");
            assert_eq!(len, base + 1, "slot {slot}"); // extra bit reads 1
        }
    }

    #[test]
    fn test_slot_to_length_max() {
        // Slot 43 with max extra bits should give MAX_LZ_MATCH = 4097
        let data = [0xFF; 8]; // all 1s
        let mut reader = BitReader::new(&data);
        let len = LzDecoder::slot_to_length(&mut reader, 43).unwrap();
        // slot 43: lbits = 43/4-1 = 9, base = 2 + (4|3)<<9 = 2 + 7*512 = 3586
        // extra = 9 bits of 1s = 511, total = 3586 + 511 = 4097
        assert_eq!(len, 4097);
    }

    #[test]
    fn test_decoder_creation() {
        let decoder = LzDecoder::new(128 * 1024, 0);
        assert_eq!(decoder.window.dict_size(), 128 * 1024);
        assert_eq!(decoder.dist_cache, [usize::MAX; 4]);
    }

    #[test]
    fn test_uninitialized_old_dist_uses_rar_behavior_sentinel() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);

        assert_eq!(decoder.promote_old_dist(2).unwrap(), usize::MAX);
        assert_eq!(decoder.dist_cache, [usize::MAX; 4]);
    }

    #[test]
    fn lz_decoder_rejects_future_rar5_unpack_versions_like_rar_behavior() {
        assert!(matches!(
            LzDecoder::try_new(128 * 1024, 2),
            Err(RarError::UnsupportedCompression { version: 2, .. })
        ));
    }

    #[test]
    fn lz_decoder_accepts_rar7_unpack_version_like_rar_behavior() {
        let decoder = LzDecoder::try_new(128 * 1024, 1).unwrap();

        assert!(decoder.extra_dist);
        assert_eq!(
            decoder.code_lengths.len(),
            huffman::HUFF_NC + huffman::HUFF_DCX + huffman::HUFF_LDC + huffman::HUFF_RC
        );
    }

    #[test]
    fn test_effective_lz_window_uses_rar_behavior_minimum() {
        assert_eq!(effective_lz_window_size(128 * 1024), 0x40000);
        assert_eq!(effective_lz_window_size(512 * 1024), 512 * 1024);
    }

    #[test]
    fn distance_slot_parts_compute_boundary_distances_exactly() {
        let distance = LzDecoder::distance_from_slot_parts(61, 29, (1u64 << 29) - 16, 15).unwrap();

        assert_eq!(distance, 0x8000_0000);
    }

    #[test]
    fn distance_slot_parts_allow_rar7_extended_distance() {
        let distance = LzDecoder::distance_from_slot_parts(79, 38, 0, 0).unwrap();

        assert_eq!(distance, (3u64 << 38) as usize + 1);
    }

    #[test]
    fn test_checked_lz_dict_size_enforces_effective_minimum() {
        let info = CompressionInfo {
            format: crate::types::ArchiveFormat::Rar5,
            version: 0,
            solid: false,
            method: crate::types::CompressionMethod::Normal,
            dict_size: 128 * 1024,
        };

        let result = checked_lz_dict_size(&info, 128 * 1024);

        assert!(matches!(
            result,
            Err(RarError::DictionaryTooLarge {
                size: 262_144,
                max: 131_072
            })
        ));
    }

    #[test]
    fn test_checked_lz_dict_size_allows_custom_limit_above_default() {
        let info = CompressionInfo {
            format: crate::types::ArchiveFormat::Rar5,
            version: 1,
            solid: false,
            method: crate::types::CompressionMethod::Normal,
            dict_size: 512 * 1024 * 1024,
        };

        let dict_size = checked_lz_dict_size(&info, 512 * 1024 * 1024).unwrap();

        assert_eq!(dict_size, 512 * 1024 * 1024);
    }

    #[test]
    fn test_max_dict_size_enforcement() {
        let info = CompressionInfo {
            format: crate::types::ArchiveFormat::Rar5,
            version: 0,
            solid: false,
            method: crate::types::CompressionMethod::Normal,
            dict_size: 1024 * 1024 * 1024, // 1 GB
        };
        let result = decompress_lz(&[], 0, &info);
        assert!(matches!(result, Err(RarError::DictionaryTooLarge { .. })));
    }

    #[test]
    fn test_empty_input() {
        let info = CompressionInfo {
            format: crate::types::ArchiveFormat::Rar5,
            version: 0,
            solid: false,
            method: crate::types::CompressionMethod::Normal,
            dict_size: 128 * 1024,
        };
        let result = decompress_lz(&[], 0, &info);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decoder_reset() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.dist_cache = [10, 20, 30, 40];
        decoder.block_bits_remaining = 100;
        decoder.reset();
        assert_eq!(decoder.dist_cache, [usize::MAX; 4]);
        assert_eq!(decoder.block_bits_remaining, 0);
        assert!(decoder.nc_table.is_none());
    }

    #[test]
    fn test_prepare_solid_continuation() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.dist_cache = [10, 20, 30, 40];
        decoder.block_bits_remaining = 50;
        // Write some data to the window to simulate previous decompression.
        decoder.window.put_byte(0xAA);
        decoder.window.put_byte(0xBB);

        decoder.prepare_solid_continuation();

        // block state should be reset.
        assert_eq!(decoder.block_bits_remaining, 0);
        // dist_cache should be preserved.
        assert_eq!(decoder.dist_cache, [10, 20, 30, 40]);
        // Window state should be preserved.
        assert_eq!(decoder.window.total_written(), 2);
        assert_eq!(decoder.window.get_byte(1), 0xBB);
        assert_eq!(decoder.window.get_byte(2), 0xAA);
    }

    #[test]
    fn solid_version_switch_updates_extra_dist_and_code_lengths_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.dist_cache = [10, 20, 30, 40];
        decoder.window.put_byte(0xAA);
        assert!(!decoder.extra_dist);
        assert_eq!(decoder.code_lengths.len(), huffman::total_symbols(false));

        // RAR7 member continuing a RAR5-started solid stream.
        decoder
            .ensure_solid_member_compat(128 * 1024, 1)
            .expect("version switch must be accepted");

        assert!(decoder.extra_dist);
        assert_eq!(decoder.code_lengths.len(), huffman::total_symbols(true));
        // Window and rep-distance state carry across the per-file ExtraDist
        // switch.
        assert_eq!(decoder.dist_cache, [10, 20, 30, 40]);
        assert_eq!(decoder.window.total_written(), 1);

        // Switching back also works and shrinks the table scratch.
        decoder
            .ensure_solid_member_compat(128 * 1024, 0)
            .expect("switch back must be accepted");
        assert!(!decoder.extra_dist);
        assert_eq!(decoder.code_lengths.len(), huffman::total_symbols(false));
    }

    #[test]
    fn solid_member_same_version_is_a_noop() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.code_lengths[0] = 7;

        decoder
            .ensure_solid_member_compat(64 * 1024, 0)
            .expect("same version, smaller dict is fine");

        // No resize happened; scratch contents untouched.
        assert_eq!(decoder.code_lengths[0], 7);
    }

    #[test]
    fn solid_member_dict_growth_is_rejected_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);

        let err = decoder
            .ensure_solid_member_compat(256 * 1024, 0)
            .unwrap_err();

        assert!(matches!(err, RarError::CorruptArchive { .. }));
    }

    #[test]
    fn solid_member_unknown_version_is_rejected() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);

        let err = decoder
            .ensure_solid_member_compat(128 * 1024, 2)
            .unwrap_err();

        assert!(matches!(
            err,
            RarError::UnsupportedCompression { version: 2, .. }
        ));
    }

    #[test]
    fn prepare_reuse_clears_per_file_state_like_a_fresh_decoder() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.dist_cache = [10, 20, 30, 40];
        decoder.last_length = 9;
        decoder.block_bits_remaining = 100;
        decoder.is_last_block = true;
        decoder.parallel_mode_exhausted = true;
        decoder.current_file_written_size = 77;
        decoder.code_lengths[0] = 7;
        decoder.nc_table = Some(Arc::new(HuffmanTable::build(&[9u8; 306]).unwrap()));
        decoder.window.put_bytes(b"previous member output");

        decoder.prepare_reuse(128 * 1024, 0).unwrap();

        assert_eq!(decoder.dist_cache, [usize::MAX; DIST_CACHE_SIZE]);
        assert_eq!(decoder.last_length, 0);
        assert_eq!(decoder.block_bits_remaining, 0);
        assert!(!decoder.is_last_block);
        assert!(!decoder.parallel_mode_exhausted);
        assert_eq!(decoder.current_file_base_total, 0);
        assert_eq!(decoder.current_file_written_size, 0);
        assert!(decoder.nc_table.is_none());
        assert!(decoder.code_lengths.iter().all(|&length| length == 0));
        // The window restarts empty, so nothing the previous member wrote is
        // reachable — but the allocation is kept.
        assert_eq!(decoder.window.total_written(), 0);
        assert_eq!(decoder.window.total_flushed(), 0);

        let fresh = LzDecoder::new(128 * 1024, 0);
        assert_eq!(decoder.flush_at, fresh.flush_at);
    }

    #[test]
    fn prepare_reuse_resizes_the_window_in_both_directions() {
        let mut decoder = LzDecoder::new(256 * 1024, 0);

        decoder.prepare_reuse(1024 * 1024, 0).unwrap();
        assert_eq!(decoder.window.dict_size(), 1024 * 1024);
        assert_eq!(decoder.window.allocated_size(), 1024 * 1024);

        // Shrinking keeps the larger allocation: reuse must not thrash the
        // dictionary buffer across members.
        decoder.prepare_reuse(128 * 1024, 0).unwrap();
        assert_eq!(decoder.window.dict_size(), 128 * 1024);
        assert_eq!(decoder.window.allocated_size(), 1024 * 1024);
    }

    #[test]
    fn prepare_reuse_tracks_the_member_unpack_version() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        assert!(!decoder.extra_dist);

        decoder.prepare_reuse(128 * 1024, 1).unwrap();
        assert!(decoder.extra_dist);
        assert_eq!(decoder.code_lengths.len(), huffman::total_symbols(true));

        decoder.prepare_reuse(128 * 1024, 0).unwrap();
        assert!(!decoder.extra_dist);
        assert_eq!(decoder.code_lengths.len(), huffman::total_symbols(false));
    }

    #[test]
    fn prepare_reuse_rejects_unknown_versions_without_touching_state() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"in flight");
        decoder.block_bits_remaining = 42;

        let err = decoder.prepare_reuse(128 * 1024, 2).unwrap_err();

        assert!(matches!(
            err,
            RarError::UnsupportedCompression { version: 2, .. }
        ));
        assert_eq!(decoder.window.total_written(), 9);
        assert_eq!(decoder.block_bits_remaining, 42);
    }

    // The `rar5_filter_bounds.rar` fixture that drove
    // `rar5_filtered_output_is_bounded_at_the_write_layer_like_rar_behavior`
    // was hand-assembled: RARLAB's writer never emits a filter block that
    // overruns the declared member size, so no legitimate tool could produce
    // it. Fixtures are created by RARLAB tooling or imported unmodified from a
    // public upstream, and nothing else, so the fixture, its expectation table
    // and the test are gone. `UnpWriteData`'s write-side contract is still
    // covered by the unit tests above and by the real filtered archives in the
    // imported corpus.

    struct FixtureMember {
        packed: Vec<u8>,
        unpacked_size: u64,
        version: u8,
    }

    /// Pull one named member's raw compressed stream out of a single-volume
    /// fixture.
    fn fixture_member(fixture: &str, member_name: &str) -> Option<FixtureMember> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar5")
            .join(fixture);
        // Existence is the wrong guard under partial Git LFS hydration (see
        // stored_layout.rs): a pointer stub exists and then fails the parse.
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping test: {fixture} fixture not present");
            return None;
        };
        if !bytes.starts_with(b"Rar!") {
            eprintln!("skipping test: {fixture} fixture not hydrated (LFS pointer)");
            return None;
        }
        let archive =
            crate::RarArchive::open(std::io::Cursor::new(bytes.clone())).expect("fixture parses");
        let metadata = archive.metadata();
        let index = metadata
            .members
            .iter()
            .position(|member| member.name == member_name)
            .expect("member present");
        let member = &metadata.members[index];
        let unpacked_size = member.unpacked_size.expect("member declares its size");
        let version = member.compression.version;
        let mut packed = Vec::new();
        for segment in archive.member_segments(index).expect("member segments") {
            let start = segment.data_offset as usize;
            let end = start + segment.data_size as usize;
            packed.extend_from_slice(&bytes[start..end]);
        }
        Some(FixtureMember {
            packed,
            unpacked_size,
            version,
        })
    }

    fn decode_with(decoder: &mut LzDecoder, member: &FixtureMember) -> Vec<u8> {
        let mut output = Vec::new();
        let written = decoder
            .decompress_reader_to_writer(
                member.packed.as_slice(),
                member.unpacked_size,
                &mut output,
            )
            .expect("member decodes");
        assert_eq!(written, member.unpacked_size);
        output
    }

    #[test]
    fn reused_decoder_matches_fresh_decoders_across_non_solid_members() {
        // Seven independent non-solid LZ members, so the reused decoder has to
        // clear real per-file state rather than a pristine one.
        let Some(first) = fixture_member("test_read_format_rar5_win32.rar", "test.bin") else {
            return;
        };
        let second =
            fixture_member("test_read_format_rar5_win32.rar", "test1.bin").expect("second member");

        // A non-solid stream never reaches behind its own start, so a wider
        // window decodes it identically; that lets one fixture exercise a
        // dictionary that grows and then shrinks across members.
        let large = 1024 * 1024usize;
        let small = 128 * 1024usize;

        let mut fresh_first = LzDecoder::try_new(large, first.version).unwrap();
        let expected_first = decode_with(&mut fresh_first, &first);
        let mut fresh_second = LzDecoder::try_new(small, second.version).unwrap();
        let expected_second = decode_with(&mut fresh_second, &second);

        let mut reused = LzDecoder::try_new(small, first.version).unwrap();
        reused.prepare_reuse(large, first.version).unwrap();
        let actual_first = decode_with(&mut reused, &first);
        // Larger dictionary first, then a smaller one: the reuse must shrink
        // the logical window without dragging the previous member's history in.
        reused.prepare_reuse(small, second.version).unwrap();
        let actual_second = decode_with(&mut reused, &second);

        assert_eq!(actual_first, expected_first);
        assert_eq!(actual_second, expected_second);
        assert_eq!(reused.window.dict_size(), small);
        // One allocation covered both members.
        assert_eq!(reused.window.allocated_size(), large);
    }

    #[test]
    fn reused_decoder_recycles_its_input_staging() {
        // Only the staged path owns an input stage.
        if !parallel::parallel_enabled() {
            return;
        }
        let Some(member) = fixture_member("test_read_format_rar5_win32.rar", "test.bin") else {
            return;
        };

        let mut decoder = LzDecoder::try_new(128 * 1024, member.version).unwrap();
        assert!(decoder.staged_input.is_none());

        decode_with(&mut decoder, &member);
        let staged_ptr = decoder
            .staged_input
            .as_ref()
            .expect("streaming decode installs the stage")
            .padded_input()
            .as_ptr();

        decoder.prepare_reuse(128 * 1024, member.version).unwrap();
        decode_with(&mut decoder, &member);

        assert_eq!(
            decoder
                .staged_input
                .as_ref()
                .expect("stage survives the member")
                .padded_input()
                .as_ptr(),
            staged_ptr
        );
    }

    #[test]
    fn test_flush_filters_stops_at_first_incomplete_block() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"abcdefghij");
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 4,
                block_length: 8,
                channels: 0,
            },
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 8,
                block_length: 1,
                channels: 0,
            },
        ];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        assert_eq!(out, b"abcd");
        assert_eq!(decoder.window.total_flushed(), 4);
        assert_eq!(decoder.pending_filters.len(), 2);
        assert_eq!(decoder.pending_filters[0].block_start, 4);
        assert_eq!(decoder.pending_filters[1].block_start, 8);
    }

    #[test]
    fn test_filterless_flush_advances_hidden_match_tail_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"ABCD");
        decoder.window.mark_flushed(4);
        decoder.current_file_written_size = 4;
        decoder.window.copy_with_visible_len(4, 4, 2).unwrap();

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        assert_eq!(out, b"AB");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
        assert_eq!(decoder.current_file_written_size, 8);
    }

    #[test]
    fn test_raw_stream_flush_advances_later_filter_file_offset_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        let mut out = Vec::new();

        decoder.window.put_bytes(b"prefix");
        decoder.flush_stream_output(&mut out).unwrap();
        assert_eq!(out, b"prefix");
        assert_eq!(decoder.window.total_flushed(), 6);
        assert_eq!(decoder.current_file_written_size, 6);

        decoder.window.put_bytes(&[0xe8, 100, 0, 0, 0]);
        decoder.pending_filters = vec![PendingFilter {
            filter_type: FilterType::E8,
            block_start: 6,
            block_length: 5,
            channels: 0,
        }];

        decoder.flush_stream_output(&mut out).unwrap();

        let mut expected_filter_output = vec![0xe8, 100, 0, 0, 0];
        filter::apply_e8(&mut expected_filter_output, 6);
        assert_eq!(&out[..6], b"prefix");
        assert_eq!(&out[6..], expected_filter_output.as_slice());
        assert_ne!(&out[6..], &[0xe8, 99, 0, 0, 0]);
        assert_eq!(decoder.current_file_written_size, 11);
    }

    /// The filtered write is not clamped, so a hidden tail inside a filter
    /// block still reaches the writer.
    ///
    /// The oracle hands the whole block to `UnpWrite` and adds all of it to
    /// `WrittenFileSize` (unpack50.cpp:355-360); only `UnpWriteData` clamps,
    /// and only raw spans go through it. The block here covers the hidden tail
    /// entirely, so all four of its bytes go out where the old behaviour
    /// emitted only the two visible ones.
    #[test]
    fn test_filter_block_emits_whole_block_over_a_hidden_tail() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"ABCD");
        decoder.window.mark_flushed(4);
        decoder.current_file_written_size = 4;
        decoder.window.copy_with_visible_len(4, 4, 2).unwrap();
        decoder.pending_filters = vec![PendingFilter {
            filter_type: FilterType::E8,
            block_start: 4,
            block_length: 4,
            channels: 0,
        }];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        let mut expected = decoder.window.copy_output(4, 4);
        filter::apply_e8(&mut expected, 4);
        assert_eq!(out, expected);
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
        assert_eq!(decoder.current_file_written_size, 8);
        assert!(decoder.pending_filters.is_empty());
    }

    #[test]
    fn test_flush_filters_keeps_future_filter_when_no_output_is_ready() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 0,
                block_length: 5,
                channels: 0,
            },
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 8,
                block_length: 5,
                channels: 0,
            },
        ];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        assert!(out.is_empty());
        assert_eq!(decoder.pending_filters.len(), 2);
        assert_eq!(decoder.pending_filters[0].block_start, 0);
        assert_eq!(decoder.pending_filters[1].block_start, 8);
    }

    #[test]
    fn test_unsupported_filter_skips_block_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"prefixBLOCKsuffix");
        decoder.pending_filters = vec![PendingFilter {
            filter_type: FilterType::Unsupported(7),
            block_start: 6,
            block_length: 5,
            channels: 0,
        }];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        assert_eq!(out, b"prefixsuffix");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
        assert!(decoder.pending_filters.is_empty());
    }

    fn write_test_bits(bits: &mut Vec<u8>, value: u32, count: u8) {
        for shift in (0..count).rev() {
            bits.push(((value >> shift) & 1) as u8);
        }
    }

    fn pack_test_bits(bits: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(bits.len().div_ceil(8));
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (idx, bit) in chunk.iter().enumerate() {
                byte |= *bit << (7 - idx);
            }
            bytes.push(byte);
        }
        bytes
    }

    fn rar5_filter_descriptor(block_start: u8, block_length: u8, filter_code: u8) -> Vec<u8> {
        let mut bits = Vec::new();
        write_test_bits(&mut bits, 0, 2);
        write_test_bits(&mut bits, u32::from(block_start), 8);
        write_test_bits(&mut bits, 0, 2);
        write_test_bits(&mut bits, u32::from(block_length), 8);
        write_test_bits(&mut bits, u32::from(filter_code), 3);
        pack_test_bits(&bits)
    }

    #[test]
    fn test_filter_descriptor_resets_unflushable_full_queue_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        // Every queued filter covers bytes that were never decoded, so the
        // overflow write cannot retire any of them.
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 0,
                block_length: 5,
                channels: 0,
            };
            MAX_PENDING_FILTERS
        ];

        let descriptor = rar5_filter_descriptor(3, 5, 1);
        let mut reader = BitReader::new(&descriptor);
        let mut out = Vec::new();
        decoder.handle_filter(&mut reader, 10, &mut out).unwrap();

        assert!(out.is_empty());
        assert_eq!(decoder.pending_filters.len(), 1);
        assert_eq!(decoder.pending_filters[0].filter_type, FilterType::E8);
        assert_eq!(decoder.pending_filters[0].block_start, 13);
        assert_eq!(decoder.pending_filters[0].block_length, 5);
    }

    #[test]
    fn test_full_filter_queue_flushes_before_discarding_like_rar_behavior() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(&[0u8; MAX_PENDING_FILTERS]);
        // Each queued filter covers one already decoded byte, so the overflow
        // write retires the whole queue and nothing is discarded.
        decoder.pending_filters = (0..MAX_PENDING_FILTERS as u64)
            .map(|index| PendingFilter {
                filter_type: FilterType::Arm,
                block_start: index,
                block_length: 1,
                channels: 0,
            })
            .collect();

        let mut out = Vec::new();
        decoder
            .register_pending_filter(
                PendingFilter {
                    filter_type: FilterType::E8,
                    block_start: MAX_PENDING_FILTERS as u64,
                    block_length: 4,
                    channels: 0,
                },
                &mut out,
            )
            .unwrap();

        assert_eq!(out.len(), MAX_PENDING_FILTERS);
        assert_eq!(decoder.pending_filters.len(), 1);
        assert_eq!(
            decoder.pending_filters[0].block_start,
            MAX_PENDING_FILTERS as u64
        );
    }

    #[test]
    fn test_flush_filters_drops_a_filter_behind_the_written_border() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"abcdefghij");
        decoder.window.mark_flushed(6);
        decoder.current_file_written_size = 6;
        // Stale head: its bytes were already written, so it can never apply.
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 2,
                block_length: 3,
                channels: 0,
            },
            PendingFilter {
                filter_type: FilterType::Unsupported(7),
                block_start: 6,
                block_length: 4,
                channels: 0,
            },
        ];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        // The stale filter is dropped rather than failing the member, and the
        // still-applicable one suppresses its own block.
        assert!(out.is_empty());
        assert!(decoder.pending_filters.is_empty());
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
        assert_eq!(decoder.current_file_written_size, 10);
    }

    #[test]
    fn test_apply_filters_to_vec_uses_logical_offset_after_suppressed_block() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        let mut output = b"preXXX".to_vec();
        output.extend_from_slice(&[0xE8, 10, 0, 0, 0]);
        output.extend_from_slice(b"tail");
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::Unsupported(7),
                block_start: 3,
                block_length: 3,
                channels: 0,
            },
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 6,
                block_length: 5,
                channels: 0,
            },
        ];

        let filtered = decoder.apply_filters_to_vec(output, 0);

        let mut expected_e8 = [0xE8, 10, 0, 0, 0];
        filter::apply_e8(&mut expected_e8, 6);
        let mut expected = b"pre".to_vec();
        expected.extend_from_slice(&expected_e8);
        expected.extend_from_slice(b"tail");
        assert_eq!(filtered, expected);
        assert!(decoder.pending_filters.is_empty());
    }

    #[test]
    fn test_flush_filters_uses_logical_offset_after_suppressed_block() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.window.put_bytes(b"preXXX");
        decoder.window.put_bytes(&[0xE8, 10, 0, 0, 0]);
        decoder.window.put_bytes(b"tail");
        decoder.pending_filters = vec![
            PendingFilter {
                filter_type: FilterType::Unsupported(7),
                block_start: 3,
                block_length: 3,
                channels: 0,
            },
            PendingFilter {
                filter_type: FilterType::E8,
                block_start: 6,
                block_length: 5,
                channels: 0,
            },
        ];

        let mut out = Vec::new();
        decoder.flush_filters_and_write(&mut out).unwrap();

        let mut expected_e8 = [0xE8, 10, 0, 0, 0];
        filter::apply_e8(&mut expected_e8, 6);
        let mut expected = b"pre".to_vec();
        expected.extend_from_slice(&expected_e8);
        expected.extend_from_slice(b"tail");
        assert_eq!(out, expected);
        assert_eq!(decoder.current_file_written_size, 15);
        assert!(decoder.pending_filters.is_empty());
    }

    #[test]
    fn test_slot_ranges_contiguous() {
        // Verify the length ranges from SlotToLength are contiguous (no gaps).
        // Each slot covers [base, base + 2^extra_bits). Next slot's base = prev end.
        let data = [0u8; 8];
        let mut prev_end = 3; // slot 0 covers [2,3), slot 1 should start at 3
        for slot in 1..NUM_LENGTH_SLOTS {
            let mut reader = BitReader::new(&data);
            let base = LzDecoder::slot_to_length(&mut reader, slot).unwrap();
            assert_eq!(
                base, prev_end,
                "slot {slot}: base {base} != prev_end {prev_end}"
            );
            let extra_bits = if slot < 8 { 0 } else { slot / 4 - 1 };
            prev_end = base + (1 << extra_bits);
        }
    }

    #[test]
    fn test_all_compression_methods_accepted() {
        for method_code in 1..=5u8 {
            let info = CompressionInfo {
                format: crate::types::ArchiveFormat::Rar5,
                version: 0,
                solid: false,
                method: crate::types::CompressionMethod::from_code(method_code),
                dict_size: 128 * 1024,
            };
            let result = decompress_lz(&[], 0, &info);
            assert!(result.is_ok(), "method {} failed", method_code);
        }
    }
}
