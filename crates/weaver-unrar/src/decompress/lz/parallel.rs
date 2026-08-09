//! Block-level parallel Huffman decode for RAR5 LZ decompression.
//!
//! Scans block headers sequentially to resolve Huffman table dependencies,
//! dispatches per-block symbol decoding to rayon worker threads, then applies
//! decoded items to the window serially.
//!
//! The parallelism is in the Huffman decode phase only — window writes,
//! distance cache updates, and filter application remain sequential because
//! they depend on running output state.

use rayon::ThreadPool;
use std::sync::Arc;
use std::time::Instant;

use super::bitstream::{BitRead, BitReader};
use super::block_reader::BlockReader;
use super::filter::{FilterType, PendingFilter};
use super::huffman::{self, HuffmanTable};
use super::phase_diagnostics::{self, Phase, SymbolKind, WorkerCounters};
use super::{LzDecoder, NUM_LENGTH_SLOTS};
use crate::error::{RarError, RarResult};

struct ScannedBlocks {
    blocks: Vec<BlockInfo>,
    consumed_bytes: usize,
    saw_last_block: bool,
}

/// Minimum number of blocks to justify parallel dispatch.
/// Below this, rayon overhead exceeds the benefit.
const MIN_PARALLEL_BLOCKS: usize = 4;

/// Per-block decoded item buffer size.
const DECODED_ITEMS_CAPACITY: usize = 0x4100;

/// Maximum worker count to consider when sizing parallel decode batches.
const MAX_PARALLEL_THREADS: usize = 8;

/// Maximum compressed block size (in bits) for parallel decode.
/// Blocks exceeding this fall back to single-threaded inline decode.
const LARGE_BLOCK_BITS: i64 = 0x20000 * 8;

/// Maximum number of pending filters to hold at once.
const MAX_PENDING_FILTERS: usize = 8192;

/// Maximum accepted filter block size.
const MAX_FILTER_BLOCK_SIZE: u32 = 0x400000;

// ─── Types ───────────────────────────────────────────────────────────────────

/// A decoded Huffman item — one logical operation extracted from the bitstream.
///
/// Everything needed from the bitstream is fully resolved; only sequential
/// state (window, dist_cache, last_length) is deferred to the apply phase.
#[derive(Clone, Copy)]
pub enum DecodedItem {
    /// 1–8 consecutive literal bytes, batched for cache efficiency.
    Literals { bytes: [u8; 8], count: u8 },
    /// Inline match (sym >= 262): length and distance fully resolved.
    /// Distance is 1-based. Length includes distance-based adjustment.
    /// Distance must be u64: RAR7 (`extra_dist`) match distances exceed 4 GiB.
    Match { length: u32, distance: u64 },
    /// Repeat previous match (sym 257). Uses current last_length + dist_cache[0].
    RepeatPrev,
    /// Cache reference (sym 258–261). Distance resolved from cache during apply.
    CacheRef { cache_idx: u8, length: u32 },
    /// Filter marker (sym 256). `block_start_delta` is relative to output_size
    /// at the point this item is applied (NOT an absolute offset).
    Filter {
        filter_type: u8,
        block_start_delta: u64,
        block_length: u32,
        channels: u8,
    },
}

/// Metadata for one LZ block, parsed during the sequential header scan.
#[derive(Clone)]
struct BlockInfo {
    /// Bit offset at the start of the complete block payload.
    payload_bit_offset: usize,
    /// Number of bits in the complete payload, including optional tables.
    payload_bits: usize,
    /// A table-present block starts a new dependency span.
    table_present: bool,
    /// Whether this block exceeds the large-block threshold.
    is_large: bool,
}

/// A set of Huffman tables shared by one or more blocks.
#[derive(Clone)]
struct TableSet {
    nc: HuffmanTable,
    dc: HuffmanTable,
    ldc: HuffmanTable,
    rc: HuffmanTable,
}

struct WorkerState {
    tables: Option<TableSet>,
    code_lengths: Vec<u8>,
    diagnostics: WorkerCounters,
}

#[derive(Clone, Copy)]
struct BlockAssignment {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct WorkerOptions {
    extra_dist: bool,
    diagnostics_enabled: bool,
}

pub(super) fn parallel_enabled() -> bool {
    // `!cfg!(target_family = "wasm")` const-folds to `true` on native (the
    // native branch below is preserved verbatim) and to `false` on wasm, so
    // every LZ decode takes the single-thread path there and the rayon
    // `rar_decode_pool` is never built (wasip1 has no thread spawn).
    !cfg!(target_family = "wasm")
        && parallel_enabled_from_disable_env(
            std::env::var_os("WEAVER_RAR_DISABLE_PARALLEL").as_deref(),
        )
}

fn parallel_enabled_from_disable_env(disable_env: Option<&std::ffi::OsStr>) -> bool {
    disable_env.is_none()
}

pub(super) fn is_truncated_input_error(error: &RarError) -> bool {
    match error {
        RarError::InvalidHuffmanTable => true,
        RarError::CorruptArchive { detail } => {
            detail.contains("unexpected end of data")
                || detail.contains("truncated")
                || detail.contains("no bits remaining")
                || detail.contains("need ")
                || detail.contains("cannot skip")
        }
        _ => false,
    }
}

fn scan_next_block(
    reader: &mut BitReader<'_>,
    has_inherited_tables: bool,
) -> RarResult<Option<(BlockInfo, bool)>> {
    if !reader.has_bits() {
        return Ok(None);
    }

    reader.align_byte();

    if reader.bits_remaining() < 16 {
        return Ok(None);
    }

    let flags = reader.read_bits(8)? as u8;
    let checksum = reader.read_bits(8)? as u8;

    let extra_bits = (flags & 0x07) as i64 + 1;
    let num_size_bytes = ((flags >> 3) & 0x03) + 1;
    if num_size_bytes > 3 {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 block header: invalid size byte count".into(),
        });
    }

    let is_last = (flags & 0x40) != 0;
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

    let block_bits_remaining = if block_bytes == 0 {
        0
    } else {
        extra_bits + (block_bytes - 1) * 8
    };

    if !table_present && !has_inherited_tables {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 first block is missing Huffman tables".into(),
        });
    }

    let payload_bit_offset = reader.position();
    let payload_bits =
        usize::try_from(block_bits_remaining).map_err(|_| RarError::CorruptArchive {
            detail: "RAR5 block payload is too large".into(),
        })?;
    if payload_bits > u32::MAX as usize {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 block payload is too large".into(),
        });
    }
    let is_large = block_bits_remaining > LARGE_BLOCK_BITS;

    if payload_bits > 0 {
        reader.skip_bits(payload_bits as u32)?;
    }

    Ok(Some((
        BlockInfo {
            payload_bit_offset,
            payload_bits,
            table_present,
            is_large,
        },
        is_last,
    )))
}

fn scan_block_headers(
    input: &[u8],
    header_limit: usize,
    has_inherited_tables: bool,
    allow_incomplete_tail: bool,
) -> RarResult<ScannedBlocks> {
    let mut reader = BitReader::new(input);
    let estimated_blocks = (input.len() / 0x4000).clamp(8, 512);
    let mut blocks: Vec<BlockInfo> = Vec::with_capacity(estimated_blocks);
    let mut consumed_bytes = 0usize;
    let mut saw_last_block = false;
    let mut have_tables = has_inherited_tables;

    loop {
        // Stop accepting blocks whose header would start at or beyond the
        // caller's limit (volume boundary or unreliable staging tail).
        if reader.position().div_ceil(8) >= header_limit {
            break;
        }

        match scan_next_block(&mut reader, have_tables) {
            Ok(Some((block, is_last))) => {
                have_tables |= block.table_present;
                blocks.push(block);
                consumed_bytes = reader.position().div_ceil(8);
                if is_last {
                    saw_last_block = true;
                    break;
                }
            }
            Ok(None) => {
                break;
            }
            Err(error) if allow_incomplete_tail && is_truncated_input_error(&error) => {
                break;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(ScannedBlocks {
        blocks,
        consumed_bytes,
        saw_last_block,
    })
}

fn scan_complete_blocks(
    input: &[u8],
    header_limit: usize,
    has_inherited_tables: bool,
) -> RarResult<ScannedBlocks> {
    scan_block_headers(input, header_limit, has_inherited_tables, true)
}

// ─── Phase 1: Sequential generic-header scan ─────────────────────────────────

/// Scan complete generic block headers without parsing Huffman tables.
fn scan_blocks(input: &[u8], has_inherited_tables: bool) -> RarResult<ScannedBlocks> {
    scan_block_headers(input, input.len(), has_inherited_tables, false)
}

// ─── Phase 2: Per-block Huffman decode (pure, parallelizable) ────────────────

trait DecodeBits {
    fn position(&self) -> usize;
    fn has_bits(&self) -> bool;
    fn read_bits(&mut self, count: u8) -> RarResult<u32>;
    fn read_bits64(&mut self, count: u8) -> RarResult<u64>;
    fn decode_symbol<const DIAGNOSTICS: bool>(
        &mut self,
        table: &HuffmanTable,
    ) -> RarResult<(u16, bool)>;
    fn validate_end(&self, end_bit: usize) -> RarResult<()>;
}

impl DecodeBits for BitReader<'_> {
    #[inline(always)]
    fn position(&self) -> usize {
        BitReader::position(self)
    }

    #[inline(always)]
    fn has_bits(&self) -> bool {
        BitReader::has_bits(self)
    }

    #[inline(always)]
    fn read_bits(&mut self, count: u8) -> RarResult<u32> {
        BitReader::read_bits(self, count)
    }

    #[inline(always)]
    fn read_bits64(&mut self, count: u8) -> RarResult<u64> {
        BitRead::read_bits64(self, count)
    }

    #[inline(always)]
    fn decode_symbol<const DIAGNOSTICS: bool>(
        &mut self,
        table: &HuffmanTable,
    ) -> RarResult<(u16, bool)> {
        let quick = if DIAGNOSTICS {
            table.is_quick_code(self.getbits()?)
        } else {
            false
        };
        Ok((table.decode_bitreader(self)?, quick))
    }

    fn validate_end(&self, end_bit: usize) -> RarResult<()> {
        if self.position() > end_bit {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 block decode exceeded its logical boundary".into(),
            });
        }
        Ok(())
    }
}

impl DecodeBits for BlockReader<'_> {
    #[inline(always)]
    fn position(&self) -> usize {
        BlockReader::position(self)
    }

    #[inline(always)]
    fn has_bits(&self) -> bool {
        self.position() < self.end()
    }

    #[inline(always)]
    fn read_bits(&mut self, count: u8) -> RarResult<u32> {
        Ok(BlockReader::read_bits(self, count) as u32)
    }

    #[inline(always)]
    fn read_bits64(&mut self, count: u8) -> RarResult<u64> {
        Ok(BlockReader::read_bits(self, count))
    }

    #[inline(always)]
    fn decode_symbol<const DIAGNOSTICS: bool>(
        &mut self,
        table: &HuffmanTable,
    ) -> RarResult<(u16, bool)> {
        Ok(table.decode_block_reader(self))
    }

    fn validate_end(&self, _end_bit: usize) -> RarResult<()> {
        BlockReader::validate_end(self).map_err(|error| RarError::CorruptArchive {
            detail: format!("RAR5 block reader: {error}"),
        })
    }
}

/// Decode Huffman symbols from one block into a DecodedItem buffer.
#[cfg(test)]
fn decode_block_symbols(
    input: &[u8],
    block: &BlockInfo,
    tables: &TableSet,
    extra_dist: bool,
    items: &mut Vec<DecodedItem>,
) -> RarResult<()> {
    let mut counters = WorkerCounters::new();
    decode_block_symbols_counted(
        input,
        block,
        tables,
        extra_dist,
        false,
        items,
        &mut counters,
    )
}

fn decode_block_symbols_counted(
    input: &[u8],
    block: &BlockInfo,
    tables: &TableSet,
    extra_dist: bool,
    diagnostics: bool,
    items: &mut Vec<DecodedItem>,
    counters: &mut WorkerCounters,
) -> RarResult<()> {
    let byte_offset = block.payload_bit_offset / 8;
    let bit_remainder = block.payload_bit_offset % 8;
    let slice = input
        .get(byte_offset..)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR5 block data starts beyond the staged input".into(),
        })?;
    let block_end_bits = bit_remainder + block.payload_bits;
    if let Ok(mut reader) = BlockReader::new(slice, bit_remainder, block_end_bits) {
        #[cfg(test)]
        note_fast_reader_selection();
        if diagnostics {
            decode_block_symbols_inner::<_, true>(
                &mut reader,
                block_end_bits,
                tables,
                extra_dist,
                items,
                counters,
            )
        } else {
            decode_block_symbols_inner::<_, false>(
                &mut reader,
                block_end_bits,
                tables,
                extra_dist,
                items,
                counters,
            )
        }
    } else {
        let mut reader = BitReader::new(slice);
        if bit_remainder > 0 {
            reader.skip_bits(bit_remainder as u32)?;
        }
        if diagnostics {
            decode_block_symbols_inner::<_, true>(
                &mut reader,
                block_end_bits,
                tables,
                extra_dist,
                items,
                counters,
            )
        } else {
            decode_block_symbols_inner::<_, false>(
                &mut reader,
                block_end_bits,
                tables,
                extra_dist,
                items,
                counters,
            )
        }
    }
}

fn decode_block_symbols_inner<R: DecodeBits, const DIAGNOSTICS: bool>(
    reader: &mut R,
    block_end_bits: usize,
    tables: &TableSet,
    extra_dist: bool,
    items: &mut Vec<DecodedItem>,
    counters: &mut WorkerCounters,
) -> RarResult<()> {
    let mut lit_bytes = [0u8; 8];
    let mut lit_count: usize = 0;

    while reader.position() < block_end_bits && reader.has_bits() {
        let (sym, quick) = reader.decode_symbol::<DIAGNOSTICS>(&tables.nc)?;
        let sym = u32::from(sym);
        if DIAGNOSTICS {
            if quick {
                counters.record_quick_huffman_hit();
            } else {
                counters.record_slow_huffman_hit();
            }
        }

        if sym < 256 {
            if DIAGNOSTICS {
                counters.record_symbol(SymbolKind::Literal);
            }
            lit_bytes[lit_count] = sym as u8;
            lit_count += 1;
            if lit_count == 8 {
                items.push(DecodedItem::Literals {
                    bytes: lit_bytes,
                    count: 7,
                });
                lit_count = 0;
            }
            continue;
        }

        if lit_count > 0 {
            items.push(DecodedItem::Literals {
                bytes: lit_bytes,
                count: (lit_count - 1) as u8,
            });
            lit_count = 0;
        }

        if sym >= 262 {
            if DIAGNOSTICS {
                counters.record_symbol(SymbolKind::Match);
            }
            let length_idx = (sym - 262) as usize;
            let length = slot_to_length(reader, length_idx)?;
            let distance = decode_distance::<_, DIAGNOSTICS>(
                reader,
                &tables.dc,
                &tables.ldc,
                extra_dist,
                counters,
            )?;
            let length = adjust_length_for_distance(length, distance);
            items.push(DecodedItem::Match {
                length: length as u32,
                distance: distance as u64,
            });
            continue;
        }

        if sym == 256 {
            if DIAGNOSTICS {
                counters.record_symbol(SymbolKind::Filter);
            }
            let (filter_type, block_start_delta, block_length, channels) =
                read_filter_descriptor(reader)?;
            items.push(DecodedItem::Filter {
                filter_type,
                block_start_delta,
                block_length,
                channels,
            });
            continue;
        }

        if DIAGNOSTICS {
            counters.record_symbol(SymbolKind::Repeat);
        }
        if sym == 257 {
            items.push(DecodedItem::RepeatPrev);
            continue;
        }

        let cache_idx = (sym - 258) as u8;
        let (slot, quick) = reader.decode_symbol::<DIAGNOSTICS>(&tables.rc)?;
        if DIAGNOSTICS {
            if quick {
                counters.record_quick_huffman_hit();
            } else {
                counters.record_slow_huffman_hit();
            }
        }
        let length = slot_to_length(reader, slot as usize)?;
        items.push(DecodedItem::CacheRef {
            cache_idx,
            length: length as u32,
        });
    }

    if lit_count > 0 {
        items.push(DecodedItem::Literals {
            bytes: lit_bytes,
            count: (lit_count - 1) as u8,
        });
    }

    reader.validate_end(block_end_bits)
}

/// Read a filter descriptor from the bitstream (sym 256 handler).
/// Returns (filter_type_code, block_start_delta, block_length, channels).
fn read_filter_descriptor<R: DecodeBits>(reader: &mut R) -> RarResult<(u8, u64, u32, u8)> {
    let block_start_delta = read_filter_data(reader)? as u64;
    let mut block_length = read_filter_data(reader)?;
    let filter_code = reader.read_bits(3)? as u8;

    if block_length > MAX_FILTER_BLOCK_SIZE {
        block_length = 0;
    }

    let channels = if filter_code == 0 {
        (reader.read_bits(5)? + 1) as u8
    } else {
        0
    };

    Ok((filter_code, block_start_delta, block_length, channels))
}

fn read_filter_data<R: DecodeBits>(reader: &mut R) -> RarResult<u32> {
    let byte_count = reader.read_bits(2)? as usize + 1;
    let mut data = 0u32;
    for index in 0..byte_count {
        data |= reader.read_bits(8)? << (index * 8);
    }
    Ok(data)
}

// ─── Standalone decode helpers (no &self, usable from parallel context) ──────

fn slot_to_length<R: DecodeBits>(reader: &mut R, slot: usize) -> RarResult<usize> {
    if slot >= NUM_LENGTH_SLOTS {
        return Err(RarError::CorruptArchive {
            detail: format!("length slot out of range: {slot}"),
        });
    }
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

fn decode_distance<R: DecodeBits, const DIAGNOSTICS: bool>(
    reader: &mut R,
    dc: &HuffmanTable,
    ldc: &HuffmanTable,
    extra_dist: bool,
    counters: &mut WorkerCounters,
) -> RarResult<usize> {
    let (dist_code, quick) = reader.decode_symbol::<DIAGNOSTICS>(dc)?;
    if DIAGNOSTICS {
        if quick {
            counters.record_quick_huffman_hit();
        } else {
            counters.record_slow_huffman_hit();
        }
    }
    let dist_code = dist_code as usize;
    let max_dist_code = if extra_dist { 79 } else { 63 };
    if dist_code > max_dist_code {
        return Err(RarError::CorruptArchive {
            detail: format!("distance code out of range: {dist_code}"),
        });
    }

    if dist_code < 4 {
        return Ok(dist_code + 1);
    }

    let num_bits = (dist_code >> 1) - 1;
    let distance = if num_bits >= 4 {
        let high = if num_bits > 4 {
            reader.read_bits64((num_bits - 4) as u8)? << 4
        } else {
            0
        };
        let (low, quick) = reader.decode_symbol::<DIAGNOSTICS>(ldc)?;
        if DIAGNOSTICS {
            if quick {
                counters.record_quick_huffman_hit();
            } else {
                counters.record_slow_huffman_hit();
            }
        }
        let low = u64::from(low);
        super::LzDecoder::distance_from_slot_parts(dist_code, num_bits, high, low)?
    } else {
        let extra = reader.read_bits64(num_bits as u8)?;
        super::LzDecoder::distance_from_slot_parts(dist_code, num_bits, extra, 0)?
    };

    Ok(distance)
}

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

fn prepare_block(
    input: &[u8],
    source: &BlockInfo,
    tables: &mut Option<TableSet>,
    code_lengths: &mut [u8],
    extra_dist: bool,
) -> RarResult<BlockInfo> {
    let byte_offset = source.payload_bit_offset / 8;
    let bit_remainder = source.payload_bit_offset % 8;
    let slice = input
        .get(byte_offset..)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR5 block payload starts beyond the staged input".into(),
        })?;
    let mut reader = BitReader::new(slice);
    if bit_remainder > 0 {
        reader.skip_bits(bit_remainder as u32)?;
    }

    if source.table_present {
        let (nc, dc, ldc, rc) =
            huffman::read_tables_bitreader(&mut reader, code_lengths, extra_dist)?;
        *tables = Some(TableSet { nc, dc, ldc, rc });
    }

    if tables.is_none() {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 block has no Huffman tables".into(),
        });
    }
    let table_bits = reader.position().saturating_sub(bit_remainder);
    if table_bits > source.payload_bits {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 Huffman tables exceed block payload".into(),
        });
    }

    Ok(BlockInfo {
        payload_bit_offset: byte_offset * 8 + reader.position(),
        payload_bits: source.payload_bits - table_bits,
        table_present: false,
        is_large: source.is_large,
    })
}

fn next_span_end(blocks: &[BlockInfo], start: usize, limit: usize) -> usize {
    let mut end = start.saturating_add(1).min(limit);
    while end < limit && !blocks[end].table_present {
        end += 1;
    }
    end
}

fn next_controller_batch_end(
    blocks: &[BlockInfo],
    start: usize,
    limit: usize,
    worker_count: usize,
) -> usize {
    if worker_count <= 1 {
        return start;
    }

    let mut cursor = start;
    let mut workers = 0usize;
    let block_capacity = worker_count.saturating_mul(2);

    if !blocks[start].table_present {
        while cursor < limit
            && cursor - start < block_capacity
            && !blocks[cursor].table_present
            && !blocks[cursor].is_large
        {
            cursor += 1;
        }
        return cursor;
    }

    while cursor < limit && workers < worker_count && cursor - start < block_capacity {
        let first_end = next_span_end(blocks, cursor, limit);
        let first_len = first_end - cursor;
        if first_len > 2 || blocks[cursor..first_end].iter().any(|block| block.is_large) {
            break;
        }

        let mut assignment_end = first_end;
        if first_len == 1 && assignment_end < limit {
            let second_end = next_span_end(blocks, assignment_end, limit);
            if second_end - assignment_end == 1 && !blocks[assignment_end].is_large {
                assignment_end = second_end;
            }
        }
        if assignment_end - start > block_capacity {
            break;
        }
        cursor = assignment_end;
        workers += 1;
    }
    cursor
}

fn build_assignments(
    blocks: &[BlockInfo],
    start: usize,
    end: usize,
    worker_count: usize,
) -> RarResult<Vec<BlockAssignment>> {
    if worker_count <= 1 || end - start > worker_count.saturating_mul(2) {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 parallel controller received an oversized batch".into(),
        });
    }

    let mut assignments = Vec::new();
    let mut cursor = start;
    while cursor < end {
        if !blocks[cursor].table_present {
            let assignment_end = cursor.saturating_add(2).min(end);
            if blocks[cursor..assignment_end]
                .iter()
                .any(|block| block.table_present || block.is_large)
            {
                return Err(RarError::CorruptArchive {
                    detail: "RAR5 parallel controller received a mixed inherited-table batch"
                        .into(),
                });
            }
            assignments.push(BlockAssignment {
                start: cursor,
                end: assignment_end,
            });
            cursor = assignment_end;
            continue;
        }

        let span_end = next_span_end(blocks, cursor, end);
        if span_end - cursor > 2 {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 parallel controller received an unbounded table span".into(),
            });
        }
        let mut assignment_end = span_end;
        if span_end - cursor == 1 && assignment_end < end {
            let next_end = next_span_end(blocks, assignment_end, end);
            if next_end - assignment_end == 1 {
                assignment_end = next_end;
            }
        }
        assignments.push(BlockAssignment {
            start: cursor,
            end: assignment_end,
        });
        cursor = assignment_end;
    }
    if assignments.len() > worker_count {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 parallel controller exceeded its worker pool".into(),
        });
    }
    Ok(assignments)
}

fn decode_worker_assignment(
    input: &[u8],
    blocks: &[BlockInfo],
    assignment: BlockAssignment,
    inherited_tables: Option<TableSet>,
    initial_code_lengths: &[u8],
    options: WorkerOptions,
    items: &mut [Vec<DecodedItem>],
) -> RarResult<WorkerState> {
    let mut tables = inherited_tables;
    let mut code_lengths = initial_code_lengths.to_vec();
    let mut diagnostics = WorkerCounters::new();
    if options.diagnostics_enabled {
        diagnostics.record_assignment();
    }

    for (source, items) in blocks[assignment.start..assignment.end]
        .iter()
        .zip(items.iter_mut())
    {
        let table_started = options.diagnostics_enabled.then(Instant::now);
        let prepared = prepare_block(
            input,
            source,
            &mut tables,
            &mut code_lengths,
            options.extra_dist,
        )?;
        if let Some(started) = table_started {
            diagnostics
                .add_table_prepare_nanos(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
            diagnostics.record_block(source.table_present);
        }
        items.clear();
        let previous_capacity = items.capacity();
        if items.capacity() < DECODED_ITEMS_CAPACITY {
            items.reserve(DECODED_ITEMS_CAPACITY);
        }
        if options.diagnostics_enabled {
            diagnostics.record_decoded_buffer_growth(previous_capacity, items.capacity());
        }
        let decode_started = options.diagnostics_enabled.then(Instant::now);
        decode_block_symbols_counted(
            input,
            &prepared,
            tables.as_ref().expect("prepared block has tables"),
            options.extra_dist,
            options.diagnostics_enabled,
            items,
            &mut diagnostics,
        )?;
        if let Some(started) = decode_started {
            diagnostics
                .add_symbol_decode_nanos(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        }
    }

    Ok(WorkerState {
        tables,
        code_lengths,
        diagnostics,
    })
}

fn parallel_decode_static(
    input: &[u8],
    blocks: &[BlockInfo],
    range: std::ops::Range<usize>,
    inherited_tables: Option<&TableSet>,
    initial_code_lengths: &[u8],
    extra_dist: bool,
    items: &mut [Vec<DecodedItem>],
) -> RarResult<Vec<WorkerState>> {
    let pool = rar_decode_pool().ok_or_else(|| RarError::CorruptArchive {
        detail: "RAR5 parallel controller has no worker pool".into(),
    })?;
    let worker_count = pool.current_num_threads().min(MAX_PARALLEL_THREADS);
    let assignments = build_assignments(blocks, range.start, range.end, worker_count)?;
    if items.len() != range.end - range.start {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 parallel controller received mismatched output slots".into(),
        });
    }
    let mut results: Vec<Option<RarResult<WorkerState>>> =
        (0..assignments.len()).map(|_| None).collect();
    let mut aggregate = phase_diagnostics::AggregateDiagnostics::new();
    let diagnostics_enabled = aggregate.is_enabled();
    let worker_options = WorkerOptions {
        extra_dist,
        diagnostics_enabled,
    };
    if diagnostics_enabled {
        aggregate.record_worker_slots(
            assignments.len(),
            worker_count.saturating_sub(assignments.len()),
        );
    }
    let pool_started = diagnostics_enabled.then(Instant::now);
    let mut dispatch_nanos = 0u64;

    pool.install(|| {
        rayon::scope(|scope| {
            let dispatch_started = aggregate.is_enabled().then(Instant::now);
            let mut item_tail = &mut *items;
            let mut result_tail = results.as_mut_slice();
            for assignment in assignments.iter().copied() {
                let count = assignment.end - assignment.start;
                let (worker_items, remaining_items) = item_tail.split_at_mut(count);
                let (worker_result, remaining_results) = result_tail.split_at_mut(1);
                // A table-present block rewrites the complete RAR5 length table;
                // repeat symbols only refer to entries in that same table read.
                // Independent assignments can therefore share the initial scratch.
                let worker_inherited = if blocks[assignment.start].table_present {
                    None
                } else {
                    inherited_tables.cloned()
                };
                scope.spawn(move |_| {
                    worker_result[0] = Some(decode_worker_assignment(
                        input,
                        blocks,
                        assignment,
                        worker_inherited,
                        initial_code_lengths,
                        worker_options,
                        worker_items,
                    ));
                });
                item_tail = remaining_items;
                result_tail = remaining_results;
            }
            if let Some(started) = dispatch_started {
                dispatch_nanos = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            }
        });
    });

    if results.iter().any(Option::is_none) {
        return Err(RarError::CorruptArchive {
            detail: "RAR5 parallel worker did not complete".into(),
        });
    }
    let states: RarResult<Vec<WorkerState>> = results
        .into_iter()
        .map(|result| result.expect("parallel worker result checked above"))
        .collect();
    if let Some(started) = pool_started {
        let total_nanos = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        aggregate.add_pool_dispatch_nanos(dispatch_nanos);
        aggregate.add_pool_wait_nanos(total_nanos.saturating_sub(dispatch_nanos));
        if let Ok(states) = &states {
            for state in states {
                aggregate.absorb_worker(state.diagnostics);
            }
        }
        aggregate.emit();
    }
    states
}

// ─── Phase 3: Sequential item application ────────────────────────────────────

// ─── Phase 4: Parallel dispatch ──────────────────────────────────────────────

/// Decode a batch of (non-large) blocks in parallel using rayon.
fn decoded_item_buffers(
    buffers: &mut Vec<Vec<DecodedItem>>,
    active_len: usize,
) -> &mut [Vec<DecodedItem>] {
    if buffers.len() < active_len {
        buffers.resize_with(active_len, || Vec::with_capacity(DECODED_ITEMS_CAPACITY));
    }

    for buffer in buffers.iter_mut() {
        buffer.clear();
    }

    &mut buffers[..active_len]
}

/// Dedicated bounded pool for RAR block decode. Keeps decode fan-out off the
/// shared global pool and bounds wake/park churn.
fn rar_decode_pool() -> Option<&'static ThreadPool> {
    use std::sync::OnceLock;

    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(MAX_PARALLEL_THREADS);
        if threads <= 1 {
            return None;
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("unrar-rs-dec-{i}"))
            .build()
            .ok()
    })
    .as_ref()
}

fn rar_decode_worker_count() -> usize {
    rar_decode_pool()
        .map(ThreadPool::current_num_threads)
        .unwrap_or(0)
        .min(MAX_PARALLEL_THREADS)
}

#[cfg(test)]
thread_local! {
    static CONTROLLER_DISPATCH_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAST_READER_SELECTION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_controller_dispatch() {
    CONTROLLER_DISPATCH_COUNT.set(CONTROLLER_DISPATCH_COUNT.get() + 1);
}

#[cfg(test)]
fn note_fast_reader_selection() {
    FAST_READER_SELECTION_COUNT.set(FAST_READER_SELECTION_COUNT.get() + 1);
}

// ─── Public entry point ──────────────────────────────────────────────────────

impl LzDecoder {
    fn take_item_buffer_set(&mut self) -> Vec<Vec<DecodedItem>> {
        self.parallel_item_buffer_sets.pop().unwrap_or_default()
    }

    fn recycle_item_buffer_set(&mut self, set: Vec<Vec<DecodedItem>>) {
        if self.parallel_item_buffer_sets.is_empty() {
            self.parallel_item_buffer_sets.push(set);
        }
    }

    pub(super) fn process_buffered_blocks<W: std::io::Write>(
        &mut self,
        input: &[u8],
        header_limit: usize,
        unpacked_size: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<usize> {
        let has_inherited_tables = self.has_current_tables();
        let scanned = phase_diagnostics::measure(Phase::HeaderScan, || {
            scan_complete_blocks(input, header_limit, has_inherited_tables)
        })?;
        if scanned.blocks.is_empty() {
            return Ok(0);
        }

        let worker_count = if parallel_enabled() {
            rar_decode_worker_count()
        } else {
            0
        };
        let mut block_index = 0usize;
        while block_index < scanned.blocks.len() && *output_size < unpacked_size {
            let span_end = next_span_end(&scanned.blocks, block_index, scanned.blocks.len());
            let span = &scanned.blocks[block_index..span_end];
            let batch_end = next_controller_batch_end(
                &scanned.blocks,
                block_index,
                scanned.blocks.len(),
                worker_count,
            );
            if worker_count > 1 && batch_end - block_index >= MIN_PARALLEL_BLOCKS {
                self.decode_and_apply_static_batch(
                    input,
                    &scanned.blocks,
                    block_index..batch_end,
                    unpacked_size,
                    output_size,
                    writer,
                )?;
                block_index = batch_end;
            } else {
                let inline_end = if worker_count > 1 && span.len() > 2 {
                    block_index + 1
                } else {
                    span_end
                };
                phase_diagnostics::measure(Phase::SerialApply, || {
                    self.decode_span_inline(
                        input,
                        &scanned.blocks[block_index..inline_end],
                        unpacked_size,
                        output_size,
                        writer,
                    )
                })?;
                block_index = inline_end;
            }
        }

        self.block_bits_remaining = 0;
        self.is_last_block = scanned.saw_last_block;
        self.flush_filters_and_write(writer)?;
        Ok(scanned.consumed_bytes)
    }

    fn has_current_tables(&self) -> bool {
        self.nc_table.is_some()
            && self.dc_table.is_some()
            && self.ldc_table.is_some()
            && self.rc_table.is_some()
    }

    fn current_tables(&self) -> Option<TableSet> {
        match (
            &self.nc_table,
            &self.dc_table,
            &self.ldc_table,
            &self.rc_table,
        ) {
            (Some(nc), Some(dc), Some(ldc), Some(rc)) => Some(TableSet {
                nc: (**nc).clone(),
                dc: (**dc).clone(),
                ldc: (**ldc).clone(),
                rc: (**rc).clone(),
            }),
            _ => None,
        }
    }

    fn set_table_state(&mut self, state: WorkerState) {
        if let Some(tables) = state.tables {
            self.nc_table = Some(Arc::new(tables.nc));
            self.dc_table = Some(Arc::new(tables.dc));
            self.ldc_table = Some(Arc::new(tables.ldc));
            self.rc_table = Some(Arc::new(tables.rc));
        }
        self.code_lengths = state.code_lengths;
    }

    fn install_inline_tables(&mut self, tables: &TableSet) {
        self.nc_table = Some(Arc::new(tables.nc.clone()));
        self.dc_table = Some(Arc::new(tables.dc.clone()));
        self.ldc_table = Some(Arc::new(tables.ldc.clone()));
        self.rc_table = Some(Arc::new(tables.rc.clone()));
    }

    fn decode_span_inline<W: std::io::Write>(
        &mut self,
        input: &[u8],
        span: &[BlockInfo],
        unpacked_size: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<()> {
        let mut tables = if span.first().is_some_and(|block| block.table_present) {
            None
        } else {
            self.current_tables()
        };
        let mut code_lengths = self.code_lengths.clone();
        for source in span {
            let prepared = prepare_block(
                input,
                source,
                &mut tables,
                &mut code_lengths,
                self.extra_dist,
            )?;
            if source.table_present {
                self.install_inline_tables(tables.as_ref().expect("prepared block has tables"));
            }
            self.code_lengths.copy_from_slice(&code_lengths);
            self.decode_block_inline(input, &prepared, unpacked_size, output_size, writer)?;
            if *output_size >= unpacked_size {
                break;
            }
        }
        Ok(())
    }

    fn decode_and_apply_static_batch<W: std::io::Write>(
        &mut self,
        input: &[u8],
        blocks: &[BlockInfo],
        range: std::ops::Range<usize>,
        unpacked_size: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<()> {
        let worker_count = rar_decode_worker_count();
        if worker_count <= 1 || range.end - range.start > worker_count.saturating_mul(2) {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 parallel controller received an invalid dispatch".into(),
            });
        }
        let inherited_tables = self.current_tables();
        let initial_code_lengths = self.code_lengths.clone();
        let mut set = self.take_item_buffer_set();
        #[cfg(test)]
        note_controller_dispatch();
        let result = (|| {
            let active = decoded_item_buffers(&mut set, range.end - range.start);
            let states = phase_diagnostics::measure(Phase::WorkerDecode, || {
                parallel_decode_static(
                    input,
                    blocks,
                    range,
                    inherited_tables.as_ref(),
                    &initial_code_lengths,
                    self.extra_dist,
                    active,
                )
            })?;
            phase_diagnostics::measure(Phase::SerialApply, || {
                self.apply_decoded_items_parallel(active, unpacked_size, output_size, writer)
            })?;
            if let Some(state) = states.into_iter().last() {
                self.set_table_state(state);
            }
            Ok(())
        })();
        self.recycle_item_buffer_set(set);
        result
    }

    fn decode_block_inline<W: std::io::Write>(
        &mut self,
        input: &[u8],
        block: &BlockInfo,
        unpacked_size: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<()> {
        self.block_bits_remaining = block.payload_bits as i64;

        let byte_offset = block.payload_bit_offset / 8;
        let bit_remainder = block.payload_bit_offset % 8;
        let slice = input
            .get(byte_offset..)
            .ok_or_else(|| RarError::CorruptArchive {
                detail: "RAR5 block data starts beyond the staged input".into(),
            })?;
        let mut reader = BitReader::new(slice);
        if bit_remainder > 0 {
            reader.skip_bits(bit_remainder as u32)?;
        }

        let flush_threshold = self.flush_threshold();
        while *output_size < unpacked_size && self.block_bits_remaining > 0 {
            *output_size = self.decode_block(
                &mut reader,
                unpacked_size,
                *output_size,
                Some(flush_threshold),
            )?;

            if self.pending_filters.is_empty() {
                if self.window.unflushed_bytes() as usize >= flush_threshold {
                    self.flush_unfiltered_stream_output(writer)?;
                }
            } else {
                self.flush_filters_and_write(writer)?;
                if self.window.unflushed_bytes() as usize > self.window.dict_size() {
                    return Err(RarError::CorruptArchive {
                        detail: "RAR5 pending filters exceeded dictionary window before flush"
                            .into(),
                    });
                }
            }
        }

        Ok(())
    }

    fn apply_decoded_items_parallel<W: std::io::Write>(
        &mut self,
        all_items: &[Vec<DecodedItem>],
        unpacked_size: u64,
        output_size: &mut u64,
        writer: &mut W,
    ) -> RarResult<()> {
        let flush_threshold = self.flush_threshold();
        let mut bytes_since_flush = 0usize;

        for block_items in all_items {
            for item in block_items {
                if *output_size >= unpacked_size {
                    return Ok(());
                }

                let mut produced = 0usize;
                let mut force_sync = false;

                match *item {
                    DecodedItem::Literals { bytes, count } => {
                        let n = (count as usize + 1).min((unpacked_size - *output_size) as usize);
                        self.window.put_literal_batch(&bytes, n);
                        *output_size += n as u64;
                        produced = n;
                    }
                    DecodedItem::Match { length, distance } => {
                        let remaining = (unpacked_size - *output_size) as usize;
                        let full_len = length as usize;
                        let len = full_len.min(remaining);

                        self.insert_old_dist(distance as usize);

                        self.last_length = full_len;
                        self.window
                            .copy_with_visible_len(distance as usize, full_len, len)?;
                        *output_size += len as u64;
                        produced = len;
                    }
                    DecodedItem::RepeatPrev => {
                        if self.last_length != 0 {
                            let distance = self.dist_cache[0];
                            let remaining = (unpacked_size - *output_size) as usize;
                            let len = self.last_length.min(remaining);
                            self.window
                                .copy_with_visible_len(distance, self.last_length, len)?;
                            *output_size += len as u64;
                            produced = len;
                        }
                    }
                    DecodedItem::CacheRef { cache_idx, length } => {
                        let idx = cache_idx as usize;
                        let distance = self.promote_old_dist(idx)?;

                        let remaining = (unpacked_size - *output_size) as usize;
                        let full_len = length as usize;
                        let len = full_len.min(remaining);
                        self.last_length = full_len;
                        self.window.copy_with_visible_len(distance, full_len, len)?;
                        *output_size += len as u64;
                        produced = len;
                    }
                    DecodedItem::Filter {
                        filter_type,
                        block_start_delta,
                        block_length,
                        channels,
                    } => {
                        let ft = FilterType::from_code(filter_type);
                        super::filter::push_pending_filter(
                            &mut self.pending_filters,
                            PendingFilter {
                                filter_type: ft,
                                block_start: self.current_file_base_total
                                    + *output_size
                                    + block_start_delta,
                                block_length: block_length as usize,
                                channels,
                            },
                            MAX_PENDING_FILTERS,
                        );

                        force_sync = true;
                    }
                }

                if force_sync || !self.pending_filters.is_empty() {
                    self.flush_stream_output(writer)?;
                    bytes_since_flush = 0;
                } else if produced != 0 {
                    bytes_since_flush += produced;
                    if bytes_since_flush >= flush_threshold {
                        self.flush_unfiltered_stream_output(writer)?;
                        bytes_since_flush = 0;
                    }
                }
            }

            if !self.pending_filters.is_empty() {
                self.flush_stream_output(writer)?;
                bytes_since_flush = 0;
            }
        }

        Ok(())
    }

    /// Attempt parallel decompression. Returns `None` if the input has too few
    /// blocks to benefit (caller should fall back to single-threaded).
    pub(super) fn try_decompress_parallel<W: std::io::Write>(
        &mut self,
        input: &[u8],
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<Option<u64>> {
        if !parallel_enabled() {
            return Ok(None);
        }
        let worker_count = rar_decode_worker_count();
        if worker_count <= 1 {
            return Ok(None);
        }

        let has_inherited_tables = self.has_current_tables();
        let scanned = phase_diagnostics::measure(Phase::HeaderScan, || {
            scan_blocks(input, has_inherited_tables)
        })?;
        if scanned.blocks.len() < MIN_PARALLEL_BLOCKS {
            return Ok(None);
        }

        let mut output_size = 0u64;
        let mut block_index = 0usize;
        while block_index < scanned.blocks.len() && output_size < unpacked_size {
            let span_end = next_span_end(&scanned.blocks, block_index, scanned.blocks.len());
            let span = &scanned.blocks[block_index..span_end];
            let batch_end = next_controller_batch_end(
                &scanned.blocks,
                block_index,
                scanned.blocks.len(),
                worker_count,
            );
            if batch_end - block_index >= MIN_PARALLEL_BLOCKS {
                self.decode_and_apply_static_batch(
                    input,
                    &scanned.blocks,
                    block_index..batch_end,
                    unpacked_size,
                    &mut output_size,
                    writer,
                )?;
                block_index = batch_end;
            } else {
                let inline_end = if span.len() > 2 {
                    block_index + 1
                } else {
                    span_end
                };
                phase_diagnostics::measure(Phase::SerialApply, || {
                    self.decode_span_inline(
                        input,
                        &scanned.blocks[block_index..inline_end],
                        unpacked_size,
                        &mut output_size,
                        writer,
                    )
                })?;
                block_index = inline_end;
            }
            if output_size >= unpacked_size {
                break;
            }
        }

        self.block_bits_remaining = 0;
        self.is_last_block = scanned.saw_last_block;
        self.flush_filters_and_write(writer)?;

        Ok(Some(output_size))
    }
}

#[cfg(test)]
mod tests {
    use super::super::block_reader::LOOKAHEAD_BYTES;
    use super::*;

    fn reset_dispatch_count() {
        CONTROLLER_DISPATCH_COUNT.set(0);
    }

    fn dispatch_count() -> usize {
        CONTROLLER_DISPATCH_COUNT.get()
    }

    fn reset_fast_reader_selection_count() {
        FAST_READER_SELECTION_COUNT.set(0);
    }

    fn fast_reader_selection_count() -> usize {
        FAST_READER_SELECTION_COUNT.get()
    }

    fn shifted_payload(payload: &[u8], payload_bits: usize, offset: usize) -> Vec<u8> {
        let payload_end = offset + payload_bits;
        let mut shifted = vec![0u8; payload_end.div_ceil(8) + LOOKAHEAD_BYTES];
        for bit in 0..payload_bits {
            let value = (payload[bit / 8] >> (7 - bit % 8)) & 1;
            shifted[(offset + bit) / 8] |= value << (7 - (offset + bit) % 8);
        }
        shifted
    }

    fn rar7_tables() -> TableSet {
        TableSet {
            nc: HuffmanTable::build(&[9u8; 306]).unwrap(),
            dc: HuffmanTable::build(&[7u8; 80]).unwrap(),
            ldc: HuffmanTable::build(&[4u8; 16]).unwrap(),
            rc: HuffmanTable::build(&[6u8; 44]).unwrap(),
        }
    }

    fn test_block(
        payload_bit_offset: usize,
        payload_bits: usize,
        table_present: bool,
    ) -> BlockInfo {
        BlockInfo {
            payload_bit_offset,
            payload_bits,
            table_present,
            is_large: false,
        }
    }

    #[test]
    fn static_assignments_pack_two_independent_blocks() {
        let blocks = vec![
            test_block(0, 1, true),
            test_block(1, 1, true),
            test_block(2, 1, true),
            test_block(3, 1, true),
        ];
        let assignments = build_assignments(&blocks, 0, 4, 2).unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].end, 2);
        assert_eq!(assignments[1].start, 2);
        assert!(
            assignments
                .iter()
                .all(|assignment| blocks[assignment.start].table_present)
        );
    }

    #[test]
    fn static_assignments_keep_short_tableless_span_together() {
        let blocks = vec![
            test_block(0, 1, true),
            test_block(1, 1, false),
            test_block(2, 1, true),
        ];
        let assignments = build_assignments(&blocks, 0, 3, 2).unwrap();
        assert_eq!(assignments.len(), 2);
        assert_eq!((assignments[0].start, assignments[0].end), (0, 2));
        assert_eq!((assignments[1].start, assignments[1].end), (2, 3));
    }

    #[test]
    fn long_tableless_span_uses_established_tables_in_parallel() {
        let mut blocks = vec![test_block(0, 1, true)];
        blocks.extend((1..7).map(|offset| test_block(offset, 1, false)));

        // The table-defining root is decoded first. Once installed, the
        // inherited-table suffix can be split without reparsing or mutation.
        assert_eq!(next_controller_batch_end(&blocks, 0, blocks.len(), 4), 0);
        assert_eq!(next_controller_batch_end(&blocks, 1, blocks.len(), 4), 7);

        let assignments = build_assignments(&blocks, 1, 7, 4).unwrap();
        assert_eq!(assignments.len(), 3);
        assert!(assignments.iter().all(|assignment| {
            blocks[assignment.start..assignment.end]
                .iter()
                .all(|block| !block.table_present)
        }));

        blocks[4].is_large = true;
        assert_eq!(next_controller_batch_end(&blocks, 1, blocks.len(), 4), 4);
    }

    #[test]
    fn controller_batch_end_caps_workers_and_respects_large_fallback() {
        let mut blocks = vec![test_block(0, 1, true); 20];
        blocks[4].is_large = true;
        assert_eq!(next_controller_batch_end(&blocks, 0, blocks.len(), 3), 4);
        blocks[4].is_large = false;
        assert_eq!(next_controller_batch_end(&blocks, 0, blocks.len(), 3), 6);
        assert_eq!(next_controller_batch_end(&blocks, 0, blocks.len(), 1), 0);
    }

    #[test]
    fn decoded_item_stays_cache_sized() {
        // The apply loop streams these items, so the u64 distance must not grow
        // the item beyond 16 bytes.
        assert_eq!(std::mem::size_of::<DecodedItem>(), 16);
    }

    #[test]
    fn decode_block_symbols_preserves_rar7_distance_beyond_u32() {
        // Uniform code lengths make canonical codes equal symbol indices:
        // NC len 9 (306 syms), DC len 7 (80 syms, RAR7 DCX), LDC len 4, RC len 6.
        let tables = rar7_tables();

        // Bitstream: NC sym 262 (9 bits) → length slot 0 (len 2, no extra),
        // DC sym 66 (7 bits) → 32 distance bits: 28 high bits = 0 from the
        // stream, low 4 bits from LDC sym 3. distance = (2<<32) + 3 + 1.
        // Packed MSB-first: 100000110 1000010 0^28 0011 = 48 bits.
        let input = [0x83u8, 0x42, 0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0];
        let block = BlockInfo {
            payload_bit_offset: 0,
            payload_bits: 48,
            table_present: false,
            is_large: false,
        };

        reset_fast_reader_selection_count();
        let mut checked_items = Vec::new();
        decode_block_symbols(&input, &block, &tables, true, &mut checked_items).unwrap();
        assert_eq!(fast_reader_selection_count(), 0);

        let mut guarded_input = input[..6].to_vec();
        guarded_input.resize(6 + LOOKAHEAD_BYTES, 0);
        let mut items = Vec::new();
        decode_block_symbols(&guarded_input, &block, &tables, true, &mut items).unwrap();
        assert_eq!(fast_reader_selection_count(), 1);

        assert_eq!(items.len(), 1);
        let DecodedItem::Match { length, distance } = items[0] else {
            panic!("expected a match item");
        };
        let expected = (2u64 << 32) + 3 + 1;
        assert!(expected > u32::MAX as u64);
        assert_eq!(distance, expected);
        // Base length 2, +3 from the distance-based length adjustment.
        assert_eq!(length, 5);

        let DecodedItem::Match {
            length: checked_length,
            distance: checked_distance,
        } = checked_items[0]
        else {
            panic!("expected a checked-reader match item");
        };
        assert_eq!((length, distance), (checked_length, checked_distance));

        let shifted_input = shifted_payload(&input, 48, 3);
        let shifted_block = BlockInfo {
            payload_bit_offset: 3,
            ..block.clone()
        };
        let mut shifted_items = Vec::new();
        decode_block_symbols(
            &shifted_input,
            &shifted_block,
            &tables,
            true,
            &mut shifted_items,
        )
        .unwrap();
        assert_eq!(fast_reader_selection_count(), 2);
        let DecodedItem::Match {
            length: shifted_length,
            distance: shifted_distance,
        } = shifted_items[0]
        else {
            panic!("expected an unaligned fast-reader match item");
        };
        assert_eq!((length, distance), (shifted_length, shifted_distance));

        let short_block = BlockInfo {
            payload_bits: 47,
            ..block
        };
        let mut malformed_items = Vec::new();
        let error = decode_block_symbols(
            &guarded_input,
            &short_block,
            &tables,
            true,
            &mut malformed_items,
        )
        .unwrap_err();
        assert!(matches!(error, RarError::CorruptArchive { .. }));
        assert_eq!(fast_reader_selection_count(), 3);
    }

    #[test]
    fn parallel_enabled_defaults_on() {
        assert!(parallel_enabled_from_disable_env(None));
    }

    #[test]
    fn parallel_disable_env_turns_off_parallel_path() {
        assert!(!parallel_enabled_from_disable_env(Some(
            std::ffi::OsStr::new("1")
        )));
    }

    #[test]
    fn decoded_item_buffers_reuse_allocations() {
        let mut buffers = Vec::new();
        let first_ptr = {
            let active = decoded_item_buffers(&mut buffers, 2);
            active[0].push(DecodedItem::RepeatPrev);
            active[0].as_ptr()
        };

        let active = decoded_item_buffers(&mut buffers, 2);
        assert_eq!(active.len(), 2);
        assert!(active[0].is_empty());
        assert!(active[0].capacity() >= DECODED_ITEMS_CAPACITY);
        assert_eq!(active[0].as_ptr(), first_ptr);
    }

    #[test]
    fn parallel_apply_keeps_filter_until_future_bytes_arrive() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        let mut output_size = 0u64;
        let mut out = Vec::new();
        let all_items = vec![vec![
            DecodedItem::Filter {
                filter_type: 7,
                block_start_delta: 0,
                block_length: 1,
                channels: 0,
            },
            DecodedItem::Literals {
                bytes: [b'X', 0, 0, 0, 0, 0, 0, 0],
                count: 0,
            },
        ]];

        decoder
            .apply_decoded_items_parallel(&all_items, 1, &mut output_size, &mut out)
            .unwrap();

        assert_eq!(output_size, 1);
        assert!(out.is_empty());
        assert!(decoder.pending_filters.is_empty());
        assert_eq!(decoder.current_file_written_size, 1);
    }

    #[test]
    fn parallel_filter_offsets_include_current_file_base_total() {
        let mut decoder = LzDecoder::new(128 * 1024, 0);
        decoder.current_file_base_total = 1_000;
        let mut output_size = 7u64;
        let mut out = Vec::new();
        let all_items = vec![vec![DecodedItem::Filter {
            filter_type: 1,
            block_start_delta: 5,
            block_length: 4,
            channels: 0,
        }]];

        decoder
            .apply_decoded_items_parallel(&all_items, 20, &mut output_size, &mut out)
            .unwrap();

        assert!(out.is_empty());
        assert_eq!(decoder.pending_filters.len(), 1);
        assert_eq!(
            decoder.pending_filters[0].block_start,
            decoder.current_file_base_total + output_size + 5
        );
    }

    #[test]
    fn controller_batch_end_stops_before_large_block() {
        let blocks = vec![
            BlockInfo {
                payload_bit_offset: 0,
                payload_bits: 1,
                table_present: true,
                is_large: false,
            },
            BlockInfo {
                payload_bit_offset: 1,
                payload_bits: 1,
                table_present: true,
                is_large: false,
            },
            BlockInfo {
                payload_bit_offset: 2,
                payload_bits: 1,
                table_present: true,
                is_large: true,
            },
            BlockInfo {
                payload_bit_offset: 3,
                payload_bits: 1,
                table_present: true,
                is_large: false,
            },
        ];

        assert_eq!(next_controller_batch_end(&blocks, 0, 4, 4), 2);
        assert_eq!(next_controller_batch_end(&blocks, 3, 4, 4), 4);
    }

    #[test]
    fn tableless_block_inherits_worker_table_state() {
        let mut tables = Some(rar7_tables());
        let before = tables.as_ref().map(std::ptr::from_ref);
        let source = test_block(0, 0, false);
        let mut code_lengths = vec![0u8; 484];
        let prepared = prepare_block(&[], &source, &mut tables, &mut code_lengths, false).unwrap();
        assert!(!prepared.table_present);
        assert_eq!(prepared.payload_bits, 0);
        assert_eq!(before, tables.as_ref().map(std::ptr::from_ref));
    }

    #[test]
    fn table_present_blocks_are_independent_length_table_roots() {
        let blocks = vec![test_block(0, 1, true), test_block(1, 1, true)];
        let assignments = build_assignments(&blocks, 0, blocks.len(), 2).unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!((assignments[0].start, assignments[0].end), (0, 2));
        assert!(blocks.iter().all(|block| block.table_present));
    }

    #[test]
    fn worker_failure_returns_after_all_scoped_jobs_join() {
        let worker_count = rar_decode_worker_count();
        if worker_count <= 1 {
            return;
        }
        let blocks = vec![test_block(0, 0, true); 4];
        let mut items = (0..4)
            .map(|_| Vec::new())
            .collect::<Vec<Vec<DecodedItem>>>();
        let result = parallel_decode_static(
            &[],
            &blocks,
            0..blocks.len(),
            None,
            &[0u8; 484],
            false,
            &mut items,
        );
        assert!(result.is_err());

        let input = [0x83u8, 0x42, 0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0];
        let valid_blocks = vec![test_block(0, 48, false); 2];
        let tables = rar7_tables();
        let states = parallel_decode_static(
            &input,
            &valid_blocks,
            0..valid_blocks.len(),
            Some(&tables),
            &[0u8; 484],
            true,
            &mut items[..valid_blocks.len()],
        )
        .unwrap();
        assert_eq!(states.len(), 1);
        assert!(
            items[..valid_blocks.len()]
                .iter()
                .all(|buffer| !buffer.is_empty())
        );
    }

    #[test]
    fn hydrated_multiblock_extraction_dispatches_controller() {
        if rar_decode_worker_count() <= 1 {
            return;
        }
        reset_dispatch_count();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar5/rar5_solid.rar");
        let mut archive = crate::RarArchive::open(std::fs::File::open(fixture).unwrap()).unwrap();
        let options = crate::ExtractOptions::default();
        for member_index in 0..archive.metadata().members.len() {
            archive
                .extract_member(member_index, &options, None)
                .unwrap();
            if dispatch_count() > 0 {
                break;
            }
        }
        assert!(dispatch_count() > 0);
    }

    #[test]
    fn phase_diagnostics_follow_process_opt_in_contract() {
        if rar_decode_worker_count() <= 1 {
            return;
        }

        let run = |enabled: bool| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("hydrated_multiblock_extraction_dispatches_controller")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env_remove("RARPAR_BENCH_PHASES");
            if enabled {
                command.env("RARPAR_BENCH_PHASES", "1");
            }
            command.output().unwrap()
        };

        let enabled = run(true);
        assert!(enabled.status.success());
        let enabled_log = format!(
            "{}{}",
            String::from_utf8_lossy(&enabled.stdout),
            String::from_utf8_lossy(&enabled.stderr)
        );
        for phase in ["staging", "header_scan", "worker_decode", "serial_apply"] {
            assert!(
                enabled_log.contains(&format!("RARPAR_BENCH_PHASE {{\"phase\":\"{phase}\"")),
                "missing {phase} marker from enabled controller run"
            );
        }

        let disabled = run(false);
        assert!(disabled.status.success());
        let disabled_log = format!(
            "{}{}",
            String::from_utf8_lossy(&disabled.stdout),
            String::from_utf8_lossy(&disabled.stderr)
        );
        assert!(!disabled_log.contains("RARPAR_BENCH_PHASE "));
    }
}
