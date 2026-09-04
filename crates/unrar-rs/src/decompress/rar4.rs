//! RAR4 (v29) LZ decompressor.
//!
//! Implements the Unpack29 algorithm used by RAR 3.x/4.x archives.
//!
//! Symbol interpretation (LD table, 299 symbols):
//! - 0-255: literal bytes
//! - 256: end of block
//! - 257: VM filter code (only recognized standard filters are applied)
//! - 258: repeat previous match (`last_length`, `dist_cache[0]`)
//! - 259-262: repeat distance cache references (new length from RD table)
//! - 263-270: short distance matches (length=2)
//! - 271-298: inline length codes with extra bits (distance from DD/LDD tables)

use std::io::Write;
use std::sync::OnceLock;

use tracing::trace;

use super::lz::bitstream::{BitRead, BitReader, LzSpan, StreamingBitReader};
use super::lz::block_reader::{BitCursor, cursor_read_bits, cursor_refill};
use super::lz::huffman::HuffmanTable;
use super::lz::window::Window;
use super::ppmd::model::Model;
use super::ppmd::range::{BitReadRangeDecoder, RangeCode, RangeCoderState};
use crate::error::{RarError, RarResult};

fn rar4_debug_filters_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("UNRAR_RS_RAR4_DEBUG_FILTERS").is_some())
}

/// RAR4 Huffman table sizes.
const NC: usize = 299; // Literal/Length codes
const DC: usize = 60; // Distance codes
const LDC: usize = 17; // Low distance codes
const RC: usize = 28; // Repeat/Length codes
const BC: usize = 20; // Bit length codes

/// Total symbols across all tables (for delta encoding persistence).
const HUFF_TABLE_SIZE: usize = NC + DC + LDC + RC;

/// Length decode base values (28 entries).
const LDECODE: [u16; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];

/// Length extra bits (28 entries).
const LBITS: [u8; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// Short distance decode base values (8 entries, for symbols 263-270).
const SDDECODE: [u16; 8] = [0, 4, 8, 16, 32, 64, 128, 192];

/// Short distance extra bits.
const SDBITS: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// DBitLengthCounts for building DDecode/DBits tables.
const DBIT_LENGTH_COUNTS: [usize; 19] = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];

/// Low distance repeat count.
const LOW_DIST_REP_COUNT: usize = 16;

/// Maximum dictionary size (256 MB).
const MAX_DICT_SIZE: u64 = 256 * 1024 * 1024;
const VM_MEM_SIZE: usize = 0x40000;
/// `VM_MEMMASK` (rarvm.hpp:5). The VM reports `FilteredDataSize` as
/// `InitR[4] & VM_MEMMASK` (rarvm.cpp:29-30), so a filter covering exactly
/// `VM_MEM_SIZE` bytes emits nothing at all.
const VM_MEM_MASK: usize = VM_MEM_SIZE - 1;
const MAX3_UNPACK_FILTERS: usize = 8192;
const MAX3_UNPACK_CHANNELS: u32 = 1024;
const MAX3_INC_LZ_MATCH: usize = 0x104;

/// Maximum number of bytes to accumulate before flushing decoded output.
const UNPACK_MAX_WRITE: usize = 0x400000;

/// Block type: LZ or PPMd.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockType {
    Lz,
    Ppm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rar4StandardFilter {
    /// Non-standard VM bytecode. Unknown programs leave `VMSF_NONE` with
    /// `FilteredDataSize == 0`, so the covered block is suppressed.
    None,
    E8,
    E8E9,
    Itanium,
    Delta,
    Rgb,
    Audio,
}

#[derive(Clone, Debug)]
struct Rar4VmFilterDefinition {
    filter_type: Rar4StandardFilter,
    last_block_length: usize,
}

#[derive(Clone, Debug)]
struct Rar4PendingVmFilter {
    filter_type: Rar4StandardFilter,
    block_start_total: u64,
    block_length: usize,
    init_regs: [u32; 7],
}

/// Distance decode base values (computed from DBIT_LENGTH_COUNTS).
fn build_ddecode_tables() -> ([u32; DC], [u8; DC]) {
    let mut ddecode = [0u32; DC];
    let mut dbits = [0u8; DC];
    let mut dist: u32 = 0;
    let mut slot: usize = 0;
    for (bit_length, &count) in (0u8..).zip(DBIT_LENGTH_COUNTS.iter()) {
        for _ in 0..count {
            if slot < DC {
                ddecode[slot] = dist;
                dbits[slot] = bit_length;
                dist += 1u32 << bit_length;
                slot += 1;
            }
        }
    }
    (ddecode, dbits)
}

/// A table the decoder expected to have been built by `read_tables`.
///
/// Outlined so the symbol loop carries the branch but not the construction:
/// the oracle's equivalent is a plain `&BlockTables.LD` with no failure case
/// at all (unpack30.cpp:139).
#[cold]
#[inline(never)]
fn missing_table(name: &str) -> RarError {
    RarError::CorruptArchive {
        detail: format!("RAR4: missing {name} table"),
    }
}

/// A Huffman decode that ran out of input mid-symbol.
///
/// Outlined for the same reason as [`missing_table`]: `format!` in the
/// per-symbol path keeps its arguments live and inflates the loop even though
/// the oracle simply `break`s (unpack30.cpp:58-59).
#[cold]
#[inline(never)]
fn decode_failed(name: &str, err: &RarError) -> RarError {
    RarError::CorruptArchive {
        detail: format!("RAR4: {name} decode failed: {err}"),
    }
}

/// [`decode_failed`] for the two sites that also report the output position.
#[cold]
#[inline(never)]
fn decode_failed_at(name: &str, output_size: u64, err: &RarError) -> RarError {
    RarError::CorruptArchive {
        detail: format!("RAR4: {name} decode failed at output_size={output_size}: {err}"),
    }
}

/// The Huffman and distance tables a leased span decodes against.
///
/// Borrowed once per lease instead of being re-reached through
/// `self.ld_table.as_ref().ok_or_else(..)?` on every symbol, which is where
/// UnRAR simply has `&BlockTables.LD` (unpack30.cpp:139).
struct Rar4FastTables<'a> {
    ld: &'a HuffmanTable,
    dd: &'a HuffmanTable,
    ldd: &'a HuffmanTable,
    rd: &'a HuffmanTable,
    ddecode: &'a [u32; DC],
    dbits: &'a [u8; DC],
}

/// The mutable decoder state a leased span keeps in locals.
///
/// UnRAR holds `OldDist`, `LastLength`, `LowDistRepCount` and `PrevLowDist` as
/// `Unpack` members, but `Unpack29` is one function over them, so a release
/// build keeps them in registers across the whole symbol loop. rarpar reaches
/// them through `&mut Rar4LzDecoder`, so they are copied in here for the span
/// and written back at every exit from it.
#[derive(Clone, Copy)]
struct Rar4FastState {
    dist_cache: [usize; 4],
    last_length: usize,
    low_dist_rep_count: usize,
    prev_low_dist: usize,
}

/// Why the leased-span loop handed control back.
enum Rar4FastExit {
    /// The cursor reached the span border; the caller takes a fresh lease or
    /// falls back to the per-symbol path for the buffer tail.
    Border,
    /// `output_size` reached `unpacked_size`.
    Complete,
    /// The unflushed-output threshold was crossed and a flush can progress.
    Yield,
    /// Symbol 256 or 257 was decoded and consumed; the caller runs its arm.
    Cold(usize),
}

/// `flush_is_pinned_by_pending_head` over the state a leased span can see.
///
/// Symbol 257 exits the span, so the pending-filter queue cannot change while
/// one runs and its head is captured once per lease.
#[inline]
fn fast_flush_is_pinned(window: &Window, pending_head: Option<(u64, usize)>) -> bool {
    let Some((block_start_total, block_length)) = pending_head else {
        return false;
    };
    block_start_total == window.total_flushed()
        && block_start_total.saturating_add(block_length as u64) > window.total_written()
        && window.unflushed_bytes() <= window.dict_size() as u64
}

/// Where [`run_fast_symbols`] puts the operations it decodes.
///
/// The symbol loop is one implementation with two consumers: the serial path
/// writes straight into the window ([`Rar4WindowSink`]), and the threaded path
/// records the operation for an apply thread ([`Rar4RecordSink`]). Everything
/// here is `#[inline(always)]` and the threaded sink's `yield_armed` is a
/// literal `false`, so the serial monomorphization folds back to exactly the
/// code that existed before the split. That is verified, not assumed: building
/// the crate with `cargo rustc --release --lib -- --emit asm` before and after
/// this split produces a byte-identical instruction stream for all five
/// `decode_lz_symbols` monomorphizations (3859 instructions each for the four
/// streaming readers, 1694 for `BitReader`). Re-run that comparison after
/// touching anything in this loop.
trait Rar4Sink {
    /// Apply a run of `n` literals (1..=8) packed so literal `i` occupies bits
    /// `8 * i`, which is the byte order [`Window::put_literal_batch`] stores.
    fn put_literals(&mut self, packed: u64, n: usize);

    /// Apply a match of `length` bytes at `distance`.
    ///
    /// Nothing here knows about the declared unpacked size: `Unpack29` copies
    /// whole matches into the window and the write layer decides what of it
    /// reaches the caller (unpack30.cpp:200-247, unpack50.cpp:538-548).
    fn copy_match(&mut self, distance: usize, length: usize) -> RarResult<()>;

    /// Cheap pre-test: is the unflushed span (plus `pending_literals` still in
    /// the register run) at or past the caller's flush threshold?
    ///
    /// Const-`false` for the threaded sink, whose apply thread owns the window
    /// and flushes inline instead of handing control back.
    fn yield_armed(&mut self, pending_literals: usize) -> bool;

    /// Full test, run only after the pending literal run has been applied:
    /// would a flush right now actually move the write border?
    fn yield_now(&mut self) -> bool;
}

/// The serial sink: operations go straight into the sliding window.
struct Rar4WindowSink<'a> {
    window: &'a mut Window,
    yield_threshold: Option<usize>,
    pending_head: Option<(u64, usize)>,
}

impl Rar4Sink for Rar4WindowSink<'_> {
    #[inline(always)]
    fn put_literals(&mut self, packed: u64, n: usize) {
        self.window.put_literal_batch(&packed.to_le_bytes(), n);
    }

    #[inline(always)]
    fn copy_match(&mut self, distance: usize, length: usize) -> RarResult<()> {
        self.window.copy(distance, length)
    }

    #[inline(always)]
    fn yield_armed(&mut self, pending_literals: usize) -> bool {
        match self.yield_threshold {
            Some(threshold) => {
                self.window.unflushed_bytes() as usize + pending_literals >= threshold
            }
            None => false,
        }
    }

    #[inline(always)]
    fn yield_now(&mut self) -> bool {
        !fast_flush_is_pinned(self.window, self.pending_head)
    }
}

// ─── Threaded decode/apply split ─────────────────────────────────────────────
//
// UnRAR does not multithread rar3/rar4 at all — `Unpack::DoUnpack` routes
// version 29 straight to the single-threaded `Unpack29` (unpack.cpp), and only
// RAR5 gets `Unpack5MT`. The structural template here is therefore rarpar's own
// RAR5 controller (`lz/parallel.rs`) with UnRAR's `unpack50mt.cpp` supplying the
// record shape and the batch sizing, adapted to the one thing RAR4 cannot do:
// its Huffman blocks are not independently addressable, so decode cannot fan
// out across blocks. What it can do is run *ahead* of the window, which is what
// this split does — one decode thread producing records, the calling thread
// applying them in stream order.

/// Items per batch handed to the apply side.
///
/// UnRAR sizes its per-thread `Decoded` array at `0x4100` because "typical
/// number of items in RAR blocks does not exceed 0x4000"
/// (unpack50mt.cpp:46-49), and rarpar's RAR5 controller carries the same number
/// as `DECODED_ITEMS_CAPACITY` (lz/parallel.rs:45-46). RAR4 reuses it unchanged
/// so all three agree on what a batch costs.
const RAR4_MT_BATCH_ITEMS: usize = 0x4100;

/// Batches alive at once: one being applied on this thread, one being filled by
/// the decode thread, one in transit. The RAR5 controller's `PIPELINE_DEPTH` is
/// 2 for exactly this reason (lz/parallel.rs:40-43); the third slot is the
/// recycling channel's headroom.
const RAR4_MT_PIPELINE_DEPTH: usize = 2;

/// Buffers the recycling channel holds, and the hard cap on how many are
/// carried between leases.
///
/// Nothing may ever *block* on this channel. An earlier revision let the
/// carried-over set grow past the channel's capacity and then primed it with a
/// blocking `send` before the decode thread was spawned — with no receiver
/// running, that hung the whole extraction. Every operation on the spare
/// channel is now `try_*`, and the carried set is truncated to this, so the
/// only blocking points left are the record channel's `send`/`recv` pair: a
/// single producer and a single consumer that always drains.
const RAR4_MT_SPARE_SLOTS: usize = RAR4_MT_PIPELINE_DEPTH + 1;

/// Records per batch. A compile-time constant in every shipped build.
#[cfg(not(test))]
#[inline(always)]
fn mt_batch_items() -> usize {
    RAR4_MT_BATCH_ITEMS
}

/// Records per batch, shrinkable by a test.
///
/// The repo's RAR4 fixtures are small enough that a full-size batch is never
/// filled, so nothing in the suite would cross the hand-off boundary — which is
/// exactly where the recycling protocol lives. Tests therefore drive the batch
/// down to a handful of records so the sweeps hammer it.
#[cfg(test)]
fn mt_batch_items() -> usize {
    mt_test_hooks::batch_items().unwrap_or(RAR4_MT_BATCH_ITEMS)
}

/// Whether the split runs unless a caller explicitly asks for it.
///
/// **Measured false.** There is no member size at which the split pays, so
/// there is no threshold to set — the cost is per byte, not per member, and it
/// grows with the member instead of amortizing.
///
/// On an i5-1240P, 8 MiB text payloads, `perf`-pinned, best-of-9 in-process,
/// serial on one CPU against the split on two of the same class:
///
/// | case                    | E serial | E split  | P serial | P split  |
/// |-------------------------|---------:|---------:|---------:|---------:|
/// | rar3 normal single      | 21.1 ms  | 23.6 ms  | 14.5 ms  | 16.9 ms  |
/// | rar4 normal single      | 21.4 ms  | 23.4 ms  | 14.8 ms  | 17.2 ms  |
/// | rar4 solid multivolume  | 21.4 ms  | 24.9 ms  | 15.0 ms  | 18.1 ms  |
/// | rar4 solid, 85 MiB      | 1152 ms  | 1475 ms  |  837 ms  | 1002 ms  |
///
/// The cause is in the same runs' `cpu/wall`, which is 1.02–1.06 on the split:
/// the two threads overlap for 2–6% of wall time and no more, because the apply
/// half is all there is to hide and it is only a few percent of the work. A
/// RAR4 apply is one eight-byte store per literal run and a `memcpy` per match;
/// the per-member CRC — the other candidate for hiding — measures at 3% here
/// (21.9 ms with verification against 21.5 ms without), because `crc-fast` is
/// hardware-accelerated. Against that ceiling the record stream costs about two
/// bytes written and two bytes read per output byte, and that is the 16–28%.
///
/// The one shape that does not lose is a degenerate match-heavy stream, where
/// records are rare per output byte and the `memcpy` share is large:
/// `test_read_format_rar_multi_lzss_blocks` (20 MiB out of 24 KiB in) runs
/// 17.09 → 16.90 ms on an E-core and 11.71 → 11.53 ms on a P-core, a 1%
/// improvement — not enough to admit on, and not detectable before decoding.
///
/// The mechanism is kept, tested and reachable through
/// `UNRAR_RS_RAR4_MT_THREADS`, because what it establishes — that RAR4 decode can
/// be lifted off the window thread byte-exactly — is the prerequisite for any
/// future arc that finds *more* work to move. What it does not do is pay for
/// itself today, so it does not run today.
const RAR4_MT_ADMITTED_BY_DEFAULT: bool = false;

/// One decoded RAR4 LZ operation, in flight between the two threads.
///
/// Shaped after UnRAR's `UnpackDecodedItem` (unpack.hpp:99-108): a small tag, a
/// length, and an eight-byte payload that is *either* the packed literal run or
/// the match distance. Same 16 bytes as the oracle's record.
///
/// Unlike the RAR5 controller's [`DecodedItem`], there is no `RepeatPrev` or
/// `CacheRef` variant: RAR5 fans decode out over several workers that cannot
/// see the running distance cache, so it defers cache resolution to the apply
/// phase. RAR4 has exactly one decode thread, which owns `Rar4FastState` and
/// therefore resolves every distance before the record is emitted. Two kinds is
/// all that reaches the window.
///
/// [`DecodedItem`]: super::lz::parallel::DecodedItem
#[derive(Clone, Copy)]
struct Rar4Item {
    /// Literals held in `payload` (1..=8), or 0 when this is a match.
    literals: u8,
    /// Full match length, when `literals == 0`.
    length: u32,
    /// The packed literal run (`literals != 0`) or the match distance.
    payload: u64,
}

/// The threaded sink: operations are recorded, not applied.
///
/// Backpressure is the bounded `items` channel: once the apply side is one
/// batch behind, `send` blocks the decode thread, which is what bounds this
/// path's memory to [`RAR4_MT_PIPELINE_DEPTH`] batches no matter how far ahead
/// decode could otherwise run.
struct Rar4RecordSink {
    /// [`RAR4_MT_BATCH_ITEMS`], except where a test shrinks it so small
    /// fixtures still cross the hand-off boundary many times over.
    batch_items: usize,
    batch: Vec<Rar4Item>,
    items: std::sync::mpsc::SyncSender<Vec<Rar4Item>>,
    spare: std::sync::mpsc::Receiver<Vec<Rar4Item>>,
    /// Set once the apply side has stopped taking batches, which only happens
    /// when it has already failed. Decode then runs the span out with the
    /// records discarded — see [`Rar4RecordSink::hand_off`].
    detached: bool,
}

impl Rar4RecordSink {
    fn new(
        items: std::sync::mpsc::SyncSender<Vec<Rar4Item>>,
        spare: std::sync::mpsc::Receiver<Vec<Rar4Item>>,
    ) -> Self {
        let batch_items = mt_batch_items();
        let batch = Self::take_empty(&spare, batch_items);
        Self {
            batch_items,
            batch,
            items,
            spare,
            detached: false,
        }
    }

    /// A batch buffer to fill, recycled if one is waiting.
    ///
    /// The `clear` is load-bearing and is why every take goes through here: a
    /// buffer handed back by the apply side still holds the records it just
    /// applied, and filling on top of them would re-apply the whole batch.
    fn take_empty(
        spare: &std::sync::mpsc::Receiver<Vec<Rar4Item>>,
        batch_items: usize,
    ) -> Vec<Rar4Item> {
        match spare.try_recv() {
            Ok(mut buf) => {
                buf.clear();
                buf.reserve(batch_items.saturating_sub(buf.capacity()));
                buf
            }
            Err(_) => Vec::with_capacity(batch_items),
        }
    }

    #[inline(always)]
    fn push(&mut self, item: Rar4Item) {
        self.batch.push(item);
        if self.batch.len() >= self.batch_items {
            self.hand_off();
        }
    }

    /// Hand the full batch to the apply side and take an empty one back.
    ///
    /// Outlined: it runs once per batch, so keeping
    /// the channel code out of the symbol loop's inlined body matters more than
    /// its own speed.
    #[cold]
    #[inline(never)]
    fn hand_off(&mut self) {
        if self.detached {
            // The apply side has failed; nothing downstream will read these.
            // Decode still runs the span out so the thread terminates and the
            // scope can join — the alternative, blocking on a dead channel, is
            // the deadlock this branch exists to prevent.
            self.batch.clear();
            return;
        }
        let empty = Self::take_empty(&self.spare, self.batch_items);
        let full = std::mem::replace(&mut self.batch, empty);
        if self.items.send(full).is_err() {
            self.detached = true;
        }
    }

    /// Send the trailing partial batch, close the item channel, and collect
    /// whatever buffers are already back for the next lease.
    ///
    /// Dropping the item sender is what ends the apply loop, so it happens
    /// first. The drain that follows is non-blocking: a buffer the apply side
    /// hands back after this point is kept on *its* side instead (see the
    /// consumer loop in [`Rar4LzDecoder::lease_fast_symbols_mt`]), so nothing
    /// is lost and nothing waits.
    fn finish(mut self) -> Vec<Vec<Rar4Item>> {
        if !self.detached && !self.batch.is_empty() {
            let full = std::mem::take(&mut self.batch);
            if self.items.send(full).is_err() {
                self.detached = true;
            }
        }
        drop(self.items);

        let mut recovered = Vec::with_capacity(RAR4_MT_SPARE_SLOTS);
        if self.batch.capacity() > 0 {
            self.batch.clear();
            recovered.push(std::mem::take(&mut self.batch));
        }
        while let Ok(mut buf) = self.spare.try_recv() {
            buf.clear();
            recovered.push(buf);
        }
        recovered.truncate(RAR4_MT_SPARE_SLOTS);
        recovered
    }
}

impl Rar4Sink for Rar4RecordSink {
    #[inline(always)]
    fn put_literals(&mut self, packed: u64, n: usize) {
        debug_assert!((1..=8).contains(&n), "literal run out of range: {n}");
        self.push(Rar4Item {
            literals: n as u8,
            length: 0,
            payload: packed,
        });
    }

    #[inline(always)]
    fn copy_match(&mut self, distance: usize, length: usize) -> RarResult<()> {
        // A RAR4 match is at most LDECODE's 224 + 3 + 31 extra bits + 2 of
        // distance adjustment, so `length` cannot reach `u32::MAX`.
        debug_assert!(length <= u32::MAX as usize, "match length {length}");
        self.push(Rar4Item {
            literals: 0,
            length: length as u32,
            payload: distance as u64,
        });
        Ok(())
    }

    /// Const-`false`: the apply thread owns the window, so it flushes in place
    /// instead of handing control back. This folds the whole yield block out of
    /// the threaded monomorphization.
    #[inline(always)]
    fn yield_armed(&mut self, _pending_literals: usize) -> bool {
        false
    }

    #[inline(always)]
    fn yield_now(&mut self) -> bool {
        false
    }
}

/// Which lease `decode_lz_symbols` drives: the serial one or the split one.
///
/// This is the "two monomorphizations" half of keeping the serial engine
/// untouched. Both instantiations share one copy of the per-symbol tail — the
/// arms that run for the last [`LZ_SPAN_SLACK_BYTES`] of every buffer fill and
/// for readers that cannot lend a span at all — while the lease call itself is
/// a zero-sized, always-inlined dispatch. The serial instantiation compiles to
/// the same instructions it did before the split existed — see the codegen note
/// on [`Rar4Sink`] for how that is checked.
///
/// [`LZ_SPAN_SLACK_BYTES`]: super::lz::bitstream::LZ_SPAN_SLACK_BYTES
trait Rar4LeaseDriver {
    fn lease<R: BitRead>(
        &mut self,
        decoder: &mut Rar4LzDecoder,
        reader: &mut R,
        decode_limit: u64,
        output_size: &mut u64,
        yield_threshold: Option<usize>,
    ) -> RarResult<Option<Rar4FastExit>>;
}

/// The serial driver: decode writes straight into the window, as it always has.
struct Rar4SerialLease;

impl Rar4LeaseDriver for Rar4SerialLease {
    #[inline(always)]
    fn lease<R: BitRead>(
        &mut self,
        decoder: &mut Rar4LzDecoder,
        reader: &mut R,
        decode_limit: u64,
        output_size: &mut u64,
        yield_threshold: Option<usize>,
    ) -> RarResult<Option<Rar4FastExit>> {
        decoder.lease_fast_symbols(reader, decode_limit, output_size, yield_threshold)
    }
}

/// The split driver: decode runs on a worker, apply and flush run here.
struct Rar4ThreadedLease<'w, W: Write + ?Sized> {
    writer: &'w mut W,
    flush_threshold: usize,
}

impl<W: Write + ?Sized> Rar4LeaseDriver for Rar4ThreadedLease<'_, W> {
    fn lease<R: BitRead>(
        &mut self,
        decoder: &mut Rar4LzDecoder,
        reader: &mut R,
        decode_limit: u64,
        output_size: &mut u64,
        _yield_threshold: Option<usize>,
    ) -> RarResult<Option<Rar4FastExit>> {
        decoder.lease_fast_symbols_mt(
            reader,
            decode_limit,
            output_size,
            self.flush_threshold,
            self.writer,
        )
    }
}

/// Test-only switches for the threaded LZ path.
///
/// Thread-local for the same reason [`super::lz::bitstream::test_hooks`] is:
/// the suite runs tests in parallel inside one process, so a process-wide
/// switch (an environment variable, a static) would let one test's setting
/// decide another test's path. The production knob stays the environment
/// variable; this only overrides it, and only in `cfg(test)` builds.
#[cfg(test)]
pub(crate) mod mt_test_hooks {
    use std::cell::Cell;

    thread_local! {
        static FORCED_THREADS: Cell<Option<usize>> = const { Cell::new(None) };
        static BATCH_ITEMS: Cell<Option<usize>> = const { Cell::new(None) };
    }

    thread_local! {
        /// Spans actually handed to a decode thread. Thread-local and exact:
        /// the lease is taken on the calling thread, so a test can assert that
        /// its own run engaged the split without a concurrently running test
        /// perturbing the count.
        pub(super) static MT_LEASES: Cell<usize> = const { Cell::new(0) };
    }

    struct Restore(Option<usize>);

    impl Drop for Restore {
        fn drop(&mut self) {
            FORCED_THREADS.with(|cell| cell.set(self.0));
        }
    }

    /// Run `body` with the RAR4 LZ split forced to `threads` (1 = serial).
    pub(crate) fn with_mt_threads<T>(threads: usize, body: impl FnOnce() -> T) -> T {
        let _restore = Restore(FORCED_THREADS.with(Cell::get));
        FORCED_THREADS.with(|cell| cell.set(Some(threads)));
        body()
    }

    struct RestoreBatch(Option<usize>);

    impl Drop for RestoreBatch {
        fn drop(&mut self) {
            BATCH_ITEMS.with(|cell| cell.set(self.0));
        }
    }

    /// Run `body` with the record batch shrunk to `items`, so the hand-off and
    /// buffer-recycling protocol runs many times over even on a small fixture.
    pub(crate) fn with_mt_batch_items<T>(items: usize, body: impl FnOnce() -> T) -> T {
        let _restore = RestoreBatch(BATCH_ITEMS.with(Cell::get));
        BATCH_ITEMS.with(|cell| cell.set(Some(items)));
        body()
    }

    pub(super) fn batch_items() -> Option<usize> {
        BATCH_ITEMS.with(Cell::get)
    }

    pub(super) fn forced_threads() -> Option<usize> {
        FORCED_THREADS.with(Cell::get)
    }

    pub(super) fn note_mt_lease() {
        MT_LEASES.with(|cell| cell.set(cell.get() + 1));
    }

    pub(crate) fn mt_lease_count() -> usize {
        MT_LEASES.with(Cell::get)
    }
}

/// Threads the RAR4 LZ split may use, and the knob the tests and the perf
/// harness drive it with.
///
/// The split is one producer plus one consumer, so any width at or above two
/// engages the same two threads; the value is still read (rather than treated
/// as a bool) so a harness can sweep it the way it sweeps the RAR5 worker
/// count, and so `1` means "serial" everywhere.
fn rar4_mt_threads() -> usize {
    #[cfg(test)]
    if let Some(forced) = mt_test_hooks::forced_threads() {
        return forced;
    }
    if let Some(raw) = std::env::var_os("UNRAR_RS_RAR4_MT_THREADS")
        && let Some(text) = raw.to_str()
        && let Ok(value) = text.trim().parse::<usize>()
    {
        return value;
    }
    if std::env::var_os("UNRAR_RS_DISABLE_PARALLEL").is_some() {
        return 1;
    }
    // `parallel_enabled` const-folds to `true` on native and probes once on
    // wasm, where `wasm32-wasip1` cannot spawn at all. See
    // `reedsolomon_rs::threading` for why this is not a plain `cfg!`.
    if !reedsolomon_rs::threading::parallel_enabled() {
        return 1;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Whether the decode/apply split runs for this member.
///
/// The RAR5 controller's admission shape (`MIN_PARALLEL_BLOCKS`,
/// lz/parallel.rs:37-38): decide once, up front, and fall back to the untouched
/// serial engine rather than degrade inside it. The difference is what the
/// decision reduces to — see [`RAR4_MT_ADMITTED_BY_DEFAULT`] for why RAR4's is
/// a measured "no" rather than a size threshold.
///
/// `unpacked_size` is taken so a future arc that does find a crossover has
/// somewhere to put it, and so the shape stays comparable to RAR5's.
fn rar4_mt_admitted(unpacked_size: u64) -> bool {
    let _ = unpacked_size;
    if rar4_mt_threads() < 2 {
        return false;
    }
    // An explicit width is a deliberate request — a test, or a perf sweep —
    // and turns the split on regardless of the default.
    #[cfg(test)]
    if mt_test_hooks::forced_threads().is_some() {
        return true;
    }
    if std::env::var_os("UNRAR_RS_RAR4_MT_THREADS").is_some() {
        return true;
    }
    RAR4_MT_ADMITTED_BY_DEFAULT
}

/// `Rar4LzDecoder::decode_distance` driven off the register cursor.
///
/// Line for line the same shape as the oracle's inline distance decode
/// (unpack30.cpp:154-190); only the bit source differs.
#[inline(always)]
fn fast_decode_distance(
    cursor: &mut BitCursor,
    data: &[u8],
    end_bit: usize,
    tables: &Rar4FastTables<'_>,
    state: &mut Rar4FastState,
) -> usize {
    let (dist_number, _) = tables.dd.decode_cursor(cursor, data, end_bit);
    let dist_number = dist_number as usize;
    // The DD table is built from exactly `DC` code lengths, and
    // `decode_cursor` cannot return a symbol at or past `num_symbols`.
    debug_assert!(
        dist_number < DC,
        "distance code out of range: {dist_number}"
    );

    let mut distance = tables.ddecode[dist_number] as usize + 1;
    let bits = tables.dbits[dist_number];

    if bits > 0 {
        if dist_number > 9 {
            if bits > 4 {
                distance += (cursor_read_bits(cursor, data, end_bit, bits - 4) as usize) << 4;
            }

            if state.low_dist_rep_count > 0 {
                state.low_dist_rep_count -= 1;
                distance += state.prev_low_dist;
            } else {
                let (low_dist, _) = tables.ldd.decode_cursor(cursor, data, end_bit);
                let low_dist = low_dist as usize;
                if low_dist == 16 {
                    state.low_dist_rep_count = LOW_DIST_REP_COUNT - 1;
                    distance += state.prev_low_dist;
                } else {
                    distance += low_dist;
                    state.prev_low_dist = low_dist;
                }
            }
        } else {
            distance += cursor_read_bits(cursor, data, end_bit, bits) as usize;
        }
    }

    distance
}

/// Decode RAR4 LZ symbols across one leased input span.
///
/// This is the loop the whole restructure exists for. Everything it touches
/// per symbol is a local or a table load: the bit cursor is a `BitCursor`
/// copy, the distance/length state is `Rar4FastState`, the tables are
/// borrowed once, and the input has [`LZ_SPAN_SLACK_BYTES`] of guaranteed
/// slack so no read needs a bounds or availability test — the same three
/// properties that make UnRAR's `Unpack29` loop cheap.
///
/// Returns the bit offset in `span.data` it stopped at, which the reader uses
/// to re-establish its own cursor, plus why it stopped.
///
/// [`LZ_SPAN_SLACK_BYTES`]: super::lz::bitstream::LZ_SPAN_SLACK_BYTES
fn run_fast_symbols<S: Rar4Sink>(
    span: &LzSpan<'_>,
    tables: &Rar4FastTables<'_>,
    state: &mut Rar4FastState,
    sink: &mut S,
    decode_limit: u64,
    output_size: &mut u64,
) -> (usize, RarResult<Rar4FastExit>) {
    let data = span.data;
    let end_bit = data.len() * 8;
    let mut cursor = BitCursor {
        acc: 0,
        acc_bits: 0,
        pos: span.start_bit,
    };
    cursor_refill(&mut cursor, data, end_bit);

    let mut out = *output_size;

    // Pending literal run, packed so that literal `i` occupies bits `8 * i` —
    // the byte order `Window::put_literal_batch` stores. Accumulating in a
    // register and storing eight at a time replaces eight
    // store/increment/wrap-compare/counter sequences with one 8-byte store.
    let mut lit_packed: u64 = 0;
    let mut lit_len: usize = 0;

    // Every window read has to see the literals decoded before it, so the run
    // is applied before any match copy, before the flush bookkeeping is
    // consulted, and before the loop hands control back.
    macro_rules! apply_literals {
        () => {
            if lit_len != 0 {
                sink.put_literals(lit_packed, lit_len);
                lit_packed = 0;
                lit_len = 0;
            }
        };
    }

    macro_rules! copy_match {
        ($distance:expr, $length:expr) => {{
            apply_literals!();
            let length = $length;
            if let Err(err) = sink.copy_match($distance, length) {
                *output_size = out;
                return (cursor.pos, Err(err));
            }
            out += length as u64;
        }};
    }

    let exit = loop {
        if out >= decode_limit {
            break Rar4FastExit::Complete;
        }
        // UnRAR's `Inp.InAddr > ReadBorder` (unpack30.cpp:56), in bits.
        if cursor.pos >= span.border_bit {
            break Rar4FastExit::Border;
        }

        let (number, _) = tables.ld.decode_cursor(&mut cursor, data, end_bit);
        let number = number as usize;
        let mut produced_output = false;

        if number < 256 {
            // Literal byte (most common — first).
            lit_packed |= (number as u64) << (8 * lit_len);
            lit_len += 1;
            out += 1;
            if lit_len == 8 {
                sink.put_literals(lit_packed, 8);
                lit_packed = 0;
                lit_len = 0;
            }
            produced_output = true;
        } else if number >= 271 {
            // Regular match: decode length then distance.
            let length_idx = number - 271;
            debug_assert!(
                length_idx < LDECODE.len(),
                "length index out of range: {length_idx}"
            );
            let mut length = LDECODE[length_idx] as usize + 3;
            let lbits = LBITS[length_idx];
            if lbits > 0 {
                length += cursor_read_bits(&mut cursor, data, end_bit, lbits) as usize;
            }

            let distance = fast_decode_distance(&mut cursor, data, end_bit, tables, state);

            // Distance-based length adjustment.
            if distance >= 0x2000 {
                length += 1;
                if distance >= 0x40000 {
                    length += 1;
                }
            }

            state.dist_cache[3] = state.dist_cache[2];
            state.dist_cache[2] = state.dist_cache[1];
            state.dist_cache[1] = state.dist_cache[0];
            state.dist_cache[0] = distance;
            state.last_length = length;
            copy_match!(distance, length);
            produced_output = true;
        } else if number == 256 || number == 257 {
            // End of block and VM filter code both need the reader itself.
            apply_literals!();
            break Rar4FastExit::Cold(number);
        } else if number == 258 {
            // Repeat previous match.
            if state.last_length != 0 {
                copy_match!(state.dist_cache[0], state.last_length);
                produced_output = true;
            }
        } else if number < 263 {
            // Repeat distance from cache (259-262).
            let cache_idx = number - 259;
            let distance = state.dist_cache[cache_idx];

            // Rotate cache.
            for j in (1..=cache_idx).rev() {
                state.dist_cache[j] = state.dist_cache[j - 1];
            }
            state.dist_cache[0] = distance;

            // Decode length from RD table.
            let (length_number, _) = tables.rd.decode_cursor(&mut cursor, data, end_bit);
            let length_number = length_number as usize;
            debug_assert!(
                length_number < LDECODE.len(),
                "RD length index out of range: {length_number}"
            );
            let mut length = LDECODE[length_number] as usize + 2; // +2 for cache refs
            let lbits = LBITS[length_number];
            if lbits > 0 {
                length += cursor_read_bits(&mut cursor, data, end_bit, lbits) as usize;
            }

            state.last_length = length;
            copy_match!(distance, length);
            produced_output = true;
        } else if number < 272 {
            // Short match (263-270): length=2, decode short distance.
            let sd_idx = number - 263;
            let mut distance = SDDECODE[sd_idx] as usize + 1;
            let sd_bits = SDBITS[sd_idx];
            if sd_bits > 0 {
                distance += cursor_read_bits(&mut cursor, data, end_bit, sd_bits) as usize;
            }

            state.dist_cache[3] = state.dist_cache[2];
            state.dist_cache[2] = state.dist_cache[1];
            state.dist_cache[1] = state.dist_cache[0];
            state.dist_cache[0] = distance;
            state.last_length = 2;
            copy_match!(distance, 2);
            produced_output = true;
        } else {
            // Unreachable for the same reason as the per-symbol path: the LD
            // table has 299 symbols and 256..=298 are covered above.
            debug_assert!(false, "invalid symbol: {number}");
        }

        if produced_output && sink.yield_armed(lit_len) {
            // The pin test reads the window's write/flush borders, so the
            // pending literals have to be in the window before it runs.
            apply_literals!();
            if sink.yield_now() {
                break Rar4FastExit::Yield;
            }
        }
    };

    // `Cold` and `Yield` already applied their run before breaking; `Border`
    // and `Complete` land here with one still pending.
    if lit_len != 0 {
        sink.put_literals(lit_packed, lit_len);
    }
    *output_size = out;
    (cursor.pos, Ok(exit))
}

/// State for the RAR4 LZ decompressor.
pub struct Rar4LzDecoder {
    /// Sliding window / ring buffer.
    window: Window,
    /// Last-distance cache (4 entries for repeat matches).
    dist_cache: [usize; 4],
    /// Last match length (for symbol 258 repeat).
    last_length: usize,
    /// `OldDistPtr` and `LastDist` from the shared `Unpack` object.
    ///
    /// `Unpack29` reads neither — it indexes `OldDist` directly and repeats
    /// `OldDist[0]` (unpack30.cpp:204-217, 227-231) — but both live in the same
    /// object as the window and survive a solid unpack-version switch
    /// (unpack.cpp:194-206), so this decoder carries them for whichever 1.5 or
    /// 2.0 member the archive switches to next. See
    /// [`Rar4Decoder::shared_lz_state`](super::rar4_old::Rar4Decoder).
    carried_old_dist_ptr: usize,
    carried_last_dist: usize,
    /// Huffman tables.
    ld_table: Option<HuffmanTable>,
    dd_table: Option<HuffmanTable>,
    ldd_table: Option<HuffmanTable>,
    rd_table: Option<HuffmanTable>,
    /// Code lengths for delta encoding persistence across blocks.
    code_lengths: Vec<u8>,
    /// Distance decode tables (built once).
    ddecode: [u32; DC],
    dbits: [u8; DC],
    /// Low distance state.
    low_dist_rep_count: usize,
    prev_low_dist: usize,
    /// Current block type (LZ or PPMd).
    block_type: BlockType,
    /// PPMd model (persists across PPMd blocks within a file).
    ppm_model: Option<Model>,
    /// PPMd escape character (default 2).
    ppm_esc_char: u8,
    /// Whether the RAR3 Huffman tables have been read.
    tables_read: bool,
    /// Reusable VM filter definitions within the current filter scope.
    vm_filters: Vec<Rar4VmFilterDefinition>,
    /// Pending filters waiting for their output block to become flushable.
    pending_vm_filters: Vec<Rar4PendingVmFilter>,
    /// Last referenced VM filter slot.
    last_vm_filter: usize,
    /// Absolute window position where the current file started.
    current_file_base_total: u64,
    /// `Unpack::WrittenFileSize` for the member being decoded.
    ///
    /// This is the oracle's counter, not a count of emitted bytes:
    /// `UnpWriteData` advances it by the *full* span it was handed even when it
    /// clamped the write to the declared size, and stops advancing it once it
    /// has reached that size (unpack50.cpp:538-548). It seeds the VM's `R[6]`
    /// (unpack30.cpp:624-628) and it is what the decode loop's size stop tests
    /// (unpack30.cpp:59-70).
    current_file_written_size: u64,
    /// Bytes this member has actually handed to the writer.
    ///
    /// Distinct from `current_file_written_size` on exactly the streams this
    /// module's size handling is about: a clamped raw span advances the counter
    /// without emitting, and a filtered block emits without being clamped.
    current_file_emitted: u64,
    /// The member's declared unpacked size, i.e. the oracle's `DestUnpSize`.
    current_file_unpacked_size: u64,
    /// Range coder registers saved when a solid member's output ends inside
    /// a PPMd block. One coder stays alive across solid members: only
    /// PPMd block headers re-initialize it, so the next member must resume
    /// with these registers instead of consuming init bytes.
    ppm_rc_state: Option<RangeCoderState>,
    /// Set when the LZ loop hit a stop condition that ends this member.
    ///
    /// Symbol 256 signalling "new file" and a truncated VM code packet both
    /// `break` out of `Unpack29`'s main loop (unpack30.cpp:204-215), which
    /// flushes what was decoded and returns. Without this the outer loop would
    /// re-enter `decode_lz_symbols` and keep decoding against stale tables.
    member_decode_done: bool,
    /// Staging buffer holding the VM filter's input block, reused for every
    /// filtered block instead of being allocated per block.
    filter_scratch: Vec<u8>,
    /// Destination buffer for the media filters (DELTA/RGB/AUDIO). It is
    /// swapped with `filter_scratch` when a filter completes, so a chain of
    /// filters over one block ping-pongs between two long-lived allocations.
    media_scratch: Vec<u8>,
    /// Highest `base + output_size` a pending filter has been queued at, used
    /// only to assert that the decoder-owned half of a filter start never moves
    /// backwards (see the push site in `add_vm_code`).
    #[cfg(debug_assertions)]
    last_pending_filter_base: u64,
    /// Entries into `decode_lz_symbols`, so the border-pin test can show the
    /// loop is not re-entered once per symbol.
    #[cfg(test)]
    decode_lz_calls: usize,
    /// Recycled record batches for the threaded LZ path.
    ///
    /// An empty `Vec` allocates nothing, so a build that never admits the
    /// threaded path — wasm, a single-CPU host, or the default configuration —
    /// pays one 24-byte field and no work at all. Once the path does run, the
    /// batches are carried between leases here rather than reallocated per
    /// span.
    mt_spare_batches: Vec<Vec<Rar4Item>>,
    /// Recycled `StreamingBitReader` input buffer (512 KiB).
    ///
    /// Every streaming decode entry point builds a fresh `StreamingBitReader`
    /// (each member's data area is an independent byte-aligned bitstream), but
    /// the 512 KiB backing allocation has no per-member state, so it is parked
    /// here between members instead of being allocated and zeroed again. See
    /// `StreamingBitReader::with_buffer` for why reuse needs no zeroing.
    input_buffer: Option<Box<[u8]>>,
}

impl Rar4LzDecoder {
    /// Create a new RAR4 LZ decoder with the specified dictionary size.
    pub fn new(dict_size: usize) -> Self {
        Self::try_new(dict_size).expect("RAR4 LZ decoder allocation failed")
    }

    /// Fallibly create a new RAR4 LZ decoder with the specified dictionary size.
    pub fn try_new(dict_size: usize) -> RarResult<Self> {
        let (ddecode, dbits) = build_ddecode_tables();
        Ok(Self {
            window: Window::try_new(dict_size)?,
            dist_cache: [usize::MAX; 4],
            last_length: 0,
            carried_old_dist_ptr: 0,
            carried_last_dist: usize::MAX,
            ld_table: None,
            dd_table: None,
            ldd_table: None,
            rd_table: None,
            code_lengths: vec![0u8; HUFF_TABLE_SIZE],
            ddecode,
            dbits,
            low_dist_rep_count: 0,
            prev_low_dist: 0,
            block_type: BlockType::Lz,
            ppm_model: None,
            ppm_esc_char: 2,
            tables_read: false,
            vm_filters: Vec::new(),
            pending_vm_filters: Vec::new(),
            last_vm_filter: 0,
            current_file_base_total: 0,
            current_file_written_size: 0,
            current_file_emitted: 0,
            current_file_unpacked_size: 0,
            ppm_rc_state: None,
            member_decode_done: false,
            filter_scratch: Vec::new(),
            media_scratch: Vec::new(),
            #[cfg(debug_assertions)]
            last_pending_filter_base: 0,
            #[cfg(test)]
            decode_lz_calls: 0,
            mt_spare_batches: Vec::new(),
            input_buffer: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn window_size(&self) -> usize {
        self.window.dict_size()
    }

    /// Borrow the recycled streaming input buffer, allocating on first use.
    fn take_input_buffer(&mut self) -> Box<[u8]> {
        self.input_buffer
            .take()
            .unwrap_or_else(StreamingBitReader::<std::io::Empty>::alloc_buffer)
    }

    fn recycle_input_buffer(&mut self, buf: Box<[u8]>) {
        self.input_buffer = Some(buf);
    }

    /// The parked input buffer, for the buffer-reuse test.
    #[cfg(test)]
    pub(crate) fn input_buffer_for_test(&self) -> Option<&[u8]> {
        self.input_buffer.as_deref()
    }

    fn flush_threshold(&self) -> usize {
        self.window
            .dict_size()
            .saturating_sub(MAX3_INC_LZ_MATCH)
            .clamp(1, UNPACK_MAX_WRITE)
    }

    fn begin_file_decode(&mut self, unpacked_size: u64) {
        self.pending_vm_filters.clear();
        // Filter starts are only monotonic within one filter scope: a
        // non-solid member restarts both the window and the base, so the
        // push-side baseline restarts with it.
        #[cfg(debug_assertions)]
        {
            self.last_pending_filter_base = 0;
        }
        self.current_file_base_total = self.window.total_written();
        self.current_file_written_size = 0;
        self.current_file_emitted = 0;
        self.current_file_unpacked_size = unpacked_size;
        self.member_decode_done = false;
        self.window.mark_flushed(self.current_file_base_total);
    }

    /// How far past the file start this member may decode.
    ///
    /// `Unpack29` has no size-driven loop bound at all: it decodes until the
    /// end-of-file marker or the end of the packed area, and it stops early
    /// only when a mid-loop flush has already pushed `WrittenFileSize` past
    /// `DestUnpSize` (unpack30.cpp:59-70) -- which is [`Self::size_stop_reached`],
    /// not this. That flush fires when the window's write border is about to be
    /// overrun, i.e. once every [`Self::flush_threshold`] bytes, so the oracle
    /// decodes up to one write window past the declared size and every VM
    /// filter queued inside that window still runs. Filtered blocks are written
    /// without a clamp (unpack30.cpp:597-599), so what it decodes there can
    /// still reach the output.
    ///
    /// rarpar keeps the declared size as the bound, because everything the
    /// oracle decodes past it that is *not* under a filter is dropped by
    /// `UnpWriteData` and cannot change one output byte — and stopping there
    /// keeps a corrupt stream from being decoded for output nobody will see.
    /// What the bound has to add is the reach of the blocks already queued: a
    /// block is written whole or not at all, so cutting the decode inside one
    /// would drop it. The reach is capped one dictionary past the declared
    /// size, which is the furthest the oracle can still apply a block — beyond
    /// that the ring has overwritten the block's own bytes.
    ///
    /// The residual: a filter queued *entirely* past the declared size, with
    /// nothing queued before it to carry the bound there, is never seen. The
    /// oracle would reach it inside its write window. No writer emits one —
    /// RAR queues a filter before the data it covers, which is exactly the
    /// case the reach term keeps.
    fn decode_limit(&self) -> u64 {
        let base = self.current_file_base_total;
        let declared = self.current_file_unpacked_size;
        let mut limit = declared;
        for filter in &self.pending_vm_filters {
            let end = filter
                .block_start_total
                .saturating_add(filter.block_length as u64);
            limit = limit.max(end.saturating_sub(base));
        }
        limit.min(declared.saturating_add(self.window.dict_size() as u64))
    }

    /// `UnpWriteData` over the window span `[total_flushed, advance_to)`
    /// (unpack50.cpp:538-548, shared by the v29 and v5 write paths).
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

    fn reset_vm_filter_state(&mut self) {
        self.pending_vm_filters.clear();
        self.vm_filters.clear();
        self.last_vm_filter = 0;
    }

    fn ensure_vm_filter_definition(&mut self, filter_pos: usize, new_filter: bool) {
        if new_filter {
            debug_assert_eq!(filter_pos, self.vm_filters.len());
            self.vm_filters.push(Rar4VmFilterDefinition {
                filter_type: Rar4StandardFilter::None,
                last_block_length: 0,
            });
        }
    }

    fn read_vm_data(reader: &mut BitReader<'_>) -> RarResult<u32> {
        let bits_avail = reader.bits_remaining();
        if bits_avail == 0 {
            return Err(RarError::CorruptArchive {
                detail: "RAR4: unexpected end of VM code".into(),
            });
        }
        let peek_count = 16.min(bits_avail) as u8;
        let raw = reader.peek_bits(peek_count)?;
        let data = if peek_count < 16 {
            raw << (16 - peek_count)
        } else {
            raw
        };
        match data & 0xC000 {
            0 => {
                reader.consume_bits(6)?;
                Ok((data >> 10) & 0x0F)
            }
            0x4000 => {
                if (data & 0x3C00) == 0 {
                    reader.consume_bits(14)?;
                    Ok(0xFFFF_FF00 | ((data >> 2) & 0xFF))
                } else {
                    reader.consume_bits(10)?;
                    Ok((data >> 6) & 0xFF)
                }
            }
            0x8000 => {
                reader.consume_bits(2)?;
                reader.read_bits(16)
            }
            _ => {
                reader.consume_bits(2)?;
                let high = reader.read_bits(16)?;
                let low = reader.read_bits(16)?;
                Ok((high << 16) | low)
            }
        }
    }

    fn decode_vm_code_length<F>(first_byte: u8, mut read_byte: F) -> RarResult<usize>
    where
        F: FnMut() -> RarResult<u8>,
    {
        let mut length = (first_byte & 7) as usize + 1;
        if length == 7 {
            length = read_byte()? as usize + 7;
        } else if length == 8 {
            let high = read_byte()? as usize;
            let low = read_byte()? as usize;
            length = (high << 8) | low;
        }

        if length == 0 {
            return Err(RarError::CorruptArchive {
                detail: "RAR4: VM code length is 0".into(),
            });
        }

        Ok(length)
    }

    fn standard_vm_filter(code: &[u8]) -> Option<Rar4StandardFilter> {
        if code.is_empty() {
            return None;
        }

        let xor_sum = code[1..].iter().fold(0u8, |acc, byte| acc ^ byte);
        if xor_sum != code[0] {
            return None;
        }

        match (code.len(), crc32fast::hash(code)) {
            (53, 0xAD57_6887) => Some(Rar4StandardFilter::E8),
            (57, 0x3CD7_E57E) => Some(Rar4StandardFilter::E8E9),
            (120, 0x3769_893F) => Some(Rar4StandardFilter::Itanium),
            (29, 0x0E06_077D) => Some(Rar4StandardFilter::Delta),
            (149, 0x1C2C_5DC8) => Some(Rar4StandardFilter::Rgb),
            (216, 0xBC85_E701) => Some(Rar4StandardFilter::Audio),
            _ => None,
        }
    }

    fn vm_u32_to_usize(value: u32, field: &str) -> RarResult<usize> {
        usize::try_from(value).map_err(|_| RarError::CorruptArchive {
            detail: format!("RAR4: {field} value {value} does not fit usize"),
        })
    }

    fn add_vm_code(&mut self, first_byte: u8, code: &[u8], output_size: u64) -> RarResult<()> {
        let mut vm_reader = BitReader::new(code);

        let filter_pos = if (first_byte & 0x80) != 0 {
            let value = Self::vm_u32_to_usize(Self::read_vm_data(&mut vm_reader)?, "filter slot")?;
            if value == 0 {
                self.reset_vm_filter_state();
                0
            } else {
                value - 1
            }
        } else {
            self.last_vm_filter
        };

        if filter_pos > self.vm_filters.len() || filter_pos > MAX3_UNPACK_FILTERS {
            return Err(RarError::CorruptArchive {
                detail: format!("RAR4: VM filter slot {filter_pos} is out of range"),
            });
        }

        let new_filter = filter_pos == self.vm_filters.len();
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 add_vm_code: first_byte=0x{first_byte:02x} filter_pos={filter_pos} new={new_filter} bits_remaining={}",
                vm_reader.bits_remaining()
            );
        }
        self.ensure_vm_filter_definition(filter_pos, new_filter);
        let mut block_start =
            Self::vm_u32_to_usize(Self::read_vm_data(&mut vm_reader)?, "block start")?;
        if (first_byte & 0x40) != 0 {
            block_start = block_start.saturating_add(258);
        }
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 add_vm_code block_start={block_start} bits_remaining={}",
                vm_reader.bits_remaining()
            );
        }

        let block_length = if (first_byte & 0x20) != 0 {
            let length =
                Self::vm_u32_to_usize(Self::read_vm_data(&mut vm_reader)?, "block length")?;
            if let Some(existing) = self.vm_filters.get_mut(filter_pos) {
                existing.last_block_length = length;
            }
            length
        } else if let Some(existing) = self.vm_filters.get(filter_pos) {
            existing.last_block_length
        } else {
            0
        };
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 add_vm_code block_length={block_length} bits_remaining={}",
                vm_reader.bits_remaining()
            );
        }

        let mut init_regs = [0u32; 7];
        init_regs[4] = block_length as u32;
        if (first_byte & 0x10) != 0 {
            let init_mask = vm_reader.read_bits(7)? as u8;
            if rar4_debug_filters_enabled() {
                eprintln!(
                    "RAR4 add_vm_code init_mask=0x{init_mask:02x} bits_remaining={}",
                    vm_reader.bits_remaining()
                );
            }
            for (index, register) in init_regs.iter_mut().enumerate() {
                if (init_mask & (1 << index)) != 0 {
                    *register = Self::read_vm_data(&mut vm_reader)?;
                }
            }
        }

        let filter_type = if new_filter {
            let code_size =
                Self::vm_u32_to_usize(Self::read_vm_data(&mut vm_reader)?, "VM code size")?;
            if rar4_debug_filters_enabled() {
                eprintln!(
                    "RAR4 add_vm_code code_size={code_size} bits_remaining={}",
                    vm_reader.bits_remaining()
                );
            }
            if code_size == 0 || code_size >= 0x10000 {
                return Err(RarError::CorruptArchive {
                    detail: format!("RAR4: invalid VM code size {code_size}"),
                });
            }
            if !vm_reader.has_exact_bits(code_size.saturating_mul(8))? {
                return Err(RarError::CorruptArchive {
                    detail: format!("RAR4: VM code size {code_size} exceeds filter packet"),
                });
            }

            let mut vm_code = Vec::with_capacity(code_size);
            for _ in 0..code_size {
                vm_code.push(vm_reader.read_bits(8)? as u8);
            }

            let filter_type =
                Self::standard_vm_filter(&vm_code).unwrap_or(Rar4StandardFilter::None);

            self.vm_filters[filter_pos].filter_type = filter_type;
            filter_type
        } else {
            self.vm_filters[filter_pos].filter_type
        };

        // `PrgStack` is bounded the same way `Filters30` is (unpack30.cpp:
        // 426-430). The oracle answers an overflow with `return false`, which
        // ends the member decode; rarpar is stricter and surfaces it, matching
        // how every other RAR4 resource bound in this decoder behaves.
        if self.pending_vm_filters.len() > MAX3_UNPACK_FILTERS {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "RAR4: queued VM filter blocks exceed maximum {MAX3_UNPACK_FILTERS}"
                ),
            });
        }

        self.last_vm_filter = filter_pos;
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 filter: output_size={output_size} start={} len={} type={:?} base={}",
                block_start, block_length, filter_type, self.current_file_base_total
            );
        }
        // Why `flush_ready_output_to_writer` may look at the queue head alone:
        // a filter's start is `base + output_size + block_start`, where `base`
        // only advances between members, `output_size` only grows inside the
        // decode loop, and the stream-supplied `block_start` is a non-negative
        // delta from that point. A stream written by RAR therefore queues
        // filters in non-decreasing start order, so the head is the earliest
        // block and the drain can stop as soon as the head is not flushable.
        //
        // Only the `base + output_size` half of that is an invariant this
        // decoder can enforce, and it is what the assert below pins. The
        // `block_start` delta comes from the archive and a corrupt stream can
        // make it jump backwards, so out-of-order arrival stays *handled*
        // rather than assumed: the drain drops a head that already sits behind
        // the write border (see the `next_start < written_border` arm).
        // Asserting the composed total here would turn that hostile-input path
        // into a debug-build panic.
        #[cfg(debug_assertions)]
        {
            let base = self.current_file_base_total + output_size;
            debug_assert!(
                base >= self.last_pending_filter_base,
                "RAR4 filter base moved backwards: {base} < {}",
                self.last_pending_filter_base
            );
            self.last_pending_filter_base = base;
        }

        self.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type,
            block_start_total: self.current_file_base_total + output_size + block_start as u64,
            block_length,
            init_regs,
        });
        Ok(())
    }

    /// The oracle addresses an Itanium bundle through a flat `byte *Data`
    /// (rarvm.cpp:335-364), so neither of its bit helpers pays for a bounds
    /// check. This port keeps the safety but pays the check once per bundle by
    /// viewing the bundle as a fixed-size array: the widest reach is slot 2's
    /// opcode read at bit 124, i.e. byte 15, and both helpers touch 4 bytes
    /// from there, so byte 18 is the highest index either can reach. 22 is what
    /// the loop condition `cur_pos + 21 < data_size` already proves addressable,
    /// so forming the view can never fail and the inner accesses are all
    /// statically in range.
    const ITANIUM_BUNDLE_WINDOW: usize = 22;

    /// The 4 bytes `bit_pos` addresses, as one bounds-checked window.
    ///
    /// `in_addr` is at most 15 (bit 124), so `in_addr + 4 <= 19` is always
    /// within [`Self::ITANIUM_BUNDLE_WINDOW`] and this slice cannot panic.
    #[inline(always)]
    fn itanium_word_range(bit_pos: u32) -> std::ops::Range<usize> {
        let in_addr = (bit_pos / 8) as usize;
        in_addr..in_addr + 4
    }

    #[inline(always)]
    fn itanium_get_bits(
        data: &[u8; Self::ITANIUM_BUNDLE_WINDOW],
        bit_pos: u32,
        bit_count: u32,
    ) -> u32 {
        let in_bit = bit_pos & 7;
        let word: [u8; 4] = data[Self::itanium_word_range(bit_pos)]
            .try_into()
            .expect("4-byte itanium window");
        // Little-endian assembly of the four bytes, matching the oracle's
        // byte-at-a-time `BitField |= Data[InAddr++] << N`.
        let bit_field = u32::from_le_bytes(word);
        (bit_field >> in_bit) & (0xFFFF_FFFFu32 >> (32 - bit_count))
    }

    #[inline(always)]
    fn itanium_set_bits(
        data: &mut [u8; Self::ITANIUM_BUNDLE_WINDOW],
        bit_field: u32,
        bit_pos: u32,
        bit_count: u32,
    ) {
        let in_bit = bit_pos & 7;
        let mut and_mask = !(0xFFFF_FFFFu32 >> (32 - bit_count) << in_bit);
        let mut bit_field = bit_field << in_bit;

        let word: &mut [u8; 4] = (&mut data[Self::itanium_word_range(bit_pos)])
            .try_into()
            .expect("4-byte itanium window");
        for byte in word.iter_mut() {
            *byte &= and_mask as u8;
            *byte |= bit_field as u8;
            and_mask = (and_mask >> 8) | 0xFF00_0000;
            bit_field >>= 8;
        }
    }

    /// Stage a media filter's destination buffer inside `scratch`.
    ///
    /// The returned slice is deliberately **not** zeroed. Every media filter
    /// below writes `dest[channel], dest[channel + channels], ...` for each
    /// channel, which partitions `0..data_size` exactly, so no byte of the
    /// returned slice is read before it is written. `scratch` only ever grows,
    /// so the `resize` zero-fill is paid once per high-water mark rather than
    /// once per filtered block.
    fn media_scratch(scratch: &mut Vec<u8>, data_size: usize) -> &mut [u8] {
        if scratch.len() < data_size {
            scratch.resize(data_size, 0);
        }
        &mut scratch[..data_size]
    }

    /// Publish a media filter's result: swap the staged destination into
    /// `data` and hand the now-stale input buffer back as the scratch.
    fn commit_media_scratch(data: &mut Vec<u8>, scratch: &mut Vec<u8>, data_size: usize) {
        std::mem::swap(data, scratch);
        data.truncate(data_size);
    }

    /// Run one standard filter over the VM's memory.
    ///
    /// `data_size` is the oracle's `DataSize = R[4]`, taken unmasked from
    /// `InitR[4]` (rarvm.cpp:24 copies `InitR` into `R`, then rarvm.cpp:130,
    /// 165, 202, 218 and 262 read `R[4]`). It is **not** the length of `data`:
    /// `data` is the VM memory window, which holds `min(R[4], VM_MEM_SIZE)`
    /// bytes, while `R[4]` itself is a full 32-bit value that a crafted stream
    /// can push past `VM_MEM_SIZE` to make every filter bail out. Each arm
    /// range-checks `data_size` exactly like the oracle before touching
    /// `data`, and every surviving bound is `<= VM_MEM_SIZE`, so the slices
    /// below are always inside the buffer.
    fn execute_standard_filter(
        filter: &Rar4PendingVmFilter,
        data_size: usize,
        written_file_size: u64,
        data: &mut Vec<u8>,
        scratch: &mut Vec<u8>,
    ) -> RarResult<()> {
        debug_assert_eq!(data.len(), data_size.min(VM_MEM_SIZE));
        let file_offset = written_file_size as u32;

        match filter.filter_type {
            Rar4StandardFilter::None => {}
            Rar4StandardFilter::E8 | Rar4StandardFilter::E8E9 => {
                if !(4..=VM_MEM_SIZE).contains(&data_size) {
                    return Ok(());
                }

                if filter.filter_type == Rar4StandardFilter::E8E9 {
                    super::lz::filter::apply_rar4_e8e9(&mut data[..data_size], file_offset);
                } else {
                    super::lz::filter::apply_rar4_e8(&mut data[..data_size], file_offset);
                }
            }
            Rar4StandardFilter::Itanium => {
                if !(21..=VM_MEM_SIZE).contains(&data_size) {
                    return Ok(());
                }

                let masks = [4u8, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
                let mut file_offset = file_offset >> 4;
                let mut cur_pos = 0usize;
                while cur_pos + 21 < data_size {
                    let byte = (data[cur_pos] & 0x1F) as i32 - 0x10;
                    if byte >= 0 {
                        let cmd_mask = masks[byte as usize];
                        if cmd_mask != 0 {
                            // One bounds check for the whole bundle. The loop
                            // condition above proves `cur_pos + 22 <= data_size`.
                            let bundle: &mut [u8; Self::ITANIUM_BUNDLE_WINDOW] = (&mut data
                                [cur_pos..cur_pos + Self::ITANIUM_BUNDLE_WINDOW])
                                .try_into()
                                .expect("itanium bundle window");
                            for slot in 0..=2u32 {
                                if (cmd_mask & (1 << slot)) != 0 {
                                    let start_pos = slot * 41 + 5;
                                    let op_type = Self::itanium_get_bits(bundle, start_pos + 37, 4);
                                    if op_type == 5 {
                                        let offset =
                                            Self::itanium_get_bits(bundle, start_pos + 13, 20);
                                        Self::itanium_set_bits(
                                            bundle,
                                            offset.wrapping_sub(file_offset) & 0x0F_FFFF,
                                            start_pos + 13,
                                            20,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    cur_pos += 16;
                    file_offset = file_offset.wrapping_add(1);
                }
            }
            Rar4StandardFilter::Delta => {
                let channels = filter.init_regs[0];
                if data_size > VM_MEM_SIZE / 2 || channels == 0 || channels > MAX3_UNPACK_CHANNELS {
                    return Ok(());
                }

                let channels = channels as usize;
                let dest = Self::media_scratch(scratch, data_size);

                // Each channel consumes a contiguous run of the source and
                // writes one strided lane of the destination. Splitting the
                // source per channel and zipping the two exact-size iterators
                // keeps the per-byte load and store out of bounds-check
                // territory: neither side can outrun the other.
                let mut src = &data[..data_size];
                for channel in 0..channels {
                    let lane_len = data_size.saturating_sub(channel).div_ceil(channels);
                    let (lane, rest) = src.split_at(lane_len.min(src.len()));
                    src = rest;

                    let mut prev_byte = 0u8;
                    for (out, &cur) in dest.iter_mut().skip(channel).step_by(channels).zip(lane) {
                        prev_byte = prev_byte.wrapping_sub(cur);
                        *out = prev_byte;
                    }
                }

                Self::commit_media_scratch(data, scratch, data_size);
            }
            Rar4StandardFilter::Rgb => {
                let width = filter.init_regs[0].wrapping_sub(3) as usize;
                let pos_r = filter.init_regs[1] as usize;
                if !(3..=VM_MEM_SIZE / 2).contains(&data_size) || width > data_size || pos_r > 2 {
                    return Ok(());
                }

                const CHANNELS: usize = 3;
                let dest = Self::media_scratch(scratch, data_size);
                // Unlike DELTA and AUDIO this filter reads `dest` back, at
                // `index - width` and `index - width - 3`. Both are congruent
                // to `index` modulo 3 exactly when the row stride is a whole
                // number of RGB pixels, and are then earlier entries of the
                // lane currently being written, i.e. already initialized. A
                // stride that is not a multiple of 3 only occurs in malformed
                // streams — the oracle reads whatever its VM memory happens to
                // hold there — so zero the staging buffer in that case to keep
                // rarpar's output deterministic rather than dependent on the
                // previous block's leftovers.
                if !width.is_multiple_of(CHANNELS) {
                    dest.fill(0);
                }

                let mut src = &data[..data_size];
                for channel in 0..CHANNELS {
                    let lane_len = data_size.saturating_sub(channel).div_ceil(CHANNELS);
                    let (lane, rest) = src.split_at(lane_len.min(src.len()));
                    src = rest;

                    let mut prev_byte = 0u8;
                    let mut index = channel;
                    for &cur in lane {
                        let predicted = if index >= width + 3 {
                            let prev = u32::from(prev_byte);
                            let upper = u32::from(dest[index - width]);
                            let upper_left = u32::from(dest[index - width - 3]);
                            let mut predicted = prev.wrapping_add(upper).wrapping_sub(upper_left);
                            let pa = (predicted.wrapping_sub(prev) as i32).abs();
                            let pb = (predicted.wrapping_sub(upper) as i32).abs();
                            let pc = (predicted.wrapping_sub(upper_left) as i32).abs();
                            if pa <= pb && pa <= pc {
                                predicted = prev;
                            } else if pb <= pc {
                                predicted = upper;
                            } else {
                                predicted = upper_left;
                            }
                            predicted
                        } else {
                            u32::from(prev_byte)
                        };

                        let value = (predicted as u8).wrapping_sub(cur);
                        dest[index] = value;
                        prev_byte = value;
                        index += CHANNELS;
                    }
                }

                let border = data_size.saturating_sub(2);
                let mut index = pos_r;
                while index < border {
                    let g = dest[index + 1];
                    dest[index] = dest[index].wrapping_add(g);
                    dest[index + 2] = dest[index + 2].wrapping_add(g);
                    index += CHANNELS;
                }

                Self::commit_media_scratch(data, scratch, data_size);
            }
            Rar4StandardFilter::Audio => {
                let channels = filter.init_regs[0] as usize;
                if data_size > VM_MEM_SIZE / 2 || channels == 0 || channels > 128 {
                    return Ok(());
                }

                let dest = Self::media_scratch(scratch, data_size);
                let mut src_pos = 0usize;
                for channel in 0..channels {
                    let mut prev_byte = 0u32;
                    let mut prev_delta = 0i32;
                    let mut dif = [0i32; 7];
                    let (mut d1, mut d2) = (0i32, 0i32);
                    let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
                    let mut byte_count = 0usize;
                    let mut index = channel;

                    while index < data_size {
                        let d3 = d2;
                        d2 = prev_delta - d1;
                        d1 = prev_delta;

                        let predicted = 8u32
                            .wrapping_mul(prev_byte)
                            .wrapping_add((k1 * d1) as u32)
                            .wrapping_add((k2 * d2) as u32)
                            .wrapping_add((k3 * d3) as u32)
                            >> 3
                            & 0xff;

                        let cur_byte = data[src_pos];
                        src_pos += 1;

                        let decoded_raw = predicted.wrapping_sub(u32::from(cur_byte));
                        let decoded = decoded_raw as u8;
                        dest[index] = decoded;
                        prev_delta = (decoded_raw.wrapping_sub(prev_byte) as u8) as i8 as i32;
                        prev_byte = decoded_raw;

                        let d = (cur_byte as i8 as i32) << 3;
                        dif[0] += d.abs();
                        dif[1] += (d - d1).abs();
                        dif[2] += (d + d1).abs();
                        dif[3] += (d - d2).abs();
                        dif[4] += (d + d2).abs();
                        dif[5] += (d - d3).abs();
                        dif[6] += (d + d3).abs();

                        if (byte_count & 0x1F) == 0 {
                            // A constant-trip indexed loop over the fixed-size
                            // array, not an iterator chain: LLVM unrolls this
                            // and keeps `dif` scalarized in registers across
                            // the whole channel instead of spilling it to a
                            // stack slot for `iter_mut` to walk.
                            let mut min_dif = dif[0];
                            let mut min_index = 0usize;
                            dif[0] = 0;
                            #[allow(clippy::needless_range_loop)]
                            for candidate in 1..dif.len() {
                                if dif[candidate] < min_dif {
                                    min_dif = dif[candidate];
                                    min_index = candidate;
                                }
                                dif[candidate] = 0;
                            }
                            match min_index {
                                1 if k1 >= -16 => k1 -= 1,
                                2 if k1 < 16 => k1 += 1,
                                3 if k2 >= -16 => k2 -= 1,
                                4 if k2 < 16 => k2 += 1,
                                5 if k3 >= -16 => k3 -= 1,
                                6 if k3 < 16 => k3 += 1,
                                _ => {}
                            }
                        }

                        byte_count += 1;
                        index += channels;
                    }
                }

                Self::commit_media_scratch(data, scratch, data_size);
            }
        }

        Ok(())
    }

    fn flush_ready_output_to_writer<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        final_flush: bool,
    ) -> RarResult<()> {
        loop {
            let written_border = self.window.total_flushed();
            let total_written = self.window.total_written();

            if self.pending_vm_filters.is_empty() {
                let total_written = self.window.total_written();
                // Kept from the `flush_to_writer` this replaced: an unflushed
                // span wider than the dictionary means the ring has already
                // overwritten output nobody has read.
                if total_written - written_border > self.window.dict_size() as u64 {
                    return Err(RarError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "window overrun: {} unflushed bytes exceeds dictionary size {}",
                            total_written - written_border,
                            self.window.dict_size()
                        ),
                    )));
                }
                self.write_raw_span(total_written, writer)?;
                return Ok(());
            }

            let next_start = self.pending_vm_filters[0].block_start_total;
            if next_start < written_border {
                // A later same-start filter can remain after a VMSF_NONE program
                // suppresses the block to zero bytes. Once the raw block has
                // been flushed, the later filter is inert.
                self.pending_vm_filters.remove(0);
                continue;
            }

            let raw_len = next_start.saturating_sub(written_border);
            if raw_len > 0 {
                if rar4_debug_filters_enabled() {
                    eprintln!("RAR4 flush prefix: [{written_border}, {next_start}) len={raw_len}");
                }
                self.write_raw_span(next_start, writer)?;
                if self.window.total_flushed() == written_border {
                    // The prefix is not in the window yet; nothing moved, so
                    // looping again would spin.
                    return Ok(());
                }
                continue;
            }

            let block_length = self.pending_vm_filters[0].block_length as u64;
            let block_end =
                next_start
                    .checked_add(block_length)
                    .ok_or_else(|| RarError::CorruptArchive {
                        detail: "RAR4: VM filter block end overflow".into(),
                    })?;
            if block_end > total_written {
                if rar4_debug_filters_enabled() {
                    eprintln!(
                        "RAR4 defer filter: [{next_start}, {block_end}) total={total_written} final={final_flush}"
                    );
                }
                if final_flush {
                    // Leave the write border at the incomplete filter so damaged
                    // streams surface later through size/CRC validation instead
                    // of a filter-specific error.
                    return Ok(());
                }
                return Ok(());
            }

            let filter_block_length = self.pending_vm_filters[0].block_length;
            // `VM_MEM_SIZE` itself is in range: the VM copies the block into
            // its memory unmasked and only the *reported* filtered size is
            // masked, so a `0x40000` block is staged, transformed and then
            // emitted as zero bytes.
            if filter_block_length > VM_MEM_SIZE {
                return Err(RarError::CorruptArchive {
                    detail: format!(
                        "RAR4: VM filter block length {filter_block_length} exceeds maximum {VM_MEM_SIZE}"
                    ),
                });
            }

            // Staged through the decoder's own scratch: a filtered block is
            // copied out of the window, transformed and written without any
            // per-block allocation.
            self.window.copy_output_into(
                next_start,
                filter_block_length,
                &mut self.filter_scratch,
            )?;
            let mut chain_len = 0usize;
            while chain_len < self.pending_vm_filters.len() {
                let filter = &self.pending_vm_filters[chain_len];
                if filter.block_start_total != next_start
                    || filter.block_length != self.filter_scratch.len()
                {
                    break;
                }
                if filter.filter_type == Rar4StandardFilter::None {
                    self.filter_scratch.clear();
                } else {
                    // The VM sizes both the transform and its output from
                    // `InitR[4]`, not from the staged block. `ReadVMCode` seeds
                    // `InitR[4]` with `BlockLength` (unpack30.cpp:462) and then
                    // lets the `FirstByte & 0x10` init-mask loop overwrite any
                    // of `R0..R6` — index 4 included (unpack30.cpp:464-471) —
                    // so a crafted stream decouples the two. `RarVM::Execute`
                    // then runs the filter on `R[4]` bytes and reports
                    // `InitR[4] & VM_MEMMASK` as the filtered size
                    // (rarvm.cpp:24-36). Real RAR encoders only ever set R0/R1,
                    // which is why the two agree on every archive a writer
                    // produces.
                    let vm_data_size = filter.init_regs[4] as usize;
                    // `VM.SetMemory` copied `BlockLength` bytes to offset 0 and
                    // left the rest of the VM's `Mem` buffer alone
                    // (rarvm.cpp:107-117), so an `R[4]` beyond the staged block
                    // reads VM memory the oracle never initialized. rarpar
                    // defines those bytes as zero to stay deterministic.
                    self.filter_scratch.resize(vm_data_size.min(VM_MEM_SIZE), 0);
                    Self::execute_standard_filter(
                        filter,
                        vm_data_size,
                        self.current_file_written_size,
                        &mut self.filter_scratch,
                        &mut self.media_scratch,
                    )?;
                    // Only the emitted span is masked; the next filter in the
                    // chain is matched against this masked size, exactly as the
                    // oracle matches `NextFilter->BlockLength` against
                    // `FilteredDataSize` (unpack30.cpp:578-580).
                    self.filter_scratch.truncate(vm_data_size & VM_MEM_MASK);
                }
                chain_len += 1;
            }

            if rar4_debug_filters_enabled() {
                eprintln!("RAR4 flush filter: [{next_start}, {block_end}) chain_len={chain_len}");
            }
            // No clamp: the oracle hands `FilteredDataSize` straight to
            // `UnpWrite` and adds all of it to `WrittenFileSize`
            // (unpack30.cpp:597-599), so a filtered block is emitted in full
            // even when it carries the member past its declared size.
            writer
                .write_all(&self.filter_scratch)
                .map_err(RarError::Io)?;
            self.current_file_emitted = self
                .current_file_emitted
                .saturating_add(self.filter_scratch.len() as u64);
            self.current_file_written_size = self
                .current_file_written_size
                .saturating_add(self.filter_scratch.len() as u64);
            self.window.mark_flushed(block_end);
            self.pending_vm_filters.drain(..chain_len);
        }
    }

    /// Decompress RAR4 LZ data, returning the decompressed output.
    pub fn decompress(&mut self, input: &[u8], unpacked_size: u64) -> RarResult<Vec<u8>> {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        let mut reader = BitReader::new(input);
        self.decompress_with_reader(&mut reader, unpacked_size)
    }

    fn decompress_with_reader<R: BitRead>(
        &mut self,
        reader: &mut R,
        unpacked_size: u64,
    ) -> RarResult<Vec<u8>> {
        let mut output = Vec::with_capacity(unpacked_size.min(1024 * 1024) as usize);
        self.decompress_to_writer_with_reader(reader, unpacked_size, &mut output)?;
        Ok(output)
    }

    /// Decode a RAR4 solid member only to advance decoder state.
    pub fn replay(&mut self, input: &[u8], unpacked_size: u64) -> RarResult<u64> {
        if unpacked_size == 0 {
            return Ok(0);
        }

        let mut reader = BitReader::new(input);

        self.replay_with_reader(&mut reader, unpacked_size)
    }

    fn replay_with_reader<R: BitRead>(
        &mut self,
        reader: &mut R,
        unpacked_size: u64,
    ) -> RarResult<u64> {
        let mut sink = std::io::sink();
        self.decompress_to_writer_with_reader(reader, unpacked_size, &mut sink)
    }

    /// Decompress RAR4 LZ data directly to a writer.
    pub fn decompress_to_writer<W: Write>(
        &mut self,
        input: &[u8],
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        if unpacked_size == 0 {
            return Ok(0);
        }

        let mut reader = BitReader::new(input);

        self.decompress_to_writer_with_reader(&mut reader, unpacked_size, writer)
    }

    pub fn decompress_reader_to_writer<Rd: std::io::Read, W: Write>(
        &mut self,
        input: Rd,
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        if unpacked_size == 0 {
            return Ok(0);
        }

        // Each solid member's data area is an independent byte-aligned
        // bitstream: reset the bit input for every file (solid or not) and
        // discard any leftover from the previous area.
        // Only decoder state (window, tables, block type, PPM model and its
        // range coder registers) persists.
        //
        // The reader is new per member but its 512 KiB buffer is recycled: it
        // is taken here and handed back on every exit path, error included.
        let buf = self.take_input_buffer();
        let mut reader = StreamingBitReader::with_buffer(input, buf);
        let result = self.decompress_to_writer_with_reader(&mut reader, unpacked_size, writer);
        self.recycle_input_buffer(reader.into_buffer());
        result
    }

    fn decompress_to_writer_with_reader<R: BitRead, W: Write>(
        &mut self,
        reader: &mut R,
        unpacked_size: u64,
        writer: &mut W,
    ) -> RarResult<u64> {
        if unpacked_size == 0 {
            return Ok(0);
        }

        if !self.tables_read {
            self.read_tables(reader)?;
        }

        self.begin_file_decode(unpacked_size);
        let mut output_size: u64 = 0;
        let flush_threshold = self.flush_threshold();
        // Decided once per member, as the RAR5 controller decides its own
        // admission once per member. Only this entry point can take the split:
        // the chunked variants place their volume boundaries at
        // `reader.byte_position()` observed between decode rounds, and a decode
        // thread that runs ahead of the window would move those observations.
        // Here output is a single ordered stream, so nothing observes decode's
        // lead but the window itself — and the window is on this thread.
        let threaded = rar4_mt_admitted(unpacked_size);

        'member: loop {
            while output_size < self.decode_limit() {
                if reader.bits_remaining() < 1 {
                    break;
                }

                match self.block_type {
                    // PPMd members stay serial. A mixed solid archive flips
                    // `block_type` at symbol 256, which ends the lease and hands the
                    // fully materialized window back before the PPMd round starts,
                    // so the transition is the same one the serial path makes.
                    BlockType::Lz if threaded => {
                        let mut driver = Rar4ThreadedLease {
                            writer: &mut *writer,
                            flush_threshold,
                        };
                        let limit = self.decode_limit();
                        output_size = self.decode_lz_symbols_with(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                            &mut driver,
                        )?;
                    }
                    BlockType::Lz => {
                        let limit = self.decode_limit();
                        output_size = self.decode_lz_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                        )?;
                    }
                    BlockType::Ppm => {
                        let limit = self.decode_limit();
                        output_size = self.decode_ppm_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                            writer,
                        )?;
                    }
                }

                if self.window.unflushed_bytes() as usize >= flush_threshold {
                    self.flush_ready_output_to_writer(writer, false)?;
                }

                if self.member_decode_done || self.size_stop_reached() {
                    break;
                }
            }

            if self.member_decode_done || output_size < unpacked_size {
                break 'member;
            }
            if !self.consume_solid_end_marker(reader)? {
                break 'member;
            }
        }
        self.flush_ready_output_to_writer(writer, true)?;
        Ok(self.current_file_emitted)
    }

    /// The oracle's post-flush size stop: `WrittenFileSize > DestUnpSize`
    /// ends the member's decode (unpack30.cpp:64-65).
    ///
    /// It is *strictly* greater, so a member whose output lands exactly on the
    /// declared size keeps decoding and reaches its end-of-file marker, which
    /// is what leaves `tables_read` right for the next solid member.
    fn size_stop_reached(&self) -> bool {
        self.current_file_written_size > self.current_file_unpacked_size
    }

    /// Chunked variant: decompress with output split at compressed byte boundaries.
    ///
    /// Same as `decompress_to_writer` but switches output writers when the
    /// compressed byte position crosses volume boundaries.
    pub fn decompress_to_writer_chunked<F, W>(
        &mut self,
        input: &[u8],
        unpacked_size: u64,
        first_volume_index: usize,
        boundaries: &[super::VolumeTransition],
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        W: Write,
        F: FnMut(usize) -> RarResult<W>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        let mut reader = BitReader::new(input);

        self.decompress_to_writer_chunked_with_reader(
            &mut reader,
            unpacked_size,
            first_volume_index,
            boundaries,
            writer_factory,
        )
    }

    pub fn decompress_reader_to_writer_chunked<Rd: std::io::Read, F, W>(
        &mut self,
        input: Rd,
        unpacked_size: u64,
        first_volume_index: usize,
        shared_transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        W: Write,
        F: FnMut(usize) -> RarResult<W>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        // Recycled input buffer, handed back on every exit path (see
        // `decompress_reader_to_writer`).
        let buf = self.take_input_buffer();
        let mut reader = StreamingBitReader::with_buffer(input, buf);
        let result = self.decompress_to_writer_chunked_with_shared_transitions(
            &mut reader,
            unpacked_size,
            first_volume_index,
            shared_transitions,
            writer_factory,
        );
        self.recycle_input_buffer(reader.into_buffer());
        result
    }

    fn decompress_to_writer_chunked_with_reader<R: BitRead, F, W>(
        &mut self,
        reader: &mut R,
        unpacked_size: u64,
        first_volume_index: usize,
        boundaries: &[super::VolumeTransition],
        mut writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        W: Write,
        F: FnMut(usize) -> RarResult<W>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        if !self.tables_read {
            self.read_tables(reader)?;
        }

        self.begin_file_decode(unpacked_size);
        let mut output_size: u64 = 0;
        let flush_threshold = self.flush_threshold();
        let mut boundary_idx = 0;

        let mut chunks: Vec<(usize, u64)> = Vec::new();
        let mut current_vol = first_volume_index;
        let mut current_writer = writer_factory(current_vol)?;
        let mut chunk_bytes: u64 = 0;
        let mut pending_boundary_volume = None;

        'member: loop {
            while output_size < self.decode_limit() {
                if reader.bits_remaining() < 1 {
                    break;
                }

                let prev_emitted = self.current_file_emitted;
                match self.block_type {
                    BlockType::Lz => {
                        let limit = self.decode_limit();
                        output_size = self.decode_lz_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                        )?;
                    }
                    BlockType::Ppm => {
                        let limit = self.decode_limit();
                        output_size = self.decode_ppm_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                            &mut current_writer,
                        )?;
                    }
                }

                let byte_pos = reader.byte_position() as u64;
                if pending_boundary_volume.is_none()
                    && boundary_idx < boundaries.len()
                    && byte_pos >= boundaries[boundary_idx].compressed_offset
                {
                    pending_boundary_volume = Some(boundaries[boundary_idx].volume_index);
                    boundary_idx += 1;
                }

                if pending_boundary_volume.is_some()
                    || self.window.unflushed_bytes() as usize >= flush_threshold
                {
                    self.flush_ready_output_to_writer(&mut current_writer, false)?;
                    if self.window.unflushed_bytes() as usize > self.window.dict_size() {
                        return Err(RarError::CorruptArchive {
                            detail:
                                "RAR4 pending VM filters exceeded dictionary window before flush"
                                    .into(),
                        });
                    }
                }
                chunk_bytes += self.current_file_emitted - prev_emitted;

                // VM filters can span a compressed-volume boundary, so only hand
                // output to the next writer after the current chunk is fully
                // materialized through the filter queue.
                if let Some(next_vol) = pending_boundary_volume
                    && self.window.total_flushed() == self.window.total_written()
                {
                    chunks.push((current_vol, chunk_bytes));
                    current_vol = next_vol;
                    current_writer = writer_factory(current_vol)?;
                    chunk_bytes = 0;
                    pending_boundary_volume = None;
                }

                if self.member_decode_done || self.size_stop_reached() {
                    break;
                }
            }

            if self.member_decode_done
                || output_size < unpacked_size
                || !self.consume_solid_end_marker(reader)?
            {
                break 'member;
            }
        }
        let prev_emitted = self.current_file_emitted;
        self.flush_ready_output_to_writer(&mut current_writer, true)?;
        chunk_bytes += self.current_file_emitted - prev_emitted;
        if chunk_bytes > 0 || chunks.is_empty() {
            chunks.push((current_vol, chunk_bytes));
        }

        Ok(chunks)
    }

    fn decompress_to_writer_chunked_with_shared_transitions<R: BitRead, F, W>(
        &mut self,
        reader: &mut R,
        unpacked_size: u64,
        first_volume_index: usize,
        shared_transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
        mut writer_factory: F,
    ) -> RarResult<Vec<(usize, u64)>>
    where
        W: Write,
        F: FnMut(usize) -> RarResult<W>,
    {
        if unpacked_size == 0 {
            return Ok(Vec::new());
        }

        if !self.tables_read {
            self.read_tables(reader)?;
        }

        self.begin_file_decode(unpacked_size);
        let mut output_size: u64 = 0;
        let flush_threshold = self.flush_threshold();
        let mut boundary_idx = 0;

        let mut chunks: Vec<(usize, u64)> = Vec::new();
        let mut current_vol = first_volume_index;
        let mut current_writer = writer_factory(current_vol)?;
        let mut chunk_bytes: u64 = 0;
        let mut pending_boundary_volume = None;

        'member: loop {
            while output_size < self.decode_limit() {
                if reader.bits_remaining() < 1 {
                    break;
                }

                let prev_emitted = self.current_file_emitted;
                match self.block_type {
                    BlockType::Lz => {
                        let limit = self.decode_limit();
                        output_size = self.decode_lz_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                        )?;
                    }
                    BlockType::Ppm => {
                        let limit = self.decode_limit();
                        output_size = self.decode_ppm_symbols(
                            reader,
                            limit,
                            output_size,
                            Some(flush_threshold),
                            &mut current_writer,
                        )?;
                    }
                }

                let byte_pos = reader.byte_position() as u64;
                let next_boundary = {
                    let guard =
                        shared_transitions
                            .lock()
                            .map_err(|_| RarError::CorruptArchive {
                                detail: "RAR4 volume transition state is poisoned".into(),
                            })?;
                    guard.get(boundary_idx).cloned()
                };

                if pending_boundary_volume.is_none()
                    && let Some(boundary) = next_boundary
                    && byte_pos >= boundary.compressed_offset
                {
                    pending_boundary_volume = Some(boundary.volume_index);
                    boundary_idx += 1;
                }

                if pending_boundary_volume.is_some()
                    || self.window.unflushed_bytes() as usize >= flush_threshold
                {
                    self.flush_ready_output_to_writer(&mut current_writer, false)?;
                    if self.window.unflushed_bytes() as usize > self.window.dict_size() {
                        return Err(RarError::CorruptArchive {
                            detail:
                                "RAR4 pending VM filters exceeded dictionary window before flush"
                                    .into(),
                        });
                    }
                }
                chunk_bytes += self.current_file_emitted - prev_emitted;

                if let Some(next_vol) = pending_boundary_volume
                    && self.window.total_flushed() == self.window.total_written()
                {
                    chunks.push((current_vol, chunk_bytes));
                    current_vol = next_vol;
                    current_writer = writer_factory(current_vol)?;
                    chunk_bytes = 0;
                    pending_boundary_volume = None;
                }

                if self.member_decode_done || self.size_stop_reached() {
                    break;
                }
            }

            if self.member_decode_done
                || output_size < unpacked_size
                || !self.consume_solid_end_marker(reader)?
            {
                break 'member;
            }
        }
        let prev_emitted = self.current_file_emitted;
        self.flush_ready_output_to_writer(&mut current_writer, true)?;
        chunk_bytes += self.current_file_emitted - prev_emitted;
        if chunk_bytes > 0 || chunks.is_empty() {
            chunks.push((current_vol, chunk_bytes));
        }

        Ok(chunks)
    }

    /// Read Huffman tables from the bitstream (ReadTables30 equivalent).
    ///
    /// Byte-aligns first, then reads:
    /// 1. Block type flag (PPM or LZ)
    /// 2. Table inheritance flag
    /// 3. BC code lengths (20 x 4-bit, with 15+zero_count special case)
    /// 4. Main code lengths using BC table (delta encoded)
    /// 5. Builds LD, DD, LDD, RD tables
    fn read_tables<R: BitRead>(&mut self, reader: &mut R) -> RarResult<()> {
        let build_table = |name: &str,
                           lengths: &[u8],
                           total_written: u64|
         -> RarResult<HuffmanTable> {
            HuffmanTable::build(lengths).map_err(|err| {
                if rar4_debug_filters_enabled() {
                    eprintln!(
                        "RAR4 invalid {name} table at total_written={total_written}: lengths={lengths:?}"
                    );
                }
                RarError::CorruptArchive {
                    detail: format!("RAR4: invalid {name} table: {err}"),
                }
            })
        };

        // Align to byte boundary.
        reader.align_byte()?;
        if rar4_debug_filters_enabled() {
            let total_written = self.window.total_written();
            if (39_000_000..=41_000_000).contains(&total_written) {
                let bitfield = reader.peek_16_left_aligned()?;
                eprintln!(
                    "RAR4 read_tables header total_written={total_written} bitfield={bitfield:#06x} bit_pos={}",
                    reader.position()
                );
            }
        }

        if reader.bits_remaining() < 2 {
            return Err(RarError::CorruptArchive {
                detail: "RAR4: not enough data for table header".into(),
            });
        }

        // Bit 0: PPM flag (1=PPM block, 0=LZ block).
        let ppm_flag = reader.read_bits(1)?;
        if ppm_flag != 0 {
            self.block_type = BlockType::Ppm;
            return self.init_ppm(reader);
        }

        self.block_type = BlockType::Lz;

        // Bit 1: inherit previous tables (1=keep, 0=reset).
        let inherit = reader.read_bits(1)?;
        if inherit == 0 {
            self.code_lengths.fill(0);
        }

        // Reset low distance state on new tables.
        self.prev_low_dist = 0;
        self.low_dist_rep_count = 0;

        // Read BC table: 20 x 4-bit lengths.
        let mut bc_lengths = [0u8; BC];
        let mut i = 0;
        while i < BC {
            if reader.bits_remaining() < 4 {
                return Err(RarError::CorruptArchive {
                    detail: "RAR4: truncated BC table".into(),
                });
            }
            let length = reader.read_bits(4)? as u8;
            if length == 15 {
                let zero_count = reader.read_bits(4)? as usize;
                if zero_count == 0 {
                    // Literal 15.
                    bc_lengths[i] = 15;
                } else {
                    // Zero fill: zero_count + 2 entries.
                    let fill = zero_count + 2;
                    for _ in 0..fill {
                        if i < BC {
                            bc_lengths[i] = 0;
                            i += 1;
                        }
                    }
                    continue; // i already advanced
                }
            } else {
                bc_lengths[i] = length;
            }
            i += 1;
        }
        let bc_table = build_table("BC", &bc_lengths, self.window.total_written())?;
        if rar4_debug_filters_enabled() {
            let total_written = self.window.total_written();
            if (39_000_000..=41_000_000).contains(&total_written) {
                eprintln!("RAR4 read_tables total_written={total_written} BC={bc_lengths:?}");
            }
        }

        // Read main code lengths using BC table (delta encoded).
        let mut i = 0;
        while i < HUFF_TABLE_SIZE {
            if reader.bits_remaining() < 1 {
                // Fail the whole table read when input runs out mid-table;
                // building from a partial array would leak stale lengths from
                // the previous block's tables (same hardening as the RAR5
                // reader in huffman.rs).
                return Err(RarError::CorruptArchive {
                    detail: format!(
                        "RAR4: truncated main code length table: {i} of {HUFF_TABLE_SIZE} lengths"
                    ),
                });
            }
            let number = bc_table
                .decode(reader)
                .map_err(|err| RarError::CorruptArchive {
                    detail: format!(
                        "RAR4: BC decode failed at total_written={}: {err}",
                        self.window.total_written()
                    ),
                })? as usize;
            if number < 16 {
                // Delta: add to previous value mod 16.
                self.code_lengths[i] = ((self.code_lengths[i] as usize + number) & 0xF) as u8;
                i += 1;
            } else if number < 18 {
                // Repeat previous value.
                let count = if number == 16 {
                    reader.read_bits(3)? as usize + 3
                } else {
                    reader.read_bits(7)? as usize + 11
                };
                if i == 0 {
                    return Err(RarError::CorruptArchive {
                        detail: "RAR4: repeat-previous at position 0".into(),
                    });
                }
                let prev = self.code_lengths[i - 1];
                for _ in 0..count {
                    if i >= HUFF_TABLE_SIZE {
                        break;
                    }
                    self.code_lengths[i] = prev;
                    i += 1;
                }
            } else {
                // Zero fill.
                let count = if number == 18 {
                    reader.read_bits(3)? as usize + 3
                } else {
                    reader.read_bits(7)? as usize + 11
                };
                for _ in 0..count {
                    if i >= HUFF_TABLE_SIZE {
                        break;
                    }
                    self.code_lengths[i] = 0;
                    i += 1;
                }
            }
        }

        // Build the four main tables.
        let total_written = self.window.total_written();
        let mut offset = 0;
        self.ld_table = Some(build_table(
            "LD",
            &self.code_lengths[offset..offset + NC],
            total_written,
        )?);
        offset += NC;
        self.dd_table = Some(build_table(
            "DD",
            &self.code_lengths[offset..offset + DC],
            total_written,
        )?);
        offset += DC;
        self.ldd_table = Some(build_table(
            "LDD",
            &self.code_lengths[offset..offset + LDC],
            total_written,
        )?);
        offset += LDC;
        self.rd_table = Some(build_table(
            "RD",
            &self.code_lengths[offset..offset + RC],
            total_written,
        )?);

        self.tables_read = true;
        Ok(())
    }

    /// Consume the code that follows a member's last output symbol.
    ///
    /// The oracle's size check is strictly `WrittenFileSize > DestUnpSize`
    /// (unpack30.cpp:64), so after the final output symbol it still decodes the
    /// next code. Two things live there:
    ///
    /// * code 256, whose new-file/new-table flags decide whether the next
    ///   member re-reads Huffman tables. Skipping it leaves `tables_read` stale
    ///   and desyncs every later solid member.
    /// * code 257, a VM filter packet. A block queued here covers data past the
    ///   declared size, and the oracle still applies it, so the caller has to
    ///   resume decoding far enough to complete the block.
    ///
    /// Returns whether that block moved the decode bound, i.e. whether the
    /// caller should re-enter its decode loop. A failed decode is not an error:
    /// at the true end of the stream there may be no code here at all.
    fn consume_solid_end_marker<R: BitRead>(&mut self, reader: &mut R) -> RarResult<bool> {
        if !matches!(self.block_type, BlockType::Lz) || !self.tables_read {
            return Ok(false);
        }
        let number = {
            let Some(ld) = self.ld_table.as_ref() else {
                return Ok(false);
            };
            match ld.decode(reader) {
                Ok(number) => number as usize,
                Err(_) => return Ok(false),
            }
        };
        if number == 256 {
            self.read_end_of_block(reader)?;
            return Ok(false);
        }
        if number == 257 {
            let before = self.decode_limit();
            if !self.read_vm_code(
                reader,
                self.window.total_written() - self.current_file_base_total,
            )? {
                self.member_decode_done = true;
                return Ok(false);
            }
            return Ok(self.decode_limit() > before);
        }
        Ok(false)
    }

    /// Decode symbols out of one leased input span, if the reader can lend one.
    ///
    /// Borrows the tables and the window as disjoint fields, copies the small
    /// mutable state into locals, and writes everything back before returning
    /// — including on the error path, so a failed match leaves the decoder
    /// exactly where the per-symbol path would have left it.
    fn lease_fast_symbols<R: BitRead>(
        &mut self,
        reader: &mut R,
        decode_limit: u64,
        output_size: &mut u64,
        yield_threshold: Option<usize>,
    ) -> RarResult<Option<Rar4FastExit>> {
        // A missing table is an error the per-symbol path already reports with
        // the table's name; do not duplicate that here. This guard and the
        // reader's own span test are all the per-symbol fallback pays.
        if self.ld_table.is_none()
            || self.dd_table.is_none()
            || self.ldd_table.is_none()
            || self.rd_table.is_none()
        {
            return Ok(None);
        }

        // Everything below runs only once a span has actually been lent, so
        // declining a lease costs nothing beyond the guard above.
        let leased = reader.lease_lz_span(|span| {
            let mut state = Rar4FastState {
                dist_cache: self.dist_cache,
                last_length: self.last_length,
                low_dist_rep_count: self.low_dist_rep_count,
                prev_low_dist: self.prev_low_dist,
            };
            let pending_head = self
                .pending_vm_filters
                .first()
                .map(|filter| (filter.block_start_total, filter.block_length));

            let outcome = {
                let tables = Rar4FastTables {
                    ld: self.ld_table.as_ref().expect("LD table checked above"),
                    dd: self.dd_table.as_ref().expect("DD table checked above"),
                    ldd: self.ldd_table.as_ref().expect("LDD table checked above"),
                    rd: self.rd_table.as_ref().expect("RD table checked above"),
                    ddecode: &self.ddecode,
                    dbits: &self.dbits,
                };
                let mut sink = Rar4WindowSink {
                    window: &mut self.window,
                    yield_threshold,
                    pending_head,
                };
                run_fast_symbols(
                    span,
                    &tables,
                    &mut state,
                    &mut sink,
                    decode_limit,
                    output_size,
                )
            };

            self.dist_cache = state.dist_cache;
            self.last_length = state.last_length;
            self.low_dist_rep_count = state.low_dist_rep_count;
            self.prev_low_dist = state.prev_low_dist;
            outcome
        })?;

        match leased {
            None => Ok(None),
            Some(exit) => exit.map(Some),
        }
    }

    /// Materialize one batch of decoded records into the window, in order.
    ///
    /// This is the RAR4 twin of [`LzDecoder::apply_decoded_items_parallel`]
    /// (lz/parallel.rs:2539): the same per-item shape, the same "check the
    /// flush border once per item" cadence, and the same rule that nothing
    /// about the window may be decided anywhere else. It runs only on the
    /// thread that owns the decoder, so solid and multivolume window continuity
    /// is not merely serialized — it never leaves its owner.
    ///
    /// The one difference from the RAR5 apply loop is what is *not* here: no
    /// distance cache is touched, because RAR4's single decode thread already
    /// resolved every distance.
    ///
    /// [`LzDecoder::apply_decoded_items_parallel`]: super::lz::LzDecoder
    fn apply_lz_items<W: Write + ?Sized>(
        &mut self,
        items: &[Rar4Item],
        output_size: &mut u64,
        flush_threshold: usize,
        writer: &mut W,
    ) -> RarResult<()> {
        for item in items {
            if item.literals != 0 {
                let n = item.literals as usize;
                self.window
                    .put_literal_batch(&item.payload.to_le_bytes(), n);
                *output_size += n as u64;
            } else {
                let length = item.length as usize;
                self.window.copy(item.payload as usize, length)?;
                *output_size += length as u64;
            }

            // The serial loop's `Rar4FastExit::Yield`, resolved in place. The
            // serial path breaks out so its caller can flush; here the flush is
            // already on this thread, so the same test drives it directly. The
            // pin test is the same one the serial path consults, for the same
            // reason: while the pending-filter head holds the write border, a
            // flush would move nothing.
            if self.window.unflushed_bytes() as usize >= flush_threshold
                && !self.flush_is_pinned_by_pending_head()
            {
                self.flush_ready_output_to_writer(writer, false)?;
            }
        }

        Ok(())
    }

    /// Decode one leased span on a worker thread while applying its records
    /// here, in stream order.
    ///
    /// The decode thread sees only a byte slice, the Huffman tables and
    /// `Rar4FastState`; the window, the pending-filter queue, the flush and the
    /// writer never leave this thread. That is what keeps the split free of new
    /// invariants: everything the serial path does to the window still happens
    /// on the decoder's own thread, in the same order, under the same tests.
    ///
    /// The tables are moved out of `self` for the duration of the lease rather
    /// than borrowed, so the apply half keeps a whole `&mut self` — which is
    /// what lets it call [`Self::flush_ready_output_to_writer`] between items
    /// instead of unwinding to a caller. They are put back on every exit path.
    fn lease_fast_symbols_mt<R: BitRead, W: Write + ?Sized>(
        &mut self,
        reader: &mut R,
        decode_limit: u64,
        output_size: &mut u64,
        flush_threshold: usize,
        writer: &mut W,
    ) -> RarResult<Option<Rar4FastExit>> {
        // Same guard, same reason, as the serial lease.
        if self.ld_table.is_none()
            || self.dd_table.is_none()
            || self.ldd_table.is_none()
            || self.rd_table.is_none()
        {
            return Ok(None);
        }

        let ld = self.ld_table.take().expect("LD table checked above");
        let dd = self.dd_table.take().expect("DD table checked above");
        let ldd = self.ldd_table.take().expect("LDD table checked above");
        let rd = self.rd_table.take().expect("RD table checked above");
        let ddecode = self.ddecode;
        let dbits = self.dbits;
        let mut state = Rar4FastState {
            dist_cache: self.dist_cache,
            last_length: self.last_length,
            low_dist_rep_count: self.low_dist_rep_count,
            prev_low_dist: self.prev_low_dist,
        };
        let mut spare = std::mem::take(&mut self.mt_spare_batches);

        let leased = reader.lease_lz_span(|span| {
            #[cfg(test)]
            mt_test_hooks::note_mt_lease();
            // Copied out of the borrowed span so the decode thread owns a plain
            // value; every field is already a `Copy` view of the reader's
            // buffer, which stays put for the whole lease.
            let span = LzSpan {
                data: span.data,
                start_bit: span.start_bit,
                border_bit: span.border_bit,
            };
            let tables = Rar4FastTables {
                ld: &ld,
                dd: &dd,
                ldd: &ldd,
                rd: &rd,
                ddecode: &ddecode,
                dbits: &dbits,
            };
            let start_out = *output_size;
            let mut applied_out = *output_size;
            let mut apply_result: RarResult<()> = Ok(());

            let scoped = std::thread::scope(|scope| {
                // Capacity one: the decode thread may be at most one batch
                // ahead of the apply thread before `send` parks it. This, and
                // nothing else, is what bounds this path's memory.
                let (item_tx, item_rx) = std::sync::mpsc::sync_channel::<Vec<Rar4Item>>(1);
                // Hand-backs are `try_send`, so this only sizes how many
                // buffers survive to the next lease.
                let (spare_tx, spare_rx) =
                    std::sync::mpsc::sync_channel::<Vec<Rar4Item>>(RAR4_MT_SPARE_SLOTS);
                // The carried set must never outgrow the channel. When it did,
                // and priming still used a blocking `send`, this loop parked
                // with no receiver running and hung the extraction. Both halves
                // of that are now impossible: the set is truncated where it is
                // built, and priming cannot block.
                #[cfg(test)]
                assert!(
                    spare.len() <= RAR4_MT_SPARE_SLOTS,
                    "carried {} recycled batches, more than the {RAR4_MT_SPARE_SLOTS} slots",
                    spare.len()
                );
                for buf in spare.drain(..) {
                    let _ = spare_tx.try_send(buf);
                }
                // Buffers the apply side could not hand back, kept here so the
                // next lease still gets them.
                let mut kept: Vec<Vec<Rar4Item>> = Vec::new();

                let span = &span;
                let tables = &tables;
                let mut decode_state = state;
                let decoder = scope.spawn(move || {
                    let mut sink = Rar4RecordSink::new(item_tx, spare_rx);
                    let mut out = start_out;
                    let outcome = run_fast_symbols(
                        span,
                        tables,
                        &mut decode_state,
                        &mut sink,
                        decode_limit,
                        &mut out,
                    );
                    // Drops the item sender, which is what ends the apply loop
                    // below, then reclaims the buffers already handed back.
                    let recovered = sink.finish();
                    ((outcome, decode_state, out), recovered)
                });

                while let Ok(batch) = item_rx.recv() {
                    if apply_result.is_ok() {
                        apply_result =
                            self.apply_lz_items(&batch, &mut applied_out, flush_threshold, writer);
                    }
                    // On failure the loop keeps draining rather than dropping
                    // the receiver: the decode thread runs the rest of the span
                    // out and exits, so the scope can join. Nothing here can
                    // wait on a thread that is itself waiting on this channel.
                    //
                    // `try_send`, never `send`: a blocking hand-back could park
                    // this thread while the decode thread waits for it to take
                    // the next batch. A buffer that does not fit is carried in
                    // `kept` instead of being dropped.
                    match spare_tx.try_send(batch) {
                        Ok(()) => {}
                        Err(std::sync::mpsc::TrySendError::Full(buf))
                        | Err(std::sync::mpsc::TrySendError::Disconnected(buf)) => kept.push(buf),
                    }
                }
                drop(spare_tx);

                let (decoded, recovered) = decoder
                    .join()
                    .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
                (decoded, recovered, kept)
            });

            let (decoded, recovered, kept) = scoped;
            // Underscored: only the `cfg(test)` cross-check below reads it.
            let ((end_bit, exit), final_state, _decoded_out) = decoded;
            state = final_state;
            spare = recovered;
            spare.extend(kept);
            spare.truncate(RAR4_MT_SPARE_SLOTS);

            // Both halves count output with identical arithmetic over an
            // identical record sequence, so a mismatch is a decode/apply drift
            // bug and nothing else. `cfg(test)` rather than `debug_assert!`
            // because the suite runs in release, where a debug assertion would
            // compile away and check nothing.
            #[cfg(test)]
            assert!(
                apply_result.is_err() || applied_out == _decoded_out,
                "RAR4 MT: applied {applied_out} bytes, decoded {_decoded_out}"
            );
            *output_size = applied_out;

            // The apply side's failure wins: it is the one the serial path
            // would have reported, at the same output offset. The decode side
            // cannot fail at all here — its sink is infallible — but the result
            // is threaded through rather than discarded so that stays true by
            // construction rather than by comment.
            let outcome = match apply_result {
                Err(err) => Err(err),
                Ok(()) => exit,
            };
            (end_bit, outcome)
        });

        self.ld_table = Some(ld);
        self.dd_table = Some(dd);
        self.ldd_table = Some(ldd);
        self.rd_table = Some(rd);
        self.dist_cache = state.dist_cache;
        self.last_length = state.last_length;
        self.low_dist_rep_count = state.low_dist_rep_count;
        self.prev_low_dist = state.prev_low_dist;
        self.mt_spare_batches = spare;

        match leased? {
            None => Ok(None),
            Some(exit) => exit.map(Some),
        }
    }

    /// Run the arm for a symbol that needs the reader itself: 256 or 257.
    ///
    /// Shared by the per-symbol path and the leased-span path so the two
    /// cannot drift. Returns `false` when the member's decode ends here.
    fn handle_cold_symbol<R: BitRead>(
        &mut self,
        reader: &mut R,
        number: usize,
        output_size: u64,
    ) -> RarResult<bool> {
        if number == 256 {
            // End of block.
            if rar4_debug_filters_enabled() {
                eprintln!(
                    "RAR4 end_of_block: output_size={output_size} bits_remaining={}",
                    reader.bits_remaining()
                );
            }
            let continue_decompressing = self.read_end_of_block(reader)?;
            if !continue_decompressing {
                // "New file" ends this member's decode; re-entering would
                // decode LZ symbols against the next member's stream.
                self.member_decode_done = true;
                return Ok(false);
            }
            return Ok(self.block_type == BlockType::Lz);
        }

        debug_assert_eq!(number, 257);
        if !self.read_vm_code(reader, output_size)? {
            // Truncated VM code packet: unpack30.cpp:210-215 breaks out
            // of the main loop and returns the partial output.
            self.member_decode_done = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn decode_lz_symbols<R: BitRead>(
        &mut self,
        reader: &mut R,
        decode_limit: u64,
        output_size: u64,
        yield_threshold: Option<usize>,
    ) -> RarResult<u64> {
        self.decode_lz_symbols_with(
            reader,
            decode_limit,
            output_size,
            yield_threshold,
            &mut Rar4SerialLease,
        )
    }

    /// `output_size` is the oracle's `UnpPtr` measured from the file start, so
    /// it counts every byte the match copies into the dictionary. What of it
    /// reaches the caller is the write layer's decision, not this loop's.
    fn decode_lz_symbols_with<R: BitRead, L: Rar4LeaseDriver>(
        &mut self,
        reader: &mut R,
        decode_limit: u64,
        mut output_size: u64,
        yield_threshold: Option<usize>,
        driver: &mut L,
    ) -> RarResult<u64> {
        #[cfg(test)]
        {
            self.decode_lz_calls += 1;
        }
        'stream: while output_size < decode_limit {
            // Fast path: decode as many symbols as the reader can lend input
            // for. The per-symbol path below runs only for the last
            // `LZ_SPAN_SLACK_BYTES` of each buffer fill and for readers that
            // cannot lend a span at all.
            while let Some(exit) = driver.lease(
                self,
                reader,
                decode_limit,
                &mut output_size,
                yield_threshold,
            )? {
                match exit {
                    // A fresh lease starts past the border and declines, which
                    // is what drops through to the per-symbol path.
                    Rar4FastExit::Border => continue,
                    Rar4FastExit::Complete | Rar4FastExit::Yield => break 'stream,
                    Rar4FastExit::Cold(number) => {
                        if !self.handle_cold_symbol(reader, number, output_size)? {
                            break 'stream;
                        }
                    }
                }
            }

            if !reader.has_bits() {
                break;
            }

            let number = self
                .ld_table
                .as_ref()
                .ok_or_else(|| missing_table("LD"))?
                .decode(reader)
                .map_err(|err| decode_failed_at("LD", output_size, &err))?
                as usize;
            let mut should_check_yield = false;

            if number < 256 {
                // Literal byte (most common — first).
                self.window.put_byte(number as u8);
                output_size += 1;
                should_check_yield = true;
            } else if number >= 271 {
                // Regular match: decode length then distance.
                let length_idx = number - 271;
                // The LD table is built from exactly `NC` (299) code lengths and
                // `HuffmanTable::decode` cannot return a symbol at or past
                // `num_symbols`, so `number - 271` is always below LDECODE's 28.
                debug_assert!(
                    length_idx < LDECODE.len(),
                    "length index out of range: {length_idx}"
                );
                let mut length = LDECODE[length_idx] as usize + 3;
                let lbits = LBITS[length_idx];
                if lbits > 0 {
                    length += reader.read_bits(lbits)? as usize;
                }

                let distance = self.decode_distance(reader)?;

                // Distance-based length adjustment.
                if distance >= 0x2000 {
                    length += 1;
                    if distance >= 0x40000 {
                        length += 1;
                    }
                }

                self.insert_old_dist(distance);
                self.last_length = length;
                self.window.copy(distance, length)?;
                output_size += length as u64;
                should_check_yield = true;
            } else if number == 256 || number == 257 {
                // End of block and VM filter code; shared with the fast path.
                if !self.handle_cold_symbol(reader, number, output_size)? {
                    break;
                }
            } else if number == 258 {
                // Repeat previous match.
                if self.last_length != 0 {
                    let distance = self.dist_cache[0];
                    self.window.copy(distance, self.last_length)?;
                    output_size += self.last_length as u64;
                    should_check_yield = true;
                }
            } else if number < 263 {
                // Repeat distance from cache (259-262).
                let cache_idx = number - 259;
                let distance = self.dist_cache[cache_idx];

                // Rotate cache.
                for j in (1..=cache_idx).rev() {
                    self.dist_cache[j] = self.dist_cache[j - 1];
                }
                self.dist_cache[0] = distance;

                // Decode length from RD table.
                let length_number = self
                    .rd_table
                    .as_ref()
                    .ok_or_else(|| missing_table("RD"))?
                    .decode(reader)
                    .map_err(|err| decode_failed_at("RD", output_size, &err))?
                    as usize;
                // The RD table is built from exactly `RC` (28) code lengths,
                // which is LDECODE's length, and `HuffmanTable::decode` cannot
                // return a symbol at or past `num_symbols`.
                debug_assert!(
                    length_number < LDECODE.len(),
                    "RD length index out of range: {length_number}"
                );
                let mut length = LDECODE[length_number] as usize + 2; // +2 for cache refs
                let lbits = LBITS[length_number];
                if lbits > 0 {
                    length += reader.read_bits(lbits)? as usize;
                }

                self.last_length = length;
                self.window.copy(distance, length)?;
                output_size += length as u64;
                should_check_yield = true;
            } else if number < 272 {
                // Short match (263-270): length=2, decode short distance.
                let sd_idx = number - 263;
                let mut distance = SDDECODE[sd_idx] as usize + 1;
                let sd_bits = SDBITS[sd_idx];
                if sd_bits > 0 {
                    distance += reader.read_bits(sd_bits)? as usize;
                }

                self.insert_old_dist(distance);
                self.last_length = 2;
                self.window.copy(distance, 2)?;
                output_size += 2;
                should_check_yield = true;
            } else {
                // Unreachable: `number` is below the LD table's 299 symbols,
                // 271..299 is taken by the match arm above, 256/257/258 are
                // explicit, and the two arms before this one cover 259..271.
                debug_assert!(false, "invalid symbol: {number}");
            }

            if should_check_yield
                && let Some(threshold) = yield_threshold
                && self.window.unflushed_bytes() as usize >= threshold
            {
                // Yielding here asks the caller to flush. While the queue head
                // pins the write border there is nothing for it to flush, and
                // the border can only move once this loop has decoded the rest
                // of the head's block — so the caller would flush nothing and
                // immediately re-enter, once per symbol. Keep decoding in
                // place instead; every other exit from this loop (end of
                // block, new file, truncated VM code, input exhaustion) is
                // untouched, and the yield fires as soon as a flush could
                // actually make progress.
                if self.flush_is_pinned_by_pending_head() {
                    continue;
                }
                break;
            }
        }

        Ok(output_size)
    }

    /// True exactly when a flush attempt right now would move nothing.
    ///
    /// Mirrors the three conditions under which
    /// [`Self::flush_ready_output_to_writer`] returns without writing: the
    /// queue is non-empty, its head starts precisely at the write border (a
    /// head *past* the border lets the prefix flush make progress, and one
    /// *behind* it is dropped), and the head's block is not fully decoded yet.
    ///
    /// The overrun bound keeps the corrupt-stream guard in the chunked caller
    /// (`unflushed > dict_size`) reachable at the same point it is today: past
    /// that size the loop yields normally and the caller raises the error.
    fn flush_is_pinned_by_pending_head(&self) -> bool {
        let Some(head) = self.pending_vm_filters.first() else {
            return false;
        };
        head.block_start_total == self.window.total_flushed()
            && head
                .block_start_total
                .saturating_add(head.block_length as u64)
                > self.window.total_written()
            && self.window.unflushed_bytes() <= self.window.dict_size() as u64
    }

    /// Decode a full distance value from DD and LDD tables.
    fn decode_distance<R: BitRead>(&mut self, reader: &mut R) -> RarResult<usize> {
        let dist_number = self
            .dd_table
            .as_ref()
            .ok_or_else(|| missing_table("DD"))?
            .decode(reader)
            .map_err(|err| decode_failed("DD", &err))? as usize;
        // The DD table is built from exactly `DC` (60) code lengths — the size
        // of `ddecode`/`dbits` — and `HuffmanTable::decode` cannot return a
        // symbol at or past `num_symbols`.
        debug_assert!(
            dist_number < DC,
            "distance code out of range: {dist_number}"
        );

        let mut distance = self.ddecode[dist_number] as usize + 1;
        let bits = self.dbits[dist_number];

        if bits > 0 {
            if dist_number > 9 {
                // Complex case: high bits from bitstream, low 4 bits from LDD table.
                if bits > 4 {
                    let high_bits = bits - 4;
                    distance += (reader.read_bits(high_bits)? as usize) << 4;
                }

                if self.low_dist_rep_count > 0 {
                    self.low_dist_rep_count -= 1;
                    distance += self.prev_low_dist;
                } else {
                    let low_dist = self
                        .ldd_table
                        .as_ref()
                        .ok_or_else(|| missing_table("LDD"))?
                        .decode(reader)
                        .map_err(|err| decode_failed("LDD", &err))?
                        as usize;
                    if low_dist == 16 {
                        // Repeat previous low distance.
                        self.low_dist_rep_count = LOW_DIST_REP_COUNT - 1;
                        distance += self.prev_low_dist;
                    } else {
                        distance += low_dist;
                        self.prev_low_dist = low_dist;
                    }
                }
            } else {
                // Simple case: just read extra bits directly.
                distance += reader.read_bits(bits)? as usize;
            }
        }

        Ok(distance)
    }

    /// Insert a new distance into the old distance cache (rotate right).
    fn insert_old_dist(&mut self, distance: usize) {
        self.dist_cache[3] = self.dist_cache[2];
        self.dist_cache[2] = self.dist_cache[1];
        self.dist_cache[1] = self.dist_cache[0];
        self.dist_cache[0] = distance;
    }

    /// Handle end-of-block marker (symbol 256).
    ///
    /// Returns true if decompression should continue (new tables read),
    /// false if this is the end of file.
    fn read_end_of_block<R: BitRead>(&mut self, reader: &mut R) -> RarResult<bool> {
        if reader.bits_remaining() < 1 {
            return Ok(false);
        }

        let bit = reader.read_bits(1)?;
        if bit != 0 {
            // "1" — no new file, new table immediately.
            if rar4_debug_filters_enabled() {
                eprintln!(
                    "RAR4 read_end_of_block: immediate_table total_written={} bits_remaining={}",
                    self.window.total_written(),
                    reader.bits_remaining()
                );
            }
            self.tables_read = false;
            self.read_tables(reader)?;
            return Ok(true);
        }

        // "0x" — new file.
        if reader.bits_remaining() < 1 {
            return Ok(false);
        }
        let new_table_bit = reader.read_bits(1)?;
        self.tables_read = new_table_bit == 0;
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 read_end_of_block: new_file total_written={} new_table_bit={} tables_read={} bits_remaining={}",
                self.window.total_written(),
                new_table_bit,
                self.tables_read,
                reader.bits_remaining()
            );
        }
        Ok(false)
    }

    /// Read VM filter code (symbol 257) and queue a standard filter block.
    ///
    /// Returns `false` when the packet is truncated. `ReadVMCode` answers input
    /// exhaustion with `return false`, which breaks the unpack loop and ends the
    /// member with whatever was already decoded (unpack30.cpp:210-215) — no
    /// error. Malformed VM *data* that `add_vm_code` rejects still errors:
    /// rarpar is deliberately stricter than the oracle there.
    fn read_vm_code<R: BitRead>(&mut self, reader: &mut R, output_size: u64) -> RarResult<bool> {
        if rar4_debug_filters_enabled() {
            eprintln!(
                "RAR4 read_vm_code: output_size={output_size} bits_remaining={}",
                reader.bits_remaining()
            );
        }
        if !reader.has_exact_bits(8)? {
            return Ok(false);
        }
        let first_byte = reader.read_bits(8)? as u8;
        // `decode_vm_code_length` consumes one further byte for the 7 form and
        // two for the 8 form; check them here so a short packet stops the
        // member instead of being mistaken for a malformed length.
        let extra_length_bytes: usize = match (first_byte & 7) + 1 {
            7 => 1,
            8 => 2,
            _ => 0,
        };
        if !reader.has_exact_bits(extra_length_bytes * 8)? {
            return Ok(false);
        }
        let length = Self::decode_vm_code_length(first_byte, || Ok(reader.read_bits(8)? as u8))?;
        let mut code = Vec::with_capacity(length);
        for _ in 0..length {
            if !reader.has_exact_bits(8)? {
                return Ok(false);
            }
            code.push(reader.read_bits(8)? as u8);
        }
        self.add_vm_code(first_byte, &code, output_size)?;
        Ok(true)
    }

    /// Initialize a PPMd block from the RAR3 DecodeInit header.
    ///
    /// The PPM flag bit has already been consumed. The remaining 7 bits of that
    /// byte plus subsequent bytes form the DecodeInit header:
    /// - Bits 0-4: max order value
    /// - Bit 5: reset flag (reinitialize model)
    /// - Bit 6: new escape character flag
    /// - If reset: next byte = allocator size in MB
    /// - If bit 6: next byte = new escape character
    /// - Then the range coder reads its init bytes from the stream
    fn init_ppm<R: BitRead>(&mut self, reader: &mut R) -> RarResult<()> {
        // A new PPMd block header always starts a fresh range coder; any
        // saved mid-block registers are stale.
        self.ppm_rc_state = None;

        // The PPM flag (bit 7) was consumed as 1 bit. Read remaining 7 bits
        // to reconstruct the MaxOrder byte (bit 7 is always 1 but unused).
        if reader.bits_remaining() < 7 {
            return Err(RarError::CorruptArchive {
                detail: "RAR4: truncated PPMd init header".into(),
            });
        }
        let max_order_byte = reader.read_bits(7)? as u8;

        let reset = (max_order_byte & 0x20) != 0;
        let new_esc = (max_order_byte & 0x40) != 0;

        let max_mb = if reset {
            reader.read_bits(8)? as usize
        } else {
            if self.ppm_model.is_none() {
                return Err(RarError::CorruptArchive {
                    detail: "RAR4: PPMd block without model (no reset)".into(),
                });
            }
            0
        };

        if new_esc {
            self.ppm_esc_char = reader.read_bits(8)? as u8;
        }

        if reset {
            let mut order = (max_order_byte & 0x1F) as usize + 1;
            if order > 16 {
                order = 16 + (order - 16) * 3;
            }
            if order < 2 {
                return Err(RarError::CorruptArchive {
                    detail: "RAR4: PPMd order too small".into(),
                });
            }
            let alloc_size = (max_mb + 1) * 1024 * 1024;
            trace!("RAR4 PPMd init: order={order}, alloc={alloc_size}");
            if let Some(model) = self.ppm_model.as_mut() {
                model.start(order, alloc_size);
            } else {
                self.ppm_model = Some(Model::new(order, alloc_size));
            }
        }

        Ok(())
    }

    /// Decode PPMd symbols until block switch, EOF, or output complete.
    ///
    /// Creates a RangeDecoder from the remaining bitstream bytes, decodes
    /// symbols via the PPMd model, and handles escape sequences.
    ///
    /// The range decoder's lookahead state cannot survive a drop/recreate, so
    /// unlike the LZ loop this one cannot yield to the caller for flushing;
    /// instead it flushes ready output to `writer` itself whenever the
    /// unflushed window span reaches `yield_threshold`.
    fn decode_ppm_symbols<R: BitRead, W: Write + ?Sized>(
        &mut self,
        reader: &mut R,
        decode_limit: u64,
        mut output_size: u64,
        yield_threshold: Option<usize>,
        writer: &mut W,
    ) -> RarResult<u64> {
        if self.ppm_rc_state.is_none() && reader.bits_remaining() < 32 {
            return Ok(output_size);
        }

        let mut switch_to_lz_tables = false;
        let mut end_marker_seen = false;
        let mut ppm_corrupt = false;

        {
            // A solid member boundary can fall inside a PPMd block; one range
            // coder stays alive across members, so resume from the saved
            // registers instead of consuming init bytes again.
            let mut rc = match self.ppm_rc_state.take() {
                Some(state) => BitReadRangeDecoder::from_state(reader, state),
                None => BitReadRangeDecoder::new(reader)?,
            };
            let Some(mut ppm_model) = self.ppm_model.take() else {
                self.block_type = BlockType::Lz;
                return Ok(output_size);
            };
            let mut literals = [0u8; 1024];
            let mut literal_len = 0usize;
            macro_rules! flush_literals {
                () => {
                    if literal_len != 0 {
                        self.window.put_bytes(&literals[..literal_len]);
                        literal_len = 0;
                    }
                };
            }

            while output_size < decode_limit {
                if let Some(threshold) = yield_threshold
                    && self.window.unflushed_bytes() as usize + literal_len >= threshold
                {
                    flush_literals!();
                    self.flush_ready_output_to_writer(writer, false)?;
                }

                let Some(ch) = ppm_model.decode_char_result(&mut rc)? else {
                    if rar4_debug_filters_enabled() {
                        eprintln!("RAR4 PPM decode_char=-1 at output_size={output_size}");
                        if let Some(path) = std::env::var_os("UNRAR_RS_RAR4_DEBUG_DUMP_PATH") {
                            let bytes = self
                                .window
                                .try_copy_output(0, output_size as usize)
                                .unwrap_or_default();
                            let _ = std::fs::write(path, &bytes);
                        }
                        let tail_len = (output_size as usize).min(160);
                        if tail_len > 0 {
                            let start = output_size - tail_len as u64;
                            let tail = self
                                .window
                                .try_copy_output(start, tail_len)
                                .unwrap_or_default();
                            eprintln!(
                                "RAR4 PPM decode_char tail[{start}..{output_size}]: {:?}",
                                String::from_utf8_lossy(&tail)
                            );
                        }
                    }
                    trace!("RAR4 PPMd corruption at output_size={output_size}: cleaning up");
                    ppm_corrupt = true;
                    break;
                };

                if ch == self.ppm_esc_char {
                    // Commands can inspect or copy the dictionary, so publish
                    // preceding literals before interpreting the escape.
                    flush_literals!();
                    // Escape sequence — decode the command byte.
                    let Some(next_ch) = ppm_model.decode_char_result(&mut rc)? else {
                        if rar4_debug_filters_enabled() {
                            eprintln!("RAR4 PPM next_ch=-1 at output_size={output_size}");
                            if let Some(path) = std::env::var_os("UNRAR_RS_RAR4_DEBUG_DUMP_PATH") {
                                let bytes = self
                                    .window
                                    .try_copy_output(0, output_size as usize)
                                    .unwrap_or_default();
                                let _ = std::fs::write(path, &bytes);
                            }
                            let tail_len = (output_size as usize).min(160);
                            if tail_len > 0 {
                                let start = output_size - tail_len as u64;
                                let tail = self
                                    .window
                                    .try_copy_output(start, tail_len)
                                    .unwrap_or_default();
                                eprintln!(
                                    "RAR4 PPM next_ch tail[{start}..{output_size}]: {:?}",
                                    String::from_utf8_lossy(&tail)
                                );
                            }
                        }
                        trace!(
                            "RAR4 PPMd command corruption at output_size={output_size}: cleaning up"
                        );
                        ppm_corrupt = true;
                        break;
                    };

                    match next_ch {
                        0 => {
                            if rar4_debug_filters_enabled() {
                                eprintln!("RAR4 PPM switch_to_lz at output_size={output_size}");
                            }
                            switch_to_lz_tables = true;
                            break;
                        }
                        2 => {
                            if rar4_debug_filters_enabled() {
                                eprintln!("RAR4 PPM end_of_file at output_size={output_size}");
                            }
                            // "End of file in PPM mode" leaves `Unpack29`'s
                            // main loop outright (unpack30.cpp:88-89), exactly
                            // as symbol 256's new-file flag does on the LZ
                            // side. This member is done; re-entering would
                            // decode the next member's stream.
                            end_marker_seen = true;
                            self.member_decode_done = true;
                            break;
                        }
                        3 => {
                            if !self.read_vm_code_ppm(&mut ppm_model, &mut rc, output_size)? {
                                trace!(
                                    "RAR4 PPMd VM-code corruption at output_size={output_size}: cleaning up"
                                );
                                ppm_corrupt = true;
                                break;
                            }
                        }
                        4 => {
                            let mut distance: u32 = 0;
                            let mut length: u32 = 0;
                            let mut failed = false;
                            for i in 0..4 {
                                let Some(b) = ppm_model.decode_char_result(&mut rc)? else {
                                    failed = true;
                                    break;
                                };
                                if i == 3 {
                                    length = b as u32;
                                } else {
                                    distance = (distance << 8) | u32::from(b);
                                }
                            }
                            if failed {
                                trace!(
                                    "RAR4 PPMd match-command corruption at output_size={output_size}: cleaning up"
                                );
                                ppm_corrupt = true;
                                break;
                            }
                            if rar4_debug_filters_enabled() {
                                eprintln!(
                                    "RAR4 PPM lz_copy at output_size={output_size} distance={} length={}",
                                    distance + 2,
                                    length + 32
                                );
                            }
                            let copy_len = (length + 32) as usize;
                            let copy_dist = (distance + 2) as usize;
                            self.window.copy(copy_dist, copy_len)?;
                            output_size += copy_len as u64;
                        }
                        5 => {
                            let Some(len_byte) = ppm_model.decode_char_result(&mut rc)? else {
                                trace!(
                                    "RAR4 PPMd run-length corruption at output_size={output_size}: cleaning up"
                                );
                                ppm_corrupt = true;
                                break;
                            };
                            if rar4_debug_filters_enabled() {
                                eprintln!(
                                    "RAR4 PPM rle_copy at output_size={output_size} length={}",
                                    usize::from(len_byte) + 4
                                );
                            }
                            let copy_len = usize::from(len_byte) + 4;
                            self.window.copy(1, copy_len)?;
                            output_size += copy_len as u64;
                        }
                        _ => {
                            literals[literal_len] = ch;
                            literal_len += 1;
                            if literal_len == literals.len() {
                                flush_literals!();
                            }
                            output_size += 1;
                        }
                    }
                } else {
                    literals[literal_len] = ch;
                    literal_len += 1;
                    if literal_len == literals.len() {
                        flush_literals!();
                    }
                    output_size += 1;
                }
            }
            if literal_len != 0 {
                self.window.put_bytes(&literals[..literal_len]);
            }

            if ppm_corrupt {
                // SafePPMDecodeChar (unpack30.cpp:1-13, and the inlined copy at
                // unpack30.cpp:77-83): reset the possibly corrupt PPM structures
                // and fall back to the more fail-proof LZ mode. The oracle's
                // caller then breaks out of the unpack loop, so the member ends
                // with the output decoded so far instead of an error.
                ppm_model.cleanup();
                self.block_type = BlockType::Lz;
                self.member_decode_done = true;
            }

            if !ppm_corrupt && !switch_to_lz_tables && matches!(self.block_type, BlockType::Ppm) {
                // The output check is strictly `Written > DestSize`, so
                // the esc,2 end-of-file marker following a member's last
                // output byte is consumed before its decode ends. Consume it
                // here when the loop stopped on exact output completion.
                if !end_marker_seen && output_size >= self.current_file_unpacked_size {
                    let esc = self.ppm_esc_char;
                    if let Ok(Some(ch)) = ppm_model.decode_char_result(&mut rc) {
                        if rar4_debug_filters_enabled() {
                            eprintln!(
                                "RAR4 PPM trailing consume: ch={ch} esc={esc} output_size={output_size}"
                            );
                        }
                        if ch == esc {
                            // Subcode 2 = end of file; anything else only
                            // occurs in malformed streams.
                            let sub = ppm_model.decode_char_result(&mut rc);
                            if rar4_debug_filters_enabled() {
                                eprintln!("RAR4 PPM trailing consume subcode: {sub:?}");
                            }
                        }
                    }
                }

                // The member's output ended while the PPMd block continues;
                // the next solid member resumes with these registers.
                self.ppm_rc_state = Some(rc.state());
            }
            self.ppm_model = Some(ppm_model);
        }

        if switch_to_lz_tables {
            self.read_tables(reader)?;
        }

        Ok(output_size)
    }

    /// Read VM filter code in PPM mode and queue a standard filter block.
    ///
    /// Returns `false` when the model reported corruption. `ReadVMCodePPM`
    /// reads every byte through `SafePPMDecodeChar` and answers its `-1` with
    /// `return false` (unpack30.cpp:104-131), which the caller turns into the
    /// same CleanUp + `BLOCK_LZ` + end-of-member handling a corrupt literal
    /// gets — not an archive error. Malformed VM *data* that `add_vm_code`
    /// rejects still errors: rarpar is deliberately stricter there, matching
    /// [`Self::read_vm_code`].
    fn read_vm_code_ppm<R: RangeCode>(
        &mut self,
        model: &mut Model,
        rc: &mut R,
        output_size: u64,
    ) -> RarResult<bool> {
        let corrupt = std::cell::Cell::new(false);
        let read_model_byte = |model: &mut Model, rc: &mut R| -> RarResult<u8> {
            match model.decode_char_result(rc)? {
                Some(byte) => Ok(byte),
                None => {
                    corrupt.set(true);
                    Ok(0)
                }
            }
        };

        let first_byte = read_model_byte(model, rc)?;
        if corrupt.get() {
            return Ok(false);
        }

        // A corrupt length byte reads back as 0, which can make the length
        // decode itself fail; that failure belongs to the corruption, not to
        // the stream, so it degrades rather than erroring.
        let length = match Self::decode_vm_code_length(first_byte, || read_model_byte(model, rc)) {
            Ok(length) => length,
            Err(_) if corrupt.get() => return Ok(false),
            Err(err) => return Err(err),
        };
        if corrupt.get() {
            return Ok(false);
        }

        let mut code = Vec::with_capacity(length);
        for _ in 0..length {
            code.push(read_model_byte(model, rc)?);
            if corrupt.get() {
                return Ok(false);
            }
        }

        self.add_vm_code(first_byte, &code, output_size)?;
        Ok(true)
    }

    /// Prepare for solid continuation (keep window state, reset block state).
    ///
    /// `LowDistRepCount`/`PrevLowDist` are deliberately **not** cleared here:
    /// the oracle resets them only in the LZ branch of `ReadTables30`
    /// (unpack30.cpp:647-648), which [`Self::read_tables`] already mirrors. A
    /// solid member that inherits its tables also inherits this state.
    pub fn prepare_solid_continuation(&mut self) {
        // Tables are kept across solid continuation.
        // Window state is preserved.
        self.pending_vm_filters.clear();
        self.current_file_base_total = self.window.total_written();
        self.current_file_written_size = 0;
    }

    /// Prepare this cached decoder for the next member of the archive.
    ///
    /// Mirrors `Unpack::DoUnpack` dispatching on the per-file solid flag plus
    /// `UnpInitData(Solid)`/`UnpInitData30(Solid)` (unpack.cpp:192-228,
    /// unpack30.cpp:741-768). A non-solid member restarts every adaptive
    /// structure **without** giving up an allocation: the window is re-pointed
    /// through [`Window::reset_for_reuse`] (no memset), and the PPMd model is
    /// kept so its arena survives — the oracle likewise keeps `ModelPPM`
    /// across files, with `DecodeInit` restarting it and `StartSubAllocator`
    /// early-outing on an unchanged size (suballoc.cpp:79-83).
    pub fn prepare_member(&mut self, solid: bool, dict_size: usize) -> RarResult<()> {
        if solid {
            self.ensure_solid_dict_compat(dict_size)?;
            self.prepare_solid_continuation();
            return Ok(());
        }

        // No memset: `reset_for_reuse` documents why the window's own
        // first-window guard makes leftover bytes unreachable.
        self.window.reset_for_reuse(dict_size)?;

        self.dist_cache = [usize::MAX; 4];
        self.last_length = 0;
        self.carried_old_dist_ptr = 0;
        self.carried_last_dist = usize::MAX;
        self.ld_table = None;
        self.dd_table = None;
        self.ldd_table = None;
        self.rd_table = None;
        self.code_lengths.fill(0);
        self.tables_read = false;
        self.block_type = BlockType::Lz;
        self.ppm_esc_char = 2;
        // InitFilters30(false): filter definitions, their memos and the queued
        // blocks all go away for a non-solid member.
        self.reset_vm_filter_state();
        self.ppm_rc_state = None;
        // `ppm_model` is intentionally retained; see the doc comment.
        self.current_file_base_total = 0;
        self.current_file_written_size = 0;
        Ok(())
    }

    fn ensure_solid_dict_compat(&mut self, dict_size: usize) -> RarResult<()> {
        ensure_solid_window_dict(self.window.dict_size(), dict_size)
    }

    /// See [`Rar4Decoder::shared_lz_state`](super::rar4_old::Rar4Decoder).
    pub(crate) fn shared_lz_state(&mut self) -> super::rar4_old::Rar4SharedLzState<'_> {
        super::rar4_old::Rar4SharedLzState {
            window: &mut self.window,
            old_dist: &mut self.dist_cache,
            old_dist_ptr: &mut self.carried_old_dist_ptr,
            last_dist: &mut self.carried_last_dist,
            last_length: &mut self.last_length,
        }
    }

    /// Reset the decoder for a new non-solid file.
    pub fn reset(&mut self) {
        self.dist_cache = [usize::MAX; 4];
        self.last_length = 0;
        self.carried_old_dist_ptr = 0;
        self.carried_last_dist = usize::MAX;
        self.ld_table = None;
        self.dd_table = None;
        self.ldd_table = None;
        self.rd_table = None;
        self.code_lengths.fill(0);
        self.low_dist_rep_count = 0;
        self.prev_low_dist = 0;
        self.block_type = BlockType::Lz;
        self.ppm_esc_char = 2;
        self.tables_read = false;
        self.vm_filters.clear();
        self.pending_vm_filters.clear();
        self.last_vm_filter = 0;
        self.current_file_base_total = 0;
        self.current_file_written_size = 0;
        self.ppm_rc_state = None;
        self.member_decode_done = false;
        self.window.reset();
    }
}

/// Reject a solid member that declares a dictionary larger than the live
/// window.
///
/// The window cannot grow mid-solid-stream without discarding the history the
/// member is entitled to reference — the oracle throws `bad_alloc` for exactly
/// this case (unpack.cpp:110-123) — so this mirrors
/// `LzDecoder::ensure_solid_member_compat`. A non-solid member is free to grow
/// through `Window::ensure_capacity`; it starts from an empty history.
pub(crate) fn ensure_solid_window_dict(live_dict_size: usize, dict_size: usize) -> RarResult<()> {
    if dict_size > live_dict_size {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "solid member declares {dict_size} byte dictionary but the solid stream window is {live_dict_size} bytes"
            ),
        });
    }
    Ok(())
}

/// Decompress RAR4 LZ data.
pub fn decompress_rar4_lz(input: &[u8], unpacked_size: u64, dict_size: u64) -> RarResult<Vec<u8>> {
    let dict_size = effective_lz_dict_size(dict_size)?;
    let mut decoder = Rar4LzDecoder::try_new(dict_size)?;
    decoder.decompress(input, unpacked_size)
}

/// Streaming variant: decompress RAR4 LZ data directly to a writer.
pub fn decompress_rar4_lz_to_writer<W: Write>(
    input: &[u8],
    unpacked_size: u64,
    dict_size: u64,
    writer: &mut W,
) -> RarResult<u64> {
    let dict_size = effective_lz_dict_size(dict_size)?;
    let mut decoder = Rar4LzDecoder::try_new(dict_size)?;
    decoder.decompress_to_writer(input, unpacked_size, writer)
}

pub fn decompress_rar4_lz_reader_to_writer<R: std::io::Read, W: Write>(
    input: R,
    unpacked_size: u64,
    dict_size: u64,
    writer: &mut W,
) -> RarResult<u64> {
    let dict_size = effective_lz_dict_size(dict_size)?;
    let mut decoder = Rar4LzDecoder::try_new(dict_size)?;
    let mut reader = StreamingBitReader::new(input);
    decoder.decompress_to_writer_with_reader(&mut reader, unpacked_size, writer)
}

pub fn decompress_rar4_lz_reader_to_writer_chunked<R: std::io::Read, F, W>(
    input: R,
    unpacked_size: u64,
    dict_size: u64,
    first_volume_index: usize,
    shared_transitions: std::sync::Arc<std::sync::Mutex<Vec<super::VolumeTransition>>>,
    writer_factory: F,
) -> RarResult<Vec<(usize, u64)>>
where
    W: Write,
    F: FnMut(usize) -> RarResult<W>,
{
    let dict_size = effective_lz_dict_size(dict_size)?;
    let mut decoder = Rar4LzDecoder::try_new(dict_size)?;
    let mut reader = StreamingBitReader::new(input);
    decoder.decompress_to_writer_chunked_with_shared_transitions(
        &mut reader,
        unpacked_size,
        first_volume_index,
        shared_transitions,
        writer_factory,
    )
}

fn effective_lz_dict_size(dict_size: u64) -> RarResult<usize> {
    let effective_size = super::rar4_old::effective_rar4_window_size(dict_size);
    if effective_size > MAX_DICT_SIZE {
        return Err(RarError::DictionaryTooLarge {
            size: effective_size,
            max: MAX_DICT_SIZE,
        });
    }

    Ok(effective_size as usize)
}

#[cfg(test)]
mod tests {
    // These tests drive the pre-0.9.0 buffered entry point on purpose: it is
    // still part of the crate's surface until 0.10.0, and holding the decoder
    // to it here is what proves the wrappers stay honest.
    #![allow(deprecated)]
    use super::*;

    #[test]
    fn test_ddecode_table_construction() {
        let (ddecode, dbits) = build_ddecode_tables();
        // First 4 entries: distance 0,1,2,3 with 0 extra bits.
        assert_eq!(ddecode[0], 0);
        assert_eq!(ddecode[1], 1);
        assert_eq!(ddecode[2], 2);
        assert_eq!(ddecode[3], 3);
        assert_eq!(dbits[0], 0);
        assert_eq!(dbits[3], 0);

        // Entries 4-5: distance 4,6 with 1 extra bit.
        assert_eq!(ddecode[4], 4);
        assert_eq!(ddecode[5], 6);
        assert_eq!(dbits[4], 1);
        assert_eq!(dbits[5], 1);

        // Entries 6-7: distance 8,12 with 2 extra bits.
        assert_eq!(ddecode[6], 8);
        assert_eq!(ddecode[7], 12);
        assert_eq!(dbits[6], 2);
    }

    #[test]
    fn test_ddecode_table_coverage() {
        let (ddecode, dbits) = build_ddecode_tables();
        // Verify entries are monotonically increasing.
        for i in 1..DC {
            if dbits[i] > 0 || ddecode[i] > 0 {
                assert!(
                    ddecode[i] >= ddecode[i - 1],
                    "ddecode not monotonic at {i}: {} < {}",
                    ddecode[i],
                    ddecode[i - 1]
                );
            }
        }
    }

    /// D1: the 512 KiB streaming input buffer is allocated once and handed
    /// from member to member, and its stale contents never reach a decode.
    #[test]
    fn streaming_input_buffer_is_recycled_across_members_without_leaking_stale_bytes() {
        use std::io::Cursor;

        // 0x55 keeps the leading PPM flag bit clear, so this stays on the LZ
        // path (no PPMd arena allocation), and is non-zero so the recycled
        // buffer is visibly dirty for the next member.
        let member1 = vec![0x55u8; 600 * 1024];
        let member2: Vec<u8> = (0..=255u8).cycle().take(4096).collect();

        let mut recycling = Rar4LzDecoder::new(0x40000);
        recycling.prepare_member(false, 0x40000).unwrap();
        let mut out1 = Vec::new();
        let _ = recycling.decompress_reader_to_writer(Cursor::new(&member1), 4096, &mut out1);

        let parked = recycling
            .input_buffer_for_test()
            .expect("buffer parked after member 1");
        let addr_after_first = parked.as_ptr() as usize;
        // The buffer really is dirty: this is the state the next member starts
        // from, and it is deliberately not zeroed.
        assert!(
            parked.contains(&0x55),
            "member 1 should have left bytes in the recycled buffer"
        );

        recycling.prepare_member(false, 0x40000).unwrap();
        let mut out2 = Vec::new();
        let recycled_result =
            recycling.decompress_reader_to_writer(Cursor::new(&member2), 4096, &mut out2);
        let addr_after_second = recycling
            .input_buffer_for_test()
            .expect("buffer parked after member 2")
            .as_ptr() as usize;

        // One allocation for both members, returned on every exit path
        // (member 1 above may well have ended in an error).
        assert_eq!(
            addr_after_first, addr_after_second,
            "streaming input buffer was reallocated between members"
        );

        // A fresh decoder starts from a zeroed buffer. Identical answers prove
        // no byte above `buf_len` is observable, i.e. reuse needs no zeroing.
        let mut fresh = Rar4LzDecoder::new(0x40000);
        fresh.prepare_member(false, 0x40000).unwrap();
        let mut fresh_out = Vec::new();
        let fresh_result =
            fresh.decompress_reader_to_writer(Cursor::new(&member2), 4096, &mut fresh_out);

        assert_eq!(
            out2, fresh_out,
            "recycled buffer changed the decoded output"
        );
        assert_eq!(
            recycled_result.is_ok(),
            fresh_result.is_ok(),
            "recycled buffer changed the decode outcome"
        );
        if let (Ok(a), Ok(b)) = (&recycled_result, &fresh_result) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_decoder_creation() {
        let decoder = Rar4LzDecoder::new(4 * 1024 * 1024);
        assert_eq!(decoder.window.dict_size(), 4 * 1024 * 1024);
        assert_eq!(decoder.dist_cache, [usize::MAX; 4]);
        assert_eq!(decoder.last_length, 0);
    }

    #[test]
    fn non_solid_reset_keeps_ppmd_allocation_for_the_next_header() {
        let mut decoder = Rar4LzDecoder::new(1024 * 1024);
        decoder.ppm_model = Some(Model::new(16, 1024 * 1024));
        decoder.block_type = BlockType::Ppm;

        decoder.reset();

        assert!(decoder.ppm_model.is_some());
        assert!(matches!(decoder.block_type, BlockType::Lz));
        assert!(decoder.ppm_rc_state.is_none());
    }

    /// Previously pinned as `Err(CorruptArchive)`. The oracle answers a `-1`
    /// from `DecodeChar` with `PPM.CleanUp()` + `UnpBlockType=BLOCK_LZ` and
    /// breaks the unpack loop (unpack30.cpp:1-13 and 77-83), so the member ends
    /// with the output decoded so far instead of failing.
    #[test]
    fn corrupt_ppmd_symbol_cleans_up_and_falls_back_to_lz_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024 * 1024);
        decoder.ppm_model = Some(Model::new(16, 4 * 1024 * 1024));
        decoder.block_type = BlockType::Ppm;
        let input = [0xff; 4];
        let mut reader = BitReader::new(&input);
        let mut output = Vec::new();

        let result = decoder.decode_ppm_symbols(&mut reader, 1, 0, None, &mut output);

        assert!(result.is_ok(), "{result:?}");
        assert!(matches!(decoder.block_type, BlockType::Lz));
        assert!(decoder.member_decode_done);
        assert!(decoder.ppm_rc_state.is_none());
        // The model survives, shrunk to the CleanUp allocation.
        assert!(decoder.ppm_model.is_some());
        assert!(output.is_empty());
    }

    /// The escape-3 (VM filter code) command reads every byte through
    /// `SafePPMDecodeChar` too, and `ReadVMCodePPM` answers a `-1` with
    /// `return false` (unpack30.cpp:104-131) — the member ends through the
    /// same CleanUp path rather than failing the archive.
    ///
    /// This reuses the exact model/stream pair pinned by
    /// `corrupt_ppmd_symbol_cleans_up_and_falls_back_to_lz_like_rar_behavior`:
    /// a freshly restarted order-16 model reports corruption on its very first
    /// symbol, because the initial 256-symbol root context has `SummFreq` 257
    /// and an all-ones code decodes to a count of exactly 257, which is out of
    /// range.
    #[test]
    fn corrupt_ppmd_vm_code_ends_the_member_instead_of_failing_the_archive() {
        let mut decoder = Rar4LzDecoder::new(1024 * 1024);
        let mut model = Model::new(16, 4 * 1024 * 1024);
        let input = [0xff; 4];
        let mut reader = BitReader::new(&input);
        let mut rc = BitReadRangeDecoder::new(&mut reader).unwrap();

        let result = decoder.read_vm_code_ppm(&mut model, &mut rc, 0);

        assert!(
            matches!(result, Ok(false)),
            "corrupt VM filter code must degrade, not error: {result:?}"
        );
    }

    /// The PPMd arena must survive a member boundary: [`Model::start`]
    /// early-outs when the declared allocation size is unchanged, exactly as
    /// `StartSubAllocator` does (suballoc.cpp:79-83), so the second member of a
    /// multi-member PPMd archive reuses the pages the first one faulted in. A
    /// *different* declared size must still reallocate.
    #[test]
    fn ppmd_arena_is_reused_across_members_with_the_same_declared_size() {
        // `init_ppm` runs with the PPM flag bit already consumed: 7 bits of the
        // MaxOrder byte, then the allocator size in MB when the reset flag is
        // set. 0x2F = reset (0x20) + order 16 (0x1F), new-escape flag clear.
        fn init_bits(max_mb: u8) -> Vec<u8> {
            let mut bits: Vec<u8> = (0..7).rev().map(|i| (0x2Fu8 >> i) & 1).collect();
            bits.extend((0..8).rev().map(|i| (max_mb >> i) & 1));
            bits
        }

        let mut decoder = Rar4LzDecoder::new(0x40000);

        let one_mb = pack_bits(&init_bits(0));
        decoder.init_ppm(&mut BitReader::new(&one_mb)).unwrap();
        let model = decoder.ppm_model.as_ref().unwrap();
        let arena = model.arena_addr();
        assert_eq!(model.arena_size(), 1024 * 1024);

        // Member 2 declares the same size. `prepare_member` keeps the model.
        decoder.prepare_member(false, 0x40000).unwrap();
        decoder.init_ppm(&mut BitReader::new(&one_mb)).unwrap();
        let model = decoder.ppm_model.as_ref().unwrap();
        assert_eq!(
            model.arena_addr(),
            arena,
            "a same-size PPMd restart must reuse the arena, not fault in a fresh one"
        );
        assert_eq!(model.arena_size(), 1024 * 1024);

        // Member 3 declares a different size, which must still reallocate.
        let two_mb = pack_bits(&init_bits(1));
        decoder.prepare_member(false, 0x40000).unwrap();
        decoder.init_ppm(&mut BitReader::new(&two_mb)).unwrap();
        let model = decoder.ppm_model.as_ref().unwrap();
        assert_eq!(model.arena_size(), 2 * 1024 * 1024);
        assert_ne!(
            model.arena_addr(),
            arena,
            "a changed PPMd allocation size must replace the arena"
        );
    }

    fn pack_bits(bits: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; bits.len().div_ceil(8)];
        for (index, &bit) in bits.iter().enumerate() {
            if bit != 0 {
                out[index / 8] |= 0x80 >> (index % 8);
            }
        }
        out
    }

    fn nibble_bits(value: u8) -> [u8; 4] {
        [
            (value >> 3) & 1,
            (value >> 2) & 1,
            (value >> 1) & 1,
            value & 1,
        ]
    }

    #[test]
    fn truncated_main_code_length_table_is_rejected() {
        let mut bits = vec![0u8, 0u8]; // LZ block, do not inherit code lengths.
        // BC table: symbols 0 and 1 each get a one-bit code (a complete tree).
        bits.extend_from_slice(&nibble_bits(1));
        bits.extend_from_slice(&nibble_bits(1));
        for _ in 2..BC {
            bits.extend_from_slice(&nibble_bits(0));
        }
        // A few "delta 0" symbols, then the stream simply stops part-way
        // through the 404 main code lengths.
        bits.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let data = pack_bits(&bits);

        let mut decoder = Rar4LzDecoder::new(0x40000);
        let mut reader = BitReader::new(&data);
        let err = decoder.read_tables(&mut reader).unwrap_err();

        assert!(
            matches!(&err, RarError::CorruptArchive { detail } if detail.contains("truncated")),
            "{err:?}"
        );
        assert!(!decoder.tables_read);
        assert!(decoder.ld_table.is_none());
    }

    #[test]
    fn non_solid_member_restarts_the_window_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(0x40000);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"FIRST-MEMBER-DATA");
        decoder.tables_read = true;
        decoder.dist_cache = [7, 8, 9, 10];
        decoder.last_length = 5;
        decoder.ppm_esc_char = 9;
        decoder.block_type = BlockType::Ppm;
        decoder.last_vm_filter = 3;
        decoder.vm_filters.push(Rar4VmFilterDefinition {
            filter_type: Rar4StandardFilter::Delta,
            last_block_length: 8,
        });
        decoder.ppm_model = Some(Model::new(6, 1024 * 1024));

        decoder.prepare_member(false, 0x40000).unwrap();

        assert_eq!(decoder.window.total_written(), 0);
        assert!(!decoder.tables_read);
        assert_eq!(decoder.dist_cache, [usize::MAX; 4]);
        assert_eq!(decoder.last_length, 0);
        assert_eq!(decoder.ppm_esc_char, 2);
        assert!(matches!(decoder.block_type, BlockType::Lz));
        assert!(decoder.vm_filters.is_empty());
        assert_eq!(decoder.last_vm_filter, 0);
        // The PPMd arena persists across files exactly as ModelPPM does.
        assert!(decoder.ppm_model.is_some());

        // The decisive check: a back-reference into the previous member's bytes
        // must zero-fill rather than resurrect them.
        decoder.begin_file_decode(u64::MAX);
        decoder.window.copy_with_visible_len(4, 4, 4).unwrap();
        assert_eq!(decoder.window.try_copy_output(0, 4).unwrap(), [0, 0, 0, 0]);
    }

    #[test]
    fn solid_member_keeps_the_window_and_low_dist_state_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(0x40000);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"ABCD");
        decoder.tables_read = true;
        decoder.low_dist_rep_count = 5;
        decoder.prev_low_dist = 9;
        decoder.dist_cache = [7, 8, 9, 10];

        decoder.prepare_member(true, 0x40000).unwrap();

        assert_eq!(decoder.window.total_written(), 4);
        assert!(decoder.tables_read);
        assert_eq!(decoder.dist_cache, [7, 8, 9, 10]);
        // ReadTables30 owns these (unpack30.cpp:647-648), not UnpInitData30.
        assert_eq!(decoder.low_dist_rep_count, 5);
        assert_eq!(decoder.prev_low_dist, 9);

        // The window history is still reachable from the next member.
        decoder.begin_file_decode(u64::MAX);
        decoder.window.copy_with_visible_len(4, 4, 4).unwrap();
        assert_eq!(decoder.window.try_copy_output(4, 4).unwrap(), b"ABCD");
    }

    #[test]
    fn solid_member_cannot_grow_the_dictionary_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(0x40000);

        let err = decoder.prepare_member(true, 0x80000).unwrap_err();
        assert!(
            matches!(&err, RarError::CorruptArchive { detail } if detail.contains("solid stream window")),
            "{err:?}"
        );
        assert_eq!(decoder.window.dict_size(), 0x40000);

        // A non-solid member starts from an empty history, so it may grow.
        decoder.prepare_member(false, 0x80000).unwrap();
        assert_eq!(decoder.window.dict_size(), 0x80000);
    }

    #[test]
    fn vm_filter_block_of_exactly_vm_mem_size_emits_nothing_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(VM_MEM_SIZE * 2);
        decoder.begin_file_decode(u64::MAX);
        let chunk = vec![0xE8u8; 4096];
        for _ in 0..(VM_MEM_SIZE / chunk.len()) {
            decoder.window.put_bytes(&chunk);
        }
        decoder.window.put_bytes(b"TAIL");
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 0,
            block_length: VM_MEM_SIZE,
            // ReadVMCode seeds InitR[4] from BlockLength (unpack30.cpp:462),
            // so this is the register state a stream reaching this block size
            // without an init-mask override produces.
            init_regs: [0, 0, 0, 0, VM_MEM_SIZE as u32, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        // FilteredDataSize is InitR[4] & VM_MEMMASK, which is 0 here, but the
        // written border still jumps past the whole block.
        assert_eq!(out, b"TAIL");
        assert!(decoder.pending_vm_filters.is_empty());
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn queued_vm_filter_blocks_are_bounded_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.vm_filters.push(Rar4VmFilterDefinition {
            filter_type: Rar4StandardFilter::None,
            last_block_length: 1,
        });
        decoder.pending_vm_filters = vec![
            Rar4PendingVmFilter {
                filter_type: Rar4StandardFilter::None,
                block_start_total: 0,
                block_length: 1,
                init_regs: [0; 7],
            };
            MAX3_UNPACK_FILTERS + 1
        ];

        // first_byte 0x00: reuse the last slot, inherit its block length.
        let err = decoder.add_vm_code(0x00, &[0x00], 0).unwrap_err();

        assert!(
            matches!(&err, RarError::CorruptArchive { detail } if detail.contains("8192")),
            "{err:?}"
        );
    }

    #[test]
    fn truncated_vm_code_ends_the_member_without_an_error_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        let data = [0x00u8];
        let mut reader = BitReader::new(&data);
        reader.read_bits(4).unwrap();

        // Fewer than eight bits left: ReadVMCode returns false, which breaks
        // the unpack loop rather than failing the member.
        assert!(!decoder.read_vm_code(&mut reader, 0).unwrap());
    }

    #[test]
    fn test_direct_lz_helpers_apply_rar_behavior_minimum_window() {
        assert_eq!(effective_lz_dict_size(0).unwrap(), 0x40000);
        assert_eq!(effective_lz_dict_size(128 * 1024).unwrap(), 0x40000);
        assert_eq!(effective_lz_dict_size(512 * 1024).unwrap(), 512 * 1024);
    }

    #[test]
    fn test_insert_old_dist() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.insert_old_dist(100);
        assert_eq!(
            decoder.dist_cache,
            [100, usize::MAX, usize::MAX, usize::MAX]
        );
        decoder.insert_old_dist(200);
        assert_eq!(decoder.dist_cache, [200, 100, usize::MAX, usize::MAX]);
        decoder.insert_old_dist(300);
        assert_eq!(decoder.dist_cache, [300, 200, 100, usize::MAX]);
        decoder.insert_old_dist(400);
        assert_eq!(decoder.dist_cache, [400, 300, 200, 100]);
        decoder.insert_old_dist(500);
        assert_eq!(decoder.dist_cache, [500, 400, 300, 200]);
    }

    #[test]
    fn test_uninitialized_old_dist_zero_fills_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        let distance = decoder.dist_cache[0];

        decoder
            .window
            .copy_with_visible_len(distance, 3, 3)
            .unwrap();

        assert_eq!(decoder.window.try_copy_output(0, 3).unwrap(), [0, 0, 0]);
    }

    #[test]
    fn test_empty_input() {
        let result = decompress_rar4_lz(&[], 0, 4 * 1024 * 1024);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_dict_size_enforcement() {
        let result = decompress_rar4_lz(&[], 0, 1024 * 1024 * 1024);
        assert!(matches!(result, Err(RarError::DictionaryTooLarge { .. })));
    }

    #[test]
    fn test_length_tables() {
        // Verify length decode tables produce contiguous ranges.
        // Slot 0: base=0+3=3, extra=0, covers [3,4)
        // Slot 1: base=1+3=4, extra=0, covers [4,5)
        // ...
        let mut prev_end = LDECODE[0] as u32 + 3 + (1 << LBITS[0]); // end of slot 0
        for i in 1..LDECODE.len() {
            let base = LDECODE[i] as u32 + 3;
            assert_eq!(
                base, prev_end,
                "slot {i}: base {base} != prev_end {prev_end}"
            );
            prev_end = base + (1 << LBITS[i]);
        }
    }

    #[test]
    fn test_length_tables_cache_ref() {
        // Cache refs use +2 instead of +3.
        let mut prev_end = LDECODE[0] as u32 + 2 + (1 << LBITS[0]); // end of slot 0
        for i in 1..LDECODE.len() {
            let base = LDECODE[i] as u32 + 2;
            assert_eq!(
                base, prev_end,
                "slot {i}: base {base} != prev_end {prev_end}"
            );
            prev_end = base + (1 << LBITS[i]);
        }
    }

    #[test]
    fn test_execute_standard_delta_filter() {
        let filter = Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::Delta,
            block_start_total: 0,
            block_length: 4,
            init_regs: [1, 0, 0, 0, 4, 0, 0],
        };
        let mut data = vec![1u8, 2, 3, 4];
        let data_size = data.len();
        Rar4LzDecoder::execute_standard_filter(&filter, data_size, 0, &mut data, &mut Vec::new())
            .unwrap();
        assert_eq!(data, vec![255, 253, 250, 246]);
    }

    #[test]
    fn test_invalid_standard_filters_leave_block_unchanged_like_rar_behavior() {
        for (filter_type, data, init_regs) in [
            (Rar4StandardFilter::E8, vec![0xe8, 1, 2], [0; 7]),
            (Rar4StandardFilter::Itanium, vec![0x10; 20], [0; 7]),
            (Rar4StandardFilter::Delta, vec![1, 2, 3, 4], [0; 7]),
            (
                Rar4StandardFilter::Rgb,
                vec![1, 2, 3],
                [2, 0, 0, 0, 3, 0, 0],
            ),
            (Rar4StandardFilter::Audio, vec![1, 2, 3, 4], [0; 7]),
        ] {
            let filter = Rar4PendingVmFilter {
                filter_type,
                block_start_total: 0,
                block_length: data.len(),
                init_regs,
            };
            let expected = data.clone();
            let mut actual = data;
            let data_size = actual.len();

            Rar4LzDecoder::execute_standard_filter(
                &filter,
                data_size,
                0,
                &mut actual,
                &mut Vec::new(),
            )
            .unwrap();

            assert_eq!(actual, expected, "filter {filter_type:?}");
        }
    }

    #[test]
    fn test_vm_itanium_filter_advances_per_bundle_like_rar_behavior() {
        const W: usize = Rar4LzDecoder::ITANIUM_BUNDLE_WINDOW;
        fn window(data: &mut [u8], at: usize) -> &mut [u8; W] {
            (&mut data[at..at + W]).try_into().unwrap()
        }

        let mut data = vec![0u8; 48];
        data[16] = 0x10; // selects mask 4, which probes slot 2 in this bundle.
        Rar4LzDecoder::itanium_set_bits(window(&mut data, 16), 0x12345, 100, 20);
        Rar4LzDecoder::itanium_set_bits(window(&mut data, 16), 5, 124, 4);

        Rar4LzDecoder::execute_standard_filter(
            &Rar4PendingVmFilter {
                filter_type: Rar4StandardFilter::Itanium,
                block_start_total: 0,
                block_length: data.len(),
                init_regs: [0; 7],
            },
            data.len(),
            0,
            &mut data,
            &mut Vec::new(),
        )
        .unwrap();

        assert_eq!(
            Rar4LzDecoder::itanium_get_bits(window(&mut data, 0), 100, 20),
            0
        );
        assert_eq!(
            Rar4LzDecoder::itanium_get_bits(window(&mut data, 16), 100, 20),
            0x12344
        );
    }

    #[test]
    fn test_flush_ready_output_to_writer_applies_e8_filter() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(&[0xAA, 0xBB, 0xE8, 100, 0, 0, 0]);
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 2,
            block_length: 5,
            init_regs: [0, 0, 0, 0, 5, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0xE8, 97, 0, 0, 0]);
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    /// Same oracle rule as the RAR5 counterpart: `UnpWriteData` adds the whole
    /// span while still under the declared size, then early-returns on every
    /// later span, so a 2-byte member fed a 4-byte span freezes the counter at
    /// 4 rather than at 2 (unpack50.cpp:538-548, shared by v29).
    #[test]
    fn rar4_raw_span_past_member_boundary_freezes_the_counter_above_the_limit() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(2);
        let mut out = Vec::new();

        decoder.window.put_bytes(b"abcd");
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();
        decoder.window.put_bytes(b"efgh");
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"ab");
        assert_eq!(decoder.current_file_emitted, 2);
        assert_eq!(decoder.current_file_written_size, 4);
        assert_eq!(decoder.window.total_flushed(), 8);
    }

    #[test]
    fn test_filter_flush_respects_hidden_match_tail() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"ABCD");
        decoder.window.mark_flushed(4);
        // The test pre-marks ABCD as flushed, so mirror the logical
        // written-file size for those already-emitted bytes.
        decoder.current_file_written_size = 4;
        decoder.window.copy_with_visible_len(4, 4, 2).unwrap();
        decoder.window.put_bytes(&[0xE8, 100, 0, 0, 0]);
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 8,
            block_length: 5,
            init_regs: [0, 0, 0, 0, 5, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        // Two of the four prefix bytes are hidden, so only `AB` is emitted --
        // but `WrittenFileSize` advances by the whole span the write layer was
        // handed, not by the part that reached the writer (`WrittenFileSize+=Size`,
        // unpack50.cpp:547). The filter behind the prefix therefore runs with
        // `R[6] == 8`, and the E8 record at file offset 1 is rewritten to
        // `100 - (1 + 8) == 91`.
        assert_eq!(out, vec![b'A', b'B', 0xE8, 91, 0, 0, 0]);
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_filterless_flush_respects_hidden_match_tail() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"ABCD");
        decoder.window.mark_flushed(4);
        decoder.window.copy_with_visible_len(4, 4, 2).unwrap();

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"AB");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_incomplete_final_vm_filter_defers_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"abcdef");
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 3,
            block_length: 4,
            init_regs: [0, 0, 0, 0, 4, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"abc");
        assert_eq!(decoder.window.total_flushed(), 3);
        assert_eq!(decoder.pending_vm_filters.len(), 1);
    }

    #[test]
    fn test_none_vm_filter_emits_zero_bytes_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"prefixBLOCKsuffix");
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::None,
            block_start_total: 6,
            block_length: 5,
            init_regs: [0; 7],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"prefixsuffix");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    /// D5: a filter block spanning nearly the whole dictionary pins the write
    /// border for its entire length. The decode loop must ride that out in
    /// place instead of yielding to a caller that has nothing to flush.
    #[test]
    fn border_pinned_filter_block_does_not_re_enter_the_lz_loop_per_symbol() {
        const DICT: usize = 1024;
        const BLOCK: usize = 1000;

        let mut decoder = Rar4LzDecoder::new(DICT);
        // A single 1-bit code for symbol 0, so every zero bit decodes to one
        // literal byte and the stream below is a pure literal run.
        let mut ld_lengths = vec![0u8; NC];
        ld_lengths[0] = 1;
        decoder.ld_table = Some(HuffmanTable::build(&ld_lengths).unwrap());
        decoder.begin_file_decode(u64::MAX);

        // The block starts exactly at the write border and ends past anything
        // this round can produce: the flush border cannot move until the whole
        // block is decoded.
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 0,
            block_length: BLOCK,
            init_regs: [0, 0, 0, 0, (BLOCK) as u32, 0, 0],
        });
        assert!(
            decoder.flush_is_pinned_by_pending_head(),
            "an undecoded head block starting at the border must pin the flush"
        );

        let input = vec![0u8; BLOCK.div_ceil(8) + 32];
        let mut reader = BitReader::new(&input);
        let mut out = Vec::new();

        // The shape of the real decode loop, with a deliberately tiny flush
        // threshold so every symbol would have yielded before this fix.
        let mut output_size = 0u64;
        while output_size < BLOCK as u64 {
            let before = output_size;
            output_size = decoder
                .decode_lz_symbols(&mut reader, BLOCK as u64, output_size, Some(64))
                .expect("border-pinned decode must not fail");
            decoder
                .flush_ready_output_to_writer(&mut out, false)
                .expect("flush during a pinned border must not fail");
            assert!(
                output_size > before,
                "decode made no progress: {output_size} bytes after {} calls",
                decoder.decode_lz_calls
            );
        }

        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .expect("final flush must not fail");

        // The whole block decoded, and the E8 filter over an all-zero block is
        // a no-op, so every byte comes back.
        assert_eq!(output_size, BLOCK as u64);
        assert_eq!(out.len(), BLOCK);
        assert!(out.iter().all(|&b| b == 0));

        // The point of the fix: the pinned stretch is decoded in place. Per
        // symbol re-entry would be BLOCK (1000) calls.
        assert!(
            decoder.decode_lz_calls <= 4,
            "border-pinned decode re-entered {} times for {BLOCK} symbols",
            decoder.decode_lz_calls
        );

        // Once the block is fully decoded the pin releases, so ordinary
        // threshold yielding is restored.
        assert!(!decoder.flush_is_pinned_by_pending_head());
    }

    /// D4: the drain reads only the queue head, which is sound because valid
    /// streams queue filters in non-decreasing start order. A corrupt stream
    /// can still queue a start that moves backwards; it must be dropped by the
    /// `next_start < written_border` arm rather than panic or corrupt output.
    #[test]
    fn out_of_order_filter_start_is_dropped_instead_of_panicking() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"prefixBLOCKsuffix");

        // Queued directly: `add_vm_code` cannot produce this order from a
        // well-formed stream, so this stands in for a corrupt archive.
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::None,
            block_start_total: 6,
            block_length: 5,
            init_regs: [0; 7],
        });
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 2, // behind the filter already queued.
            block_length: 4,
            init_regs: [0, 0, 0, 0, 4, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .expect("out-of-order filter start must not fail the member");

        // The first filter still suppresses its block; the stale one is
        // dropped once the border has passed it, and everything drains.
        assert_eq!(out, b"prefixsuffix");
        assert!(decoder.pending_vm_filters.is_empty());
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_chunked_flush_applies_e8_filter() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(&[0xAA, 0xBB, 0xE8, 100, 0, 0, 0]);
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 2,
            block_length: 5,
            init_regs: [0, 0, 0, 0, 5, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, false)
            .unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0xE8, 97, 0, 0, 0]);
        assert!(decoder.pending_vm_filters.is_empty());
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_vm_none_filter_suppresses_block_like_current_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"prefixBLOCKsuffix");
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::None,
            block_start_total: 6,
            block_length: 5,
            init_regs: [0; 7],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();
        assert_eq!(out, b"prefixsuffix");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_vm_none_filter_discards_stale_same_start_filter_like_current_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"prefixBLOCKsuffix");
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::None,
            block_start_total: 6,
            block_length: 5,
            init_regs: [0; 7],
        });
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 6,
            block_length: 5,
            init_regs: [0, 0, 0, 0, 5, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"prefixsuffix");
        assert!(decoder.pending_vm_filters.is_empty());
    }

    fn rar_rgb_filter_reference(input: &[u8], width: usize, pos_r: usize) -> Vec<u8> {
        let mut output = vec![0u8; input.len()];
        let mut src_pos = 0usize;
        for channel in 0..3 {
            let mut prev_byte = 0u32;
            let mut index = channel;
            while index < input.len() {
                let predicted = if index >= width + 3 {
                    let upper = u32::from(output[index - width]);
                    let upper_left = u32::from(output[index - width - 3]);
                    let mut predicted = prev_byte.wrapping_add(upper).wrapping_sub(upper_left);
                    let pa = (predicted.wrapping_sub(prev_byte) as i32).abs();
                    let pb = (predicted.wrapping_sub(upper) as i32).abs();
                    let pc = (predicted.wrapping_sub(upper_left) as i32).abs();
                    if pa <= pb && pa <= pc {
                        predicted = prev_byte;
                    } else if pb <= pc {
                        predicted = upper;
                    } else {
                        predicted = upper_left;
                    }
                    predicted
                } else {
                    prev_byte
                };
                let decoded = (predicted as u8).wrapping_sub(input[src_pos]);
                output[index] = decoded;
                prev_byte = u32::from(decoded);
                src_pos += 1;
                index += 3;
            }
        }

        let mut index = pos_r;
        let border = input.len().saturating_sub(2);
        while index < border {
            let green = output[index + 1];
            output[index] = output[index].wrapping_add(green);
            output[index + 2] = output[index + 2].wrapping_add(green);
            index += 3;
        }
        output
    }

    #[test]
    fn test_vm_rgb_filter_keeps_predictor_wide_like_rar_behavior() {
        let mut data = [0xff, 0xff, 0xff, 0x01, 0x02, 0x03].repeat(16);
        let expected = rar_rgb_filter_reference(&data, 1, 0);
        Rar4LzDecoder::execute_standard_filter(
            &Rar4PendingVmFilter {
                filter_type: Rar4StandardFilter::Rgb,
                block_start_total: 0,
                block_length: data.len(),
                init_regs: [4, 0, 0, 0, 0, 0, 0],
            },
            data.len(),
            0,
            &mut data,
            &mut Vec::new(),
        )
        .unwrap();

        assert_eq!(data, expected);
        assert_eq!(
            &data[6..18],
            &[3, 0, 252, 255, 253, 251, 254, 254, 253, 252, 255, 253]
        );
    }

    fn rar_audio_filter_reference(input: &[u8], channels: usize) -> Vec<u8> {
        let mut output = vec![0u8; input.len()];
        let mut src_pos = 0usize;
        for channel in 0..channels {
            let mut prev_byte = 0u32;
            let mut prev_delta = 0i32;
            let mut dif = [0i32; 7];
            let (mut d1, mut d2) = (0i32, 0i32);
            let (mut k1, mut k2, mut k3) = (0i32, 0i32, 0i32);
            let mut byte_count = 0usize;
            let mut index = channel;

            while index < input.len() {
                let d3 = d2;
                d2 = prev_delta - d1;
                d1 = prev_delta;

                let predicted = 8u32
                    .wrapping_mul(prev_byte)
                    .wrapping_add((k1 * d1) as u32)
                    .wrapping_add((k2 * d2) as u32)
                    .wrapping_add((k3 * d3) as u32)
                    >> 3
                    & 0xff;
                let cur_byte = input[src_pos];
                src_pos += 1;
                let decoded_raw = predicted.wrapping_sub(u32::from(cur_byte));
                let decoded = decoded_raw as u8;
                output[index] = decoded;
                prev_delta = (decoded_raw.wrapping_sub(prev_byte) as u8) as i8 as i32;
                prev_byte = decoded_raw;

                let d = (cur_byte as i8 as i32) << 3;
                dif[0] += d.abs();
                dif[1] += (d - d1).abs();
                dif[2] += (d + d1).abs();
                dif[3] += (d - d2).abs();
                dif[4] += (d + d2).abs();
                dif[5] += (d - d3).abs();
                dif[6] += (d + d3).abs();

                if (byte_count & 0x1f) == 0 {
                    let mut min_dif = dif[0];
                    let mut min_index = 0usize;
                    dif[0] = 0;
                    for (candidate, value) in dif.iter_mut().enumerate().skip(1) {
                        if *value < min_dif {
                            min_dif = *value;
                            min_index = candidate;
                        }
                        *value = 0;
                    }
                    match min_index {
                        1 if k1 >= -16 => k1 -= 1,
                        2 if k1 < 16 => k1 += 1,
                        3 if k2 >= -16 => k2 -= 1,
                        4 if k2 < 16 => k2 += 1,
                        5 if k3 >= -16 => k3 -= 1,
                        6 if k3 < 16 => k3 += 1,
                        _ => {}
                    }
                }

                byte_count += 1;
                index += channels;
            }
        }
        output
    }

    #[test]
    fn test_vm_audio_filter_uses_signed_delta_for_adaptation_like_rar_behavior() {
        let mut data = [0xff, 0x00, 0x80, 0x7f].repeat(24);
        let expected = rar_audio_filter_reference(&data, 1);
        Rar4LzDecoder::execute_standard_filter(
            &Rar4PendingVmFilter {
                filter_type: Rar4StandardFilter::Audio,
                block_start_total: 0,
                block_length: data.len(),
                init_regs: [1, 0, 0, 0, 0, 0, 0],
            },
            data.len(),
            0,
            &mut data,
            &mut Vec::new(),
        )
        .unwrap();

        assert_eq!(data, expected);
        assert_eq!(&data[32..40], &[17, 33, 162, 17, 47, 36, 158, 47]);
    }

    #[test]
    fn test_vm_filter_rejects_oversized_block_before_copy() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);

        let chunk = vec![0u8; 1024];
        for _ in 0..(VM_MEM_SIZE + 1).div_ceil(chunk.len()) {
            decoder.window.put_bytes(&chunk);
        }
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 0,
            block_length: VM_MEM_SIZE + 1,
            init_regs: [0, 0, 0, 0, (VM_MEM_SIZE + 1) as u32, 0, 0],
        });

        let mut out = Vec::new();
        let err = decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap_err();
        assert!(matches!(
            err,
            RarError::CorruptArchive { detail } if detail.contains("exceeds maximum")
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn test_vm_filter_reset_clears_pending_state() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.vm_filters.push(Rar4VmFilterDefinition {
            filter_type: Rar4StandardFilter::Delta,
            last_block_length: 8,
        });
        decoder.last_vm_filter = 3;
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::Delta,
            block_start_total: 12,
            block_length: 8,
            init_regs: [1, 0, 0, 0, 8, 0, 0],
        });

        decoder.reset_vm_filter_state();

        assert!(decoder.pending_vm_filters.is_empty());
        assert!(decoder.vm_filters.is_empty());
        assert_eq!(decoder.last_vm_filter, 0);
    }

    #[test]
    fn test_new_vm_filter_definition_starts_with_zero_block_length() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.ensure_vm_filter_definition(0, true);

        assert_eq!(decoder.vm_filters.len(), 1);
        assert_eq!(decoder.vm_filters[0].filter_type, Rar4StandardFilter::None);
        assert_eq!(decoder.vm_filters[0].last_block_length, 0);
    }

    #[test]
    fn test_custom_vm_program_becomes_none_filter_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        // first_byte: new filter definition with explicit block length.
        // VM data: slot=0, start=0, length=1, code_size=1, code=[0].
        // The one-byte program is not one of the standard-filter programs.
        decoder
            .add_vm_code(0xA0, &[0x00, 0x00, 0x41, 0x00], 0)
            .unwrap();

        assert_eq!(decoder.vm_filters.len(), 1);
        assert_eq!(decoder.vm_filters[0].filter_type, Rar4StandardFilter::None);
        assert_eq!(decoder.pending_vm_filters.len(), 1);
        assert_eq!(
            decoder.pending_vm_filters[0].filter_type,
            Rar4StandardFilter::None
        );
    }

    #[test]
    fn test_vm_program_body_must_fit_filter_packet_like_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        // Same packet shape as test_custom_vm_program_becomes_none_filter,
        // but the declared one-byte program body is missing, so the packet
        // fails the VMCodeInp.InAddr + VMCodeSize > CodeSize guard.
        let err = decoder
            .add_vm_code(0xA0, &[0x00, 0x00, 0x41], 0)
            .unwrap_err();

        assert!(matches!(err, RarError::CorruptArchive { .. }));
        assert!(decoder.pending_vm_filters.is_empty());
    }

    #[test]
    fn test_custom_vm_program_suppresses_filtered_block_like_current_rar_behavior() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"ABCD");

        // Only recognized standard filters execute. Non-standard bytecode
        // remains VMSF_NONE, leaving FilteredDataSize == 0, so the covered block
        // is suppressed.
        decoder
            .add_vm_code(0xA0, &[0x00, 0x00, 0x41, 0x00], 0)
            .unwrap();

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, b"BCD");
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    #[test]
    fn test_vm_filter_file_offset_uses_filtered_written_size_after_suppressed_block() {
        let mut decoder = Rar4LzDecoder::new(1024);
        decoder.begin_file_decode(u64::MAX);
        decoder.window.put_bytes(b"XXXXX");
        decoder.window.put_bytes(&[0xE8, 100, 0, 0, 0]);

        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::None,
            block_start_total: 0,
            block_length: 5,
            init_regs: [0; 7],
        });
        decoder.pending_vm_filters.push(Rar4PendingVmFilter {
            filter_type: Rar4StandardFilter::E8,
            block_start_total: 5,
            block_length: 5,
            init_regs: [0, 0, 0, 0, 5, 0, 0],
        });

        let mut out = Vec::new();
        decoder
            .flush_ready_output_to_writer(&mut out, true)
            .unwrap();

        assert_eq!(out, vec![0xE8, 99, 0, 0, 0]);
        assert_eq!(decoder.current_file_written_size, 5);
        assert_eq!(
            decoder.window.total_flushed(),
            decoder.window.total_written()
        );
    }

    // ---------------------------------------------------------------
    // Leased-span fast path vs. retained per-symbol path.
    //
    // `run_fast_symbols` and the per-symbol tail of `decode_lz_symbols` are two
    // implementations of the same arms, so they have to be pinned against each
    // other permanently. These tests decode real rar3/rar4 LZ fixtures through
    // both and require byte-identical output and identical error behaviour,
    // under conditions the corpus does not reach on its own:
    //
    //   * forced small dictionaries, so the ring wraps continuously and the
    //     batched literal store's wrap handling is exercised (sizes that are
    //     and are not multiples of eight put the boundary at both phases);
    //   * forced small input fills, so the span border — and with it the
    //     handover to the per-symbol path, `seek_to_buffer_bit`'s commit
    //     arithmetic and the accumulator-straddling-two-fills decline — recurs
    //     every few dozen bytes instead of once per member.

    /// rar3/rar4 LZ fixtures covering plain, solid, multi-member, RAR 2.0,
    /// VM-filtered and multi-block streams.
    const LZ_PATH_FIXTURES: &[&str] = &[
        "rar4_lz.rar",
        "rar4_solid.rar",
        "rar4_lz_solid_mv.rar",
        "rar4_multifile_lz.rar",
        "rar20_lz.rar",
        "test_read_format_rar_filter.rar",
        "test_read_format_rar_multi_lzss_blocks.rar",
    ];

    /// Every member of `filename`, decoded with verification off.
    ///
    /// Verification is off deliberately: a forced small dictionary produces
    /// output that legitimately fails the archive's checksum, and comparing
    /// two identical "checksum mismatch" errors would not discriminate between
    /// the paths. Comparing the bytes does.
    /// Existence is the wrong guard under partial Git LFS hydration (see
    /// stored_layout.rs): the no-fixture CI lane checks fixtures out as
    /// pointer stubs, which exist and then fail the signature parse. A
    /// hydrated RAR fixture starts with `Rar!`.
    fn fixture_hydrated(filename: &str) -> bool {
        use std::io::Read;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar4")
            .join(filename);
        let Ok(mut file) = std::fs::File::open(&path) else {
            return false;
        };
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).is_ok() && &magic == b"Rar!"
    }

    fn fixtures_hydrated(filenames: &[&str]) -> bool {
        if filenames.iter().all(|name| fixture_hydrated(name)) {
            return true;
        }
        eprintln!("skipping test: rar4 fixtures not hydrated (LFS pointers)");
        false
    }

    fn decode_members(filename: &str) -> Vec<Result<Vec<u8>, String>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar4")
            .join(filename);
        let data =
            std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let mut archive = crate::RarArchive::open(std::io::Cursor::new(data))
            .unwrap_or_else(|err| panic!("open {filename}: {err}"));
        let options = crate::ExtractOptions {
            verify: false,
            ..Default::default()
        };

        (0..archive.metadata().members.len())
            .map(|index| {
                archive
                    .extract_member(index, &options, None)
                    .and_then(|member| member.into_bytes())
                    .map_err(|err| err.to_string())
            })
            .collect()
    }

    /// Expected bytes for `rar4_vm_initr4_override.rar`, straight from the
    /// unrar 7.20 binary (`tests/fixtures/generate_vm_fidelity.py` stamps the
    /// same bytes' CRC32 into the archive's file headers).
    ///
    /// Every member queues one VM filter over the same 64-byte block, and each
    /// one drives `InitR[4]` somewhere the staged block length cannot reach:
    ///
    /// * `e8-shorter` — `R[4] = 16`, so the E8/E9 transform stops after 16
    ///   bytes and only 16 are emitted; the two rewritten addresses are the
    ///   markers at offsets 2 and 8.
    /// * `e8-oversize` — `R[4] = 0x40010` exceeds `VM_MEMSIZE`, so
    ///   `ExecuteStandardFilter` returns immediately (rarvm.cpp:129-130) and
    ///   the untouched first `0x40010 & VM_MEMMASK == 16` bytes go out.
    /// * `delta-shorter` — `R[4] = 32` with two channels, so the delta runs
    ///   over half the block and emits the 32-byte result from `Mem+BlockSize`.
    /// * `delta-oversize` — `R[4] = 0x40008` exceeds `VM_MEMSIZE/2`, so the
    ///   filter fails and `FilteredData` falls back to `Mem` itself
    ///   (rarvm.cpp:31-34): 8 raw bytes.
    const VM_INITR4_EXPECTED: &[(&str, &[u8])] = &[
        (
            "e8-shorter.bin",
            &[
                0x40, 0x41, 0xE8, 0x0D, 0x00, 0x00, 0x00, 0x47, 0xE8, 0x17, 0x00, 0x00, 0x00, 0x4D,
                0x4E, 0x4F,
            ],
        ),
        (
            "e8-oversize.bin",
            &[
                0x40, 0x41, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x47, 0xE8, 0x20, 0x00, 0x00, 0x00, 0x4D,
                0x4E, 0x4F,
            ],
        ),
        (
            "delta-shorter.bin",
            &[
                0xC0, 0xB0, 0x7F, 0x5F, 0x97, 0x0D, 0x87, 0xBA, 0x87, 0x66, 0x87, 0x11, 0x87, 0xBB,
                0x40, 0x64, 0x58, 0x0C, 0x38, 0xB3, 0x38, 0x59, 0x38, 0xFE, 0x38, 0xA2, 0xEB, 0x45,
                0x9D, 0x5D, 0x4E, 0x2D,
            ],
        ),
        (
            "delta-oversize.bin",
            &[0x40, 0x41, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x47],
        ),
    ];

    /// The `InitR[4]` init-mask override decides both the transform width and
    /// the emitted size, independently of the staged block (review item V7).
    #[test]
    fn vm_filter_honors_initr4_override_like_rar_behavior() {
        const FIXTURE: &str = "rar4_vm_initr4_override.rar";
        if !fixtures_hydrated(&[FIXTURE]) {
            return;
        }

        let members = decode_members(FIXTURE);
        assert_eq!(members.len(), VM_INITR4_EXPECTED.len());
        for (member, (name, expected)) in members.iter().zip(VM_INITR4_EXPECTED) {
            let bytes = member
                .as_ref()
                .unwrap_or_else(|err| panic!("{name} failed to decode: {err}"));
            assert_eq!(bytes.as_slice(), *expected, "{name}");
        }
    }

    // The `rar4_vm_output_bounds.rar` fixture that drove
    // `vm_filtered_output_is_bounded_at_the_write_layer_like_rar_behavior` and
    // `filter_queued_ahead_of_the_window_does_not_stall_the_flush` was
    // hand-assembled: RARLAB's writer never emits a filter block that overruns
    // the declared member size, so no legitimate tool could produce it. Fixtures
    // are created by RARLAB tooling or imported unmodified from a public
    // upstream, and nothing else, so the fixture and both tests are gone. The
    // write-layer bounds and the flush drain they covered are still exercised by
    // the VM tests above and by the real filtered archives in the imported
    // corpus.

    /// A solid member that changes unpack version keeps reading the previous
    /// member's dictionary (review item G5).
    ///
    /// The fixture's second member is RAR 2.9 and solid behind a RAR 2.0
    /// member; its very first symbol is a 19-byte match at distance 32, which
    /// lands entirely inside what the RAR 2.0 member decoded. unrar serves both
    /// methods from one `Unpack` object (unpack.cpp:154-190) and
    /// `UnpInitData(true)` keeps its `Window` (unpack.cpp:194-206), so those 19
    /// bytes are the earlier member's tail — not zeroes from a fresh window.
    #[test]
    fn solid_unpack_version_switch_keeps_the_window_like_rar_behavior() {
        const FIXTURE: &str = "rar4_version_switch_solid.rar";
        if !fixtures_hydrated(&[FIXTURE]) {
            return;
        }

        let first: Vec<u8> = (0x61u8..0x61 + 64).collect();
        let mut expected_second = first[32..32 + 19].to_vec();
        expected_second.extend_from_slice(&[0x30, 0x31, 0x32, 0x33, 0x34]);

        let members = decode_members(FIXTURE);
        assert_eq!(members.len(), 2);
        assert_eq!(
            members[0].as_ref().expect("v20 member decodes").as_slice(),
            first.as_slice()
        );
        assert_eq!(
            members[1]
                .as_ref()
                .expect("solid v29 member decodes")
                .as_slice(),
            expected_second.as_slice()
        );
    }

    /// Thread widths the split is pinned at, alongside the two serial paths.
    ///
    /// The split is one decode thread plus the calling apply thread, so 2 and 4
    /// drive the same two threads; both are pinned anyway so that a future
    /// width-dependent change cannot land without moving this list.
    const MT_WIDTHS: &[usize] = &[2, 4];

    /// Decode `filename` down all three paths and require them to agree exactly.
    ///
    /// The three are the per-symbol reference path, the leased-span path
    /// writing straight into the window, and the leased-span path decoding on a
    /// worker while this thread applies. Every caller passes fixtures whose
    /// window sizes and fill caps put the comparison on the forced-wrap and
    /// lease-border seams, so all three are pinned there too.
    /// Returns whether the threaded runs actually leased a span.
    ///
    /// Not every (fixture, setting) pair can: `rar20_lz.rar` is decoded by the
    /// RAR 2.0 engine, which has no leased-span path at all, and a fill cap
    /// near [`LZ_SPAN_SLACK_BYTES`] leaves too little contiguous input to lend.
    /// The callers therefore require that the split engaged *somewhere* in
    /// their sweep rather than everywhere in it, which keeps the requirement
    /// honest without pinning it to a fixture list.
    ///
    /// [`LZ_SPAN_SLACK_BYTES`]: super::super::lz::bitstream::LZ_SPAN_SLACK_BYTES
    fn assert_paths_agree(filename: &str, label: &str) -> bool {
        // Serial, so a stray thread-local from an earlier `with_mt_threads`
        // cannot make "fast-direct" secretly mean "fast-MT".
        let fast = super::mt_test_hooks::with_mt_threads(1, || decode_members(filename));
        let reference = super::super::lz::bitstream::test_hooks::without_lz_span(|| {
            super::mt_test_hooks::with_mt_threads(1, || decode_members(filename))
        });
        assert_eq!(
            fast, reference,
            "{filename} [{label}]: leased-span output differs from the \
             per-symbol path"
        );
        assert!(
            !fast.is_empty(),
            "{filename} [{label}]: fixture decoded no members, so the \
             comparison proved nothing"
        );

        // The full-size batch (0x4100 records) is never filled by a fixture
        // this small, so a run at the shipped size would never cross the
        // hand-off boundary and the recycling protocol would go untested. 3 and
        // 17 cross it constantly, on and off the eight-literal batch boundary;
        // the shipped size is run too so the common path is not left out.
        let mut leased = false;
        for &batch in &[super::RAR4_MT_BATCH_ITEMS, 3, 17] {
            for &threads in MT_WIDTHS {
                let before = super::mt_test_hooks::mt_lease_count();
                let threaded = super::mt_test_hooks::with_mt_batch_items(batch, || {
                    super::mt_test_hooks::with_mt_threads(threads, || decode_members(filename))
                });
                assert_eq!(
                    threaded, fast,
                    "{filename} [{label}]: {threads}-thread apply with \
                     {batch}-record batches differs from the leased-span direct \
                     write"
                );
                leased |= super::mt_test_hooks::mt_lease_count() > before;
            }
        }
        leased
    }

    /// The subset used for the exhaustive sweeps below.
    ///
    /// Every stream shape in [`LZ_PATH_FIXTURES`] except `rar4_solid.rar`,
    /// whose 85 MB of packed data would dominate the suite's runtime without
    /// adding a shape — `rar4_lz_solid_mv.rar` is also solid, at 1/400th the
    /// size. The sweeps decode each of these once per path per setting, so
    /// keeping them small is what makes the full cross-product affordable.
    const LZ_PATH_SWEEP_FIXTURES: &[&str] = &[
        "rar4_lz.rar",
        "rar4_lz_solid_mv.rar",
        "rar4_multifile_lz.rar",
        "rar20_lz.rar",
        "test_read_format_rar_filter.rar",
        "test_read_format_rar_multi_lzss_blocks.rar",
    ];

    #[test]
    fn fast_and_per_symbol_paths_agree_on_lz_fixtures() {
        if !fixtures_hydrated(LZ_PATH_FIXTURES) {
            return;
        }
        let mut leased = false;
        for filename in LZ_PATH_FIXTURES {
            leased |= assert_paths_agree(filename, "native dictionary");
        }
        assert!(leased, "the threaded path never engaged in this sweep");
    }

    #[test]
    fn fast_and_per_symbol_paths_agree_when_the_window_wraps() {
        if !fixtures_hydrated(LZ_PATH_SWEEP_FIXTURES) {
            return;
        }
        // 12288 is a multiple of the eight-literal batch, 6151 and 65537 are
        // not, so the ring boundary lands both on and between batch stores.
        let mut leased = false;
        for window in [12288u64, 6151, 65537] {
            for filename in LZ_PATH_SWEEP_FIXTURES {
                super::super::rar4_old::with_rar4_window_size(window, || {
                    leased |= assert_paths_agree(filename, &format!("window={window}"));
                });
            }
        }
        assert!(leased, "the threaded path never engaged in this sweep");
    }

    #[test]
    fn fast_and_per_symbol_paths_agree_across_span_borders() {
        if !fixtures_hydrated(LZ_PATH_SWEEP_FIXTURES) {
            return;
        }
        // A leased span reserves LZ_SPAN_SLACK_BYTES (32), so a fill of 40
        // leaves only 8 bytes of fast path per fill and hands over constantly;
        // 33 is the smallest fill that can still be leased at all; 97 is odd,
        // so the border lands at a different bit phase each time; and 16 is
        // below the slack, which declines every lease and must still decode
        // correctly.
        let mut leased = false;
        for fill in [16usize, 33, 40, 97] {
            for filename in LZ_PATH_SWEEP_FIXTURES {
                super::super::lz::bitstream::test_hooks::with_fill_cap(fill, || {
                    leased |= assert_paths_agree(filename, &format!("fill={fill}"));
                });
            }
        }
        // The whole point of this sweep for the threaded path: a span border
        // every few dozen bytes means a decode thread per lease, so the
        // handover itself is what is under test.
        assert!(leased, "the threaded path never engaged in this sweep");
    }

    #[test]
    fn span_border_handover_preserves_the_native_decode() {
        if !fixtures_hydrated(LZ_PATH_SWEEP_FIXTURES) {
            return;
        }
        // The tests above pin the two paths against each other; this one pins
        // both against the archive's own checksum. Whatever the fill size, the
        // bytes must still be the ones the native full-fill decode produces —
        // so a lease/commit bug that corrupted both paths identically cannot
        // pass unnoticed.
        for filename in LZ_PATH_SWEEP_FIXTURES {
            let native = super::mt_test_hooks::with_mt_threads(1, || decode_members(filename));
            for fill in [16usize, 40, 97, 4096] {
                let capped = super::super::lz::bitstream::test_hooks::with_fill_cap(fill, || {
                    super::mt_test_hooks::with_mt_threads(1, || decode_members(filename))
                });
                assert_eq!(
                    native, capped,
                    "{filename}: decoding with {fill}-byte fills changed the output"
                );
                let per_symbol =
                    super::super::lz::bitstream::test_hooks::with_fill_cap(fill, || {
                        super::super::lz::bitstream::test_hooks::without_lz_span(|| {
                            super::mt_test_hooks::with_mt_threads(1, || decode_members(filename))
                        })
                    });
                assert_eq!(
                    native, per_symbol,
                    "{filename}: per-symbol decoding with {fill}-byte fills \
                     changed the output"
                );
                for &threads in MT_WIDTHS {
                    let threaded =
                        super::super::lz::bitstream::test_hooks::with_fill_cap(fill, || {
                            super::mt_test_hooks::with_mt_threads(threads, || {
                                decode_members(filename)
                            })
                        });
                    assert_eq!(
                        native, threaded,
                        "{filename}: {threads}-thread decoding with {fill}-byte \
                         fills changed the output"
                    );
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Threaded decode/apply split.
    //
    // The equivalence sweeps above already pin the split's output against both
    // serial paths, at every window size and fill cap they exercise. What is
    // left is what those sweeps cannot see: that the split actually engages,
    // that it hands the window over cleanly at an LZ/PPMd transition, and that
    // a member which fails mid-stream fails the same way — and terminates — no
    // matter how many threads were asked for.

    /// Run `body` on its own thread and fail if it has not finished in time.
    ///
    /// Every threaded-path test goes through this. The split's failure mode is
    /// not a wrong answer but a stalled one — a decode thread parked on a
    /// channel nobody drains, or a hand-back parked on a channel nobody
    /// empties — and a plain `assert_eq!` cannot see that. The guard is
    /// deliberately generous: it is there to turn a hang into a failure, not to
    /// measure anything.
    fn with_timeout<T: Send + 'static>(
        seconds: u64,
        what: &str,
        body: impl FnOnce() -> T + Send,
    ) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let _ = tx.send(body());
            });
            match rx.recv_timeout(std::time::Duration::from_secs(seconds)) {
                Ok(value) => value,
                Err(_) => panic!("{what}: did not finish within {seconds}s — the split stalled"),
            }
        })
    }

    /// A member that fails must fail identically on all three paths, and end.
    ///
    /// Both halves of the split can be the one that notices: the apply side
    /// raises window errors, the decode thread runs the span out afterwards.
    /// The error the caller sees has to be the apply side's either way, and the
    /// run has to terminate — which is what the timeout guard is for.
    #[test]
    fn corrupt_members_fail_identically_on_every_path() {
        if !fixtures_hydrated(LZ_PATH_SWEEP_FIXTURES) {
            return;
        }
        // Fixtures whose members do not all decode cleanly; the comparison is
        // over the `Err(String)` surface `decode_members` already produces.
        for filename in LZ_PATH_SWEEP_FIXTURES {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/rar4")
                .join(filename);
            let data = std::fs::read(&path).unwrap();

            // Truncating the packed data mid-member forces a decode that runs
            // out of input, and truncating at several points reaches different
            // failure sites (table read, symbol loop, filter block).
            for numerator in [2usize, 3, 5, 7] {
                let cut = data.len() * numerator / 8;
                if cut == 0 {
                    continue;
                }
                let truncated = data[..cut].to_vec();

                let serial =
                    super::mt_test_hooks::with_mt_threads(1, || decode_bytes_members(&truncated));
                for &batch in &[super::RAR4_MT_BATCH_ITEMS, 3] {
                    for &threads in MT_WIDTHS {
                        let input = truncated.clone();
                        let what = format!(
                            "{filename} truncated to {cut}, {threads} threads, batch {batch}"
                        );
                        let threaded = with_timeout(120, &what, || {
                            super::mt_test_hooks::with_mt_batch_items(batch, || {
                                super::mt_test_hooks::with_mt_threads(threads, || {
                                    decode_bytes_members(&input)
                                })
                            })
                        });
                        assert_eq!(
                            serial, threaded,
                            "{what}: error surface differs from serial"
                        );
                    }
                }
            }
        }
    }

    /// The recycling protocol must survive many leases and many hand-offs.
    ///
    /// This is the shape that hung: buffers accumulated across leases until the
    /// carried-over set outgrew the recycling channel, and the next lease's
    /// priming send — issued before the decode thread existed — blocked with no
    /// receiver running. It also covers filling on top of a handed-back buffer,
    /// which silently re-applied a whole batch. A small fill cap gives many
    /// leases and a three-record batch gives many hand-offs per lease, so both
    /// are hammered together.
    #[test]
    fn many_leases_and_hand_offs_neither_stall_nor_duplicate() {
        if !fixtures_hydrated(&[
            "rar4_lz.rar",
            "rar4_lz_solid_mv.rar",
            "rar4_multifile_lz.rar",
        ]) {
            return;
        }
        for filename in [
            "rar4_lz.rar",
            "rar4_lz_solid_mv.rar",
            "rar4_multifile_lz.rar",
        ] {
            let expected = super::mt_test_hooks::with_mt_threads(1, || decode_members(filename));
            // `None` is the production 512 KiB fill: a lease then covers a whole
            // buffer, so a small batch hands off thousands of times inside one
            // lease and the recycled set carried to the *next* lease is at its
            // largest. That combination — a full fill and a small batch — is
            // what overflowed the recycling channel and stalled the priming
            // send; the capped fills add the many-leases dimension instead.
            for fill in [None, Some(64usize), Some(512)] {
                for batch in [1usize, 3, 8] {
                    let what = format!("{filename} fill={fill:?} batch={batch}");
                    let run = || {
                        super::mt_test_hooks::with_mt_batch_items(batch, || {
                            super::mt_test_hooks::with_mt_threads(2, || decode_members(filename))
                        })
                    };
                    let got = with_timeout(180, &what, || match fill {
                        Some(bytes) => {
                            super::super::lz::bitstream::test_hooks::with_fill_cap(bytes, run)
                        }
                        None => run(),
                    });
                    assert_eq!(expected, got, "{what}: threaded output diverged");
                }
            }
        }
    }

    /// Every member of an in-memory archive image, decoded with verification
    /// off, tolerating an archive that will not even open.
    fn decode_bytes_members(data: &[u8]) -> Vec<Result<Vec<u8>, String>> {
        let options = crate::ExtractOptions {
            verify: false,
            ..Default::default()
        };
        let mut archive = match crate::RarArchive::open(std::io::Cursor::new(data.to_vec())) {
            Ok(archive) => archive,
            Err(err) => return vec![Err(format!("open: {err}"))],
        };
        (0..archive.metadata().members.len())
            .map(|index| {
                archive
                    .extract_member(index, &options, None)
                    .and_then(|member| member.into_bytes())
                    .map_err(|err| err.to_string())
            })
            .collect()
    }

    /// A solid archive that mixes LZ and PPMd members must hand the window
    /// between the threaded LZ path and the serial PPMd path intact.
    ///
    /// PPMd is out of the split's scope, so every PPMd round runs on this
    /// thread against a window the previous LZ round left fully materialized.
    /// If the split ever returned with records still in flight, a following
    /// PPMd member would read a short window and this would diverge.
    ///
    /// `rar4_ppm_order16_32m.rar` is deliberately not in this sweep. It is a
    /// single pure-PPMd member (the 32 MiB order-16 performance corpus), so it
    /// has no LZ round to hand a window from and no member to hand it to: on
    /// every one of the eight decodes `assert_paths_agree` performs, the
    /// split never engages and the comparison cannot disagree. Those eight
    /// serial 32 MiB PPMd decodes were most of the crate's CI wall clock, for
    /// no shape this test is about — the same reason the LZ sweeps leave
    /// `rar4_solid.rar` out. Its bytes stay pinned by
    /// `test_rar4_ppmd_order16_32m_payload` in `tests/integration.rs`.
    ///
    /// One `#[test]` per fixture rather than one loop: each fixture is eight
    /// serial PPMd decodes, so as separate tests they run on separate test
    /// threads and the sweep costs one fixture's time instead of three.
    fn assert_mixed_lz_and_ppmd_paths_agree(filename: &str) {
        if !fixtures_hydrated(&[filename]) {
            return;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar4")
            .join(filename);
        assert!(path.exists(), "missing fixture {filename}");
        assert_paths_agree(filename, "mixed LZ/PPMd solid");
    }

    /// Switches between PPMd and LZ blocks inside one stream.
    #[test]
    fn mixed_lz_and_ppmd_conversion_stream_agrees_on_every_path() {
        assert_mixed_lz_and_ppmd_paths_agree("test_read_format_rar_ppmd_lzss_conversion.rar");
    }

    #[test]
    fn mixed_lz_and_ppmd_solid_multivolume_agrees_on_every_path() {
        assert_mixed_lz_and_ppmd_paths_agree("rar4_ppm_solid_mv.rar");
    }

    #[test]
    fn mixed_lz_and_ppmd_solid_restart_agrees_on_every_path() {
        assert_mixed_lz_and_ppmd_paths_agree("rar4_ppm_solid_restart.rar");
    }

    /// The split must engage on its own on the arc's own reference shapes.
    ///
    /// The sweeps above tolerate a fixture that cannot lease; this one does
    /// not, so a regression that quietly stopped admitting the threaded path
    /// would fail here instead of turning every other assertion vacuous.
    #[test]
    fn the_threaded_path_engages_on_plain_and_solid_lz() {
        if !fixtures_hydrated(&["rar4_lz.rar", "rar4_lz_solid_mv.rar"]) {
            return;
        }
        for filename in ["rar4_lz.rar", "rar4_lz_solid_mv.rar"] {
            let before = super::mt_test_hooks::mt_lease_count();
            let threaded = super::mt_test_hooks::with_mt_threads(2, || decode_members(filename));
            assert!(
                super::mt_test_hooks::mt_lease_count() > before,
                "{filename}: the threaded path leased no span"
            );
            assert!(
                threaded.iter().any(Result::is_ok),
                "{filename}: no member decoded"
            );
        }
    }

    /// Admission is off by default, at every member size, and an explicit
    /// width decides it either way.
    ///
    /// The default is a *measured* one — see [`RAR4_MT_ADMITTED_BY_DEFAULT`].
    /// This test exists so flipping it is a deliberate act with a number
    /// attached, not a drive-by edit.
    ///
    /// [`RAR4_MT_ADMITTED_BY_DEFAULT`]: super::RAR4_MT_ADMITTED_BY_DEFAULT
    #[test]
    fn admission_is_off_by_default_at_every_size() {
        for size in [0u64, 1, 1 << 20, 1 << 30, u64::MAX] {
            assert_eq!(
                super::rar4_mt_admitted(size),
                super::RAR4_MT_ADMITTED_BY_DEFAULT,
                "member size {size} changed admission, but the split's cost is \
                 per byte and has no crossover"
            );
        }
        // Deliberately a compile-time check: flipping the default should break
        // the build here and send the author back to the measurement.
        const {
            assert!(
                !RAR4_MT_ADMITTED_BY_DEFAULT,
                "the split measured 16-28% slower on rar3/rar4; turning it on \
                 needs a new measurement, not a new constant"
            );
        }

        // A forced width decides both ways, whatever the size.
        super::mt_test_hooks::with_mt_threads(1, || {
            assert!(!super::rar4_mt_admitted(u64::MAX));
        });
        super::mt_test_hooks::with_mt_threads(2, || {
            assert!(super::rar4_mt_admitted(0));
        });
    }

    /// Report how many spans each fixture hands to a decode thread.
    ///
    /// Each lease is one thread handover, so this number times the spawn cost
    /// is the split's fixed overhead. Printed rather than asserted on absolute
    /// values, but the ratio to output size is pinned: a regression that
    /// re-leased per Huffman block instead of per buffer fill would blow past
    /// it and the split would lose on every member.
    #[test]
    fn leases_stay_proportional_to_input_not_to_blocks() {
        if !fixtures_hydrated(&[
            "rar4_lz.rar",
            "rar4_multifile_lz.rar",
            "rar4_lz_solid_mv.rar",
            "test_read_format_rar_filter.rar",
            "test_read_format_rar_multi_lzss_blocks.rar",
        ]) {
            return;
        }
        for filename in [
            "rar4_lz.rar",
            "rar4_multifile_lz.rar",
            "rar4_lz_solid_mv.rar",
            "test_read_format_rar_filter.rar",
            "test_read_format_rar_multi_lzss_blocks.rar",
        ] {
            let before = super::mt_test_hooks::mt_lease_count();
            let members = super::mt_test_hooks::with_mt_threads(2, || decode_members(filename));
            let leases = super::mt_test_hooks::mt_lease_count() - before;
            let bytes: usize = members
                .iter()
                .filter_map(|m| m.as_ref().ok())
                .map(Vec::len)
                .sum();
            println!("{filename}: {leases} leases for {bytes} output bytes");
            // One lease per 4 KiB of output would mean the handover, not the
            // decode, is the unit of work.
            assert!(
                leases <= 1 + bytes / 4096,
                "{filename}: {leases} leases for {bytes} bytes is a handover \
                 per block, not per buffer fill"
            );
        }
    }

    /// One decoded record is the same 16 bytes UnRAR's `UnpackDecodedItem` is
    /// (unpack.hpp:99-108), which is what makes the batch sizing below
    /// transferable from the oracle and from the RAR5 controller.
    #[test]
    fn record_and_queue_sizing_match_the_templates() {
        assert_eq!(std::mem::size_of::<super::Rar4Item>(), 16);
        // UnRAR: `DecodedAllocated = 0x4100` (unpack50mt.cpp:47).
        // rarpar RAR5: `DECODED_ITEMS_CAPACITY = 0x4100` (lz/parallel.rs:46).
        assert_eq!(super::RAR4_MT_BATCH_ITEMS, 0x4100);
        // rarpar RAR5: `PIPELINE_DEPTH = 2` (lz/parallel.rs:43).
        assert_eq!(super::RAR4_MT_PIPELINE_DEPTH, 2);
        // Bounded memory: depth batches of records, and nothing else.
        assert!(
            super::RAR4_MT_BATCH_ITEMS
                * std::mem::size_of::<super::Rar4Item>()
                * (super::RAR4_MT_PIPELINE_DEPTH + 1)
                <= 1 << 20
        );
    }
}
