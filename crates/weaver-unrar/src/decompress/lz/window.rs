//! Sliding window / ring buffer for LZ decompression.
//!
//! The window holds previously decompressed output. Length-distance pairs
//! reference bytes already written to the window. The window wraps around
//! when it reaches the dictionary size.

use std::io::Write;
use std::ptr;

use crate::error::{RarError, RarResult};

/// Maximum incremental match length used by RAR LZ decoding.
const MAX_INC_LZ_MATCH: usize = 0x1004;

/// Longest non-overlapping match still copied with inline chunk stores instead
/// of `ptr::copy_nonoverlapping`. `copy_nonoverlapping` lowers to a `memcpy`
/// call for runtime lengths; below this size the call overhead dominates, above
/// it the libc SIMD implementation wins.
const INLINE_COPY_MAX: usize = 64;

/// Unaligned little/native-endian scalar loads and stores.
///
/// Weaver targets 64-bit and wasm32, and both handle unaligned `u64` access
/// natively through these intrinsics, so no arch-specific code is needed. The
/// value is only ever round-tripped through memory, so native endianness is
/// correct on every target.
#[inline(always)]
unsafe fn load_u64(src: *const u8) -> u64 {
    unsafe { src.cast::<u64>().read_unaligned() }
}

#[inline(always)]
unsafe fn store_u64(dst: *mut u8, value: u64) {
    unsafe { dst.cast::<u64>().write_unaligned(value) }
}

#[inline(always)]
unsafe fn load_u32(src: *const u8) -> u32 {
    unsafe { src.cast::<u32>().read_unaligned() }
}

#[inline(always)]
unsafe fn store_u32(dst: *mut u8, value: u32) {
    unsafe { dst.cast::<u32>().write_unaligned(value) }
}

#[inline(always)]
unsafe fn load_u16(src: *const u8) -> u16 {
    unsafe { src.cast::<u16>().read_unaligned() }
}

#[inline(always)]
unsafe fn store_u16(dst: *mut u8, value: u16) {
    unsafe { dst.cast::<u16>().write_unaligned(value) }
}

/// Copy a 1..=16 byte match with at most two overlapping power-of-two stores.
///
/// This is the RAR5 hot case (typical match lengths are 3..30) that the oracle
/// handles with a nested-if byte tail (unpackinline.cpp:95-102) and that
/// `ptr::copy_nonoverlapping` would turn into a `memcpy` call.
///
/// # Safety
///
/// * `[src, src + length)` and `[dst, dst + length)` must be in bounds of the
///   same allocation, and `length` must be in `1..=16`.
/// * `gap = |dst - src|` must be `>= the store width` used below, i.e. `>= 8`
///   for `length >= 8`, `>= 4` for `length >= 4`, `>= 2` for `length >= 2`.
///   Callers pass `gap >= 8`, or `gap == length` when seeding a repeating
///   pattern (where the source is entirely pre-existing data).
///
/// Exactly `length` bytes are written — deliberately no wildcopy overrun. In a
/// ring buffer the bytes just past the write cursor are also the *oldest*
/// history, which a match with `distance` within a few bytes of `dict_size`
/// still reads (the oracle allows `Distance <= MaxWinSize`), so an overrun
/// would be observable on corrupt archives.
///
/// Correctness under overlap (`src < dst`, `gap == distance`): the head store
/// runs before the tail load, and the tail load covers output-relative indices
/// `length - width - gap ..= length - 1 - gap`. With `gap >= width` and
/// `gap >= length - width` (true for the width chosen per length band below)
/// every one of those indices is either negative — pre-existing window data —
/// or already carries its final value from the head store.
#[inline(always)]
unsafe fn copy_short_exact(src: *const u8, dst: *mut u8, length: usize) {
    debug_assert!((1..=16).contains(&length));
    unsafe {
        if length >= 8 {
            store_u64(dst, load_u64(src));
            store_u64(dst.add(length - 8), load_u64(src.add(length - 8)));
        } else if length >= 4 {
            store_u32(dst, load_u32(src));
            store_u32(dst.add(length - 4), load_u32(src.add(length - 4)));
        } else if length >= 2 {
            store_u16(dst, load_u16(src));
            store_u16(dst.add(length - 2), load_u16(src.add(length - 2)));
        } else {
            *dst = *src;
        }
    }
}

/// Copy a >16 byte match in 8 or 16 byte chunks, writing exactly `length` bytes.
///
/// Mirrors the oracle's chunked `CopyString` loop (unpackinline.cpp:63-92) with
/// a wider stride when the gap allows it.
///
/// # Safety
///
/// * `[src, src + length)` and `[dst, dst + length)` must be in bounds of the
///   same allocation and `length` must be `> 16`.
/// * `gap = |dst - src|` must be `>= 8`; the 16 byte stride is used only when
///   `gap >= 16`.
///
/// Overlap reasoning, with `i` the chunk offset:
/// * `src < dst` (ordinary match, `gap == distance`): the chunk reads output
///   indices `i - gap ..= i + width - 1 - gap`, all `< i` because
///   `gap >= width`, so every byte read already holds its final value.
/// * `src > dst` (a source wrapped around the ring, only reachable for
///   `distance` within `MAX_INC_LZ_MATCH` of `dict_size`): the chunk reads
///   indices `>= i`, which this copy has not written yet — exactly what the
///   oracle's byte loop reads there.
///
/// The final partial chunk is emitted as one 8 byte store overlapping the
/// previous chunk (`length >= 8` holds), so nothing past `dst + length` is
/// touched. Its load covers indices `<= length - 1 - gap <= length - 9`, and at
/// least `length - 7` bytes have already been stored, so those are final too.
#[inline(always)]
unsafe fn copy_chunked(src: *const u8, dst: *mut u8, gap: usize, length: usize) {
    debug_assert!(length > 16);
    debug_assert!(gap >= 8);
    unsafe {
        let mut i = 0usize;
        if gap >= 16 {
            while i + 16 <= length {
                let lo = load_u64(src.add(i));
                let hi = load_u64(src.add(i + 8));
                store_u64(dst.add(i), lo);
                store_u64(dst.add(i + 8), hi);
                i += 16;
            }
        }
        while i + 8 <= length {
            let chunk = load_u64(src.add(i));
            store_u64(dst.add(i), chunk);
            i += 8;
        }
        if i < length {
            store_u64(dst.add(length - 8), load_u64(src.add(length - 8)));
        }
    }
}

// Weaver only targets 64-bit, so the dictionary is always one contiguous
// allocation; the fragmented-window fallback for 32-bit address spaces is
// intentionally not ported.
struct WindowStorage {
    buf: Vec<u8>,
}

impl WindowStorage {
    fn try_contiguous(len: usize) -> Result<Self, String> {
        debug_assert!(len > 0);
        let layout = std::alloc::Layout::array::<u8>(len).map_err(|err| err.to_string())?;
        // alloc_zeroed reaches calloc/mmap for large sizes, so the OS hands
        // back lazy zero pages: a RAR7-scale dictionary (>4 GiB) reserves
        // address space up front but commits physical pages only as the
        // window fills. Vec::resize(len, 0) would memset-commit the whole
        // declared size before the first decoded byte. Window reads of
        // never-written areas must still observe zeros.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(format!("allocation of {len} bytes failed"));
        }
        // SAFETY: ptr came from the global allocator with the exact layout
        // Vec<u8> uses to deallocate len == capacity bytes, and every byte is
        // initialized (zeroed).
        let buf = unsafe { Vec::from_raw_parts(ptr, len, len) };
        Ok(Self { buf })
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    #[inline(always)]
    fn get(&self, idx: usize) -> u8 {
        self.buf[idx]
    }

    #[inline(always)]
    fn set(&mut self, idx: usize, value: u8) {
        self.buf[idx] = value;
    }

    /// Store one byte without the slice bounds check.
    ///
    /// # Safety
    ///
    /// `idx` must be `< self.len()`.
    #[inline(always)]
    unsafe fn set_unchecked(&mut self, idx: usize, value: u8) {
        debug_assert!(idx < self.buf.len());
        unsafe { *self.buf.as_mut_ptr().add(idx) = value };
    }

    fn copy_from_slice(&mut self, start: usize, bytes: &[u8]) {
        self.buf[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn fill(&mut self, start: usize, len: usize, value: u8) {
        self.buf[start..start + len].fill(value);
    }

    fn fill_all(&mut self, value: u8) {
        self.buf.fill(value);
    }

    fn extend_from_range(&self, start: usize, len: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.buf[start..start + len]);
    }

    fn write_range_to_writer<W: Write + ?Sized>(
        &self,
        start: usize,
        len: usize,
        writer: &mut W,
    ) -> std::io::Result<()> {
        writer.write_all(&self.buf[start..start + len])
    }
}

/// Sliding window ring buffer used during LZ decompression.
pub struct Window {
    /// The ring buffer. `buf.len()` is the *allocated* size, which can exceed
    /// `dict_size` after a shrinking reuse — see [`Window::ensure_capacity`].
    /// Nothing outside `[0, dict_size)` is ever read or written.
    buf: WindowStorage,
    /// Logical dictionary size, mirroring the oracle's `MaxWinSize` (which is
    /// likewise distinct from its `AllocWinSize`, unpack.cpp:107-157). Every
    /// ring/wrap computation uses this, never `buf.len()`.
    ///
    /// Invariant: `0 < dict_size <= buf.len()`.
    dict_size: usize,
    /// Current write position (wraps at `dict_size`).
    ///
    /// Invariant: `pos < dict_size` at all times. Every path that advances the
    /// cursor re-wraps before it returns, and [`Window::ensure_capacity`]
    /// re-wraps after a shrink. [`Window::put_byte`] relies on this invariant
    /// for an unchecked store on the per-literal hot path.
    pos: usize,
    /// True once the write cursor has wrapped at least once, i.e. the whole
    /// logical dictionary has been written since the last reset. Cached
    /// equivalent of `total_written >= dict_size` (the oracle's `FirstWinDone`,
    /// unpackinline.cpp:31-35) so `copy_advance` does not have to redo the
    /// widening compare for every match.
    first_win_done: bool,
    /// Total number of bytes ever written (monotonically increasing).
    total_written: u64,
    /// Absolute dictionary position consumed by the external writer.
    total_flushed: u64,
    /// Absolute output ranges that advanced the dictionary but must not be
    /// emitted to callers (truncated final matches). Almost always empty, so
    /// the visible output is derived as the complement — this keeps the
    /// per-literal hot path free of range bookkeeping.
    invisible_ranges: Vec<(u64, u64)>,
}

impl Window {
    /// Create a new window with the given dictionary size.
    ///
    /// The dictionary size determines the maximum lookback distance for
    /// length-distance copies.
    pub fn new(dict_size: usize) -> Self {
        Self::try_new(dict_size).expect("window allocation failed")
    }

    /// Fallibly create a new window with the given dictionary size.
    ///
    /// Use fallible allocation on production paths so a crafted large-window
    /// archive cannot abort the daemon through Rust's infallible Vec allocation.
    pub fn try_new(dict_size: usize) -> RarResult<Self> {
        if dict_size == 0 {
            return Err(RarError::DictionaryTooLarge { size: 0, max: 0 });
        }

        let buf = match WindowStorage::try_contiguous(dict_size) {
            Ok(buf) => buf,
            Err(err) => {
                return Err(RarError::ResourceLimit {
                    detail: format!("failed to allocate {dict_size} byte RAR dictionary: {err}"),
                });
            }
        };

        Ok(Self {
            buf,
            dict_size,
            pos: 0,
            first_win_done: false,
            total_written: 0,
            total_flushed: 0,
            invisible_ranges: Vec::new(),
        })
    }

    /// Grow the allocation if needed and set the logical dictionary size.
    ///
    /// Mirrors the oracle's `AllocWinSize` handling (unpack.cpp:107-157): a
    /// request that fits the current allocation only re-points the logical
    /// size — window contents are left untouched and no memory is faulted in.
    /// A larger request allocates a fresh zeroed buffer, which necessarily
    /// discards the previous history, so callers that grow must follow with
    /// [`Window::reset_for_reuse`] (or start a fresh non-solid member).
    pub fn ensure_capacity(&mut self, dict_size: usize) -> RarResult<()> {
        if dict_size == 0 {
            return Err(RarError::DictionaryTooLarge { size: 0, max: 0 });
        }

        if dict_size > self.buf.len() {
            match WindowStorage::try_contiguous(dict_size) {
                Ok(buf) => self.buf = buf,
                Err(err) => {
                    return Err(RarError::ResourceLimit {
                        detail: format!(
                            "failed to allocate {dict_size} byte RAR dictionary: {err}"
                        ),
                    });
                }
            }
        }

        self.dict_size = dict_size;
        // Restore the `pos < dict_size` invariant after a shrink; the cursor is
        // meaningless across a size change anyway and `reset_for_reuse` zeroes
        // it right after, but the unchecked store in `put_byte` must never see
        // a stale out-of-range cursor.
        if self.pos >= dict_size {
            self.pos %= dict_size;
        }
        self.first_win_done = self.total_written >= dict_size as u64;
        Ok(())
    }

    /// Reuse this window for a new non-solid member with `dict_size` bytes.
    ///
    /// Deliberately does **not** memset the buffer — the oracle dropped its own
    /// window memset for exactly this reason (unpack.cpp:149-153), because the
    /// `FirstWinDone` guard in `CopyString` already makes decoding independent
    /// of leftover bytes: with `total_written == 0`, `pos == 0` and
    /// `first_win_done == false`, every `distance >= 1` is `> pos` and routes
    /// to the zero-fill path, and once `pos` has advanced, an in-range
    /// `distance <= pos` can only reach bytes written since this reset. After
    /// the cursor wraps, `first_win_done` is true only because all `dict_size`
    /// bytes have been rewritten. Skipping the memset keeps a multi-gigabyte
    /// RAR7 dictionary from being re-committed once per member.
    ///
    /// `get_byte` is the one accessor without that guard; it is used by tests
    /// only and must not be used to read pre-reset history.
    pub fn reset_for_reuse(&mut self, dict_size: usize) -> RarResult<()> {
        self.ensure_capacity(dict_size)?;
        self.pos = 0;
        self.first_win_done = false;
        self.total_written = 0;
        self.total_flushed = 0;
        self.invisible_ranges.clear();
        Ok(())
    }

    /// Bytes currently allocated for the ring buffer.
    ///
    /// Always `>= dict_size()`; they differ only after a shrinking reuse.
    pub fn allocated_size(&self) -> usize {
        self.buf.len()
    }

    /// Record a dictionary-only advance: bytes in `[start_total,
    /// start_total + len)` advanced the window but must not reach callers.
    fn mark_invisible(&mut self, start_total: u64, len: u64) {
        if len == 0 {
            return;
        }
        if let Some((last_start, last_len)) = self.invisible_ranges.last_mut()
            && last_start.saturating_add(*last_len) == start_total
        {
            *last_len += len;
            return;
        }
        self.invisible_ranges.push((start_total, len));
    }

    /// Sum of invisible bytes intersecting `[start, end)`.
    fn invisible_overlap(&self, start: u64, end: u64) -> u64 {
        if self.invisible_ranges.is_empty() {
            return 0;
        }
        self.invisible_ranges
            .iter()
            .map(|&(inv_start, inv_len)| {
                let inv_end = inv_start.saturating_add(inv_len);
                let overlap_start = inv_start.max(start);
                let overlap_end = inv_end.min(end);
                overlap_end.saturating_sub(overlap_start)
            })
            .sum()
    }

    /// Drop invisible ranges that ended at or before the flushed border.
    fn gc_invisible(&mut self) {
        if self.invisible_ranges.is_empty() {
            return;
        }
        let border = self.total_flushed;
        self.invisible_ranges
            .retain(|&(start, len)| start.saturating_add(len) > border);
    }

    /// Write a single literal byte to the window.
    #[inline(always)]
    pub fn put_byte(&mut self, b: u8) {
        // SAFETY: `pos < dict_size <= buf.len()` is a type invariant (see the
        // field docs) — every cursor-advancing path re-wraps before returning —
        // so this store is in bounds. It is written unchecked because this is
        // the per-literal hot path and the bounds check is otherwise re-proved
        // on every decoded byte.
        unsafe { self.buf.set_unchecked(self.pos, b) };
        self.pos += 1;
        if self.pos == self.dict_size {
            self.pos = 0;
            self.first_win_done = true;
        }
        self.total_written += 1;
    }

    /// Write an up-to-8-byte literal batch from the parallel apply loop.
    ///
    /// A full batch away from the window edge compiles to one fixed 8-byte
    /// store; the variable-length `put_bytes` path costs a memmove call per
    /// batch, which dominates the apply phase on literal-heavy streams.
    #[inline(always)]
    pub fn put_literal_batch(&mut self, bytes: &[u8; 8], n: usize) {
        debug_assert!((1..=8).contains(&n));
        if n == 8 && self.pos + 8 <= self.dict_size {
            // SAFETY: `pos + 8 <= dict_size <= buf.len()`, so the 8 byte store
            // is fully in bounds. `bytes` is a caller-owned array and cannot
            // alias the window.
            unsafe {
                store_u64(
                    self.buf.as_mut_ptr().add(self.pos),
                    u64::from_ne_bytes(*bytes),
                )
            };
            self.pos += 8;
            if self.pos == self.dict_size {
                self.pos = 0;
                self.first_win_done = true;
            }
            self.total_written += 8;
            return;
        }
        self.put_bytes(&bytes[..n]);
    }

    /// Write a contiguous slice of literal bytes to the window.
    #[inline]
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        let length = bytes.len();
        if length == 0 {
            return;
        }

        let dict_size = self.dict_size;
        let dst = self.pos;

        if dst + length <= dict_size {
            if length <= 8 {
                // Short literal runs — the parallel apply loop's tail batches
                // and the RAR4 filter tails — are cheaper as inline stores than
                // as the `memcpy` call `copy_from_slice` lowers to.
                //
                // SAFETY: `dst + length <= dict_size <= buf.len()`, so every
                // store is in bounds; `bytes` is caller-owned and cannot alias
                // the window.
                unsafe {
                    let out = self.buf.as_mut_ptr().add(dst);
                    for (i, &b) in bytes.iter().enumerate() {
                        *out.add(i) = b;
                    }
                }
            } else {
                self.buf.copy_from_slice(dst, bytes);
            }
            self.pos = dst + length;
            if self.pos == dict_size {
                self.pos = 0;
                self.first_win_done = true;
            }
        } else {
            // Split the write at the dictionary boundary. A run longer than the
            // dictionary would wrap more than once; callers never do that, but
            // the loop keeps the `pos < dict_size` invariant unconditional.
            let mut rest = bytes;
            while !rest.is_empty() {
                let chunk = rest.len().min(dict_size - self.pos);
                self.buf.copy_from_slice(self.pos, &rest[..chunk]);
                self.pos += chunk;
                if self.pos == dict_size {
                    self.pos = 0;
                    self.first_win_done = true;
                }
                rest = &rest[chunk..];
            }
        }

        self.total_written += length as u64;
    }

    /// Copy a match that is guaranteed not to wrap the ring.
    ///
    /// Callers must have checked `length <= MAX_INC_LZ_MATCH`, `src <
    /// fast_limit` and `pos < fast_limit` with `fast_limit = dict_size -
    /// MAX_INC_LZ_MATCH`, so both `src + length` and `pos + length` stay below
    /// `dict_size` and neither run wraps — the same precondition the oracle
    /// uses to drop its wrap handling (unpackinline.cpp:51-53).
    ///
    /// Everything below addresses the source through `src`, exactly like the
    /// oracle, rather than through `dst - distance`. The two coincide for an
    /// ordinary match, but a match whose source wrapped around the ring has
    /// `src > dst`, where `dst - distance` would run off the front of the
    /// buffer.
    ///
    /// Dispatch is therefore on `gap = |dst - src|`, not on `distance`: for
    /// `src < dst` they are equal, and for a wrapped source `gap = dict_size -
    /// distance`, which is what actually bounds how far a block load may reach
    /// into bytes this copy is still writing.
    #[inline]
    fn copy_no_wrap_fast(&mut self, src: usize, length: usize) {
        let dst = self.pos;
        debug_assert!(length > 0);
        debug_assert!(src + length <= self.dict_size);
        debug_assert!(dst + length <= self.dict_size);

        // `gap == 0` is legal: `distance == dict_size` is the largest distance
        // the oracle accepts, and it resolves to `src == dst`, i.e. the window
        // copied onto itself.
        let gap = dst.abs_diff(src);

        // SAFETY: the debug assertions above restate the caller's guarantees:
        // `src`, `dst` and both `+ length` ends are inside the single window
        // allocation, so every pointer formed here stays in bounds. The helper
        // safety contracts (store width vs `gap`, `length` band) are discharged
        // by the branch conditions.
        unsafe {
            let buf_ptr = self.buf.as_mut_ptr();
            let src_ptr = buf_ptr.add(src);
            let dst_ptr = buf_ptr.add(dst);

            if gap >= 8 {
                if length <= 16 {
                    copy_short_exact(src_ptr, dst_ptr, length);
                } else if gap >= length && length > INLINE_COPY_MAX {
                    // Provably disjoint runs (`gap >= length`) that are long
                    // enough to amortize the call.
                    ptr::copy_nonoverlapping(src_ptr, dst_ptr, length);
                } else {
                    copy_chunked(src_ptr, dst_ptr, gap, length);
                }
            } else if src < dst {
                // Repeating pattern with a 2..=7 byte period (`distance == 1`
                // is served by the byte-fill path in `copy_advance`).
                if length <= 16 {
                    // Short repeats: a byte loop of at most 16 iterations beats
                    // both a `memcpy` call and the expansion bookkeeping.
                    for i in 0..length {
                        *dst_ptr.add(i) = *src_ptr.add(i);
                    }
                } else {
                    // Long repeats: seed the period once, then double the
                    // just-written prefix. This beats the oracle's byte-wise
                    // loop by a wide margin, so it is preserved as-is; only the
                    // small seed/first chunks avoid the `memcpy` call now.
                    let mut copied = gap;
                    copy_short_exact(src_ptr, dst_ptr, copied);

                    while copied < length {
                        let chunk = copied.min(length - copied);
                        if chunk <= 16 {
                            copy_short_exact(dst_ptr, dst_ptr.add(copied), chunk);
                        } else {
                            ptr::copy_nonoverlapping(dst_ptr, dst_ptr.add(copied), chunk);
                        }
                        copied += chunk;
                    }
                }
            } else {
                // Wrapped source sitting fewer than 8 bytes ahead of the write
                // cursor. Only reachable for `distance` within 8 bytes of
                // `dict_size`, which no real archive emits (the oracle notes
                // the same at unpackinline.cpp:83-85). Block loads here would
                // pick up bytes this copy has already written, so fall back to
                // the oracle's exact forward byte loop.
                for i in 0..length {
                    *dst_ptr.add(i) = *src_ptr.add(i);
                }
            }
        }

        self.pos = dst + length;
        self.total_written += length as u64;
    }

    /// Copy `length` bytes from `distance` bytes back in the output.
    ///
    /// Handles overlapping copies correctly (e.g., distance=1, length=100
    /// repeats the last byte 100 times).
    #[inline]
    fn copy_advance(&mut self, distance: usize, length: usize) -> RarResult<()> {
        let dict_size = self.dict_size;
        debug_assert_eq!(
            self.first_win_done,
            self.total_written >= dict_size as u64,
            "cached first_win_done drifted from the write counter"
        );
        if length == 0 {
            return Ok(());
        }

        // No RAR decoder can produce distance 0: RAR5/RAR3/RAR2 distances are
        // decoded as `base + 1`, and the repeat-distance caches are seeded with
        // `usize::MAX` (rar4.rs:184, rar4_old.rs:363/953, lz/mod.rs:133) so an
        // unused slot zero-fills instead of aliasing distance 0. RAR 1.5 routes
        // 0 through `copy_rar15_with_visible_len` before it gets here. But
        // `Window` is a public API (`weaver_unrar::decompress::lz::window`), so
        // an external caller can still pass 0, and the arm is what keeps that
        // from becoming a non-terminating expansion in `copy_no_wrap_fast`.
        // It stays: it costs one perfectly-predicted compare per match.
        //
        // Semantics match the oracle, whose `CopyString` with `Distance == 0`
        // has `SrcPtr == UnpPtr` and copies the window onto itself — a pure
        // cursor advance that preserves the existing dictionary bytes.
        if distance == 0 {
            self.advance_preserving_window(length);
            return Ok(());
        }

        if distance > dict_size || (distance > self.pos && !self.first_win_done) {
            self.fill_zeroes_advance(length);
            return Ok(());
        }

        let src = if distance <= self.pos {
            self.pos - distance
        } else {
            dict_size - (distance - self.pos)
        };

        // Fast path: distance=1 is byte-fill (very common RLE pattern).
        if distance == 1 {
            let byte = self.buf.get(src);
            let dst = self.pos;
            if dst + length <= dict_size {
                self.buf.fill(dst, length, byte);
                self.pos = dst + length;
                if self.pos == dict_size {
                    self.pos = 0;
                    self.first_win_done = true;
                }
            } else {
                let mut remaining = length;
                while remaining > 0 {
                    let chunk = remaining.min(dict_size - self.pos);
                    self.buf.fill(self.pos, chunk, byte);
                    self.pos += chunk;
                    if self.pos == dict_size {
                        self.pos = 0;
                        self.first_win_done = true;
                    }
                    remaining -= chunk;
                }
            }
            self.total_written += length as u64;
            return Ok(());
        }

        // If both pointers are sufficiently far
        // from the end of the window, CopyString can avoid wrap handling for
        // the maximum legal match length, not just for this specific length.
        // `pos + length < dict_size` then holds, so this path never wraps and
        // never touches `first_win_done`.
        let fast_limit = dict_size.saturating_sub(MAX_INC_LZ_MATCH);
        if length <= MAX_INC_LZ_MATCH && src < fast_limit && self.pos < fast_limit {
            self.copy_no_wrap_fast(src, length);
            return Ok(());
        }

        // General path with wrap handling and overlap support.
        // Keep it branch-light and forward-copying.
        let mut src = src;
        let mut dst = self.pos;
        let mut remaining = length;

        while remaining > 0 {
            let byte = self.buf.get(src);
            self.buf.set(dst, byte);
            src += 1;
            if src == dict_size {
                src = 0;
            }
            dst += 1;
            if dst == dict_size {
                dst = 0;
                self.first_win_done = true;
            }
            remaining -= 1;
        }

        self.pos = dst;
        self.total_written += length as u64;
        Ok(())
    }

    /// Copy `length` bytes from `distance` bytes back and expose all copied bytes.
    ///
    /// Handles overlapping copies correctly (e.g., distance=1, length=100
    /// repeats the last byte 100 times).
    #[inline]
    pub fn copy(&mut self, distance: usize, length: usize) -> RarResult<()> {
        self.copy_with_visible_len(distance, length, length)
    }

    /// Copy a full match into the dictionary while exposing only `visible_len`.
    ///
    /// Advance the sliding dictionary by the complete match even when a
    /// malformed final match crosses the declared unpacked size. Only the bytes
    /// within the declared member size are emitted to callers.
    #[inline]
    pub(crate) fn copy_with_visible_len(
        &mut self,
        distance: usize,
        length: usize,
        visible_len: usize,
    ) -> RarResult<()> {
        let start_total = self.total_written;
        self.copy_advance(distance, length)?;
        let visible = visible_len.min(length);
        if visible < length {
            self.mark_invisible(start_total + visible as u64, (length - visible) as u64);
        }
        Ok(())
    }

    /// Copy for RAR 1.5 damaged-stream compatibility.
    ///
    /// RAR 1.5 zero-fills invalid pre-window, oversize, and
    /// zero-distance matches instead of hard-failing. Valid streams never use
    /// distance zero, but this keeps damaged old-RAR recovery aligned.
    pub(crate) fn copy_rar15_with_visible_len(
        &mut self,
        distance: usize,
        length: usize,
        visible_len: usize,
    ) -> RarResult<()> {
        let start_total = self.total_written;
        if distance == 0 {
            self.fill_zeroes_advance(length);
        } else {
            self.copy_advance(distance, length)?;
        }
        let visible = visible_len.min(length);
        if visible < length {
            self.mark_invisible(start_total + visible as u64, (length - visible) as u64);
        }
        Ok(())
    }

    fn fill_zeroes_advance(&mut self, length: usize) {
        let dict_size = self.dict_size;
        let mut remaining = length;
        while remaining > 0 {
            let chunk = remaining.min(dict_size - self.pos);
            self.buf.fill(self.pos, chunk, 0);
            self.pos += chunk;
            if self.pos == dict_size {
                self.pos = 0;
                self.first_win_done = true;
            }
            remaining -= chunk;
        }
        self.total_written += length as u64;
    }

    fn advance_preserving_window(&mut self, length: usize) {
        let dict_size = self.dict_size;
        if self.pos + length >= dict_size {
            self.first_win_done = true;
        }
        self.pos = (self.pos + length) % dict_size;
        self.total_written += length as u64;
    }

    /// Get a byte at a specific distance back from the current position.
    ///
    /// `distance` is 1-based: distance=1 returns the last byte written.
    ///
    /// Unlike `copy`, this has no `first_win_done` guard, so a distance beyond
    /// what has been written since the last reset reads whatever the buffer
    /// holds there. That is zero after [`Window::try_new`] / [`Window::reset`]
    /// but stale after [`Window::reset_for_reuse`]; no decoder uses it.
    #[inline]
    pub fn get_byte(&self, distance: usize) -> u8 {
        let dict_size = self.dict_size;
        let idx = if distance <= self.pos {
            self.pos - distance
        } else {
            dict_size - (distance - self.pos)
        };
        self.buf.get(idx)
    }

    /// Total number of bytes ever written to the window.
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Current write position in the ring buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Get the logical dictionary size (maximum lookback distance).
    ///
    /// This is the size the ring wraps at, not the size of the underlying
    /// allocation — see [`Window::allocated_size`].
    pub fn dict_size(&self) -> usize {
        self.dict_size
    }

    /// Copy output bytes from the window into the destination buffer.
    ///
    /// `start_total` is the absolute position (based on total_written) to start copying.
    /// `len` is the number of bytes to copy.
    /// Returns the bytes copied.
    pub fn try_copy_output(&self, start_total: u64, len: usize) -> RarResult<Vec<u8>> {
        let end_total =
            start_total
                .checked_add(len as u64)
                .ok_or_else(|| RarError::CorruptArchive {
                    detail: "window output range overflows u64".to_string(),
                })?;
        if start_total > self.total_written || end_total > self.total_written {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "window output range [{start_total}, {end_total}) exceeds written output {}",
                    self.total_written
                ),
            });
        }

        let dict_size = self.dict_size;
        let distance = (self.total_written - start_total) as usize;
        if distance > dict_size {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "window output start {start_total} is outside the {} byte dictionary history",
                    dict_size
                ),
            });
        }

        let mut result = Vec::with_capacity(len);

        let mut idx = if distance <= self.pos {
            self.pos - distance
        } else {
            dict_size - (distance - self.pos)
        };

        let mut remaining = len;
        while remaining > 0 {
            let contig = (dict_size - idx).min(remaining);
            self.buf.extend_from_range(idx, contig, &mut result);
            idx = (idx + contig) % dict_size;
            remaining -= contig;
        }

        Ok(result)
    }

    #[cfg(test)]
    pub fn copy_output(&self, start_total: u64, len: usize) -> Vec<u8> {
        self.try_copy_output(start_total, len)
            .expect("valid window output range")
    }

    /// Flush unflushed bytes from the window to a writer.
    ///
    /// Writes all bytes between `total_flushed` and `total_written` to the
    /// provided writer. Handles ring buffer wrap-around correctly.
    /// Returns the number of bytes written.
    pub fn flush_to_writer<W: Write + ?Sized>(&mut self, writer: &mut W) -> std::io::Result<u64> {
        let unflushed = self.unflushed_bytes();
        if unflushed == 0 {
            self.total_flushed = self.total_written;
            self.gc_invisible();
            return Ok(0);
        }

        let dict_size = self.dict_size;
        if unflushed > dict_size as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "window overrun: {unflushed} unflushed bytes exceeds dictionary size {dict_size}"
                ),
            ));
        }
        self.write_visible_span(self.total_flushed, self.total_written, writer)?;
        self.total_flushed = self.total_written;
        self.gc_invisible();
        Ok(unflushed)
    }

    /// Write the visible bytes of `[start, end)` to `writer`, skipping any
    /// invisible ranges. Ranges are stored in increasing start order.
    fn write_visible_span<W: Write + ?Sized>(
        &self,
        start: u64,
        end: u64,
        writer: &mut W,
    ) -> std::io::Result<u64> {
        let mut written = 0u64;
        let mut cursor = start;
        if !self.invisible_ranges.is_empty() {
            for &(inv_start, inv_len) in &self.invisible_ranges {
                let inv_end = inv_start.saturating_add(inv_len);
                if inv_end <= cursor {
                    continue;
                }
                if inv_start >= end {
                    break;
                }
                if inv_start > cursor {
                    let gap_end = inv_start.min(end);
                    self.write_range_to_writer(cursor, (gap_end - cursor) as usize, writer)?;
                    written += gap_end - cursor;
                }
                cursor = cursor.max(inv_end.min(end));
            }
        }
        if cursor < end {
            self.write_range_to_writer(cursor, (end - cursor) as usize, writer)?;
            written += end - cursor;
        }
        Ok(written)
    }

    /// Flush visible output up to `up_to`, advancing across hidden dictionary
    /// bytes without emitting them.
    pub(crate) fn flush_visible_until<W: Write + ?Sized>(
        &mut self,
        up_to: u64,
        writer: &mut W,
    ) -> std::io::Result<u64> {
        let target = up_to.min(self.total_written);
        if target <= self.total_flushed {
            return Ok(0);
        }

        let written = self.write_visible_span(self.total_flushed, target, writer)?;
        self.total_flushed = target;
        self.gc_invisible();
        Ok(written)
    }

    /// Return visible subranges within `[start_total, start_total + len)`.
    ///
    /// Each tuple is `(offset_inside_range, visible_len)`. Hidden bytes are
    /// dictionary-only advancement and must not be emitted to callers.
    pub(crate) fn visible_subranges(&self, start_total: u64, len: usize) -> Vec<(usize, usize)> {
        let end_total = start_total
            .saturating_add(len as u64)
            .min(self.total_written);
        let mut ranges = Vec::new();
        let mut cursor = start_total;

        for &(inv_start, inv_len) in &self.invisible_ranges {
            let inv_end = inv_start.saturating_add(inv_len);
            if inv_end <= cursor {
                continue;
            }
            if inv_start >= end_total {
                break;
            }
            if inv_start > cursor {
                let gap_end = inv_start.min(end_total);
                ranges.push(((cursor - start_total) as usize, (gap_end - cursor) as usize));
            }
            cursor = cursor.max(inv_end.min(end_total));
        }
        if cursor < end_total {
            ranges.push((
                (cursor - start_total) as usize,
                (end_total - cursor) as usize,
            ));
        }

        ranges
    }

    /// Number of unflushed bytes currently in the window.
    pub fn unflushed_bytes(&self) -> u64 {
        let span = self.total_written.saturating_sub(self.total_flushed);
        span - self.invisible_overlap(self.total_flushed, self.total_written)
    }

    /// Absolute position up to which data has been flushed.
    pub fn total_flushed(&self) -> u64 {
        self.total_flushed
    }

    /// Write a specific absolute output range to a writer without advancing
    /// the flushed marker.
    pub fn write_range_to_writer<W: Write + ?Sized>(
        &self,
        start_total: u64,
        len: usize,
        writer: &mut W,
    ) -> std::io::Result<()> {
        if len == 0 {
            return Ok(());
        }

        let dict_size = self.dict_size;
        let end_total = start_total.checked_add(len as u64).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "range overflow")
        })?;
        if end_total > self.total_written {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "requested range [{start_total}, {end_total}) exceeds total written {}",
                    self.total_written
                ),
            ));
        }
        let distance_from_end = self.total_written.checked_sub(start_total).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "requested range start {start_total} exceeds total written {}",
                    self.total_written
                ),
            )
        })?;
        if distance_from_end > dict_size as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "requested range start {start_total} is older than window capacity {dict_size}"
                ),
            ));
        }

        let distance = distance_from_end as usize;
        let mut idx = if distance <= self.pos {
            self.pos - distance
        } else {
            dict_size - (distance - self.pos)
        };

        let mut remaining = len;
        while remaining > 0 {
            let contig = (dict_size - idx).min(remaining);
            self.buf.write_range_to_writer(idx, contig, writer)?;
            idx = (idx + contig) % dict_size;
            remaining -= contig;
        }

        Ok(())
    }

    /// Manually mark data as flushed up to a given total position.
    /// Used when data is extracted via `copy_output` and written externally.
    pub fn mark_flushed(&mut self, up_to: u64) {
        self.total_flushed = up_to.min(self.total_written);
        self.gc_invisible();
    }

    /// Reset the window for a new file (non-solid mode), zeroing the buffer.
    ///
    /// Test-only in intent: the memset makes assertions about "unwritten"
    /// window bytes trivially checkable, but it commits (and dirties) the whole
    /// dictionary. Production reuse paths should call
    /// [`Window::reset_for_reuse`], which the oracle's own dropped memset
    /// (unpack.cpp:149-153) shows to be sufficient.
    pub fn reset(&mut self) {
        self.buf.fill_all(0);
        self.pos = 0;
        self.first_win_done = false;
        self.total_written = 0;
        self.total_flushed = 0;
        self.invisible_ranges.clear();
    }

    /// The logical dictionary contents, for tests that compare the whole ring
    /// against a reference model (this is what catches a wildcopy overrun).
    #[cfg(test)]
    fn logical_buffer(&self) -> &[u8] {
        &self.buf.buf[..self.dict_size]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic, positionally distinct filler. Uniform bytes would hide
    /// off-by-one errors in the block copy paths.
    fn junk_byte(i: usize) -> u8 {
        let x = (i as u64)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (x >> 33) as u8
    }

    /// Byte-exact model of the oracle's `CopyString` (unpackinline.cpp:13-112),
    /// written as the naive ring walk with no fast paths at all. Every block
    /// copy in `Window` must reproduce it exactly, including the bytes it does
    /// *not* touch.
    struct RefWindow {
        buf: Vec<u8>,
        pos: usize,
        total: u64,
    }

    impl RefWindow {
        fn new(dict_size: usize) -> Self {
            Self {
                buf: vec![0; dict_size],
                pos: 0,
                total: 0,
            }
        }

        fn put_byte(&mut self, b: u8) {
            let n = self.buf.len();
            self.buf[self.pos] = b;
            self.pos = (self.pos + 1) % n;
            self.total += 1;
        }

        fn copy(&mut self, distance: usize, length: usize) {
            let n = self.buf.len();
            if length == 0 {
                return;
            }
            if distance == 0 {
                self.pos = (self.pos + length) % n;
                self.total += length as u64;
                return;
            }
            if distance > n || (distance > self.pos && self.total < n as u64) {
                for _ in 0..length {
                    self.buf[self.pos] = 0;
                    self.pos = (self.pos + 1) % n;
                }
                self.total += length as u64;
                return;
            }
            let mut src = if distance <= self.pos {
                self.pos - distance
            } else {
                n - (distance - self.pos)
            };
            for _ in 0..length {
                let b = self.buf[src];
                self.buf[self.pos] = b;
                src = (src + 1) % n;
                self.pos = (self.pos + 1) % n;
            }
            self.total += length as u64;
        }
    }

    #[track_caller]
    fn assert_copy_matches_reference(
        dict_size: usize,
        prefill: usize,
        distance: usize,
        length: usize,
    ) {
        let mut window = Window::new(dict_size);
        let mut reference = RefWindow::new(dict_size);
        for i in 0..prefill {
            let b = junk_byte(i);
            window.put_byte(b);
            reference.put_byte(b);
        }

        window.copy(distance, length).unwrap();
        reference.copy(distance, length);

        let ctx = format!("dict={dict_size} prefill={prefill} distance={distance} length={length}");
        assert_eq!(window.position(), reference.pos, "position mismatch: {ctx}");
        assert_eq!(
            window.total_written(),
            reference.total,
            "total mismatch: {ctx}"
        );
        assert_eq!(
            window.logical_buffer(),
            reference.buf.as_slice(),
            "window contents mismatch: {ctx}"
        );
    }

    #[test]
    fn copy_matrix_matches_reference_in_fast_region() {
        // 8192 - MAX_INC_LZ_MATCH = 4092, so a prefill of 64 keeps both the
        // source and the cursor well inside the no-wrap fast region.
        for distance in 1..=32usize {
            for length in 1..=40usize {
                assert_copy_matches_reference(8192, 64, distance, length);
            }
        }
    }

    #[test]
    fn copy_matrix_matches_reference_near_fast_limit() {
        let fast_limit = 8192 - MAX_INC_LZ_MATCH;
        for prefill in [fast_limit - 2, fast_limit - 1, fast_limit, fast_limit + 1] {
            for distance in 1..=32usize {
                for length in 1..=40usize {
                    assert_copy_matches_reference(8192, prefill, distance, length);
                }
            }
        }
    }

    #[test]
    fn copy_matrix_matches_reference_across_wrap() {
        // 128 byte dictionary: `fast_limit` saturates to 0, so every copy takes
        // the wrap-safe path, and prefills straddle the ring boundary.
        for prefill in [10usize, 100, 127, 128, 200] {
            for distance in 1..=32usize {
                for length in 1..=40usize {
                    assert_copy_matches_reference(128, prefill, distance, length);
                }
            }
        }
        // Same, but with a dictionary large enough that the cursor leaves the
        // fast region only because it is near the end of the buffer.
        for distance in 1..=32usize {
            for length in 1..=40usize {
                assert_copy_matches_reference(8192, 8180, distance, length);
            }
        }
    }

    #[test]
    fn copy_matrix_matches_reference_for_wrapped_sources() {
        // distance close to dict_size resolves to `src >= dst`: the source has
        // wrapped around the ring and sits just *ahead* of the write cursor.
        // These are the cases where a block load could pick up bytes the same
        // copy just wrote, so they must agree with the oracle byte loop.
        let dict = 8192;
        for distance in (dict - 40)..=dict {
            for length in 1..=40usize {
                assert_copy_matches_reference(dict, dict + 100, distance, length);
            }
        }
    }

    #[test]
    fn long_match_copies_match_reference() {
        for distance in [
            2usize, 3, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 65, 100, 200,
        ] {
            for length in [
                17usize,
                24,
                31,
                32,
                33,
                63,
                64,
                65,
                100,
                255,
                1000,
                MAX_INC_LZ_MATCH - 1,
                MAX_INC_LZ_MATCH,
                MAX_INC_LZ_MATCH + 1,
            ] {
                assert_copy_matches_reference(8192, 256, distance, length);
            }
        }
    }

    #[test]
    fn short_match_copy_never_writes_past_the_match() {
        // The window starts zeroed and only the prefill is written, so any
        // non-zero byte past `pos + length` is a wildcopy overrun.
        for length in 1..=40usize {
            for distance in [1usize, 2, 3, 7, 8, 9, 15, 16, 17, 40, 63, 64] {
                let mut window = Window::new(8192);
                for i in 0..64 {
                    window.put_byte(junk_byte(i) | 1);
                }
                let guard = window.position() + length;
                window.copy(distance, length).unwrap();
                assert!(
                    window.logical_buffer()[guard..guard + 64]
                        .iter()
                        .all(|&b| b == 0),
                    "copy(distance={distance}, length={length}) wrote past the match end"
                );
            }
        }
    }

    #[test]
    fn first_win_done_tracks_the_write_counter() {
        // `copy_advance` debug-asserts the cached flag against the counter, so
        // exercising every cursor-advancing path here is what proves the cache.
        let mut window = Window::new(16);
        window.put_bytes(b"ABCDEFGH");
        window.copy(8, 4).unwrap(); // fast/slow copy, no wrap
        assert!(!window.first_win_done);
        window.put_literal_batch(b"IJKLMNOP", 4);
        assert_eq!(window.total_written(), 16);
        assert!(window.first_win_done);

        let mut window = Window::new(16);
        window.put_bytes(b"AB");
        window.copy(1, 14).unwrap(); // byte-fill path wraps
        assert!(window.first_win_done);

        let mut window = Window::new(16);
        window.put_bytes(b"AB");
        window.copy(64, 14).unwrap(); // zero-fill path wraps
        assert!(window.first_win_done);

        let mut window = Window::new(16);
        window.put_bytes(b"AB");
        window.copy(0, 14).unwrap(); // cursor-only advance wraps
        assert!(window.first_win_done);

        let mut window = Window::new(16);
        window.put_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); // wrapping put_bytes
        assert!(window.first_win_done);
        window.copy(4, 4).unwrap();
    }

    #[test]
    fn ensure_capacity_reuses_the_allocation_when_shrinking() {
        let mut window = Window::new(64);
        assert_eq!(window.allocated_size(), 64);

        window.ensure_capacity(256).unwrap();
        assert_eq!(window.dict_size(), 256);
        assert_eq!(window.allocated_size(), 256);

        window.reset_for_reuse(32).unwrap();
        assert_eq!(window.dict_size(), 32);
        assert_eq!(window.allocated_size(), 256, "shrink must not reallocate");

        window.reset_for_reuse(256).unwrap();
        assert_eq!(window.dict_size(), 256);
        assert_eq!(window.allocated_size(), 256, "regrow within the allocation");

        assert!(matches!(
            window.ensure_capacity(0),
            Err(RarError::DictionaryTooLarge { size: 0, max: 0 })
        ));
    }

    #[test]
    fn ensure_capacity_preserves_contents_when_it_fits() {
        let mut window = Window::new(64);
        window.put_bytes(b"ABCDEFGH");

        window.ensure_capacity(32).unwrap();

        assert_eq!(window.dict_size(), 32);
        assert_eq!(window.allocated_size(), 64);
        assert_eq!(window.copy_output(0, 8), b"ABCDEFGH");
    }

    /// A decode script that leans on every stale-byte-sensitive path: a match
    /// reaching before anything written, a pre-window distance, an overlapping
    /// repeat, an RLE run, a wrap, and a full-dictionary lookback afterwards.
    fn scripted_decode(window: &mut Window) -> Vec<u8> {
        window.copy(40, 6).unwrap(); // distance beyond written-so-far
        window.put_bytes(b"hello");
        window.copy(5, 12).unwrap(); // overlapping repeat
        window.copy(1, 9).unwrap(); // RLE
        window.put_byte(b'!');
        window.copy(100, 3).unwrap(); // distance beyond the dictionary
        for i in 0..80 {
            window.put_byte(junk_byte(i * 7));
        }
        window.copy(64, 20).unwrap(); // full-dictionary lookback after the wrap
        let total = window.total_written();
        window.copy_output(total - 64, 64)
    }

    #[test]
    fn reset_for_reuse_output_is_independent_of_pre_reset_bytes() {
        let mut fresh = Window::new(64);
        let expected = scripted_decode(&mut fresh);

        let mut reused = Window::new(64);
        for i in 0..500 {
            // `| 1` guarantees every stale byte differs from the zero fill a
            // memset would have produced.
            reused.put_byte(junk_byte(i) | 1);
        }
        let stale = reused.logical_buffer().to_vec();

        reused.reset_for_reuse(64).unwrap();

        assert_eq!(reused.total_written(), 0);
        assert_eq!(reused.total_flushed(), 0);
        assert_eq!(reused.position(), 0);
        assert!(!reused.first_win_done);
        assert_eq!(
            reused.logical_buffer(),
            stale.as_slice(),
            "reset_for_reuse must not memset the dictionary"
        );

        assert_eq!(scripted_decode(&mut reused), expected);
    }

    #[test]
    fn reset_for_reuse_zero_fills_matches_older_than_the_reset() {
        let mut window = Window::new(64);
        for i in 0..500 {
            window.put_byte(junk_byte(i) | 1);
        }

        window.reset_for_reuse(64).unwrap();

        // Every distance is > pos == 0 with the first window not done, so the
        // guard routes to the zero fill instead of the stale bytes.
        window.copy(64, 8).unwrap();
        assert_eq!(window.copy_output(0, 8), &[0u8; 8]);
        window.put_bytes(b"XY");
        window.copy(9, 3).unwrap();
        assert_eq!(window.copy_output(10, 3), &[0u8; 3]);
    }

    #[test]
    fn reset_for_reuse_wraps_at_the_logical_size_after_a_shrink() {
        let mut window = Window::new(256);
        for i in 0..300 {
            window.put_byte(junk_byte(i) | 1);
        }

        window.reset_for_reuse(64).unwrap();
        assert_eq!(window.dict_size(), 64);
        assert_eq!(window.allocated_size(), 256);

        for i in 0..64u8 {
            window.put_byte(i);
        }
        assert_eq!(window.position(), 0, "wrap at the logical size, not 256");
        assert!(window.first_win_done);

        window.put_byte(0xFF);
        assert_eq!(window.position(), 1);
        assert_eq!(window.get_byte(1), 0xFF);
        assert_eq!(window.get_byte(64), 1);

        window.copy(63, 4).unwrap();
        assert_eq!(window.copy_output(65, 4), &[2u8, 3, 4, 5]);
    }

    #[test]
    fn reused_window_matches_a_fresh_window_over_the_copy_matrix() {
        for distance in 1..=32usize {
            for length in 1..=40usize {
                let mut fresh = Window::new(128);
                let mut reused = Window::new(128);
                for i in 0..400 {
                    reused.put_byte(junk_byte(i) | 1);
                }
                reused.reset_for_reuse(128).unwrap();

                for i in 0..200 {
                    let b = junk_byte(i);
                    fresh.put_byte(b);
                    reused.put_byte(b);
                }
                fresh.copy(distance, length).unwrap();
                reused.copy(distance, length).unwrap();

                assert_eq!(
                    reused.logical_buffer(),
                    fresh.logical_buffer(),
                    "distance={distance} length={length}"
                );
            }
        }
    }

    #[test]
    fn try_new_rejects_zero_dictionary() {
        let Err(err) = Window::try_new(0) else {
            panic!("zero dictionary unexpectedly succeeded");
        };
        assert!(matches!(
            err,
            RarError::DictionaryTooLarge { size: 0, max: 0 }
        ));
    }

    #[test]
    fn try_new_reports_capacity_overflow_as_resource_limit() {
        let Err(err) = Window::try_new(usize::MAX) else {
            panic!("usize::MAX dictionary unexpectedly succeeded");
        };
        assert!(matches!(err, RarError::ResourceLimit { .. }));
    }

    #[test]
    fn window_reset_zeroes_storage() {
        let mut window = Window::new(10);
        window.put_bytes(b"ABCDEFGHIJ");
        window.reset();

        window.copy(5, 5).unwrap();

        assert_eq!(window.copy_output(0, 5), b"\0\0\0\0\0");
    }

    #[test]
    fn window_writes_ranges_to_writer() {
        let mut window = Window::new(12);
        window.put_bytes(b"ABCDEFGHIJKL");

        let mut out = Vec::new();
        window.write_range_to_writer(3, 7, &mut out).unwrap();

        assert_eq!(out, b"DEFGHIJ");
        assert_eq!(window.try_copy_output(2, 8).unwrap(), b"CDEFGHIJ");
    }

    #[test]
    fn test_put_byte() {
        let mut w = Window::new(16);
        w.put_byte(0xAA);
        w.put_byte(0xBB);
        assert_eq!(w.total_written(), 2);
        assert_eq!(w.position(), 2);
    }

    #[test]
    fn test_get_byte() {
        let mut w = Window::new(16);
        w.put_byte(0x01);
        w.put_byte(0x02);
        w.put_byte(0x03);
        // distance=1 -> last byte = 0x03
        assert_eq!(w.get_byte(1), 0x03);
        // distance=2 -> 0x02
        assert_eq!(w.get_byte(2), 0x02);
        // distance=3 -> 0x01
        assert_eq!(w.get_byte(3), 0x01);
    }

    #[test]
    fn test_copy_non_overlapping() {
        let mut w = Window::new(256);
        // Write "ABCD"
        w.put_byte(b'A');
        w.put_byte(b'B');
        w.put_byte(b'C');
        w.put_byte(b'D');
        // Copy from distance=4 (start of "ABCD"), length=4
        w.copy(4, 4).unwrap();
        assert_eq!(w.total_written(), 8);
        // Should have written "ABCDABCD"
        let output = w.copy_output(0, 8);
        assert_eq!(&output, b"ABCDABCD");
    }

    #[test]
    fn test_copy_overlapping() {
        let mut w = Window::new(256);
        // Write single byte
        w.put_byte(b'X');
        // Copy from distance=1, length=5 => repeat 'X' 5 times
        w.copy(1, 5).unwrap();
        assert_eq!(w.total_written(), 6);
        let output = w.copy_output(0, 6);
        assert_eq!(&output, b"XXXXXX");
    }

    #[test]
    fn test_copy_pattern_repeat() {
        let mut w = Window::new(256);
        // Write "AB"
        w.put_byte(b'A');
        w.put_byte(b'B');
        // Copy distance=2, length=6 => "ABABAB"
        w.copy(2, 6).unwrap();
        let output = w.copy_output(0, 8);
        assert_eq!(&output, b"ABABABAB");
    }

    #[test]
    fn test_wrap_around() {
        let mut w = Window::new(4);
        // Write 5 bytes, should wrap around
        w.put_byte(b'A');
        w.put_byte(b'B');
        w.put_byte(b'C');
        w.put_byte(b'D');
        w.put_byte(b'E'); // wraps, overwrites 'A'
        assert_eq!(w.position(), 1);
        assert_eq!(w.total_written(), 5);
        // Last byte (distance=1) should be 'E'
        assert_eq!(w.get_byte(1), b'E');
        // 4 back from current should be 'B' (D was at pos 3, C at 2, B at 1)
        assert_eq!(w.get_byte(4), b'B');
    }

    #[test]
    fn test_copy_across_wrap() {
        let mut w = Window::new(8);
        // Fill to near wrap point
        for b in b"ABCDEF" {
            w.put_byte(*b);
        }
        // pos is now 6. Copy distance=4, length=4 => copies "CDEF"
        // This will wrap around the buffer
        w.copy(4, 4).unwrap();
        assert_eq!(w.total_written(), 10);
        let output = w.copy_output(6, 4);
        assert_eq!(&output, b"CDEF");
    }

    #[test]
    fn test_copy_output() {
        let mut w = Window::new(256);
        for b in b"Hello, world!" {
            w.put_byte(*b);
        }
        let output = w.copy_output(0, 13);
        assert_eq!(&output, b"Hello, world!");
        let partial = w.copy_output(7, 6);
        assert_eq!(&partial, b"world!");
    }

    #[test]
    fn test_try_copy_output_rejects_future_start() {
        let mut w = Window::new(16);
        for b in b"abc" {
            w.put_byte(*b);
        }

        assert!(matches!(
            w.try_copy_output(4, 1),
            Err(RarError::CorruptArchive { .. })
        ));
    }

    #[test]
    fn test_try_copy_output_rejects_evicted_history() {
        let mut w = Window::new(4);
        for b in b"abcdef" {
            w.put_byte(*b);
        }

        assert!(matches!(
            w.try_copy_output(0, 1),
            Err(RarError::CorruptArchive { .. })
        ));
    }

    #[test]
    fn test_reset() {
        let mut w = Window::new(16);
        w.put_byte(0xFF);
        w.put_byte(0xAA);
        w.reset();
        assert_eq!(w.total_written(), 0);
        assert_eq!(w.position(), 0);
    }

    #[test]
    fn test_large_copy() {
        let mut w = Window::new(1024);
        // Write a pattern and copy it many times
        for i in 0..10u8 {
            w.put_byte(i);
        }
        w.copy(10, 100).unwrap(); // repeat 10-byte pattern 10 times
        assert_eq!(w.total_written(), 110);
        let output = w.copy_output(0, 110);
        for (i, &b) in output.iter().enumerate() {
            assert_eq!(b, (i % 10) as u8, "mismatch at position {i}");
        }
    }

    #[test]
    fn test_copy_single_byte_repeat() {
        // distance=1 with large length: classic RLE pattern
        let mut w = Window::new(256);
        w.put_byte(b'Z');
        w.copy(1, 255).unwrap();
        assert_eq!(w.total_written(), 256);
        let output = w.copy_output(0, 256);
        assert!(output.iter().all(|&b| b == b'Z'));
    }

    #[test]
    fn test_distance_one_fill_handles_multiple_wraps() {
        let mut w = Window::new(4);
        w.put_byte(b'Z');
        w.copy(1, 10).unwrap();

        assert_eq!(w.total_written(), 11);
        assert_eq!(w.position(), 3);
        for distance in 1..=4 {
            assert_eq!(w.get_byte(distance), b'Z');
        }
    }

    #[test]
    fn test_copy_output_partial() {
        let mut w = Window::new(256);
        for b in b"0123456789" {
            w.put_byte(*b);
        }
        // Read just the middle portion
        let output = w.copy_output(3, 4);
        assert_eq!(&output, b"3456");
    }

    #[test]
    fn test_multiple_wraps() {
        let mut w = Window::new(4);
        // Write 12 bytes through a 4-byte window (3 full wraps)
        for i in 0..12u8 {
            w.put_byte(i);
        }
        assert_eq!(w.total_written(), 12);
        assert_eq!(w.position(), 0); // 12 % 4 = 0
        // Last 4 bytes should be 8, 9, 10, 11
        assert_eq!(w.get_byte(1), 11);
        assert_eq!(w.get_byte(2), 10);
        assert_eq!(w.get_byte(3), 9);
        assert_eq!(w.get_byte(4), 8);
    }

    #[test]
    fn test_generic_zero_distance_preserves_zeroed_first_window_like_rar_behavior() {
        let mut w = Window::new(8);
        w.put_bytes(b"ABCD");

        w.copy(0, 2).unwrap();

        assert_eq!(w.total_written(), 6);
        assert_eq!(w.copy_output(4, 2), b"\0\0");
        assert_eq!(w.get_byte(1), 0);
        assert_eq!(w.get_byte(2), 0);
    }

    #[test]
    fn test_generic_zero_distance_preserves_wrapped_window_bytes_like_rar_behavior() {
        let mut w = Window::new(4);
        w.put_bytes(b"ABCD");
        w.put_byte(b'E');

        w.copy(0, 2).unwrap();

        assert_eq!(w.total_written(), 7);
        assert_eq!(w.copy_output(5, 2), b"BC");
        assert_eq!(w.get_byte(1), b'C');
        assert_eq!(w.get_byte(2), b'B');
    }

    #[test]
    fn test_rar15_zero_distance_still_zero_fills() {
        let mut w = Window::new(4);
        w.put_bytes(b"ABCD");
        w.put_byte(b'E');

        w.copy_rar15_with_visible_len(0, 2, 2).unwrap();

        assert_eq!(w.total_written(), 7);
        assert_eq!(w.copy_output(5, 2), b"\0\0");
        assert_eq!(w.get_byte(1), 0);
        assert_eq!(w.get_byte(2), 0);
    }

    #[test]
    fn test_window_valid_distance() {
        let mut w = Window::new(256);
        w.put_byte(b'A');

        assert!(w.copy(1, 1).is_ok());
    }

    #[test]
    fn test_pre_window_distance_zero_fills_like_rar_behavior() {
        let mut w = Window::new(8);
        w.put_byte(b'A');

        w.copy(4, 3).unwrap();

        assert_eq!(w.total_written(), 4);
        assert_eq!(w.get_byte(1), 0);
        assert_eq!(w.get_byte(2), 0);
        assert_eq!(w.get_byte(3), 0);
        assert_eq!(w.get_byte(4), b'A');
    }

    #[test]
    fn test_oversize_distance_zero_fills_like_rar_behavior() {
        let mut w = Window::new(8);
        w.put_bytes(b"ABCD");

        w.copy(9, 2).unwrap();

        assert_eq!(w.total_written(), 6);
        assert_eq!(w.get_byte(1), 0);
        assert_eq!(w.get_byte(2), 0);
    }

    #[test]
    fn full_match_can_advance_dictionary_past_visible_output() {
        let mut w = Window::new(16);
        w.put_bytes(b"ABCD");
        w.mark_flushed(4);

        w.copy_with_visible_len(4, 4, 2).unwrap();

        assert_eq!(w.total_written(), 8);
        assert_eq!(w.copy_output(4, 2), b"AB");
        assert_eq!(w.copy_output(6, 2), b"CD");

        let mut emitted = Vec::new();
        assert_eq!(w.flush_to_writer(&mut emitted).unwrap(), 2);
        assert_eq!(emitted, b"AB");
        assert_eq!(w.total_flushed(), w.total_written());
    }

    #[test]
    fn visible_ranges_skip_hidden_gap_before_later_output() {
        let mut w = Window::new(16);
        w.put_bytes(b"ABCD");
        w.mark_flushed(4);
        w.copy_with_visible_len(4, 4, 2).unwrap();
        w.put_bytes(b"Z");

        let mut emitted = Vec::new();
        assert_eq!(w.flush_to_writer(&mut emitted).unwrap(), 3);
        assert_eq!(emitted, b"ABZ");
        assert_eq!(w.total_flushed(), w.total_written());
    }

    #[test]
    fn visible_subranges_reports_only_visible_parts_inside_range() {
        let mut w = Window::new(16);
        w.put_bytes(b"ABCD");
        w.mark_flushed(4);
        w.copy_with_visible_len(4, 4, 2).unwrap();
        w.put_bytes(b"Z");

        assert_eq!(w.visible_subranges(4, 5), vec![(0, 2), (4, 1)]);
        assert_eq!(w.visible_subranges(6, 3), vec![(2, 1)]);
        assert!(w.visible_subranges(6, 2).is_empty());
    }

    #[test]
    fn flush_visible_until_stops_before_hidden_gap_boundary() {
        let mut w = Window::new(16);
        w.put_bytes(b"ABCD");
        w.mark_flushed(4);
        w.copy_with_visible_len(4, 4, 2).unwrap();
        w.put_bytes(b"Z");

        let mut emitted = Vec::new();
        assert_eq!(w.flush_visible_until(6, &mut emitted).unwrap(), 2);
        assert_eq!(emitted, b"AB");
        assert_eq!(w.total_flushed(), 6);

        let mut tail = Vec::new();
        assert_eq!(w.flush_to_writer(&mut tail).unwrap(), 1);
        assert_eq!(tail, b"Z");
        assert_eq!(w.total_flushed(), w.total_written());
    }

    #[test]
    fn test_distance_wraps_after_first_window_done() {
        let mut w = Window::new(4);
        w.put_bytes(b"ABCD");
        w.put_byte(b'E');

        w.copy(3, 2).unwrap();

        assert_eq!(w.get_byte(1), b'D');
        assert_eq!(w.get_byte(2), b'C');
    }

    #[test]
    fn overlong_match_candidate_uses_wrap_safe_copy_path() {
        let mut w = Window::new(8192);
        w.put_bytes(b"AB");

        w.copy(2, MAX_INC_LZ_MATCH + 2048).unwrap();

        assert_eq!(w.total_written(), (MAX_INC_LZ_MATCH + 2050) as u64);
        assert_eq!(w.position(), (MAX_INC_LZ_MATCH + 2050) % 8192);
    }

    #[test]
    fn test_copy_wraps_source_and_dest() {
        // Window of 8, write 6 bytes, then copy distance=6, length=8
        // This wraps both source and destination
        let mut w = Window::new(8);
        for b in b"ABCDEF" {
            w.put_byte(*b);
        }
        // pos = 6, copy from pos 0 (dist=6), length=8
        // Should produce: ABCDEF ABCDEFAB (wrapping)
        w.copy(6, 8).unwrap();
        assert_eq!(w.total_written(), 14);
        // Last 8 bytes written
        let output = w.copy_output(6, 8);
        assert_eq!(&output, b"ABCDEFAB");
    }

    #[test]
    fn test_flush_to_writer_rejects_overfull_unflushed_region() {
        let mut w = Window::new(8);
        for i in 0..16u8 {
            w.put_byte(i);
        }

        let mut out = Vec::new();
        let err = w.flush_to_writer(&mut out).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
