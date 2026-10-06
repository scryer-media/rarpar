//! Explicit-candidate content placement with bounded CRC64 sliding searches.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot, read_exact_at};
use crate::{Fingerprint, FingerprintHasher};

/// Work limits and explicit source filtering for content discovery.
#[derive(Clone, Debug)]
pub struct PlacementOptions {
    /// Cumulative source bytes read, including strong-hash confirmations.
    pub max_read_bytes: u64,
    /// Maximum candidate sources to inspect.
    pub max_candidates: usize,
    /// Maximum confirmed matches to retain.
    pub max_matches: usize,
    /// If nonempty, only these source identities may be searched.
    pub allowlist: BTreeSet<SourceId>,
    /// These identities are always excluded.
    pub blocklist: BTreeSet<SourceId>,
}

impl Default for PlacementOptions {
    fn default() -> Self {
        Self {
            max_read_bytes: 1 << 30,
            max_candidates: 1024,
            max_matches: 64,
            allowlist: BTreeSet::new(),
            blocklist: BTreeSet::new(),
        }
    }
}

/// Strong evidence for an extent found at a different source offset.
#[derive(Clone, Debug)]
pub struct PlacedExtent {
    pub(crate) layout: Fingerprint,
    pub(crate) file: usize,
    pub(crate) extent: usize,
    pub(crate) source: SourceId,
    pub(crate) snapshot: SourceSnapshot,
    pub(crate) offset: u64,
    _reservation: Arc<Reservation>,
}

impl PlacedExtent {
    /// Source containing the confirmed bytes.
    #[must_use]
    pub fn source(&self) -> SourceId {
        self.source
    }
    /// Start of the extent in that source.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Source generation which must remain immutable.
    #[must_use]
    pub fn snapshot(&self) -> SourceSnapshot {
        self.snapshot
    }

    pub(crate) fn rehome(&mut self, options: &ExecutionOptions) -> EngineResult<()> {
        if !self._reservation.belongs_to(&options.memory) {
            self._reservation = Arc::new(
                options
                    .memory
                    .reserve_as(self._reservation.category(), self._reservation.bytes())?,
            );
        }
        Ok(())
    }
}

/// Results and measured work from one explicit search.
#[derive(Debug)]
pub struct PlacementReport {
    /// Matches confirmed using the required BLAKE3 fingerprint.
    pub matches: Vec<PlacedExtent>,
    /// Total bytes read, including CRC candidates rejected by BLAKE3.
    pub read_bytes: u64,
    /// Number of candidate sources inspected.
    pub candidates: usize,
}

/// Locate one block or described tail without discovering directories. CRC64
/// filters positions; only complete BLAKE3 matches produce placement evidence.
pub fn search_extent(
    layout: &BlockLayout,
    file: usize,
    extent: usize,
    access: &dyn SourceAccess,
    candidates: &[SourceId],
    limits: &PlacementOptions,
    options: &ExecutionOptions,
) -> EngineResult<PlacementReport> {
    let mut progress = options.stage(crate::runtime::Stage::Placement)?;
    let description = layout
        .files
        .get(file)
        .and_then(|file| file.extents.get(extent))
        .ok_or(EngineError::InvalidState("unknown placement extent"))?;
    let length = description.range.end - description.range.start;
    let (expected, crc, window) = match description.kind {
        ExtentKind::Block {
            fingerprint: Some(hash),
            rolling_hash: Some(crc),
            ..
        } => (
            hash,
            crc,
            if length == layout.block_size {
                length
            } else {
                40
            },
        ),
        _ => {
            return Err(EngineError::Unsupported(
                "placement requires extent fingerprints and CRC64",
            ));
        }
    };
    let window =
        usize::try_from(window).map_err(|_| EngineError::resource_limit("placement window"))?;
    if window == 0 || window as u64 > length {
        return Err(EngineError::InvalidState("invalid placement window"));
    }
    let stripe = options.stripe_bytes.min(64 << 10);
    let size = window
        .checked_add(
            stripe
                .checked_mul(2)
                .ok_or(EngineError::resource_limit("placement buffers"))?,
        )
        .and_then(|size| size.checked_add(8192))
        .and_then(|size| size.checked_add(candidates.len().checked_mul(32)?))
        .ok_or(EngineError::resource_limit("placement buffers"))?;
    let _buffers = options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size)?;
    let mut sliding = SlidingWindow::new(window);
    let mut input = vec![0; stripe];
    let mut confirmation = vec![0; stripe];
    let roll = SlidingCrc::new(window as u64);
    let mut report = PlacementReport {
        matches: Vec::new(),
        read_bytes: 0,
        candidates: 0,
    };
    let mut visited = BTreeSet::new();
    for &source in candidates {
        options.cancel.check()?;
        if limits.blocklist.contains(&source)
            || (!limits.allowlist.is_empty() && !limits.allowlist.contains(&source))
        {
            continue;
        }
        if visited.contains(&source) {
            continue;
        }
        if report.candidates >= limits.max_candidates {
            return Err(EngineError::resource_limit("placement candidates"));
        }
        visited.insert(source);
        report.candidates += 1;
        let Some(snapshot) = access.snapshot(source)? else {
            continue;
        };
        let mut next = 0;
        while let Some(range) = access.next_available(source, next)? {
            options.cancel.check()?;
            if range.start < next || range.end <= range.start || range.end > snapshot.len {
                return Err(EngineError::InvalidState(
                    "invalid placement availability range",
                ));
            }
            next = range.end;
            if range.end - range.start < window as u64 {
                continue;
            }
            charge(&mut report, window as u64, limits)?;
            sliding.start(&roll, |ring| {
                read_exact_at(&options.diagnostics, access, source, range.start, ring)
            })?;
            progress.advance(window as u64);
            // Absolute offset of `input[0]`; the window ends at `at + consumed`.
            let mut at = range.start + window as u64;
            let mut take = 0;
            let mut consumed = 0;
            let mut candidate = sliding.crc(&roll) == crc;
            loop {
                options.cancel.check()?;
                let start = at + consumed as u64 - window as u64;
                if candidate
                    && start
                        .checked_add(length)
                        .is_some_and(|end| end <= range.end)
                {
                    // The window and the rest of the stripe are already in
                    // memory; only bytes beyond both are read to confirm.
                    let mut hash = FingerprintHasher::new();
                    for piece in sliding.pieces(&input[..take], consumed) {
                        hash.update(piece);
                    }
                    let buffered = (length - window as u64).min((take - consumed) as u64);
                    hash.update(&input[consumed..consumed + buffered as usize]);
                    let mut position = start + window as u64 + buffered;
                    while position - start < length {
                        options.cancel.check()?;
                        let count = (length - (position - start)).min(stripe as u64) as usize;
                        charge(&mut report, count as u64, limits)?;
                        read_exact_at(
                            &options.diagnostics,
                            access,
                            source,
                            position,
                            &mut confirmation[..count],
                        )?;
                        hash.update(&confirmation[..count]);
                        position += count as u64;
                    }
                    if hash.finalize() == expected {
                        ensure_snapshot(access, source, snapshot)?;
                        if report.matches.len() >= limits.max_matches {
                            return Err(EngineError::resource_limit("placement matches"));
                        }
                        let reservation = options
                            .memory
                            .reserve_as(MemoryCategory::LayoutEvidence, 512)?;
                        report.matches.push(PlacedExtent {
                            layout: layout.identity,
                            file,
                            extent,
                            source,
                            snapshot,
                            offset: start,
                            _reservation: Arc::new(reservation),
                        });
                    }
                }
                // Stop at the next CRC candidate, retaining the remaining input
                // buffer while confirming it so each search byte is read once.
                if let Some(used) =
                    sliding.scan(&roll, &input[..take], consumed, |value| value == crc)
                {
                    consumed = used;
                    candidate = true;
                    continue;
                }
                sliding.push(&input[..take]);
                at += take as u64;
                if at >= range.end {
                    break;
                }
                take = (range.end - at).min(stripe as u64) as usize;
                charge(&mut report, take as u64, limits)?;
                read_exact_at(&options.diagnostics, access, source, at, &mut input[..take])?;
                progress.advance(take as u64);
                consumed = 0;
                candidate = false;
            }
        }
        ensure_snapshot(access, source, snapshot)?;
    }
    Ok(report)
}

fn charge(report: &mut PlacementReport, bytes: u64, limits: &PlacementOptions) -> EngineResult<()> {
    report.read_bytes = report
        .read_bytes
        .checked_add(bytes)
        .filter(|bytes| *bytes <= limits.max_read_bytes)
        .ok_or(EngineError::resource_limit("placement read work"))?;
    Ok(())
}

// Reflected CRC-64/GO-ISO, expressed as a linear state plus its affine initial
// value. Removing an outgoing byte is a polynomial shift, not a second hash.
// The reflected polynomial only sets bits 59, 60, 62 and 63, so for up to 60
// consumed bits no reduction reaches the low bits still to be consumed, and the
// bitwise iterations collapse to four shifts of the consumed bits.
#[inline(always)]
fn step(state: u64, byte: u8) -> u64 {
    let consumed = (state ^ byte as u64) << 56;
    (state >> 8) ^ consumed ^ (consumed >> 1) ^ (consumed >> 3) ^ (consumed >> 4)
}

/// Four bytes at once, with the little-endian `word` as input.
#[inline(always)]
fn step4(state: u64, word: u32) -> u64 {
    let consumed = (state ^ word as u64) << 32;
    (state >> 32) ^ consumed ^ (consumed >> 1) ^ (consumed >> 3) ^ (consumed >> 4)
}

fn apply(matrix: &[u64; 64], mut value: u64) -> u64 {
    let mut output = 0;
    while value != 0 {
        let bit = value.trailing_zeros() as usize;
        output ^= matrix[bit];
        value &= value - 1;
    }
    output
}

/// The linear map which advances a state across `bytes` zero bytes.
fn power(mut bytes: u64) -> [u64; 64] {
    let mut result = std::array::from_fn(|bit| 1u64 << bit);
    let mut matrix = std::array::from_fn(|bit| step(1u64 << bit, 0));
    while bytes != 0 {
        if bytes & 1 != 0 {
            result = std::array::from_fn(|bit| apply(&matrix, result[bit]));
        }
        bytes >>= 1;
        if bytes != 0 {
            matrix = std::array::from_fn(|bit| apply(&matrix, matrix[bit]));
        }
    }
    result
}

pub(crate) struct SlidingCrc {
    /// `remove[k][byte]`: an outgoing byte's contribution, advanced `k` more
    /// zero bytes, so four positions can be rolled from one state.
    remove: [[u64; 256]; 4],
    initial: u64,
}

impl SlidingCrc {
    pub(crate) fn new(window: u64) -> Self {
        let power = power(window);
        let bits: [u64; 8] = std::array::from_fn(|bit| apply(&power, step(0, 1 << bit)));
        let mut remove = [std::array::from_fn(|byte| {
            (0..8)
                .filter(|bit| byte & (1 << bit) != 0)
                .fold(0, |value, bit| value ^ bits[bit])
        }); 4];
        for later in 1..4 {
            remove[later] = remove[later - 1].map(|value| step(value, 0));
        }
        Self {
            remove,
            initial: apply(&power, u64::MAX),
        }
    }
    pub(crate) fn finish(&self, raw: u64) -> u64 {
        !(raw ^ self.initial)
    }
    /// Linear state of one complete window, via the vectorized CRC.
    fn raw(&self, window: &[u8]) -> u64 {
        !crate::rolling_hash(window) ^ self.initial
    }
    /// Roll `incoming[i]` in as `outgoing[i]` leaves, stopping after the first
    /// CRC accepted by `hit`; returns how many bytes were consumed at that hit.
    #[inline(always)]
    fn roll(
        &self,
        raw: &mut u64,
        incoming: &[u8],
        outgoing: &[u8],
        hit: impl Fn(u64) -> bool,
    ) -> Option<usize> {
        let [r0, r1, r2, r3] = &self.remove;
        let mut state = *raw;
        let mut index = 0;
        // The carried state advances four bytes per dependent step; the three
        // positions between are side branches which only feed the test.
        for (input, old) in incoming.chunks_exact(4).zip(outgoing.chunks_exact(4)) {
            let (o0, o1, o2, o3) = (
                old[0] as usize,
                old[1] as usize,
                old[2] as usize,
                old[3] as usize,
            );
            let s1 = step(state, input[0]) ^ r0[o0];
            let s2 = step(s1, input[1]) ^ r0[o1];
            let s3 = step(s2, input[2]) ^ r0[o2];
            let word = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            let s4 = step4(state, word) ^ (r3[o0] ^ r2[o1]) ^ (r1[o2] ^ r0[o3]);
            let found = [s1, s2, s3, s4];
            if found.iter().any(|state| hit(self.finish(*state))) {
                let offset = found
                    .iter()
                    .position(|state| hit(self.finish(*state)))
                    .unwrap_or(3);
                *raw = found[offset];
                return Some(index + offset + 1);
            }
            state = s4;
            index += 4;
        }
        for (&byte, &old) in incoming[index..].iter().zip(&outgoing[index..]) {
            state = step(state, byte) ^ r0[old as usize];
            index += 1;
            if hit(self.finish(state)) {
                *raw = state;
                return Some(index);
            }
        }
        *raw = state;
        None
    }
}

/// The trailing `window` bytes of a sliding search. Each input stripe is rolled
/// as contiguous slice pairs; the ring only bridges stripe boundaries, so the
/// outgoing byte of a position past the first window comes from the stripe.
pub(crate) struct SlidingWindow {
    ring: Vec<u8>,
    cursor: usize,
    raw: u64,
}

impl SlidingWindow {
    pub(crate) fn new(window: usize) -> Self {
        Self {
            ring: vec![0; window],
            cursor: 0,
            raw: 0,
        }
    }
    /// Restart from a window filled by `read`.
    pub(crate) fn start(
        &mut self,
        roll: &SlidingCrc,
        read: impl FnOnce(&mut [u8]) -> EngineResult<()>,
    ) -> EngineResult<()> {
        read(&mut self.ring)?;
        self.cursor = 0;
        self.raw = roll.raw(&self.ring);
        Ok(())
    }
    pub(crate) fn crc(&self, roll: &SlidingCrc) -> u64 {
        roll.finish(self.raw)
    }
    /// Roll `input[from..]` until `hit` accepts a CRC and return the count of
    /// `input` bytes consumed at that position. `input` follows the window.
    pub(crate) fn scan(
        &mut self,
        roll: &SlidingCrc,
        input: &[u8],
        mut from: usize,
        hit: impl Fn(u64) -> bool,
    ) -> Option<usize> {
        let window = self.ring.len();
        let wrap = window - self.cursor;
        while from < input.len() {
            let outgoing = if from < wrap {
                &self.ring[self.cursor + from..]
            } else if from < window {
                &self.ring[from - wrap..self.cursor]
            } else {
                &input[from - window..]
            };
            let count = outgoing.len().min(input.len() - from);
            if let Some(used) = roll.roll(
                &mut self.raw,
                &input[from..from + count],
                &outgoing[..count],
                &hit,
            ) {
                return Some(from + used);
            }
            from += count;
        }
        None
    }
    /// The window after `consumed` bytes of `input`, oldest bytes first.
    pub(crate) fn pieces<'a>(&'a self, input: &'a [u8], consumed: usize) -> [&'a [u8]; 3] {
        let window = self.ring.len();
        let wrap = window - self.cursor;
        let (first, second): (&[u8], &[u8]) = if consumed < wrap {
            (
                &self.ring[self.cursor + consumed..],
                &self.ring[..self.cursor],
            )
        } else if consumed < window {
            (&self.ring[consumed - wrap..self.cursor], &[])
        } else {
            (&[], &[])
        };
        [
            first,
            second,
            &input[consumed.saturating_sub(window)..consumed],
        ]
    }
    /// Retire a completely rolled stripe into the ring.
    pub(crate) fn push(&mut self, input: &[u8]) {
        let window = self.ring.len();
        if input.len() >= window {
            self.ring.copy_from_slice(&input[input.len() - window..]);
            self.cursor = 0;
            return;
        }
        let first = input.len().min(window - self.cursor);
        self.ring[self.cursor..self.cursor + first].copy_from_slice(&input[..first]);
        self.ring[..input.len() - first].copy_from_slice(&input[first..]);
        self.cursor += input.len();
        if self.cursor >= window {
            self.cursor -= window;
        }
    }
}

/// Exact-miss prefilter over wanted CRC64 values: a clear bit proves that no
/// wanted value shares those high bits. At least `BITS_PER_VALUE` bits per
/// value keep false positives, each of which interrupts the roll, at or below
/// one in 64 positions.
pub(crate) struct CrcFilter {
    words: Vec<u64>,
    shift: u32,
    len: usize,
}

const BITS_PER_VALUE: usize = 64;

impl CrcFilter {
    pub(crate) fn new(values: impl ExactSizeIterator<Item = u64>) -> Self {
        let bits = values
            .len()
            .max(1)
            .saturating_mul(BITS_PER_VALUE)
            .next_power_of_two()
            .max(64);
        let mut filter = Self {
            words: vec![0; bits / 64],
            shift: 64 - bits.trailing_zeros(),
            len: 0,
        };
        values.for_each(|value| filter.set(value));
        filter
    }
    fn set(&mut self, value: u64) {
        let bit = (value >> self.shift) as usize;
        self.words[bit / 64] |= 1 << (bit % 64);
        self.len += 1;
    }
    /// Add one value, or report that the caller must rebuild a larger filter.
    pub(crate) fn insert(&mut self, value: u64) -> bool {
        if (self.len + 1).saturating_mul(BITS_PER_VALUE) > self.words.len() * 64 {
            return false;
        }
        self.set(value);
        true
    }
    #[inline(always)]
    pub(crate) fn contains(&self, value: u64) -> bool {
        let bit = (value >> self.shift) as usize;
        self.words[bit / 64] & (1 << (bit % 64)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step_bitwise(mut state: u64, byte: u8) -> u64 {
        state ^= byte as u64;
        for _ in 0..8 {
            state = (state >> 1) ^ (0xd800_0000_0000_0000 & 0u64.wrapping_sub(state & 1));
        }
        state
    }

    #[test]
    fn byte_step_matches_the_bitwise_reference() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..4096u64 {
            let probe = match round {
                0 => 0,
                1 => u64::MAX,
                _ => state,
            };
            for byte in 0..=255u8 {
                assert_eq!(
                    step(probe, byte),
                    step_bitwise(probe, byte),
                    "{probe:x} {byte}"
                );
            }
            let word = (state >> 13) as u32 ^ round as u32;
            let bitwise = word
                .to_le_bytes()
                .iter()
                .fold(probe, |value, byte| step_bitwise(value, *byte));
            assert_eq!(step4(probe, word), bitwise, "{probe:x} {word:x}");
            state = state.rotate_left(17).wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ round;
        }
        for bit in 0..64 {
            for byte in 0..=255u8 {
                assert_eq!(step(1 << bit, byte), step_bitwise(1 << bit, byte));
            }
        }
    }

    #[test]
    fn sliding_window_scans_stripes_and_reports_every_window() {
        let bytes: Vec<u8> = (0..3000u32)
            .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for window in [1, 2, 7, 40, 255, 1024] {
            let roll = SlidingCrc::new(window as u64);
            for stripe in [1, 3, 40, 127, 4096] {
                let mut sliding = SlidingWindow::new(window);
                sliding
                    .start(&roll, |ring| {
                        ring.copy_from_slice(&bytes[..window]);
                        Ok(())
                    })
                    .unwrap();
                let mut at = window;
                let mut seen = 0;
                while at < bytes.len() {
                    let input = &bytes[at..(at + stripe).min(bytes.len())];
                    let mut consumed = 0;
                    // Accept every position so each window is checked.
                    while let Some(used) = sliding.scan(&roll, input, consumed, |_| true) {
                        assert_eq!(used, consumed + 1);
                        consumed = used;
                        let end = at + consumed;
                        let expected = &bytes[end - window..end];
                        assert_eq!(sliding.crc(&roll), crate::rolling_hash(expected));
                        assert_eq!(sliding.pieces(input, consumed).concat(), expected);
                        seen += 1;
                    }
                    sliding.push(input);
                    at += input.len();
                }
                assert_eq!(seen, bytes.len() - window, "{window} {stripe}");
            }
        }
    }

    #[test]
    fn crc_filter_never_misses_and_grows() {
        let values: Vec<u64> = (0..5000u64)
            .map(|index| index.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .collect();
        let mut filter = CrcFilter::new(std::iter::empty());
        for (count, &value) in values.iter().enumerate() {
            if !filter.insert(value) {
                filter = CrcFilter::new(values[..=count].iter().copied());
            }
            assert!(values[..=count].iter().all(|value| filter.contains(*value)));
        }
        let false_positive = (0..100_000u64)
            .map(|index| index.wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ 0x5555)
            .filter(|value| filter.contains(*value))
            .count();
        assert!(false_positive < 100_000 / 8, "{false_positive}");
    }

    /// Bare roll throughput; run with `--release -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn roll_throughput() {
        let window = 1 << 20;
        let mut seed = 0x243f_6a88_85a3_08d3u64;
        let bytes: Vec<u8> = (0..(window + (128 << 20)))
            .map(|_| {
                seed = seed.rotate_left(23).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x1234_5678;
                (seed >> 56) as u8
            })
            .collect();
        let rolled = (bytes.len() - window) as f64;
        let roll = SlidingCrc::new(window as u64);
        let started = std::time::Instant::now();
        for _ in 0..64 {
            std::hint::black_box(SlidingCrc::new(std::hint::black_box(window as u64)));
        }
        println!("SlidingCrc::new: {:?}", started.elapsed() / 64);

        // Previous shape: bitwise step, ring store and a modulo per byte.
        let started = std::time::Instant::now();
        let mut ring = bytes[..window].to_vec();
        let mut raw = roll.raw(&ring);
        let mut cursor = 0;
        let mut hits = 0;
        for &byte in &bytes[window..] {
            raw = step_bitwise(raw, byte) ^ roll.remove[0][ring[cursor] as usize];
            ring[cursor] = byte;
            cursor = (cursor + 1) % window;
            hits += usize::from(roll.finish(raw) == 1);
        }
        let old = started.elapsed();
        let old_raw = raw;

        fn run(
            name: &str,
            bytes: &[u8],
            roll: &SlidingCrc,
            expected: u64,
            hit: impl Fn(u64) -> bool + Copy,
        ) {
            let (window, stripe) = (1 << 20, 64 << 10);
            let started = std::time::Instant::now();
            let mut sliding = SlidingWindow::new(window);
            sliding
                .start(roll, |ring| {
                    ring.copy_from_slice(&bytes[..window]);
                    Ok(())
                })
                .unwrap();
            for input in bytes[window..].chunks(stripe) {
                let mut consumed = 0;
                while let Some(used) = sliding.scan(roll, input, consumed, hit) {
                    consumed = used;
                }
                sliding.push(input);
            }
            let elapsed = started.elapsed();
            assert_eq!(sliding.raw, expected);
            println!(
                "{name}: {:.0} MiB/s",
                (bytes.len() - window) as f64 / elapsed.as_secs_f64() / f64::from(1 << 20)
            );
        }
        println!(
            "bitwise ring: {:.0} MiB/s ({hits})",
            rolled / old.as_secs_f64() / f64::from(1 << 20)
        );
        run("slice, one target", &bytes, &roll, old_raw, |value| {
            value == 1
        });
        let filter = CrcFilter::new(
            (0..1024u32).map(|value| u64::from(value).wrapping_mul(0x9e37_79b9_7f4a_7c15)),
        );
        run("slice, filtered 1024", &bytes, &roll, old_raw, |value| {
            filter.contains(value)
        });
    }

    #[test]
    fn sliding_crc_agrees_with_authoritative_hash_at_every_offset() {
        let bytes: Vec<u8> = (0..5000)
            .map(|index| (index * 97 + index / 17) as u8)
            .collect();
        for window in [1, 2, 40, 255, 1024] {
            let roll = SlidingCrc::new(window as u64);
            let mut raw = bytes[..window]
                .iter()
                .fold(0, |state, byte| step(state, *byte));
            for at in 0..=bytes.len() - window {
                assert_eq!(
                    roll.finish(raw),
                    crate::rolling_hash(&bytes[at..at + window])
                );
                if at + window < bytes.len() {
                    raw = step(raw, bytes[at + window]) ^ roll.remove[0][bytes[at] as usize];
                }
            }
        }
    }
}
