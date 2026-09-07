//! Explicit-candidate content placement with bounded CRC64 sliding searches.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
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
            self._reservation = Arc::new(options.memory.reserve(self._reservation.bytes())?);
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
    options.validate()?;
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
        usize::try_from(window).map_err(|_| EngineError::ResourceLimit("placement window"))?;
    if window == 0 || window as u64 > length {
        return Err(EngineError::InvalidState("invalid placement window"));
    }
    let stripe = options.stripe_bytes.min(64 << 10);
    let size = window
        .checked_add(
            stripe
                .checked_mul(2)
                .ok_or(EngineError::ResourceLimit("placement buffers"))?,
        )
        .and_then(|size| size.checked_add(8192))
        .ok_or(EngineError::ResourceLimit("placement buffers"))?;
    let _buffers = options.memory.reserve(size)?;
    let mut ring = vec![0; window];
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
            return Err(EngineError::ResourceLimit("placement candidates"));
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
            read_exact_at(access, source, range.start, &mut ring)?;
            let mut raw = SlidingCrc::raw(&ring);
            let mut start = range.start;
            let mut cursor = 0;
            let mut at = start + window as u64;
            loop {
                options.cancel.check()?;
                if start == range.start
                    && roll.finish(raw) == crc
                    && start
                        .checked_add(length)
                        .is_some_and(|end| end <= range.end)
                {
                    let mut hash = FingerprintHasher::new();
                    let mut position = start;
                    while position - start < length {
                        options.cancel.check()?;
                        let take = (length - (position - start)).min(stripe as u64) as usize;
                        charge(&mut report, take as u64, limits)?;
                        read_exact_at(access, source, position, &mut confirmation[..take])?;
                        hash.update(&confirmation[..take]);
                        position += take as u64;
                    }
                    if hash.finalize() == expected {
                        ensure_snapshot(access, source, snapshot)?;
                        if report.matches.len() >= limits.max_matches {
                            return Err(EngineError::ResourceLimit("placement matches"));
                        }
                        let reservation = options.memory.reserve(512)?;
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
                if at >= range.end {
                    break;
                }
                let take = (range.end - at).min(stripe as u64) as usize;
                charge(&mut report, take as u64, limits)?;
                read_exact_at(access, source, at, &mut input[..take])?;
                // Stop at the next CRC candidate, retaining the remaining input
                // buffer while confirming it so each search byte is read once.
                for &byte in &input[..take] {
                    raw = roll.advance(raw, byte, ring[cursor]);
                    ring[cursor] = byte;
                    cursor = (cursor + 1) % window;
                    start += 1;
                    at += 1;
                    if roll.finish(raw) != crc
                        || start.checked_add(length).is_none_or(|end| end > range.end)
                    {
                        continue;
                    }
                    let mut hash = FingerprintHasher::new();
                    let mut position = start;
                    while position - start < length {
                        options.cancel.check()?;
                        let count = (length - (position - start)).min(stripe as u64) as usize;
                        charge(&mut report, count as u64, limits)?;
                        read_exact_at(access, source, position, &mut confirmation[..count])?;
                        hash.update(&confirmation[..count]);
                        position += count as u64;
                    }
                    if hash.finalize() == expected {
                        ensure_snapshot(access, source, snapshot)?;
                        if report.matches.len() >= limits.max_matches {
                            return Err(EngineError::ResourceLimit("placement matches"));
                        }
                        report.matches.push(PlacedExtent {
                            layout: layout.identity,
                            file,
                            extent,
                            source,
                            snapshot,
                            offset: start,
                            _reservation: Arc::new(options.memory.reserve(512)?),
                        });
                    }
                }
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
        .ok_or(EngineError::ResourceLimit("placement read work"))?;
    Ok(())
}

// Reflected CRC-64/GO-ISO, expressed as a linear state plus its affine initial
// value. Removing an outgoing byte is a polynomial shift, not a second hash.
fn step(mut state: u64, byte: u8) -> u64 {
    state ^= byte as u64;
    for _ in 0..8 {
        state = (state >> 1) ^ (0xd800_0000_0000_0000 & 0u64.wrapping_sub(state & 1));
    }
    state
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

fn shift(mut state: u64, mut bytes: u64) -> u64 {
    let mut matrix = std::array::from_fn(|bit| step(1u64 << bit, 0));
    while bytes != 0 {
        if bytes & 1 != 0 {
            state = apply(&matrix, state);
        }
        bytes >>= 1;
        if bytes != 0 {
            matrix = std::array::from_fn(|bit| apply(&matrix, matrix[bit]));
        }
    }
    state
}

pub(crate) struct SlidingCrc {
    remove: [u64; 256],
    initial: u64,
}

impl SlidingCrc {
    pub(crate) fn new(window: u64) -> Self {
        let bits: [u64; 8] = std::array::from_fn(|bit| shift(step(0, 1 << bit), window));
        let remove = std::array::from_fn(|byte| {
            (0..8)
                .filter(|bit| byte & (1 << bit) != 0)
                .fold(0, |value, bit| value ^ bits[bit])
        });
        Self {
            remove,
            initial: shift(u64::MAX, window),
        }
    }
    pub(crate) fn finish(&self, raw: u64) -> u64 {
        !(raw ^ self.initial)
    }
    pub(crate) fn raw(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0, |state, byte| step(state, *byte))
    }
    pub(crate) fn advance(&self, raw: u64, incoming: u8, outgoing: u8) -> u64 {
        step(raw, incoming) ^ self.remove[outgoing as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                    raw = step(raw, bytes[at + window]) ^ roll.remove[bytes[at] as usize];
                }
            }
        }
    }
}
