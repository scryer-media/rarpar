//! Strong, generation-bound verification evidence for decoded bytes.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::source::{SourceAccess, SourceId, SourceSnapshot, ensure_snapshot};
use crate::{Fingerprint, FingerprintHasher};

#[path = "evidence_checkpoint.rs"]
mod checkpoint;
pub use checkpoint::EvidenceCheckpoint;

/// Verification state of a file-coordinate extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentVerdict {
    /// No complete strong hash is available yet.
    Unknown,
    /// Authenticated metadata agrees with the bytes.
    Intact,
    /// A complete extent disagreed with its fingerprint or inline bytes.
    Damaged,
    /// The format deliberately excludes these bytes from protection.
    Unprotected,
}

/// Sealed evidence produced by hashing bytes against an authenticated layout,
/// or replaying such verdicts using a checkpoint digest trusted by the host.
#[derive(Clone, Debug)]
pub struct FileEvidence {
    pub(crate) layout: Fingerprint,
    pub(crate) file: usize,
    pub(crate) source: SourceId,
    pub(crate) snapshot: SourceSnapshot,
    pub(crate) verdicts: Arc<[ExtentVerdict]>,
    pub(crate) whole_matches: Option<bool>,
    pub(crate) expected_len: u64,
    _reservation: Arc<Reservation>,
}

impl FileEvidence {
    /// Source whose published bytes were checked.
    #[must_use]
    pub fn source(&self) -> SourceId {
        self.source
    }

    /// Source generation and logical length at verification.
    #[must_use]
    pub fn snapshot(&self) -> SourceSnapshot {
        self.snapshot
    }

    /// Retained allocation charged for this evidence.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self._reservation.bytes()
    }

    pub(crate) fn rehome(&mut self, options: &ExecutionOptions) -> EngineResult<()> {
        if !self._reservation.belongs_to(&options.memory) {
            self._reservation = Arc::new(options.memory.reserve(self.retained_bytes())?);
        }
        Ok(())
    }

    /// Extent verdicts in layout order.
    #[must_use]
    pub fn verdicts(&self) -> &[ExtentVerdict] {
        &self.verdicts
    }

    /// Whole protected-data fingerprint result, or `None` when ordered bytes
    /// were incomplete or the File packet does not supply this fingerprint.
    /// Unprotected ranges are omitted, including unavailable carrier gaps.
    pub fn whole_matches(&self) -> Option<bool> {
        self.whole_matches
    }

    /// Whether all protected extents are proven, with the expected file length.
    /// Unprotected ranges are not certified by this answer.
    #[must_use]
    pub fn protected_complete(&self) -> bool {
        self.snapshot.len == self.expected_len
            && self.whole_matches != Some(false)
            && self
                .verdicts
                .iter()
                .all(|state| matches!(state, ExtentVerdict::Intact | ExtentVerdict::Unprotected))
    }

    /// Largest verified prefix, stopping at unknown, damaged or unprotected data.
    pub fn verified_prefix(&self, layout: &BlockLayout) -> EngineResult<u64> {
        self.check_layout(layout)?;
        let mut end = 0;
        for (extent, verdict) in layout.files[self.file]
            .extents
            .iter()
            .zip(self.verdicts.iter())
        {
            if *verdict != ExtentVerdict::Intact {
                break;
            }
            end = extent.range.end;
        }
        Ok(end)
    }

    /// File-coordinate ranges that need verification or reconstruction.
    pub fn unresolved_ranges(&self, layout: &BlockLayout) -> EngineResult<Vec<Range<u64>>> {
        self.check_layout(layout)?;
        let mut ranges: Vec<Range<u64>> = Vec::new();
        for (extent, verdict) in layout.files[self.file]
            .extents
            .iter()
            .zip(self.verdicts.iter())
        {
            if !matches!(verdict, ExtentVerdict::Unknown | ExtentVerdict::Damaged) {
                continue;
            }
            if let Some(previous) = ranges.last_mut()
                && previous.end == extent.range.start
            {
                previous.end = extent.range.end;
            } else {
                ranges.push(extent.range.clone());
            }
        }
        Ok(ranges)
    }

    pub(crate) fn check_layout(&self, layout: &BlockLayout) -> EngineResult<()> {
        if self.layout != layout.identity
            || self.file >= layout.files.len()
            || self.verdicts.len() != layout.files[self.file].extents.len()
        {
            return Err(EngineError::InvalidState(
                "evidence belongs to another layout",
            ));
        }
        Ok(())
    }
}

struct Fragment {
    bytes: Vec<u8>,
    _reservation: Reservation,
}

struct PartialExtent {
    next: u64,
    hasher: FingerprintHasher,
    pending: BTreeMap<u64, Fragment>,
    _reservation: Reservation,
}

/// Bounded out-of-order verifier for one logical file.
///
/// It hashes each extent independently and separately maintains a whole-file
/// hash when arrivals are ordered. Out-of-order bytes may be retained under the
/// shared budget. If they do not fit, only that extent's incomplete work is
/// discarded; its verdict stays `Unknown` for a later source read.
pub struct StreamingVerifier {
    layout: Arc<BlockLayout>,
    file: usize,
    source: SourceId,
    snapshot: SourceSnapshot,
    options: ExecutionOptions,
    verdicts: Vec<ExtentVerdict>,
    partial: BTreeMap<usize, PartialExtent>,
    whole: FingerprintHasher,
    whole_next: u64,
    whole_ordered: bool,
    dropped: u64,
    reservation: Reservation,
}

impl StreamingVerifier {
    /// Start hashing one file against a source generation.
    pub fn new(
        layout: Arc<BlockLayout>,
        file: usize,
        source: SourceId,
        snapshot: SourceSnapshot,
        options: ExecutionOptions,
    ) -> EngineResult<Self> {
        options.validate()?;
        let description = layout
            .files
            .get(file)
            .ok_or(EngineError::InvalidState("unknown file index"))?;
        let cost = description
            .extents
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(4096))
            .ok_or(EngineError::ResourceLimit("verification evidence"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::ResourceLimit("retained verification evidence"));
        }
        let reservation = options.memory.reserve(cost)?;
        let verdicts = description
            .extents
            .iter()
            .map(|extent| {
                if matches!(extent.kind, ExtentKind::Unprotected) {
                    ExtentVerdict::Unprotected
                } else {
                    ExtentVerdict::Unknown
                }
            })
            .collect();
        Ok(Self {
            layout,
            file,
            source,
            snapshot,
            options,
            verdicts,
            partial: BTreeMap::new(),
            whole: FingerprintHasher::new(),
            whole_next: 0,
            whole_ordered: true,
            dropped: 0,
            reservation,
        })
    }

    /// Supply bytes at their decoded file offset. The source generation must
    /// satisfy `SourceSnapshot`'s immutable-publication contract.
    pub fn feed(&mut self, offset: u64, bytes: &[u8]) -> EngineResult<()> {
        let mut progress = self.options.stage(crate::runtime::Stage::Verify)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(EngineError::InvalidState("verification offset overflow"))?;
        if end > self.snapshot.len {
            return Err(EngineError::InvalidState("bytes exceed source length"));
        }
        let file = &self.layout.files[self.file];
        if !bytes.is_empty() && !unprotected_between(file, self.whole_next, offset) {
            self.whole_ordered = false;
        }
        let mut index = file
            .extents
            .partition_point(|extent| extent.range.end <= offset);
        while index < self.layout.files[self.file].extents.len() {
            self.options.cancel.check()?;
            let extent = &self.layout.files[self.file].extents[index];
            if extent.range.start >= end {
                break;
            }
            let start = extent.range.start.max(offset);
            let stop = extent.range.end.min(end);
            let data = &bytes[(start - offset) as usize..(stop - offset) as usize];
            if self.whole_ordered && !matches!(extent.kind, ExtentKind::Unprotected) {
                self.whole.update(data);
            }
            if self.verdicts[index] == ExtentVerdict::Unknown {
                let relative = start - extent.range.start;
                match self.feed_extent(index, relative, data) {
                    Err(EngineError::ResourceLimit(_)) => {
                        self.partial.remove(&index);
                        self.dropped += 1;
                    }
                    result => result?,
                }
            }
            index += 1;
        }
        if self.whole_ordered {
            self.whole_next = end;
        }
        progress.advance(bytes.len() as u64);
        self.options.cancel.check()
    }

    fn feed_extent(&mut self, index: usize, offset: u64, bytes: &[u8]) -> EngineResult<()> {
        if !self.partial.contains_key(&index) {
            let reservation = self.options.memory.reserve(4096)?;
            self.partial.insert(
                index,
                PartialExtent {
                    next: 0,
                    hasher: FingerprintHasher::new(),
                    pending: BTreeMap::new(),
                    _reservation: reservation,
                },
            );
        }
        let partial = self
            .partial
            .get_mut(&index)
            .expect("inserted partial extent");
        if offset > partial.next {
            // Overlap of separately received fragments is harmless to source
            // identity, but discarding this frontier avoids unbounded interval
            // splitting. The caller can reread that extent later.
            if partial.pending.iter().any(|(at, fragment)| {
                offset < *at + fragment.bytes.len() as u64 && *at < offset + bytes.len() as u64
            }) {
                return Err(EngineError::ResourceLimit("overlapping pending fragments"));
            }
            let reservation = self.options.memory.reserve(
                bytes
                    .len()
                    .checked_add(128)
                    .ok_or(EngineError::ResourceLimit("pending fragment"))?,
            )?;
            partial.pending.insert(
                offset,
                Fragment {
                    bytes: bytes.to_vec(),
                    _reservation: reservation,
                },
            );
            return Ok(());
        }
        let skip = (partial.next - offset).min(bytes.len() as u64) as usize;
        partial.hasher.update(&bytes[skip..]);
        partial.next += (bytes.len() - skip) as u64;
        while let Some((&at, _)) = partial.pending.first_key_value() {
            if at > partial.next {
                break;
            }
            let fragment = partial.pending.pop_first().expect("pending fragment").1;
            let skip = (partial.next - at).min(fragment.bytes.len() as u64) as usize;
            partial.hasher.update(&fragment.bytes[skip..]);
            partial.next += (fragment.bytes.len() - skip) as u64;
        }
        let extent = &self.layout.files[self.file].extents[index];
        if partial.next == extent.range.end - extent.range.start {
            let expected = match &extent.kind {
                ExtentKind::Block { fingerprint, .. } => *fingerprint,
                ExtentKind::Inline(bytes) => Some(crate::fingerprint(bytes)),
                ExtentKind::Unprotected => None,
            };
            if let Some(expected) = expected {
                self.verdicts[index] = if partial.hasher.finalize() == expected {
                    ExtentVerdict::Intact
                } else {
                    ExtentVerdict::Damaged
                };
            }
            self.partial.remove(&index);
        }
        Ok(())
    }

    /// Incomplete hash frontiers discarded to honor the budget.
    #[must_use]
    pub fn dropped_frontiers(&self) -> u64 {
        self.dropped
    }

    /// Resume from strong evidence for the same source generation. Previously
    /// verified extents are never hashed again. This cannot resume a discarded
    /// whole-file hash; missing per-extent checksums can require a full read.
    pub fn resume(
        layout: Arc<BlockLayout>,
        previous: &FileEvidence,
        options: ExecutionOptions,
    ) -> EngineResult<Self> {
        previous.check_layout(&layout)?;
        let mut verifier = Self::new(
            layout,
            previous.file,
            previous.source,
            previous.snapshot,
            options,
        )?;
        verifier.verdicts.copy_from_slice(&previous.verdicts);
        verifier.whole_ordered = false;
        Ok(verifier)
    }

    /// Return sealed evidence; incomplete extents remain explicitly unknown.
    pub fn finish(mut self) -> FileEvidence {
        let file = &self.layout.files[self.file];
        let whole_matches = (self.whole_ordered
            && unprotected_between(file, self.whole_next, file.len)
            && file.fingerprint != [0; 16])
            .then(|| self.whole.finalize() == file.fingerprint);
        if whole_matches == Some(true) {
            for state in &mut self.verdicts {
                if *state == ExtentVerdict::Unknown {
                    *state = ExtentVerdict::Intact;
                }
            }
        }
        FileEvidence {
            layout: self.layout.identity,
            file: self.file,
            source: self.source,
            snapshot: self.snapshot,
            verdicts: self.verdicts.into(),
            whole_matches,
            expected_len: file.len,
            _reservation: Arc::new(self.reservation),
        }
    }
}

fn unprotected_between(file: &crate::layout::FileLayout, start: u64, end: u64) -> bool {
    start <= end
        && end <= file.len
        && file
            .extents
            .iter()
            .skip(
                file.extents
                    .partition_point(|extent| extent.range.end <= start),
            )
            .take_while(|extent| extent.range.start < end)
            .all(|extent| matches!(extent.kind, ExtentKind::Unprotected))
}

/// Recheck only unknown extents after new bytes arrive within an immutable source
/// generation. Already admitted strong evidence incurs no verification rereads.
pub fn verify_arrivals(
    layout: Arc<BlockLayout>,
    previous: &FileEvidence,
    access: &dyn SourceAccess,
    options: &ExecutionOptions,
) -> EngineResult<FileEvidence> {
    ensure_snapshot(access, previous.source, previous.snapshot)?;
    let mut verifier = StreamingVerifier::resume(Arc::clone(&layout), previous, options.clone())?;
    let size = options.stripe_bytes.min(64 << 10);
    let _buffer = options.memory.reserve(size)?;
    let mut bytes = vec![0; size];
    for (extent, verdict) in layout.files[previous.file]
        .extents
        .iter()
        .zip(previous.verdicts.iter())
    {
        if *verdict != ExtentVerdict::Unknown {
            continue;
        }
        let mut at = extent.range.start;
        while at < extent.range.end {
            options.cancel.check()?;
            let Some(range) = access.next_available(previous.source, at)? else {
                break;
            };
            if range.start < at || range.end <= range.start || range.end > previous.snapshot.len {
                return Err(EngineError::InvalidState(
                    "invalid source availability range",
                ));
            }
            at = range.start;
            let end = range.end.min(extent.range.end);
            while at < end {
                options.cancel.check()?;
                let take = (end - at).min(size as u64) as usize;
                let read =
                    options
                        .diagnostics
                        .read_at(access, previous.source, at, &mut bytes[..take])?;
                if read > take {
                    return Err(EngineError::InvalidState("invalid source read length"));
                }
                if read == 0 {
                    break;
                }
                verifier.feed(at, &bytes[..read])?;
                at += read as u64;
            }
            at = range.end;
        }
    }
    ensure_snapshot(access, previous.source, previous.snapshot)?;
    let mut result = verifier.finish();
    result.whole_matches = previous.whole_matches;
    Ok(result)
}

/// Verify through a source provider, using a forward reader when it is offered.
/// Real I/O errors propagate; holes leave extents unknown.
pub fn verify_source(
    layout: Arc<BlockLayout>,
    file: usize,
    access: &dyn SourceAccess,
    source: SourceId,
    options: &ExecutionOptions,
) -> EngineResult<FileEvidence> {
    options.validate()?;
    let snapshot = access.snapshot(source)?.ok_or(EngineError::Unavailable {
        source_id: source,
        offset: 0,
    })?;
    let mut verifier = StreamingVerifier::new(layout, file, source, snapshot, options.clone())?;
    let size = options.stripe_bytes.min(64 << 10);
    let _reservation = options.memory.reserve(size)?;
    let mut buffer = vec![0; size];
    let mut offset = 0;
    if let Some(mut reader) = access.open_sequential(source)? {
        while offset < snapshot.len {
            options.cancel.check()?;
            let take = (snapshot.len - offset).min(buffer.len() as u64) as usize;
            let read = options
                .diagnostics
                .read(reader.as_mut(), &mut buffer[..take])?;
            if read == 0 {
                break;
            }
            verifier.feed(offset, &buffer[..read])?;
            offset += read as u64;
        }
    }
    if offset < snapshot.len {
        while let Some(range) = access.next_available(source, offset)? {
            if range.start < offset || range.end <= range.start || range.end > snapshot.len {
                return Err(EngineError::InvalidState(
                    "invalid source availability range",
                ));
            }
            offset = range.start;
            while offset < range.end {
                options.cancel.check()?;
                let take = (range.end - offset).min(buffer.len() as u64) as usize;
                let read =
                    options
                        .diagnostics
                        .read_at(access, source, offset, &mut buffer[..take])?;
                if read == 0 {
                    break;
                }
                if read > take {
                    return Err(EngineError::InvalidState("invalid source read length"));
                }
                verifier.feed(offset, &buffer[..read])?;
                offset += read as u64;
            }
            offset = range.end;
        }
    }
    ensure_snapshot(access, source, snapshot)?;
    Ok(verifier.finish())
}
