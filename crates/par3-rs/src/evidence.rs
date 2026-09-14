//! Strong, generation-bound verification evidence for decoded bytes.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use crate::layout::{BlockLayout, ExtentKind};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};
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

/// Every extent verdict of one file, two bits each.
///
/// The four states are exactly the ones [`ExtentVerdict`] names, so nothing the
/// evidence exposes is lost; only the byte per extent the verdicts used to
/// occupy is. Verdicts are read and written by extent index, in layout order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtentVerdicts {
    bits: Vec<u8>,
    len: usize,
}

impl ExtentVerdicts {
    /// `len` verdicts, all [`ExtentVerdict::Unknown`].
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            bits: vec![0; len.div_ceil(4)],
            len,
        }
    }

    /// Number of extents these verdicts describe.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the file has no extents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// One extent's verdict, or `None` past the last extent.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<ExtentVerdict> {
        if index >= self.len {
            return None;
        }
        Some(match (self.bits[index / 4] >> ((index % 4) * 2)) & 0b11 {
            0 => ExtentVerdict::Unknown,
            1 => ExtentVerdict::Intact,
            2 => ExtentVerdict::Damaged,
            _ => ExtentVerdict::Unprotected,
        })
    }

    /// Record one extent's verdict.
    pub fn set(&mut self, index: usize, verdict: ExtentVerdict) {
        assert!(index < self.len, "extent verdict out of range");
        let code = match verdict {
            ExtentVerdict::Unknown => 0u8,
            ExtentVerdict::Intact => 1,
            ExtentVerdict::Damaged => 2,
            ExtentVerdict::Unprotected => 3,
        };
        let shift = (index % 4) * 2;
        let slot = &mut self.bits[index / 4];
        *slot = (*slot & !(0b11 << shift)) | (code << shift);
    }

    /// Every verdict in layout order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ExtentVerdict> + '_ {
        (0..self.len).map(|index| self.get(index).expect("bounded verdict"))
    }

    /// Bytes this storage holds, from its real capacity.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        self.bits.capacity()
    }
}

impl<'a> IntoIterator for &'a ExtentVerdicts {
    type Item = ExtentVerdict;
    type IntoIter = Box<dyn ExactSizeIterator<Item = ExtentVerdict> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Bytes one file's sealed evidence holds: its packed verdicts, its own value,
/// and a fixed allowance for the hashing frontier's bookkeeping.
pub(crate) fn evidence_bytes(extents: usize) -> Option<usize> {
    extents
        .div_ceil(4)
        .checked_add(size_of::<FileEvidence>())?
        .checked_add(EVIDENCE_BASE_BYTES)
}

/// Fixed allowance for one file's evidence beyond its verdicts.
const EVIDENCE_BASE_BYTES: usize = 4096;

/// Sealed evidence produced by hashing bytes against an authenticated layout,
/// or replaying such verdicts using a checkpoint digest trusted by the host.
#[derive(Clone, Debug)]
pub struct FileEvidence {
    pub(crate) layout: Fingerprint,
    pub(crate) file: usize,
    pub(crate) source: SourceId,
    pub(crate) snapshot: SourceSnapshot,
    pub(crate) verdicts: Arc<ExtentVerdicts>,
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
            self._reservation = Arc::new(
                options
                    .memory
                    .reserve_as(self._reservation.category(), self.retained_bytes())?,
            );
        }
        Ok(())
    }

    /// Extent verdicts in layout order.
    #[must_use]
    pub fn verdicts(&self) -> &ExtentVerdicts {
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
        let extents = &layout.files[self.file].extents;
        let mut end = 0;
        for (index, verdict) in self.verdicts.iter().enumerate() {
            if verdict != ExtentVerdict::Intact {
                break;
            }
            end = extents.range(index).expect("checked extent").end;
        }
        Ok(end)
    }

    /// File-coordinate ranges that need verification or reconstruction.
    pub fn unresolved_ranges(&self, layout: &BlockLayout) -> EngineResult<Vec<Range<u64>>> {
        self.check_layout(layout)?;
        let extents = &layout.files[self.file].extents;
        let mut ranges: Vec<Range<u64>> = Vec::new();
        for (index, verdict) in self.verdicts.iter().enumerate() {
            if !matches!(verdict, ExtentVerdict::Unknown | ExtentVerdict::Damaged) {
                continue;
            }
            let range = extents.range(index).expect("checked extent");
            if let Some(previous) = ranges.last_mut()
                && previous.end == range.start
            {
                previous.end = range.end;
            } else {
                ranges.push(range);
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
    verdicts: ExtentVerdicts,
    partial: BTreeMap<usize, Box<PartialExtent>>,
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
        let cost = evidence_bytes(description.extents.len())
            .ok_or(EngineError::resource_limit("verification evidence"))?;
        if cost > options.retained_bytes {
            return Err(EngineError::budget_limit(
                "retained verification evidence",
                cost,
                options.retained_bytes,
                options.retained_bytes,
            ));
        }
        let reservation = options
            .memory
            .reserve_as(MemoryCategory::LayoutEvidence, cost)?;
        let mut verdicts = ExtentVerdicts::new(description.extents.len());
        for index in 0..verdicts.len() {
            if description.extents.is_unprotected(index) {
                verdicts.set(index, ExtentVerdict::Unprotected);
            }
        }
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
        let mut index = file.extents.first_after(offset);
        while index < self.layout.files[self.file].extents.len() {
            self.options.cancel.check()?;
            let extents = &self.layout.files[self.file].extents;
            let range = extents.range(index).expect("bounded extent");
            if range.start >= end {
                break;
            }
            let unprotected = extents.is_unprotected(index);
            let start = range.start.max(offset);
            let stop = range.end.min(end);
            let data = &bytes[(start - offset) as usize..(stop - offset) as usize];
            if self.whole_ordered && !unprotected {
                self.whole.update(data);
            }
            if self.verdicts.get(index) == Some(ExtentVerdict::Unknown) {
                let relative = start - range.start;
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
            let reservation = self
                .options
                .memory
                .reserve_as(MemoryCategory::QueuedPayloads, 4096)?;
            self.partial.insert(
                index,
                Box::new(PartialExtent {
                    next: 0,
                    hasher: FingerprintHasher::new(),
                    pending: BTreeMap::new(),
                    _reservation: reservation,
                }),
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
                return Err(EngineError::resource_limit("overlapping pending fragments"));
            }
            let reservation = self.options.memory.reserve_as(
                MemoryCategory::QueuedPayloads,
                bytes
                    .len()
                    .checked_add(128)
                    .ok_or(EngineError::resource_limit("pending fragment"))?,
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
        let extents = &self.layout.files[self.file].extents;
        let range = extents.range(index).expect("bounded extent");
        if partial.next == range.end - range.start {
            let expected = match extents.get(index).expect("bounded extent").kind {
                ExtentKind::Block { fingerprint, .. } => fingerprint,
                ExtentKind::Inline(bytes) => Some(crate::fingerprint(&bytes)),
                ExtentKind::Unprotected => None,
            };
            if let Some(expected) = expected {
                let verdict = if partial.hasher.finalize() == expected {
                    ExtentVerdict::Intact
                } else {
                    ExtentVerdict::Damaged
                };
                self.verdicts.set(index, verdict);
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
        verifier.verdicts = previous.verdicts.as_ref().clone();
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
            for index in 0..self.verdicts.len() {
                if self.verdicts.get(index) == Some(ExtentVerdict::Unknown) {
                    self.verdicts.set(index, ExtentVerdict::Intact);
                }
            }
        }
        FileEvidence {
            layout: self.layout.identity,
            file: self.file,
            source: self.source,
            snapshot: self.snapshot,
            verdicts: Arc::new(self.verdicts),
            whole_matches,
            expected_len: file.len,
            _reservation: Arc::new(self.reservation),
        }
    }
}

fn unprotected_between(file: &crate::layout::FileLayout, start: u64, end: u64) -> bool {
    start <= end && end <= file.len && file.extents.all_unprotected(start, end)
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
    let _buffer = options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size)?;
    let mut bytes = vec![0; size];
    for (index, verdict) in previous.verdicts.iter().enumerate() {
        if verdict != ExtentVerdict::Unknown {
            continue;
        }
        let extent = layout.files[previous.file]
            .extents
            .range(index)
            .expect("bounded extent");
        let mut at = extent.start;
        while at < extent.end {
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
            let end = range.end.min(extent.end);
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
    let _reservation = options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size)?;
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
