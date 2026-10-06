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

    /// Every protected extent matches its own fingerprint at the right length,
    /// yet the whole-file fingerprint does not: metadata that contradicts itself.
    pub(crate) fn contradicts_itself(&self) -> bool {
        self.whole_matches == Some(false)
            && self.snapshot.len == self.expected_len
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
    /// Whether whole-file hashing may fork onto the caller's admitted pool.
    /// Only a caller that is already inside one may set it.
    parallel_hash: bool,
    whole_next: u64,
    whole_ordered: bool,
    /// The end of the bytes [`Self::feed_whole`] has already reported as
    /// Verify progress, so that rereading them does not report them again.
    reported: u64,
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
            parallel_hash: false,
            whole_next: 0,
            whole_ordered: true,
            reported: 0,
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
        // Adjacent protected extents are hashed as one update. A PAR3 block is
        // often far smaller than a read, and splitting the read at every block
        // boundary would keep every update under the parallel gate.
        let mut run: Option<Range<u64>> = None;
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
            if self.whole_ordered {
                match (&mut run, unprotected) {
                    (Some(open), false) if open.end == start => open.end = stop,
                    (open, false) => {
                        if let Some(closed) = open.take() {
                            self.hash_run(&closed, offset, bytes);
                        }
                        *open = Some(start..stop);
                    }
                    (open, true) => {
                        if let Some(closed) = open.take() {
                            self.hash_run(&closed, offset, bytes);
                        }
                    }
                }
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
        if let Some(closed) = run {
            self.hash_run(&closed, offset, bytes);
        }
        if self.whole_ordered {
            self.whole_next = end;
        }
        progress.advance(end.saturating_sub(offset.max(self.reported)));
        self.options.cancel.check()
    }

    /// Feed one coalesced protected run of the current read into the
    /// whole-file hash.
    fn hash_run(&mut self, run: &Range<u64>, offset: u64, bytes: &[u8]) {
        let data = &bytes[(run.start - offset) as usize..(run.end - offset) as usize];
        self.whole.update_admitted(data, self.parallel_hash);
    }

    /// [`Self::feed`] for the whole-file hash alone: no extent is hashed and
    /// no verdict changes. Returns whether the hash can still decide the file;
    /// once protected bytes arrive out of order it cannot, the bytes are not
    /// taken, and the caller should feed them and the rest to [`Self::feed`].
    fn feed_whole(&mut self, offset: u64, bytes: &[u8]) -> EngineResult<bool> {
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
        if !self.whole_ordered {
            return Ok(false);
        }
        let mut index = file.extents.first_after(offset);
        let mut run: Option<Range<u64>> = None;
        while index < self.layout.files[self.file].extents.len() {
            let extents = &self.layout.files[self.file].extents;
            let range = extents.range(index).expect("bounded extent");
            if range.start >= end {
                break;
            }
            let start = range.start.max(offset);
            let stop = range.end.min(end);
            if extents.is_unprotected(index) {
                if let Some(closed) = run.take() {
                    self.hash_run(&closed, offset, bytes);
                }
            } else {
                match &mut run {
                    Some(open) if open.end == start => open.end = stop,
                    open => {
                        if let Some(closed) = open.take() {
                            self.hash_run(&closed, offset, bytes);
                        }
                        *open = Some(start..stop);
                    }
                }
            }
            index += 1;
        }
        if let Some(closed) = run {
            self.hash_run(&closed, offset, bytes);
        }
        self.whole_next = end;
        self.reported = end;
        progress.advance(bytes.len() as u64);
        self.options.cancel.check()?;
        Ok(true)
    }

    /// The whole-file verdict [`Self::finish`] would seal from the bytes fed
    /// so far.
    fn whole_result(&self) -> Option<bool> {
        let file = &self.layout.files[self.file];
        (self.whole_ordered
            && unprotected_between(file, self.whole_next, file.len)
            && file.fingerprint != [0; 16])
            .then(|| self.whole.finalize() == file.fingerprint)
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
        partial
            .hasher
            .update_admitted(&bytes[skip..], self.parallel_hash);
        partial.next += (bytes.len() - skip) as u64;
        while let Some((&at, _)) = partial.pending.first_key_value() {
            if at > partial.next {
                break;
            }
            let fragment = partial.pending.pop_first().expect("pending fragment").1;
            let skip = (partial.next - at).min(fragment.bytes.len() as u64) as usize;
            partial
                .hasher
                .update_admitted(&fragment.bytes[skip..], self.parallel_hash);
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
        let whole_matches = self.whole_result();
        let file = &self.layout.files[self.file];
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

/// The verification read buffer: the sequential read size for the source,
/// whatever the block size and whether or not the hash runs in parallel, as
/// long as the shared budget still leaves working room afterwards.
///
/// A refused growth is not a refused verification: the small buffer is the
/// documented fallback, and it never reacquires workers.
fn verification_buffer(options: &ExecutionOptions, len: u64) -> EngineResult<Reservation> {
    let small = options.stripe_bytes.min(64 << 10);
    let large = crate::source::sequential_read_bytes(options, len);
    if large > small {
        match options
            .memory
            .reserve_as(MemoryCategory::SourceScratch, large)
        {
            Ok(reservation) if options.memory.available() >= 128 << 10 => return Ok(reservation),
            Ok(_) | Err(EngineError::ResourceLimit(_)) => {}
            Err(error) => return Err(error),
        }
    }
    options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, small)
}

/// Verify through a source provider, using a forward reader when it is offered.
/// Real I/O errors propagate; holes leave extents unknown.
///
/// The whole-file hash is computed first, and a file it proves intact is read
/// once, with every protected extent intact. A file it does not prove is read a second
/// time to hash its extents. A source with protected bytes missing cannot be
/// proved by the whole-file hash: when its first available range already
/// shows the gap, its extents are hashed in a single pass; when the gap shows
/// only later, hashing switches to extents there and only the prefix before
/// the gap is read again.
///
/// A source of at least [`crate::hash::PARALLEL_SOURCE_BYTES`] may start a
/// private worker pool solely to hash it; a smaller one never does, because the
/// pool's own startup would cost more than the hash. A caller that already
/// holds an admitted pool must call [`verify_source_in_pool`] instead, so that
/// pools are never nested.
pub fn verify_source(
    layout: Arc<BlockLayout>,
    file: usize,
    access: &dyn SourceAccess,
    source: SourceId,
    options: &ExecutionOptions,
) -> EngineResult<FileEvidence> {
    options.validate()?;
    let large = layout
        .files
        .get(file)
        .is_some_and(|file| file.len >= crate::hash::PARALLEL_SOURCE_BYTES);
    let pool = if large {
        match crate::runtime::WorkerPool::for_work(
            options,
            crate::hash::PARALLEL_HASH_WORKERS,
            crate::hash::PARALLEL_HASH_BYTES + (128 << 10),
        ) {
            Ok(pool) => pool,
            Err(EngineError::ResourceLimit(_)) => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    match &pool {
        Some(pool) => pool
            .pool()
            .install(|| verify_source_in_pool(layout, file, access, source, options, true)),
        None => verify_source_in_pool(layout, file, access, source, options, false),
    }
}

/// [`verify_source`] for a caller that is already inside an admitted worker
/// pool. `parallel` must be true only from inside such a pool.
pub(crate) fn verify_source_in_pool(
    layout: Arc<BlockLayout>,
    file: usize,
    access: &dyn SourceAccess,
    source: SourceId,
    options: &ExecutionOptions,
    parallel: bool,
) -> EngineResult<FileEvidence> {
    options.validate()?;
    let snapshot = access.snapshot(source)?.ok_or(EngineError::Unavailable {
        source_id: source,
        offset: 0,
    })?;
    let mut verifier = StreamingVerifier::new(layout, file, source, snapshot, options.clone())?;
    let reservation = verification_buffer(options, snapshot.len)?;
    let size = reservation.bytes();
    verifier.parallel_hash = parallel && size >= crate::hash::PARALLEL_HASH_BYTES;
    let _reservation = reservation;
    let mut buffer = vec![0; size];
    let description = &verifier.layout.files[verifier.file];
    // The first pass begins from here, so that what it asks the provider is
    // asked once.
    let mut start = match access.open_sequential(source)? {
        Some(reader) => Start::Reader(reader),
        None if snapshot.len == 0 => Start::Range(None),
        None => Start::Range(access.next_available(source, 0)?),
    };
    let mut end = snapshot.len;
    let mut whole = None;
    if description.fingerprint == [0; 16] {
        // Nothing can promote extents without a whole-file hash, so skip
        // computing one; `finish` would seal `None` either way.
        verifier.whole_ordered = false;
    } else if options.disk_verify_whole_first != Some(false)
        && unprotected_between(description, snapshot.len, description.len)
        && match &start {
            // A first available range that leaves protected bytes out means
            // the whole-file hash can never settle the file. The extent pass
            // below hashes it beside the extents, as it always did.
            Start::Range(Some(range)) => {
                unprotected_between(description, 0, range.start)
                    && unprotected_between(description, range.end, description.len)
            }
            Start::Range(None) => false,
            Start::Reader(_) | Start::Probe => true,
        }
    {
        // The whole-file hash alone settles an intact file, and hashing every
        // extent beside it would double the work of the common case. Only a
        // file it does not settle pays a second read, for its extents.
        let mut gap = None;
        read_source(
            access,
            source,
            snapshot,
            end,
            options,
            &mut buffer,
            std::mem::replace(&mut start, Start::Probe),
            &mut |offset, bytes| {
                if gap.is_none() {
                    if verifier.feed_whole(offset, bytes)? {
                        return Ok(());
                    }
                    // Protected bytes before `offset` are missing, so the
                    // whole-file hash cannot decide. Hash extents from here
                    // on; only the prefix needs reading again.
                    gap = Some(offset);
                }
                verifier.feed(offset, bytes)
            },
        )?;
        match gap {
            Some(gap) => end = gap,
            None => {
                whole = verifier.whole_result();
                if whole == Some(true) {
                    ensure_snapshot(access, source, snapshot)?;
                    return Ok(verifier.finish());
                }
                // The verdict is known; the extent pass need not hash the
                // file again.
                verifier.whole_ordered = false;
            }
        }
    }
    read_source(
        access,
        source,
        snapshot,
        end,
        options,
        &mut buffer,
        start,
        &mut |offset, bytes| verifier.feed(offset, bytes),
    )?;
    ensure_snapshot(access, source, snapshot)?;
    let mut evidence = verifier.finish();
    if whole.is_some() {
        evidence.whole_matches = whole;
    }
    Ok(evidence)
}

/// Where [`read_source`] begins: what a first pass already asked the provider
/// for, or nothing, so that it asks itself.
enum Start {
    Probe,
    Reader(Box<dyn std::io::Read + Send>),
    /// The answer to `next_available(source, 0)`.
    Range(Option<Range<u64>>),
}

/// Read a source generation in order up to `end`, through its forward reader
/// when it offers one and through `next_available` past that prefix, handing
/// each filled buffer to `feed`.
#[allow(clippy::too_many_arguments)]
fn read_source(
    access: &dyn SourceAccess,
    source: SourceId,
    snapshot: SourceSnapshot,
    end: u64,
    options: &ExecutionOptions,
    buffer: &mut [u8],
    start: Start,
    feed: &mut dyn FnMut(u64, &[u8]) -> EngineResult<()>,
) -> EngineResult<()> {
    let mut offset = 0;
    let (reader, mut first) = match start {
        Start::Probe => (access.open_sequential(source)?, None),
        Start::Reader(reader) => (Some(reader), None),
        Start::Range(range) => (None, Some(range)),
    };
    if let Some(mut reader) = reader {
        while offset < end {
            options.cancel.check()?;
            let take = (end - offset).min(buffer.len() as u64) as usize;
            // Fill the buffer before hashing it. A provider is free to return
            // short reads, and a megabyte buffer fed 17 bytes at a time would
            // never reach the parallel gate.
            let mut read = 0;
            while read < take {
                options.cancel.check()?;
                let count = options
                    .diagnostics
                    .read(reader.as_mut(), &mut buffer[read..take])?;
                if count == 0 {
                    break;
                }
                if count > take - read {
                    return Err(EngineError::InvalidState("invalid source read length"));
                }
                read += count;
            }
            if read == 0 {
                break;
            }
            feed(offset, &buffer[..read])?;
            offset += read as u64;
        }
    }
    while offset < end {
        let range = match first.take() {
            Some(range) => range,
            None => access.next_available(source, offset)?,
        };
        let Some(range) = range else {
            break;
        };
        if range.start < offset || range.end <= range.start || range.end > snapshot.len {
            return Err(EngineError::InvalidState(
                "invalid source availability range",
            ));
        }
        offset = range.start;
        let stop = range.end.min(end);
        while offset < stop {
            options.cancel.check()?;
            let take = (stop - offset).min(buffer.len() as u64) as usize;
            let mut read = 0;
            while read < take {
                options.cancel.check()?;
                let count = options.diagnostics.read_at(
                    access,
                    source,
                    offset + read as u64,
                    &mut buffer[read..take],
                )?;
                if count == 0 {
                    break;
                }
                if count > take - read {
                    return Err(EngineError::InvalidState("invalid source read length"));
                }
                read += count;
            }
            if read == 0 {
                break;
            }
            feed(offset, &buffer[..read])?;
            offset += read as u64;
        }
        offset = range.end;
    }
    Ok(())
}

#[cfg(test)]
mod parallel_tests {
    use super::*;
    use crate::hash::PARALLEL_HASH_BYTES;
    use crate::runtime::MemoryBudget;

    #[test]
    fn a_refused_large_buffer_falls_back_without_leaking_its_reservation() {
        for limit in [64 << 10, 1 << 20, (1 << 20) + (128 << 10), 8 << 20] {
            let options = ExecutionOptions {
                memory: MemoryBudget::new(limit),
                stripe_bytes: 1 << 20,
                ..ExecutionOptions::default()
            };
            for len in [
                0,
                64 << 10,
                (64 << 10) + 1,
                (PARALLEL_HASH_BYTES - 1) as u64,
                PARALLEL_HASH_BYTES as u64,
                8 * PARALLEL_HASH_BYTES as u64,
            ] {
                let buffer = verification_buffer(&options, len).unwrap();
                // A source's read size never depends on its block size or on
                // whether its hash runs in parallel: only on its length and
                // on room left in the budget.
                let wanted = len.min(PARALLEL_HASH_BYTES as u64) as usize;
                let expected = if wanted > 64 << 10 && limit >= wanted + (128 << 10) {
                    wanted
                } else {
                    64 << 10
                };
                assert_eq!(buffer.bytes(), expected, "limit {limit} len {len}");
                assert_eq!(buffer.category(), MemoryCategory::SourceScratch);
                drop(buffer);
                assert_eq!(options.memory.used(), 0);
            }
        }
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;
    use crate::runtime::Stage;
    use crate::source::MemorySourceAccess;
    use crate::test_reference::{TempTree, cauchy_block_set, gf8_contents, gf8_set};

    /// A provider with no forward reader, so both passes take positioned reads.
    struct Positioned(MemorySourceAccess);

    impl SourceAccess for Positioned {
        fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
            self.0.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.read_at(source, offset, out)
        }
        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<Range<u64>>> {
            self.0.next_available(source, offset)
        }
    }

    /// What one streaming pass over `bytes` seals: the extent and whole-file
    /// hashes side by side, which is what disk verification used to compute.
    fn single_pass(layout: &Arc<BlockLayout>, file: usize, bytes: &[u8]) -> FileEvidence {
        let snapshot = SourceSnapshot {
            len: bytes.len() as u64,
            generation: 1,
        };
        let options = ExecutionOptions::default();
        let mut verifier =
            StreamingVerifier::new(Arc::clone(layout), file, SourceId(1), snapshot, options)
                .unwrap();
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            verifier.feed(index as u64 * 4096, chunk).unwrap();
        }
        verifier.finish()
    }

    /// Verify `bytes` from disk-style access, returning the evidence and the
    /// source bytes it read and hashed.
    fn verified(
        layout: &Arc<BlockLayout>,
        file: usize,
        bytes: &[u8],
        positioned: bool,
    ) -> (FileEvidence, u64, u64) {
        let options = ExecutionOptions {
            stripe_bytes: 1000,
            ..ExecutionOptions::default()
        };
        let mut memory = MemorySourceAccess::default();
        memory.insert(SourceId(1), 1, bytes.to_vec().into());
        let positioned_access = Positioned(memory);
        let access: &dyn SourceAccess = if positioned {
            &positioned_access
        } else {
            &positioned_access.0
        };
        let evidence =
            verify_source(Arc::clone(layout), file, access, SourceId(1), &options).unwrap();
        (
            evidence,
            options.diagnostics.source_io().read_bytes,
            options.diagnostics.stage(Stage::Verify).completed,
        )
    }

    fn assert_same(found: &FileEvidence, expected: &FileEvidence, case: &str) {
        assert_eq!(found.verdicts(), expected.verdicts(), "{case}");
        assert_eq!(found.whole_matches(), expected.whole_matches(), "{case}");
        assert_eq!(
            found.protected_complete(),
            expected.protected_complete(),
            "{case}"
        );
    }

    #[test]
    fn a_matching_whole_hash_settles_the_file_without_an_extent_pass() {
        let options = ExecutionOptions::default();
        let layout = Arc::new(BlockLayout::new(&gf8_set(), &options).unwrap());
        for (index, (name, bytes)) in gf8_contents().into_iter().enumerate() {
            assert_eq!(layout.files[index].path, name);
            for positioned in [false, true] {
                let (evidence, read, hashed) = verified(&layout, index, &bytes, positioned);
                assert_same(&evidence, &single_pass(&layout, index, &bytes), name);
                assert_eq!(evidence.whole_matches(), Some(true), "{name}");
                assert!(evidence.protected_complete(), "{name}");
                assert_eq!(read, bytes.len() as u64, "{name}: read more than once");
                assert_eq!(hashed, bytes.len() as u64, "{name}: hashed more than once");
            }
        }
    }

    #[test]
    fn a_mismatch_rereads_once_and_finds_the_same_damaged_extents() {
        let tree = TempTree::new("verify-order-mismatch");
        let built = cauchy_block_set(64, 1024, 4, b"PAR3 verify order", &tree);
        let mut packets = Vec::new();
        for path in &built.paths {
            packets.extend(
                crate::scan::scan_packets_from_path(path)
                    .unwrap()
                    .into_iter()
                    .map(|(_, packet)| packet),
            );
        }
        let set = crate::set::Par3Set::from_packets_for(packets, built.id).unwrap();
        let options = ExecutionOptions::default();
        let many = Arc::new(BlockLayout::new(&set, &options).unwrap());
        let gf8 = Arc::new(BlockLayout::new(&gf8_set(), &options).unwrap());
        let mut cases: Vec<(String, Arc<BlockLayout>, usize, Vec<u8>)> = Vec::new();
        let mut blocks = built.contents[0].1.clone();
        for block in [0usize, 3, 17, 40, 63] {
            blocks[block * 1024 + 11] ^= 0x80;
        }
        cases.push(("blocks".into(), Arc::clone(&many), 0, blocks));
        for (index, (name, bytes)) in gf8_contents().into_iter().enumerate() {
            // The last byte sits in the tail, packed or inline.
            let mut tail = bytes.clone();
            *tail.last_mut().unwrap() ^= 0x01;
            cases.push((format!("{name} tail"), Arc::clone(&gf8), index, tail));
            let mut head = bytes.clone();
            head[0] ^= 0x01;
            cases.push((format!("{name} head"), Arc::clone(&gf8), index, head));
        }
        for (case, layout, file, bytes) in &cases {
            let expected = single_pass(layout, *file, bytes);
            assert_eq!(expected.whole_matches(), Some(false), "{case}");
            for positioned in [false, true] {
                let (evidence, read, hashed) = verified(layout, *file, bytes, positioned);
                assert_same(&evidence, &expected, case);
                assert_eq!(
                    read,
                    2 * bytes.len() as u64,
                    "{case}: not exactly one reread"
                );
                // The reread reports no progress the first pass reported.
                assert_eq!(hashed, bytes.len() as u64, "{case}");
            }
        }
        let (evidence, _, _) = verified(&many, 0, &cases[0].3, false);
        let damaged: Vec<usize> = evidence
            .verdicts()
            .iter()
            .enumerate()
            .filter(|(_, verdict)| *verdict == ExtentVerdict::Damaged)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(damaged, [0, 3, 17, 40, 63]);
    }

    #[test]
    fn sizes_that_cannot_match_skip_the_whole_hash_pass() {
        let options = ExecutionOptions::default();
        let layout = Arc::new(BlockLayout::new(&gf8_set(), &options).unwrap());
        let (_, bytes) = gf8_contents().remove(0);
        let mut longer = bytes.clone();
        longer.extend_from_slice(b"trailing");
        for (case, bytes) in [
            ("short", bytes[..bytes.len() - 100].to_vec()),
            ("long", longer),
        ] {
            let expected = single_pass(&layout, 0, &bytes);
            for positioned in [false, true] {
                let (evidence, read, _) = verified(&layout, 0, &bytes, positioned);
                assert_same(&evidence, &expected, case);
                assert_eq!(evidence.whole_matches(), None, "{case}");
                assert_eq!(read, bytes.len() as u64, "{case}: one pass, not two");
            }
        }
    }

    #[test]
    fn a_file_without_a_whole_hash_takes_one_extent_pass() {
        let options = ExecutionOptions::default();
        // Model a File packet that carries no fingerprint. The layout is the
        // engine's in-memory view; no packet bytes are touched.
        let mut layout = BlockLayout::new(&gf8_set(), &options).unwrap();
        layout.files[0].fingerprint = [0; 16];
        let layout = Arc::new(layout);
        let (_, bytes) = gf8_contents().remove(0);
        let mut damaged = bytes.clone();
        damaged[0] ^= 0x01;
        for (case, bytes) in [("intact", bytes), ("damaged", damaged)] {
            let expected = single_pass(&layout, 0, &bytes);
            assert_eq!(expected.whole_matches(), None, "{case}");
            for positioned in [false, true] {
                let (evidence, read, hashed) = verified(&layout, 0, &bytes, positioned);
                assert_same(&evidence, &expected, case);
                assert_eq!(read, bytes.len() as u64, "{case}: one pass, not two");
                assert_eq!(hashed, bytes.len() as u64, "{case}");
            }
        }
    }
}

#[cfg(test)]
mod whole_file_first_tests {
    //! Whole-file-first disk verification against the single streaming pass.
    use super::*;
    use crate::runtime::Stage;
    use crate::source::MemorySourceAccess;
    use crate::test_reference::{TempTree, cauchy_block_set};

    /// Provider that reports `hole` as unavailable. With `forward`, it also
    /// offers a forward reader that stops at the hole, as a partially
    /// downloaded source does.
    struct Holey {
        inner: MemorySourceAccess,
        hole: Option<Range<u64>>,
        forward: bool,
    }

    impl SourceAccess for Holey {
        fn snapshot(&self, source: SourceId) -> std::io::Result<Option<SourceSnapshot>> {
            self.inner.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read_at(source, offset, out)
        }
        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<Range<u64>>> {
            let Some(range) = self.inner.next_available(source, offset)? else {
                return Ok(None);
            };
            Ok(match &self.hole {
                Some(hole) if range.start < hole.start => {
                    Some(range.start..hole.start.min(range.end))
                }
                Some(hole) if range.start < hole.end => {
                    (hole.end < range.end).then_some(hole.end..range.end)
                }
                _ => Some(range),
            })
        }
        fn open_sequential(
            &self,
            source: SourceId,
        ) -> std::io::Result<Option<Box<dyn std::io::Read + Send>>> {
            if !self.forward {
                return Ok(None);
            }
            let Some(reader) = self.inner.open_sequential(source)? else {
                return Ok(None);
            };
            let prefix = self.hole.as_ref().map_or(u64::MAX, |hole| hole.start);
            Ok(Some(Box::new(std::io::Read::take(reader, prefix))))
        }
    }

    /// The pre-W2.1 verifier: one streaming pass hashing extents and the whole
    /// file side by side.
    fn single_pass(
        layout: &Arc<BlockLayout>,
        file: usize,
        bytes: &[u8],
        hole: Option<Range<u64>>,
    ) -> FileEvidence {
        let snapshot = SourceSnapshot {
            len: bytes.len() as u64,
            generation: 1,
        };
        let mut verifier = StreamingVerifier::new(
            Arc::clone(layout),
            file,
            SourceId(1),
            snapshot,
            ExecutionOptions::default(),
        )
        .unwrap();
        let mut at = 0usize;
        while at < bytes.len() {
            let mut end = (at + 4096).min(bytes.len());
            if let Some(hole) = &hole {
                if (at as u64) >= hole.start && (at as u64) < hole.end {
                    at = hole.end as usize;
                    continue;
                }
                if (at as u64) < hole.start && (end as u64) > hole.start {
                    end = hole.start as usize;
                }
            }
            verifier.feed(at as u64, &bytes[at..end]).unwrap();
            at = end;
        }
        verifier.finish()
    }

    fn run(
        layout: &Arc<BlockLayout>,
        file: usize,
        bytes: &[u8],
        hole: Option<Range<u64>>,
        forward: bool,
    ) -> (FileEvidence, u64, u64, u64) {
        run_ordered(layout, file, bytes, hole, forward, None)
    }

    fn run_ordered(
        layout: &Arc<BlockLayout>,
        file: usize,
        bytes: &[u8],
        hole: Option<Range<u64>>,
        forward: bool,
        whole_first: Option<bool>,
    ) -> (FileEvidence, u64, u64, u64) {
        let options = ExecutionOptions {
            stripe_bytes: 1000,
            disk_verify_whole_first: whole_first,
            ..ExecutionOptions::default()
        };
        let mut memory = MemorySourceAccess::default();
        memory.insert(SourceId(1), 1, bytes.to_vec().into());
        let access = Holey {
            inner: memory,
            hole,
            forward,
        };
        let evidence =
            verify_source(Arc::clone(layout), file, &access, SourceId(1), &options).unwrap();
        (
            evidence,
            options.diagnostics.source_io().read_bytes,
            options.diagnostics.source_io().read_calls,
            options.diagnostics.stage(Stage::Verify).completed,
        )
    }

    fn many_layout(tree: &TempTree) -> (Arc<BlockLayout>, Vec<u8>) {
        let built = cauchy_block_set(64, 1024, 4, b"PAR3 w2 review", tree);
        let mut packets = Vec::new();
        for path in &built.paths {
            packets.extend(
                crate::scan::scan_packets_from_path(path)
                    .unwrap()
                    .into_iter()
                    .map(|(_, packet)| packet),
            );
        }
        let set = crate::set::Par3Set::from_packets_for(packets, built.id).unwrap();
        let layout = Arc::new(BlockLayout::new(&set, &ExecutionOptions::default()).unwrap());
        (layout, built.contents[0].1.clone())
    }

    /// Truncated / appended files, with and without damage, on a 64-block
    /// file. Classification must match the single pass, and a length that
    /// cannot match must cost exactly one pass.
    #[test]
    fn truncated_and_appended_files_match_the_single_pass() {
        let tree = TempTree::new("whole-first-lengths");
        let (layout, bytes) = many_layout(&tree);
        let mut damaged = bytes.clone();
        damaged[5 * 1024 + 3] ^= 0x40;
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("short half block", bytes[..bytes.len() - 512].to_vec()),
            ("short one block", bytes[..bytes.len() - 1024].to_vec()),
            ("short to one byte", bytes[..1].to_vec()),
            ("empty", Vec::new()),
            ("short + damaged", damaged[..damaged.len() - 512].to_vec()),
        ];
        let mut long = bytes.clone();
        long.extend_from_slice(&[0xAA; 3000]);
        cases.push(("appended", long));
        let mut long_damaged = damaged.clone();
        long_damaged.extend_from_slice(b"x");
        cases.push(("appended + damaged", long_damaged));
        for (case, data) in &cases {
            let expected = single_pass(&layout, 0, data, None);
            for forward in [false, true] {
                let (found, read, _, hashed) = run(&layout, 0, data, None, forward);
                assert_eq!(found.verdicts(), expected.verdicts(), "{case}");
                assert_eq!(found.whole_matches(), expected.whole_matches(), "{case}");
                assert_eq!(found.whole_matches(), None, "{case}");
                assert_eq!(read, data.len() as u64, "{case}: more than one pass");
                assert_eq!(hashed, data.len() as u64, "{case}");
            }
        }
    }

    /// A positioned source with a hole over protected bytes can never be
    /// settled by the whole-file hash. Its first available range already
    /// shows the hole, so it is read once, extents and whole hash side by
    /// side, as the single pass read it.
    #[test]
    fn a_hole_in_a_positioned_source_costs_one_pass() {
        let tree = TempTree::new("whole-first-hole");
        let (layout, bytes) = many_layout(&tree);
        let len = bytes.len() as u64;
        let hole = (len - 3 * 1024)..(len - 2 * 1024);
        let expected = single_pass(&layout, 0, &bytes, Some(hole.clone()));
        let (found, read, calls, hashed) = run(&layout, 0, &bytes, Some(hole.clone()), false);
        assert_eq!(found.verdicts(), expected.verdicts());
        assert_eq!(found.whole_matches(), expected.whole_matches());
        let available = len - (hole.end - hole.start);
        eprintln!(
            "hole: file {len} available {available} read {read} calls {calls} hashed {hashed}"
        );
        assert_eq!(
            read, available,
            "hole case read {read} bytes for {available} available"
        );
        assert_eq!(hashed, available);
    }

    /// The same hole behind a forward reader that stops at it: nothing shows
    /// the hole before the reader runs out, so the prefix is hashed whole
    /// first. Past the hole the extents are hashed as they arrive, and only
    /// the prefix is read again.
    #[test]
    fn a_hole_behind_a_forward_reader_rereads_only_the_prefix() {
        let tree = TempTree::new("whole-first-hole-forward");
        let (layout, bytes) = many_layout(&tree);
        let len = bytes.len() as u64;
        for hole in [
            (len - 3 * 1024)..(len - 2 * 1024),
            (5 * 1024 + 100)..(9 * 1024),
        ] {
            let expected = single_pass(&layout, 0, &bytes, Some(hole.clone()));
            let (found, read, calls, hashed) = run(&layout, 0, &bytes, Some(hole.clone()), true);
            assert_eq!(found.verdicts(), expected.verdicts(), "{hole:?}");
            assert_eq!(found.whole_matches(), expected.whole_matches(), "{hole:?}");
            let available = len - (hole.end - hole.start);
            eprintln!(
                "forward hole {hole:?}: available {available} read {read} calls {calls} hashed {hashed}"
            );
            assert_eq!(read, available + hole.start, "{hole:?}");
            assert_eq!(hashed, available, "{hole:?}");
        }
    }

    /// Progress: a damaged file reports its length once as completed Verify
    /// work, though it is read twice.
    #[test]
    fn a_damaged_file_reports_its_length_once() {
        let tree = TempTree::new("whole-first-progress");
        let (layout, mut bytes) = many_layout(&tree);
        bytes[100] ^= 1;
        for forward in [false, true] {
            let (_, read, _, hashed) = run(&layout, 0, &bytes, None, forward);
            eprintln!(
                "progress: len {} read {read} verify-completed {hashed}",
                bytes.len()
            );
            assert_eq!(read, 2 * bytes.len() as u64, "operator decision D2");
            assert_eq!(hashed, bytes.len() as u64, "progress overshoot");
        }
    }

    /// The forced single-pass order reads intact and damaged files once and
    /// reaches the same evidence as the default whole-file-first order.
    #[test]
    fn the_single_pass_order_reads_once_with_the_same_evidence() {
        let tree = TempTree::new("whole-first-off");
        let (layout, bytes) = many_layout(&tree);
        let mut damaged = bytes.clone();
        damaged[5 * 1024 + 3] ^= 0x40;
        for (case, data) in [("intact", &bytes), ("damaged", &damaged)] {
            for forward in [false, true] {
                let (expected, ..) = run(&layout, 0, data, None, forward);
                let (found, read, _, hashed) =
                    run_ordered(&layout, 0, data, None, forward, Some(false));
                assert_eq!(found.verdicts(), expected.verdicts(), "{case}");
                assert_eq!(found.whole_matches(), expected.whole_matches(), "{case}");
                assert_eq!(read, data.len() as u64, "{case}: more than one pass");
                assert_eq!(hashed, data.len() as u64, "{case}");
            }
        }
    }
}
