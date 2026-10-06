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
    /// Whether whole-file hashing may fork onto the caller's admitted pool.
    /// Only a caller that is already inside one may set it.
    parallel_hash: bool,
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
            parallel_hash: false,
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
        progress.advance(bytes.len() as u64);
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
    /// once protected bytes arrive out of order it cannot, and the caller
    /// should stop reading for it.
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

/// The verification read buffer, grown to the parallel-hash size only when a
/// pool is admitted, the source is large enough to use it, and the shared
/// budget still leaves working room afterwards.
///
/// A refused growth is not a refused verification: the small buffer is the
/// documented fallback, and it never reacquires workers.
fn verification_buffer(
    options: &ExecutionOptions,
    len: u64,
    parallel: bool,
) -> EngineResult<Reservation> {
    let small = options.stripe_bytes.min(64 << 10);
    let large = crate::hash::PARALLEL_HASH_BYTES;
    if parallel && len >= large as u64 {
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
/// time to hash its extents.
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
    let reservation = verification_buffer(options, snapshot.len, parallel)?;
    let size = reservation.bytes();
    verifier.parallel_hash = parallel && size >= crate::hash::PARALLEL_HASH_BYTES;
    let _reservation = reservation;
    let mut buffer = vec![0; size];
    let description = &verifier.layout.files[verifier.file];
    let mut whole = None;
    if description.fingerprint == [0; 16] {
        // Nothing can promote extents without a whole-file hash, so skip
        // computing one; `finish` would seal `None` either way.
        verifier.whole_ordered = false;
    } else if unprotected_between(description, snapshot.len, description.len) {
        // The whole-file hash alone settles an intact file, and hashing every
        // extent beside it would double the work of the common case. Only a
        // file it does not settle pays a second read, for its extents.
        read_source(
            access,
            source,
            snapshot,
            options,
            &mut buffer,
            &mut |offset, bytes| verifier.feed_whole(offset, bytes),
        )?;
        whole = verifier.whole_result();
        if whole == Some(true) {
            ensure_snapshot(access, source, snapshot)?;
            return Ok(verifier.finish());
        }
        // The verdict is known; the extent pass need not hash the file again.
        verifier.whole_ordered = false;
    }
    read_source(
        access,
        source,
        snapshot,
        options,
        &mut buffer,
        &mut |offset, bytes| verifier.feed(offset, bytes).map(|()| true),
    )?;
    ensure_snapshot(access, source, snapshot)?;
    let mut evidence = verifier.finish();
    if whole.is_some() {
        evidence.whole_matches = whole;
    }
    Ok(evidence)
}

/// Read a source generation in order, through its forward reader when it
/// offers one and through `next_available` past that prefix, handing each
/// filled buffer to `feed` until it returns `false`.
fn read_source(
    access: &dyn SourceAccess,
    source: SourceId,
    snapshot: SourceSnapshot,
    options: &ExecutionOptions,
    buffer: &mut [u8],
    feed: &mut dyn FnMut(u64, &[u8]) -> EngineResult<bool>,
) -> EngineResult<()> {
    let mut offset = 0;
    if let Some(mut reader) = access.open_sequential(source)? {
        while offset < snapshot.len {
            options.cancel.check()?;
            let take = (snapshot.len - offset).min(buffer.len() as u64) as usize;
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
            if !feed(offset, &buffer[..read])? {
                return Ok(());
            }
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
                if !feed(offset, &buffer[..read])? {
                    return Ok(());
                }
                offset += read as u64;
            }
            offset = range.end;
        }
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
            for parallel in [false, true] {
                for len in [
                    0,
                    (PARALLEL_HASH_BYTES - 1) as u64,
                    PARALLEL_HASH_BYTES as u64,
                ] {
                    let buffer = verification_buffer(&options, len, parallel).unwrap();
                    let large = parallel
                        && len >= PARALLEL_HASH_BYTES as u64
                        && limit >= PARALLEL_HASH_BYTES + (128 << 10);
                    assert_eq!(
                        buffer.bytes(),
                        if large { PARALLEL_HASH_BYTES } else { 64 << 10 }
                    );
                    assert_eq!(buffer.category(), MemoryCategory::SourceScratch);
                    drop(buffer);
                    assert_eq!(options.memory.used(), 0);
                }
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
                assert_eq!(hashed, 2 * bytes.len() as u64, "{case}");
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
