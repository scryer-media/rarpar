//! Streaming verification session for incremental PAR2 verification during download.
//!
//! [`VerificationSession`] tracks verification state as data arrives, allowing
//! the scheduler to query file status and repairability at any time without
//! waiting for the full download to complete.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use thiserror::Error;

use crate::checksum::SliceChecksumState;
use crate::packet::Packet;
use crate::par2_set::Par2FileSet;
use crate::types::{FileId, RecoverySetId, SliceChecksum};
use crate::verify::{FileStatus, FileVerification, Repairability, VerificationResult};

const DEFAULT_BUFFERED_BOUNDARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_PARTIAL_RANGES_PER_SLICE: usize = 4096;
const PARTIAL_RANGE_ACCOUNTING_BYTES: usize = std::mem::size_of::<(u64, Vec<u8>)>() + 64;

/// A caller-shareable cap for buffered, incomplete slice data.
///
/// Whole, aligned slices are checksummed immediately and do not consume this
/// budget. Cloning the budget makes its limit apply across all of the sessions
/// using that clone.
#[derive(Clone, Debug)]
pub struct VerificationMemoryBudget {
    inner: Arc<VerificationMemoryBudgetInner>,
}

#[derive(Debug)]
struct VerificationMemoryBudgetInner {
    max_buffered_bytes: usize,
    buffered_bytes: AtomicUsize,
}

impl VerificationMemoryBudget {
    /// Create a budget shared by any sessions given a clone of this value.
    pub fn new(max_buffered_bytes: usize) -> Self {
        Self {
            inner: Arc::new(VerificationMemoryBudgetInner {
                max_buffered_bytes,
                buffered_bytes: AtomicUsize::new(0),
            }),
        }
    }

    /// Maximum number of buffered boundary bytes allowed across all users.
    pub fn max_buffered_bytes(&self) -> usize {
        self.inner.max_buffered_bytes
    }

    /// Number of bytes currently reserved by incomplete slices.
    pub fn buffered_bytes(&self) -> usize {
        self.inner.buffered_bytes.load(Ordering::Acquire)
    }

    /// Number of additional boundary bytes that can currently be buffered.
    pub fn available_bytes(&self) -> usize {
        self.max_buffered_bytes()
            .saturating_sub(self.buffered_bytes())
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }

        let limit = self.inner.max_buffered_bytes;
        let mut current = self.inner.buffered_bytes.load(Ordering::Acquire);
        loop {
            if bytes > limit.saturating_sub(current) {
                return false;
            }

            match self.inner.buffered_bytes.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, bytes: usize) {
        if bytes != 0 {
            self.inner.buffered_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

impl Default for VerificationMemoryBudget {
    fn default() -> Self {
        Self::new(DEFAULT_BUFFERED_BOUNDARY_BYTES)
    }
}

/// Configuration for a [`VerificationSession`].
#[derive(Clone, Debug, Default)]
pub struct VerificationSessionOptions {
    memory_budget: VerificationMemoryBudget,
}

impl VerificationSessionOptions {
    /// Create options with the default 64 MiB boundary-buffer budget.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the caller-shareable budget used for incomplete slice data.
    pub fn with_memory_budget(mut self, memory_budget: VerificationMemoryBudget) -> Self {
        self.memory_budget = memory_budget;
        self
    }

    /// The budget this session will use for incomplete slice data.
    pub fn memory_budget(&self) -> &VerificationMemoryBudget {
        &self.memory_budget
    }
}

/// A completed PAR2 slice verdict, suitable for passing to a repair session.
///
/// Evidence deliberately identifies PAR2 coordinates only. It never exposes a
/// filesystem path or assumes where the downloaded bytes were stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceEvidenceStrength {
    /// The slice was compared using the PAR2 IFSC CRC32 only.
    Crc32Only,
    /// The slice was compared using both the PAR2 IFSC CRC32 and MD5.
    Crc32AndMd5,
}

/// Why an in-stream CRC32 attestation cannot be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InStreamCrc32ProofError {
    #[error("in-stream CRC32 covered no bytes")]
    EmptyCoverage,
    #[error("in-stream CRC32 did not cover the whole slice")]
    IncompleteSliceCoverage,
    #[error("in-stream CRC32 was not derived from the bytes the source will serve")]
    UnverifiedSourceBytes,
    #[error("in-stream CRC32 has no independent second-grid CRC32 coverage")]
    NoIndependentCrc32Coverage,
}

/// Validated attestation that a caller derived a slice's PAR2 CRC32 in stream.
///
/// This is the counterpart to [`crate::ContiguousAssemblyProof`] for a single
/// slice: it does not itself verify anything, it records that the caller
/// asserted every property that makes a CRC32-only slice verdict admissible,
/// and refuses to exist when any of them is false.
///
/// # What a proven attestation asserts
///
/// - The CRC32 covered the slice's full extent — every byte from the slice's
///   own offset in the file the recovery set describes, zero-padded to the
///   block size exactly as PAR2 checksums a short final slice.
/// - Those bytes are the bytes the repair source will serve, already durable,
///   not a speculative or in-flight buffer.
/// - The same span is independently covered by a second CRC32 cut on an
///   unrelated grid — for a Usenet download path, the article-aligned yEnc
///   `pcrc32` beside the block-aligned PAR2 CRC32.
///
/// # What it does not assert
///
/// No MD5 was computed, so this is not slice *identity*: it is the statement
/// that a 32-bit checksum over the slice's bytes agreed with the recovery
/// set's IFSC entry. A verdict admitted this way seeds a repair *input*; it
/// never promotes a file to a whole-file match, and repair still recomputes
/// the IFSC CRC32 **and MD5** over every byte it consumes, so an attestation
/// that turns out to be wrong fails the repair loudly rather than producing
/// wrong output. Settle-time verification of slices with no verdict is
/// likewise untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InStreamCrc32Proof {
    covered_length: u64,
}

impl InStreamCrc32Proof {
    /// Validate and record an in-stream CRC32 attestation.
    ///
    /// `covered_length` is the number of the file's real bytes the derivation
    /// covered for this slice — the full block size, or the short remainder for
    /// a final slice before PAR2's zero padding. The three flags are the
    /// caller's assertions described on the type; every one must hold.
    pub fn try_new(
        covered_length: u64,
        slice_fully_covered: bool,
        derived_from_durable_bytes: bool,
        independently_crc32_covered: bool,
    ) -> Result<Self, InStreamCrc32ProofError> {
        if covered_length == 0 {
            return Err(InStreamCrc32ProofError::EmptyCoverage);
        }
        if !slice_fully_covered {
            return Err(InStreamCrc32ProofError::IncompleteSliceCoverage);
        }
        if !derived_from_durable_bytes {
            return Err(InStreamCrc32ProofError::UnverifiedSourceBytes);
        }
        if !independently_crc32_covered {
            return Err(InStreamCrc32ProofError::NoIndependentCrc32Coverage);
        }

        Ok(Self { covered_length })
    }

    /// Real file bytes the attested derivation covered for this slice.
    pub fn covered_length(&self) -> u64 {
        self.covered_length
    }
}

/// A completed PAR2 slice verdict, suitable for passing to a repair session.
///
/// Evidence deliberately identifies PAR2 coordinates only. It never exposes a
/// filesystem path or assumes where the downloaded bytes were stored.
///
/// A session produces this itself from bytes it hashed
/// ([`VerificationSession::slice_evidence`]). A caller that hashed the bytes
/// during its own single pass over them — never handing them to par2-rs at all
/// — mints one with [`SliceEvidence::from_in_stream_crc32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceEvidence {
    recovery_set_id: RecoverySetId,
    file_id: FileId,
    slice_index: u32,
    valid: bool,
    strength: SliceEvidenceStrength,
    /// Present only for externally attested verdicts. This is what separates a
    /// CRC32-only verdict a repair session may act on from one it may not.
    in_stream: Option<InStreamCrc32Proof>,
}

impl SliceEvidence {
    /// Recovery set whose metadata produced this verdict.
    pub fn recovery_set_id(&self) -> RecoverySetId {
        self.recovery_set_id
    }

    /// File to which this PAR2 slice belongs.
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Zero-based PAR2 slice index within [`Self::file_id`].
    pub fn slice_index(&self) -> u32 {
        self.slice_index
    }

    /// Whether this slice's CRC32 and MD5 matched the PAR2 IFSC entry.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Hash strength used to produce this verdict.
    ///
    /// Externally attested verdicts report [`SliceEvidenceStrength::Crc32Only`],
    /// because that is what was actually computed. Use
    /// [`Self::in_stream_proof`] to tell them apart from an unattested CRC32
    /// comparison.
    pub fn strength(&self) -> SliceEvidenceStrength {
        self.strength
    }

    /// Mint a verdict the caller derived itself, in stream, from a slice's
    /// PAR2 CRC32.
    ///
    /// This exists for a caller that already hashes every payload byte for its
    /// own reasons and can cut that hash on the recovery set's block grid. It
    /// hands par2-rs the *conclusion* — this slice's CRC32 did or did not agree
    /// with the recovery set's IFSC entry — without ever handing over the
    /// bytes, so nothing is read, buffered or hashed twice.
    ///
    /// `valid` is the result of that comparison. `proof` is the caller's
    /// attestation, and [`InStreamCrc32Proof`] documents exactly what it does
    /// and does not assert — in short, that a CRC32 covering the whole slice's
    /// durable bytes agreed with the IFSC entry, and *not* that the slice's
    /// identity was established, which needs MD5.
    ///
    /// The comparison itself is the caller's: par2-rs is not given the derived
    /// CRC32 and does not re-run the check. That is the point — the recovery
    /// set's expected CRC32 is public in its IFSC packet, so a caller that has
    /// read the set can compare against it as well as this crate can, and
    /// asking it to ship the value back for a redundant comparison would prove
    /// nothing the attestation does not already carry.
    ///
    /// # Where this lands
    ///
    /// A **valid** verdict seeds a repair input for that one slice, the same
    /// seat a slice hashed by [`VerificationSession`] takes. It never promotes
    /// a file to a whole-file match — only a complete-file hash does that — and
    /// repair re-derives both the IFSC CRC32 and MD5 over every byte it
    /// consumes, so a mistaken attestation fails the repair loudly instead of
    /// producing wrong output.
    ///
    /// An **invalid** verdict routes into the session's ordinary contradiction
    /// handling, which retires the *source* the verdict named — for a source
    /// served by a handle, that is the whole file, because file identity is the
    /// only thing such a source has to be named by. A caller holding good
    /// verdicts for a file's other slices should therefore seed those and
    /// simply not seed the damaged one, leaving it unresolved for repair or for
    /// a read-back pass, rather than seeding a contradiction that retires the
    /// good slices alongside it.
    pub fn from_in_stream_crc32(
        recovery_set_id: RecoverySetId,
        file_id: FileId,
        slice_index: u32,
        valid: bool,
        proof: InStreamCrc32Proof,
    ) -> Self {
        Self {
            recovery_set_id,
            file_id,
            slice_index,
            valid,
            strength: SliceEvidenceStrength::Crc32Only,
            in_stream: Some(proof),
        }
    }

    /// The in-stream attestation carried by this verdict, when it was minted by
    /// [`Self::from_in_stream_crc32`] rather than hashed by a session.
    pub fn in_stream_proof(&self) -> Option<&InStreamCrc32Proof> {
        self.in_stream.as_ref()
    }

    /// Whether a repair session may act on this verdict.
    ///
    /// True for a slice this crate hashed with both the IFSC CRC32 and MD5, and
    /// for an externally attested in-stream CRC32 verdict. False for a bare
    /// CRC32 comparison with nothing vouching for where its bytes came from —
    /// [`VerificationSession::verify_from_slice_crcs`] produces those, and a
    /// caller-supplied CRC32 with no attestation cannot say whether it
    /// describes the bytes a repair would later read.
    pub fn may_seed_repair_input(&self) -> bool {
        self.strength == SliceEvidenceStrength::Crc32AndMd5 || self.in_stream.is_some()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        recovery_set_id: RecoverySetId,
        file_id: FileId,
        slice_index: u32,
        valid: bool,
        strength: SliceEvidenceStrength,
    ) -> Self {
        Self {
            recovery_set_id,
            file_id,
            slice_index,
            valid,
            strength,
            in_stream: None,
        }
    }
}

/// A byte range the caller should read to settle an incomplete or ambiguous
/// slice. The range is expressed in the logical file, not a filesystem path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleRead {
    file_id: FileId,
    slice_index: u32,
    offset: u64,
    length: u64,
}

impl SettleRead {
    fn new(file_id: FileId, slice_index: usize, offset: u64, length: u64) -> Self {
        Self {
            file_id,
            slice_index: u32::try_from(slice_index).unwrap_or(u32::MAX),
            offset,
            length,
        }
    }

    /// File containing the range to be read.
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Zero-based PAR2 slice index containing this read.
    pub fn slice_index(&self) -> u32 {
        self.slice_index
    }

    /// Logical file offset to read.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Number of bytes to read.
    pub fn length(&self) -> u64 {
        self.length
    }
}

/// High-level disposition for a call to [`VerificationSession::feed_range`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedDisposition {
    /// One or more slices were verified immediately or after completing a buffer.
    Verified,
    /// Boundary data was retained while waiting for the requested settle reads.
    Buffered,
    /// The range only repeated bytes already retained or verified.
    Duplicate,
    /// PAR2 metadata or slice checksums have not arrived yet.
    MetadataPending,
    /// The supplied file ID is not part of the currently known PAR2 set.
    UnknownFile,
    /// The supplied byte range is outside the declared file length.
    OutOfRange,
    /// Retaining a boundary range would exceed the shared memory budget.
    BudgetExhausted,
    /// A previously buffered byte and this feed disagree.
    ConflictingOverlap,
    /// A settled slice was supplied only partially, so its identity cannot be
    /// checked without reading the complete slice again.
    NeedsSettleRead,
}

/// Detailed result of an arbitrary-range feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedOutcome {
    disposition: FeedDisposition,
    evidence: Vec<SliceEvidence>,
    settle_reads: Vec<SettleRead>,
}

impl FeedOutcome {
    fn new(disposition: FeedDisposition) -> Self {
        Self {
            disposition,
            evidence: Vec::new(),
            settle_reads: Vec::new(),
        }
    }

    /// Summary disposition for this feed.
    pub fn disposition(&self) -> FeedDisposition {
        self.disposition
    }

    /// Slices whose verdict became known during this feed.
    pub fn evidence(&self) -> &[SliceEvidence] {
        &self.evidence
    }

    /// Missing or full-slice reads needed to settle the affected slices.
    pub fn settle_reads(&self) -> &[SettleRead] {
        &self.settle_reads
    }
}

/// Stable spelling for callers that prefer to name the operation explicitly.
pub type FeedRangeOutcome = FeedOutcome;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SliceFingerprint {
    crc32: u32,
    md5: [u8; 16],
}

impl SliceFingerprint {
    fn from_data(data: &[u8], slice_size: u64) -> Self {
        let mut state = SliceChecksumState::new();
        state.update(data);
        let pad_to = ((data.len() as u64) < slice_size).then_some(slice_size);
        let (crc32, md5) = state.finalize(pad_to);
        Self { crc32, md5 }
    }

    fn is_valid_for(self, expected: &SliceChecksum) -> bool {
        self.crc32 == expected.crc32 && self.md5 == expected.md5
    }
}

/// Sparse byte storage for a slice which arrived in more than one range.
struct PartialSlice {
    expected_len: u64,
    ranges: BTreeMap<u64, Vec<u8>>,
    buffered_bytes: usize,
    reserved_bytes: usize,
}

impl PartialSlice {
    fn new(expected_len: u64) -> Self {
        Self {
            expected_len,
            ranges: BTreeMap::new(),
            buffered_bytes: 0,
            reserved_bytes: 0,
        }
    }

    fn matches(&self, start: u64, data: &[u8]) -> bool {
        let end = start + data.len() as u64;
        self.ranges.range(..end).all(|(&range_start, existing)| {
            let range_end = range_start + existing.len() as u64;
            let overlap_start = range_start.max(start);
            let overlap_end = range_end.min(end);
            overlap_start >= overlap_end
                || existing
                    [(overlap_start - range_start) as usize..(overlap_end - range_start) as usize]
                    == data[(overlap_start - start) as usize..(overlap_end - start) as usize]
        })
    }

    fn uncovered_ranges(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut cursor = start;
        let mut uncovered = Vec::new();

        for (&range_start, existing) in self.ranges.range(..end) {
            let range_end = range_start + existing.len() as u64;
            if range_end <= cursor {
                continue;
            }
            if range_start > cursor {
                let gap_end = range_start.min(end);
                uncovered.push((cursor, gap_end));
                cursor = gap_end;
            }
            cursor = cursor.max(range_end.min(end));
            if cursor == end {
                break;
            }
        }

        if cursor < end {
            uncovered.push((cursor, end));
        }
        uncovered
    }

    /// Insert only previously unseen bytes. Returns the new byte count, or
    /// `None` when the shared budget cannot reserve the requested storage.
    fn insert(
        &mut self,
        start: u64,
        data: &[u8],
        budget: &VerificationMemoryBudget,
    ) -> Option<usize> {
        let end = start + data.len() as u64;
        let uncovered = self.uncovered_ranges(start, end);
        if self.ranges.len().saturating_add(uncovered.len()) > MAX_PARTIAL_RANGES_PER_SLICE {
            return None;
        }
        let added = uncovered
            .iter()
            .map(|(from, to)| usize::try_from(to - from).unwrap_or(usize::MAX))
            .sum::<usize>();
        let reservation = added.saturating_add(
            uncovered
                .len()
                .saturating_mul(PARTIAL_RANGE_ACCOUNTING_BYTES),
        );

        if !budget.try_reserve(reservation) {
            return None;
        }

        for (from, to) in uncovered {
            self.ranges.insert(
                from,
                data[(from - start) as usize..(to - start) as usize].to_vec(),
            );
        }
        self.buffered_bytes += added;
        self.reserved_bytes = self.reserved_bytes.saturating_add(reservation);
        Some(added)
    }

    fn is_complete(&self) -> bool {
        self.buffered_bytes as u64 == self.expected_len
    }

    fn fingerprint(&self, slice_size: u64) -> Option<SliceFingerprint> {
        if !self.is_complete() {
            return None;
        }

        let mut state = SliceChecksumState::new();
        let mut offset = 0;
        for (&range_start, data) in &self.ranges {
            if range_start != offset {
                return None;
            }
            state.update(data);
            offset += data.len() as u64;
        }
        if offset != self.expected_len {
            return None;
        }

        let pad_to = (self.expected_len < slice_size).then_some(slice_size);
        let (crc32, md5) = state.finalize(pad_to);
        Some(SliceFingerprint { crc32, md5 })
    }

    fn settle_reads(
        &self,
        file_id: FileId,
        slice_index: usize,
        slice_offset: u64,
    ) -> Vec<SettleRead> {
        self.uncovered_ranges(0, self.expected_len)
            .into_iter()
            .map(|(start, end)| {
                SettleRead::new(file_id, slice_index, slice_offset + start, end - start)
            })
            .collect()
    }
}

/// Per-file verification state tracking.
struct FileVerificationState {
    /// Boundary slices kept only until their sparse ranges cover the slice.
    partial_slices: HashMap<usize, PartialSlice>,
    /// Per-slice verification result. `None` means not yet finalized,
    /// `Some(true)` = valid, `Some(false)` = damaged.
    verified_slices: Vec<Option<bool>>,
    /// Checksum fingerprints retained after immediate hashing so an identical
    /// full-slice retry is cheap and a conflicting full-slice retry is explicit.
    fingerprints: Vec<Option<SliceFingerprint>>,
    /// Total unique bytes accepted into still-pending or finalized slices.
    bytes_received: u64,
    /// Expected file length from the PAR2 file description.
    file_length: u64,
    /// PAR2 slice size.
    slice_size: u64,
}

impl FileVerificationState {
    fn new(file_length: u64, slice_size: u64) -> Self {
        let num_slices = if file_length == 0 || slice_size == 0 {
            0
        } else {
            file_length.div_ceil(slice_size) as usize
        };

        Self {
            partial_slices: HashMap::new(),
            verified_slices: vec![None; num_slices],
            fingerprints: vec![None; num_slices],
            bytes_received: 0,
            file_length,
            slice_size,
        }
    }

    fn slice_offset(&self, slice_index: usize) -> Option<u64> {
        (slice_index as u64).checked_mul(self.slice_size)
    }

    fn slice_len(&self, slice_index: usize) -> Option<u64> {
        let offset = self.slice_offset(slice_index)?;
        (offset < self.file_length).then(|| (self.file_length - offset).min(self.slice_size))
    }

    fn evidence(
        &self,
        recovery_set_id: RecoverySetId,
        file_id: FileId,
        slice_index: usize,
        valid: bool,
    ) -> SliceEvidence {
        SliceEvidence {
            recovery_set_id,
            file_id,
            slice_index: u32::try_from(slice_index).unwrap_or(u32::MAX),
            valid,
            strength: if self
                .fingerprints
                .get(slice_index)
                .is_some_and(Option::is_some)
            {
                SliceEvidenceStrength::Crc32AndMd5
            } else {
                SliceEvidenceStrength::Crc32Only
            },
            // A session hashed these bytes itself; there is no external claim
            // to record, and its own CRC32-only verdicts stay inadmissible.
            in_stream: None,
        }
    }

    fn full_slice_read(&self, file_id: FileId, slice_index: usize) -> SettleRead {
        SettleRead::new(
            file_id,
            slice_index,
            self.slice_offset(slice_index).unwrap_or(self.file_length),
            self.slice_len(slice_index).unwrap_or(0),
        )
    }

    fn discard_partial(&mut self, slice_index: usize, budget: &VerificationMemoryBudget) -> usize {
        self.partial_slices
            .remove(&slice_index)
            .map(|partial| {
                budget.release(partial.reserved_bytes);
                partial.buffered_bytes
            })
            .unwrap_or(0)
    }

    /// Count how many slices have been verified as valid.
    fn verified_count(&self) -> usize {
        self.verified_slices
            .iter()
            .filter(|v| **v == Some(true))
            .count()
    }

    /// Count how many slices have been verified as damaged.
    fn damaged_count(&self) -> usize {
        self.verified_slices
            .iter()
            .filter(|v| **v == Some(false))
            .count()
    }

    /// Count how many slices are still pending (not yet finalized).
    fn pending_count(&self) -> usize {
        self.verified_slices.iter().filter(|v| v.is_none()).count()
    }

    /// Total number of slices.
    fn total_slices(&self) -> usize {
        self.verified_slices.len()
    }
}

enum SliceFeed {
    Verified(SliceEvidence),
    Buffered(Vec<SettleRead>),
    Duplicate(Vec<SettleRead>),
    BudgetExhausted(SettleRead),
    Conflict(SettleRead),
    NeedsSettleRead(SettleRead),
}

/// Streaming verification session that tracks PAR2 verification state as data
/// arrives during download.
///
/// Usage:
/// 1. Call [`Self::add_par2_data`] when PAR2 metadata packets arrive.
/// 2. Call [`Self::feed_data`] as decoded file data arrives (slice-aligned).
/// 3. Query [`Self::file_status`], [`Self::repairability`], or
///    [`Self::is_complete`] at any time.
/// 4. Call [`Self::verification_result`] once all data has been fed.
pub struct VerificationSession {
    par2_set: Option<Arc<Par2FileSet>>,
    file_states: HashMap<FileId, FileVerificationState>,
    /// Packets received before the PAR2 set was complete. These are buffered
    /// so that `add_par2_data` can be called incrementally.
    buffered_packets: Vec<Packet>,
    memory_budget: VerificationMemoryBudget,
}

impl VerificationSession {
    /// Create a new empty verification session.
    pub fn new() -> Self {
        Self::with_options(VerificationSessionOptions::default())
    }

    /// Create a session using the supplied buffering policy.
    pub fn with_options(options: VerificationSessionOptions) -> Self {
        Self {
            par2_set: None,
            file_states: HashMap::new(),
            buffered_packets: Vec::new(),
            memory_budget: options.memory_budget,
        }
    }

    /// Create a session using a caller-shareable boundary-buffer budget.
    pub fn with_memory_budget(memory_budget: VerificationMemoryBudget) -> Self {
        Self::with_options(VerificationSessionOptions::new().with_memory_budget(memory_budget))
    }

    /// The budget used for incomplete slice data in this session.
    pub fn memory_budget(&self) -> &VerificationMemoryBudget {
        &self.memory_budget
    }

    fn initialize_file_states(&mut self) {
        let Some(par2_set) = self.par2_set.as_ref() else {
            return;
        };

        for file_id in &par2_set.recovery_file_ids {
            if !self.file_states.contains_key(file_id)
                && let Some(desc) = par2_set.file_description(file_id)
            {
                self.file_states.insert(
                    *file_id,
                    FileVerificationState::new(desc.length, par2_set.slice_size),
                );
            }
        }
    }

    /// Called when PAR2 metadata arrives. May be called multiple times as
    /// packets from different .par2 volumes arrive.
    ///
    /// Once a valid `Par2FileSet` can be built from the accumulated packets,
    /// per-file verification state is initialized.
    pub fn add_par2_data(&mut self, packets: &[Packet]) {
        if let Some(par2_set) = self.par2_set.as_mut() {
            // Once a set exists, merge only the new packets. Rebuilding from
            // `buffered_packets` would clone every earlier recovery payload on
            // every PAR2 volume arrival.
            let _ = Arc::make_mut(par2_set).merge_packets(packets.to_vec());
            self.initialize_file_states();
            return;
        }

        self.buffered_packets.extend(packets.iter().cloned());

        // Try to build a Par2FileSet from all accumulated packets.
        match Par2FileSet::from_packets(self.buffered_packets.clone()) {
            Ok(set) => {
                self.par2_set = Some(Arc::new(set));
                // The packets are now represented by the set. Keep no second
                // copy, especially because recovery payloads can be large.
                self.buffered_packets.clear();
                self.initialize_file_states();
            }
            Err(_) => {
                // Not enough packets yet (e.g., no main packet). Keep buffering.
            }
        }
    }

    /// Feed decoded file data for a specific file.
    ///
    /// This compatibility wrapper accepts the historical aligned input and
    /// intentionally discards the detailed outcome. New callers should use
    /// [`feed_range`](Self::feed_range) to receive evidence and settle reads.
    ///
    /// If PAR2 metadata has not yet arrived, the data is silently ignored.
    /// (The assembly layer should re-feed data after PAR2 metadata arrives
    /// if needed, or the caller can handle this at a higher level.)
    pub fn feed_data(&mut self, file_id: &FileId, offset: u64, data: &[u8]) {
        let _ = self.feed_range(file_id, offset, data);
    }

    /// Feed an arbitrary logical byte range for a PAR2 file.
    ///
    /// Aligned complete slices are checksummed immediately without retaining
    /// the slice payload. Only incomplete boundary slices are buffered. The
    /// returned [`FeedOutcome`] reports newly settled [`SliceEvidence`] and
    /// precise [`SettleRead`] ranges needed to complete or disambiguate a slice.
    pub fn feed_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> FeedOutcome {
        let par2_set = match &self.par2_set {
            Some(set) => Arc::clone(set),
            None => return FeedOutcome::new(FeedDisposition::MetadataPending),
        };

        let Some(desc) = par2_set.file_description(file_id) else {
            return FeedOutcome::new(FeedDisposition::UnknownFile);
        };
        let Some(checksums) = par2_set.file_checksums(file_id) else {
            return FeedOutcome::new(FeedDisposition::MetadataPending);
        };
        if par2_set.slice_size == 0 {
            return FeedOutcome::new(FeedDisposition::OutOfRange);
        }

        let range_end = match offset.checked_add(data.len() as u64) {
            Some(end) if offset <= desc.length && end <= desc.length => end,
            _ => return FeedOutcome::new(FeedDisposition::OutOfRange),
        };
        if data.is_empty() {
            return FeedOutcome::new(FeedDisposition::Duplicate);
        }

        // Ensure file state exists. This also supports non-recovery files for
        // callers that choose to verify their available IFSC metadata.
        if !self.file_states.contains_key(file_id) {
            self.file_states.insert(
                *file_id,
                FileVerificationState::new(desc.length, par2_set.slice_size),
            );
        }

        let first_slice = usize::try_from(offset / par2_set.slice_size)
            .map_err(|_| ())
            .ok();
        let last_slice = usize::try_from((range_end - 1) / par2_set.slice_size)
            .map_err(|_| ())
            .ok();
        let (Some(first_slice), Some(last_slice)) = (first_slice, last_slice) else {
            return FeedOutcome::new(FeedDisposition::OutOfRange);
        };

        let state = self
            .file_states
            .get_mut(file_id)
            .expect("state inserted above");
        let mut outcome = FeedOutcome::new(FeedDisposition::Duplicate);
        let mut saw_verified = false;
        let mut saw_buffered = false;
        let mut saw_budget_exhausted = false;
        let mut saw_conflict = false;
        let mut saw_needs_settle_read = false;

        for slice_index in first_slice..=last_slice {
            let Some(slice_offset) = state.slice_offset(slice_index) else {
                saw_needs_settle_read = true;
                continue;
            };
            let Some(slice_len) = state.slice_len(slice_index) else {
                saw_needs_settle_read = true;
                continue;
            };
            let Some(expected) = checksums.get(slice_index) else {
                return FeedOutcome::new(FeedDisposition::MetadataPending);
            };

            let piece_start = offset.max(slice_offset);
            let piece_end = range_end.min(slice_offset + slice_len);
            let piece = &data[(piece_start - offset) as usize..(piece_end - offset) as usize];
            let whole_slice = piece_start == slice_offset && piece.len() as u64 == slice_len;

            match Self::feed_slice_range(
                state,
                &self.memory_budget,
                par2_set.recovery_set_id,
                *file_id,
                slice_index,
                piece_start - slice_offset,
                piece,
                whole_slice,
                expected,
            ) {
                SliceFeed::Verified(evidence) => {
                    saw_verified = true;
                    outcome.evidence.push(evidence);
                }
                SliceFeed::Buffered(reads) => {
                    saw_buffered = true;
                    Self::append_settle_reads(&mut outcome.settle_reads, reads);
                }
                SliceFeed::Duplicate(reads) => {
                    Self::append_settle_reads(&mut outcome.settle_reads, reads);
                }
                SliceFeed::BudgetExhausted(read) => {
                    saw_budget_exhausted = true;
                    Self::append_settle_reads(&mut outcome.settle_reads, [read]);
                }
                SliceFeed::Conflict(read) => {
                    saw_conflict = true;
                    Self::append_settle_reads(&mut outcome.settle_reads, [read]);
                }
                SliceFeed::NeedsSettleRead(read) => {
                    saw_needs_settle_read = true;
                    Self::append_settle_reads(&mut outcome.settle_reads, [read]);
                }
            }
        }

        outcome.disposition = if saw_conflict {
            FeedDisposition::ConflictingOverlap
        } else if saw_budget_exhausted {
            FeedDisposition::BudgetExhausted
        } else if saw_needs_settle_read {
            FeedDisposition::NeedsSettleRead
        } else if saw_verified {
            FeedDisposition::Verified
        } else if saw_buffered {
            FeedDisposition::Buffered
        } else {
            FeedDisposition::Duplicate
        };
        outcome
    }

    /// Alias for callers that use `feed_data` terminology for arbitrary ranges.
    pub fn feed_data_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> FeedOutcome {
        self.feed_range(file_id, offset, data)
    }

    fn append_settle_reads(
        target: &mut Vec<SettleRead>,
        reads: impl IntoIterator<Item = SettleRead>,
    ) {
        for read in reads {
            if !target.contains(&read) {
                target.push(read);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn feed_slice_range(
        state: &mut FileVerificationState,
        memory_budget: &VerificationMemoryBudget,
        recovery_set_id: RecoverySetId,
        file_id: FileId,
        slice_index: usize,
        slice_data_offset: u64,
        data: &[u8],
        whole_slice: bool,
        expected: &SliceChecksum,
    ) -> SliceFeed {
        let full_read = state.full_slice_read(file_id, slice_index);

        if let Some(fingerprint) = state.fingerprints[slice_index] {
            if whole_slice {
                return if fingerprint == SliceFingerprint::from_data(data, state.slice_size) {
                    SliceFeed::Duplicate(Vec::new())
                } else {
                    SliceFeed::Conflict(full_read.clone())
                };
            }
            return SliceFeed::NeedsSettleRead(full_read.clone());
        }
        if state.verified_slices[slice_index].is_some() {
            // `verify_from_slice_crcs` can settle a CRC-only slice. A partial
            // byte retry cannot prove it is the same data because MD5 was not
            // retained, so request one trusted full-slice read.
            return SliceFeed::NeedsSettleRead(full_read.clone());
        }

        let slice_len = state.slice_len(slice_index).unwrap_or(0);
        if whole_slice {
            let partial_bytes = match state.partial_slices.get(&slice_index) {
                Some(partial) if !partial.matches(0, data) => {
                    state.discard_partial(slice_index, memory_budget);
                    return SliceFeed::Conflict(full_read.clone());
                }
                Some(partial) => partial.buffered_bytes as u64,
                None => 0,
            };
            if partial_bytes != 0 {
                state.discard_partial(slice_index, memory_budget);
            }

            let fingerprint = SliceFingerprint::from_data(data, state.slice_size);
            let valid = fingerprint.is_valid_for(expected);
            state.verified_slices[slice_index] = Some(valid);
            state.fingerprints[slice_index] = Some(fingerprint);
            state.bytes_received += slice_len.saturating_sub(partial_bytes);
            return SliceFeed::Verified(state.evidence(
                recovery_set_id,
                file_id,
                slice_index,
                valid,
            ));
        }

        if state
            .partial_slices
            .get(&slice_index)
            .is_some_and(|partial| !partial.matches(slice_data_offset, data))
        {
            state.discard_partial(slice_index, memory_budget);
            return SliceFeed::Conflict(full_read.clone());
        }

        let had_partial = state.partial_slices.contains_key(&slice_index);
        let inserted = state
            .partial_slices
            .entry(slice_index)
            .or_insert_with(|| PartialSlice::new(slice_len))
            .insert(slice_data_offset, data, memory_budget);
        let Some(inserted) = inserted else {
            if !had_partial {
                state.partial_slices.remove(&slice_index);
            }
            return SliceFeed::BudgetExhausted(full_read.clone());
        };
        state.bytes_received += inserted as u64;

        let complete = state
            .partial_slices
            .get(&slice_index)
            .is_some_and(PartialSlice::is_complete);
        if complete {
            let partial = state
                .partial_slices
                .remove(&slice_index)
                .expect("complete partial slice exists");
            let fingerprint = partial
                .fingerprint(state.slice_size)
                .expect("complete partial slice covers every byte");
            memory_budget.release(partial.reserved_bytes);
            let valid = fingerprint.is_valid_for(expected);
            state.verified_slices[slice_index] = Some(valid);
            state.fingerprints[slice_index] = Some(fingerprint);
            return SliceFeed::Verified(state.evidence(
                recovery_set_id,
                file_id,
                slice_index,
                valid,
            ));
        }

        let reads = state
            .partial_slices
            .get(&slice_index)
            .expect("partial slice remains when incomplete")
            .settle_reads(
                file_id,
                slice_index,
                state.slice_offset(slice_index).unwrap_or(state.file_length),
            );
        if inserted == 0 {
            SliceFeed::Duplicate(reads)
        } else {
            SliceFeed::Buffered(reads)
        }
    }

    /// Query the current status of a specific file.
    pub fn file_status(&self, file_id: &FileId) -> Option<FileStatus> {
        let state = self.file_states.get(file_id)?;

        if state.total_slices() == 0 {
            return Some(FileStatus::Complete);
        }

        // If all slices are verified as valid, the file is complete.
        if state.verified_count() == state.total_slices() {
            return Some(FileStatus::Complete);
        }

        let damaged = state.damaged_count() as u32;
        if damaged > 0 {
            return Some(FileStatus::Damaged(damaged));
        }

        // Still pending -- report as complete only if everything known is valid.
        if state.pending_count() == state.total_slices() {
            // No data received yet.
            return Some(FileStatus::Missing);
        }

        // Partially verified, no damage found yet.
        // Report damaged with 0 to indicate "in progress" -- but the pending
        // slices could still be bad. Return Missing for files with no verified
        // slices, or Damaged(0) for partially verified.
        if state.bytes_received == 0 {
            Some(FileStatus::Missing)
        } else {
            Some(FileStatus::Damaged(0))
        }
    }

    /// Estimate repairability given the current state.
    ///
    /// This accounts for both verified-damaged slices and pending (unverified)
    /// slices, treating pending slices optimistically (assuming they will pass).
    pub fn repairability(&self) -> Repairability {
        let par2_set = match &self.par2_set {
            Some(set) => set,
            None => return Repairability::NotNeeded,
        };

        let mut total_damaged: u32 = 0;
        let mut total_missing: u32 = 0;

        for file_id in &par2_set.recovery_file_ids {
            if let Some(state) = self.file_states.get(file_id) {
                total_damaged += state.damaged_count() as u32;
                // Files that haven't received any data are considered missing.
                if state.bytes_received == 0 {
                    total_missing += state.total_slices() as u32;
                }
            } else {
                // File state not initialized yet; treat as missing.
                if let Some(desc) = par2_set.file_description(file_id) {
                    total_missing += par2_set.slice_count_for_file(desc.length);
                }
            }
        }

        let blocks_needed = total_damaged + total_missing;
        let blocks_available = par2_set.recovery_block_count();

        if blocks_needed == 0 {
            Repairability::NotNeeded
        } else if blocks_needed <= blocks_available {
            Repairability::Repairable {
                blocks_needed,
                blocks_available,
            }
        } else {
            Repairability::Insufficient {
                blocks_needed,
                blocks_available,
                deficit: blocks_needed - blocks_available,
            }
        }
    }

    /// Check if all files have been verified successfully.
    pub fn is_complete(&self) -> bool {
        let par2_set = match &self.par2_set {
            Some(set) => set,
            None => return false,
        };

        for file_id in &par2_set.recovery_file_ids {
            match self.file_states.get(file_id) {
                Some(state) => {
                    if state.verified_count() != state.total_slices() {
                        return false;
                    }
                }
                None => return false,
            }
        }

        true
    }

    /// Produce a full [`VerificationResult`] from the current session state.
    ///
    /// This can be passed to [`plan_repair`](crate::repair::plan_repair) if
    /// repair is needed. Returns `None` if PAR2 metadata has not been loaded.
    pub fn verification_result(&self) -> Option<VerificationResult> {
        let par2_set = self.par2_set.as_ref()?;

        let mut files = Vec::new();
        let mut total_missing_blocks = 0u32;

        for file_id in &par2_set.recovery_file_ids {
            let desc = match par2_set.file_description(file_id) {
                Some(d) => d,
                None => continue,
            };

            let state = match self.file_states.get(file_id) {
                Some(s) => s,
                None => {
                    // No state at all: file is missing.
                    let slice_count = par2_set.slice_count_for_file(desc.length);
                    total_missing_blocks += slice_count;
                    files.push(FileVerification {
                        file_id: *file_id,
                        filename: desc.filename.clone(),
                        status: FileStatus::Missing,
                        valid_slices: vec![false; slice_count as usize],
                        missing_slice_count: slice_count,
                    });
                    continue;
                }
            };

            let valid_slices: Vec<bool> = state
                .verified_slices
                .iter()
                .map(|v| v.unwrap_or(false))
                .collect();
            let missing_count = valid_slices.iter().filter(|&&v| !v).count() as u32;
            total_missing_blocks += missing_count;

            let status = if missing_count == 0 {
                FileStatus::Complete
            } else if state.bytes_received == 0 {
                FileStatus::Missing
            } else {
                FileStatus::Damaged(missing_count)
            };

            files.push(FileVerification {
                file_id: *file_id,
                filename: desc.filename.clone(),
                status,
                valid_slices,
                missing_slice_count: missing_count,
            });
        }

        let recovery_blocks_available = par2_set.recovery_block_count();
        let repairable = if total_missing_blocks == 0 {
            Repairability::NotNeeded
        } else if total_missing_blocks <= recovery_blocks_available {
            Repairability::Repairable {
                blocks_needed: total_missing_blocks,
                blocks_available: recovery_blocks_available,
            }
        } else {
            Repairability::Insufficient {
                blocks_needed: total_missing_blocks,
                blocks_available: recovery_blocks_available,
                deficit: total_missing_blocks - recovery_blocks_available,
            }
        };

        Some(VerificationResult {
            files,
            recovery_blocks_available,
            total_missing_blocks,
            repairable,
        })
    }

    /// Verify a file's slices using pre-computed CRC32 values from download.
    ///
    /// Each entry in `slice_crcs` must be the CRC32 of the (possibly zero-padded)
    /// slice data. This is a CRC-only check (no MD5); it avoids re-reading files
    /// from disk when the download layer already computed per-slice CRCs.
    ///
    /// Returns per-slice validity, or `None` if PAR2 metadata isn't loaded or
    /// the file is unknown.
    pub fn verify_from_slice_crcs(
        &mut self,
        file_id: &FileId,
        slice_crcs: &[u32],
    ) -> Option<Vec<bool>> {
        let par2_set = self.par2_set.as_ref()?;
        let checksums = par2_set.file_checksums(file_id)?;

        // Ensure file state exists.
        if !self.file_states.contains_key(file_id) {
            let desc = par2_set.file_description(file_id)?;
            self.file_states.insert(
                *file_id,
                FileVerificationState::new(desc.length, par2_set.slice_size),
            );
        }

        let state = self.file_states.get_mut(file_id)?;
        let mut results = Vec::with_capacity(checksums.len());
        for (i, expected) in checksums.iter().enumerate() {
            let valid = slice_crcs
                .get(i)
                .map(|&crc| crc == expected.crc32)
                .unwrap_or(false);
            // Update the verified_slices state (only if not already verified).
            if state.verified_slices[i].is_none() {
                state.discard_partial(i, &self.memory_budget);
                state.verified_slices[i] = Some(valid);
                if valid {
                    // Mark bytes as received so file isn't treated as "missing".
                    state.bytes_received = state.bytes_received.max(1);
                }
            }
            results.push(valid);
        }

        Some(results)
    }

    /// Return every settled slice verdict held by this session.
    ///
    /// The result is deterministic by file ID and slice index, and contains
    /// only PAR2 coordinates plus validity so it can be handed to a later
    /// repair stage without coupling it to filesystem paths.
    pub fn slice_evidence(&self) -> Vec<SliceEvidence> {
        let Some(recovery_set_id) = self.par2_set.as_ref().map(|set| set.recovery_set_id) else {
            return Vec::new();
        };
        let mut evidence = self
            .file_states
            .iter()
            .flat_map(|(file_id, state)| {
                state
                    .verified_slices
                    .iter()
                    .enumerate()
                    .filter_map(|(slice_index, valid)| {
                        valid.map(|valid| {
                            state.evidence(recovery_set_id, *file_id, slice_index, valid)
                        })
                    })
            })
            .collect::<Vec<_>>();
        evidence.sort_unstable_by(|left, right| {
            left.file_id()
                .as_bytes()
                .cmp(right.file_id().as_bytes())
                .then_with(|| left.slice_index().cmp(&right.slice_index()))
        });
        evidence
    }

    /// Get a reference to the underlying PAR2 file set, if loaded.
    pub fn par2_set(&self) -> Option<&Arc<Par2FileSet>> {
        self.par2_set.as_ref()
    }
}

impl Default for VerificationSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VerificationSession {
    fn drop(&mut self) {
        for state in self.file_states.values() {
            for partial in state.partial_slices.values() {
                self.memory_budget.release(partial.reserved_bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::packet::header;
    use crate::par2_set::RecoverySlice;
    use crate::types::SliceChecksum;
    use bytes::Bytes;
    use md5::{Digest, Md5};

    /// Helper to build a complete valid packet (header + body).
    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (header::HEADER_SIZE + body.len()) as u64;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);
        let packet_hash: [u8; 16] = Md5::digest(&hash_input).into();

        let mut data = Vec::new();
        data.extend_from_slice(header::MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    /// Build PAR2 packets for a single file. Returns (packets_bytes, file_id, rsid).
    fn build_par2_packets(file_data: &[u8], slice_size: u64) -> (Vec<u8>, FileId, [u8; 16]) {
        let file_length = file_data.len() as u64;
        let hash_full = checksum::md5(file_data);
        let hash_16k_data = &file_data[..file_data.len().min(16384)];
        let hash_16k = checksum::md5(hash_16k_data);

        let filename = b"testfile.dat";
        let mut id_input = Vec::new();
        id_input.extend_from_slice(&hash_16k);
        id_input.extend_from_slice(&file_length.to_le_bytes());
        id_input.extend_from_slice(filename);
        let file_id_bytes: [u8; 16] = Md5::digest(&id_input).into();
        let file_id = FileId::from_bytes(file_id_bytes);

        let num_slices = if file_length == 0 {
            0
        } else {
            file_length.div_ceil(slice_size) as usize
        };

        let mut checksums = Vec::new();
        for i in 0..num_slices {
            let offset = i as u64 * slice_size;
            let end = ((offset + slice_size) as usize).min(file_data.len());
            let slice_data = &file_data[offset as usize..end];
            let mut state = SliceChecksumState::new();
            state.update(slice_data);
            let pad_to = if (slice_data.len() as u64) < slice_size {
                Some(slice_size)
            } else {
                None
            };
            let (crc, md5) = state.finalize(pad_to);
            checksums.push(SliceChecksum { crc32: crc, md5 });
        }

        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&1u32.to_le_bytes());
        main_body.extend_from_slice(&file_id_bytes);
        let rsid: [u8; 16] = Md5::digest(&main_body).into();

        let mut fd_body = Vec::new();
        fd_body.extend_from_slice(&file_id_bytes);
        fd_body.extend_from_slice(&hash_full);
        fd_body.extend_from_slice(&hash_16k);
        fd_body.extend_from_slice(&file_length.to_le_bytes());
        fd_body.extend_from_slice(filename);
        while fd_body.len() % 4 != 0 {
            fd_body.push(0);
        }

        let mut ifsc_body = Vec::new();
        ifsc_body.extend_from_slice(&file_id_bytes);
        for cs in &checksums {
            ifsc_body.extend_from_slice(&cs.md5);
            ifsc_body.extend_from_slice(&cs.crc32.to_le_bytes());
        }

        let mut stream = Vec::new();
        stream.extend_from_slice(&make_full_packet(header::TYPE_MAIN, &main_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_FILE_DESC, &fd_body, rsid));
        stream.extend_from_slice(&make_full_packet(header::TYPE_IFSC, &ifsc_body, rsid));

        (stream, file_id, rsid)
    }

    fn parse_packets(data: &[u8]) -> Vec<Packet> {
        crate::packet::scan_packets(data, 0)
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    }

    #[test]
    fn session_feed_correct_data_all_pass() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();

        // Add PAR2 metadata first.
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);
        assert!(session.par2_set().is_some());

        // Feed data slice by slice.
        session.feed_data(&file_id, 0, &file_data[0..1024]);
        session.feed_data(&file_id, 1024, &file_data[1024..2048]);

        // All slices should pass.
        assert!(session.is_complete());
        assert!(matches!(
            session.file_status(&file_id),
            Some(FileStatus::Complete)
        ));
        assert!(matches!(session.repairability(), Repairability::NotNeeded));

        // verification_result should show all valid.
        let result = session.verification_result().unwrap();
        assert_eq!(result.total_missing_blocks, 0);
        assert!(result.files[0].valid_slices.iter().all(|&v| v));
    }

    #[test]
    fn session_detects_corrupted_slice() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        // Feed correct first slice.
        session.feed_data(&file_id, 0, &file_data[0..1024]);

        // Feed corrupted second slice.
        let mut corrupted = file_data[1024..2048].to_vec();
        corrupted[0] ^= 0xFF;
        session.feed_data(&file_id, 1024, &corrupted);

        // Should not be complete.
        assert!(!session.is_complete());

        // File should be damaged.
        assert!(matches!(
            session.file_status(&file_id),
            Some(FileStatus::Damaged(1))
        ));

        let result = session.verification_result().unwrap();
        assert_eq!(result.total_missing_blocks, 1);
        assert!(result.files[0].valid_slices[0]); // first slice valid
        assert!(!result.files[0].valid_slices[1]); // second slice damaged
    }

    #[test]
    fn session_handles_data_before_metadata() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();

        // Feed data before PAR2 metadata -- should be silently ignored.
        session.feed_data(&file_id, 0, &file_data[0..1024]);
        session.feed_data(&file_id, 1024, &file_data[1024..2048]);

        // No PAR2 set yet.
        assert!(session.par2_set().is_none());
        assert!(!session.is_complete());
        assert!(session.verification_result().is_none());

        // Now add metadata.
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        // Data was ignored, so nothing is verified yet.
        assert!(!session.is_complete());

        // Re-feed data after metadata.
        session.feed_data(&file_id, 0, &file_data[0..1024]);
        session.feed_data(&file_id, 1024, &file_data[1024..2048]);

        assert!(session.is_complete());
    }

    #[test]
    fn session_repairability_mid_stream() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        // Before any data: all 4 slices are "missing" (no bytes received).
        match session.repairability() {
            Repairability::Insufficient {
                blocks_needed: 4, ..
            } => {}
            other => panic!("expected Insufficient with 4 blocks needed, got {other:?}"),
        }

        // Feed first slice correctly.
        session.feed_data(&file_id, 0, &file_data[0..1024]);

        // Now 3 slices haven't received data = missing.
        // But the repairability only counts files with 0 bytes as "missing".
        // After feeding 1 slice, bytes_received > 0, so no longer "missing" --
        // only actually damaged slices count.

        // Feed corrupted second slice.
        let mut corrupted = file_data[1024..2048].to_vec();
        corrupted[0] ^= 0xFF;
        session.feed_data(&file_id, 1024, &corrupted);

        // 1 damaged, file has data so not counted as fully missing.
        match session.repairability() {
            Repairability::Insufficient {
                blocks_needed: 1,
                blocks_available: 0,
                ..
            } => {}
            other => panic!("expected Insufficient with 1 block needed, got {other:?}"),
        }
    }

    #[test]
    fn session_integration_with_repair_plan() {
        use crate::gf;
        use crate::repair::plan_repair;

        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        // Add recovery blocks to the par2_set.
        {
            let set = Arc::make_mut(session.par2_set.as_mut().unwrap());
            let num_slices = 4; // 256 / 64
            let constants = gf::input_slice_constants(num_slices);
            let ss = slice_size as usize;
            let word_count = ss / 2;

            let mut padded = file_data.clone();
            padded.resize(num_slices * ss, 0);

            for r in 0..2u32 {
                let mut recovery = vec![0u8; ss];
                for (i, &constant) in constants.iter().enumerate() {
                    let factor = gf::pow(constant, r);
                    for w in 0..word_count {
                        let input_word = u16::from_le_bytes([
                            padded[i * ss + w * 2],
                            padded[i * ss + w * 2 + 1],
                        ]);
                        let contribution = gf::mul(input_word, factor);
                        let rec_word = u16::from_le_bytes([recovery[w * 2], recovery[w * 2 + 1]]);
                        let new_val = gf::add(rec_word, contribution);
                        let bytes = new_val.to_le_bytes();
                        recovery[w * 2] = bytes[0];
                        recovery[w * 2 + 1] = bytes[1];
                    }
                }
                set.recovery_slices.insert(
                    r,
                    RecoverySlice {
                        exponent: r,
                        data: Bytes::from(recovery).into(),
                    },
                );
            }
        }

        // Feed correct slices 0, 1, 3; corrupt slice 2.
        session.feed_data(&file_id, 0, &file_data[0..64]);
        session.feed_data(&file_id, 64, &file_data[64..128]);

        let mut corrupted = file_data[128..192].to_vec();
        corrupted[0] ^= 0xFF;
        session.feed_data(&file_id, 128, &corrupted);

        session.feed_data(&file_id, 192, &file_data[192..256]);

        // Get verification result and pass to plan_repair.
        let result = session.verification_result().unwrap();
        assert_eq!(result.total_missing_blocks, 1);

        let plan = plan_repair(session.par2_set().unwrap(), &result).unwrap();
        assert_eq!(plan.missing_slices.len(), 1);
        assert_eq!(plan.missing_slices[0], (file_id, 2));
    }

    #[test]
    fn session_partial_last_slice() {
        let slice_size = 1024u64;
        // File is 1500 bytes -> 2 slices, last is 476 bytes.
        let file_data: Vec<u8> = (0..1500u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        session.feed_data(&file_id, 0, &file_data[0..1024]);
        session.feed_data(&file_id, 1024, &file_data[1024..1500]);

        assert!(session.is_complete());
        let result = session.verification_result().unwrap();
        assert_eq!(result.total_missing_blocks, 0);
    }

    #[test]
    fn session_verify_from_slice_crcs() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        // Compute per-slice CRC32s (these would come from yEnc decode in practice).
        let crc0 = checksum::crc32(&file_data[0..1024]);
        let crc1 = checksum::crc32(&file_data[1024..2048]);

        let result = session
            .verify_from_slice_crcs(&file_id, &[crc0, crc1])
            .unwrap();
        assert_eq!(result, vec![true, true]);

        // Session should now show file as complete.
        assert!(session.is_complete());
        assert!(matches!(
            session.file_status(&file_id),
            Some(FileStatus::Complete)
        ));
        assert!(
            session
                .slice_evidence()
                .iter()
                .all(|evidence| evidence.strength() == SliceEvidenceStrength::Crc32Only)
        );
    }

    #[test]
    fn session_verify_from_slice_crcs_partial_damage() {
        let slice_size = 1024u64;
        let file_data: Vec<u8> = (0..2048u32).map(|i| (i % 256) as u8).collect();
        let (par2_bytes, file_id, _rsid) = build_par2_packets(&file_data, slice_size);

        let mut session = VerificationSession::new();
        let packets = parse_packets(&par2_bytes);
        session.add_par2_data(&packets);

        let crc0 = checksum::crc32(&file_data[0..1024]);
        let wrong_crc = 0xDEADBEEF;

        let result = session
            .verify_from_slice_crcs(&file_id, &[crc0, wrong_crc])
            .unwrap();
        assert_eq!(result, vec![true, false]);

        assert!(!session.is_complete());
        assert!(matches!(
            session.file_status(&file_id),
            Some(FileStatus::Damaged(1))
        ));
    }

    #[test]
    fn session_empty_before_metadata() {
        let session = VerificationSession::new();
        assert!(!session.is_complete());
        assert!(session.verification_result().is_none());
        assert!(matches!(session.repairability(), Repairability::NotNeeded));
    }

    #[test]
    fn feed_range_settles_out_of_order_boundaries_without_buffering_full_slices() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..24u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let mut session = VerificationSession::new();
        session.add_par2_data(&parse_packets(&par2_bytes));

        // Feed the tail of slice 1 before its prefix, then settle it. The
        // buffered range reports the exact three-byte prefix still needed.
        let pending = session.feed_range(&file_id, 11, &file_data[11..16]);
        assert_eq!(pending.disposition(), FeedDisposition::Buffered);
        assert_eq!(pending.settle_reads().len(), 1);
        assert_eq!(pending.settle_reads()[0].offset(), 8);
        assert_eq!(pending.settle_reads()[0].length(), 3);

        let settled = session.feed_range(&file_id, 8, &file_data[8..11]);
        assert_eq!(settled.disposition(), FeedDisposition::Verified);
        assert_eq!(settled.evidence().len(), 1);
        assert_eq!(settled.evidence()[0].slice_index(), 1);
        assert!(settled.evidence()[0].is_valid());

        // The two boundary pieces of slice 0 arrive in the opposite order.
        assert_eq!(
            session
                .feed_range(&file_id, 3, &file_data[3..8])
                .disposition(),
            FeedDisposition::Buffered
        );
        let settled = session.feed_range(&file_id, 0, &file_data[..3]);
        assert_eq!(settled.disposition(), FeedDisposition::Verified);
        assert_eq!(settled.evidence()[0].slice_index(), 0);

        // Slice 2 is aligned and complete, so it is immediately hashed rather
        // than retained in the boundary buffer.
        let direct = session.feed_range(&file_id, 16, &file_data[16..24]);
        assert_eq!(direct.disposition(), FeedDisposition::Verified);
        assert_eq!(direct.evidence()[0].slice_index(), 2);
        assert!(session.is_complete());
    }

    #[test]
    fn feed_range_distinguishes_identical_and_conflicting_overlaps() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..8u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let reserved = 4 + PARTIAL_RANGE_ACCOUNTING_BYTES;
        let budget = VerificationMemoryBudget::new(reserved);
        let mut session = VerificationSession::with_memory_budget(budget.clone());
        session.add_par2_data(&parse_packets(&par2_bytes));

        assert_eq!(
            session
                .feed_range(&file_id, 0, &file_data[..4])
                .disposition(),
            FeedDisposition::Buffered
        );
        assert_eq!(budget.buffered_bytes(), reserved);

        // Repeating data already in the sparse buffer neither consumes budget
        // again nor creates a competing slice result.
        let duplicate = session.feed_range(&file_id, 2, &file_data[2..4]);
        assert_eq!(duplicate.disposition(), FeedDisposition::Duplicate);
        assert_eq!(budget.buffered_bytes(), reserved);

        let mut conflicting = file_data[3..5].to_vec();
        conflicting[0] ^= 0xFF;
        let conflict = session.feed_range(&file_id, 3, &conflicting);
        assert_eq!(conflict.disposition(), FeedDisposition::ConflictingOverlap);
        assert_eq!(budget.buffered_bytes(), 0);
        assert_eq!(conflict.settle_reads().len(), 1);
        assert_eq!(conflict.settle_reads()[0].offset(), 0);
        assert_eq!(conflict.settle_reads()[0].length(), slice_size);

        let settled = session.feed_range(&file_id, 0, &file_data);
        assert_eq!(settled.disposition(), FeedDisposition::Verified);
        assert!(settled.evidence()[0].is_valid());
    }

    #[test]
    fn feed_range_reports_metadata_and_out_of_range_input() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..8u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let mut session = VerificationSession::new();

        assert_eq!(
            session.feed_range(&file_id, 0, &file_data).disposition(),
            FeedDisposition::MetadataPending
        );

        session.add_par2_data(&parse_packets(&par2_bytes));
        assert_eq!(
            session
                .feed_range(&file_id, file_data.len() as u64, &[1])
                .disposition(),
            FeedDisposition::OutOfRange
        );
        assert_eq!(
            session.feed_range(&file_id, u64::MAX, &[1]).disposition(),
            FeedDisposition::OutOfRange
        );
    }

    #[test]
    fn feed_range_pads_a_partial_last_slice_after_arbitrary_ranges() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..13u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let mut session = VerificationSession::new();
        session.add_par2_data(&parse_packets(&par2_bytes));

        assert_eq!(
            session
                .feed_range(&file_id, 0, &file_data[..8])
                .disposition(),
            FeedDisposition::Verified
        );
        assert_eq!(
            session
                .feed_range(&file_id, 10, &file_data[10..])
                .disposition(),
            FeedDisposition::Buffered
        );
        let last = session.feed_range(&file_id, 8, &file_data[8..10]);
        assert_eq!(last.disposition(), FeedDisposition::Verified);
        assert_eq!(last.evidence()[0].slice_index(), 1);
        assert!(last.evidence()[0].is_valid());
        assert!(session.is_complete());
    }

    #[test]
    fn shared_boundary_budget_is_released_on_settlement_and_drop() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..8u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let packets = parse_packets(&par2_bytes);
        let reserved = 4 + PARTIAL_RANGE_ACCOUNTING_BYTES;
        let budget = VerificationMemoryBudget::new(reserved);
        let options = VerificationSessionOptions::new().with_memory_budget(budget.clone());
        let mut first = VerificationSession::with_options(options.clone());
        let mut second = VerificationSession::with_options(options);
        first.add_par2_data(&packets);
        second.add_par2_data(&packets);

        assert_eq!(
            first.feed_range(&file_id, 0, &file_data[..4]).disposition(),
            FeedDisposition::Buffered
        );
        assert_eq!(budget.buffered_bytes(), reserved);
        assert_eq!(
            second
                .feed_range(&file_id, 0, &file_data[..4])
                .disposition(),
            FeedDisposition::BudgetExhausted
        );

        // An aligned full retry settles first's partial slice directly and
        // releases its reservation before hashing.
        assert_eq!(
            first.feed_range(&file_id, 0, &file_data).disposition(),
            FeedDisposition::Verified
        );
        assert_eq!(budget.buffered_bytes(), 0);
        assert_eq!(
            second
                .feed_range(&file_id, 0, &file_data[..4])
                .disposition(),
            FeedDisposition::Buffered
        );
        assert_eq!(budget.buffered_bytes(), reserved);

        drop(second);
        assert_eq!(budget.buffered_bytes(), 0);
    }

    #[test]
    fn fragmented_range_metadata_counts_toward_shared_budget() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..8u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let budget = VerificationMemoryBudget::new(2 + PARTIAL_RANGE_ACCOUNTING_BYTES * 2 - 1);
        let mut session = VerificationSession::with_memory_budget(budget.clone());
        session.add_par2_data(&parse_packets(&par2_bytes));

        assert_eq!(
            session
                .feed_range(&file_id, 0, &file_data[..1])
                .disposition(),
            FeedDisposition::Buffered
        );
        assert_eq!(
            session
                .feed_range(&file_id, 2, &file_data[2..3])
                .disposition(),
            FeedDisposition::BudgetExhausted
        );
        assert_eq!(budget.buffered_bytes(), 1 + PARTIAL_RANGE_ACCOUNTING_BYTES);
    }

    #[test]
    fn add_par2_data_merges_new_packets_without_rebuilding_an_existing_set() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..8u8).collect();
        let (par2_bytes, _file_id, _) = build_par2_packets(&file_data, slice_size);
        let packets = parse_packets(&par2_bytes);
        let mut session = VerificationSession::new();
        session.add_par2_data(&packets);

        let before = Arc::as_ptr(session.par2_set.as_ref().unwrap());
        // Re-merging an already represented main packet must keep the existing
        // set allocation instead of rebuilding every accumulated packet.
        session.add_par2_data(&packets[..1]);
        assert_eq!(before, Arc::as_ptr(session.par2_set.as_ref().unwrap()));
    }

    #[test]
    fn in_stream_proof_refuses_every_incomplete_attestation() {
        let proof = InStreamCrc32Proof::try_new(4096, true, true, true)
            .expect("a complete attestation should prove");
        assert_eq!(proof.covered_length(), 4096);

        assert!(matches!(
            InStreamCrc32Proof::try_new(0, true, true, true),
            Err(InStreamCrc32ProofError::EmptyCoverage)
        ));
        assert!(matches!(
            InStreamCrc32Proof::try_new(4096, false, true, true),
            Err(InStreamCrc32ProofError::IncompleteSliceCoverage)
        ));
        assert!(matches!(
            InStreamCrc32Proof::try_new(4096, true, false, true),
            Err(InStreamCrc32ProofError::UnverifiedSourceBytes)
        ));
        assert!(matches!(
            InStreamCrc32Proof::try_new(4096, true, true, false),
            Err(InStreamCrc32ProofError::NoIndependentCrc32Coverage)
        ));
    }

    /// The attestation is what admits a verdict, not the hash strength: an
    /// in-stream verdict still reports honestly that only a CRC32 was computed.
    #[test]
    fn in_stream_evidence_reports_crc32_only_strength_and_is_admissible() {
        let set_id = RecoverySetId::from_bytes([0x51; 16]);
        let file_id = FileId::from_bytes([0x52; 16]);
        let proof = InStreamCrc32Proof::try_new(1024, true, true, true).unwrap();
        let evidence = SliceEvidence::from_in_stream_crc32(set_id, file_id, 7, true, proof);

        assert_eq!(evidence.recovery_set_id(), set_id);
        assert_eq!(evidence.file_id(), file_id);
        assert_eq!(evidence.slice_index(), 7);
        assert!(evidence.is_valid());
        assert_eq!(evidence.strength(), SliceEvidenceStrength::Crc32Only);
        assert_eq!(evidence.in_stream_proof(), Some(&proof));
        assert!(evidence.may_seed_repair_input());

        // An invalid verdict is equally well formed: contradiction is a result,
        // not a failure to attest.
        let damaged = SliceEvidence::from_in_stream_crc32(set_id, file_id, 7, false, proof);
        assert!(!damaged.is_valid());
        assert!(damaged.may_seed_repair_input());
    }

    /// A CRC32 the session merely compared, with nothing vouching for where its
    /// bytes came from, stays inadmissible — this is the case
    /// `verify_from_slice_crcs` produces.
    #[test]
    fn session_hashed_crc32_only_evidence_carries_no_attestation() {
        let slice_size = 8u64;
        let file_data: Vec<u8> = (0..16u8).collect();
        let (par2_bytes, file_id, _) = build_par2_packets(&file_data, slice_size);
        let mut session = VerificationSession::new();
        session.add_par2_data(&parse_packets(&par2_bytes));

        let crcs: Vec<u32> = file_data
            .chunks(slice_size as usize)
            .map(|slice| {
                let mut state = SliceChecksumState::new();
                state.update(slice);
                state.finalize(Some(slice_size)).0
            })
            .collect();
        session
            .verify_from_slice_crcs(&file_id, &crcs)
            .expect("slice CRCs settle the file");

        let evidence = session.slice_evidence();
        assert!(!evidence.is_empty());
        for entry in evidence {
            assert_eq!(entry.strength(), SliceEvidenceStrength::Crc32Only);
            assert_eq!(entry.in_stream_proof(), None);
            assert!(!entry.may_seed_repair_input());
        }
    }
}
