//! High-level PAR2 verifier/repairer.
//!
//! This module mirrors the repairer shape used by traditional PAR2 tools:
//! load packets, build source blocks, scan job-local files for usable blocks,
//! stage/copy known-good blocks, run RS reconstruction for the missing blocks,
//! and verify repaired output before installing it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt as _;
#[cfg(windows)]
use std::os::windows::fs::FileExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use crate::DiskFileAccess;
use crate::checksum::{self, Crc32Hasher, Md5State};
use crate::error::{Par2Error, Result};
use crate::evidence::FileStatFingerprint;
use crate::md5_simd;
use crate::packet::budget::packet_retained_bytes;
use crate::packet::{
    Packet, PacketScanBudget, PacketScanLimits, PacketSink, scan_packets_from_path_bounded,
};
use crate::par2_set::{FileDescription, PacketAdmission, Par2FileSet, Par2FileSetBuilder};
use crate::path::is_generated_par2_artifact_name;
use crate::repair::{
    DEFAULT_REPAIR_MEMORY_LIMIT, RepairOptions, execute_repair_with_options,
    plan_repair_with_memory_limit, repair_matrix_resource_limit_reason,
};
use crate::types::{
    CancellationToken, FileId, MAX_SLICES_PER_FILE, ProgressCallback, RecoverySetId, SliceChecksum,
};
use crate::verify::{
    self, FileAccess, FileStatus, FileVerification, Repairability, VerificationResult,
};
use rayon::prelude::*;
use thiserror::Error;
use tracing::{debug, warn};

const ZERO_PAD_CHUNK: [u8; 8192] = [0u8; 8192];
const SCANNER_MD5_BATCH_MEMORY_BYTES: usize = 4 * 1024 * 1024;
const SCANNER_IO_TARGET_BYTES: usize = 4 * 1024 * 1024;
const SCANNER_MMAP_FALLBACK_SLICE_BYTES: usize = 8 * 1024 * 1024;
const SCANNER_PARALLEL_SEGMENT_TARGET_BYTES: usize = 8 * 1024 * 1024;
const ORDERED_SCAN_SERIAL_ENV: &str = "WEAVER_PAR2_SERIAL_SCAN";
const ORDERED_SCAN_PARALLEL_ENV: &str = "WEAVER_PAR2_PARALLEL_SCAN";
const CANONICAL_COMPLETE_HASH_SKIP_BYTES: u64 = 1024 * 1024;
const ORDERED_SCAN_DEFAULT_SKIP_LEEWAY: u64 = 64;
const SCANNER_SLOW_WARN_STEPS: u64 = 5_000_000;
const SCANNER_SLOW_WARN_DURATION: Duration = Duration::from_secs(5);

/// Read-only view over a whole file, used by the block scanner.
///
/// On native targets this is a real memory map (`memmap2`), preserving the
/// existing zero-copy scan behaviour and performance byte-for-byte. On wasm
/// targets — where `mmap` does not exist under wasip1 — it is a compile-time
/// fallback that reads the file into an owned `Vec<u8>`. Both variants
/// `Deref` to `&[u8]`, so every scan call site is identical across targets.
///
/// The selection is purely `#[cfg(target_family = "wasm")]`, so native
/// codegen is unchanged: the `Vec` variant does not exist in the native build
/// and the mmap variant does not exist in the wasm build.
struct MappedFile {
    #[cfg(not(target_family = "wasm"))]
    inner: memmap2::Mmap,
    #[cfg(target_family = "wasm")]
    inner: Vec<u8>,
}

impl MappedFile {
    /// Map (native) or fully read (wasm) an already-opened file.
    ///
    /// `#[inline]` so the native wrapper collapses into the call site, leaving
    /// the exact `MmapOptions::new().map(&file)` codegen the scanner had before.
    #[cfg(not(target_family = "wasm"))]
    #[inline]
    fn map(file: &File) -> io::Result<Self> {
        // SAFETY: identical to the prior inline `MmapOptions::new().map(&file)`
        // call. The scanner only reads through the returned slice and drops the
        // map before the file is truncated or rewritten.
        let inner = unsafe { memmap2::MmapOptions::new().map(file)? };
        Ok(Self { inner })
    }

    /// wasip1 has no `mmap`; buffer the whole file into memory instead. The
    /// scanner treats the result as an immutable `&[u8]`, so behaviour matches
    /// the native mmap path (only the backing storage differs).
    #[cfg(target_family = "wasm")]
    fn map(file: &File) -> io::Result<Self> {
        let mut inner = Vec::new();
        // Clone the handle so this read does not disturb any cursor the caller
        // holds, mirroring mmap's independence from the file position.
        (&mut &*file).read_to_end(&mut inner)?;
        Ok(Self { inner })
    }
}

impl std::ops::Deref for MappedFile {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Par2RepairStatus {
    Verified,
    RepairPossible,
    Repaired,
    Insufficient,
    ResourceLimited,
}

#[derive(Debug, Clone, Default)]
pub struct PacketDiagnostics {
    pub packets_loaded: u32,
    pub corrupt_packets: u32,
    pub duplicate_packets: u32,
    pub discarded_recovery_blocks: u32,
    pub inconsistent_packets: u32,
    pub conflicting_packets: u32,
}

#[derive(Debug, Clone, Default)]
// A pass learns to report more about itself over time; a new counter should
// not cost every consumer a major version.
#[non_exhaustive]
pub struct ScanDiagnostics {
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    pub blocks_found: u32,
    pub duplicate_blocks: u32,
    pub files_skipped: u32,
    /// Candidates the deferred short-block relocation search re-read. Zero is
    /// the healthy shape: it means the merged scan state already placed every
    /// short block, so nothing had to be hunted for.
    pub short_relocation_candidates_scanned: u32,
    /// Candidates the relocation search declined to re-read because the merged
    /// scan state already accounts for every byte of them.
    pub short_relocation_candidates_skipped: u32,
    /// Rolling windows the relocation search stepped, summed over candidates.
    /// This is the counter that makes an exhaustive relocation search visible;
    /// the ordinary per-file scan counters never see its work.
    pub short_relocation_windows_stepped: u64,
    /// Bytes the relocation search re-read from candidate files.
    pub short_relocation_bytes_read: u64,
    /// Short blocks the relocation search matched and placed. A block whose
    /// held location the search may not displace is skipped before the match
    /// check, so a match counted here is never a futile offer.
    pub short_relocation_blocks_placed: u32,
    /// True when this pass installed a prior pass's scan instead of running
    /// its own. Every counter above then describes that earlier scan, and this
    /// pass read no source bytes to analyse the set.
    pub carried: bool,
    /// Source slices this pass declined to read because evidence had already
    /// located them and the file still matched the stat fingerprint that
    /// evidence was admitted against. Zero unless the host opted in with
    /// [`crate::Par2RepairSessionOptions::trust_seeded_evidence_for_scan`], or
    /// supplied a carry built from its own verification
    /// ([`ScanCarry::from_verification`]), where every located slice is one
    /// this crate never read.
    pub slices_settled_by_evidence: u32,
    /// Source bytes covered by [`Self::slices_settled_by_evidence`], and
    /// therefore neither read nor hashed. [`Self::bytes_scanned`] excludes
    /// them, so an outcome reached without reading its sources in full is
    /// distinguishable from one that was: this counter is non-zero.
    pub bytes_skipped_by_evidence: u64,
}

/// How a pass treated the scan state it was handed.
///
/// A host that wants to know whether a repair cost one scan or two reads three
/// fields together: `carry_applied` says this pass installed carried state
/// instead of scanning, `carry_retried_fresh` says a second pass ran from a
/// real scan anyway, and `carry_consumed_for_repair` says the mutation itself
/// ran on the carried analysis. `carry_applied && carry_consumed_for_repair &&
/// !carry_retried_fresh` is the single-scan shape; the accompanying
/// [`ScanDiagnostics::carried`] flag says the same thing about the scan
/// counters in the same outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CarryDiagnostics {
    pub carry_attempted: bool,
    pub carry_applied: bool,
    pub carry_retried_fresh: bool,
    pub carry_retry_reason: Option<CarryRetryReason>,
    /// The mutating repair ran on the carried analysis, with no second scan.
    /// Set only after every source the repair would read was re-stat'd
    /// immediately before mutation and still matched the fingerprint the
    /// carried scan captured.
    pub carry_consumed_for_repair: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// New reasons are diagnostic detail, not a contract change for matchers.
#[non_exhaustive]
pub enum CarryRetryReason {
    TerminalStatus(Par2RepairStatus),
    RepairRequested,
    PostRepairVerificationFailed,
    /// A source the repair would have read no longer matches the stat
    /// fingerprint the carried scan captured for it — it changed, was
    /// replaced, or is gone. Also reported when validated reads found the
    /// bytes themselves changed under a fingerprint that did not move.
    RepairInputChanged,
    /// A source the repair would have read carries no fingerprint the carry
    /// can be checked against — an access-backed source, whose validity is a
    /// property of the serving handle rather than of the filesystem.
    RepairInputNotFingerprinted,
}

/// Scan state carried from an analyze pass to a later execute pass over the
/// same set, letting later scheduling avoid re-scanning every source file.
/// Application re-stats every file the scan observed (including recording
/// nonexistence) and refuses on visible drift.
///
/// A repair consumes an applied carry only after a second, narrower check
/// immediately before it mutates anything: every source the repair will read
/// must still match the fingerprint the scan captured for it. That repair then
/// reads through the validated path, so a change too subtle for `stat` is
/// still caught on the bytes rather than written into the output.
///
/// Every carried result that does *not* mutate stays speculative and is
/// re-established from a fresh content scan before it is reported.
///
/// A carry never discovers source files that appeared after the analyze
/// pass — callers that allow drop-ins between passes should not supply one.
///
/// A carry can also come from outside this crate:
/// [`ScanCarry::from_verification`] turns a host's own verification pass into
/// one, so a host that already read the payload does not pay for the
/// repairer's scan to read it again. Both origins meet the same gates — the
/// set match, the per-path stat snapshot, the pre-mutation re-stat of every
/// repair input, and the validated read during repair — and nothing
/// downstream can tell them apart.
#[derive(Debug)]
pub struct ScanCarry {
    /// Identity of the set this carry describes. Checked before the carried
    /// files and blocks are installed, because those vectors are swapped in
    /// wholesale: their `first_block` offsets, expected lengths and slice
    /// checksums are only meaningful for the set they were laid out from.
    /// File IDs alone nearly settle this (a `FileId` hashes the file's first
    /// 16 KiB, length and name), but they say nothing about the slice size
    /// that turns a local slice index into a byte offset.
    recovery_set_id: RecoverySetId,
    slice_size: u64,
    set_file_ids: Vec<FileId>,
    snapshot: Vec<CarriedFileStat>,
    files: Vec<SourceFileEntry>,
    blocks: Vec<SourceBlock>,
    diagnostics: ScanDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CarriedFileStat {
    path: PathBuf,
    /// The stat fingerprint when the path existed as a regular file, and
    /// `None` when it did not. Recording nonexistence is load-bearing: a file
    /// that appears between two passes is drift just as much as one that
    /// changes.
    state: Option<FileStatFingerprint>,
}

/// Fingerprint `path` as the carry gate sees it.
///
/// Symlinks are not followed and only regular files fingerprint, so a path
/// that becomes a directory, a symlink, or a device reads as absent rather
/// than as an unchanged file. What the fingerprint covers — length, mtime,
/// and on Unix device and inode — is what `stat` can prove; a same-length
/// rewrite that also restores the original mtime in place is invisible to it,
/// which is why the repair that consumes a carry re-checks the bytes
/// themselves against their slice checksums as it reads them.
fn stat_for_carry(path: &Path) -> CarriedFileStat {
    CarriedFileStat {
        path: path.to_path_buf(),
        state: stat_fingerprint(path),
    }
}

/// Fingerprint `path` as every stat gate in this crate compares it: symlinks
/// are not followed and only regular files fingerprint, so a path that became
/// a directory, a symlink or a device reads as absent rather than unchanged.
///
/// This is a one-line forward to [`FileStatFingerprint::capture_path`], the
/// public capture a host uses when it builds a carry from its own verification
/// ([`ScanCarry::from_verification`]). Having exactly one implementation is the
/// point: a host-captured fingerprint and the gate that re-checks it must
/// agree about what "the same file" means, and two copies of this rule would
/// eventually stop agreeing.
pub(crate) fn stat_fingerprint(path: &Path) -> Option<FileStatFingerprint> {
    FileStatFingerprint::capture_path(path)
}

/// Why a host's verification could not be turned into a [`ScanCarry`].
///
/// Every variant names a disagreement between the attestation and the set it
/// claims to describe, not a property of the files on disk. They are caller
/// bugs — a mismatched set, an attestation that contradicts itself — and are
/// reported rather than absorbed, because a carry built from an attestation
/// this crate could not make sense of is exactly the thing that must never
/// reach a repair.
#[derive(Debug, Error)]
// New ways for an attestation to be inconsistent are detail, not a contract
// change for matchers.
#[non_exhaustive]
pub enum ExternalCarryError {
    /// The verification covers a file the set does not describe.
    #[error("verification names file {file_id}, which is not in the recovery set")]
    UnknownFile { file_id: FileId },
    /// Two entries in the verification claim the same file.
    #[error("verification names file {file_id} more than once")]
    DuplicateFile { file_id: FileId },
    /// A recoverable file in the set has no entry in the verification. A carry
    /// must describe the whole set: what it does not mention would otherwise
    /// be silently taken as unrecoverable.
    #[error("verification does not cover recovery-set file {file_id}")]
    UncoveredFile { file_id: FileId },
    /// The per-slice validity vector is not the length the set's slice layout
    /// requires for that file.
    #[error(
        "file {file_id} has {expected} slices in the set but the verification supplied {supplied}"
    )]
    SliceCountMismatch {
        file_id: FileId,
        expected: usize,
        supplied: usize,
    },
    /// `missing_slice_count` disagrees with the count of invalid slices, or a
    /// `Damaged(n)` status disagrees with either.
    #[error(
        "file {file_id} declares {declared} damaged slices but its validity vector shows {actual}"
    )]
    DamagedCountMismatch {
        file_id: FileId,
        declared: u32,
        actual: u32,
    },
    /// A file claimed `Complete` whose validity vector is not all-valid.
    #[error("file {file_id} is reported complete but its validity vector has invalid slices")]
    IncompleteCompleteFile { file_id: FileId },
    /// A file claimed `Missing` for which a stat fingerprint was supplied, or
    /// whose validity vector claims a valid slice. A missing file has neither.
    #[error("file {file_id} is reported missing but the verification also claims content for it")]
    MissingFileWithContent { file_id: FileId },
    /// A file that is not `Missing` but carries no stat fingerprint. Without
    /// one there is nothing for the carry gate to re-check, so the carry would
    /// be refused at repair time anyway; refusing to build it says so up front.
    #[error("file {file_id} is present in the verification but carries no stat fingerprint")]
    UnfingerprintedFile { file_id: FileId },
    /// A `Renamed` status. A carry built from a host verification describes
    /// files at their canonical paths only (see [`ScanCarry::from_verification`]).
    #[error(
        "file {file_id} is reported at a non-canonical path, which an external carry cannot describe"
    )]
    RelocatedFile { file_id: FileId },
    /// The set could not be laid out into source files and blocks at all.
    #[error("PAR2 set cannot be laid out for a carry: {0}")]
    Set(#[from] Par2Error),
}

impl ScanCarry {
    /// Build a carry from a verification pass this crate did not run.
    ///
    /// # What this is for
    ///
    /// A host that verifies a set itself — a full strict read through
    /// [`crate::verify`] — and then decides to repair would otherwise watch
    /// [`Par2Repairer`] scan and hash the very bytes it just read. Handing the
    /// repairer a carry built from that verification skips the repairer's
    /// scan: the payload is read once, by the host, and the repair proceeds on
    /// what the host found.
    ///
    /// # The trust contract
    ///
    /// The caller attests that it read the bytes it claims: that
    /// `verification`'s per-slice validity is what a real read of each file
    /// produced, and that each `fingerprints` entry was captured
    /// ([`FileStatFingerprint::capture_path`]) at the moment of that read. This
    /// crate cannot check the first claim — that is what "attest" means — and
    /// it does not try to.
    ///
    /// What it does instead is refuse to let a false attestation reach the
    /// output, through the same three gates a natively-produced carry passes:
    ///
    /// 1. **The snapshot gate.** Before the carried analysis is installed,
    ///    every path the carry names is re-stat'd and must still match the
    ///    fingerprint the caller captured. A file that changed after the
    ///    caller read it — including one whose length is unchanged but whose
    ///    mtime moved — refuses the carry, and the pass scans for real.
    /// 2. **The pre-mutation gate.** Immediately before a repair mutates
    ///    anything, every source it will read is re-stat'd again against the
    ///    same fingerprints. Anything else sends the pass back to a full scan
    ///    before a byte is written.
    /// 3. **The validated read.** A repair that consumes a carry — whatever
    ///    produced it — reads every source slice through the validated path,
    ///    checking it against its IFSC checksum on the way into staging and
    ///    into the Reed-Solomon input stream. This is unconditional, and it is
    ///    what covers the one drift `stat` cannot see: a same-length rewrite
    ///    that also restored the original mtime.
    ///
    /// So a false attestation degrades to a rescan (gates 1 and 2) or to a
    /// caught checksum mismatch that retries from a fresh scan before
    /// installing anything (gate 3). It never produces corrupt output. The
    /// cost of being wrong is the scan the carry was meant to save, which is
    /// the honest price.
    ///
    /// # What a carry built this way describes
    ///
    /// Only canonical placement. A host verification reads each file at its
    /// recorded path, so this constructor can only say "this file's slice *i*
    /// is intact, at its canonical offset, at its canonical path". It cannot
    /// describe a file found under a different name, a copy in an extra search
    /// path, or a block relocated within a file — the three things the
    /// repairer's own scanner exists to find. Those are not lost, only
    /// unclaimed: a slice this carry does not locate is a slice the repair
    /// reconstructs from parity, which costs Reed-Solomon work but produces
    /// the same bytes. A [`FileStatus::Renamed`] entry is refused outright
    /// rather than silently downgraded, because a host that found a renamed
    /// file is describing a placement this form has no way to carry.
    ///
    /// Non-recovery files (those the set describes but does not protect) are
    /// neither required in `verification` nor recorded here: they are never
    /// repair inputs and never repair targets.
    ///
    /// # Consistency the constructor does check
    ///
    /// The attestation must agree with itself and with the set: one entry per
    /// recoverable file, validity vectors of the length the set's slice layout
    /// requires, damage counts that match their validity vectors, a
    /// fingerprint for every file not reported [`FileStatus::Missing`] and
    /// none for one that is. These are caller bugs, and each returns an
    /// [`ExternalCarryError`] instead of a carry.
    ///
    /// A slice claimed valid whose bytes would fall past the end of the file
    /// the fingerprint describes is dropped rather than carried: the caller
    /// cannot have read bytes that are not there. Dropping it makes the
    /// repair reconstruct that slice, which is the conservative direction.
    ///
    /// # Cost
    ///
    /// `set` is cloned to lay out the source files and blocks through exactly
    /// the same code path [`Par2Repairer`] uses, so the two layouts cannot
    /// drift. The clone is of the set's metadata; recovery slice payloads are
    /// reference-counted and are not copied. No file is opened or read here,
    /// and nothing is stat'd — the fingerprints are the caller's, by design.
    pub fn from_verification(
        base_dir: &Path,
        set: &Par2FileSet,
        verification: &VerificationResult,
        fingerprints: &HashMap<FileId, FileStatFingerprint>,
    ) -> std::result::Result<Self, ExternalCarryError> {
        // Laid out by the repairer's own constructor, not by a parallel
        // reimplementation: `try_apply_carry` swaps these vectors in wholesale,
        // so a layout that differed by one block offset would be undetectable
        // and catastrophic.
        let mut state = RepairState::from_set(base_dir, set.clone())?;
        let slice_size = state.set.slice_size;

        let mut attested: HashMap<FileId, &FileVerification> =
            HashMap::with_capacity(verification.files.len());
        for file in &verification.files {
            if attested.insert(file.file_id, file).is_some() {
                return Err(ExternalCarryError::DuplicateFile {
                    file_id: file.file_id,
                });
            }
        }

        let mut located_blocks = 0u32;
        let mut located_bytes = 0u64;

        for file_index in 0..state.files.len() {
            if !state.files[file_index].recoverable {
                continue;
            }
            let file_id = state.files[file_index].file_id;
            let attestation = attested
                .remove(&file_id)
                .ok_or(ExternalCarryError::UncoveredFile { file_id })?;
            let fingerprint = fingerprints.get(&file_id);
            check_attestation(&state.files[file_index], attestation, fingerprint)?;

            let Some(fingerprint) = fingerprint else {
                // Reported missing, and checked as such above: no target, no
                // locations. `verification_result` reads that back as
                // `FileStatus::Missing`, which is what a scan of an absent
                // file produces, so repair treats the file as a target rather
                // than as an input.
                state.files[file_index].target_exists = false;
                continue;
            };
            state.files[file_index].target_exists = true;

            let first_block = state.files[file_index].first_block;
            let block_count = state.files[file_index].block_count;
            let safe_path = state.files[file_index].safe_path.clone();
            for local in 0..block_count {
                if !attestation.valid_slices[local] {
                    continue;
                }
                let block_index = first_block + local;
                let expected_len = state.blocks[block_index].expected_len;
                let offset = local as u64 * slice_size;
                if offset.saturating_add(expected_len) > fingerprint.length() {
                    // The caller claims a slice that does not fit in the file
                    // it fingerprinted. It cannot have read those bytes, so
                    // the block stays unlocated and repair rebuilds it.
                    continue;
                }
                state.blocks[block_index].location = Some(BlockLocation {
                    source: SourceLocation::Path(safe_path.clone()),
                    offset,
                    len: expected_len,
                    kind: BlockLocationKind::Canonical,
                });
                located_blocks = located_blocks.saturating_add(1);
                located_bytes = located_bytes.saturating_add(expected_len);
            }

            if external_carry_layout_is_complete(&state, file_index, fingerprint.length()) {
                let file = &state.files[file_index];
                let complete = BlockLocation {
                    source: SourceLocation::Path(file.safe_path.clone()),
                    offset: 0,
                    len: file.length,
                    kind: BlockLocationKind::Canonical,
                };
                state.files[file_index].complete_location = Some(complete);
            }
        }

        if let Some(file_id) = attested.keys().next().copied() {
            return Err(ExternalCarryError::UnknownFile { file_id });
        }

        // The snapshot is the caller's fingerprints verbatim. Re-statting the
        // paths here would defeat the whole gate: it would record the file as
        // it is *now* rather than as it was when the caller read it, and any
        // change in between would become invisible.
        let present_files = state
            .files
            .iter()
            .filter(|file| file.recoverable && file.target_exists)
            .count() as u32;
        let absent_files = state
            .files
            .iter()
            .filter(|file| file.recoverable && !file.target_exists)
            .count() as u32;
        let snapshot: Vec<CarriedFileStat> = state
            .files
            .iter()
            .filter(|file| file.recoverable)
            .map(|file| CarriedFileStat {
                path: file.safe_path.clone(),
                state: fingerprints.get(&file.file_id).cloned(),
            })
            .collect();

        Ok(ScanCarry {
            recovery_set_id: state.set.recovery_set_id,
            slice_size,
            set_file_ids: state.files.iter().map(|file| file.file_id).collect(),
            snapshot,
            files: state.files.clone(),
            blocks: state.blocks.clone(),
            diagnostics: ScanDiagnostics {
                files_scanned: present_files,
                // This pass read nothing. The bytes behind the carried
                // verdicts are counted as skipped-by-evidence below, which is
                // the counter that exists to disclose an analysis reached
                // without reading its sources.
                bytes_scanned: 0,
                blocks_found: located_blocks,
                files_skipped: absent_files,
                slices_settled_by_evidence: located_blocks,
                bytes_skipped_by_evidence: located_bytes,
                ..ScanDiagnostics::default()
            },
        })
    }
}

/// Check one host attestation against the set entry it claims to describe.
///
/// Only self-consistency is checked — whether the vector, the counts and the
/// status agree with each other and with the set's slice layout. Whether the
/// validity bits are *true* is the caller's attestation and is not checkable
/// here; see [`ScanCarry::from_verification`] for what defends against a false
/// one.
fn check_attestation(
    file: &SourceFileEntry,
    attestation: &FileVerification,
    fingerprint: Option<&FileStatFingerprint>,
) -> std::result::Result<(), ExternalCarryError> {
    let file_id = file.file_id;
    if attestation.valid_slices.len() != file.expected_block_count {
        return Err(ExternalCarryError::SliceCountMismatch {
            file_id,
            expected: file.expected_block_count,
            supplied: attestation.valid_slices.len(),
        });
    }

    let invalid = attestation
        .valid_slices
        .iter()
        .filter(|valid| !**valid)
        .count() as u32;
    if attestation.missing_slice_count != invalid {
        return Err(ExternalCarryError::DamagedCountMismatch {
            file_id,
            declared: attestation.missing_slice_count,
            actual: invalid,
        });
    }

    match &attestation.status {
        FileStatus::Renamed(_) => return Err(ExternalCarryError::RelocatedFile { file_id }),
        FileStatus::Missing => {
            // A missing file has no bytes to have read and no file to have
            // fingerprinted. Either claim contradicts the status.
            if fingerprint.is_some() || attestation.valid_slices.iter().any(|valid| *valid) {
                return Err(ExternalCarryError::MissingFileWithContent { file_id });
            }
            return Ok(());
        }
        FileStatus::Complete => {
            if invalid != 0 {
                return Err(ExternalCarryError::IncompleteCompleteFile { file_id });
            }
        }
        FileStatus::Damaged(declared) => {
            if *declared != invalid {
                return Err(ExternalCarryError::DamagedCountMismatch {
                    file_id,
                    declared: *declared,
                    actual: invalid,
                });
            }
        }
    }

    if fingerprint.is_none() {
        return Err(ExternalCarryError::UnfingerprintedFile { file_id });
    }
    Ok(())
}

/// Whether this file's carried block locations amount to a whole-file
/// canonical source, using the caller's fingerprinted length in place of the
/// `stat` a scan would do.
///
/// This mirrors `RepairState::file_has_canonical_block_layout` exactly, with
/// the one substitution the external form requires: the length comes from the
/// fingerprint the caller captured when it read the file, not from a fresh
/// `stat`, for the same reason the snapshot does. A length read now would
/// describe a file that may already have moved on.
fn external_carry_layout_is_complete(
    state: &RepairState,
    file_index: usize,
    fingerprinted_length: u64,
) -> bool {
    let file = &state.files[file_index];
    if !file.target_exists {
        return false;
    }
    if file.block_count == 0 {
        return file.length == 0 && fingerprinted_length == 0;
    }
    if fingerprinted_length != file.length {
        return false;
    }
    (0..file.block_count).all(|local| {
        let block = &state.blocks[file.first_block + local];
        block.location.as_ref().is_some_and(|location| {
            location.kind == BlockLocationKind::Canonical
                && location.source.is_path(&file.safe_path)
                && location.offset == local as u64 * state.set.slice_size
                && location.len == block.expected_len
        })
    })
}

/// Which seeded slice verdicts an analysis pass is permitted to take on trust
/// instead of re-reading, and the proof each one must still carry.
///
/// This is empty unless the host opted in with
/// [`crate::Par2RepairSessionOptions::trust_seeded_evidence_for_scan`], and an
/// empty plan leaves the scan byte-for-byte what it always was. Only path-keyed
/// evidence can appear here: an access-backed session never scans a directory,
/// so it has no reads to skip, and committed whole-file evidence removes its
/// file from the candidate list outright.
///
/// The fingerprint is captured per slice verdict rather than per file, because
/// verdicts admitted at different moments describe different states of the same
/// path. A host that feeds verdicts while the file is still growing will find
/// most of them refused at scan time; that is the honest answer, not a defect.
#[derive(Debug, Default)]
pub(crate) struct EvidenceScanTrust {
    files: HashMap<FileId, EvidenceTrustEntry>,
}

#[derive(Debug)]
struct EvidenceTrustEntry {
    /// The path the evidence named. A skip is offered only when the candidate
    /// being scanned is this exact path.
    path: PathBuf,
    /// Set once a second path is named for the same PAR2 file, and never
    /// cleared. That is not a picture this can reason about, so the whole
    /// entry stops offering anything — latched rather than recomputed, because
    /// verdicts arrive in map order and a rule that only cleared what it had
    /// seen so far would depend on that order.
    conflicted: bool,
    /// Local slice index and the fingerprint the path carried when that
    /// verdict was admitted.
    slices: Vec<(u32, FileStatFingerprint)>,
}

impl EvidenceScanTrust {
    pub(crate) fn record(
        &mut self,
        file_id: FileId,
        path: &Path,
        slice_index: u32,
        fingerprint: FileStatFingerprint,
    ) {
        let entry = self
            .files
            .entry(file_id)
            .or_insert_with(|| EvidenceTrustEntry {
                path: path.to_path_buf(),
                conflicted: false,
                slices: Vec::new(),
            });
        if entry.conflicted {
            return;
        }
        if entry.path != path {
            entry.conflicted = true;
            entry.slices.clear();
            return;
        }
        entry.slices.push((slice_index, fingerprint));
    }

    /// Slice verdicts admitted for `path` under `file_id`, or `None` when this
    /// plan says nothing about that pair.
    fn slices_for(&self, file_id: &FileId, path: &Path) -> Option<&[(u32, FileStatFingerprint)]> {
        let entry = self.files.get(file_id)?;
        (!entry.conflicted && entry.path == path).then_some(entry.slices.as_slice())
    }
}

/// Per-local-slice bitmap of what one candidate's scan may skip.
///
/// A local index is set only when *all* of the following hold: seeded evidence
/// named it for exactly this path, the path still carries the fingerprint that
/// verdict was admitted against, the block is a full slice, and the scan state
/// already holds a location for it at this path and this offset. The last
/// condition is what makes a skip incapable of losing a block — the scan
/// declines to look for a block that is already placed.
///
/// The converse is deliberate and is the whole meaning of opting in: if the
/// host's verdict was wrong about bytes that never moved, the fingerprint still
/// matches, the range is still skipped, and the wrong verdict stands. Nothing
/// here re-derives it. That is why the evidence admission bar
/// ([`crate::SliceEvidence::may_seed_repair_input`]) exists on the way in.
fn evidence_settled_slices(
    trust: &EvidenceScanTrust,
    target_file: &SourceFileEntry,
    path: &Path,
    blocks: &ScanBlockState<'_>,
    slice_size: u64,
) -> Vec<bool> {
    let Some(slices) = trust.slices_for(&target_file.file_id, path) else {
        return Vec::new();
    };
    if slices.is_empty() || slice_size == 0 {
        return Vec::new();
    }
    // The fresh stat happens here, immediately before this candidate is read,
    // and nowhere earlier: a fingerprint checked at plan-build time would leave
    // a window in which the file could change before the scan reached it.
    let Some(current) = stat_fingerprint(path) else {
        return Vec::new();
    };

    let mut settled = vec![false; target_file.block_count];
    for (local_index, fingerprint) in slices {
        if *fingerprint != current {
            continue;
        }
        let local = *local_index as usize;
        if local >= target_file.block_count {
            continue;
        }
        let block_index = target_file.first_block + local;
        let block = blocks.block(block_index);
        if block.file_id != target_file.file_id || block.expected_len != slice_size {
            continue;
        }
        let offset = local as u64 * slice_size;
        if blocks.location(block_index).is_some_and(|location| {
            location.offset == offset
                && location.len == block.expected_len
                && location.source.is_path(path)
        }) {
            settled[local] = true;
        }
    }
    settled
}

/// Coalesce settled local slice indices into byte ranges.
///
/// Consecutive settled slices become one range, so a file whose damage is a
/// single burst costs one seek rather than one per intact slice. A slice whose
/// range would run past the file on disk is dropped: the file is shorter than
/// the set describes, which is a discrepancy for the scan to find, not one to
/// seek over.
fn settled_byte_runs(settled: &[bool], slice_size: usize, len: usize) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    if slice_size == 0 {
        return runs;
    }
    for (local, _) in settled.iter().enumerate().filter(|(_, set)| **set) {
        let start = local * slice_size;
        let end = start + slice_size;
        if end > len {
            continue;
        }
        match runs.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => runs.push((start, end)),
        }
    }
    runs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileScanMode {
    Complete,
    OrderedCanonical,
    OrderedCanonicalParallel,
    RollingGeneric,
}

impl FileScanMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::OrderedCanonical => "ordered_canonical",
            Self::OrderedCanonicalParallel => "ordered_canonical_parallel",
            Self::RollingGeneric => "rolling_generic",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FileScanStats {
    mode: FileScanMode,
    bytes_scanned: u64,
    windows_stepped: u64,
    jumps_taken: u64,
    max_consecutive_steps: u64,
    /// Bytes this file's scan seeked past instead of reading, because seeded
    /// evidence already accounted for them. Always zero without the opt-in.
    bytes_skipped_by_evidence: u64,
    slices_settled_by_evidence: u32,
}

impl FileScanStats {
    fn new(mode: FileScanMode, bytes_scanned: u64) -> Self {
        Self {
            mode,
            bytes_scanned,
            windows_stepped: 0,
            jumps_taken: 0,
            max_consecutive_steps: 0,
            bytes_skipped_by_evidence: 0,
            slices_settled_by_evidence: 0,
        }
    }
}

/// Accounting for the exhaustive short-block relocation search.
///
/// That search is the one scan phase whose cost is not proportional to the
/// candidate it was asked about: it re-reads a whole candidate once per
/// distinct still-open short length. It used to update no counter at all, so
/// a quadratic blow-up surfaced in the logs as a slow file scan reporting zero
/// windows stepped. These fields exist so it can never hide again.
#[derive(Debug, Default, Clone, Copy)]
struct ShortRelocationStats {
    windows_stepped: u64,
    bytes_read: u64,
    blocks_placed: u64,
}

impl ShortRelocationStats {
    fn accumulate(&mut self, other: &Self) {
        self.windows_stepped = self.windows_stepped.saturating_add(other.windows_stepped);
        self.bytes_read = self.bytes_read.saturating_add(other.bytes_read);
        self.blocks_placed = self.blocks_placed.saturating_add(other.blocks_placed);
    }
}

#[derive(Debug, Clone)]
struct ScanCandidate {
    path: PathBuf,
    kind: BlockLocationKind,
}

/// One candidate the deferred relocation search may re-read: a candidate that
/// reached the block-scan phase, so its bytes were never claimed wholesale by
/// a complete-file match.
#[derive(Debug, Clone)]
struct ShortRelocationTarget {
    path: PathBuf,
    kind: BlockLocationKind,
    len: u64,
}

#[derive(Debug, Clone)]
struct CompleteFileMatch {
    file_index: usize,
    location: BlockLocation,
}

type CompleteScanMatches = (Vec<CompleteFileMatch>, Vec<(usize, BlockLocation)>);

struct ScanBlockState<'a> {
    blocks: &'a [SourceBlock],
    locations: Vec<Option<BlockLocation>>,
}

impl<'a> ScanBlockState<'a> {
    fn new(blocks: &'a [SourceBlock]) -> Self {
        Self {
            blocks,
            locations: blocks
                .iter()
                .map(|block| block.location.clone())
                .collect::<Vec<_>>(),
        }
    }

    fn block(&self, block_index: usize) -> &SourceBlock {
        &self.blocks[block_index]
    }

    fn baseline(&self) -> &'a [SourceBlock] {
        self.blocks
    }

    fn location(&self, block_index: usize) -> Option<&BlockLocation> {
        self.locations[block_index].as_ref()
    }

    fn record_location(&mut self, block_index: usize, location: BlockLocation) {
        let replace = self.locations[block_index].as_ref().is_none_or(|existing| {
            location.kind < existing.kind
                || (location.kind == existing.kind && location.source < existing.source)
        });
        if replace {
            self.locations[block_index] = Some(location);
        }
    }

    fn changed_locations(&self) -> Vec<(usize, BlockLocation)> {
        self.locations
            .iter()
            .zip(self.blocks.iter())
            .enumerate()
            .filter_map(|(idx, (location, block))| {
                (location != &block.location)
                    .then(|| location.clone().map(|location| (idx, location)))
                    .flatten()
            })
            .collect()
    }

    #[cfg(test)]
    fn apply_to_blocks(self, blocks: &mut [SourceBlock]) {
        for (block, location) in blocks.iter_mut().zip(self.locations) {
            block.location = location;
        }
    }
}

#[derive(Debug)]
struct CandidateScanResult {
    path: PathBuf,
    kind: BlockLocationKind,
    files_scanned: u32,
    files_skipped: u32,
    /// The candidate's length — the bytes this scan was asked to account for.
    /// What it actually read is this minus [`Self::bytes_skipped_by_evidence`];
    /// the two are separate because the deferred short-block relocation search
    /// needs the file length, not the read total.
    bytes_scanned: u64,
    bytes_skipped_by_evidence: u64,
    slices_settled_by_evidence: u32,
    stats: Option<FileScanStats>,
    elapsed: Duration,
    complete_files: Vec<CompleteFileMatch>,
    block_locations: Vec<(usize, BlockLocation)>,
}

impl CandidateScanResult {
    fn ignored(path: &Path, kind: BlockLocationKind) -> Self {
        Self {
            path: path.to_path_buf(),
            kind,
            files_scanned: 0,
            files_skipped: 0,
            bytes_scanned: 0,
            bytes_skipped_by_evidence: 0,
            slices_settled_by_evidence: 0,
            stats: None,
            elapsed: Duration::ZERO,
            complete_files: Vec::new(),
            block_locations: Vec::new(),
        }
    }

    fn skipped(path: &Path, kind: BlockLocationKind) -> Self {
        Self {
            files_skipped: 1,
            ..Self::ignored(path, kind)
        }
    }

    /// The relocation target this candidate offers, if any.
    ///
    /// Only a candidate that actually reached the block-scan phase qualifies.
    /// [`FileScanMode::Complete`] marks the early exits — a whole-file hash
    /// match, or a rename-only pass — which never looked at short blocks
    /// before this change either.
    fn short_relocation_target(&self) -> Option<ShortRelocationTarget> {
        let stats = self.stats?;
        (stats.mode != FileScanMode::Complete && self.bytes_scanned > 0).then(|| {
            ShortRelocationTarget {
                path: self.path.clone(),
                kind: self.kind,
                len: self.bytes_scanned,
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct Par2RepairOutcome {
    pub status: Par2RepairStatus,
    pub files_complete: u32,
    pub files_renamed: u32,
    pub files_damaged: u32,
    pub files_missing: u32,
    pub available_blocks: u32,
    pub missing_blocks: u32,
    pub recovery_blocks_available: u32,
    pub recovery_blocks_used: u32,
    pub bytes_copied: u64,
    pub bytes_reconstructed: u64,
    pub packets: PacketDiagnostics,
    pub scan: ScanDiagnostics,
    pub carry: CarryDiagnostics,
    pub verification: VerificationResult,
}

#[derive(Clone)]
pub struct Par2RepairerOptions {
    pub base_dir: PathBuf,
    pub file_set: Option<Par2FileSet>,
    pub par2_paths: Vec<PathBuf>,
    pub recovery_paths: Vec<PathBuf>,
    pub extra_paths: Vec<PathBuf>,
    pub repair: bool,
    /// Working-memory budget applied to scanning and repair. Parallel ordered
    /// scans fall back to the bounded serial scanner when their fixed
    /// bookkeeping cannot fit; `None` uses the crate default.
    pub memory_limit: Option<usize>,
    /// Resource bounds for the packet-inventory load, shared across every
    /// `.par2` input of the pass. The defaults come from what the PAR2 format
    /// can describe; see [`PacketScanLimits`].
    pub packet_scan_limits: PacketScanLimits,
    pub rename_only: bool,
    pub purge: bool,
    pub scan_skip_data: bool,
    pub scan_skip_leeway: u64,
    pub cancel: Option<CancellationToken>,
    pub progress: Option<ProgressCallback>,
    /// Scan state from a prior pass over the same set (see
    /// [`Par2Repairer::verify_or_repair_carrying`]). Applied only when the
    /// set matches and every observed file's stat snapshot still matches;
    /// otherwise this pass scans normally. A mutating repair additionally
    /// re-checks every source it will read immediately before mutating, and
    /// consumes the carry only when all of them still match; every other
    /// accepted-carry result is retried from a fresh content scan before
    /// reporting. Must come from a pass with the same `base_dir`/
    /// `extra_paths`/`scan_skip_*` configuration.
    pub scan_carry: Option<Arc<ScanCarry>>,
}

impl Par2RepairerOptions {
    pub fn new(base_dir: PathBuf, par2_paths: Vec<PathBuf>) -> Self {
        Self {
            base_dir,
            file_set: None,
            par2_paths,
            recovery_paths: Vec::new(),
            extra_paths: Vec::new(),
            repair: true,
            memory_limit: Some(DEFAULT_REPAIR_MEMORY_LIMIT),
            packet_scan_limits: PacketScanLimits::default(),
            rename_only: false,
            purge: false,
            scan_skip_data: false,
            scan_skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
            cancel: None,
            progress: None,
            scan_carry: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockLocationKind {
    Canonical,
    Renamed,
    Extra,
}

/// Where the bytes behind a verified source block actually live.
///
/// PAR2 sources are not always files. A [`SourceLocation::Path`] is read with
/// `std::fs`; a [`SourceLocation::Access`] names its source only by PAR2
/// [`FileId`] and is read exclusively through the session's
/// [`FileAccess`] handle. The distinction is a type,
/// not a convention: an access-backed source carries no path, so no code path
/// can accidentally open it from disk.
///
/// ```
/// use par2_rs::{BlockLocation, BlockLocationKind, FileId, SourceLocation};
/// use std::path::PathBuf;
///
/// let on_disk = BlockLocation {
///     source: SourceLocation::Path(PathBuf::from("/downloads/release.r00")),
///     offset: 0,
///     len: 4096,
///     kind: BlockLocationKind::Canonical,
/// };
/// assert!(on_disk.path().is_some());
/// assert!(on_disk.file_id().is_none());
///
/// let virtual_volume = BlockLocation {
///     source: SourceLocation::Access(FileId::from_bytes([7; 16])),
///     offset: 0,
///     len: 4096,
///     kind: BlockLocationKind::Canonical,
/// };
/// assert!(virtual_volume.path().is_none());
/// assert_eq!(virtual_volume.file_id(), Some(FileId::from_bytes([7; 16])));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceLocation {
    /// A real file on disk, addressed by path.
    Path(PathBuf),
    /// A source served by a [`FileAccess`] handle,
    /// addressed only by its PAR2 file identifier.
    Access(FileId),
}

impl SourceLocation {
    /// The backing path, or `None` for an access-backed source.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(path) => Some(path.as_path()),
            Self::Access(_) => None,
        }
    }

    /// The backing PAR2 file identifier, or `None` for a path-backed source.
    pub fn file_id(&self) -> Option<FileId> {
        match self {
            Self::Path(_) => None,
            Self::Access(file_id) => Some(*file_id),
        }
    }

    /// Whether this source is the file at `path`. Access-backed sources are
    /// never at any path, so this is always `false` for them.
    pub fn is_path(&self, path: &Path) -> bool {
        matches!(self, Self::Path(owned) if owned == path)
    }

    /// Whether this source is served through a
    /// [`FileAccess`] handle.
    pub fn is_access(&self) -> bool {
        matches!(self, Self::Access(_))
    }

    /// Whether this source *is* the described file rather than a copy of it
    /// found elsewhere. For a path that means the file sits at its canonical
    /// location; for an access-backed source it means the handle was asked for
    /// this very file identifier, which is the only thing it can be asked for.
    fn is_canonical_for(&self, file: &SourceFileEntry) -> bool {
        match self {
            Self::Path(path) => *path == file.safe_path,
            Self::Access(file_id) => *file_id == file.file_id,
        }
    }

    /// Heap bytes owned by this location. A [`FileId`] lives inline in the
    /// enum, so an access-backed source owns nothing on the heap; a path owns
    /// its own bytes.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::Path(path) => path.as_os_str().len(),
            Self::Access(_) => 0,
        }
    }
}

/// One resolved span of source data: where it lives, and how much of it
/// belongs to the block or file that resolved to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLocation {
    /// Where the bytes are. Scanning only ever produces
    /// [`SourceLocation::Path`]; evidence fed to a session over a
    /// [`FileAccess`] handle produces [`SourceLocation::Access`].
    pub source: SourceLocation,
    /// Byte offset of this span within `source`.
    pub offset: u64,
    /// Length of this span.
    pub len: u64,
    /// How this location was matched to the set.
    pub kind: BlockLocationKind,
}

impl BlockLocation {
    /// The backing path, or `None` for an access-backed source.
    pub fn path(&self) -> Option<&Path> {
        self.source.path()
    }

    /// The backing PAR2 file identifier, or `None` for a path-backed source.
    pub fn file_id(&self) -> Option<FileId> {
        self.source.file_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockCopyRange {
    src: SourceLocation,
    src_offset: u64,
    dst: PathBuf,
    dst_offset: u64,
    len: u64,
}

/// Destination for an intact source block while reconstruction is active.
/// The source bytes are copied from the same buffer that is submitted to the
/// Reed-Solomon controller so copy and reconstruction observe identical data.
type ReconstructionCopyTargets = HashMap<(FileId, u32), BlockCopyRange>;

impl BlockCopyRange {
    fn can_extend(&self, next: &Self) -> bool {
        self.src == next.src
            && self.dst == next.dst
            && self.src_offset.checked_add(self.len) == Some(next.src_offset)
            && self.dst_offset.checked_add(self.len) == Some(next.dst_offset)
    }

    fn extend(&mut self, next: &Self) {
        self.len += next.len;
    }
}

#[derive(Debug, Clone)]
pub struct SourceBlock {
    pub global_index: usize,
    pub file_id: FileId,
    pub local_index: u32,
    pub expected_len: u64,
    pub checksum: SliceChecksum,
    pub location: Option<BlockLocation>,
}

#[derive(Debug, Clone)]
pub struct SourceFileEntry {
    pub file_id: FileId,
    pub par2_name: String,
    pub safe_path: PathBuf,
    pub safe_name: String,
    pub length: u64,
    pub hash_full: [u8; 16],
    pub hash_16k: [u8; 16],
    pub recoverable: bool,
    pub first_block: usize,
    pub expected_block_count: usize,
    pub block_count: usize,
    pub target_exists: bool,
    pub complete_location: Option<BlockLocation>,
    pub non_canonical_complete_source_count: u32,
}

#[derive(Debug, Clone)]
pub struct PacketInventory {
    pub set: Par2FileSet,
    pub diagnostics: PacketDiagnostics,
    pub purge_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct PacketInputPath {
    path: PathBuf,
    optional: bool,
    purgeable: bool,
}

pub struct Par2Repairer {
    options: Par2RepairerOptions,
}

struct RepairPassSuccess {
    outcome: Par2RepairOutcome,
    carry: Option<Arc<ScanCarry>>,
    /// Set when a carried pass refused, before installing anything, to mutate
    /// on the carried analysis. The reason names what the pre-mutation
    /// fingerprint gate — or a validated read — saw, and the caller retries
    /// the whole pass from a fresh scan.
    carry_gate_rejection: Option<CarryRetryReason>,
}

impl RepairPassSuccess {
    fn new(outcome: Par2RepairOutcome, carry: Option<Arc<ScanCarry>>) -> Self {
        Self {
            outcome,
            carry,
            carry_gate_rejection: None,
        }
    }
}

enum RepairPassResult {
    Success(RepairPassSuccess),
    PostRepairVerificationFailed {
        reason: String,
        carry: CarryDiagnostics,
    },
}

impl Par2Repairer {
    pub fn new(options: Par2RepairerOptions) -> Self {
        Self { options }
    }

    pub fn verify_or_repair(&self) -> Result<Par2RepairOutcome> {
        Ok(self.verify_or_repair_inner(false)?.0)
    }

    /// Like [`Self::verify_or_repair`], additionally returning this pass's
    /// scan state for reuse by a later pass over the same set
    /// ([`Par2RepairerOptions::scan_carry`]). A repair consumes such a carry
    /// when every source it will read still matches the fingerprint the scan
    /// captured; carried results that do not mutate stay speculative and are
    /// retried from a fresh content scan before they are reported.
    pub fn verify_or_repair_carrying(&self) -> Result<(Par2RepairOutcome, Option<Arc<ScanCarry>>)> {
        self.verify_or_repair_inner(true)
    }

    fn verify_or_repair_inner(
        &self,
        want_carry: bool,
    ) -> Result<(Par2RepairOutcome, Option<Arc<ScanCarry>>)> {
        // No-op on native. On `wasm32-wasip1-threads` this is what lets the
        // scan fan-out, the GF elimination, and the streamed repair
        // controller's `rayon::current_num_threads()` worker sizing see more
        // than one worker; the width comes from the same process-stable
        // embedder-supplied value creation uses.
        reedsolomon_rs::threading::ensure_pool(crate::create::configured_create_threads_for_pool);
        // This entry point carries repair intent: pages the scan verifies are
        // read again by staging and by copy-only repair, which never reaches
        // `execute_repair_with_options`' own deferral.
        let _cache_retention = crate::file_cache::CacheEvictionDeferral::acquire();
        match self.verify_or_repair_pass(want_carry)? {
            RepairPassResult::Success(success) => self.finish_or_retry(success, want_carry),
            RepairPassResult::PostRepairVerificationFailed { reason, carry } => {
                if carry.carry_applied {
                    debug!(
                        retry_reason = ?CarryRetryReason::PostRepairVerificationFailed,
                        "carried PAR2 repair failed post-verification; retrying from a fresh scan"
                    );
                    return self
                        .retry_fresh(want_carry, CarryRetryReason::PostRepairVerificationFailed);
                }
                Err(Par2Error::ReedSolomonError { reason })
            }
        }
    }

    fn finish_or_retry(
        &self,
        success: RepairPassSuccess,
        want_carry: bool,
    ) -> Result<(Par2RepairOutcome, Option<Arc<ScanCarry>>)> {
        let status = success.outcome.status;
        if let Some(reason) = success.carry_gate_rejection {
            debug!(
                ?status,
                retry_reason = ?reason,
                "carried PAR2 pass could not prove its repair inputs; retrying from a fresh scan before mutation"
            );
            return self.retry_fresh(want_carry, reason);
        }
        // A carried pass that reached a mutating repair and proved every
        // input still matches its scan-time fingerprint has already repaired
        // on the carried analysis; re-running it from a fresh scan would only
        // read the whole set a second time to reach the same place.
        if success.outcome.carry.carry_applied
            && self.options.repair
            && !success.outcome.carry.carry_consumed_for_repair
        {
            debug!(
                ?status,
                "carried PAR2 pass reached a repair request; retrying from a fresh scan before mutation"
            );
            return self.retry_fresh(want_carry, CarryRetryReason::RepairRequested);
        }
        if success.outcome.carry.carry_applied && Self::is_terminal_non_repair_status(status) {
            debug!(
                ?status,
                "carried PAR2 pass returned terminal non-repair status; retrying from a fresh scan"
            );
            return self.retry_fresh(want_carry, CarryRetryReason::TerminalStatus(status));
        }
        Ok((success.outcome, success.carry))
    }

    fn retry_fresh(
        &self,
        want_carry: bool,
        retry_reason: CarryRetryReason,
    ) -> Result<(Par2RepairOutcome, Option<Arc<ScanCarry>>)> {
        let mut options = self.options.clone();
        options.scan_carry = None;
        match Par2Repairer::new(options).verify_or_repair_pass(want_carry)? {
            RepairPassResult::Success(mut success) => {
                success.outcome.carry = CarryDiagnostics {
                    carry_attempted: true,
                    carry_applied: true,
                    carry_retried_fresh: true,
                    carry_retry_reason: Some(retry_reason),
                    // This outcome came from a fresh scan of the tree, not
                    // from the carried analysis, whatever the retried pass
                    // decided about its own (absent) carry.
                    carry_consumed_for_repair: false,
                };
                Ok((success.outcome, success.carry))
            }
            RepairPassResult::PostRepairVerificationFailed { reason, .. } => {
                Err(Par2Error::ReedSolomonError { reason })
            }
        }
    }

    fn is_terminal_non_repair_status(status: Par2RepairStatus) -> bool {
        matches!(
            status,
            Par2RepairStatus::Verified
                | Par2RepairStatus::RepairPossible
                | Par2RepairStatus::Insufficient
                | Par2RepairStatus::ResourceLimited
        )
    }

    fn with_carry_diagnostics(
        mut outcome: Par2RepairOutcome,
        carry: &CarryDiagnostics,
    ) -> Par2RepairOutcome {
        outcome.carry = carry.clone();
        outcome
    }

    fn verify_or_repair_pass(&self, want_carry: bool) -> Result<RepairPassResult> {
        let PacketInventory {
            set,
            diagnostics,
            purge_paths,
        } = self.load_inventory()?;
        let mut state = RepairState::from_set(&self.options.base_dir, set)?;
        let mut packet_diagnostics = diagnostics;

        packet_diagnostics.discarded_recovery_blocks = state.discarded_recovery_blocks;
        packet_diagnostics.inconsistent_packets = state.inconsistent_packets;

        let mut carry_diagnostics = CarryDiagnostics {
            carry_attempted: self.options.scan_carry.is_some(),
            ..CarryDiagnostics::default()
        };
        let scan = match self.options.scan_carry.as_deref().and_then(|carry| {
            let diagnostics = state.try_apply_carry(carry);
            if diagnostics.is_some() {
                carry_diagnostics.carry_applied = true;
            }
            diagnostics
        }) {
            Some(mut diagnostics) => {
                // The counters describe the pass that produced them, not this
                // one. Say so, so a host reading a single outcome can tell a
                // scan that happened here from one it inherited.
                diagnostics.carried = true;
                diagnostics
            }
            None => state.scan(&self.options)?,
        };
        let mut verification = state.verification_result();
        if let Some(reason) = repair_matrix_resource_limit_reason(
            &state.set,
            &verification,
            self.options.memory_limit,
        )? {
            verification.repairable = Repairability::ResourceLimited { reason };
        }
        let carry = want_carry.then(|| Arc::new(state.scan_carry(&scan)));

        if carry_diagnostics.carry_applied {
            let status =
                if verification.total_missing_blocks == 0 && state.files_are_canonical_complete() {
                    Par2RepairStatus::Verified
                } else {
                    match &verification.repairable {
                        Repairability::NotNeeded => Par2RepairStatus::Verified,
                        Repairability::Repairable { .. } => Par2RepairStatus::RepairPossible,
                        Repairability::Insufficient { .. } => Par2RepairStatus::Insufficient,
                        Repairability::ResourceLimited { .. } => Par2RepairStatus::ResourceLimited,
                    }
                };
            // Only a request that will actually rewrite the tree can consume
            // the carried analysis. Every other carried result — a clean
            // verify (which may still purge), an insufficient or
            // resource-limited verdict, and any verify-only pass — is still
            // speculative and is re-established from a real scan before it is
            // reported, exactly as before.
            let mutation_requested =
                self.options.repair && status == Par2RepairStatus::RepairPossible;
            let gate = mutation_requested
                .then(|| {
                    let applied = self
                        .options
                        .scan_carry
                        .as_deref()
                        .expect("carry_applied implies a supplied carry");
                    state.carry_repair_inputs_unchanged(applied)
                })
                .transpose();
            match gate {
                // Not a mutating request: report the carried result and let
                // the caller re-establish it from a fresh scan.
                Ok(None) => {
                    return Ok(RepairPassResult::Success(RepairPassSuccess::new(
                        Self::with_carry_diagnostics(
                            state.outcome(status, 0, 0, packet_diagnostics, scan, verification),
                            &carry_diagnostics,
                        ),
                        carry,
                    )));
                }
                // Every input the repair would read is still the file the scan
                // read. Fall through and repair on the carried analysis.
                Ok(Some(())) => {
                    carry_diagnostics.carry_consumed_for_repair = true;
                }
                Err(reason) => {
                    debug!(
                        ?status,
                        ?reason,
                        "carried PAR2 repair inputs no longer match their scan-time fingerprints"
                    );
                    return Ok(RepairPassResult::Success(RepairPassSuccess {
                        outcome: Self::with_carry_diagnostics(
                            state.outcome(status, 0, 0, packet_diagnostics, scan, verification),
                            &carry_diagnostics,
                        ),
                        carry,
                        carry_gate_rejection: Some(reason),
                    }));
                }
            }
        }

        if verification.total_missing_blocks == 0 && state.files_are_canonical_complete() {
            if self.options.purge {
                purge_files_best_effort(&purge_paths);
            }
            return Ok(RepairPassResult::Success(RepairPassSuccess::new(
                Self::with_carry_diagnostics(
                    state.outcome(
                        Par2RepairStatus::Verified,
                        0,
                        0,
                        packet_diagnostics,
                        scan,
                        verification,
                    ),
                    &carry_diagnostics,
                ),
                carry,
            )));
        }

        if !self.options.repair {
            let status = match &verification.repairable {
                Repairability::NotNeeded => Par2RepairStatus::Verified,
                Repairability::Repairable { .. } => Par2RepairStatus::RepairPossible,
                Repairability::Insufficient { .. } => Par2RepairStatus::Insufficient,
                Repairability::ResourceLimited { .. } => Par2RepairStatus::ResourceLimited,
            };
            return Ok(RepairPassResult::Success(RepairPassSuccess::new(
                Self::with_carry_diagnostics(
                    state.outcome(status, 0, 0, packet_diagnostics, scan, verification),
                    &carry_diagnostics,
                ),
                carry,
            )));
        }

        if matches!(
            &verification.repairable,
            Repairability::Insufficient { .. } | Repairability::ResourceLimited { .. }
        ) {
            let status = match &verification.repairable {
                Repairability::ResourceLimited { .. } => Par2RepairStatus::ResourceLimited,
                _ => Par2RepairStatus::Insufficient,
            };
            return Ok(RepairPassResult::Success(RepairPassSuccess::new(
                Self::with_carry_diagnostics(
                    state.outcome(status, 0, 0, packet_diagnostics, scan, verification),
                    &carry_diagnostics,
                ),
                carry,
            )));
        }

        let repair = if carry_diagnostics.carry_consumed_for_repair {
            // The analysis feeding this repair was taken before the caller's
            // own gap between passes, so the validated read path is used: each
            // source slice is checked against its IFSC checksum on the way
            // into staging and into the Reed-Solomon input stream, and every
            // path is re-stat'd as it is opened. That covers the one drift a
            // stat fingerprint cannot see — a same-length rewrite that also
            // restored the original mtime in place — by catching it on the
            // bytes instead of on the metadata. Nothing has been installed at
            // this point, so a caught change simply falls back to a fresh
            // scan.
            match state.repair_validated(&self.options, &verification) {
                Ok(repair) => repair,
                Err(error) if is_source_changed_error(&error) => {
                    debug!(
                        %error,
                        "carried PAR2 repair read a changed source; retrying from a fresh scan"
                    );
                    return Ok(RepairPassResult::Success(RepairPassSuccess {
                        outcome: Self::with_carry_diagnostics(
                            state.outcome(
                                Par2RepairStatus::RepairPossible,
                                0,
                                0,
                                packet_diagnostics,
                                scan,
                                verification,
                            ),
                            &carry_diagnostics,
                        ),
                        carry,
                        carry_gate_rejection: Some(CarryRetryReason::RepairInputChanged),
                    }));
                }
                Err(error) => return Err(error),
            }
        } else {
            state.repair(&self.options, &verification)?
        };
        let repaired_access = RepairVerificationAccess::new(
            &state.files,
            &repair.install_dir,
            &repair.staged_file_ids,
            state.source_access.clone(),
        );
        // Fresh repair passes read staged files back and verify them
        // slice-by-slice against IFSC before installation.
        let staged_ids: Vec<FileId> = state
            .set
            .recovery_file_ids
            .iter()
            .filter(|file_id| repair.staged_file_ids.contains(file_id))
            .copied()
            .collect();
        let post_staged =
            verify::verify_repaired_file_ids_parallel(&state.set, &repaired_access, &staged_ids);
        let post = verify::merge_verification_results(&state.set, &verification, post_staged);
        if post.total_missing_blocks > 0
            || !post
                .files
                .iter()
                .all(|file| matches!(file.status, FileStatus::Complete))
        {
            let _ = fs::remove_dir_all(&repair.install_dir);
            return Ok(RepairPassResult::PostRepairVerificationFailed {
                reason: format!(
                    "post-repair verification failed: {} blocks remain damaged",
                    post.total_missing_blocks
                ),
                carry: carry_diagnostics,
            });
        }

        if let Err(error) = state.install_repaired_files(&repair, &self.options) {
            let _ = fs::remove_dir_all(&repair.install_dir);
            return Err(error);
        }
        let _ = fs::remove_dir_all(&repair.install_dir);
        if self.options.purge {
            purge_files_best_effort(&purge_paths);
        }

        Ok(RepairPassResult::Success(RepairPassSuccess::new(
            Self::with_carry_diagnostics(
                state.outcome(
                    Par2RepairStatus::Repaired,
                    repair.bytes_copied,
                    repair.bytes_reconstructed,
                    packet_diagnostics,
                    scan,
                    post,
                ),
                &carry_diagnostics,
            ),
            carry,
        )))
    }

    pub(crate) fn load_inventory(&self) -> Result<PacketInventory> {
        self.load_inventory_with_adjacent_recovery(true)
    }

    pub(crate) fn load_inventory_without_adjacent_recovery(&self) -> Result<PacketInventory> {
        self.load_inventory_with_adjacent_recovery(false)
    }

    fn load_inventory_with_adjacent_recovery(
        &self,
        discover_adjacent_recovery: bool,
    ) -> Result<PacketInventory> {
        if let Some(set) = self.options.file_set.clone() {
            return Ok(PacketInventory {
                set,
                diagnostics: PacketDiagnostics::default(),
                purge_paths: Vec::new(),
            });
        }

        let mut paths = Vec::<PacketInputPath>::new();
        let mut seen = HashSet::<PathBuf>::new();
        let mut primary_par2_paths = Vec::new();

        for path in &self.options.par2_paths {
            if is_par2_path(path) {
                if seen.insert(path.clone()) {
                    paths.push(PacketInputPath {
                        path: path.clone(),
                        optional: false,
                        purgeable: true,
                    });
                }
                primary_par2_paths.push(path.clone());
                continue;
            }

            if let Some(primary) = discover_source_primary_par2_file(path)? {
                if seen.insert(primary.clone()) {
                    paths.push(PacketInputPath {
                        path: primary.clone(),
                        optional: false,
                        purgeable: true,
                    });
                }
                primary_par2_paths.push(primary);
                continue;
            }

            if seen.insert(path.clone()) {
                paths.push(PacketInputPath {
                    path: path.clone(),
                    optional: false,
                    purgeable: false,
                });
            }
        }

        for path in &self.options.recovery_paths {
            if is_par2_path(path) {
                if seen.insert(path.clone()) {
                    paths.push(PacketInputPath {
                        path: path.clone(),
                        optional: false,
                        purgeable: true,
                    });
                }
                continue;
            }

            if let Some(primary) = discover_source_primary_par2_file(path)? {
                if seen.insert(primary.clone()) {
                    paths.push(PacketInputPath {
                        path: primary,
                        optional: false,
                        purgeable: true,
                    });
                }
                continue;
            }

            if seen.insert(path.clone()) {
                paths.push(PacketInputPath {
                    path: path.clone(),
                    optional: false,
                    purgeable: false,
                });
            }
        }

        if discover_adjacent_recovery {
            for adjacent in discover_adjacent_par2_files(&primary_par2_paths)? {
                if seen.insert(adjacent.clone()) {
                    paths.push(PacketInputPath {
                        path: adjacent,
                        optional: true,
                        purgeable: true,
                    });
                }
            }
        }

        for path in self
            .options
            .extra_paths
            .iter()
            .filter(|path| has_par2_marker(path))
        {
            if seen.insert(path.clone()) {
                paths.push(PacketInputPath {
                    path: path.clone(),
                    optional: true,
                    purgeable: false,
                });
            }
        }

        let budget = PacketScanBudget::with_cancellation(
            self.options.packet_scan_limits,
            self.options.cancel.clone(),
        );
        let mut loader = InventoryLoader::new(&budget);

        for input in paths {
            budget.check_cancelled()?;
            loader.begin_file(input.path.clone(), input.purgeable);
            match scan_packets_from_path_bounded(&input.path, &budget, &mut loader) {
                Ok(()) => {}
                // A budget refusal or a cancellation is never softened into
                // "this optional input contributed nothing": that would hand
                // back a silently short inventory.
                Err(error @ (Par2Error::ResourceLimitExceeded { .. } | Par2Error::Cancelled)) => {
                    return Err(error);
                }
                Err(_) if input.optional => {}
                Err(error) => return Err(error),
            }
            loader.end_file(input.optional);
        }

        loader.finish()
    }
}

/// Streams scanned packets into one deduplicated inventory.
///
/// Replaces the scan-into-`Vec` / retain-per-file / move-into-`Vec<Packet>` /
/// build chain that used to hold the same packets in three places at once. A
/// packet is now filtered, deduplicated, and either absorbed or dropped at the
/// point it is parsed.
///
/// # Choosing the active recovery set
///
/// The active recovery-set ID is the one carried by the first Main packet seen
/// across the inputs, in input order — the same packet the previous two-pass
/// loader picked. Every later packet is filtered against it and a foreign
/// packet is discarded before its contents are retained.
///
/// Packets seen *before* that first Main cannot be filtered yet, so they are
/// staged, and the stage is flushed the moment the ID is known. Staging is
/// charged to the same budget as everything else, so a file that never yields a
/// Main cannot use the stage to escape the bound. Real volumes put their Main
/// packet within the first handful of packets, so the stage is normally short
/// lived and only ever holds part of the first input.
///
/// # Deliberate difference from the previous loader
///
/// The old loader dropped a whole file when the file's own first Main packet
/// disagreed with the active set. For a file whose packets all belong to that
/// foreign set — the case that actually occurs — the per-packet filter drops
/// exactly the same packets and reports exactly the same count. The two differ
/// only for a file that mixes packets from two recovery sets, where the
/// per-packet filter now keeps the packets that do belong to the active set
/// instead of discarding the file wholesale.
struct InventoryLoader<'a> {
    budget: &'a PacketScanBudget,
    builder: Par2FileSetBuilder,
    diagnostics: PacketDiagnostics,
    active_set_id: Option<RecoverySetId>,
    staged: Vec<StagedPacket>,
    files: Vec<InventoryFile>,
}

/// A packet held until the active recovery-set ID is known.
enum StagedPacket {
    /// Contents kept, charged to the budget's retained meters.
    Held {
        packet: Packet,
        set_id: RecoverySetId,
        bytes: usize,
        file: usize,
    },
    /// Contents dropped on arrival because the builder already holds this key.
    /// Only the record survives, so the packet can still be counted as work
    /// once the set filter has been applied.
    KnownDuplicate { set_id: RecoverySetId, file: usize },
}

struct InventoryFile {
    path: PathBuf,
    purgeable: bool,
    /// At least one packet from this file survived the recovery-set filter.
    contributed: bool,
    /// Packets this file yielded, whatever became of them.
    scanned: u32,
}

impl<'a> InventoryLoader<'a> {
    fn new(budget: &'a PacketScanBudget) -> Self {
        Self {
            budget,
            builder: Par2FileSetBuilder::new(),
            diagnostics: PacketDiagnostics::default(),
            active_set_id: None,
            staged: Vec::new(),
            files: Vec::new(),
        }
    }

    fn begin_file(&mut self, path: PathBuf, purgeable: bool) {
        self.files.push(InventoryFile {
            path,
            purgeable,
            contributed: false,
            scanned: 0,
        });
    }

    fn end_file(&mut self, optional: bool) {
        let file = self.files.last().expect("begin_file precedes end_file");
        if file.scanned == 0 && !optional {
            self.diagnostics.corrupt_packets += 1;
        }
    }

    /// Absorb a packet whose recovery set has already been checked.
    ///
    /// The budget is charged inside the builder, and only for what the builder
    /// actually keeps.
    fn commit(&mut self, packet: Packet, file: usize) -> Result<()> {
        self.diagnostics.packets_loaded += 1;
        self.files[file].contributed = true;
        if self.builder.add_packet_budgeted(packet, 0, self.budget)? == PacketAdmission::Duplicate {
            self.diagnostics.duplicate_packets += 1;
        }
        Ok(())
    }

    /// Move everything staged into the builder now that the active set is known.
    fn flush_staged(&mut self) -> Result<()> {
        for staged in std::mem::take(&mut self.staged) {
            self.budget.release_bytes(size_of::<StagedPacket>());
            match staged {
                StagedPacket::Held {
                    packet,
                    set_id,
                    bytes,
                    file,
                } => {
                    // Hand back the staging charge; `commit` re-charges for
                    // whatever the builder ends up keeping.
                    self.budget.release_retained(bytes);
                    if self.active_set_id.is_some_and(|active| active != set_id) {
                        self.diagnostics.conflicting_packets += 1;
                        continue;
                    }
                    self.commit(packet, file)?;
                }
                StagedPacket::KnownDuplicate { set_id, file } => {
                    if self.active_set_id.is_some_and(|active| active != set_id) {
                        self.diagnostics.conflicting_packets += 1;
                        continue;
                    }
                    self.diagnostics.packets_loaded += 1;
                    self.diagnostics.duplicate_packets += 1;
                    self.files[file].contributed = true;
                }
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<PacketInventory> {
        // No Main packet anywhere leaves the stage unfiltered; flush it so the
        // builder can report the real reason rather than an empty set.
        self.flush_staged()?;
        self.budget.check_cancelled()?;

        let purge_paths = self
            .files
            .iter()
            .filter(|file| {
                file.purgeable
                    && (file.contributed || !file.path.exists() || is_par2_path(&file.path))
            })
            .map(|file| file.path.clone())
            .collect();

        self.budget.check_cancelled()?;
        let set = self.builder.build()?;
        Ok(PacketInventory {
            set,
            diagnostics: self.diagnostics,
            purge_paths,
        })
    }
}

impl PacketSink for InventoryLoader<'_> {
    fn accept(
        &mut self,
        packet: Packet,
        _offset: u64,
        recovery_set_id: RecoverySetId,
    ) -> Result<()> {
        let file = self.files.len() - 1;
        self.files[file].scanned += 1;

        let newly_active = match (&packet, self.active_set_id) {
            (Packet::Main(main), None) => {
                self.active_set_id = Some(main.recovery_set_id);
                true
            }
            _ => false,
        };

        if let Some(active) = self.active_set_id
            && recovery_set_id != active
        {
            self.diagnostics.conflicting_packets += 1;
            return Ok(());
        }

        if newly_active {
            // Everything staged behind this Main can now be filtered.
            self.flush_staged()?;
        }

        if self.active_set_id.is_some() {
            return self.commit(packet, file);
        }

        // Still waiting on the first Main packet. Stage the packet, unless the
        // builder already holds its key, in which case only the fact of it
        // needs to survive.
        self.budget.charge_bytes(size_of::<StagedPacket>())?;
        crate::packet::budget::reserve_fallible(&mut self.staged, 1)?;
        if self.builder.would_duplicate(&packet) {
            self.staged.push(StagedPacket::KnownDuplicate {
                set_id: recovery_set_id,
                file,
            });
            return Ok(());
        }
        let bytes = packet_retained_bytes(&packet);
        self.budget.charge_retained(bytes)?;
        self.staged.push(StagedPacket::Held {
            packet,
            set_id: recovery_set_id,
            bytes,
            file,
        });
        Ok(())
    }
}

pub(crate) struct RepairState {
    pub(crate) set: Par2FileSet,
    pub(crate) files: Vec<SourceFileEntry>,
    pub(crate) blocks: Vec<SourceBlock>,
    file_index_by_id: HashMap<FileId, usize>,
    block_index_by_file_slice: HashMap<(FileId, u32), usize>,
    hash_table: VerificationHashTable,
    /// Handle serving every [`SourceLocation::Access`] location this state
    /// holds. `None` is the ordinary filesystem-only state.
    pub(crate) source_access: Option<Arc<dyn FileAccess + Send + Sync>>,
    discarded_recovery_blocks: u32,
    inconsistent_packets: u32,
    discarded_recoverable_files: u32,
}

pub(crate) struct RepairInstall {
    pub(crate) install_dir: PathBuf,
    pub(crate) staged_file_ids: HashSet<FileId>,
    pub(crate) bytes_copied: u64,
    pub(crate) bytes_reconstructed: u64,
    pub(crate) validation_bytes: u64,
}

struct RepairStagingGuard {
    path: PathBuf,
    armed: bool,
}

impl RepairStagingGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RepairStagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct RepairExecutionAccess {
    slice_size: u64,
    repair_paths: HashMap<FileId, PathBuf>,
    source_locations: HashMap<(FileId, u32), BlockLocation>,
    source_blocks: HashMap<(FileId, u32), SourceBlock>,
    source_files: HashMap<PathBuf, File>,
    reconstruction_copy_targets: ReconstructionCopyTargets,
    staged_writers: Mutex<HashMap<FileId, File>>,
    /// Handle serving every [`SourceLocation::Access`] location. Absent when
    /// the state has no access-backed sources.
    source_access: Option<Arc<dyn FileAccess + Send + Sync>>,
    source_snapshots: Option<HashMap<PathBuf, CarriedFileStat>>,
    stream_validation: Mutex<HashMap<(FileId, u32), StreamSourceValidation>>,
    validation_bytes: AtomicU64,
}

#[derive(Default)]
struct RepairExecutionContext {
    source_access: Option<Arc<dyn FileAccess + Send + Sync>>,
    source_snapshots: Option<HashMap<PathBuf, CarriedFileStat>>,
    reconstruction_copy_targets: ReconstructionCopyTargets,
}

struct StreamSourceValidation {
    next_offset: u64,
    crc32: Option<Crc32Hasher>,
    last_stripe: Option<(u64, usize, u32)>,
    finalized: bool,
}

impl RepairExecutionAccess {
    fn new(
        install_dir: PathBuf,
        files: &[SourceFileEntry],
        blocks: &[SourceBlock],
        staged_file_ids: &HashSet<FileId>,
        slice_size: u64,
        context: RepairExecutionContext,
    ) -> io::Result<Self> {
        let RepairExecutionContext {
            source_access,
            source_snapshots,
            reconstruction_copy_targets,
        } = context;
        let repair_paths: HashMap<FileId, PathBuf> = files
            .iter()
            .filter(|file| staged_file_ids.contains(&file.file_id))
            .map(|file| (file.file_id, install_dir.join(&file.safe_name)))
            .collect();
        let source_locations: HashMap<(FileId, u32), BlockLocation> = blocks
            .iter()
            .filter_map(|block| {
                block
                    .location
                    .clone()
                    .map(|location| ((block.file_id, block.local_index), location))
            })
            .collect();
        let source_blocks = blocks
            .iter()
            .filter(|block| block.location.is_some())
            .map(|block| ((block.file_id, block.local_index), block.clone()))
            .collect();
        // Only path-backed sources get a file handle. Access-backed sources
        // are read through `source_access` and never opened from disk.
        let source_files = source_locations
            .values()
            .filter_map(|location| location.path().map(Path::to_path_buf))
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|path| {
                File::open(&path)
                    .map(|file| (path.clone(), file))
                    .map_err(|_| source_changed_io(&path))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;
        let staged_writers = repair_paths
            .iter()
            .map(|(file_id, path)| {
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map(|file| (*file_id, file))
            })
            .collect::<io::Result<HashMap<_, _>>>()?;

        Ok(Self {
            slice_size,
            repair_paths,
            source_locations,
            source_blocks,
            source_files,
            reconstruction_copy_targets,
            staged_writers: Mutex::new(staged_writers),
            source_access,
            source_snapshots,
            stream_validation: Mutex::new(HashMap::new()),
            validation_bytes: AtomicU64::new(0),
        })
    }

    /// The handle serving access-backed sources. Reaching an access-backed
    /// location without one is a wiring defect, so it reports as a changed
    /// source rather than silently falling back to disk.
    fn access(&self, file_id: FileId) -> io::Result<&(dyn FileAccess + Send + Sync)> {
        self.source_access
            .as_deref()
            .ok_or_else(|| source_location_changed_io(&SourceLocation::Access(file_id)))
    }

    fn validation_bytes(&self) -> u64 {
        self.validation_bytes.load(Ordering::Relaxed)
    }

    fn ensure_source_unchanged(&self, path: &Path) -> io::Result<()> {
        let Some(snapshots) = self.source_snapshots.as_ref() else {
            return Ok(());
        };
        let Some(expected) = snapshots.get(path) else {
            return Ok(());
        };
        if stat_for_carry(path) == *expected {
            Ok(())
        } else {
            Err(source_changed_io(path))
        }
    }

    fn validate_source_chunk(
        &self,
        file_id: FileId,
        local_slice: u32,
        slice_offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let Some(expected) = self.source_blocks.get(&(file_id, local_slice)) else {
            return Ok(());
        };
        let stripe_crc = checksum::crc32(data);
        let mut states = self
            .stream_validation
            .lock()
            .map_err(|_| io::Error::other("source validation state lock poisoned"))?;
        let state =
            states
                .entry((file_id, local_slice))
                .or_insert_with(|| StreamSourceValidation {
                    next_offset: 0,
                    crc32: Some(Crc32Hasher::new()),
                    last_stripe: None,
                    finalized: false,
                });

        if state.finalized {
            return match state.last_stripe {
                Some((start, len, crc))
                    if start == slice_offset && len == data.len() && crc == stripe_crc =>
                {
                    // GPU fallback replays only the current outer stripe.
                    // Do not advance checksum or accounting twice.
                    Ok(())
                }
                _ => Err(source_location_changed_io(
                    &self.source_locations[&(file_id, local_slice)].source,
                )),
            };
        }
        if slice_offset != state.next_offset {
            return match state.last_stripe {
                Some((start, len, crc))
                    if start == slice_offset && len == data.len() && crc == stripe_crc =>
                {
                    // GPU fallback replays only the current outer stripe.
                    // Do not advance checksum or accounting twice.
                    Ok(())
                }
                _ => Err(source_location_changed_io(
                    &self.source_locations[&(file_id, local_slice)].source,
                )),
            };
        }
        if state.next_offset.saturating_add(data.len() as u64) > expected.expected_len {
            return Err(source_location_changed_io(
                &self.source_locations[&(file_id, local_slice)].source,
            ));
        }
        state
            .crc32
            .as_mut()
            .expect("unfinalized source checksum")
            .update(data);
        self.validation_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        state.last_stripe = Some((slice_offset, data.len(), stripe_crc));
        state.next_offset += data.len() as u64;
        if state.next_offset == expected.expected_len {
            let mut crc32 = state.crc32.take().expect("unfinalized source checksum");
            update_crc_zeros(
                &mut crc32,
                self.slice_size.saturating_sub(expected.expected_len),
            );
            if crc32.finalize() != expected.checksum.crc32 {
                return Err(source_location_changed_io(
                    &self.source_locations[&(file_id, local_slice)].source,
                ));
            }
            state.finalized = true;
        }
        Ok(())
    }

    fn repair_path_for(&self, file_id: &FileId) -> io::Result<&Path> {
        self.repair_paths
            .get(file_id)
            .map(PathBuf::as_path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "repair target not staged"))
    }

    /// Copy one source stripe into its staged destination after the source
    /// bytes have been read and, when requested, checksum-validated. Replays
    /// after a backend fallback write the same positional range again, which
    /// keeps the operation idempotent without rereading the source.
    fn copy_reconstruction_chunk(
        &self,
        file_id: FileId,
        local_slice: u32,
        slice_offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        let Some(target) = self
            .reconstruction_copy_targets
            .get(&(file_id, local_slice))
        else {
            return Ok(());
        };
        let Some(relative_end) = slice_offset.checked_add(data.len() as u64) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reconstruction copy range overflow",
            ));
        };
        if relative_end > target.len {
            return Err(source_location_changed_io(&target.src));
        }
        let dst_offset = target
            .dst_offset
            .checked_add(slice_offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "staged offset overflow"))?;
        let mut writers = self
            .staged_writers
            .lock()
            .map_err(|_| io::Error::other("staged writer lock poisoned"))?;
        let writer = writers.get_mut(&file_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "staged writer handle not cached")
        })?;
        write_all_file_at(writer, data, dst_offset)
    }
}

impl crate::verify::FileAccess for RepairExecutionAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        if offset.is_multiple_of(self.slice_size) {
            let local_slice = u32::try_from(offset / self.slice_size).ok();
            if let Some((location, expected)) = local_slice.and_then(|local_slice| {
                self.source_locations
                    .get(&(*file_id, local_slice))
                    .zip(self.source_blocks.get(&(*file_id, local_slice)))
            }) && len == expected.expected_len
                && location.len == expected.expected_len
            {
                let mut buf = vec![0u8; expected.expected_len as usize];
                match &location.source {
                    SourceLocation::Path(path) => {
                        self.ensure_source_unchanged(path)?;
                        let file = self.source_files.get(path).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "source file handle not cached")
                        })?;
                        read_exact_file_at(file, &mut buf, location.offset)
                            .map_err(|_| source_changed_io(path))?;
                        let file_len = file
                            .metadata()
                            .ok()
                            .map_or(location.len, |metadata| metadata.len());
                        crate::file_cache::drop_touched_file_cache(
                            file,
                            path,
                            file_len,
                            location.offset,
                            buf.len() as u64,
                        );
                    }
                    SourceLocation::Access(source_id) => {
                        read_exact_from_access(
                            self.access(*source_id)?,
                            source_id,
                            location.offset,
                            &mut buf,
                        )
                        .map_err(|_| source_location_changed_io(&location.source))?;
                    }
                }
                let mut checksum = checksum::SliceChecksumState::new();
                checksum.update(&buf);
                let (crc32, md5) = checksum.finalize(Some(self.slice_size));
                if crc32 != expected.checksum.crc32 || md5 != expected.checksum.md5 {
                    return Err(source_location_changed_io(&location.source));
                }
                self.validation_bytes
                    .fetch_add(buf.len() as u64, Ordering::Relaxed);
                let local_slice = u32::try_from(offset / self.slice_size).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "source slice index overflow")
                })?;
                self.copy_reconstruction_chunk(*file_id, local_slice, 0, &buf)?;
                return Ok(buf);
            }
        }
        let requested = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read range too large"))?;
        let mut buf = Vec::with_capacity(requested);
        let mut current_offset = offset;
        while buf.len() < requested {
            let slice_offset = current_offset % self.slice_size;
            let chunk_len =
                (self.slice_size - slice_offset).min((requested - buf.len()) as u64) as usize;
            if chunk_len == 0 {
                break;
            }
            let start = buf.len();
            buf.resize(start + chunk_len, 0);
            let read_len = self.read_file_range_into(
                file_id,
                current_offset,
                &mut buf[start..start + chunk_len],
            )?;
            buf.truncate(start + read_len);
            if read_len == 0 {
                break;
            }
            current_offset += read_len as u64;
        }
        Ok(buf)
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        if let Some(slice_index) = offset.checked_div(self.slice_size) {
            let local_slice = slice_index as u32;
            let slice_offset = offset % self.slice_size;
            if let Some(location) = self.source_locations.get(&(*file_id, local_slice)) {
                if slice_offset >= location.len {
                    if let SourceLocation::Path(path) = &location.source {
                        self.ensure_source_unchanged(path)?;
                    }
                    return Ok(0);
                }
                let len = (dst.len() as u64).min(location.len - slice_offset) as usize;
                let read_offset = location.offset + slice_offset;
                match &location.source {
                    SourceLocation::Path(path) => {
                        self.ensure_source_unchanged(path)?;
                        let file = self.source_files.get(path).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "source file handle not cached")
                        })?;
                        // `read_exact_file_at`, not a bare `read_file_at` plus a
                        // length check: a positional read may legally come back
                        // short, and `fd_pread` under wasmtime always does above
                        // 64 KiB (on *both* wasm targets — see
                        // `disk::read_filled`). Treating that as a changed source
                        // would abort reconstruction on any set whose slice size
                        // exceeds the host's cap. The loop keeps the same
                        // "anything less than a full fill is a changed source"
                        // outcome for a genuinely truncated file.
                        read_exact_file_at(file, &mut dst[..len], read_offset)
                            .map_err(|_| source_changed_io(path))?;
                        let read = len;
                        let file_len = file
                            .metadata()
                            .ok()
                            .map_or(location.len, |metadata| metadata.len());
                        crate::file_cache::drop_touched_file_cache(
                            file,
                            path,
                            file_len,
                            read_offset,
                            read as u64,
                        );
                    }
                    SourceLocation::Access(source_id) => {
                        read_exact_from_access(
                            self.access(*source_id)?,
                            source_id,
                            read_offset,
                            &mut dst[..len],
                        )
                        .map_err(|_| source_location_changed_io(&location.source))?;
                    }
                }
                self.validate_source_chunk(*file_id, local_slice, slice_offset, &dst[..len])?;
                self.copy_reconstruction_chunk(*file_id, local_slice, slice_offset, &dst[..len])?;
                return Ok(len);
            }
        }

        let path = self.repair_path_for(file_id)?;
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(offset))?;
        let read = crate::disk::read_filled(&mut file, dst)?;
        crate::file_cache::drop_touched_file_cache(&file, path, file_len, offset, read as u64);
        Ok(read)
    }

    fn open_sequential_reader(
        &self,
        file_id: &FileId,
    ) -> io::Result<Option<Box<dyn std::io::Read>>> {
        if self
            .source_locations
            .keys()
            .any(|(source_file_id, _)| source_file_id == file_id)
        {
            return Ok(None);
        }

        Ok(Some(Box::new(crate::file_cache::CacheAdvisedReader::open(
            self.repair_path_for(file_id)?,
        )?)))
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        self.repair_paths
            .get(file_id)
            .is_some_and(|path| path.exists())
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        self.repair_paths
            .get(file_id)
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        crate::file_cache::read_to_vec(self.repair_path_for(file_id)?)
    }

    fn write_file_range(&mut self, file_id: &FileId, offset: u64, data: &[u8]) -> io::Result<()> {
        let path = self.repair_path_for(file_id)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut writers = self
            .staged_writers
            .lock()
            .map_err(|_| io::Error::other("staged writer lock poisoned"))?;
        let file = writers.get_mut(file_id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "staged writer handle not cached")
        })?;
        write_all_file_at(file, data, offset)
    }
}

#[cfg(unix)]
fn read_file_at(file: &File, dst: &mut [u8], offset: u64) -> io::Result<usize> {
    file.read_at(dst, offset)
}

#[cfg(unix)]
fn write_file_at(file: &File, src: &[u8], offset: u64) -> io::Result<usize> {
    file.write_at(src, offset)
}

#[cfg(windows)]
fn write_file_at(file: &File, src: &[u8], offset: u64) -> io::Result<usize> {
    file.seek_write(src, offset)
}

/// Positional write on wasi, via `libc::pwrite`.
///
/// The previous portable fallback (`try_clone` + `seek` + `write`) could never
/// succeed here: `File::try_clone` is `Unsupported` on wasip1, so every staged
/// repair write failed at the first call. `pwrite` is both correct and a closer
/// match to the `unix` arm — it does not disturb the handle's seek cursor,
/// which is the property the shared-handle callers rely on.
#[cfg(target_os = "wasi")]
fn write_file_at(file: &File, src: &[u8], offset: u64) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    // SAFETY: `src` is a valid initialized slice of `src.len()` bytes and the
    // fd is owned by `file`, which outlives the call.
    let written = unsafe {
        libc::pwrite(
            file.as_raw_fd(),
            src.as_ptr().cast::<libc::c_void>(),
            src.len(),
            offset as libc::off_t,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(written as usize)
}

#[cfg(not(any(unix, windows, target_os = "wasi")))]
fn write_file_at(file: &File, src: &[u8], offset: u64) -> io::Result<usize> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(offset))?;
    cloned.write(src)
}

fn write_all_file_at(file: &File, mut src: &[u8], mut offset: u64) -> io::Result<()> {
    while !src.is_empty() {
        let written = write_file_at(file, src, offset)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write the complete staged range",
            ));
        }
        src = &src[written..];
        offset += written as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn read_file_at(file: &File, dst: &mut [u8], offset: u64) -> io::Result<usize> {
    file.seek_read(dst, offset)
}

/// Positional read on wasi, via `libc::pread`; see [`write_file_at`] for why
/// the `try_clone` fallback is unusable on this target.
#[cfg(target_os = "wasi")]
fn read_file_at(file: &File, dst: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::fd::AsRawFd;

    // SAFETY: `dst` is a valid writable slice of `dst.len()` bytes and the fd is
    // owned by `file`, which outlives the call.
    let read = unsafe {
        libc::pread(
            file.as_raw_fd(),
            dst.as_mut_ptr().cast::<libc::c_void>(),
            dst.len(),
            offset as libc::off_t,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

#[cfg(not(any(unix, windows, target_os = "wasi")))]
fn read_file_at(file: &File, dst: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(offset))?;
    cloned.read(dst)
}

/// Positional `read_exact`: fills `dst` from `offset` without relying on the
/// handle's seek cursor, so parallel scan segments can share one handle.
fn read_exact_file_at(file: &File, mut dst: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !dst.is_empty() {
        match read_file_at(file, dst, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(read) => {
                dst = &mut dst[read..];
                offset += read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) struct RepairVerificationAccess {
    paths: HashMap<FileId, PathBuf>,
    /// Handle serving files that were *not* staged for repair. Present only
    /// for access-backed states, where an unstaged file's bytes were never on
    /// disk and reading its `safe_path` would read whatever else lives there.
    unstaged_access: Option<Arc<dyn FileAccess + Send + Sync>>,
}

impl RepairVerificationAccess {
    pub(crate) fn new(
        files: &[SourceFileEntry],
        install_dir: &Path,
        staged_file_ids: &HashSet<FileId>,
        unstaged_access: Option<Arc<dyn FileAccess + Send + Sync>>,
    ) -> Self {
        let paths = files
            .iter()
            .filter(|file| unstaged_access.is_none() || staged_file_ids.contains(&file.file_id))
            .map(|file| {
                let path = if staged_file_ids.contains(&file.file_id) {
                    install_dir.join(&file.safe_name)
                } else {
                    file.safe_path.clone()
                };
                (file.file_id, path)
            })
            .collect();

        Self {
            paths,
            unstaged_access,
        }
    }

    fn path_for(&self, file_id: &FileId) -> io::Result<&Path> {
        self.paths
            .get(file_id)
            .map(PathBuf::as_path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file ID"))
    }

    /// The serving handle for a file that has no staged output. Only an
    /// access-backed verification has one; otherwise the file is on disk.
    fn unstaged(&self, file_id: &FileId) -> Option<&(dyn FileAccess + Send + Sync)> {
        if self.paths.contains_key(file_id) {
            return None;
        }
        self.unstaged_access.as_deref()
    }
}

impl crate::verify::FileAccess for RepairVerificationAccess {
    fn read_file_range(&self, file_id: &FileId, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        if let Some(access) = self.unstaged(file_id) {
            return access.read_file_range(file_id, offset, len);
        }
        let path = self.path_for(file_id)?;
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len as usize];
        let read_len = crate::disk::read_filled(&mut file, &mut buf)?;
        crate::file_cache::drop_touched_file_cache(&file, path, file_len, offset, read_len as u64);
        buf.truncate(read_len);
        Ok(buf)
    }

    fn read_file_range_into(
        &self,
        file_id: &FileId,
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<usize> {
        if let Some(access) = self.unstaged(file_id) {
            return access.read_file_range_into(file_id, offset, dst);
        }
        let path = self.path_for(file_id)?;
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(offset))?;
        let read = crate::disk::read_filled(&mut file, dst)?;
        crate::file_cache::drop_touched_file_cache(&file, path, file_len, offset, read as u64);
        Ok(read)
    }

    fn open_sequential_reader(
        &self,
        file_id: &FileId,
    ) -> io::Result<Option<Box<dyn std::io::Read>>> {
        if self.unstaged(file_id).is_some() {
            return Ok(None);
        }
        Ok(Some(Box::new(crate::file_cache::CacheAdvisedReader::open(
            self.path_for(file_id)?,
        )?)))
    }

    fn file_exists(&self, file_id: &FileId) -> bool {
        if let Some(access) = self.unstaged(file_id) {
            return access.file_exists(file_id);
        }
        self.paths.get(file_id).is_some_and(|path| path.exists())
    }

    fn file_length(&self, file_id: &FileId) -> Option<u64> {
        if let Some(access) = self.unstaged(file_id) {
            return access.file_length(file_id);
        }
        self.paths
            .get(file_id)
            .and_then(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
    }

    fn read_file(&self, file_id: &FileId) -> io::Result<Vec<u8>> {
        if let Some(access) = self.unstaged(file_id) {
            return access.read_file(file_id);
        }
        crate::file_cache::read_to_vec(self.path_for(file_id)?)
    }

    fn write_file_range(
        &mut self,
        _file_id: &FileId,
        _offset: u64,
        _data: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "verification access is read-only",
        ))
    }
}

impl RepairState {
    /// Conservative preflight estimate used before allocating the retained
    /// block map and verification hash table.
    pub(crate) fn estimated_retained_bytes_from_set(base_dir: &Path, set: &Par2FileSet) -> usize {
        let recoverable_blocks = set
            .recovery_file_ids
            .iter()
            .filter_map(|file_id| set.slice_checksums.get(file_id))
            .fold(0usize, |total, checksums| {
                total.saturating_add(checksums.len())
            });
        let recoverable_files = set.recovery_file_ids.len();
        let mut bytes = std::mem::size_of::<Self>()
            .saturating_add(std::mem::size_of::<Par2FileSet>())
            .saturating_add(
                recoverable_files.saturating_mul(
                    std::mem::size_of::<SourceFileEntry>()
                        .saturating_add(std::mem::size_of::<(FileId, usize)>() * 2),
                ),
            )
            .saturating_add(
                recoverable_blocks.saturating_mul(
                    std::mem::size_of::<SourceBlock>()
                        .saturating_add(std::mem::size_of::<((FileId, u32), usize)>() * 2)
                        .saturating_add(std::mem::size_of::<(u32, Vec<usize>)>() * 2)
                        .saturating_add(std::mem::size_of::<usize>()),
                ),
            )
            .saturating_add(
                set.recovery_file_ids
                    .len()
                    .saturating_mul(std::mem::size_of::<FileId>()),
            )
            .saturating_add(
                set.non_recovery_file_ids
                    .len()
                    .saturating_mul(std::mem::size_of::<FileId>()),
            )
            .saturating_add(
                set.files
                    .len()
                    .saturating_mul(std::mem::size_of::<(FileId, FileDescription)>() * 2),
            )
            .saturating_add(
                set.slice_checksums
                    .len()
                    .saturating_mul(std::mem::size_of::<(FileId, Vec<SliceChecksum>)>() * 2),
            );

        for description in set.files.values() {
            bytes = bytes
                .saturating_add(description.par2_name.len())
                .saturating_add(description.filename.len())
                .saturating_add(description.filename.len())
                .saturating_add(base_dir.as_os_str().len())
                .saturating_add(1);
        }
        for checksums in set.slice_checksums.values() {
            bytes = bytes.saturating_add(
                checksums
                    .len()
                    .saturating_mul(std::mem::size_of::<SliceChecksum>()),
            );
        }
        for recovery in set.recovery_slices.values() {
            bytes = bytes
                .saturating_add(std::mem::size_of_val(recovery).saturating_mul(2))
                .saturating_add(match recovery.data.as_bytes() {
                    Some(data) => data.len(),
                    None => recovery
                        .data
                        .file_span()
                        .map_or(0, |(path, _, _)| path.as_os_str().len()),
                });
        }
        if let Some(creator) = &set.creator {
            bytes = bytes.saturating_add(creator.len());
        }
        bytes
    }

    pub(crate) fn from_set(base_dir: &Path, set: Par2FileSet) -> Result<Self> {
        Self::from_set_with_access(base_dir, set, None)
    }

    /// Build a state whose sources are served by `source_access` instead of
    /// (or alongside) the filesystem. `base_dir` still names where repair
    /// *output* lands; only source reads change.
    pub(crate) fn from_set_with_access(
        base_dir: &Path,
        mut set: Par2FileSet,
        source_access: Option<Arc<dyn FileAccess + Send + Sync>>,
    ) -> Result<Self> {
        let mut discarded_recovery_blocks = 0;
        let slice_size = set.slice_size;
        set.recovery_slices.retain(|_, recovery| {
            let keep = recovery.data.len() as u64 == slice_size;
            if !keep {
                discarded_recovery_blocks += 1;
            }
            keep
        });

        let mut inconsistent_packets = 0;
        let mut discarded_recoverable_files = 0;
        let mut files = Vec::new();
        let mut blocks = Vec::new();
        let mut file_index_by_id = HashMap::new();
        let mut block_index_by_file_slice = HashMap::new();

        for file_id in set
            .recovery_file_ids
            .iter()
            .chain(set.non_recovery_file_ids.iter())
        {
            let recoverable = set.recovery_file_ids.contains(file_id);
            let Some(desc) = set.files.get(file_id) else {
                inconsistent_packets += 1;
                if recoverable {
                    discarded_recoverable_files += 1;
                }
                continue;
            };
            let safe_path = base_dir.join(&desc.filename);
            let first_block = blocks.len();
            let expected_blocks =
                usize::try_from(set.slice_count_for_file(desc.length)).map_err(|_| {
                    Par2Error::ResourceLimitExceeded {
                        reason: format!(
                            "file {} has more than {MAX_SLICES_PER_FILE} addressable PAR2 slices",
                            desc.filename
                        ),
                    }
                })?;
            if expected_blocks > MAX_SLICES_PER_FILE {
                return Err(Par2Error::ResourceLimitExceeded {
                    reason: format!(
                        "file {} has {expected_blocks} PAR2 slices; max is {MAX_SLICES_PER_FILE}",
                        desc.filename
                    ),
                });
            }
            let mut block_count = 0usize;

            if recoverable {
                if expected_blocks == 0 {
                    // Zero-length files have no IFSC entries but still need a
                    // source entry so repair can create/verify the target.
                } else if let Some(checksum_count) = set
                    .slice_checksums
                    .get(file_id)
                    .map(|checksums| checksums.len())
                {
                    if checksum_count != expected_blocks {
                        // A bad IFSC packet is unusable block metadata, not
                        // proof that the described file can be ignored.
                        set.slice_checksums.remove(file_id);
                        inconsistent_packets += 1;
                    } else if let Some(checksums) = set.slice_checksums.get(file_id) {
                        block_count = checksums.len();
                        for (local_index, checksum) in checksums.iter().enumerate() {
                            let offset = local_index as u64 * slice_size;
                            let expected_len = desc.length.saturating_sub(offset).min(slice_size);
                            let global_index = blocks.len();
                            block_index_by_file_slice
                                .insert((*file_id, local_index as u32), global_index);
                            blocks.push(SourceBlock {
                                global_index,
                                file_id: *file_id,
                                local_index: local_index as u32,
                                expected_len,
                                checksum: *checksum,
                                location: None,
                            });
                        }
                    }
                } else {
                    // A missing IFSC packet removes block-scanner evidence for
                    // this file, but FileDesc still permits exact full-hash
                    // verification and RS output.
                    inconsistent_packets += 1;
                }
            }

            let entry = SourceFileEntry {
                file_id: *file_id,
                par2_name: desc.par2_name.clone(),
                safe_path,
                safe_name: desc.filename.clone(),
                length: desc.length,
                hash_full: desc.hash_full,
                hash_16k: desc.hash_16k,
                recoverable,
                first_block,
                expected_block_count: if recoverable { expected_blocks } else { 0 },
                block_count: if recoverable { block_count } else { 0 },
                target_exists: false,
                complete_location: None,
                non_canonical_complete_source_count: 0,
            };
            file_index_by_id.insert(*file_id, files.len());
            files.push(entry);
        }

        let hash_table = VerificationHashTable::new(&blocks, slice_size);

        Ok(Self {
            set,
            files,
            blocks,
            file_index_by_id,
            block_index_by_file_slice,
            hash_table,
            source_access,
            discarded_recovery_blocks,
            inconsistent_packets,
            discarded_recoverable_files,
        })
    }

    /// Conservative heap bytes that may be added when a complete source
    /// location is cloned into the file entry and each of its block locations.
    /// An access-backed source owns no heap, so its budget is zero — which is
    /// the honest number, not a placeholder.
    pub(crate) fn complete_location_budget(
        &self,
        file_id: FileId,
        source: &SourceLocation,
    ) -> Option<usize> {
        let file = &self.files[*self.file_index_by_id.get(&file_id)?];
        file.recoverable.then(|| {
            source
                .heap_bytes()
                .saturating_mul(file.block_count.saturating_add(1))
        })
    }

    /// Conservative heap bytes that may be added for one slice location.
    pub(crate) fn block_location_budget(
        &self,
        file_id: FileId,
        local_index: u32,
        source: &SourceLocation,
    ) -> Option<usize> {
        self.block_index_by_file_slice
            .contains_key(&(file_id, local_index))
            .then_some(source.heap_bytes())
    }

    /// Seed a complete, independently committed source. The retained-session
    /// caller is responsible for checking its evidence before calling this;
    /// repair-time validation still checks every byte that is later consumed.
    pub(crate) fn seed_complete_location(
        &mut self,
        file_id: FileId,
        source: SourceLocation,
    ) -> bool {
        let Some(file_index) = self.file_index_by_id.get(&file_id).copied() else {
            return false;
        };
        let (recoverable, length, first_block, block_count, canonical) = {
            let file = &self.files[file_index];
            (
                file.recoverable,
                file.length,
                file.first_block,
                file.block_count,
                source.is_canonical_for(file),
            )
        };
        if !recoverable {
            return false;
        }
        let kind = if canonical {
            BlockLocationKind::Canonical
        } else {
            BlockLocationKind::Extra
        };
        self.files[file_index].complete_location = Some(BlockLocation {
            source: source.clone(),
            offset: 0,
            len: length,
            kind,
        });
        for block_index in first_block..first_block + block_count {
            let block = &self.blocks[block_index];
            self.record_block_location(
                block_index,
                BlockLocation {
                    source: source.clone(),
                    offset: block.local_index as u64 * self.set.slice_size,
                    len: block.expected_len,
                    kind,
                },
            );
        }
        true
    }

    /// Seed one IFSC-verified source slice. This never promotes a file to a
    /// whole-file match: only a full committed hash may do that.
    pub(crate) fn seed_block_location(
        &mut self,
        file_id: FileId,
        local_index: u32,
        source: SourceLocation,
    ) -> bool {
        let Some(block_index) = self
            .block_index_by_file_slice
            .get(&(file_id, local_index))
            .copied()
        else {
            return false;
        };
        let file = &self.files[*self
            .file_index_by_id
            .get(&file_id)
            .expect("block file exists")];
        let block = &self.blocks[block_index];
        let kind = if source.is_canonical_for(file) {
            BlockLocationKind::Canonical
        } else {
            BlockLocationKind::Extra
        };
        self.record_block_location(
            block_index,
            BlockLocation {
                source,
                offset: local_index as u64 * self.set.slice_size,
                len: block.expected_len,
                kind,
            },
        );
        true
    }

    /// Forget every retained location belonging to one PAR2 file, whichever
    /// kind of source backs it. Packet metadata and other files stay intact,
    /// so the next analysis re-resolves only what this dropped.
    pub(crate) fn invalidate_file(&mut self, file_id: FileId) -> bool {
        let Some(file_index) = self.file_index_by_id.get(&file_id).copied() else {
            return false;
        };
        let mut changed = false;
        let file = &mut self.files[file_index];
        if file.complete_location.take().is_some() {
            changed = true;
        }
        file.target_exists = false;
        file.non_canonical_complete_source_count = 0;
        let (first_block, block_count) = (file.first_block, file.block_count);
        for block in &mut self.blocks[first_block..first_block + block_count] {
            if block.location.take().is_some() {
                changed = true;
            }
        }
        changed
    }

    /// Forget every access-backed location, leaving physical ones untouched.
    /// Used when the handle's coverage generation moves on.
    pub(crate) fn invalidate_access_sources(&mut self) -> bool {
        let mut changed = false;
        for file in &mut self.files {
            if file
                .complete_location
                .as_ref()
                .is_some_and(|location| location.source.is_access())
            {
                file.complete_location = None;
                file.non_canonical_complete_source_count = 0;
                changed = true;
            }
        }
        for block in &mut self.blocks {
            if block
                .location
                .as_ref()
                .is_some_and(|location| location.source.is_access())
            {
                block.location = None;
                changed = true;
            }
        }
        changed
    }

    /// Promote every access-backed file whose slices are all seeded, and mark
    /// existence from the serving handle. This is the access counterpart of
    /// [`Self::refresh_file_states`] and touches no filesystem path: a
    /// directory walk over virtual sources would be meaningless.
    pub(crate) fn refresh_access_file_states(&mut self) {
        let Some(access) = self.source_access.clone() else {
            return;
        };
        for file_index in 0..self.files.len() {
            let file_id = self.files[file_index].file_id;
            self.files[file_index].target_exists = access.file_exists(&file_id);
            if !self.files[file_index].recoverable
                || self.files[file_index].complete_location.is_some()
            {
                continue;
            }
            let file = &self.files[file_index];
            if file.block_count == 0 || file.block_count != file.expected_block_count {
                continue;
            }
            let complete = (0..file.block_count).all(|local| {
                let block = &self.blocks[file.first_block + local];
                block.location.as_ref().is_some_and(|location| {
                    location.source == SourceLocation::Access(file_id)
                        && location.offset == local as u64 * self.set.slice_size
                        && location.len == block.expected_len
                })
            });
            if complete {
                let length = file.length;
                self.files[file_index].complete_location = Some(BlockLocation {
                    source: SourceLocation::Access(file_id),
                    offset: 0,
                    len: length,
                    kind: BlockLocationKind::Canonical,
                });
            }
        }
    }

    pub(crate) fn invalidate_path(&mut self, path: &Path) -> bool {
        let mut changed = false;
        for file in &mut self.files {
            if file
                .complete_location
                .as_ref()
                .is_some_and(|location| location.source.is_path(path))
            {
                file.complete_location = None;
                changed = true;
            }
            if file.safe_path == path {
                file.target_exists = false;
            }
        }
        for block in &mut self.blocks {
            if block
                .location
                .as_ref()
                .is_some_and(|location| location.source.is_path(path))
            {
                block.location = None;
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn invalidate_all_sources(&mut self) {
        for file in &mut self.files {
            file.complete_location = None;
            file.target_exists = false;
            file.non_canonical_complete_source_count = 0;
        }
        for block in &mut self.blocks {
            block.location = None;
        }
    }

    /// Conservative accounting for memory retained by a stateful session.
    /// File-backed recovery packets count only their owned path metadata, not
    /// their on-disk payload; in-memory recovery packets count their bytes.
    pub(crate) fn estimated_retained_bytes(&self) -> usize {
        self.estimated_retained_bytes_with_set(&self.set)
    }

    pub(crate) fn estimated_retained_bytes_with_set(&self, set: &Par2FileSet) -> usize {
        let mut bytes = std::mem::size_of::<Self>()
            .saturating_add(
                self.files
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceFileEntry>()),
            )
            .saturating_add(
                self.blocks
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SourceBlock>()),
            )
            .saturating_add(
                self.file_index_by_id
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(FileId, usize)>()),
            )
            .saturating_add(
                self.block_index_by_file_slice
                    .capacity()
                    .saturating_mul(std::mem::size_of::<((FileId, u32), usize)>()),
            )
            .saturating_add(
                set.recovery_file_ids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<FileId>()),
            )
            .saturating_add(
                set.non_recovery_file_ids
                    .capacity()
                    .saturating_mul(std::mem::size_of::<FileId>()),
            )
            .saturating_add(
                set.files
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(FileId, FileDescription)>()),
            )
            .saturating_add(
                set.slice_checksums
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(FileId, Vec<SliceChecksum>)>()),
            )
            .saturating_add(self.hash_table.estimated_retained_bytes());
        for file in &self.files {
            bytes = bytes
                .saturating_add(file.par2_name.capacity())
                .saturating_add(file.safe_name.capacity())
                .saturating_add(file.safe_path.as_os_str().len())
                .saturating_add(
                    file.complete_location
                        .as_ref()
                        .map_or(0, |location| location.source.heap_bytes()),
                );
        }
        for block in &self.blocks {
            bytes = bytes.saturating_add(
                block
                    .location
                    .as_ref()
                    .map_or(0, |location| location.source.heap_bytes()),
            );
        }
        for recovery in set.recovery_slices.values() {
            bytes = bytes
                .saturating_add(std::mem::size_of_val(recovery).saturating_mul(2))
                .saturating_add(match recovery.data.as_bytes() {
                    Some(data) => data.len(),
                    None => recovery
                        .data
                        .file_span()
                        .map_or(0, |(path, _, _)| path.as_os_str().len()),
                });
        }
        for description in set.files.values() {
            bytes = bytes
                .saturating_add(std::mem::size_of_val(description).saturating_mul(2))
                .saturating_add(description.par2_name.capacity())
                .saturating_add(description.filename.capacity());
        }
        for checksums in set.slice_checksums.values() {
            bytes = bytes.saturating_add(
                checksums
                    .capacity()
                    .saturating_mul(std::mem::size_of::<SliceChecksum>()),
            );
        }
        if let Some(creator) = &set.creator {
            bytes = bytes.saturating_add(creator.capacity());
        }
        bytes
    }

    fn sources_resolved(&self) -> bool {
        self.files
            .iter()
            .filter(|file| file.recoverable)
            .all(|file| {
                file.complete_location.is_some()
                    || (file.block_count == file.expected_block_count
                        && (0..file.block_count)
                            .all(|local| self.blocks[file.first_block + local].location.is_some()))
            })
    }

    /// Scan only files that do not already have committed whole-file or
    /// per-slice evidence. This is deliberately separate from `scan`, which
    /// remains the one-shot scanner and preserves its existing behaviour.
    ///
    /// `trust` names the seeded slice verdicts whose byte ranges this pass may
    /// take on trust rather than re-read. It is empty unless the host opted in,
    /// and an empty plan makes this function read exactly what it read before
    /// the policy existed.
    pub(crate) fn scan_unresolved(
        &mut self,
        options: &Par2RepairerOptions,
        trust: &EvidenceScanTrust,
    ) -> Result<ScanDiagnostics> {
        let mut diagnostics = ScanDiagnostics::default();
        let mut canonical_candidates = self
            .files
            .iter()
            .filter(|file| file.recoverable && file.complete_location.is_none())
            .filter(|file| {
                file.block_count == 0
                    || (0..file.block_count)
                        .any(|local| self.blocks[file.first_block + local].location.is_none())
            })
            .map(|file| ScanCandidate {
                path: file.safe_path.clone(),
                kind: BlockLocationKind::Canonical,
            })
            .collect::<Vec<_>>();
        canonical_candidates.sort_by(|left, right| left.path.cmp(&right.path));
        canonical_candidates.dedup_by(|left, right| left.path == right.path);
        self.scan_candidates(options, &canonical_candidates, &mut diagnostics, trust)?;

        self.refresh_file_states();
        if self.sources_resolved() {
            return Ok(diagnostics);
        }

        let source_file_keys: HashSet<PathBuf> = self
            .files
            .iter()
            .map(|file| canonical_extra_path(&file.safe_path))
            .collect();
        let mut extra_candidates = BTreeMap::new();
        for path in discover_candidate_files(&options.base_dir)? {
            extra_candidates
                .entry(canonical_extra_path(&path))
                .or_insert(path);
        }
        for path in &options.extra_paths {
            if !has_par2_marker(path)
                && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
            {
                let canonical = canonical_extra_path(path);
                extra_candidates.insert(canonical.clone(), canonical);
            }
        }
        let extra_candidates = extra_candidates
            .into_iter()
            .filter_map(|(key, path)| {
                (!source_file_keys.contains(&key)).then_some(ScanCandidate {
                    path,
                    kind: BlockLocationKind::Extra,
                })
            })
            .collect::<Vec<_>>();
        // Extra candidates are, by construction, paths no source file claims,
        // so no seeded verdict can name one. The empty plan states that rather
        // than relying on the lookup to miss.
        self.scan_candidates(
            options,
            &extra_candidates,
            &mut diagnostics,
            &EvidenceScanTrust::default(),
        )?;
        self.refresh_file_states();
        Ok(diagnostics)
    }

    fn scan(&mut self, options: &Par2RepairerOptions) -> Result<ScanDiagnostics> {
        let mut diagnostics = ScanDiagnostics::default();
        let mut canonical_candidates = self
            .files
            .iter()
            .map(|file| ScanCandidate {
                path: file.safe_path.clone(),
                kind: BlockLocationKind::Canonical,
            })
            .collect::<Vec<_>>();
        canonical_candidates.sort_by(|left, right| left.path.cmp(&right.path));
        canonical_candidates.dedup_by(|left, right| left.path == right.path);
        // The one-shot repairer holds no seeded evidence: nothing is located
        // before it starts, so there is nothing for a skip policy to skip.
        self.scan_candidates(
            options,
            &canonical_candidates,
            &mut diagnostics,
            &EvidenceScanTrust::default(),
        )?;

        self.refresh_file_states();
        if self.files_are_canonical_complete() {
            return Ok(diagnostics);
        }

        let source_file_keys: HashSet<PathBuf> = self
            .files
            .iter()
            .map(|file| canonical_extra_path(&file.safe_path))
            .collect();
        let mut extra_candidates = BTreeMap::new();
        for path in discover_candidate_files(&options.base_dir)? {
            extra_candidates
                .entry(canonical_extra_path(&path))
                .or_insert(path);
        }
        for path in &options.extra_paths {
            if !has_par2_marker(path) {
                let Ok(metadata) = fs::symlink_metadata(path) else {
                    continue;
                };
                if !metadata.file_type().is_file() {
                    continue;
                }
                let canonical = canonical_extra_path(path);
                extra_candidates.insert(canonical.clone(), canonical);
            }
        }

        let extra_candidates = extra_candidates
            .into_iter()
            .filter_map(|(key, path)| {
                (!source_file_keys.contains(&key)).then_some(ScanCandidate {
                    path,
                    kind: BlockLocationKind::Extra,
                })
            })
            .collect::<Vec<_>>();
        self.scan_candidates(
            options,
            &extra_candidates,
            &mut diagnostics,
            &EvidenceScanTrust::default(),
        )?;

        self.refresh_file_states();
        Ok(diagnostics)
    }

    fn scan_candidates(
        &mut self,
        options: &Par2RepairerOptions,
        candidates: &[ScanCandidate],
        diagnostics: &mut ScanDiagnostics,
        trust: &EvidenceScanTrust,
    ) -> Result<()> {
        if candidates.is_empty() {
            return Ok(());
        }

        let baseline_blocks = &self.blocks;
        let files = &self.files;
        let file_index_by_id = &self.file_index_by_id;
        let block_index_by_file_slice = &self.block_index_by_file_slice;
        let hash_table = &self.hash_table;
        let slice_size = self.set.slice_size;

        // Parallelism runs on exactly one axis: across candidates here, or
        // inside a single candidate's scan — never both (nested fan-out
        // measured as an intermittent worker stack overflow via rayon's
        // steal-on-block recursion).
        //
        // `parallel_enabled()` const-folds to `true` on native (the guard is
        // unchanged). On wasm it is a cached runtime probe: `false` on
        // single-threaded `wasm32-wasip1`, so the candidate scan is sequential
        // there and `rayon::current_num_threads` is never called; `true` on
        // `wasm32-wasip1-threads`, where the candidate fan-out is real.
        let results = if reedsolomon_rs::threading::parallel_enabled()
            && candidates.len() > 1
            && rayon::current_num_threads() > 1
        {
            candidates
                .par_iter()
                .map(|candidate| {
                    Self::scan_candidate_snapshot(
                        options,
                        candidate,
                        files,
                        file_index_by_id,
                        block_index_by_file_slice,
                        baseline_blocks,
                        hash_table,
                        slice_size,
                        false,
                        trust,
                    )
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            candidates
                .iter()
                .map(|candidate| {
                    Self::scan_candidate_snapshot(
                        options,
                        candidate,
                        files,
                        file_index_by_id,
                        block_index_by_file_slice,
                        baseline_blocks,
                        hash_table,
                        slice_size,
                        true,
                        trust,
                    )
                })
                .collect::<Result<Vec<_>>>()?
        };

        let mut relocation_targets = Vec::new();
        for result in results {
            if let Some(target) = result.short_relocation_target() {
                relocation_targets.push(target);
            }
            self.apply_scan_result(result, diagnostics);
        }
        self.relocate_open_short_blocks(options, &relocation_targets, diagnostics)?;

        Ok(())
    }

    /// Exhaustive short-block relocation, run once per candidate batch over the
    /// merged scan state.
    ///
    /// Every candidate above scans a private pre-merge snapshot, so a candidate
    /// cannot see that another candidate has already placed a short block.
    /// Searching for relocated short blocks inside that phase therefore made
    /// every candidate sweep its whole file once per distinct short length in
    /// the set — quadratic in set size, and reached in both passes, because a
    /// fully obfuscated download makes every file an extra candidate. Deferring
    /// the search to the merged state searches only for blocks that are still
    /// open, and only inside candidates the merged state cannot already account
    /// for byte-for-byte.
    ///
    /// The search itself is unchanged, and so is its reach into candidates
    /// that still hold unexplained bytes: a short block shifted inside,
    /// concatenated into, or otherwise relocated within one is still found.
    /// Only a block duplicated inside a candidate the merged state already
    /// explains in full goes unsalvaged, and that costs a recovery block, not
    /// the data.
    fn relocate_open_short_blocks(
        &mut self,
        options: &Par2RepairerOptions,
        targets: &[ShortRelocationTarget],
        diagnostics: &mut ScanDiagnostics,
    ) -> Result<()> {
        if targets.is_empty() || self.hash_table.short_blocks.is_empty() {
            return Ok(());
        }

        let started = Instant::now();
        let mut candidates_scanned = 0u32;
        let mut candidates_skipped = 0u32;
        let mut totals = ShortRelocationStats::default();
        let mut open_short_block_count;

        let changed = {
            let table = &self.hash_table;
            let slice_size = self.set.slice_size;
            // Built on demand: the healthy path breaks out below before any
            // candidate is considered, and never pays for the span map.
            let mut explained = None;
            let mut blocks = ScanBlockState::new(&self.blocks);
            let mut open = open_short_blocks(table, &blocks, slice_size);
            open_short_block_count = open.iter().filter(|open| **open).count();

            for target in targets {
                if open_short_block_count == 0 {
                    break;
                }
                check_cancel(options)?;
                if explained
                    .get_or_insert_with(|| self.explained_bytes_by_path())
                    .get_mut(&target.path)
                    .is_some_and(|spans| merged_span_bytes(spans) >= target.len)
                {
                    candidates_skipped = candidates_skipped.saturating_add(1);
                    continue;
                }

                candidates_scanned = candidates_scanned.saturating_add(1);
                let candidate_started = Instant::now();
                let mut stats = ShortRelocationStats::default();
                let attempted = {
                    let mut scan = ShortRelocationScan {
                        table,
                        path: &target.path,
                        kind: target.kind,
                        open: &open,
                        blocks: &mut blocks,
                        stats: &mut stats,
                    };
                    scan_shifted_short_blocks_from_file(&mut scan, target.len as usize)
                };
                let attempted = match attempted {
                    Ok(attempted) => attempted,
                    Err(error) => {
                        log_short_relocation(
                            &target.path,
                            target.kind,
                            &[],
                            &stats,
                            candidate_started.elapsed(),
                        );
                        return Err(error);
                    }
                };
                log_short_relocation(
                    &target.path,
                    target.kind,
                    &attempted,
                    &stats,
                    candidate_started.elapsed(),
                );
                totals.accumulate(&stats);
                if stats.blocks_placed > 0 {
                    open = open_short_blocks(table, &blocks, slice_size);
                    open_short_block_count = open.iter().filter(|open| **open).count();
                }
            }

            blocks.changed_locations()
        };

        let found_before = self
            .blocks
            .iter()
            .filter(|block| block.location.is_some())
            .count();
        for (block_index, location) in changed {
            self.record_block_location(block_index, location);
        }
        let found_after = self
            .blocks
            .iter()
            .filter(|block| block.location.is_some())
            .count();
        diagnostics.blocks_found = diagnostics
            .blocks_found
            .saturating_add(found_after.saturating_sub(found_before) as u32);
        diagnostics.short_relocation_candidates_scanned = diagnostics
            .short_relocation_candidates_scanned
            .saturating_add(candidates_scanned);
        diagnostics.short_relocation_candidates_skipped = diagnostics
            .short_relocation_candidates_skipped
            .saturating_add(candidates_skipped);
        diagnostics.short_relocation_windows_stepped = diagnostics
            .short_relocation_windows_stepped
            .saturating_add(totals.windows_stepped);
        diagnostics.short_relocation_bytes_read = diagnostics
            .short_relocation_bytes_read
            .saturating_add(totals.bytes_read);
        diagnostics.short_relocation_blocks_placed = diagnostics
            .short_relocation_blocks_placed
            .saturating_add(totals.blocks_placed.min(u64::from(u32::MAX)) as u32);

        log_short_relocation_pass(
            targets.len(),
            candidates_scanned,
            candidates_skipped,
            open_short_block_count,
            &totals,
            started.elapsed(),
        );

        Ok(())
    }

    /// Located byte spans of every path the merged state can account for,
    /// keyed by path. A candidate whose spans already cover its whole length
    /// holds no byte the merged state cannot already name, so the relocation
    /// search skips it. What that gives up is narrow and deliberate: a short
    /// block whose bytes are *duplicated* inside such a candidate is real but
    /// no longer salvaged from there, costing one recovery block instead of a
    /// whole-candidate sweep per still-open short length.
    fn explained_bytes_by_path(&self) -> HashMap<PathBuf, Vec<(u64, u64)>> {
        let mut spans: HashMap<PathBuf, Vec<(u64, u64)>> = HashMap::new();
        let mut push = |location: &BlockLocation| {
            if let Some(path) = location.path() {
                spans
                    .entry(path.to_path_buf())
                    .or_default()
                    .push((location.offset, location.len));
            }
        };
        for file in &self.files {
            if let Some(location) = file.complete_location.as_ref() {
                push(location);
            }
        }
        for block in &self.blocks {
            if let Some(location) = block.location.as_ref() {
                push(location);
            }
        }
        spans
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_candidate_snapshot(
        options: &Par2RepairerOptions,
        candidate: &ScanCandidate,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        block_index_by_file_slice: &HashMap<(FileId, u32), usize>,
        baseline_blocks: &[SourceBlock],
        hash_table: &VerificationHashTable,
        slice_size: u64,
        inner_parallel: bool,
        trust: &EvidenceScanTrust,
    ) -> Result<CandidateScanResult> {
        let path = &candidate.path;
        let kind = candidate.kind;
        check_cancel(options)?;
        if should_skip_candidate(path) {
            return Ok(CandidateScanResult::skipped(path, kind));
        }
        let metadata = if kind == BlockLocationKind::Extra {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return Ok(CandidateScanResult::ignored(path, kind));
            };
            if !metadata.file_type().is_file() {
                return Ok(CandidateScanResult::ignored(path, kind));
            }
            metadata
        } else {
            if !path.is_file() {
                return Ok(CandidateScanResult::ignored(path, kind));
            }
            fs::metadata(path)?
        };

        let mut result = CandidateScanResult {
            path: path.clone(),
            kind,
            files_scanned: 1,
            files_skipped: 0,
            bytes_scanned: metadata.len(),
            bytes_skipped_by_evidence: 0,
            slices_settled_by_evidence: 0,
            stats: None,
            elapsed: Duration::ZERO,
            complete_files: Vec::new(),
            block_locations: Vec::new(),
        };
        if kind == BlockLocationKind::Extra && metadata.len() == 0 {
            return Ok(result);
        }

        let started = Instant::now();
        let (complete_files, block_locations) = Self::scan_complete_file_matches(
            path,
            kind,
            metadata.len(),
            files,
            block_index_by_file_slice,
            baseline_blocks,
            slice_size,
        )?;
        if !complete_files.is_empty() {
            result.complete_files = complete_files;
            result.block_locations = block_locations;
            result.stats = Some(FileScanStats::new(FileScanMode::Complete, metadata.len()));
            result.elapsed = started.elapsed();
            return Ok(result);
        }
        if options.rename_only && kind == BlockLocationKind::Extra {
            result.stats = Some(FileScanStats::new(FileScanMode::Complete, metadata.len()));
            result.elapsed = started.elapsed();
            return Ok(result);
        }

        let ordered_target = (kind == BlockLocationKind::Canonical)
            .then(|| {
                files
                    .iter()
                    .find(|file| {
                        file.safe_path == *path && file.recoverable && file.block_count > 0
                    })
                    .cloned()
            })
            .flatten();
        let scanner = RollingBlockScanner::new(hash_table, slice_size);
        let mut scan_blocks = ScanBlockState::new(baseline_blocks);
        let stats = if let Some(target_file) = ordered_target.as_ref() {
            // Seeded-evidence skipping reaches exactly here: the ordered
            // canonical scan is the path a damaged source file takes, and the
            // only one where a seeded verdict names the same path and offsets
            // the scanner is about to walk.
            let settled =
                evidence_settled_slices(trust, target_file, path, &scan_blocks, slice_size);
            scanner.scan_file_ordered_canonical_state(
                path,
                kind,
                SourceFileScanLookup {
                    files,
                    file_index_by_id,
                },
                target_file,
                &mut scan_blocks,
                ScanSkipOptions {
                    skip_data: options.scan_skip_data,
                    skip_leeway: options.scan_skip_leeway,
                },
                inner_parallel,
                options.memory_limit.unwrap_or(DEFAULT_REPAIR_MEMORY_LIMIT),
                options.cancel.as_ref(),
                &settled,
            )?
        } else {
            scanner.scan_file_with_state_options(
                path,
                kind,
                files,
                file_index_by_id,
                &mut scan_blocks,
                ScanSkipOptions {
                    skip_data: options.scan_skip_data,
                    skip_leeway: options.scan_skip_leeway,
                },
            )?
        };

        result.block_locations = scan_blocks.changed_locations();
        result.bytes_skipped_by_evidence = stats.bytes_skipped_by_evidence;
        result.slices_settled_by_evidence = stats.slices_settled_by_evidence;
        result.stats = Some(stats);
        result.elapsed = started.elapsed();

        Ok(result)
    }

    fn scan_complete_file_matches(
        path: &Path,
        kind: BlockLocationKind,
        len: u64,
        files: &[SourceFileEntry],
        block_index_by_file_slice: &HashMap<(FileId, u32), usize>,
        baseline_blocks: &[SourceBlock],
        slice_size: u64,
    ) -> Result<CompleteScanMatches> {
        let first = read_first_16k(path)?;
        let hash_16k = checksum::md5(&first);

        let candidates: Vec<usize> = files
            .iter()
            .enumerate()
            .filter_map(|(idx, file)| {
                (file.length == len && file.hash_16k == hash_16k).then_some(idx)
            })
            .collect();

        if candidates.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let should_skip_full_hash = kind == BlockLocationKind::Canonical
            && len >= CANONICAL_COMPLETE_HASH_SKIP_BYTES.max(slice_size.saturating_mul(4))
            && candidates
                .iter()
                .copied()
                .any(|idx| files[idx].safe_path == path && files[idx].block_count > 0);
        if should_skip_full_hash {
            return Ok((Vec::new(), Vec::new()));
        }

        let full = hash_file(path)?;
        let mut complete_files = Vec::new();
        let mut block_locations = Vec::new();
        for idx in candidates {
            if files[idx].hash_full != full {
                continue;
            }

            let file = &files[idx];
            let file_id = file.file_id;
            let complete_kind = if file.safe_path == path {
                BlockLocationKind::Canonical
            } else {
                kind
            };
            complete_files.push(CompleteFileMatch {
                file_index: idx,
                location: BlockLocation {
                    source: SourceLocation::Path(path.to_path_buf()),
                    offset: 0,
                    len,
                    kind: complete_kind,
                },
            });

            for local_index in 0..file.block_count {
                let Some(block_index) = block_index_by_file_slice
                    .get(&(file_id, local_index as u32))
                    .copied()
                else {
                    continue;
                };
                let offset = local_index as u64 * slice_size;
                let expected_len = baseline_blocks[block_index].expected_len;
                block_locations.push((
                    block_index,
                    BlockLocation {
                        source: SourceLocation::Path(path.to_path_buf()),
                        offset,
                        len: expected_len,
                        kind: complete_kind,
                    },
                ));
            }
        }

        Ok((complete_files, block_locations))
    }

    fn apply_scan_result(
        &mut self,
        result: CandidateScanResult,
        diagnostics: &mut ScanDiagnostics,
    ) {
        diagnostics.files_scanned = diagnostics
            .files_scanned
            .saturating_add(result.files_scanned);
        diagnostics.files_skipped = diagnostics
            .files_skipped
            .saturating_add(result.files_skipped);
        // `bytes_scanned` is what this pass read. Ranges a seeded verdict
        // settled were seeked past, so they are subtracted here and reported
        // separately: the two counters together say both how big the candidate
        // was and how much of it the pass actually looked at.
        diagnostics.bytes_scanned = diagnostics.bytes_scanned.saturating_add(
            result
                .bytes_scanned
                .saturating_sub(result.bytes_skipped_by_evidence),
        );
        diagnostics.bytes_skipped_by_evidence = diagnostics
            .bytes_skipped_by_evidence
            .saturating_add(result.bytes_skipped_by_evidence);
        diagnostics.slices_settled_by_evidence = diagnostics
            .slices_settled_by_evidence
            .saturating_add(result.slices_settled_by_evidence);

        let found_before = self
            .blocks
            .iter()
            .filter(|block| block.location.is_some())
            .count();
        for complete in result.complete_files {
            if self.files[complete.file_index].safe_path != result.path {
                self.files[complete.file_index].non_canonical_complete_source_count = self.files
                    [complete.file_index]
                    .non_canonical_complete_source_count
                    .saturating_add(1);
            }
            self.files[complete.file_index].complete_location = Some(complete.location);
        }
        for (block_index, location) in result.block_locations {
            self.record_block_location(block_index, location);
        }
        let found_after = self
            .blocks
            .iter()
            .filter(|block| block.location.is_some())
            .count();
        let blocks_confirmed = found_after.saturating_sub(found_before) as u32;
        diagnostics.blocks_found = diagnostics.blocks_found.saturating_add(blocks_confirmed);

        if let Some(stats) = result.stats {
            log_file_scan(
                &result.path,
                result.kind,
                stats,
                blocks_confirmed,
                result.elapsed,
            );
        }
    }
    fn record_block_location(&mut self, block_index: usize, location: BlockLocation) {
        let replace = self.blocks[block_index]
            .location
            .as_ref()
            .is_none_or(|existing| {
                location.kind < existing.kind
                    || (location.kind == existing.kind && location.source < existing.source)
            });
        if replace {
            self.blocks[block_index].location = Some(location);
        }
    }

    fn refresh_file_states(&mut self) {
        for file_index in 0..self.files.len() {
            let target_exists = self.files[file_index].safe_path.exists();
            self.files[file_index].target_exists = target_exists;
            if !self.files[file_index].recoverable
                || self.files[file_index].complete_location.is_some()
            {
                continue;
            }
            if self.file_has_canonical_block_layout(file_index) {
                let file = &self.files[file_index];
                self.files[file_index].complete_location = Some(BlockLocation {
                    source: SourceLocation::Path(file.safe_path.clone()),
                    offset: 0,
                    len: file.length,
                    kind: BlockLocationKind::Canonical,
                });
            }
        }
    }

    fn file_has_canonical_block_layout(&self, file_index: usize) -> bool {
        let file = &self.files[file_index];
        if !file.target_exists {
            return false;
        }
        if file.block_count == 0 {
            return file.length == 0
                && fs::metadata(&file.safe_path)
                    .map(|metadata| metadata.len() == 0)
                    .unwrap_or(false);
        }
        if fs::metadata(&file.safe_path)
            .map(|metadata| metadata.len() != file.length)
            .unwrap_or(true)
        {
            return false;
        }

        (0..file.block_count).all(|local| {
            let block = &self.blocks[file.first_block + local];
            block.location.as_ref().is_some_and(|location| {
                location.kind == BlockLocationKind::Canonical
                    && location.source.is_path(&file.safe_path)
                    && location.offset == local as u64 * self.set.slice_size
                    && location.len == block.expected_len
            })
        })
    }

    /// Capture the scan's full effect (file states + block locations) plus
    /// a stat snapshot of every path it observed, for reuse by a later
    /// pass over the same set. Access-backed locations contribute no snapshot
    /// entry: their staleness is not a filesystem fact.
    fn scan_carry(&self, diagnostics: &ScanDiagnostics) -> ScanCarry {
        let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
        for file in &self.files {
            paths.insert(file.safe_path.clone());
            if let Some(path) = file
                .complete_location
                .as_ref()
                .and_then(BlockLocation::path)
            {
                paths.insert(path.to_path_buf());
            }
        }
        for block in &self.blocks {
            if let Some(path) = block.location.as_ref().and_then(BlockLocation::path) {
                paths.insert(path.to_path_buf());
            }
        }
        ScanCarry {
            recovery_set_id: self.set.recovery_set_id,
            slice_size: self.set.slice_size,
            set_file_ids: self.files.iter().map(|file| file.file_id).collect(),
            snapshot: paths.iter().map(|path| stat_for_carry(path)).collect(),
            files: self.files.clone(),
            blocks: self.blocks.clone(),
            diagnostics: diagnostics.clone(),
        }
    }

    /// Install a carried scan if it matches this state's set and every
    /// observed path is unchanged on disk (length + mtime, including
    /// nonexistence). Returns the carried diagnostics on success; `None`
    /// means the caller must run a real scan.
    fn try_apply_carry(&mut self, carry: &ScanCarry) -> Option<ScanDiagnostics> {
        // The carried vectors replace this state's own, so they must have been
        // laid out from this same set: same recovery set, same slice size.
        if carry.recovery_set_id != self.set.recovery_set_id
            || carry.slice_size != self.set.slice_size
        {
            return None;
        }
        let ids_match = self.files.len() == carry.set_file_ids.len()
            && self
                .files
                .iter()
                .zip(carry.set_file_ids.iter())
                .all(|(file, id)| file.file_id == *id);
        if !ids_match || self.blocks.len() != carry.blocks.len() {
            return None;
        }
        for expected in &carry.snapshot {
            if stat_for_carry(&expected.path) != *expected {
                return None;
            }
        }
        self.files = carry.files.clone();
        self.blocks = carry.blocks.clone();
        Some(carry.diagnostics.clone())
    }

    pub(crate) fn verification_result(&self) -> VerificationResult {
        let mut files = Vec::new();
        let mut total_missing_blocks = 0u32;
        // Only files whose FileDesc packet is missing are truly unrepairable:
        // without a length the global slice layout (and thus every RS
        // constant) is unknown. A file that merely lost its IFSC packet still
        // repairs positionally — all of its slices count as missing and the
        // FileDesc full-file hash validates the reconstruction afterwards.
        let missing_unrepairable_block_metadata = self.discarded_recoverable_files > 0;

        for file in self.files.iter().filter(|file| file.recoverable) {
            let mut valid_slices = vec![false; file.expected_block_count];
            for (local, valid) in valid_slices.iter_mut().enumerate().take(file.block_count) {
                let block = &self.blocks[file.first_block + local];
                *valid = block.location.is_some();
            }
            if file.complete_location.is_some() {
                valid_slices.fill(true);
            }
            let missing = if file.complete_location.is_some() {
                0
            } else {
                valid_slices.iter().filter(|valid| !**valid).count() as u32
            };
            total_missing_blocks = total_missing_blocks.saturating_add(missing);

            let status = if self.is_canonical_complete(file) {
                FileStatus::Complete
            } else if let Some(path) = file
                .complete_location
                .as_ref()
                .and_then(BlockLocation::path)
            {
                // Only a physical source can be "the same content under a
                // different name". An access-backed complete source is always
                // the file's own bytes, so it is complete, never renamed.
                FileStatus::Renamed(path.to_path_buf())
            } else if !file.target_exists && file.complete_location.is_none() && missing > 0 {
                FileStatus::Missing
            } else {
                FileStatus::Damaged(missing)
            };

            files.push(FileVerification {
                file_id: file.file_id,
                filename: file.safe_name.clone(),
                status,
                valid_slices,
                missing_slice_count: missing,
            });
        }

        let recovery_blocks_available = self.set.recovery_block_count();
        let blocks_needed = total_missing_blocks.saturating_add(self.discarded_recoverable_files);
        let repairable = if total_missing_blocks == 0 && self.files_are_canonical_complete() {
            Repairability::NotNeeded
        } else if missing_unrepairable_block_metadata {
            Repairability::Insufficient {
                blocks_needed,
                blocks_available: recovery_blocks_available,
                deficit: blocks_needed
                    .saturating_sub(recovery_blocks_available)
                    .max(1),
            }
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

        VerificationResult {
            files,
            recovery_blocks_available,
            total_missing_blocks,
            repairable,
        }
    }

    pub(crate) fn files_are_canonical_complete(&self) -> bool {
        if self.discarded_recoverable_files > 0 {
            return false;
        }
        self.files
            .iter()
            .filter(|file| file.recoverable)
            .all(|file| self.is_canonical_complete(file))
    }

    fn is_canonical_complete(&self, file: &SourceFileEntry) -> bool {
        file.complete_location.as_ref().is_some_and(|location| {
            location.kind == BlockLocationKind::Canonical && location.source.is_canonical_for(file)
        })
    }

    /// Every source a repair on this state would read: each recoverable file's
    /// whole-file source, plus the source behind every located block, which
    /// together cover the copy-only path, the staged block copies and the
    /// Reed-Solomon input stream.
    ///
    /// The pre-mutation carry gate and the mid-repair change check are both
    /// built from this one enumeration so they can never come to disagree
    /// about what "a repair input" is.
    fn for_each_repair_input_source<'a>(&'a self, mut visit: impl FnMut(&'a SourceLocation)) {
        for file in self.files.iter().filter(|file| file.recoverable) {
            if let Some(location) = file.complete_location.as_ref() {
                visit(&location.source);
            }
        }
        for block in &self.blocks {
            if let Some(location) = block.location.as_ref() {
                visit(&location.source);
            }
        }
    }

    /// Stat every physical repair input so a mid-repair change is caught.
    /// Access-backed sources carry no stat: their staleness is governed by the
    /// serving handle's own coverage, not by device/inode/mtime.
    fn snapshot_repair_input_sources(&self) -> HashMap<PathBuf, CarriedFileStat> {
        let mut snapshots = HashMap::new();
        self.for_each_repair_input_source(|source| {
            if let Some(path) = source.path() {
                snapshots
                    .entry(path.to_path_buf())
                    .or_insert_with(|| stat_for_carry(path));
            }
        });
        snapshots
    }

    /// Decide whether this carried analysis may be mutated on without a fresh
    /// scan.
    ///
    /// Every source the repair would read is re-stat'd and compared against
    /// the fingerprint the carried scan captured for it. All of them matching
    /// is what licenses the repair to skip its own scan; anything else — a
    /// changed, replaced, truncated, renamed or deleted file, or an input the
    /// carry holds no fingerprint for — sends the caller back to a full scan.
    ///
    /// This is deliberately narrower than [`Self::try_apply_carry`], which
    /// re-stats everything the scan ever looked at: what licenses a *mutation*
    /// is the state of the bytes the mutation will read, and this check runs
    /// immediately before that mutation rather than at the top of the pass.
    fn carry_repair_inputs_unchanged<'a>(
        &'a self,
        carry: &ScanCarry,
    ) -> std::result::Result<(), CarryRetryReason> {
        let expected: HashMap<&Path, &CarriedFileStat> = carry
            .snapshot
            .iter()
            .map(|stat| (stat.path.as_path(), stat))
            .collect();
        let mut rejection = None;
        let mut checked: HashSet<&'a Path> = HashSet::new();
        self.for_each_repair_input_source(|source| {
            if rejection.is_some() {
                return;
            }
            let Some(path) = source.path() else {
                // An access-backed source has no filesystem identity to
                // re-stat, and a carry records no serving-handle generation,
                // so nothing available here can honestly say the bytes behind
                // it are still the ones the scan read. Refuse rather than
                // guess.
                rejection = Some(CarryRetryReason::RepairInputNotFingerprinted);
                return;
            };
            if !checked.insert(path) {
                return;
            }
            match expected.get(path) {
                Some(expected) if stat_for_carry(path) == **expected => {}
                // A repair input the carry never fingerprinted cannot be
                // checked at all, so it is refused for the same reason an
                // access-backed one is.
                None => rejection = Some(CarryRetryReason::RepairInputNotFingerprinted),
                Some(_) => rejection = Some(CarryRetryReason::RepairInputChanged),
            }
        });
        match rejection {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    pub(crate) fn repair(
        &self,
        options: &Par2RepairerOptions,
        verification: &VerificationResult,
    ) -> Result<RepairInstall> {
        self.repair_inner(options, verification, false)
    }

    /// Retained sessions call this path after analysis. Every source slice is
    /// checked against its IFSC checksum before it can enter staging or the
    /// Reed-Solomon input stream.
    pub(crate) fn repair_validated(
        &self,
        options: &Par2RepairerOptions,
        verification: &VerificationResult,
    ) -> Result<RepairInstall> {
        self.repair_inner(options, verification, true)
    }

    fn repair_inner(
        &self,
        options: &Par2RepairerOptions,
        verification: &VerificationResult,
        validate_sources: bool,
    ) -> Result<RepairInstall> {
        let install_dir = unique_repair_dir(&options.base_dir);
        fs::create_dir_all(&install_dir)?;
        let mut staging_guard = RepairStagingGuard::new(install_dir.clone());
        let mut bytes_copied = 0u64;
        let staged_file_ids: HashSet<FileId> = self
            .files
            .iter()
            .filter(|file| file.recoverable && !self.is_canonical_complete(file))
            .map(|file| file.file_id)
            .collect();
        let source_snapshots = validate_sources.then(|| self.snapshot_repair_input_sources());

        for file in self
            .files
            .iter()
            .filter(|file| staged_file_ids.contains(&file.file_id))
        {
            let target = install_dir.join(&file.safe_name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let out = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&target)?;
            out.set_len(file.length)?;
        }

        let reconstruction_active = verification.total_missing_blocks > 0;
        let mut whole_file_copied_ids = HashSet::new();
        for file in self
            .files
            .iter()
            .filter(|file| staged_file_ids.contains(&file.file_id))
        {
            if reconstruction_active {
                continue;
            }
            let Some(location) = file.complete_location.as_ref() else {
                continue;
            };
            let target = install_dir.join(&file.safe_name);
            if validate_sources {
                copy_complete_file_validated(
                    file,
                    &self.blocks[file.first_block..file.first_block + file.block_count],
                    self.set.slice_size,
                    &location.source,
                    self.source_access.as_deref(),
                    &target,
                )?;
            } else {
                copy_source_range(
                    &location.source,
                    self.source_access.as_deref(),
                    0,
                    &target,
                    0,
                    file.length,
                )?;
            }
            bytes_copied += file.length;
            whole_file_copied_ids.insert(file.file_id);
        }

        let mut block_copy_ranges = Vec::new();
        let mut reconstruction_copy_targets = ReconstructionCopyTargets::new();
        let mut validated_block_copies = Vec::new();
        for block in &self.blocks {
            check_cancel(options)?;
            if !staged_file_ids.contains(&block.file_id)
                || whole_file_copied_ids.contains(&block.file_id)
            {
                continue;
            }
            let Some(location) = block.location.as_ref() else {
                continue;
            };
            let Some(file_idx) = self.file_index_by_id.get(&block.file_id).copied() else {
                continue;
            };
            let target = install_dir.join(&self.files[file_idx].safe_name);
            let range = BlockCopyRange {
                src: location.source.clone(),
                src_offset: location.offset,
                dst: target,
                dst_offset: block.local_index as u64 * self.set.slice_size,
                len: block.expected_len,
            };
            if reconstruction_active {
                reconstruction_copy_targets.insert((block.file_id, block.local_index), range);
            } else if validate_sources {
                validated_block_copies.push((block.clone(), range));
            } else {
                push_block_copy_range(&mut block_copy_ranges, range);
            }
            bytes_copied += block.expected_len;
        }
        let copy_block_ranges = |ranges: &[BlockCopyRange]| -> Result<()> {
            for range in ranges {
                check_cancel(options)?;
                copy_source_range(
                    &range.src,
                    self.source_access.as_deref(),
                    range.src_offset,
                    &range.dst,
                    range.dst_offset,
                    range.len,
                )?;
            }
            Ok(())
        };
        let copy_validated_blocks = || -> Result<()> {
            for (block, range) in &validated_block_copies {
                check_cancel(options)?;
                copy_block_range_validated(
                    block,
                    self.set.slice_size,
                    range,
                    self.source_access.as_deref(),
                )?;
            }
            Ok(())
        };

        let reconstruct = || -> Result<(u64, u64)> {
            let mut bytes_reconstructed = 0u64;
            let mut validation_bytes = 0u64;
            if verification.total_missing_blocks > 0 {
                let mut access = RepairExecutionAccess::new(
                    install_dir.clone(),
                    &self.files,
                    &self.blocks,
                    &staged_file_ids,
                    self.set.slice_size,
                    RepairExecutionContext {
                        source_access: self.source_access.clone(),
                        source_snapshots: source_snapshots.clone(),
                        reconstruction_copy_targets: reconstruction_copy_targets.clone(),
                    },
                )?;
                let plan =
                    plan_repair_with_memory_limit(&self.set, verification, options.memory_limit)?;
                bytes_reconstructed = plan
                    .missing_slices
                    .iter()
                    .filter_map(|(file_id, local)| {
                        if let Some(idx) = self.block_index_by_file_slice.get(&(*file_id, *local)) {
                            return Some(self.blocks[*idx].expected_len);
                        }
                        self.set.file_description(file_id).map(|desc| {
                            let offset = *local as u64 * self.set.slice_size;
                            desc.length.saturating_sub(offset).min(self.set.slice_size)
                        })
                    })
                    .sum();
                let repair_options = RepairOptions {
                    cancel: options.cancel.clone(),
                    progress: options.progress.clone(),
                    memory_limit: options.memory_limit,
                };
                execute_repair_with_options(&plan, &self.set, &mut access, &repair_options)?;
                validation_bytes = access.validation_bytes();
            }
            Ok((bytes_reconstructed, validation_bytes))
        };

        // Copy-only repairs retain the direct copy path. When reconstruction
        // is active, intact blocks are copied by RepairExecutionAccess from
        // the source buffer immediately before it enters the controller.
        // Overlapping the copy with compute adds page-cache and memory-bandwidth
        // contention without improving throughput, so keep the work ordered.
        copy_block_ranges(&block_copy_ranges)?;
        copy_validated_blocks()?;
        let (bytes_reconstructed, reconstruction_validation_bytes) = reconstruct()?;
        let validation_bytes = if validate_sources { bytes_copied } else { 0 }
            .saturating_add(reconstruction_validation_bytes);

        let repair = RepairInstall {
            install_dir,
            staged_file_ids,
            bytes_copied,
            bytes_reconstructed,
            validation_bytes,
        };
        staging_guard.disarm();
        Ok(repair)
    }

    pub(crate) fn install_repaired_files(
        &self,
        repair: &RepairInstall,
        options: &Par2RepairerOptions,
    ) -> Result<()> {
        let canonical_paths: HashSet<PathBuf> = self
            .files
            .iter()
            .filter(|file| file.recoverable)
            .map(|file| canonical_extra_path(&file.safe_path))
            .collect();
        let explicit_extra_paths: HashSet<PathBuf> = options
            .extra_paths
            .iter()
            .filter(|path| !has_par2_marker(path))
            .map(|path| canonical_extra_path(path))
            .collect();
        let consumed_complete_sources: HashSet<PathBuf> = self
            .files
            .iter()
            .filter(|file| repair.staged_file_ids.contains(&file.file_id))
            .filter_map(|file| {
                let location = file.complete_location.as_ref()?;
                let source = canonical_extra_path(location.path()?);
                (source != canonical_extra_path(&file.safe_path)
                    && file.non_canonical_complete_source_count == 1
                    && explicit_extra_paths.contains(&source)
                    && !canonical_paths.contains(&source))
                .then_some(source)
            })
            .collect();

        let mut installed_targets = Vec::new();
        let mut backups = Vec::new();
        let install_result = (|| -> Result<()> {
            for file in self
                .files
                .iter()
                .filter(|file| repair.staged_file_ids.contains(&file.file_id))
            {
                let src = repair.install_dir.join(&file.safe_name);
                let dst = &file.safe_path;
                match fs::symlink_metadata(dst) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        let target_metadata = fs::metadata(dst).map_err(|error| {
                            Par2Error::Io(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "repair target is a dangling symbolic link: {} ({error})",
                                    dst.display()
                                ),
                            ))
                        })?;
                        if !target_metadata.file_type().is_file() {
                            return Err(Par2Error::Io(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "repair target symbolic link does not point to a file: {}",
                                    dst.display()
                                ),
                            )));
                        }
                        let backup = unique_backup_path(dst)?;
                        crate::disk::rename_within_base(&options.base_dir, dst, &backup)?;
                        crate::file_cache::drop_path_cache(&backup);
                        backups.push((dst.clone(), backup));
                    }
                    Ok(metadata) if metadata.file_type().is_file() => {
                        let backup = unique_backup_path(dst)?;
                        crate::disk::rename_within_base(&options.base_dir, dst, &backup)?;
                        crate::file_cache::drop_path_cache(&backup);
                        backups.push((dst.clone(), backup));
                    }
                    Ok(_) => {
                        return Err(Par2Error::Io(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "repair target exists and is not a regular file: {}",
                                dst.display()
                            ),
                        )));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                crate::disk::rename_within_base(&options.base_dir, &src, dst)?;
                crate::file_cache::drop_path_cache(dst);
                installed_targets.push(dst.clone());
            }

            Ok(())
        })();

        if install_result.is_err() {
            rollback_installed_files(&options.base_dir, &installed_targets, &backups);
        } else {
            // The repaired targets are now accepted. Removing duplicate extra
            // sources is cleanup, not part of the rollback transaction: a
            // cleanup failure must never discard the valid source and then
            // restore a damaged target.
            purge_files_best_effort(&consumed_complete_sources);
            if options.purge {
                purge_files_best_effort(backups.iter().map(|(_, backup)| backup));
            }
        }
        install_result
    }

    pub(crate) fn outcome(
        &self,
        status: Par2RepairStatus,
        bytes_copied: u64,
        bytes_reconstructed: u64,
        packets: PacketDiagnostics,
        scan: ScanDiagnostics,
        verification: VerificationResult,
    ) -> Par2RepairOutcome {
        let mut files_complete = 0u32;
        let mut files_renamed = 0u32;
        let mut files_damaged = 0u32;
        let mut files_missing = self.discarded_recoverable_files;

        for file in &verification.files {
            match file.status {
                FileStatus::Complete => {
                    files_complete += 1;
                }
                FileStatus::Renamed(_) => {
                    files_renamed += 1;
                }
                FileStatus::Damaged(_) => {
                    files_damaged += 1;
                }
                FileStatus::Missing => {
                    files_missing += 1;
                }
            }
        }

        let available_blocks = self
            .blocks
            .iter()
            .filter(|block| block.location.is_some())
            .count() as u32;
        let missing_blocks = verification.total_missing_blocks;
        let recovery_blocks_used = verification
            .total_missing_blocks
            .min(self.set.recovery_block_count());

        Par2RepairOutcome {
            status,
            files_complete,
            files_renamed,
            files_damaged,
            files_missing,
            available_blocks,
            missing_blocks,
            recovery_blocks_available: self.set.recovery_block_count(),
            recovery_blocks_used,
            bytes_copied,
            bytes_reconstructed,
            packets,
            scan,
            carry: CarryDiagnostics::default(),
            verification,
        }
    }
}

struct VerificationHashTable {
    by_crc: HashMap<u32, Vec<usize>>,
    short_blocks: Vec<usize>,
    slice_size: u64,
    /// Longest `by_crc` bucket: the most CRC candidates a single window can
    /// ever produce, and so the ceiling on the parallel scanner's per-worker
    /// candidate scratch.
    max_crc_bucket: usize,
}

impl VerificationHashTable {
    fn new(blocks: &[SourceBlock], slice_size: u64) -> Self {
        let mut by_crc: HashMap<u32, Vec<usize>> = HashMap::new();
        let mut short_blocks = Vec::new();
        for block in blocks {
            by_crc
                .entry(block.checksum.crc32)
                .or_default()
                .push(block.global_index);
            if block.expected_len < slice_size {
                short_blocks.push(block.global_index);
            }
        }
        let max_crc_bucket = by_crc.values().map(Vec::len).max().unwrap_or(0);
        Self {
            by_crc,
            short_blocks,
            slice_size,
            max_crc_bucket,
        }
    }

    fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = std::mem::size_of::<Self>()
            .saturating_add(
                self.by_crc
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(u32, Vec<usize>)>()),
            )
            .saturating_add(
                self.short_blocks
                    .capacity()
                    .saturating_mul(std::mem::size_of::<usize>()),
            );
        for indexes in self.by_crc.values() {
            bytes = bytes.saturating_add(
                indexes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<usize>()),
            );
        }
        bytes
    }
}

struct RollingBlockScanner<'a> {
    table: &'a VerificationHashTable,
    window_table: [u32; 256],
}

struct PendingMd5Check<'a> {
    block_index: usize,
    data: &'a [u8],
    offset: u64,
    len: u64,
    kind: BlockLocationKind,
}

#[derive(Debug, Clone, Copy)]
struct ScanSkipOptions {
    skip_data: bool,
    skip_leeway: u64,
}

impl ScanSkipOptions {
    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            skip_data: false,
            skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
        }
    }

    fn scan_distance(self, slice_size: usize) -> usize {
        if !self.skip_data {
            return 0;
        }
        let skip_leeway = if self.skip_leeway == 0 {
            ORDERED_SCAN_DEFAULT_SKIP_LEEWAY
        } else {
            self.skip_leeway
        };
        skip_leeway
            .saturating_mul(2)
            .min(slice_size as u64)
            .try_into()
            .unwrap_or(slice_size)
    }
}

#[derive(Debug, Clone, Copy)]
struct RollingScanProgress {
    current_step_run: u64,
    scan_offset: usize,
}

impl RollingScanProgress {
    fn new(scan_options: ScanSkipOptions, slice_size: usize) -> Self {
        Self {
            current_step_run: 0,
            scan_offset: scan_options.scan_distance(slice_size) / 2,
        }
    }

    fn record_step(&mut self, stats: &mut FileScanStats) {
        stats.windows_stepped += 1;
        self.current_step_run += 1;
    }

    fn record_jump(&mut self, stats: &mut FileScanStats) {
        stats.jumps_taken += 1;
        stats.max_consecutive_steps = stats.max_consecutive_steps.max(self.current_step_run);
        self.current_step_run = 0;
    }
}

struct BufferedWindowScan<'a, 'scanner, 'blocks> {
    scanner: &'a RollingBlockScanner<'scanner>,
    path: &'a Path,
    kind: BlockLocationKind,
    blocks: &'a mut ScanBlockState<'blocks>,
    scan_options: ScanSkipOptions,
    progress: &'a mut RollingScanProgress,
    stats: &'a mut FileScanStats,
}

#[derive(Clone, Copy)]
struct SourceFileScanLookup<'a> {
    files: &'a [SourceFileEntry],
    file_index_by_id: &'a HashMap<FileId, usize>,
}

struct OrderedWindowMatch<'a> {
    path: &'a Path,
    kind: BlockLocationKind,
    target_file_id: &'a FileId,
    expected_block: Option<usize>,
    data: &'a [u8],
    crc: u32,
    offset: u64,
}

/// Selection-half inputs for one ordered window: everything
/// `select_ordered_match` needs besides the hashed match set.
struct OrderedSelection<'a> {
    path: &'a Path,
    kind: BlockLocationKind,
    target_file_id: &'a FileId,
    expected_block: Option<usize>,
    offset: u64,
}

/// Facts for aligned window `i` (offset `i * slice_size`).
/// `matches` holds ascending block indices confirmed by CRC *and* MD5;
/// empty means no aligned selection is possible at this offset.
#[derive(Default)]
struct AlignedWindowFacts {
    matches: Vec<u32>,
}

fn ordered_scan_facts_allocation_bytes(window_count: usize) -> Option<usize> {
    window_count.checked_mul(std::mem::size_of::<AlignedWindowFacts>())
}

/// Byte budget for the match entries Phase A retains. Only the `u32` payload
/// behind `AlignedWindowFacts::matches` is charged here — the fixed headers,
/// the per-worker read buffers, and the per-worker candidate scratch are all
/// charged up front by [`ordered_scan_admission`]. Shared across Phase A
/// workers, so charges are atomic; a charge that cannot fit aborts the whole
/// phase and the file goes to the serial scanner.
struct OrderedScanMatchBudget {
    remaining: AtomicUsize,
}

impl OrderedScanMatchBudget {
    fn new(bytes: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(bytes),
        }
    }

    fn charge(&self, bytes: usize) -> bool {
        self.remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(bytes)
            })
            .is_ok()
    }
}

/// How much of `memory_limit` a parallel ordered scan may spend on match
/// entries, and how many windows each worker may hold in its read buffer.
struct OrderedScanAdmission {
    read_windows: usize,
    match_budget: usize,
}

/// Smallest match budget the read buffers must leave behind. A scan whose
/// buffers would swallow the whole limit is useless: every window that matches
/// anything would blow the budget and send the file straight back to the
/// serial scanner.
const ORDERED_SCAN_MATCH_RESERVE_BYTES: usize = 1024 * 1024;

/// Count of Phase A read buffers and scratch vectors that can be live at once.
/// `try_for_each_init` builds one pair per running task, and no more tasks run
/// concurrently than there are pool threads or segments.
fn ordered_scan_workers(window_count: usize, segment_windows: usize) -> usize {
    window_count
        .div_ceil(segment_windows.max(1))
        .min(rayon::current_num_threads())
        .max(1)
}

/// Admission accounting for one parallel ordered scan, in bytes of heap held
/// at once: the fixed `AlignedWindowFacts` headers, one read buffer plus one
/// CRC-candidate scratch per concurrent worker, and the data-dependent match
/// entries Phase A retains. Read buffers shrink to fit rather than refusing
/// the scan, but never below one window per worker and never past the match
/// reserve; whatever the fixed part leaves becomes the match budget. `None`
/// means the fixed part alone does not fit, so the serial scanner takes the
/// file.
fn ordered_scan_admission(
    window_count: usize,
    segment_windows: usize,
    slice_size: usize,
    max_crc_bucket: usize,
    workers: usize,
    memory_limit: usize,
) -> Option<OrderedScanAdmission> {
    if slice_size == 0 || workers == 0 || window_count == 0 {
        return None;
    }
    let facts_bytes = ordered_scan_facts_allocation_bytes(window_count)?;
    let scratch_bytes = max_crc_bucket
        .checked_mul(std::mem::size_of::<u32>())?
        .checked_mul(workers)?;
    let fixed_bytes = facts_bytes.checked_add(scratch_bytes)?;
    let spendable = memory_limit.checked_sub(fixed_bytes)?;

    let wanted_windows = (SCANNER_IO_TARGET_BYTES / slice_size)
        .max(1)
        .min(segment_windows.max(1))
        .min(window_count);
    let affordable_windows =
        spendable.saturating_sub(ORDERED_SCAN_MATCH_RESERVE_BYTES) / workers / slice_size;
    let read_windows = wanted_windows.min(affordable_windows).max(1);
    let read_bytes = read_windows.checked_mul(slice_size)?.checked_mul(workers)?;

    Some(OrderedScanAdmission {
        read_windows,
        match_budget: spendable.checked_sub(read_bytes)?,
    })
}

/// Phase A failure modes. `Refused` means the phase could not stay inside its
/// admitted memory (budget exhausted or an allocation the allocator declined);
/// the caller drops the partial facts and re-runs the file through the serial
/// scanner, which produces the same result either way.
enum WindowFactsError {
    Refused,
    Scan(Par2Error),
}

impl From<io::Error> for WindowFactsError {
    fn from(error: io::Error) -> Self {
        Self::Scan(Par2Error::Io(error))
    }
}

/// How a gap resync hands control back to the aligned merge loop.
enum ResyncOutcome {
    Realigned {
        next_window: usize,
        preferred_next: Option<usize>,
    },
    End,
}

/// Shared read-only inputs for the gap resync loop.
struct OrderedResync<'a> {
    facts: &'a [AlignedWindowFacts],
    ordered_full_blocks: &'a [usize],
    path: &'a Path,
    kind: BlockLocationKind,
    target_file_id: &'a FileId,
}

struct OrderedWindowCursor<'a> {
    file: File,
    path: PathBuf,
    len: usize,
    block_size: usize,
    buffer: Vec<u8>,
    first_offset: usize,
    read_offset: usize,
    current_offset: usize,
    out_index: usize,
    in_index: usize,
    tail_index: usize,
    crc: u32,
    /// Bytes this cursor has actually pulled off the disk, across seeks. A
    /// walk with no skips reads the file exactly once, so the shortfall
    /// against the file length is what the skips saved.
    bytes_read: u64,
    window_table: &'a [u32; 256],
}

impl<'a> OrderedWindowCursor<'a> {
    /// Cursor whose first window starts at `start` (callers guarantee a full
    /// window fits there). The parallel scan's gap resync uses this to read
    /// only the gap region through the bounded two-window buffer.
    fn new_at(
        path: &Path,
        block_size: usize,
        window_table: &'a [u32; 256],
        start: usize,
    ) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if start > 0 {
            file.seek(SeekFrom::Start(start as u64))?;
        }
        crate::file_cache::advise_range_sequential(
            &file,
            path,
            start as u64,
            len.saturating_sub(start) as u64,
        );
        let buffer_len = block_size.checked_mul(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "scanner buffer overflow")
        })?;
        let mut cursor = Self {
            file,
            path: path.to_path_buf(),
            len,
            block_size,
            buffer: vec![0u8; buffer_len],
            first_offset: start,
            read_offset: start,
            current_offset: start,
            out_index: 0,
            in_index: block_size,
            tail_index: 0,
            crc: 0,
            bytes_read: 0,
            window_table,
        };
        cursor.fill(true)?;
        cursor.crc = checksum::crc32(&cursor.buffer[..block_size]);
        Ok(cursor)
    }

    fn last_full_offset(&self) -> usize {
        self.len - self.block_size
    }

    fn offset(&self) -> usize {
        self.current_offset
    }

    fn data(&self) -> &[u8] {
        &self.buffer[self.out_index..self.out_index + self.block_size]
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    fn step(&mut self) -> io::Result<bool> {
        if self.current_offset >= self.last_full_offset() {
            self.current_offset = self.last_full_offset().saturating_add(1);
            return Ok(false);
        }

        self.current_offset += 1;
        if self.tail_index <= self.in_index {
            self.fill(true)?;
        }

        let incoming = self.buffer[self.in_index];
        let outgoing = self.buffer[self.out_index];
        self.in_index += 1;
        self.out_index += 1;
        self.crc = crc_slide_char(self.crc, incoming, outgoing, self.window_table);

        if self.out_index == self.block_size {
            self.buffer.copy_within(self.out_index..self.tail_index, 0);
            self.tail_index -= self.block_size;
            self.in_index -= self.block_size;
            self.out_index = 0;
        }

        Ok(true)
    }

    fn jump(&mut self, mut distance: usize) -> io::Result<bool> {
        if distance == 0 {
            return Ok(self.current_offset <= self.last_full_offset());
        }
        if distance == 1 {
            return self.step();
        }
        distance = distance.min(self.block_size);

        let next_offset = self.current_offset.saturating_add(distance);
        if next_offset > self.last_full_offset() {
            self.current_offset = self.last_full_offset().saturating_add(1);
            return Ok(false);
        }

        self.current_offset = next_offset;
        let discard_start = self.out_index + distance;
        let keep = self.tail_index.saturating_sub(discard_start);
        if keep > 0 {
            self.buffer.copy_within(discard_start..self.tail_index, 0);
        }
        self.tail_index = keep;
        self.out_index = 0;
        self.in_index = self.block_size;
        self.fill(true)?;
        self.crc = checksum::crc32(&self.buffer[..self.block_size]);
        Ok(true)
    }

    /// Restart the window at `start`, reading nothing in between.
    ///
    /// This is the difference between [`Self::jump`] and a real skip: `jump`
    /// discards buffered bytes but still streams them off the disk, because
    /// every byte it passes over is a byte the scan was asked to explain. A
    /// seek is only sound where something else already explains the gap, which
    /// is the one thing the seeded-evidence policy establishes.
    ///
    /// Returns `false` when `start` leaves no room for a full window, which
    /// ends the aligned walk.
    fn seek_to(&mut self, start: usize) -> io::Result<bool> {
        if start > self.last_full_offset() {
            self.current_offset = self.last_full_offset().saturating_add(1);
            return Ok(false);
        }
        if start == self.current_offset {
            return Ok(true);
        }
        self.file.seek(SeekFrom::Start(start as u64))?;
        self.read_offset = start;
        self.current_offset = start;
        self.out_index = 0;
        self.in_index = self.block_size;
        self.tail_index = 0;
        self.fill(true)?;
        self.crc = checksum::crc32(&self.buffer[..self.block_size]);
        Ok(true)
    }

    fn fill(&mut self, long_fill: bool) -> io::Result<()> {
        if self.read_offset >= self.len {
            return Ok(());
        }

        let target = if !long_fill && self.tail_index >= self.block_size {
            self.block_size
        } else {
            self.buffer.len()
        };

        while self.tail_index < target && self.read_offset < self.len {
            let want = (target - self.tail_index).min(self.len - self.read_offset);
            let read = self
                .file
                .read(&mut self.buffer[self.tail_index..self.tail_index + want])?;
            if read == 0 {
                break;
            }
            self.tail_index += read;
            self.read_offset += read;
            self.bytes_read = self.bytes_read.saturating_add(read as u64);
        }

        if self.tail_index < self.buffer.len() {
            self.buffer[self.tail_index..].fill(0);
        }
        Ok(())
    }
}

impl Drop for OrderedWindowCursor<'_> {
    fn drop(&mut self) {
        crate::file_cache::drop_touched_file_cache(
            &self.file,
            &self.path,
            self.len as u64,
            self.first_offset as u64,
            (self.read_offset - self.first_offset) as u64,
        );
    }
}

impl<'a> RollingBlockScanner<'a> {
    fn new(table: &'a VerificationHashTable, slice_size: u64) -> Self {
        Self {
            table,
            window_table: generate_window_table(slice_size),
        }
    }

    #[cfg(test)]
    fn scan_file(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut [SourceBlock],
    ) -> Result<FileScanStats> {
        self.scan_file_with_options(
            path,
            kind,
            files,
            file_index_by_id,
            blocks,
            ScanSkipOptions::disabled(),
        )
    }

    #[cfg(test)]
    fn scan_file_with_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut [SourceBlock],
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        let baseline = blocks.to_vec();
        let mut state = ScanBlockState::new(&baseline);
        let stats = self.scan_file_with_state_options(
            path,
            kind,
            files,
            file_index_by_id,
            &mut state,
            scan_options,
        )?;
        self.relocate_open_short_blocks_in(path, kind, &mut state)?;
        state.apply_to_blocks(blocks);
        Ok(stats)
    }

    fn scan_file_with_state_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut ScanBlockState<'_>,
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        if scanner_uses_mmap_fallback(self.table.slice_size) {
            return self.scan_file_mmap_with_state_options(
                path,
                kind,
                files,
                file_index_by_id,
                blocks,
                scan_options,
            );
        }

        self.scan_file_buffered_with_target_state_options(
            path,
            kind,
            SourceFileScanLookup {
                files,
                file_index_by_id,
            },
            blocks,
            SCANNER_IO_TARGET_BYTES,
            scan_options,
        )
    }

    #[cfg(test)]
    fn scan_file_ordered_canonical(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        target_file: &SourceFileEntry,
        blocks: &mut [SourceBlock],
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        self.scan_file_ordered_canonical_settled(
            path,
            kind,
            lookup,
            target_file,
            blocks,
            scan_options,
            &[],
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn scan_file_ordered_canonical_settled(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        target_file: &SourceFileEntry,
        blocks: &mut [SourceBlock],
        scan_options: ScanSkipOptions,
        settled: &[bool],
    ) -> Result<FileScanStats> {
        let baseline = blocks.to_vec();
        let mut state = ScanBlockState::new(&baseline);
        let stats = self.scan_file_ordered_canonical_state(
            path,
            kind,
            lookup,
            target_file,
            &mut state,
            scan_options,
            true,
            DEFAULT_REPAIR_MEMORY_LIMIT,
            None,
            settled,
        )?;
        self.relocate_open_short_blocks_in(path, kind, &mut state)?;
        state.apply_to_blocks(blocks);
        Ok(stats)
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_file_ordered_canonical_state(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        target_file: &SourceFileEntry,
        blocks: &mut ScanBlockState<'_>,
        scan_options: ScanSkipOptions,
        inner_parallel: bool,
        memory_limit: usize,
        cancel: Option<&CancellationToken>,
        // Local slice indices this scan may seek past instead of reading. All
        // false (or empty) is the default and every pre-policy caller.
        settled: &[bool],
    ) -> Result<FileScanStats> {
        // Skip-data sampling is stateful and intentionally lossy, so it keeps
        // the serial scanner; single-thread pools do too. `inner_parallel`
        // is false when the caller is already fanning out across candidate
        // files: parallelism runs on exactly one axis, because nesting the
        // per-file fan-out inside the per-candidate fan-out lets a blocked
        // worker steal other files' whole scan frames onto one stack —
        // measured as an intermittent worker stack overflow on 16-file sets.
        // `!parallel_enabled()` const-folds away on native (the OR chain is
        // unchanged, byte-identical). On wasm it is a cached runtime probe: on
        // single-threaded `wasm32-wasip1` it forces the serial scanner and
        // short-circuits before `rayon::current_num_threads`, so the parallel
        // segment scanner (and its worker pool) is never reached; on
        // `wasm32-wasip1-threads` the ordinary parallel gating below applies.
        //
        // A file with honoured seeded-evidence skips joins skip-data on the
        // serial scanner for the same reason: the parallel scan's Phase A
        // computes facts for every aligned window up front, which is precisely
        // the reading the skip exists to avoid. Taking the serial path costs
        // this file its per-file fan-out and saves it most of its I/O; only a
        // file with at least one honoured skip pays that trade.
        let has_settled_skips = settled.contains(&true);
        if !reedsolomon_rs::threading::parallel_enabled()
            || scan_options.skip_data
            || has_settled_skips
            || ordered_scan_force_serial()
            || !ordered_scan_parallel_enabled()
            || !inner_parallel
            || rayon::current_num_threads() <= 1
        {
            return self.scan_file_ordered_canonical_serial(
                path,
                kind,
                lookup,
                target_file,
                blocks,
                scan_options,
                settled,
            );
        }
        let segment_windows = ordered_scan_segment_windows(self.table.slice_size as usize);
        match self.scan_file_ordered_canonical_parallel(
            path,
            kind,
            lookup,
            target_file,
            blocks,
            scan_options,
            segment_windows,
            memory_limit,
            cancel,
        ) {
            Ok(stats) => Ok(stats),
            Err(Par2Error::Cancelled) => Err(Par2Error::Cancelled),
            // mmap or I/O setup failure: the serial scanner owns the error
            // story (and will surface the same error if it persists).
            Err(_) => self.scan_file_ordered_canonical_serial(
                path,
                kind,
                lookup,
                target_file,
                blocks,
                scan_options,
                settled,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_file_ordered_canonical_serial(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        target_file: &SourceFileEntry,
        blocks: &mut ScanBlockState<'_>,
        scan_options: ScanSkipOptions,
        settled: &[bool],
    ) -> Result<FileScanStats> {
        let len = fs::metadata(path)?.len() as usize;
        let mut stats = FileScanStats::new(FileScanMode::OrderedCanonical, len as u64);
        let slice_size = self.table.slice_size as usize;
        if len == 0 || slice_size == 0 {
            return Ok(stats);
        }
        if len < slice_size {
            scan_short_blocks_from_file(
                self.table,
                path,
                kind,
                lookup.files,
                lookup.file_index_by_id,
                blocks,
                len,
            )?;
            return Ok(stats);
        }
        let ordered_full_blocks: Vec<usize> = (0..target_file.block_count)
            .map(|local| target_file.first_block + local)
            .filter(|block_index| blocks.block(*block_index).expected_len == self.table.slice_size)
            .collect();
        let settled_runs = settled_byte_runs(settled, slice_size, len);
        let mut next_run = 0usize;
        let mut settled_slices = 0u32;
        // Enter the file at its first unsettled byte rather than at zero. The
        // cursor fills its buffer as it is constructed, so opening at zero only
        // to seek away would read exactly the bytes this policy exists to
        // avoid.
        let mut entry_offset = 0usize;
        if let Some(&(start, end)) = settled_runs.first()
            && start == 0
        {
            entry_offset = end;
            next_run = 1;
            settled_slices += ((end - start) / slice_size) as u32;
        }
        if entry_offset > len - slice_size {
            // Every aligned window in the file belongs to a settled slice.
            // There is no walk left to run, only the short tail.
            stats.slices_settled_by_evidence = settled_slices;
            stats.bytes_skipped_by_evidence = entry_offset.min(len) as u64;
            scan_short_blocks_from_file(
                self.table,
                path,
                kind,
                lookup.files,
                lookup.file_index_by_id,
                blocks,
                len,
            )?;
            return Ok(stats);
        }
        let mut cursor =
            OrderedWindowCursor::new_at(path, slice_size, &self.window_table, entry_offset)?;
        let entry_local = entry_offset / slice_size;
        let mut preferred_next = ordered_full_blocks
            .iter()
            .position(|block_index| *block_index >= target_file.first_block + entry_local);
        let mut current_step_run = 0u64;
        let scan_distance = scan_options.scan_distance(slice_size);
        let scan_skip = if scan_distance > 0 {
            slice_size.saturating_sub(scan_distance)
        } else {
            0
        };
        let mut scan_offset = scan_distance / 2;

        while cursor.offset() <= cursor.last_full_offset() {
            // Retire runs the cursor has already passed. A block match or a
            // skip-data jump can land past or inside a run; either way the run
            // is simply not taken, and the bytes are read as they always were.
            while settled_runs
                .get(next_run)
                .is_some_and(|(_, end)| *end <= cursor.offset())
            {
                next_run += 1;
            }
            if let Some(&(start, end)) = settled_runs.get(next_run)
                && cursor.offset() == start
            {
                settled_slices = settled_slices.saturating_add(((end - start) / slice_size) as u32);
                stats.jumps_taken += 1;
                stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);
                current_step_run = 0;
                scan_offset = scan_distance / 2;
                next_run += 1;
                // Resume the ordered expectation at the first full block that
                // starts at or after the run, exactly as a match-driven jump
                // would have left it.
                let next_local = end / slice_size;
                preferred_next = ordered_full_blocks
                    .iter()
                    .position(|block_index| *block_index >= target_file.first_block + next_local);
                if !cursor.seek_to(end)? {
                    break;
                }
                continue;
            }

            let expected_block = preferred_next
                .and_then(|position| ordered_full_blocks.get(position))
                .copied();
            let selected = self.scan_ordered_window(
                OrderedWindowMatch {
                    path,
                    kind,
                    target_file_id: &target_file.file_id,
                    expected_block,
                    data: cursor.data(),
                    crc: cursor.crc(),
                    offset: cursor.offset() as u64,
                },
                blocks,
            );

            if let Some(selected) = selected {
                if blocks.block(selected).file_id == target_file.file_id {
                    preferred_next = ordered_full_blocks
                        .iter()
                        .position(|block_index| *block_index == selected)
                        .and_then(|position| {
                            ordered_full_blocks.get(position + 1).map(|_| position + 1)
                        });
                } else {
                    preferred_next = None;
                }

                stats.jumps_taken += 1;
                stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);
                current_step_run = 0;
                scan_offset = scan_distance / 2;

                if !cursor.jump(blocks.block(selected).expected_len as usize)? {
                    break;
                }
                continue;
            }

            preferred_next = None;
            if !cursor.step()? {
                break;
            }

            stats.windows_stepped += 1;
            current_step_run += 1;

            if scan_skip > 0 {
                scan_offset += 1;
                if scan_offset >= scan_distance && cursor.offset() < cursor.last_full_offset() {
                    stats.jumps_taken += 1;
                    stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);
                    current_step_run = 0;

                    if !cursor.jump(scan_skip)? {
                        break;
                    }
                    scan_offset = 0;
                }
            }
        }

        stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);
        stats.slices_settled_by_evidence = settled_slices;
        if settled_slices > 0 {
            // Measured, not assumed: without a skip this walk streams the whole
            // file, so whatever it did not read is what the skips saved. That
            // is narrower than the settled ranges themselves — a window
            // byte-stepping out of a damaged region still reads into the
            // settled slice that follows it — and this counter reports the
            // narrower, true number.
            stats.bytes_skipped_by_evidence = (len as u64).saturating_sub(cursor.bytes_read());
        }

        scan_short_blocks_from_file(
            self.table,
            path,
            kind,
            lookup.files,
            lookup.file_index_by_id,
            blocks,
            len,
        )?;

        Ok(stats)
    }

    fn scan_ordered_window(
        &self,
        window: OrderedWindowMatch<'_>,
        blocks: &mut ScanBlockState<'_>,
    ) -> Option<usize> {
        let matches = self.ordered_window_md5_matches(blocks.baseline(), window.data, window.crc);
        self.select_ordered_match(
            OrderedSelection {
                path: window.path,
                kind: window.kind,
                target_file_id: window.target_file_id,
                expected_block: window.expected_block,
                offset: window.offset,
            },
            &matches,
            blocks,
        )
    }

    /// Hashing half of the ordered window check: block indices whose CRC and
    /// MD5 both match the window, ascending. Expected-independent — the
    /// expected-block fast path can never select a block this set lacks, and
    /// the MD5 is computed exactly when any size-eligible CRC candidate
    /// exists, matching the serial lazy-init.
    fn ordered_window_md5_matches(
        &self,
        blocks: &[SourceBlock],
        data: &[u8],
        crc: u32,
    ) -> Vec<u32> {
        let mut matches = Vec::new();
        self.collect_ordered_window_md5_matches(blocks, data, crc, &mut matches);
        matches
    }

    /// [`Self::ordered_window_md5_matches`] into a caller-owned buffer, which
    /// it clears first. Phase A reuses one buffer per worker so it can size
    /// each retained match vector exactly, which is what its budget charges.
    fn collect_ordered_window_md5_matches(
        &self,
        blocks: &[SourceBlock],
        data: &[u8],
        crc: u32,
        matches: &mut Vec<u32>,
    ) {
        matches.clear();
        let Some(candidates) = self.table.by_crc.get(&crc) else {
            return;
        };
        let mut md5 = None;
        for block_index in candidates {
            let block = &blocks[*block_index];
            if block.expected_len != self.table.slice_size {
                continue;
            }
            let digest = *md5.get_or_insert_with(|| checksum::md5(data));
            if block.checksum.md5 == digest {
                matches.push(*block_index as u32);
            }
        }
    }

    /// Selection half of the ordered window check: applies the expected-block
    /// fast path, the duplicate-slice gate, and the rank preference over an
    /// already-hashed match set, then records the winner.
    fn select_ordered_match(
        &self,
        selection: OrderedSelection<'_>,
        matches: &[u32],
        blocks: &mut ScanBlockState<'_>,
    ) -> Option<usize> {
        let mut selected = None;

        if let Some(expected_block) = selection.expected_block
            && matches.contains(&(expected_block as u32))
            && can_select_ordered_match(
                expected_block,
                Some(expected_block),
                selection.path,
                blocks,
            )
        {
            selected = Some(expected_block);
        }

        for block_index in matches {
            let block_index = *block_index as usize;
            if Some(block_index) == selection.expected_block && selected == Some(block_index) {
                continue;
            }
            if can_select_ordered_match(
                block_index,
                selection.expected_block,
                selection.path,
                blocks,
            ) && preferred_ordered_match(
                selected,
                block_index,
                selection.expected_block,
                *selection.target_file_id,
                blocks,
            ) {
                selected = Some(block_index);
            }
        }

        if let Some(selected) = selected {
            let block = blocks.block(selected);
            record_block_location(
                blocks,
                selected,
                BlockLocation {
                    source: SourceLocation::Path(selection.path.to_path_buf()),
                    offset: selection.offset,
                    len: block.expected_len,
                    kind: selection.kind,
                },
            );
        }

        selected
    }

    /// Parallel ordered canonical scan: Phase A computes expected-independent
    /// facts for every slice-aligned window in parallel, Phase B replays the
    /// serial cursor state machine over those facts, and Phase C byte-steps
    /// through gaps, splicing back into Phase B when a match realigns. All
    /// reads go through bounded buffers (positional reads in Phase A, the
    /// serial cursor in Phase C). Everything the scan holds at once — facts
    /// headers, per-worker read buffers and scratch, and the match entries
    /// Phase A retains — is admitted under the configured working-memory
    /// budget; scans that do not fit, or that outgrow the match budget
    /// mid-flight, go to the serial scanner instead.
    #[allow(clippy::too_many_arguments)]
    fn scan_file_ordered_canonical_parallel(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        target_file: &SourceFileEntry,
        blocks: &mut ScanBlockState<'_>,
        scan_options: ScanSkipOptions,
        segment_windows: usize,
        memory_limit: usize,
        cancel: Option<&CancellationToken>,
    ) -> Result<FileScanStats> {
        let file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        let slice_size = self.table.slice_size as usize;
        if len == 0 || slice_size == 0 || len < slice_size {
            // Close the handle before the serial scan reopens `path`. Only
            // wasm targets lint here: their `std::fs::File` is an unsupported
            // stub holding nothing droppable, whereas on unix/windows it owns
            // a descriptor whose `Drop` does the close this relies on.
            #[allow(clippy::drop_non_drop)]
            drop(file);
            // No settled slices: a file with any is routed to the serial
            // scanner before this function is reached.
            return self.scan_file_ordered_canonical_serial(
                path,
                kind,
                lookup,
                target_file,
                blocks,
                scan_options,
                &[],
            );
        }
        let last_full_offset = len - slice_size;
        let window_count = last_full_offset / slice_size + 1;
        let segment_windows = segment_windows.max(1);
        let mut facts: Vec<AlignedWindowFacts> = Vec::new();
        // The header reservation runs only once the accounting admits the
        // scan, and is itself fallible; either refusal takes the serial path.
        let admission = ordered_scan_admission(
            window_count,
            segment_windows,
            slice_size,
            self.table.max_crc_bucket,
            ordered_scan_workers(window_count, segment_windows),
            memory_limit,
        )
        .filter(|_| facts.try_reserve_exact(window_count).is_ok());
        let Some(admission) = admission else {
            #[allow(clippy::drop_non_drop)]
            drop(file);
            return self.scan_file_ordered_canonical_serial(
                path,
                kind,
                lookup,
                target_file,
                blocks,
                scan_options,
                &[],
            );
        };

        crate::file_cache::advise_sequential(&file, path, len as u64);
        let mut stats = FileScanStats::new(FileScanMode::OrderedCanonicalParallel, len as u64);
        facts.resize_with(window_count, AlignedWindowFacts::default);
        let baseline = blocks.baseline();
        let shared_file = &file;
        let match_budget = OrderedScanMatchBudget::new(admission.match_budget);
        let phase_a = facts
            .par_chunks_mut(segment_windows)
            .enumerate()
            .try_for_each_init(
                || (Vec::new(), Vec::new()),
                |(read_buffer, candidates), (segment_index, segment)| {
                    self.compute_aligned_window_facts(
                        shared_file,
                        baseline,
                        segment,
                        segment_index * segment_windows,
                        admission.read_windows,
                        read_buffer,
                        candidates,
                        &match_budget,
                        cancel,
                    )
                },
            );
        match phase_a {
            Ok(()) => {}
            // Cancellation and I/O keep the pre-existing story: the caller
            // decides whether to propagate or re-run the file serially.
            Err(WindowFactsError::Scan(error)) => {
                #[allow(clippy::drop_non_drop)]
                drop(file);
                return Err(error);
            }
            // A refusal is not a failure — the partial facts go away and the
            // file is rescanned serially from a clean slate. Phase A only
            // reads `blocks`, so no partial selection has to be unwound.
            Err(WindowFactsError::Refused) => {
                drop(facts);
                #[allow(clippy::drop_non_drop)]
                drop(file);
                return self.scan_file_ordered_canonical_serial(
                    path,
                    kind,
                    lookup,
                    target_file,
                    blocks,
                    scan_options,
                    &[],
                );
            }
        }

        let ordered_full_blocks: Vec<usize> = (0..target_file.block_count)
            .map(|local| target_file.first_block + local)
            .filter(|block_index| blocks.block(*block_index).expected_len == self.table.slice_size)
            .collect();
        let resync = OrderedResync {
            facts: &facts,
            ordered_full_blocks: &ordered_full_blocks,
            path,
            kind,
            target_file_id: &target_file.file_id,
        };

        let mut preferred_next = (!ordered_full_blocks.is_empty()).then_some(0usize);
        let mut current_step_run = 0u64;
        let mut window_index = 0usize;
        while window_index < window_count {
            let expected_block = preferred_next
                .and_then(|position| ordered_full_blocks.get(position))
                .copied();
            let offset = window_index * slice_size;
            let selected = self.select_ordered_match(
                OrderedSelection {
                    path,
                    kind,
                    target_file_id: &target_file.file_id,
                    expected_block,
                    offset: offset as u64,
                },
                &facts[window_index].matches,
                blocks,
            );

            if let Some(selected) = selected {
                preferred_next = ordered_preferred_after_selection(
                    &ordered_full_blocks,
                    selected,
                    &target_file.file_id,
                    blocks,
                );
                stats.jumps_taken += 1;
                stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);
                current_step_run = 0;
                window_index += 1;
                continue;
            }

            // A mismatch clears the expected chain; the resync outcome
            // carries the replacement `preferred_next` back across the
            // boundary. Mirrors the serial cursor: a failed step off the
            // last full window ends the scan without counting a step.
            if offset >= last_full_offset {
                break;
            }
            stats.windows_stepped += 1;
            current_step_run += 1;
            match self.rolling_resync_ordered(
                &resync,
                offset + 1,
                blocks,
                &mut stats,
                &mut current_step_run,
            )? {
                ResyncOutcome::Realigned {
                    next_window,
                    preferred_next: next_preferred,
                } => {
                    window_index = next_window;
                    preferred_next = next_preferred;
                }
                ResyncOutcome::End => break,
            }
        }

        stats.max_consecutive_steps = stats.max_consecutive_steps.max(current_step_run);

        let short_result = scan_short_blocks_from_file(
            self.table,
            path,
            kind,
            lookup.files,
            lookup.file_index_by_id,
            blocks,
            len,
        );
        crate::file_cache::drop_file_cache(&file, path, 0, len as u64);
        short_result?;

        Ok(stats)
    }

    /// Phase A worker: fills one segment's facts. Reads only the hash table
    /// and the immutable baseline blocks, so segments run lock-free. Windows
    /// arrive through `read_buffer` in whole-window chunks of `read_windows`,
    /// positionally read from the shared handle. Hashing is the serial
    /// scanner's single-shot CRC-gated MD5: multi-lane MD5 batching lost here
    /// because every lane required a padded copy of its window (it may return
    /// per-arch if measurement justifies it).
    ///
    /// `read_buffer` and `candidates` are the worker-owned buffers the
    /// admission already paid for; every retained match vector is charged
    /// against `match_budget` at its exact size, so a duplicate-heavy file
    /// refuses rather than growing past the working-memory limit.
    #[allow(clippy::too_many_arguments)]
    fn compute_aligned_window_facts(
        &self,
        file: &File,
        blocks: &[SourceBlock],
        facts: &mut [AlignedWindowFacts],
        first_window: usize,
        read_windows: usize,
        read_buffer: &mut Vec<u8>,
        candidates: &mut Vec<u32>,
        match_budget: &OrderedScanMatchBudget,
        cancel: Option<&CancellationToken>,
    ) -> std::result::Result<(), WindowFactsError> {
        if let Some(cancel) = cancel
            && cancel.is_cancelled()
        {
            return Err(WindowFactsError::Scan(Par2Error::Cancelled));
        }

        let slice_size = self.table.slice_size as usize;
        let read_windows = read_windows.max(1);
        let mut slot = 0usize;
        while slot < facts.len() {
            let read_count = read_windows.min(facts.len() - slot);
            let read_len = read_count
                .checked_mul(slice_size)
                .ok_or(WindowFactsError::Refused)?;
            if read_buffer.len() < read_len {
                read_buffer
                    .try_reserve(read_len - read_buffer.len())
                    .map_err(|_| WindowFactsError::Refused)?;
                read_buffer.resize(read_len, 0);
            }
            let read_offset = ((first_window + slot) * slice_size) as u64;
            read_exact_file_at(file, &mut read_buffer[..read_len], read_offset)?;
            for (index, window) in read_buffer[..read_len].chunks_exact(slice_size).enumerate() {
                let crc = checksum::crc32(window);
                self.collect_ordered_window_md5_matches(blocks, window, crc, candidates);
                if candidates.is_empty() {
                    continue;
                }
                let charge = candidates
                    .len()
                    .checked_mul(std::mem::size_of::<u32>())
                    .ok_or(WindowFactsError::Refused)?;
                if !match_budget.charge(charge) {
                    return Err(WindowFactsError::Refused);
                }
                let mut retained = Vec::new();
                retained
                    .try_reserve_exact(candidates.len())
                    .map_err(|_| WindowFactsError::Refused)?;
                retained.extend_from_slice(candidates);
                facts[slot + index].matches = retained;
            }
            slot += read_count;
        }
        Ok(())
    }

    /// Phase C: byte-steps from `start` exactly as the serial cursor would
    /// after a failed window, consuming precomputed facts whenever the
    /// position is slice-aligned. Returns `Realigned` when a match lands on
    /// an aligned offset so the merge loop can resume from facts. Gap bytes
    /// are read through the serial scanner's bounded cursor, so only the gap
    /// region is touched and only two windows are ever resident.
    fn rolling_resync_ordered(
        &self,
        resync: &OrderedResync<'_>,
        start: usize,
        blocks: &mut ScanBlockState<'_>,
        stats: &mut FileScanStats,
        current_step_run: &mut u64,
    ) -> Result<ResyncOutcome> {
        let slice_size = self.table.slice_size as usize;
        let mut preferred_next: Option<usize> = None;
        let mut cursor =
            OrderedWindowCursor::new_at(resync.path, slice_size, &self.window_table, start)?;

        loop {
            let expected_block = preferred_next
                .and_then(|position| resync.ordered_full_blocks.get(position))
                .copied();
            let offset = cursor.offset();
            let selection = OrderedSelection {
                path: resync.path,
                kind: resync.kind,
                target_file_id: resync.target_file_id,
                expected_block,
                offset: offset as u64,
            };
            let aligned_window = offset
                .is_multiple_of(slice_size)
                .then(|| offset / slice_size);
            let selected = if let Some(window_index) = aligned_window {
                self.select_ordered_match(selection, &resync.facts[window_index].matches, blocks)
            } else {
                let matches =
                    self.ordered_window_md5_matches(blocks.baseline(), cursor.data(), cursor.crc());
                self.select_ordered_match(selection, &matches, blocks)
            };

            if let Some(selected) = selected {
                let next_preferred = ordered_preferred_after_selection(
                    resync.ordered_full_blocks,
                    selected,
                    resync.target_file_id,
                    blocks,
                );
                stats.jumps_taken += 1;
                stats.max_consecutive_steps = stats.max_consecutive_steps.max(*current_step_run);
                *current_step_run = 0;
                if let Some(window_index) = aligned_window {
                    return Ok(ResyncOutcome::Realigned {
                        next_window: window_index + 1,
                        preferred_next: next_preferred,
                    });
                }
                preferred_next = next_preferred;
                // The cursor jump recomputes a fresh window CRC, matching the
                // serial scanner's post-jump recompute.
                if !cursor.jump(slice_size)? {
                    return Ok(ResyncOutcome::End);
                }
                continue;
            }

            preferred_next = None;
            if !cursor.step()? {
                return Ok(ResyncOutcome::End);
            }
            stats.windows_stepped += 1;
            *current_step_run += 1;
        }
    }

    #[cfg(test)]
    fn scan_file_buffered_with_target(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut [SourceBlock],
        read_target: usize,
    ) -> Result<FileScanStats> {
        self.scan_file_buffered_with_target_options(
            path,
            kind,
            SourceFileScanLookup {
                files,
                file_index_by_id,
            },
            blocks,
            read_target,
            ScanSkipOptions::disabled(),
        )
    }

    #[cfg(test)]
    fn scan_file_buffered_with_target_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        blocks: &mut [SourceBlock],
        read_target: usize,
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        let baseline = blocks.to_vec();
        let mut state = ScanBlockState::new(&baseline);
        let stats = self.scan_file_buffered_with_target_state_options(
            path,
            kind,
            lookup,
            &mut state,
            read_target,
            scan_options,
        )?;
        self.relocate_open_short_blocks_in(path, kind, &mut state)?;
        state.apply_to_blocks(blocks);
        Ok(stats)
    }

    fn scan_file_buffered_with_target_state_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        lookup: SourceFileScanLookup<'_>,
        blocks: &mut ScanBlockState<'_>,
        read_target: usize,
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        crate::file_cache::advise_sequential(&file, path, len as u64);
        let mut stats = FileScanStats::new(FileScanMode::RollingGeneric, len as u64);
        if len == 0 {
            return Ok(stats);
        }

        let mut total_read = 0usize;
        let slice_size = self.table.slice_size as usize;
        if slice_size > 0 && len >= slice_size {
            let overlap = slice_size - 1;
            let fresh_read_target = slice_size.max(read_target);
            let buffer_len = overlap.checked_add(fresh_read_target).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "scanner buffer size overflow")
            })?;
            let mut buffer = vec![0u8; buffer_len];
            let mut valid_len = 0usize;
            let mut base_offset = 0usize;
            let mut next_unscanned_offset = 0usize;
            let mut scan_progress = RollingScanProgress::new(scan_options, slice_size);
            let mut scan_context = BufferedWindowScan {
                scanner: self,
                path,
                kind,
                blocks,
                scan_options,
                progress: &mut scan_progress,
                stats: &mut stats,
            };

            loop {
                if valid_len == buffer.len() {
                    let keep = overlap.min(valid_len);
                    buffer.copy_within(valid_len - keep..valid_len, 0);
                    base_offset += valid_len - keep;
                    valid_len = keep;
                }

                let read_len = file.read(&mut buffer[valid_len..])?;
                total_read += read_len;
                valid_len += read_len;

                scan_buffered_windows(
                    &mut scan_context,
                    &buffer[..valid_len],
                    base_offset,
                    &mut next_unscanned_offset,
                );

                if read_len == 0 {
                    break;
                }
            }
        }

        if !scan_options.skip_data {
            stats.max_consecutive_steps = stats.windows_stepped;
        }
        let short_result = scan_short_blocks_from_file(
            self.table,
            path,
            kind,
            lookup.files,
            lookup.file_index_by_id,
            blocks,
            len,
        );
        crate::file_cache::drop_touched_file_cache(&file, path, len as u64, 0, total_read as u64);
        short_result?;

        Ok(stats)
    }

    #[cfg(test)]
    fn scan_file_mmap(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut [SourceBlock],
    ) -> Result<FileScanStats> {
        self.scan_file_mmap_with_options(
            path,
            kind,
            files,
            file_index_by_id,
            blocks,
            ScanSkipOptions::disabled(),
        )
    }

    #[cfg(test)]
    fn scan_file_mmap_with_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut [SourceBlock],
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        let baseline = blocks.to_vec();
        let mut state = ScanBlockState::new(&baseline);
        let stats = self.scan_file_mmap_with_state_options(
            path,
            kind,
            files,
            file_index_by_id,
            &mut state,
            scan_options,
        )?;
        self.relocate_open_short_blocks_in(path, kind, &mut state)?;
        state.apply_to_blocks(blocks);
        Ok(stats)
    }

    fn scan_file_mmap_with_state_options(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        files: &[SourceFileEntry],
        file_index_by_id: &HashMap<FileId, usize>,
        blocks: &mut ScanBlockState<'_>,
        scan_options: ScanSkipOptions,
    ) -> Result<FileScanStats> {
        let file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        crate::file_cache::advise_sequential(&file, path, len as u64);
        let mut stats = FileScanStats::new(FileScanMode::RollingGeneric, len as u64);
        if len == 0 {
            return Ok(stats);
        }

        let map = MappedFile::map(&file)?;
        let slice_size = self.table.slice_size as usize;
        if slice_size > 0 && len >= slice_size {
            let mut crc = checksum::crc32(&map[..slice_size]);
            let last = len - slice_size;
            let scan_distance = scan_options.scan_distance(slice_size);
            let scan_skip = if scan_distance > 0 {
                slice_size.saturating_sub(scan_distance)
            } else {
                0
            };
            let mut scan_progress = RollingScanProgress::new(scan_options, slice_size);
            let scanner_batch_lanes = scanner_md5_batch_lanes(slice_size);
            let mut pending = Vec::with_capacity(scanner_batch_lanes);
            let mut offset = 0usize;
            while offset <= last {
                let mut saw_crc_candidate = false;
                if let Some(candidates) = self.table.by_crc.get(&crc) {
                    for block_index in candidates {
                        let block = blocks.block(*block_index);
                        if block.expected_len != self.table.slice_size {
                            continue;
                        }
                        if !can_record_block_location(blocks, *block_index, path, kind) {
                            continue;
                        }
                        saw_crc_candidate = true;
                        let data = &map[offset..offset + slice_size];
                        if scanner_batch_lanes < 2 {
                            record_matching_md5_block(
                                blocks,
                                *block_index,
                                data,
                                path,
                                offset as u64,
                                block.expected_len,
                                kind,
                            );
                            continue;
                        }
                        pending.push(PendingMd5Check {
                            block_index: *block_index,
                            data,
                            offset: offset as u64,
                            len: block.expected_len,
                            kind,
                        });
                        if pending.len() == scanner_batch_lanes {
                            flush_pending_md5_checks(&mut pending, blocks, path);
                        }
                    }
                }
                if offset < last {
                    crc = crc_slide_char(
                        crc,
                        map[offset + slice_size],
                        map[offset],
                        &self.window_table,
                    );
                    offset += 1;
                    scan_progress.record_step(&mut stats);

                    if scan_skip > 0 {
                        if saw_crc_candidate {
                            scan_progress.scan_offset = scan_distance / 2;
                        } else {
                            scan_progress.scan_offset = scan_progress.scan_offset.saturating_add(1);
                            if scan_progress.scan_offset >= scan_distance && offset < last {
                                scan_progress.record_jump(&mut stats);
                                scan_progress.scan_offset = 0;
                                offset = offset.saturating_add(scan_skip).min(last);
                                crc = checksum::crc32(&map[offset..offset + slice_size]);
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            flush_pending_md5_checks(&mut pending, blocks, path);
            stats.max_consecutive_steps = stats
                .max_consecutive_steps
                .max(scan_progress.current_step_run);
        }
        if !scan_options.skip_data {
            stats.max_consecutive_steps = stats.windows_stepped;
        }

        for block_index in &self.table.short_blocks {
            if blocks.location(*block_index).is_some() {
                continue;
            }
            let block = blocks.block(*block_index);
            let short_len = block.expected_len as usize;
            if short_len == 0 || short_len > len {
                continue;
            }
            if let Some(file) = file_index_by_id
                .get(&block.file_id)
                .and_then(|idx| files.get(*idx))
                && file.safe_path == path
            {
                let offset = block.local_index as u64 * self.table.slice_size;
                if offset <= usize::MAX as u64 {
                    let offset = offset as usize;
                    if offset.checked_add(short_len).is_some_and(|end| end <= len)
                        && short_block_matches(
                            &map[offset..offset + short_len],
                            self.table.slice_size,
                            block,
                        )
                    {
                        record_block_location(
                            blocks,
                            *block_index,
                            BlockLocation {
                                source: SourceLocation::Path(path.to_path_buf()),
                                offset: offset as u64,
                                len: block.expected_len,
                                kind,
                            },
                        );
                        continue;
                    }
                }
            }
            let tail_offset = len - short_len;
            if short_block_matches(
                &map[tail_offset..tail_offset + short_len],
                self.table.slice_size,
                block,
            ) {
                record_block_location(
                    blocks,
                    *block_index,
                    BlockLocation {
                        source: SourceLocation::Path(path.to_path_buf()),
                        offset: tail_offset as u64,
                        len: block.expected_len,
                        kind,
                    },
                );
            }
        }

        drop(map);
        crate::file_cache::drop_file_cache(&file, path, 0, len as u64);
        Ok(stats)
    }

    /// Test-only mirror of the production two-phase shape: scan one candidate,
    /// then run the relocation search over whatever short blocks that scan left
    /// open. Production defers the same search to
    /// [`RepairState::relocate_open_short_blocks`], which runs it once over the
    /// merged state of a whole candidate batch instead of once per candidate.
    #[cfg(test)]
    fn relocate_open_short_blocks_in(
        &self,
        path: &Path,
        kind: BlockLocationKind,
        blocks: &mut ScanBlockState<'_>,
    ) -> Result<ShortRelocationStats> {
        let mut stats = ShortRelocationStats::default();
        let Ok(metadata) = fs::metadata(path) else {
            return Ok(stats);
        };
        let len = metadata.len() as usize;
        if len == 0 {
            return Ok(stats);
        }
        let open = open_short_blocks(self.table, blocks, self.table.slice_size);
        let mut scan = ShortRelocationScan {
            table: self.table,
            path,
            kind,
            open: &open,
            blocks,
            stats: &mut stats,
        };
        scan_shifted_short_blocks_from_file(&mut scan, len)?;
        Ok(stats)
    }
}

fn ordered_scan_force_serial() -> bool {
    static FORCE_SERIAL: LazyLock<bool> = LazyLock::new(|| {
        std::env::var(ORDERED_SCAN_SERIAL_ENV)
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    });
    *FORCE_SERIAL
}

/// The parallel ordered scan is the default. Its first cut (whole-file
/// mmap + padded-lane MD5 batching) measured slower than the serial cursor
/// at 40x the memory and was made opt-in; the rework onto bounded buffered
/// reads and single-shot MD5 then passed the recorded gate on the x86 box
/// (damaged 2 GB verify: parallel 5.44 s / 81 MB max RSS vs serial 7.10 s /
/// 53 MB), flipping the default here. `WEAVER_PAR2_PARALLEL_SCAN=0`
/// disables it; `WEAVER_PAR2_SERIAL_SCAN=1` remains the hard force.
fn ordered_scan_parallel_enabled() -> bool {
    static ENABLED: LazyLock<bool> = LazyLock::new(|| {
        !std::env::var(ORDERED_SCAN_PARALLEL_ENV)
            .is_ok_and(|value| value == "0" || value.eq_ignore_ascii_case("false"))
    });
    *ENABLED
}

fn ordered_scan_segment_windows(slice_size: usize) -> usize {
    if slice_size == 0 {
        return 1;
    }
    (SCANNER_PARALLEL_SEGMENT_TARGET_BYTES / slice_size).clamp(1, 4096)
}

/// The serial scanner's post-selection `preferred_next` rule: continue the
/// chain past the selected block when it belongs to the target file, drop it
/// otherwise.
fn ordered_preferred_after_selection(
    ordered_full_blocks: &[usize],
    selected: usize,
    target_file_id: &FileId,
    blocks: &ScanBlockState<'_>,
) -> Option<usize> {
    if blocks.block(selected).file_id != *target_file_id {
        return None;
    }
    ordered_full_blocks
        .iter()
        .position(|block_index| *block_index == selected)
        .and_then(|position| ordered_full_blocks.get(position + 1).map(|_| position + 1))
}

fn ordered_match_rank(
    block_index: usize,
    expected_block: Option<usize>,
    preferred_file_id: FileId,
    blocks: &ScanBlockState<'_>,
) -> (u8, usize) {
    if Some(block_index) == expected_block {
        return (0, block_index);
    }
    if blocks.block(block_index).file_id == preferred_file_id {
        return (1, block_index);
    }
    (2, block_index)
}

fn can_select_ordered_match(
    block_index: usize,
    expected_block: Option<usize>,
    path: &Path,
    blocks: &ScanBlockState<'_>,
) -> bool {
    match blocks.location(block_index) {
        None => true,
        Some(location) if Some(block_index) == expected_block => !location.source.is_path(path),
        Some(_) => false,
    }
}

fn preferred_ordered_match(
    current: Option<usize>,
    candidate: usize,
    expected_block: Option<usize>,
    preferred_file_id: FileId,
    blocks: &ScanBlockState<'_>,
) -> bool {
    let candidate_rank = ordered_match_rank(candidate, expected_block, preferred_file_id, blocks);
    current.is_none_or(|current| {
        candidate_rank < ordered_match_rank(current, expected_block, preferred_file_id, blocks)
    })
}

fn log_file_scan(
    path: &Path,
    kind: BlockLocationKind,
    stats: FileScanStats,
    blocks_confirmed: u32,
    elapsed: Duration,
) {
    debug!(
        path = %path.display(),
        ?kind,
        scan_mode = stats.mode.as_str(),
        bytes_scanned = stats.bytes_scanned,
        windows_stepped = stats.windows_stepped,
        jumps_taken = stats.jumps_taken,
        max_consecutive_steps = stats.max_consecutive_steps,
        blocks_confirmed,
        elapsed_ms = elapsed.as_millis(),
        "completed par2 file scan"
    );

    if stats.max_consecutive_steps >= SCANNER_SLOW_WARN_STEPS
        || elapsed >= SCANNER_SLOW_WARN_DURATION
    {
        warn!(
            path = %path.display(),
            ?kind,
            scan_mode = stats.mode.as_str(),
            bytes_scanned = stats.bytes_scanned,
            windows_stepped = stats.windows_stepped,
            jumps_taken = stats.jumps_taken,
            max_consecutive_steps = stats.max_consecutive_steps,
            blocks_confirmed,
            elapsed_ms = elapsed.as_millis(),
            "slow par2 file scan"
        );
    }
}

/// One candidate's share of the deferred short-block relocation search.
///
/// The ordinary file-scan counters never see this work — it happens after the
/// scan, over a candidate the scan already read — so it gets its own record.
/// `short_lengths` is what the sweep actually looked for: one full pass over
/// the candidate per entry.
fn log_short_relocation(
    path: &Path,
    kind: BlockLocationKind,
    short_lengths: &[usize],
    stats: &ShortRelocationStats,
    elapsed: Duration,
) {
    debug!(
        path = %path.display(),
        ?kind,
        scan_mode = "short_relocation",
        short_lengths = ?short_lengths,
        short_lengths_attempted = short_lengths.len(),
        windows_stepped = stats.windows_stepped,
        bytes_reread = stats.bytes_read,
        blocks_placed = stats.blocks_placed,
        elapsed_ms = elapsed.as_millis(),
        "completed par2 short-block relocation scan"
    );

    if stats.windows_stepped >= SCANNER_SLOW_WARN_STEPS || elapsed >= SCANNER_SLOW_WARN_DURATION {
        warn!(
            path = %path.display(),
            ?kind,
            scan_mode = "short_relocation",
            short_lengths = ?short_lengths,
            short_lengths_attempted = short_lengths.len(),
            windows_stepped = stats.windows_stepped,
            bytes_reread = stats.bytes_read,
            blocks_placed = stats.blocks_placed,
            elapsed_ms = elapsed.as_millis(),
            "slow par2 short-block relocation scan"
        );
    }
}

fn log_short_relocation_pass(
    candidates_considered: usize,
    candidates_scanned: u32,
    candidates_skipped: u32,
    open_short_blocks: usize,
    stats: &ShortRelocationStats,
    elapsed: Duration,
) {
    debug!(
        candidates_considered,
        candidates_scanned,
        candidates_skipped,
        open_short_blocks,
        windows_stepped = stats.windows_stepped,
        bytes_reread = stats.bytes_read,
        blocks_placed = stats.blocks_placed,
        elapsed_ms = elapsed.as_millis(),
        "completed par2 short-block relocation pass"
    );

    if stats.windows_stepped >= SCANNER_SLOW_WARN_STEPS || elapsed >= SCANNER_SLOW_WARN_DURATION {
        warn!(
            candidates_considered,
            candidates_scanned,
            candidates_skipped,
            open_short_blocks,
            windows_stepped = stats.windows_stepped,
            bytes_reread = stats.bytes_read,
            blocks_placed = stats.blocks_placed,
            elapsed_ms = elapsed.as_millis(),
            "slow par2 short-block relocation pass"
        );
    }
}

fn scan_buffered_windows(
    scan: &mut BufferedWindowScan<'_, '_, '_>,
    buffer: &[u8],
    base_offset: usize,
    next_unscanned_offset: &mut usize,
) {
    let scanner = scan.scanner;
    let path = scan.path;
    let kind = scan.kind;
    let scan_options = scan.scan_options;
    let slice_size = scanner.table.slice_size as usize;
    if slice_size == 0 || buffer.len() < slice_size {
        return;
    }

    let last_local_offset = buffer.len() - slice_size;
    let mut local_offset = next_unscanned_offset.saturating_sub(base_offset);
    if local_offset > last_local_offset {
        return;
    }

    let scan_distance = scan_options.scan_distance(slice_size);
    let scan_skip = if scan_distance > 0 {
        slice_size.saturating_sub(scan_distance)
    } else {
        0
    };
    let scanner_batch_lanes = scanner_md5_batch_lanes(slice_size);
    let mut pending = Vec::with_capacity(scanner_batch_lanes);
    let mut crc = checksum::crc32(&buffer[local_offset..local_offset + slice_size]);

    loop {
        let mut saw_crc_candidate = false;
        if let Some(candidates) = scanner.table.by_crc.get(&crc) {
            for block_index in candidates {
                let expected_len = scan.blocks.block(*block_index).expected_len;
                if expected_len != scanner.table.slice_size {
                    continue;
                }
                if !can_record_block_location(scan.blocks, *block_index, path, kind) {
                    continue;
                }
                saw_crc_candidate = true;
                let data = &buffer[local_offset..local_offset + slice_size];
                let absolute_offset = (base_offset + local_offset) as u64;
                if scanner_batch_lanes < 2 {
                    record_matching_md5_block(
                        scan.blocks,
                        *block_index,
                        data,
                        path,
                        absolute_offset,
                        expected_len,
                        kind,
                    );
                    continue;
                }
                pending.push(PendingMd5Check {
                    block_index: *block_index,
                    data,
                    offset: absolute_offset,
                    len: expected_len,
                    kind,
                });
                if pending.len() == scanner_batch_lanes {
                    flush_pending_md5_checks(&mut pending, scan.blocks, path);
                }
            }
        }

        if local_offset == last_local_offset {
            break;
        }

        crc = crc_slide_char(
            crc,
            buffer[local_offset + slice_size],
            buffer[local_offset],
            &scanner.window_table,
        );
        local_offset += 1;
        scan.progress.record_step(scan.stats);
        *next_unscanned_offset = base_offset + local_offset;

        if scan_skip > 0 {
            if saw_crc_candidate {
                scan.progress.scan_offset = scan_distance / 2;
            } else {
                scan.progress.scan_offset = scan.progress.scan_offset.saturating_add(1);
                if scan.progress.scan_offset >= scan_distance && local_offset < last_local_offset {
                    let jump_offset = (base_offset + local_offset).saturating_add(scan_skip);
                    scan.progress.record_jump(scan.stats);
                    scan.progress.scan_offset = 0;

                    if jump_offset > base_offset + last_local_offset {
                        *next_unscanned_offset = jump_offset;
                        flush_pending_md5_checks(&mut pending, scan.blocks, path);
                        scan.stats.max_consecutive_steps = scan
                            .stats
                            .max_consecutive_steps
                            .max(scan.progress.current_step_run);
                        return;
                    }

                    local_offset = jump_offset - base_offset;
                    *next_unscanned_offset = jump_offset;
                    crc = checksum::crc32(&buffer[local_offset..local_offset + slice_size]);
                }
            }
        }
    }

    flush_pending_md5_checks(&mut pending, scan.blocks, path);
    *next_unscanned_offset = base_offset + last_local_offset + 1;
    scan.stats.max_consecutive_steps = scan
        .stats
        .max_consecutive_steps
        .max(scan.progress.current_step_run);
}

fn scan_short_blocks_from_file(
    table: &VerificationHashTable,
    path: &Path,
    kind: BlockLocationKind,
    files: &[SourceFileEntry],
    file_index_by_id: &HashMap<FileId, usize>,
    blocks: &mut ScanBlockState<'_>,
    len: usize,
) -> Result<()> {
    let max_tail_len = table
        .short_blocks
        .iter()
        .filter_map(|block_index| {
            let block = blocks.block(*block_index);
            let short_len = block.expected_len as usize;
            (blocks.location(*block_index).is_none() && short_len > 0 && short_len <= len)
                .then_some(short_len)
        })
        .max()
        .unwrap_or(0);

    let tail = if max_tail_len > 0 {
        read_exact_file_range(path, (len - max_tail_len) as u64, max_tail_len)?
    } else {
        Vec::new()
    };

    for block_index in &table.short_blocks {
        if blocks.location(*block_index).is_some() {
            continue;
        }
        let block = blocks.block(*block_index);
        let short_len = block.expected_len as usize;
        if short_len == 0 || short_len > len {
            continue;
        }
        if let Some(file) = file_index_by_id
            .get(&block.file_id)
            .and_then(|idx| files.get(*idx))
            && file.safe_path == path
        {
            let offset = block.local_index as u64 * table.slice_size;
            if offset <= usize::MAX as u64 {
                let offset = offset as usize;
                if offset.checked_add(short_len).is_some_and(|end| end <= len) {
                    let data = read_exact_file_range(path, offset as u64, short_len)?;
                    if short_block_matches(&data, table.slice_size, block) {
                        record_block_location(
                            blocks,
                            *block_index,
                            BlockLocation {
                                source: SourceLocation::Path(path.to_path_buf()),
                                offset: offset as u64,
                                len: block.expected_len,
                                kind,
                            },
                        );
                        continue;
                    }
                }
            }
        }

        let tail_offset = len - short_len;
        let tail_start = tail.len() - short_len;
        if short_block_matches(&tail[tail_start..], table.slice_size, block) {
            record_block_location(
                blocks,
                *block_index,
                BlockLocation {
                    source: SourceLocation::Path(path.to_path_buf()),
                    offset: tail_offset as u64,
                    len: block.expected_len,
                    kind,
                },
            );
        }
    }

    Ok(())
}

/// Everything the exhaustive short-block relocation search works on for one
/// candidate: the table it matches against, the candidate it re-reads, the set
/// of short blocks whose placement is still open, the shared block state it
/// records into, and its own accounting.
struct ShortRelocationScan<'a, 'blocks> {
    table: &'a VerificationHashTable,
    path: &'a Path,
    kind: BlockLocationKind,
    /// Indexed by block index; `true` for a short block still worth hunting.
    open: &'a [bool],
    blocks: &'a mut ScanBlockState<'blocks>,
    stats: &'a mut ShortRelocationStats,
}

/// The per-length constants of one relocation sweep, hoisted out of the
/// window loop.
struct ShortWindowParams<'a> {
    short_len: usize,
    zero_combine: &'a checksum::Crc32CombineOp,
    zero_crc: u32,
    window_table: &'a [u32; 256],
}

/// Sweep one candidate for every still-open short length that fits in it.
/// Returns the lengths it attempted, for logging.
fn scan_shifted_short_blocks_from_file(
    scan: &mut ShortRelocationScan<'_, '_>,
    len: usize,
) -> Result<Vec<usize>> {
    let lengths = open_short_lengths(scan.table, scan.blocks, scan.open, len);
    for short_len in &lengths {
        scan_shifted_short_len_from_file(scan, len, *short_len)?;
    }

    Ok(lengths)
}

/// Short block placements the relocation search is still allowed to improve.
///
/// A short block already sitting at its own slice offset is settled: whichever
/// container it was found in is a positional copy of its file — the file
/// itself, or a renamed or obfuscated copy of it — so the block is exactly
/// where it belongs and the same MD5-verified bytes found elsewhere could only
/// be an equivalent source. Hunting for it again is pure cost, and it is that
/// cost, repeated per candidate, that made a healthy multi-file set quadratic.
///
/// A placement at any other offset stays open, so a better placement can still
/// displace it exactly as it could when every candidate searched its own
/// snapshot and the merge arbitrated between them.
fn open_short_blocks(
    table: &VerificationHashTable,
    blocks: &ScanBlockState<'_>,
    slice_size: u64,
) -> Vec<bool> {
    let mut open = vec![false; blocks.baseline().len()];
    for block_index in &table.short_blocks {
        open[*block_index] = !short_block_is_settled(blocks, *block_index, slice_size);
    }
    open
}

fn short_block_is_settled(
    blocks: &ScanBlockState<'_>,
    block_index: usize,
    slice_size: u64,
) -> bool {
    let Some(location) = blocks.location(block_index) else {
        return false;
    };
    let block = blocks.block(block_index);
    location.offset == u64::from(block.local_index).saturating_mul(slice_size)
        && location.len == block.expected_len
}

/// Total bytes the merged spans cover, merging overlaps. Sorts in place.
fn merged_span_bytes(spans: &mut [(u64, u64)]) -> u64 {
    spans.sort_unstable();
    let mut covered = 0u64;
    let mut reach = 0u64;
    for (offset, len) in spans.iter() {
        let end = offset.saturating_add(*len);
        let start = (*offset).max(reach);
        if end > start {
            covered = covered.saturating_add(end - start);
            reach = end;
        }
    }
    covered
}

/// The distinct short lengths still worth sweeping a `len`-byte candidate for.
/// Deduping by length is what makes the sweep affordable: one pass over the
/// candidate answers every open short block of that length at once.
fn open_short_lengths(
    table: &VerificationHashTable,
    blocks: &ScanBlockState<'_>,
    open: &[bool],
    len: usize,
) -> Vec<usize> {
    let mut lengths: Vec<usize> = table
        .short_blocks
        .iter()
        .filter_map(|block_index| {
            let block = blocks.block(*block_index);
            let short_len = block.expected_len as usize;
            (open.get(*block_index).copied().unwrap_or(false) && short_len > 0 && short_len <= len)
                .then_some(short_len)
        })
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

fn scan_shifted_short_len_from_file(
    scan: &mut ShortRelocationScan<'_, '_>,
    len: usize,
    short_len: usize,
) -> Result<()> {
    if short_len == 0 || short_len > len {
        return Ok(());
    }
    let table = scan.table;
    let path = scan.path;

    if short_len > SCANNER_IO_TARGET_BYTES {
        let file = File::open(path)?;
        let map = MappedFile::map(&file)?;
        scan.stats.bytes_read = scan.stats.bytes_read.saturating_add(map.len() as u64);
        scan_shifted_short_len_from_slice(scan, &map, short_len);
        drop(map);
        crate::file_cache::drop_file_cache(&file, path, 0, len as u64);
        return Ok(());
    }

    let mut file = File::open(path)?;
    let overlap = short_len.saturating_sub(1);
    let fresh_read_target = SCANNER_IO_TARGET_BYTES;
    let buffer_len = overlap.checked_add(fresh_read_target).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "scanner buffer size overflow")
    })?;
    let mut buffer = vec![0u8; buffer_len];
    let mut valid_len = 0usize;
    let mut base_offset = 0usize;
    let mut next_unscanned_offset = 0usize;
    let mut total_read = 0usize;
    let window_table = generate_window_table(short_len as u64);
    let pad_len = table.slice_size.saturating_sub(short_len as u64);
    let zero_crc = crc32_zeros(pad_len);
    let zero_combine = checksum::Crc32CombineOp::new(pad_len);

    loop {
        if valid_len == buffer.len() {
            let keep = overlap.min(valid_len);
            buffer.copy_within(valid_len - keep..valid_len, 0);
            base_offset += valid_len - keep;
            valid_len = keep;
        }

        let read_len = file.read(&mut buffer[valid_len..])?;
        total_read += read_len;
        valid_len += read_len;
        scan.stats.bytes_read = scan.stats.bytes_read.saturating_add(read_len as u64);

        scan_shifted_short_windows(
            scan,
            &ShortWindowParams {
                short_len,
                zero_combine: &zero_combine,
                zero_crc,
                window_table: &window_table,
            },
            &buffer[..valid_len],
            base_offset,
            &mut next_unscanned_offset,
        );

        if read_len == 0 {
            break;
        }
    }

    crate::file_cache::drop_touched_file_cache(&file, path, len as u64, 0, total_read as u64);
    Ok(())
}

fn scan_shifted_short_len_from_slice(
    scan: &mut ShortRelocationScan<'_, '_>,
    data: &[u8],
    short_len: usize,
) {
    if short_len == 0 || data.len() < short_len {
        return;
    }

    let pad_len = scan.table.slice_size.saturating_sub(short_len as u64);
    let zero_crc = crc32_zeros(pad_len);
    let zero_combine = checksum::Crc32CombineOp::new(pad_len);
    let window_table = generate_window_table(short_len as u64);
    let mut next_unscanned_offset = 0usize;
    scan_shifted_short_windows(
        scan,
        &ShortWindowParams {
            short_len,
            zero_combine: &zero_combine,
            zero_crc,
            window_table: &window_table,
        },
        data,
        0,
        &mut next_unscanned_offset,
    );
}

fn scan_shifted_short_windows(
    scan: &mut ShortRelocationScan<'_, '_>,
    params: &ShortWindowParams<'_>,
    buffer: &[u8],
    base_offset: usize,
    next_unscanned_offset: &mut usize,
) {
    let ShortWindowParams {
        short_len,
        zero_combine,
        zero_crc,
        window_table,
    } = *params;
    let table = scan.table;
    let path = scan.path;
    let kind = scan.kind;
    if short_len == 0 || buffer.len() < short_len {
        return;
    }

    let last_local_offset = buffer.len() - short_len;
    let mut local_offset = next_unscanned_offset.saturating_sub(base_offset);
    if local_offset > last_local_offset {
        return;
    }

    let mut crc = checksum::crc32(&buffer[local_offset..local_offset + short_len]);
    let mut windows_stepped = 0u64;
    loop {
        let padded_crc = zero_combine.combine(crc, zero_crc);
        if let Some(candidates) = table.by_crc.get(&padded_crc) {
            let data = &buffer[local_offset..local_offset + short_len];
            let absolute_offset = (base_offset + local_offset) as u64;
            for block_index in candidates {
                let block = scan.blocks.block(*block_index);
                // Gating on the recording guard, not only on `open`, keeps the
                // sweep from taking a hold it is not allowed to displace — an
                // access-backed one above all — and skips the MD5 confirmation
                // for any block whose placement could not have stood anyway.
                if !scan.open.get(*block_index).copied().unwrap_or(false)
                    || block.expected_len as usize != short_len
                    || !can_record_block_location(scan.blocks, *block_index, path, kind)
                {
                    continue;
                }
                if short_block_matches(data, table.slice_size, block) {
                    scan.stats.blocks_placed = scan.stats.blocks_placed.saturating_add(1);
                    record_block_location(
                        scan.blocks,
                        *block_index,
                        BlockLocation {
                            source: SourceLocation::Path(path.to_path_buf()),
                            offset: absolute_offset,
                            len: short_len as u64,
                            kind,
                        },
                    );
                }
            }
        }

        if local_offset == last_local_offset {
            break;
        }

        crc = crc_slide_char(
            crc,
            buffer[local_offset + short_len],
            buffer[local_offset],
            window_table,
        );
        local_offset += 1;
        windows_stepped += 1;
    }

    scan.stats.windows_stepped = scan.stats.windows_stepped.saturating_add(windows_stepped);
    *next_unscanned_offset = base_offset + last_local_offset + 1;
}

fn read_exact_file_range(path: &Path, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0u8; len];
    file.read_exact(&mut data)?;
    crate::file_cache::drop_touched_file_cache(&file, path, file_len, offset, len as u64);
    Ok(data)
}

fn scanner_uses_mmap_fallback(slice_size: u64) -> bool {
    slice_size > SCANNER_MMAP_FALLBACK_SLICE_BYTES as u64
}

fn record_block_location(
    blocks: &mut ScanBlockState<'_>,
    block_index: usize,
    location: BlockLocation,
) {
    blocks.record_location(block_index, location);
}

fn can_record_block_location(
    blocks: &ScanBlockState<'_>,
    block_index: usize,
    path: &Path,
    kind: BlockLocationKind,
) -> bool {
    blocks.location(block_index).is_none_or(|existing| {
        // Scanning only ever produces path locations, so an access-backed
        // incumbent (which scanning cannot have produced) is never displaced.
        kind < existing.kind
            || (kind == existing.kind && existing.path().is_some_and(|held| path < held))
    })
}

/// Candidate blocks batched per multi-buffer MD5 call while scanning.
///
/// The kernel width comes from the ISA ([`md5_simd::max_lanes`]: 8 on AVX2, 4
/// on NEON/SSE2/simd128, 1 scalar); the memory budget caps how many
/// slice-sized candidates may be held at once on top of that.
fn scanner_md5_batch_lanes(slice_size: usize) -> usize {
    if slice_size == 0 {
        return 1;
    }
    (SCANNER_MD5_BATCH_MEMORY_BYTES / slice_size).clamp(1, md5_simd::max_lanes())
}

fn record_matching_md5_block(
    blocks: &mut ScanBlockState<'_>,
    block_index: usize,
    data: &[u8],
    path: &Path,
    offset: u64,
    len: u64,
    kind: BlockLocationKind,
) {
    if !can_record_block_location(blocks, block_index, path, kind) {
        return;
    }
    let md5 = checksum::md5(data);
    if blocks.block(block_index).checksum.md5 == md5 {
        record_block_location(
            blocks,
            block_index,
            BlockLocation {
                source: SourceLocation::Path(path.to_path_buf()),
                offset,
                len,
                kind,
            },
        );
    }
}

fn flush_pending_md5_checks(
    pending: &mut Vec<PendingMd5Check<'_>>,
    blocks: &mut ScanBlockState<'_>,
    path: &Path,
) {
    if pending.is_empty() {
        return;
    }

    let inputs = pending.iter().map(|check| check.data).collect::<Vec<_>>();
    let md5s = md5_simd::md5_multi(&inputs, None);
    for (check, md5) in pending.iter().zip(md5s) {
        if !can_record_block_location(blocks, check.block_index, path, check.kind) {
            continue;
        }
        if blocks.block(check.block_index).checksum.md5 == md5 {
            record_block_location(
                blocks,
                check.block_index,
                BlockLocation {
                    source: SourceLocation::Path(path.to_path_buf()),
                    offset: check.offset,
                    len: check.len,
                    kind: check.kind,
                },
            );
        }
    }
    pending.clear();
}

fn short_block_matches(data: &[u8], slice_size: u64, block: &SourceBlock) -> bool {
    padded_crc(data, slice_size) == block.checksum.crc32
        && padded_md5(data, slice_size) == block.checksum.md5
}

fn check_cancel(options: &Par2RepairerOptions) -> Result<()> {
    if let Some(cancel) = options.cancel.as_ref()
        && cancel.is_cancelled()
    {
        return Err(Par2Error::Cancelled);
    }
    Ok(())
}

fn discover_adjacent_par2_files(par2_paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for path in par2_paths {
        out.extend(discover_related_par2_files(path)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn discover_related_par2_files(path: &Path) -> io::Result<Vec<PathBuf>> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(stem) = par2_base_name(path) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let candidate = entry.path();
        if candidate == path {
            continue;
        }
        if !is_par2_path(&candidate) || !related_par2_name_matches(&stem, &candidate) {
            continue;
        }
        out.push(candidate);
    }
    out.sort();
    Ok(out)
}

fn discover_source_primary_par2_file(path: &Path) -> io::Result<Option<PathBuf>> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(stem) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };

    let lower = dir.join(format!("{stem}.par2"));
    if lower.is_file() {
        return Ok(Some(lower));
    }

    let upper = dir.join(format!("{stem}.PAR2"));
    if upper.is_file() {
        return Ok(Some(upper));
    }

    Ok(None)
}

fn related_par2_name_matches(stem: &str, path: &Path) -> bool {
    if stem.is_empty() {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            let suffix = name.strip_prefix(stem).unwrap_or_default();
            suffix.starts_with('.') && suffix[1..].contains('.')
        })
}

fn par2_base_name(path: &Path) -> Option<String> {
    let mut name = path.file_name()?.to_str()?.to_owned();
    loop {
        let dot = name.rfind('.')?;
        let tail = name[dot + 1..].to_owned();
        name.truncate(dot);
        if tail.eq_ignore_ascii_case("par2") {
            break;
        }
    }

    if let Some(dot) = name.rfind('.')
        && volume_suffix_matches(&name[dot + 1..])
    {
        name.truncate(dot);
    }

    Some(name)
}

fn volume_suffix_matches(tail: &str) -> bool {
    let mut state = 0u8;
    for byte in tail.bytes() {
        match state {
            0 if byte.eq_ignore_ascii_case(&b'v') => state = 1,
            1 if byte.eq_ignore_ascii_case(&b'o') => state = 2,
            2 if byte.eq_ignore_ascii_case(&b'l') => state = 3,
            3 if byte.is_ascii_digit() => {}
            3 if byte == b'-' || byte == b'+' => state = 4,
            4 if byte.is_ascii_digit() => {}
            _ => return false,
        }
    }
    true
}

fn discover_candidate_files(base_dir: &Path) -> io::Result<Vec<PathBuf>> {
    discover_files_matching(base_dir, |path| !has_par2_marker(path))
}

fn is_par2_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "par2" || ext == "PAR2")
}

fn has_par2_marker(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path.contains(".par2") || path.contains(".PAR2")
}

fn canonical_extra_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn discover_files_matching<F>(base_dir: &Path, mut matches: F) -> io::Result<Vec<PathBuf>>
where
    F: FnMut(&Path) -> bool,
{
    let mut out = Vec::new();
    let mut stack = vec![base_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if !should_skip_candidate(&path) {
                    stack.push(path);
                }
            } else if file_type.is_file() && matches(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn should_skip_candidate(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_generated_par2_artifact_name)
}

fn read_first_16k(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut buf = vec![0u8; 16_384];
    // Fill, don't single-read: a short read here would silently hash fewer
    // bytes than the 16k quick hash is defined over. See `disk::read_filled`.
    let read = crate::disk::read_filled(&mut file, &mut buf)?;
    crate::file_cache::drop_touched_file_cache(&file, path, file_len, 0, read as u64);
    buf.truncate(read);
    Ok(buf)
}

fn hash_file(path: &Path) -> io::Result<[u8; 16]> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    crate::file_cache::advise_sequential(&file, path, file_len);
    let mut hasher = Md5State::new();
    // The 1 MiB read buffer must live on the heap on every target: wasm's shadow
    // stack is ~1 MiB total, and MSVC reserves 1 MiB for the main thread, so a
    // frame this large overflows both. `verify_or_repair` runs on the caller's
    // thread, and rayon steal-on-block can nest this frame deeper still.
    //
    // Do not regress this to a guarded stack buffer either: when this function
    // inlines, LLVM hoists its static allocas into the caller's entry block,
    // so the reservation lands in the caller's prologue no matter which branch
    // runs — a caller-side guard like `should_skip_full_hash` skips the
    // hashing work, never the stack cost.
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total_read = 0u64;
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        total_read += read as u64;
    }
    crate::file_cache::drop_touched_file_cache(&file, path, file_len, 0, total_read);
    Ok(hasher.finalize())
}

const SOURCE_CHANGED_PREFIX: &str = "PAR2 source changed: ";
const VIRTUAL_SOURCE_CHANGED_PREFIX: &str = "PAR2 virtual source changed: file ";

fn source_changed_io(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{SOURCE_CHANGED_PREFIX}{}", path.display()),
    )
}

/// Whether an error reports that a source moved out from under a read, in
/// either its path-backed or its access-backed spelling. A repair that
/// consumed a carried analysis treats this as "the carry was wrong after all"
/// and falls back to a fresh scan; nothing has been installed by the time it
/// can be raised.
fn is_source_changed_error(error: &Par2Error) -> bool {
    let Par2Error::Io(source) = error else {
        return false;
    };
    let message = source.to_string();
    message.starts_with(SOURCE_CHANGED_PREFIX) || message.starts_with(VIRTUAL_SOURCE_CHANGED_PREFIX)
}

/// The location-shaped counterpart to [`source_changed_io`]. Access-backed
/// sources have no path to name, so they report their PAR2 file identifier
/// under a distinct prefix that path-oriented callers do not misread.
fn source_location_changed_io(source: &SourceLocation) -> io::Error {
    match source {
        SourceLocation::Path(path) => source_changed_io(path),
        SourceLocation::Access(file_id) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{VIRTUAL_SOURCE_CHANGED_PREFIX}{file_id}"),
        ),
    }
}

/// Fill `dst` from an access-backed source, refusing a short read. Access
/// implementations may return fewer bytes than requested; a source block is
/// only usable whole, so a short read is a changed source.
fn read_exact_from_access(
    access: &(dyn FileAccess + Send + Sync),
    file_id: &FileId,
    offset: u64,
    dst: &mut [u8],
) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < dst.len() {
        let read =
            access.read_file_range_into(file_id, offset + filled as u64, &mut dst[filled..])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "access source ended before the requested range completed",
            ));
        }
        filled += read;
    }
    Ok(())
}

/// A forward-only reader over one clean repair source, whichever kind it is.
///
/// The staging copies below consume their source strictly in order, which is
/// the one shape both a `File` and a [`FileAccess`] handle serve equally well.
/// Keeping the two behind this reader is what lets a virtual source stage into
/// repair scratch without any code path holding a path for it.
enum SourceReader<'a> {
    File {
        file: File,
        path: &'a Path,
        source_len: u64,
    },
    Access {
        access: &'a (dyn FileAccess + Send + Sync),
        file_id: FileId,
        offset: u64,
    },
}

impl<'a> SourceReader<'a> {
    /// Open `source` for a sequential read of `len` bytes from `offset`.
    /// A path source is opened and bounds-checked here; an access source is
    /// bound to its handle, which is required to be present.
    fn open(
        source: &'a SourceLocation,
        access: Option<&'a (dyn FileAccess + Send + Sync)>,
        offset: u64,
        len: u64,
    ) -> io::Result<Self> {
        match source {
            SourceLocation::Path(path) => {
                let mut file = File::open(path).map_err(|_| source_changed_io(path))?;
                let source_len = file.metadata().map_err(|_| source_changed_io(path))?.len();
                if offset.checked_add(len).is_none_or(|end| end > source_len) {
                    return Err(source_changed_io(path));
                }
                file.seek(SeekFrom::Start(offset))
                    .map_err(|_| source_changed_io(path))?;
                Ok(Self::File {
                    file,
                    path,
                    source_len,
                })
            }
            SourceLocation::Access(file_id) => {
                let access = access.ok_or_else(|| source_location_changed_io(source))?;
                Ok(Self::Access {
                    access,
                    file_id: *file_id,
                    offset,
                })
            }
        }
    }

    /// Total length of a path source. Access sources have no such fact: their
    /// length is whatever the set says it is.
    fn source_len(&self) -> Option<u64> {
        match self {
            Self::File { source_len, .. } => Some(*source_len),
            Self::Access { .. } => None,
        }
    }

    fn read_exact(&mut self, dst: &mut [u8]) -> io::Result<()> {
        match self {
            Self::File { file, path, .. } => {
                file.read_exact(dst).map_err(|_| source_changed_io(path))
            }
            Self::Access {
                access,
                file_id,
                offset,
            } => {
                read_exact_from_access(*access, file_id, *offset, dst)
                    .map_err(|_| source_location_changed_io(&SourceLocation::Access(*file_id)))?;
                *offset += dst.len() as u64;
                Ok(())
            }
        }
    }
}

fn copy_block_range_validated(
    block: &SourceBlock,
    slice_size: u64,
    range: &BlockCopyRange,
    access: Option<&(dyn FileAccess + Send + Sync)>,
) -> io::Result<()> {
    if range.len != block.expected_len {
        return Err(source_location_changed_io(&range.src));
    }
    let mut input = SourceReader::open(&range.src, access, range.src_offset, range.len)?;
    if let Some(parent) = range.dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new().write(true).open(&range.dst)?;
    output.seek(SeekFrom::Start(range.dst_offset))?;
    let mut checksum = checksum::SliceChecksumState::new();
    let mut remaining = range.len;
    let mut buf = vec![0u8; remaining.clamp(1, 256 * 1024) as usize];
    while remaining > 0 {
        let take = remaining.min(buf.len() as u64) as usize;
        input.read_exact(&mut buf[..take])?;
        output.write_all(&buf[..take])?;
        checksum.update(&buf[..take]);
        remaining -= take as u64;
    }
    output.flush()?;
    let (crc32, md5) = checksum.finalize(Some(slice_size));
    if crc32 != block.checksum.crc32 || md5 != block.checksum.md5 {
        return Err(source_location_changed_io(&range.src));
    }
    Ok(())
}

fn copy_complete_file_validated(
    file: &SourceFileEntry,
    blocks: &[SourceBlock],
    slice_size: u64,
    src: &SourceLocation,
    access: Option<&(dyn FileAccess + Send + Sync)>,
    dst: &Path,
) -> io::Result<()> {
    let mut input = SourceReader::open(src, access, 0, file.length)?;
    // A physical source of the wrong length is a changed source, even when its
    // leading bytes still hash correctly.
    if input.source_len().is_some_and(|len| len != file.length) {
        return Err(source_location_changed_io(src));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new().write(true).open(dst)?;
    let mut full_hash = Md5State::new();
    let mut copied = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    let block_iter: Box<dyn Iterator<Item = Option<&SourceBlock>>> = if blocks.is_empty() {
        Box::new(std::iter::once(None))
    } else {
        Box::new(blocks.iter().map(Some))
    };
    for block in block_iter {
        let expected_len = block.map_or(file.length, |block| block.expected_len);
        let mut remaining = expected_len;
        let mut slice_checksum = checksum::SliceChecksumState::new();
        while remaining > 0 {
            let take = remaining.min(buf.len() as u64) as usize;
            input.read_exact(&mut buf[..take])?;
            output.write_all(&buf[..take])?;
            full_hash.update(&buf[..take]);
            slice_checksum.update(&buf[..take]);
            remaining -= take as u64;
            copied += take as u64;
        }
        if let Some(block) = block {
            let (crc32, md5) = slice_checksum.finalize(Some(slice_size));
            if crc32 != block.checksum.crc32 || md5 != block.checksum.md5 {
                return Err(source_location_changed_io(src));
            }
        }
    }
    output.flush()?;
    if copied != file.length || full_hash.finalize() != file.hash_full {
        return Err(source_location_changed_io(src));
    }
    Ok(())
}

/// Copy a clean span from either source kind into a path-addressed target.
/// Repair outputs are always real files; only the *read* side virtualizes.
fn copy_source_range(
    src: &SourceLocation,
    access: Option<&(dyn FileAccess + Send + Sync)>,
    src_offset: u64,
    dst: &Path,
    dst_offset: u64,
    len: u64,
) -> io::Result<()> {
    let Some(path) = src.path() else {
        let mut input = SourceReader::open(src, access, src_offset, len)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = OpenOptions::new().write(true).open(dst)?;
        output.seek(SeekFrom::Start(dst_offset))?;
        let mut remaining = len;
        let mut buf = vec![0u8; remaining.clamp(1, 256 * 1024) as usize];
        while remaining > 0 {
            let take = remaining.min(buf.len() as u64) as usize;
            input.read_exact(&mut buf[..take])?;
            output.write_all(&buf[..take])?;
            remaining -= take as u64;
        }
        output.flush()?;
        crate::file_cache::drop_file_cache(&output, dst, dst_offset, len);
        return Ok(());
    };
    copy_range(path, src_offset, dst, dst_offset, len)
}

fn copy_range(
    src: &Path,
    src_offset: u64,
    dst: &Path,
    dst_offset: u64,
    len: u64,
) -> io::Result<()> {
    let mut input = File::open(src)?;
    let source_len = input.metadata()?.len();
    crate::file_cache::advise_range_sequential(&input, src, src_offset, len);
    input.seek(SeekFrom::Start(src_offset))?;
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new().write(true).open(dst)?;
    output.seek(SeekFrom::Start(dst_offset))?;

    #[cfg(target_os = "linux")]
    {
        // File-to-file io::copy stays in the kernel when the filesystem
        // supports range copies; the take() bound caps the span at `len`.
        let copied = io::copy(&mut (&mut input).take(len), &mut output)?;
        if copied != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "source exhausted before the copy range completed",
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The generic io::copy buffer is smaller than this; keep the wider
        // userspace loop where no kernel-copy path exists.
        let mut remaining = len;
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let take = remaining.min(buf.len() as u64) as usize;
            input.read_exact(&mut buf[..take])?;
            output.write_all(&buf[..take])?;
            remaining -= take as u64;
        }
    }
    output.flush()?;
    crate::file_cache::drop_touched_file_cache(&input, src, source_len, src_offset, len);
    // Destination advice remains opportunistic; avoid forced writeback for large repairs.
    crate::file_cache::drop_file_cache(&output, dst, dst_offset, len);
    Ok(())
}

fn push_block_copy_range(ranges: &mut Vec<BlockCopyRange>, next: BlockCopyRange) {
    if next.len == 0 {
        return;
    }
    if let Some(last) = ranges.last_mut()
        && last.can_extend(&next)
    {
        last.extend(&next);
        return;
    }
    ranges.push(next);
}

fn unique_repair_dir(base_dir: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    base_dir.join(format!(".weaver-par2-repair-{stamp}"))
}

fn unique_backup_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("target");
    for index in 1u32.. {
        let candidate = path.with_file_name(format!("{name}.{index}"));
        match fs::symlink_metadata(&candidate) {
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("no available backup suffix for {}", path.display()),
    ))
}

fn rollback_installed_files(
    base_dir: &Path,
    installed_targets: &[PathBuf],
    backups: &[(PathBuf, PathBuf)],
) {
    for target in installed_targets.iter().rev() {
        let _ = crate::disk::remove_file_within_base(base_dir, target);
        crate::file_cache::drop_path_cache(target);
    }

    for (target, backup) in backups.iter().rev() {
        let _ = crate::disk::remove_file_within_base(base_dir, target);
        if crate::disk::rename_within_base(base_dir, backup, target).is_ok() {
            crate::file_cache::drop_path_cache(backup);
            crate::file_cache::drop_path_cache(target);
        }
    }
}

fn purge_files_best_effort<I, P>(paths: I)
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    for path in paths {
        let path = path.as_ref();
        match fs::remove_file(path) {
            Ok(()) => crate::file_cache::drop_path_cache(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

fn padded_crc(data: &[u8], pad_to: u64) -> u32 {
    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    update_crc_zeros(&mut hasher, pad_to.saturating_sub(data.len() as u64));
    hasher.finalize()
}

fn crc32_zeros(len: u64) -> u32 {
    let mut hasher = Crc32Hasher::new();
    update_crc_zeros(&mut hasher, len);
    hasher.finalize()
}

/// MD5 of one short block, zero-padded to `pad_to`.
///
/// Deliberately the single-stream backend rather than [`md5_simd::md5_multi`]:
/// a multi-buffer kernel driven with one input leaves every other lane idle and
/// still pays the vector round latency, so it is slower here than the ordinary
/// MD5 implementation. Multi-buffer only pays off with several independent
/// messages in flight, which is what the batched scanner and verifier feed it.
fn padded_md5(data: &[u8], pad_to: u64) -> [u8; 16] {
    let mut hasher = Md5State::new();
    hasher.update(data);
    update_md5_zeros(&mut hasher, pad_to.saturating_sub(data.len() as u64));
    hasher.finalize()
}

fn update_crc_zeros(hasher: &mut Crc32Hasher, mut len: u64) {
    while len > 0 {
        let take = len.min(ZERO_PAD_CHUNK.len() as u64) as usize;
        hasher.update(&ZERO_PAD_CHUNK[..take]);
        len -= take as u64;
    }
}

fn update_md5_zeros(hasher: &mut Md5State, mut len: u64) {
    while len > 0 {
        let take = len.min(ZERO_PAD_CHUNK.len() as u64) as usize;
        hasher.update(&ZERO_PAD_CHUNK[..take]);
        len -= take as u64;
    }
}

static CRC_TABLE: LazyLock<[u32; 256]> = LazyLock::new(|| {
    let mut table = [0u32; 256];
    for i in 0..=255u32 {
        let mut crc = i;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xEDB8_8320 } else { 0 };
        }
        table[i as usize] = crc;
    }
    table
});

static CRC_POWER: LazyLock<[u32; 32]> = LazyLock::new(|| {
    let mut power = [0u32; 32];
    let mut k = 0x8000_0000u32 >> 1;
    for i in 0..32 {
        power[(i + 32 - 3) & 31] = k;
        k = gf32_multiply(k, k, 0xEDB8_8320);
    }
    power
});

fn gf32_multiply(mut a: u32, mut b: u32, polynomial: u32) -> u32 {
    let mut product = 0u32;
    for _ in 0..31 {
        if b >> 31 != 0 {
            product ^= a;
        }
        a = (a >> 1) ^ if a & 1 != 0 { polynomial } else { 0 };
        b <<= 1;
    }
    if b >> 31 != 0 {
        product ^= a;
    }
    product
}

fn crc_exp8(mut n: u64) -> u32 {
    let mut result = 0x8000_0000u32;
    let mut power = 0usize;
    n %= 0xffff_ffff;
    while n != 0 {
        if n & 1 != 0 {
            result = gf32_multiply(result, CRC_POWER[power], 0xEDB8_8320);
        }
        n >>= 1;
        power = (power + 1) & 31;
    }
    result
}

fn generate_window_table(window: u64) -> [u32; 256] {
    let coeff = crc_exp8(window);
    let mut mask = gf32_multiply(!0, coeff, 0xEDB8_8320);
    mask = gf32_multiply(mask, 0x8080_0000, 0xEDB8_8320);
    mask ^= !0;

    let mut table = [0u32; 256];
    for i in 0..=255usize {
        table[i] = gf32_multiply(CRC_TABLE[i], coeff, 0xEDB8_8320) ^ mask;
    }
    table
}

fn crc_slide_char(crc: u32, new: u8, old: u8, window_table: &[u32; 256]) -> u32 {
    let crc = crc ^ !0;
    ((crc >> 8) & 0x00ff_ffff)
        ^ CRC_TABLE[((crc as u8) ^ new) as usize]
        ^ window_table[old as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify_all;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use crate::checksum::SliceChecksumState;
    use crate::types::RecoverySetId;
    use tempfile::tempdir;

    #[cfg(feature = "slow-tests")]
    use std::ffi::OsStr;

    #[test]
    fn armed_repair_staging_guard_removes_failed_output() {
        let dir = tempdir().unwrap();
        let staging = dir.path().join(".weaver-par2-repair-test");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("partial.bin"), b"partial").unwrap();

        drop(RepairStagingGuard::new(staging.clone()));

        assert!(!staging.exists());
    }

    fn rewrite_same_size_and_restore_mtime(path: &Path, replacement: &[u8]) {
        let modified = fs::metadata(path).unwrap().modified().unwrap();
        assert_eq!(fs::metadata(path).unwrap().len(), replacement.len() as u64);
        fs::write(path, replacement).unwrap();
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
    }

    fn validated_source_block(file_id: FileId, path: &Path, expected: &[u8]) -> SourceBlock {
        let mut state = SliceChecksumState::new();
        state.update(expected);
        let (crc32, md5) = state.finalize(Some(expected.len() as u64));
        SourceBlock {
            global_index: 0,
            file_id,
            local_index: 0,
            expected_len: expected.len() as u64,
            checksum: SliceChecksum { crc32, md5 },
            location: Some(BlockLocation {
                source: SourceLocation::Path(path.to_path_buf()),
                offset: 0,
                len: expected.len() as u64,
                kind: BlockLocationKind::Canonical,
            }),
        }
    }

    #[test]
    fn reconstruction_rejects_same_size_source_change_with_restored_mtime() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let expected = b"good";
        fs::write(&source, expected).unwrap();
        let snapshot = HashMap::from([(source.clone(), stat_for_carry(&source))]);
        let file_id = FileId::from_bytes([0x41; 16]);
        let block = validated_source_block(file_id, &source, expected);
        rewrite_same_size_and_restore_mtime(&source, b"evil");
        assert_eq!(stat_for_carry(&source), snapshot[&source]);
        let access = RepairExecutionAccess::new(
            dir.path().join("staging"),
            &[],
            &[block],
            &HashSet::new(),
            expected.len() as u64,
            RepairExecutionContext {
                source_snapshots: Some(snapshot),
                ..RepairExecutionContext::default()
            },
        )
        .unwrap();

        let error =
            crate::verify::FileAccess::read_file_range(&access, &file_id, 0, expected.len() as u64)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!dir.path().join("installed.bin").exists());
    }

    #[test]
    fn streaming_short_slice_pads_crc_and_accepts_one_stripe_replay() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("short.bin");
        let payload = b"tail";
        fs::write(&source, payload).unwrap();
        let file_id = FileId::from_bytes([0x44; 16]);
        let mut checksum = SliceChecksumState::new();
        checksum.update(payload);
        let (crc32, md5) = checksum.finalize(Some(8));
        let block = SourceBlock {
            global_index: 0,
            file_id,
            local_index: 0,
            expected_len: payload.len() as u64,
            checksum: SliceChecksum { crc32, md5 },
            location: Some(BlockLocation {
                source: SourceLocation::Path(source),
                offset: 0,
                len: payload.len() as u64,
                kind: BlockLocationKind::Canonical,
            }),
        };
        let access = RepairExecutionAccess::new(
            dir.path().join("staging"),
            &[],
            &[block],
            &HashSet::new(),
            8,
            RepairExecutionContext::default(),
        )
        .unwrap();

        for _ in 0..2 {
            let mut read = vec![0u8; payload.len()];
            assert_eq!(
                crate::verify::FileAccess::read_file_range_into(&access, &file_id, 0, &mut read,)
                    .unwrap(),
                payload.len()
            );
            assert_eq!(read, payload);
        }
        assert_eq!(access.validation_bytes(), payload.len() as u64);
    }

    #[test]
    fn streaming_validation_replays_only_current_outer_stripe() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("multistripe.bin");
        let payload = b"12345678";
        fs::write(&source, payload).unwrap();
        let file_id = FileId::from_bytes([0x46; 16]);
        let block = validated_source_block(file_id, &source, payload);
        let access = RepairExecutionAccess::new(
            dir.path().join("staging"),
            &[],
            &[block],
            &HashSet::new(),
            payload.len() as u64,
            RepairExecutionContext::default(),
        )
        .unwrap();

        for (offset, expected) in [(0, &payload[..4]), (4, &payload[4..])] {
            let mut read = vec![0u8; expected.len()];
            assert_eq!(
                crate::verify::FileAccess::read_file_range_into(
                    &access, &file_id, offset, &mut read,
                )
                .unwrap(),
                expected.len()
            );
            assert_eq!(read, expected);
        }
        let mut replay = vec![0u8; 4];
        assert_eq!(
            crate::verify::FileAccess::read_file_range_into(&access, &file_id, 4, &mut replay)
                .unwrap(),
            replay.len()
        );
        assert_eq!(replay, &payload[4..]);

        let mut stale = vec![0u8; 4];
        assert!(
            crate::verify::FileAccess::read_file_range_into(&access, &file_id, 0, &mut stale,)
                .is_err()
        );
        assert_eq!(access.validation_bytes(), payload.len() as u64);
    }

    #[test]
    fn reconstruction_copy_uses_read_buffer_and_cached_positional_writer() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let staging = dir.path().join("staging");
        let target = staging.join("installed.bin");
        let payload = b"copy-me!";
        fs::write(&source, payload).unwrap();
        fs::create_dir_all(&staging).unwrap();
        fs::write(&target, vec![0u8; payload.len()]).unwrap();

        let file_id = FileId::from_bytes([0x45; 16]);
        let block = validated_source_block(file_id, &source, payload);
        let file = SourceFileEntry {
            file_id,
            par2_name: "installed.bin".to_owned(),
            safe_path: target.clone(),
            safe_name: "installed.bin".to_owned(),
            length: payload.len() as u64,
            hash_full: [0; 16],
            hash_16k: [0; 16],
            recoverable: true,
            first_block: 0,
            expected_block_count: 1,
            block_count: 1,
            target_exists: false,
            complete_location: None,
            non_canonical_complete_source_count: 0,
        };
        let mut staged = HashSet::new();
        staged.insert(file_id);
        let access = RepairExecutionAccess::new(
            staging,
            &[file],
            &[block],
            &staged,
            8,
            RepairExecutionContext {
                reconstruction_copy_targets: HashMap::from([(
                    (file_id, 0),
                    BlockCopyRange {
                        src: SourceLocation::Path(source),
                        src_offset: 0,
                        dst: target,
                        dst_offset: 0,
                        len: payload.len() as u64,
                    },
                )]),
                ..RepairExecutionContext::default()
            },
        )
        .unwrap();

        let mut read = vec![0u8; payload.len()];
        assert_eq!(
            crate::verify::FileAccess::read_file_range_into(&access, &file_id, 0, &mut read)
                .unwrap(),
            payload.len()
        );
        assert_eq!(read, payload);
        assert_eq!(
            fs::read(access.repair_path_for(&file_id).unwrap()).unwrap(),
            payload
        );
        assert_eq!(access.staged_writers.lock().unwrap().len(), 1);
    }

    #[test]
    fn whole_file_copy_rejects_same_size_source_change_and_cleans_staging() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let expected = b"whole-file";
        fs::write(&source, expected).unwrap();
        let file_id = FileId::from_bytes([0x42; 16]);
        let block = validated_source_block(file_id, &source, expected);
        let file = SourceFileEntry {
            file_id,
            par2_name: "installed.bin".to_owned(),
            safe_path: dir.path().join("installed.bin"),
            safe_name: "installed.bin".to_owned(),
            length: expected.len() as u64,
            hash_full: checksum::md5(expected),
            hash_16k: checksum::md5(expected),
            recoverable: true,
            first_block: 0,
            expected_block_count: 1,
            block_count: 1,
            target_exists: false,
            complete_location: None,
            non_canonical_complete_source_count: 0,
        };
        rewrite_same_size_and_restore_mtime(&source, b"changed!!!");
        let staging = dir.path().join(".weaver-par2-repair-whole");
        fs::create_dir_all(&staging).unwrap();
        let destination = staging.join("installed.bin");
        File::create(&destination).unwrap();
        let guard = RepairStagingGuard::new(staging.clone());

        let error = copy_complete_file_validated(
            &file,
            &[block],
            expected.len() as u64,
            &SourceLocation::Path(source),
            None,
            &destination,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(guard);
        assert!(!staging.exists());
        assert!(!file.safe_path.exists());
    }

    /// Staging from a virtual source writes the served bytes and validates
    /// them, opening nothing on disk but the destination.
    #[test]
    fn whole_file_copy_stages_a_virtual_source_without_a_path() {
        let dir = tempdir().unwrap();
        let expected = b"virtual-whole-file-payload!!";
        let file_id = FileId::from_bytes([0x71; 16]);
        let mut memory = crate::verify::MemoryFileAccess::new();
        memory.add_file(file_id, expected.to_vec());
        let source = SourceLocation::Access(file_id);
        let mut blocks = Vec::new();
        for (index, chunk) in expected.chunks(8).enumerate() {
            let mut state = SliceChecksumState::new();
            state.update(chunk);
            let (crc32, md5) = state.finalize(Some(8));
            blocks.push(SourceBlock {
                global_index: index,
                file_id,
                local_index: index as u32,
                expected_len: chunk.len() as u64,
                checksum: SliceChecksum { crc32, md5 },
                location: Some(BlockLocation {
                    source: source.clone(),
                    offset: index as u64 * 8,
                    len: chunk.len() as u64,
                    kind: BlockLocationKind::Canonical,
                }),
            });
        }
        let file = SourceFileEntry {
            file_id,
            par2_name: "installed.bin".to_owned(),
            safe_path: dir.path().join("installed.bin"),
            safe_name: "installed.bin".to_owned(),
            length: expected.len() as u64,
            hash_full: checksum::md5(expected),
            hash_16k: checksum::md5(expected),
            recoverable: true,
            first_block: 0,
            expected_block_count: blocks.len(),
            block_count: blocks.len(),
            target_exists: false,
            complete_location: None,
            non_canonical_complete_source_count: 0,
        };
        let staging = dir.path().join(".weaver-par2-repair-virtual");
        fs::create_dir_all(&staging).unwrap();
        let destination = staging.join("installed.bin");
        File::create(&destination).unwrap();

        copy_complete_file_validated(&file, &blocks, 8, &source, Some(&memory), &destination)
            .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), expected);
        // Nothing was created at the file's own path: only the read side is
        // virtual, and the write side went where it was told.
        assert!(!file.safe_path.exists());
    }

    /// A virtual source serving the wrong bytes is refused exactly as a
    /// changed file is, and names the file identity rather than a path.
    #[test]
    fn intact_block_copy_rejects_a_virtual_source_serving_wrong_bytes() {
        let dir = tempdir().unwrap();
        let expected = b"block";
        let file_id = FileId::from_bytes([0x72; 16]);
        let mut state = SliceChecksumState::new();
        state.update(expected);
        let (crc32, md5) = state.finalize(Some(expected.len() as u64));
        let block = SourceBlock {
            global_index: 0,
            file_id,
            local_index: 0,
            expected_len: expected.len() as u64,
            checksum: SliceChecksum { crc32, md5 },
            location: None,
        };
        let mut memory = crate::verify::MemoryFileAccess::new();
        memory.add_file(file_id, b"wrong".to_vec());
        let staging = dir.path().join(".weaver-par2-repair-virtual-block");
        fs::create_dir_all(&staging).unwrap();
        let destination = staging.join("installed.bin");
        File::create(&destination).unwrap();
        let range = BlockCopyRange {
            src: SourceLocation::Access(file_id),
            src_offset: 0,
            dst: destination,
            dst_offset: 0,
            len: expected.len() as u64,
        };

        let error =
            copy_block_range_validated(&block, expected.len() as u64, &range, Some(&memory))
                .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("virtual source changed"));
    }

    /// Without a handle there is nothing to read a virtual source from, and
    /// the refusal must not degrade into a filesystem lookup.
    #[test]
    fn virtual_source_without_a_handle_is_refused_not_resolved() {
        let dir = tempdir().unwrap();
        let file_id = FileId::from_bytes([0x73; 16]);
        let staging = dir.path().join(".weaver-par2-repair-no-handle");
        fs::create_dir_all(&staging).unwrap();
        let destination = staging.join("installed.bin");
        File::create(&destination).unwrap();
        let range = BlockCopyRange {
            src: SourceLocation::Access(file_id),
            src_offset: 0,
            dst: destination,
            dst_offset: 0,
            len: 4,
        };
        let block = SourceBlock {
            global_index: 0,
            file_id,
            local_index: 0,
            expected_len: 4,
            checksum: SliceChecksum {
                crc32: 0,
                md5: [0; 16],
            },
            location: None,
        };

        let error = copy_block_range_validated(&block, 4, &range, None).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("virtual source changed"));
    }

    #[test]
    fn intact_block_copy_rejects_same_size_source_change_and_cleans_staging() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let expected = b"block";
        fs::write(&source, expected).unwrap();
        let file_id = FileId::from_bytes([0x43; 16]);
        let block = validated_source_block(file_id, &source, expected);
        rewrite_same_size_and_restore_mtime(&source, b"wrong");
        let staging = dir.path().join(".weaver-par2-repair-block");
        fs::create_dir_all(&staging).unwrap();
        let destination = staging.join("installed.bin");
        File::create(&destination).unwrap();
        let range = BlockCopyRange {
            src: SourceLocation::Path(source),
            src_offset: 0,
            dst: destination,
            dst_offset: 0,
            len: expected.len() as u64,
        };
        let guard = RepairStagingGuard::new(staging.clone());

        let error =
            copy_block_range_validated(&block, expected.len() as u64, &range, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(guard);
        assert!(!staging.exists());
        assert!(!dir.path().join("installed.bin").exists());
    }

    fn restore_carried_modified_time(carry: &ScanCarry, path: &Path) {
        let expected = carry
            .snapshot
            .iter()
            .find(|stat| stat.path == path)
            .expect("path is in carried stat snapshot");
        let Some(modified) = expected
            .state
            .as_ref()
            .and_then(FileStatFingerprint::modified)
        else {
            panic!("carried path exists as a regular file with a readable mtime");
        };
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(
            stat_for_carry(path),
            *expected,
            "test must force the stat gate to accept stale carry"
        );
    }

    fn synthetic_set(files: &[(&str, &[u8])], slice_size: u64) -> Par2FileSet {
        let mut recovery_file_ids = Vec::new();
        let mut descriptions = HashMap::new();
        let mut slice_checksums = HashMap::new();

        for (index, (filename, bytes)) in files.iter().enumerate() {
            let mut raw_id = [0u8; 16];
            raw_id[12..].copy_from_slice(&((index as u32) + 1).to_be_bytes());
            let file_id = FileId::from_bytes(raw_id);
            recovery_file_ids.push(file_id);

            let hash_full = checksum::md5(bytes);
            let hash_16k = checksum::md5(&bytes[..bytes.len().min(16 * 1024)]);
            let mut checksums = Vec::new();
            for chunk in bytes.chunks(slice_size as usize) {
                let mut state = SliceChecksumState::new();
                state.update(chunk);
                let pad_to = ((chunk.len() as u64) < slice_size).then_some(slice_size);
                let (crc32, md5) = state.finalize(pad_to);
                checksums.push(SliceChecksum { crc32, md5 });
            }

            descriptions.insert(
                file_id,
                crate::par2_set::FileDescription {
                    file_id,
                    hash_full,
                    hash_16k,
                    length: bytes.len() as u64,
                    par2_name: (*filename).to_string(),
                    filename: (*filename).to_string(),
                },
            );
            slice_checksums.insert(file_id, checksums);
        }

        Par2FileSet {
            recovery_set_id: RecoverySetId::from_bytes([7; 16]),
            slice_size,
            recovery_file_ids,
            non_recovery_file_ids: Vec::new(),
            files: descriptions,
            slice_checksums,
            recovery_slices: BTreeMap::new(),
            creator: None,
        }
    }

    fn write_synthetic_par2_file(
        dir: &Path,
        name: &str,
        files: &[(&str, &[u8])],
        slice_size: u64,
    ) -> PathBuf {
        let file_ids: Vec<FileId> = (0..files.len())
            .map(|index| {
                let mut raw_id = [0u8; 16];
                raw_id[12..].copy_from_slice(&((index as u32) + 1).to_be_bytes());
                FileId::from_bytes(raw_id)
            })
            .collect();

        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for file_id in &file_ids {
            main_body.extend_from_slice(file_id.as_bytes());
        }
        let recovery_set_id = checksum::md5(&main_body);

        let mut stream = make_full_packet(
            crate::packet::header::TYPE_MAIN,
            &main_body,
            recovery_set_id,
        );
        for ((filename, bytes), file_id) in files.iter().zip(file_ids.iter()) {
            let mut fd_body = Vec::new();
            fd_body.extend_from_slice(file_id.as_bytes());
            fd_body.extend_from_slice(&checksum::md5(bytes));
            fd_body.extend_from_slice(&checksum::md5(&bytes[..bytes.len().min(16 * 1024)]));
            fd_body.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            fd_body.extend_from_slice(filename.as_bytes());
            while fd_body.len() % 4 != 0 {
                fd_body.push(0);
            }
            stream.extend_from_slice(&make_full_packet(
                crate::packet::header::TYPE_FILE_DESC,
                &fd_body,
                recovery_set_id,
            ));

            let mut ifsc_body = Vec::new();
            ifsc_body.extend_from_slice(file_id.as_bytes());
            for chunk in bytes.chunks(slice_size as usize) {
                let mut state = SliceChecksumState::new();
                state.update(chunk);
                let pad_to = ((chunk.len() as u64) < slice_size).then_some(slice_size);
                let (crc32, md5) = state.finalize(pad_to);
                ifsc_body.extend_from_slice(&md5);
                ifsc_body.extend_from_slice(&crc32.to_le_bytes());
            }
            stream.extend_from_slice(&make_full_packet(
                crate::packet::header::TYPE_IFSC,
                &ifsc_body,
                recovery_set_id,
            ));
        }

        let path = dir.join(name);
        fs::write(&path, stream).unwrap();
        path
    }

    fn make_full_packet(packet_type: &[u8; 16], body: &[u8], recovery_set_id: [u8; 16]) -> Vec<u8> {
        let length = (crate::packet::header::HEADER_SIZE + body.len()) as u64;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&recovery_set_id);
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);
        let packet_hash = checksum::md5(&hash_input);

        let mut data = Vec::new();
        data.extend_from_slice(crate::packet::header::MAGIC);
        data.extend_from_slice(&length.to_le_bytes());
        data.extend_from_slice(&packet_hash);
        data.extend_from_slice(&recovery_set_id);
        data.extend_from_slice(packet_type);
        data.extend_from_slice(body);
        data
    }

    #[test]
    fn par2_base_name_strips_volume_suffix() {
        assert_eq!(
            par2_base_name(Path::new("movie.vol000+001.par2")).as_deref(),
            Some("movie")
        );
        assert_eq!(
            par2_base_name(Path::new("movie.vol000-001.PAR2")).as_deref(),
            Some("movie")
        );
        assert_eq!(
            par2_base_name(Path::new("movie.extra.par2")).as_deref(),
            Some("movie.extra")
        );
    }

    #[test]
    fn discover_adjacent_par2_files_uses_set_stem_sibling_scope() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();

        let main = dir.path().join("movie.par2");
        let sibling_recovery = dir.path().join("movie.vol000+001.par2");
        let sibling_upper = dir.path().join("movie.vol001+001.PAR2");
        let sibling_mixed_extension = dir.path().join("movie.vol002+001.Par2");
        let sibling_main_upper = dir.path().join("movie.PAR2");
        let unrelated = dir.path().join("other.vol000+001.par2");
        let nested_recovery = nested.join("movie.vol002+001.par2");

        for path in [
            &main,
            &sibling_recovery,
            &sibling_upper,
            &sibling_mixed_extension,
            &sibling_main_upper,
            &unrelated,
            &nested_recovery,
        ] {
            fs::write(path, b"not parsed in this test").unwrap();
        }

        let discovered = discover_adjacent_par2_files(std::slice::from_ref(&main)).unwrap();

        assert_eq!(discovered, vec![sibling_recovery, sibling_upper]);
    }

    #[test]
    fn discover_source_primary_par2_file_uses_set_stem() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("movie.mkv");
        let volume_only = dir.path().join("movie.mkv.vol000+001.par2");
        fs::write(&source, b"source").unwrap();
        fs::write(&volume_only, b"volume").unwrap();

        assert_eq!(discover_source_primary_par2_file(&source).unwrap(), None);

        let lower_primary = dir.path().join("movie.mkv.par2");
        let upper_primary = dir.path().join("movie.mkv.PAR2");
        fs::write(&upper_primary, b"primary").unwrap();
        let expected_upper_only = if lower_primary.is_file() {
            lower_primary.clone()
        } else {
            upper_primary
        };
        assert_eq!(
            discover_source_primary_par2_file(&source).unwrap(),
            Some(expected_upper_only)
        );

        fs::write(&lower_primary, b"primary").unwrap();
        assert_eq!(
            discover_source_primary_par2_file(&source).unwrap(),
            Some(lower_primary)
        );
    }

    #[cfg(unix)]
    #[test]
    fn discover_adjacent_par2_files_skips_unreadable_sibling_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let main = dir.path().join("movie.par2");
        fs::write(&main, b"not parsed in this test").unwrap();

        let original_perms = fs::metadata(dir.path()).unwrap().permissions();
        let mut closed_perms = original_perms.clone();
        closed_perms.set_mode(0o0);
        fs::set_permissions(dir.path(), closed_perms).unwrap();

        let discovered = discover_adjacent_par2_files(std::slice::from_ref(&main));

        fs::set_permissions(dir.path(), original_perms).unwrap();

        assert_eq!(discovered.unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn load_inventory_ignores_unusable_par2_marker_extra_paths() {
        let dir = tempdir().unwrap();
        let mut main_body = Vec::new();
        main_body.extend_from_slice(&4u64.to_le_bytes());
        main_body.extend_from_slice(&0u32.to_le_bytes());
        let rsid = checksum::md5(&main_body);
        let main_path = dir.path().join("target.par2");
        fs::write(
            &main_path,
            make_full_packet(crate::packet::header::TYPE_MAIN, &main_body, rsid),
        )
        .unwrap();

        let junk_marker_path = dir.path().join("junk.par2.bak");
        fs::write(&junk_marker_path, b"not a PAR2 packet stream").unwrap();

        let mut options =
            Par2RepairerOptions::new(dir.path().to_path_buf(), vec![main_path.clone()]);
        options
            .extra_paths
            .push(dir.path().join("missing.par2.bak"));
        options.extra_paths.push(junk_marker_path);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 0);
        assert_eq!(inventory.diagnostics.corrupt_packets, 0);
        assert_eq!(inventory.purge_paths, vec![main_path]);
    }

    #[test]
    fn load_inventory_remembers_optional_adjacent_par2_files_for_purge() {
        let dir = tempdir().unwrap();
        let mut main_body = Vec::new();
        main_body.extend_from_slice(&4u64.to_le_bytes());
        main_body.extend_from_slice(&0u32.to_le_bytes());
        let rsid = checksum::md5(&main_body);
        let main_path = dir.path().join("target.par2");
        let corrupt_adjacent = dir.path().join("target.vol000+001.par2");
        fs::write(
            &main_path,
            make_full_packet(crate::packet::header::TYPE_MAIN, &main_body, rsid),
        )
        .unwrap();
        fs::write(&corrupt_adjacent, b"not a PAR2 packet stream").unwrap();

        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), vec![main_path.clone()]);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        assert_eq!(inventory.diagnostics.corrupt_packets, 0);
        assert_eq!(inventory.purge_paths, vec![main_path, corrupt_adjacent]);
    }

    #[test]
    fn load_inventory_prefers_adjacent_recovery_over_duplicate_marker_extra() {
        let dir = tempdir().unwrap();
        let mut main_body = Vec::new();
        main_body.extend_from_slice(&4u64.to_le_bytes());
        main_body.extend_from_slice(&0u32.to_le_bytes());
        let rsid = checksum::md5(&main_body);

        let main_path = dir.path().join("target.par2");
        fs::write(
            &main_path,
            make_full_packet(crate::packet::header::TYPE_MAIN, &main_body, rsid),
        )
        .unwrap();

        let mut sibling_recovery_body = Vec::new();
        sibling_recovery_body.extend_from_slice(&0u32.to_le_bytes());
        sibling_recovery_body.extend_from_slice(&[0x11; 4]);
        fs::write(
            dir.path().join("target.vol000+001.par2"),
            make_full_packet(
                crate::packet::header::TYPE_RECOVERY,
                &sibling_recovery_body,
                rsid,
            ),
        )
        .unwrap();

        let mut extra_recovery_body = Vec::new();
        extra_recovery_body.extend_from_slice(&0u32.to_le_bytes());
        extra_recovery_body.extend_from_slice(&[0x22; 4]);
        let extra_path = dir.path().join("target.par2.bak");
        fs::write(
            &extra_path,
            make_full_packet(
                crate::packet::header::TYPE_RECOVERY,
                &extra_recovery_body,
                rsid,
            ),
        )
        .unwrap();

        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), vec![main_path]);
        options.extra_paths.push(extra_path);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        let recovery = inventory.set.recovery_slices.get(&0).unwrap();
        assert_eq!(recovery.data.to_vec().unwrap(), vec![0x11; 4]);
    }

    #[test]
    fn load_inventory_reads_par2_marker_extra_paths_as_packets() {
        let dir = tempdir().unwrap();
        let file_id = FileId::from_bytes([1; 16]);
        let file_data = b"abcd";
        let slice_size = 4u64;

        let mut main_body = Vec::new();
        main_body.extend_from_slice(&slice_size.to_le_bytes());
        main_body.extend_from_slice(&1u32.to_le_bytes());
        main_body.extend_from_slice(file_id.as_bytes());
        let rsid = checksum::md5(&main_body);

        let mut fd_body = Vec::new();
        fd_body.extend_from_slice(file_id.as_bytes());
        fd_body.extend_from_slice(&checksum::md5(file_data));
        fd_body.extend_from_slice(&checksum::md5(file_data));
        fd_body.extend_from_slice(&(file_data.len() as u64).to_le_bytes());
        fd_body.extend_from_slice(b"target.bin");
        while fd_body.len() % 4 != 0 {
            fd_body.push(0);
        }

        let mut slice_state = SliceChecksumState::new();
        slice_state.update(file_data);
        let (crc32, md5) = slice_state.finalize(None);
        let mut ifsc_body = Vec::new();
        ifsc_body.extend_from_slice(file_id.as_bytes());
        ifsc_body.extend_from_slice(&md5);
        ifsc_body.extend_from_slice(&crc32.to_le_bytes());

        let mut main_stream = Vec::new();
        main_stream.extend_from_slice(&make_full_packet(
            crate::packet::header::TYPE_MAIN,
            &main_body,
            rsid,
        ));
        main_stream.extend_from_slice(&make_full_packet(
            crate::packet::header::TYPE_FILE_DESC,
            &fd_body,
            rsid,
        ));
        main_stream.extend_from_slice(&make_full_packet(
            crate::packet::header::TYPE_IFSC,
            &ifsc_body,
            rsid,
        ));

        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes());
        recovery_body.extend_from_slice(&[0xAB; 4]);
        let mut recovery_stream = Vec::new();
        recovery_stream.extend_from_slice(&make_full_packet(
            crate::packet::header::TYPE_MAIN,
            &main_body,
            rsid,
        ));
        recovery_stream.extend_from_slice(&make_full_packet(
            crate::packet::header::TYPE_RECOVERY,
            &recovery_body,
            rsid,
        ));

        let main_path = dir.path().join("target.par2");
        let extra_recovery_path = dir.path().join("target.par2.bak");
        fs::write(&main_path, main_stream).unwrap();
        fs::write(&extra_recovery_path, recovery_stream).unwrap();

        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), vec![main_path]);
        options.extra_paths.push(extra_recovery_path);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 1);
        assert!(inventory.set.recovery_slices.contains_key(&0));
    }

    #[test]
    fn unique_backup_path_uses_numbered_suffixes() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.bin");
        fs::write(&target, b"target").unwrap();

        assert_eq!(
            unique_backup_path(&target).unwrap(),
            dir.path().join("target.bin.1")
        );
        fs::write(dir.path().join("target.bin.1"), b"first backup").unwrap();
        fs::write(dir.path().join("target.bin.2"), b"second backup").unwrap();

        assert_eq!(
            unique_backup_path(&target).unwrap(),
            dir.path().join("target.bin.3")
        );
    }

    #[test]
    fn block_copy_ranges_coalesce_contiguous_runs() {
        let src = PathBuf::from("source.bin");
        let other_src = PathBuf::from("other-source.bin");
        let dst = PathBuf::from("target.bin");
        let other_dst = PathBuf::from("other-target.bin");
        let mut ranges = Vec::new();

        push_block_copy_range(
            &mut ranges,
            BlockCopyRange {
                src: SourceLocation::Path(src.clone()),
                src_offset: 0,
                dst: dst.clone(),
                dst_offset: 0,
                len: 1024,
            },
        );
        push_block_copy_range(
            &mut ranges,
            BlockCopyRange {
                src: SourceLocation::Path(src.clone()),
                src_offset: 1024,
                dst: dst.clone(),
                dst_offset: 1024,
                len: 1024,
            },
        );
        push_block_copy_range(
            &mut ranges,
            BlockCopyRange {
                src: SourceLocation::Path(src.clone()),
                src_offset: 4096,
                dst: dst.clone(),
                dst_offset: 4096,
                len: 1024,
            },
        );
        push_block_copy_range(
            &mut ranges,
            BlockCopyRange {
                src: SourceLocation::Path(other_src),
                src_offset: 5120,
                dst: dst.clone(),
                dst_offset: 5120,
                len: 1024,
            },
        );
        push_block_copy_range(
            &mut ranges,
            BlockCopyRange {
                src: SourceLocation::Path(src),
                src_offset: 6144,
                dst: other_dst,
                dst_offset: 6144,
                len: 1024,
            },
        );

        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0].src_offset, 0);
        assert_eq!(ranges[0].dst_offset, 0);
        assert_eq!(ranges[0].len, 2048);
        assert_eq!(ranges[1].src_offset, 4096);
        assert_eq!(ranges[1].len, 1024);
    }

    #[test]
    fn copy_range_preserves_small_range_from_large_source() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("source.bin");
        let dst = dir.path().join("dest.bin");
        let payload = b"small range from a sparse large source";
        let source_offset = 4096u64;
        let dest_offset = 128u64;

        let mut source = File::create(&src).unwrap();
        source.set_len(64 * 1024 * 1024 + 4096).unwrap();
        source.seek(SeekFrom::Start(source_offset)).unwrap();
        source.write_all(payload).unwrap();
        drop(source);

        let dest = File::create(&dst).unwrap();
        dest.set_len(1024).unwrap();
        drop(dest);

        copy_range(&src, source_offset, &dst, dest_offset, payload.len() as u64).unwrap();

        let bytes = fs::read(&dst).unwrap();
        assert_eq!(
            &bytes[..dest_offset as usize],
            vec![0u8; dest_offset as usize]
        );
        assert_eq!(
            &bytes[dest_offset as usize..dest_offset as usize + payload.len()],
            payload
        );
        assert_eq!(fs::metadata(&src).unwrap().len(), 64 * 1024 * 1024 + 4096);
    }

    #[test]
    fn preview_survives_tiny_memory_limit_via_matrix_budget_floor() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let mut set = synthetic_set(&[("data.bin", &file_data)], slice_size);
        for exponent in 0..2u32 {
            set.recovery_slices.insert(
                exponent,
                crate::par2_set::RecoverySlice {
                    exponent,
                    data: vec![0u8; slice_size as usize].into(),
                },
            );
        }

        let mut damaged = file_data.clone();
        damaged[..64].fill(0);
        damaged[64..128].fill(0);
        fs::write(dir.path().join("data.bin"), damaged).unwrap();

        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.file_set = Some(set);
        options.repair = false;
        options.memory_limit = Some(8);

        // The decode matrix no longer competes with the slice-buffer budget,
        // so a tiny configured limit still previews as repairable.
        let outcome = Par2Repairer::new(options).verify_or_repair().unwrap();
        assert_eq!(outcome.status, Par2RepairStatus::RepairPossible);
    }

    #[test]
    fn preview_reports_resource_limited_for_sets_over_total_slice_cap() {
        let dir = tempdir().unwrap();
        let slice_size = 4u64;
        // Two files of 20000 slices each: 40000 total, over the 32768 cap.
        let file_a = vec![0xA5u8; 80_000];
        let file_b = vec![0x5Au8; 80_000];
        let mut set = synthetic_set(&[("a.bin", &file_a), ("b.bin", &file_b)], slice_size);
        for exponent in 0..40_000u32 {
            set.recovery_slices.insert(
                exponent,
                crate::par2_set::RecoverySlice {
                    exponent,
                    data: vec![0u8; slice_size as usize].into(),
                },
            );
        }

        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.file_set = Some(set);
        options.repair = false;

        let outcome = Par2Repairer::new(options).verify_or_repair().unwrap();
        assert_eq!(outcome.status, Par2RepairStatus::ResourceLimited);
        assert!(matches!(
            outcome.verification.repairable,
            Repairability::ResourceLimited { .. }
        ));
    }

    #[cfg(feature = "slow-tests")]
    fn crate_fixture_dir(name: &str) -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let crate_fixture = manifest_dir.join("tests/fixtures").join(name);
        if crate_fixture.is_dir() {
            return crate_fixture;
        }

        panic!(
            "missing slow-test fixture {name}; looked in {}",
            crate_fixture.display()
        );
    }

    #[cfg(feature = "slow-tests")]
    fn copy_dir_contents(src: &Path, dst: &Path) {
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir_all(&dst_path).unwrap();
                copy_dir_contents(&src_path, &dst_path);
            } else {
                fs::copy(&src_path, &dst_path).unwrap();
            }
        }
    }

    #[cfg(feature = "slow-tests")]
    fn copy_fixture_dir(name: &str) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        copy_dir_contents(&crate_fixture_dir(name), dir.path());
        dir
    }

    #[cfg(feature = "slow-tests")]
    fn collect_paths(dir: &Path, prefix: &str, extension: &str) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension() == Some(OsStr::new(extension))
                    && path
                        .file_name()
                        .and_then(OsStr::to_str)
                        .is_some_and(|name| name.starts_with(prefix))
            })
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn rolling_crc_matches_direct_crc() {
        let data: Vec<u8> = (0..4096u32).map(|value| (value % 251) as u8).collect();
        let window = 257usize;
        let table = generate_window_table(window as u64);
        let mut crc = checksum::crc32(&data[..window]);
        for offset in 0..=data.len() - window {
            assert_eq!(crc, checksum::crc32(&data[offset..offset + window]));
            if offset < data.len() - window {
                crc = crc_slide_char(crc, data[offset + window], data[offset], &table);
            }
        }
    }

    fn block_location_summary(blocks: &[SourceBlock]) -> BlockLocationSummary {
        blocks
            .iter()
            .map(|block| {
                block.location.as_ref().map(|location| {
                    (
                        location
                            .path()
                            .expect("scanned location is a path")
                            .to_path_buf(),
                        location.offset,
                        location.len,
                        location.kind,
                    )
                })
            })
            .collect()
    }

    type BlockLocationSummaryEntry = (PathBuf, u64, u64, BlockLocationKind);
    type BlockLocationSummary = Vec<Option<BlockLocationSummaryEntry>>;

    fn scan_with_mmap(
        state: &RepairState,
        path: &Path,
        kind: BlockLocationKind,
    ) -> BlockLocationSummary {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        scanner
            .scan_file_mmap(
                path,
                kind,
                &state.files,
                &state.file_index_by_id,
                &mut blocks,
            )
            .unwrap();
        block_location_summary(&blocks)
    }

    fn scan_with_mmap_stats(
        state: &RepairState,
        path: &Path,
        kind: BlockLocationKind,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let stats = scanner
            .scan_file_mmap(
                path,
                kind,
                &state.files,
                &state.file_index_by_id,
                &mut blocks,
            )
            .unwrap();
        (block_location_summary(&blocks), stats)
    }

    fn scan_with_ordered_canonical(
        state: &RepairState,
        path: &Path,
    ) -> (BlockLocationSummary, FileScanStats) {
        scan_with_ordered_canonical_options(
            state,
            path,
            ScanSkipOptions {
                skip_data: false,
                skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
            },
        )
    }

    fn scan_with_ordered_canonical_options(
        state: &RepairState,
        path: &Path,
        scan_options: ScanSkipOptions,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let target = state
            .files
            .iter()
            .find(|file| file.safe_path == path)
            .unwrap();
        let stats = scanner
            .scan_file_ordered_canonical(
                path,
                BlockLocationKind::Canonical,
                SourceFileScanLookup {
                    files: &state.files,
                    file_index_by_id: &state.file_index_by_id,
                },
                target,
                &mut blocks,
                scan_options,
            )
            .unwrap();
        (block_location_summary(&blocks), stats)
    }

    /// Pre-locate `settled_locals` from "evidence", then run the ordered
    /// canonical scan with the skip policy either honouring them (`honour`) or
    /// ignoring them. Both arms start from the same located state, so the only
    /// difference between them is the policy.
    fn scan_with_settled_evidence(
        state: &RepairState,
        path: &Path,
        settled_locals: &[usize],
        honour: bool,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let target = state
            .files
            .iter()
            .find(|file| file.safe_path == path)
            .unwrap()
            .clone();
        let mut settled = vec![false; target.block_count];
        for &local in settled_locals {
            let block_index = target.first_block + local;
            blocks[block_index].location = Some(BlockLocation {
                source: SourceLocation::Path(path.to_path_buf()),
                offset: local as u64 * state.set.slice_size,
                len: blocks[block_index].expected_len,
                kind: BlockLocationKind::Canonical,
            });
            settled[local] = true;
        }
        if !honour {
            settled = vec![false; target.block_count];
        }
        let stats = scanner
            .scan_file_ordered_canonical_settled(
                path,
                BlockLocationKind::Canonical,
                SourceFileScanLookup {
                    files: &state.files,
                    file_index_by_id: &state.file_index_by_id,
                },
                &target,
                &mut blocks,
                ScanSkipOptions::disabled(),
                &settled,
            )
            .unwrap();
        (block_location_summary(&blocks), stats)
    }

    #[test]
    fn settled_byte_runs_coalesce_and_drop_ranges_past_the_file() {
        assert_eq!(settled_byte_runs(&[], 64, 384), Vec::new());
        assert_eq!(
            settled_byte_runs(&[true, true, false, true, false, true], 64, 384),
            vec![(0, 128), (192, 256), (320, 384)]
        );
        // A slice the set describes but the file on disk is too short to hold
        // is a discrepancy for the scan to find, never one to seek over.
        assert_eq!(
            settled_byte_runs(&[true, true, true], 64, 100),
            vec![(0, 64)]
        );
    }

    #[test]
    fn evidence_skip_leaves_the_ordered_scan_locations_unchanged() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let mut target = Vec::new();
        for block in 0..8u8 {
            target.extend(
                (0..slice_size as usize)
                    .map(|index| block.wrapping_mul(37).wrapping_add(index as u8)),
            );
        }
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = target.clone();
        damaged[3 * slice_size as usize..4 * slice_size as usize].fill(0xEE);
        fs::write(&candidate, &damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let settled_locals = [0usize, 1, 2, 4, 5, 6, 7];
        let (read_in_full, full_stats) =
            scan_with_settled_evidence(&state, &candidate, &settled_locals, false);
        let (with_skips, skip_stats) =
            scan_with_settled_evidence(&state, &candidate, &settled_locals, true);

        assert_eq!(with_skips, read_in_full, "the skip must not move a block");
        assert_eq!(full_stats.slices_settled_by_evidence, 0);
        assert_eq!(full_stats.bytes_skipped_by_evidence, 0);
        assert_eq!(skip_stats.slices_settled_by_evidence, 7);
        assert!(
            skip_stats.bytes_skipped_by_evidence > 0,
            "a honoured skip must show up as bytes not read"
        );
        assert!(
            skip_stats.bytes_skipped_by_evidence < target.len() as u64,
            "the damaged slice still has to be read"
        );
        assert!(skip_stats.windows_stepped < full_stats.windows_stepped);
    }

    #[test]
    fn an_entirely_settled_file_is_not_walked_at_all() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let target: Vec<u8> = (0..4 * slice_size as usize).map(|i| i as u8).collect();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (_, stats) = scan_with_settled_evidence(&state, &candidate, &[0, 1, 2, 3], true);

        assert_eq!(stats.slices_settled_by_evidence, 4);
        assert_eq!(stats.bytes_skipped_by_evidence, target.len() as u64);
        assert_eq!(stats.windows_stepped, 0);
    }

    #[test]
    fn a_settled_slice_with_no_recorded_location_is_never_skipped() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let target: Vec<u8> = (0..4 * slice_size as usize).map(|i| i as u8).collect();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let file = state.files.first().unwrap();
        let fingerprint = stat_fingerprint(&candidate).unwrap();

        let mut trust = EvidenceScanTrust::default();
        for local in 0..4u32 {
            trust.record(file.file_id, &candidate, local, fingerprint.clone());
        }

        // Nothing is located yet, so nothing may be skipped: a skip is only
        // ever permitted over a block the state already holds.
        let blocks = ScanBlockState::new(&state.blocks);
        let settled = evidence_settled_slices(&trust, file, &candidate, &blocks, slice_size);
        assert!(settled.iter().all(|set| !*set));

        // With the locations in place the same plan settles every slice.
        let mut located = state.blocks.clone();
        for local in 0..4usize {
            located[file.first_block + local].location = Some(BlockLocation {
                source: SourceLocation::Path(candidate.clone()),
                offset: local as u64 * slice_size,
                len: slice_size,
                kind: BlockLocationKind::Canonical,
            });
        }
        let blocks = ScanBlockState::new(&located);
        let settled = evidence_settled_slices(&trust, file, &candidate, &blocks, slice_size);
        assert_eq!(settled, vec![true; 4]);

        // A stat the file no longer matches refuses every one of them, with no
        // error: the file is simply read in full.
        bump_modified_time(&candidate);
        let settled = evidence_settled_slices(&trust, file, &candidate, &blocks, slice_size);
        assert!(settled.iter().all(|set| !*set));
    }

    #[test]
    fn a_trust_plan_naming_two_paths_for_one_file_settles_nothing() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let target: Vec<u8> = (0..2 * slice_size as usize).map(|i| i as u8).collect();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let decoy = dir.path().join("elsewhere.bin");
        fs::write(&candidate, &target).unwrap();
        fs::write(&decoy, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let file = state.files.first().unwrap();
        let fingerprint = stat_fingerprint(&candidate).unwrap();

        // The conflict latches: a verdict for the canonical path arriving
        // after the decoy must not revive the entry, whichever order the map
        // hands them over in.
        for order in [[&candidate, &decoy], [&decoy, &candidate]] {
            let mut trust = EvidenceScanTrust::default();
            trust.record(file.file_id, order[0], 0, fingerprint.clone());
            trust.record(file.file_id, order[1], 1, fingerprint.clone());
            trust.record(file.file_id, order[0], 2, fingerprint.clone());

            let blocks = ScanBlockState::new(&state.blocks);
            assert!(
                evidence_settled_slices(&trust, file, &candidate, &blocks, slice_size)
                    .iter()
                    .all(|set| !*set)
            );
        }
    }

    fn scan_with_buffered(
        state: &RepairState,
        path: &Path,
        kind: BlockLocationKind,
        read_target: usize,
    ) -> Vec<Option<(PathBuf, u64, u64, BlockLocationKind)>> {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        scanner
            .scan_file_buffered_with_target(
                path,
                kind,
                &state.files,
                &state.file_index_by_id,
                &mut blocks,
                read_target,
            )
            .unwrap();
        block_location_summary(&blocks)
    }

    fn scan_with_buffered_options(
        state: &RepairState,
        path: &Path,
        kind: BlockLocationKind,
        read_target: usize,
        scan_options: ScanSkipOptions,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let stats = scanner
            .scan_file_buffered_with_target_options(
                path,
                kind,
                SourceFileScanLookup {
                    files: &state.files,
                    file_index_by_id: &state.file_index_by_id,
                },
                &mut blocks,
                read_target,
                scan_options,
            )
            .unwrap();
        (block_location_summary(&blocks), stats)
    }

    #[test]
    fn buffered_scan_matches_mmap_for_intact_full_blocks() {
        let dir = tempdir().unwrap();
        let target: Vec<u8> = (0..256u32).map(|value| (value % 251) as u8).collect();
        let set = synthetic_set(&[("target.bin", &target)], 64);
        let candidate = dir.path().join("candidate.bin");
        fs::write(&candidate, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let mmap = scan_with_mmap(&state, &candidate, BlockLocationKind::Extra);
        let buffered = scan_with_buffered(&state, &candidate, BlockLocationKind::Extra, 96);

        assert_eq!(buffered, mmap);
    }

    #[test]
    fn buffered_scan_matches_mmap_for_damaged_partial_matches() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbccccdddd".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        let candidate = dir.path().join("partial.bin");
        fs::write(&candidate, b"xxxxbbbbzzzzdddd").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let mmap = scan_with_mmap(&state, &candidate, BlockLocationKind::Extra);
        let buffered = scan_with_buffered(&state, &candidate, BlockLocationKind::Extra, 7);

        assert_eq!(buffered, mmap);
    }

    #[test]
    fn ordered_canonical_scan_matches_generic_locations_for_shifted_damage() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let mut target = Vec::new();
        let mut blocks = Vec::new();
        for block in 0..6u8 {
            let bytes = (0..slice_size as usize)
                .map(|index| block.wrapping_mul(37).wrapping_add(index as u8))
                .collect::<Vec<_>>();
            target.extend_from_slice(&bytes);
            blocks.push(bytes);
        }
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = Vec::new();
        damaged.extend_from_slice(&blocks[0]);
        damaged.extend_from_slice(&blocks[1]);
        damaged.extend_from_slice(&blocks[3]);
        damaged.extend_from_slice(&blocks[4]);
        damaged.extend_from_slice(&blocks[5]);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (generic_locations, generic_stats) =
            scan_with_mmap_stats(&state, &candidate, BlockLocationKind::Canonical);
        let (ordered_locations, ordered_stats) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(ordered_locations, generic_locations);
        assert!(ordered_stats.jumps_taken >= 3);
        assert!(ordered_stats.windows_stepped < generic_stats.windows_stepped);
    }

    #[test]
    fn ordered_canonical_scan_preserves_mixed_block_harvesting() {
        let dir = tempdir().unwrap();
        let alpha = b"aaaabbbbccccdddd".to_vec();
        let beta = b"1111222233334444".to_vec();
        let set = synthetic_set(&[("alpha.bin", &alpha), ("beta.bin", &beta)], 4);
        let candidate = dir.path().join("alpha.bin");
        fs::write(&candidate, b"aaaa2222ccccxxxx").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (generic_locations, _) =
            scan_with_mmap_stats(&state, &candidate, BlockLocationKind::Canonical);
        let (ordered_locations, ordered_stats) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(ordered_locations, generic_locations);
        assert_eq!(
            ordered_locations[5],
            Some((candidate.clone(), 4, 4, BlockLocationKind::Canonical))
        );
        assert!(ordered_stats.jumps_taken >= 1);
    }

    #[test]
    fn ordered_canonical_scan_ignores_already_used_duplicate_block_when_jumping() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbaaaacccc".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"aaaaaaaacccc").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (ordered_locations, ordered_stats) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(
            ordered_locations[0],
            Some((candidate.clone(), 0, 4, BlockLocationKind::Canonical))
        );
        assert_eq!(
            ordered_locations[2],
            Some((candidate.clone(), 4, 4, BlockLocationKind::Canonical))
        );
        assert!(ordered_stats.jumps_taken >= 2);
    }

    #[test]
    fn ordered_canonical_scan_checks_shifted_short_file_below_slice_size() {
        let dir = tempdir().unwrap();
        let target = b"ABCDE".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 8);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"xABCDEy").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (ordered_locations, ordered_stats) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(
            ordered_locations[0],
            Some((candidate.clone(), 1, 5, BlockLocationKind::Canonical))
        );
        assert_eq!(ordered_stats.windows_stepped, 0);
    }

    #[test]
    fn shifted_large_short_block_scans_without_large_heap_buffer() {
        let dir = tempdir().unwrap();
        let short_len = SCANNER_IO_TARGET_BYTES + 1;
        let slice_size = short_len as u64 + 1024;
        let target = (0..short_len)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect::<Vec<_>>();
        let set = synthetic_set(&[("large-short.bin", &target)], slice_size);
        let candidate = dir.path().join("large-short.bin");
        let mut damaged = Vec::with_capacity(short_len + 2);
        damaged.push(0xA5);
        damaged.extend_from_slice(&target);
        damaged.push(0x5A);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (ordered_locations, _) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(
            ordered_locations[0],
            Some((
                candidate.clone(),
                1,
                short_len as u64,
                BlockLocationKind::Canonical
            ))
        );
    }

    #[test]
    fn ordered_canonical_scan_checks_every_byte_through_long_miss_runs() {
        let dir = tempdir().unwrap();
        let slice_size = 1024u64;
        let block = |seed: u8| {
            (0..slice_size as usize)
                .map(|index| seed.wrapping_add(index as u8))
                .collect::<Vec<_>>()
        };
        let first = block(3);
        let second = block(71);
        let target = [first.as_slice(), second.as_slice()].concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = Vec::new();
        damaged.extend_from_slice(&first);
        damaged.extend(std::iter::repeat_n(0xEE, 176));
        damaged.extend_from_slice(&second);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (generic_locations, generic_stats) =
            scan_with_mmap_stats(&state, &candidate, BlockLocationKind::Canonical);
        let (ordered_locations, ordered_stats) = scan_with_ordered_canonical(&state, &candidate);

        assert_eq!(ordered_locations, generic_locations);
        assert_eq!(
            ordered_locations[1],
            Some((
                candidate.clone(),
                slice_size + 176,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
        assert!(ordered_stats.jumps_taken >= 2);
        assert!(ordered_stats.windows_stepped > 64);
        assert!(ordered_stats.windows_stepped <= generic_stats.windows_stepped);
    }

    #[test]
    fn ordered_canonical_scan_can_skip_long_in_place_miss_runs_when_enabled() {
        let dir = tempdir().unwrap();
        let slice_size = 1024u64;
        let make_block = |seed: u8| {
            (0..slice_size as usize)
                .map(|index| seed.wrapping_mul(17).wrapping_add(index as u8))
                .collect::<Vec<_>>()
        };
        let blocks = [
            make_block(3),
            make_block(31),
            make_block(71),
            make_block(109),
        ];
        let target = blocks
            .iter()
            .flat_map(|block| block.iter().copied())
            .collect::<Vec<_>>();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = target.clone();
        damaged[slice_size as usize..(slice_size as usize * 2)].fill(0xEE);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (default_locations, default_stats) = scan_with_ordered_canonical(&state, &candidate);
        let (skip_locations, skip_stats) = scan_with_ordered_canonical_options(
            &state,
            &candidate,
            ScanSkipOptions {
                skip_data: true,
                skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
            },
        );

        assert_eq!(skip_locations, default_locations);
        assert_eq!(
            skip_locations[0],
            Some((
                candidate.clone(),
                0,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
        assert_eq!(skip_locations[1], None);
        assert_eq!(
            skip_locations[2],
            Some((
                candidate.clone(),
                slice_size * 2,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
        assert_eq!(
            skip_locations[3],
            Some((
                candidate.clone(),
                slice_size * 3,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
        assert!(default_stats.windows_stepped >= slice_size);
        assert!(skip_stats.windows_stepped < default_stats.windows_stepped / 2);
        assert!(skip_stats.max_consecutive_steps <= ORDERED_SCAN_DEFAULT_SKIP_LEEWAY);
    }

    fn scan_ordered_serial_direct(
        state: &RepairState,
        path: &Path,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let baseline = blocks.clone();
        let mut scan_state = ScanBlockState::new(&baseline);
        let target = state
            .files
            .iter()
            .find(|file| file.safe_path == path)
            .unwrap();
        let stats = scanner
            .scan_file_ordered_canonical_serial(
                path,
                BlockLocationKind::Canonical,
                SourceFileScanLookup {
                    files: &state.files,
                    file_index_by_id: &state.file_index_by_id,
                },
                target,
                &mut scan_state,
                ScanSkipOptions::disabled(),
                &[],
            )
            .unwrap();
        scan_state.apply_to_blocks(&mut blocks);
        (block_location_summary(&blocks), stats)
    }

    fn scan_ordered_parallel_direct(
        state: &RepairState,
        path: &Path,
        segment_windows: usize,
    ) -> (BlockLocationSummary, FileScanStats) {
        scan_ordered_parallel_direct_with_memory_limit(
            state,
            path,
            segment_windows,
            DEFAULT_REPAIR_MEMORY_LIMIT,
        )
    }

    fn scan_ordered_parallel_direct_with_memory_limit(
        state: &RepairState,
        path: &Path,
        segment_windows: usize,
        memory_limit: usize,
    ) -> (BlockLocationSummary, FileScanStats) {
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();
        let baseline = blocks.clone();
        let mut scan_state = ScanBlockState::new(&baseline);
        let target = state
            .files
            .iter()
            .find(|file| file.safe_path == path)
            .unwrap();
        let stats = scanner
            .scan_file_ordered_canonical_parallel(
                path,
                BlockLocationKind::Canonical,
                SourceFileScanLookup {
                    files: &state.files,
                    file_index_by_id: &state.file_index_by_id,
                },
                target,
                &mut scan_state,
                ScanSkipOptions::disabled(),
                segment_windows,
                memory_limit,
                None,
            )
            .unwrap();
        scan_state.apply_to_blocks(&mut blocks);
        (block_location_summary(&blocks), stats)
    }

    fn scan_stat_counters(stats: FileScanStats) -> (u64, u64, u64, u64) {
        (
            stats.bytes_scanned,
            stats.windows_stepped,
            stats.jumps_taken,
            stats.max_consecutive_steps,
        )
    }

    /// Runs the serial scanner and the parallel scanner (forced-tiny and
    /// default segment sizes) over the same candidate and asserts identical
    /// block locations and scan counters. Returns the serial result for
    /// fixture-specific assertions.
    fn assert_ordered_scan_parity(
        state: &RepairState,
        path: &Path,
    ) -> (BlockLocationSummary, FileScanStats) {
        let (serial_locations, serial_stats) = scan_ordered_serial_direct(state, path);
        let default_segment = ordered_scan_segment_windows(state.set.slice_size as usize);
        for segment_windows in [1usize, 2, default_segment] {
            let (parallel_locations, parallel_stats) =
                scan_ordered_parallel_direct(state, path, segment_windows);
            assert_eq!(
                parallel_locations, serial_locations,
                "locations diverged with segment_windows={segment_windows}"
            );
            assert_eq!(
                scan_stat_counters(parallel_stats),
                scan_stat_counters(serial_stats),
                "scan counters diverged with segment_windows={segment_windows}"
            );
        }
        (serial_locations, serial_stats)
    }

    fn seeded_block(seed: u8, slice_size: usize) -> Vec<u8> {
        (0..slice_size)
            .map(|index| {
                seed.wrapping_mul(37)
                    .wrapping_add((index as u8).wrapping_mul(11))
            })
            .collect()
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_for_intact_file() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let mut target = Vec::new();
        for seed in 0..6u8 {
            target.extend_from_slice(&seeded_block(seed, slice_size as usize));
        }
        target.extend_from_slice(b"tail!");
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, stats) = assert_ordered_scan_parity(&state, &candidate);

        assert!(locations.iter().all(Option::is_some));
        assert_eq!(stats.windows_stepped, 0);
        assert_eq!(stats.jumps_taken, 6);
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_for_deleted_full_block() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let blocks: Vec<Vec<u8>> = (0..6u8)
            .map(|seed| seeded_block(seed, slice_size as usize))
            .collect();
        let target: Vec<u8> = blocks.concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = Vec::new();
        for (index, block) in blocks.iter().enumerate() {
            if index != 2 {
                damaged.extend_from_slice(block);
            }
        }
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);
        let generic = scan_with_mmap(&state, &candidate, BlockLocationKind::Canonical);

        assert_eq!(locations, generic);
        assert_eq!(locations[2], None);
        assert_eq!(
            locations[3],
            Some((
                candidate.clone(),
                slice_size * 2,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_for_insertion_gap() {
        let dir = tempdir().unwrap();
        let slice_size = 1024u64;
        let first = seeded_block(3, slice_size as usize);
        let second = seeded_block(71, slice_size as usize);
        let target = [first.as_slice(), second.as_slice()].concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate = dir.path().join("target.bin");
        let mut damaged = Vec::new();
        damaged.extend_from_slice(&first);
        damaged.extend(std::iter::repeat_n(0xEE, 176));
        damaged.extend_from_slice(&second);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, stats) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(
            locations[1],
            Some((
                candidate.clone(),
                slice_size + 176,
                slice_size,
                BlockLocationKind::Canonical
            ))
        );
        assert!(stats.windows_stepped > 64);
    }

    #[test]
    fn ordered_parallel_scan_realigns_mid_file_after_compensating_deletion() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let blocks: Vec<Vec<u8>> = (0..6u8)
            .map(|seed| seeded_block(seed.wrapping_add(11), slice_size))
            .collect();
        let target: Vec<u8> = blocks.concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        // Insert 17 junk bytes before block 1, then replace block 2 with 47
        // junk bytes: block 1 matches unaligned, block 3 realigns exactly at
        // 3 * slice_size, so the resync must splice back into the aligned
        // merge mid-file.
        let insert_len = 17usize;
        let mut damaged = Vec::new();
        damaged.extend_from_slice(&blocks[0]);
        damaged.extend(std::iter::repeat_n(0xEE, insert_len));
        damaged.extend_from_slice(&blocks[1]);
        damaged.extend(std::iter::repeat_n(0xDD, slice_size - insert_len));
        damaged.extend_from_slice(&blocks[3]);
        damaged.extend_from_slice(&blocks[4]);
        damaged.extend_from_slice(&blocks[5]);
        assert_eq!(damaged.len(), target.len());
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, stats) = assert_ordered_scan_parity(&state, &candidate);

        let aligned = |index: u64| {
            Some((
                candidate.clone(),
                index * slice_size as u64,
                slice_size as u64,
                BlockLocationKind::Canonical,
            ))
        };
        assert_eq!(locations[0], aligned(0));
        assert_eq!(
            locations[1],
            Some((
                candidate.clone(),
                (slice_size + insert_len) as u64,
                slice_size as u64,
                BlockLocationKind::Canonical
            ))
        );
        assert_eq!(locations[2], None);
        assert_eq!(locations[3], aligned(3));
        assert_eq!(locations[4], aligned(4));
        assert_eq!(locations[5], aligned(5));
        assert_eq!(stats.jumps_taken, 5);
    }

    #[test]
    fn ordered_parallel_scan_stays_misaligned_through_unaligned_tail() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let blocks: Vec<Vec<u8>> = (0..5u8)
            .map(|seed| seeded_block(seed.wrapping_add(29), slice_size))
            .collect();
        let target: Vec<u8> = blocks.concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        // Delete 17 bytes (not a multiple of the slice size) from block 1:
        // every later block sits at an unaligned offset until EOF, so the
        // scan never realigns after the gap.
        let mut damaged = Vec::new();
        damaged.extend_from_slice(&blocks[0]);
        damaged.extend_from_slice(&blocks[1][..slice_size - 17]);
        damaged.extend_from_slice(&blocks[2]);
        damaged.extend_from_slice(&blocks[3]);
        damaged.extend_from_slice(&blocks[4]);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);
        let generic = scan_with_mmap(&state, &candidate, BlockLocationKind::Canonical);

        assert_eq!(locations, generic);
        assert_eq!(locations[1], None);
        for index in [2u64, 3, 4] {
            assert_eq!(
                locations[index as usize],
                Some((
                    candidate.clone(),
                    index * slice_size as u64 - 17,
                    slice_size as u64,
                    BlockLocationKind::Canonical
                ))
            );
        }
    }

    #[test]
    fn ordered_parallel_scan_dedupes_duplicate_blocks_across_segment_boundary() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbaaaacccc".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"aaaaaaaacccc").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        // The parity helper forces one- and two-window segments, so the
        // duplicate pair lands in different Phase A tasks.
        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(
            locations[0],
            Some((candidate.clone(), 0, 4, BlockLocationKind::Canonical))
        );
        assert_eq!(
            locations[2],
            Some((candidate.clone(), 4, 4, BlockLocationKind::Canonical))
        );
    }

    #[test]
    fn ordered_parallel_scan_prefers_target_blocks_over_cross_file_duplicates() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let shared = seeded_block(200, slice_size);
        let alpha = [
            shared.clone(),
            seeded_block(1, slice_size),
            seeded_block(2, slice_size),
            seeded_block(3, slice_size),
        ]
        .concat();
        let beta = [
            seeded_block(4, slice_size),
            shared.clone(),
            seeded_block(5, slice_size),
            seeded_block(6, slice_size),
        ]
        .concat();
        let set = synthetic_set(
            &[("alpha.bin", &alpha), ("beta.bin", &beta)],
            slice_size as u64,
        );
        let candidate = dir.path().join("alpha.bin");
        // Junk replaces alpha's first block, pushing the shared block to an
        // offset only reachable through the resync loop; the target's copy
        // (rank 1) must win over beta's identical block (rank 2).
        let mut damaged = Vec::new();
        damaged.extend(std::iter::repeat_n(0xEE, slice_size));
        damaged.extend_from_slice(&shared);
        damaged.extend_from_slice(&alpha[slice_size * 2..]);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(
            locations[0],
            Some((
                candidate.clone(),
                slice_size as u64,
                slice_size as u64,
                BlockLocationKind::Canonical
            ))
        );
        // Beta's identical block stays unclaimed by alpha's scan.
        assert_eq!(locations[5], None);
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_for_mixed_harvesting() {
        let dir = tempdir().unwrap();
        let alpha = b"aaaabbbbccccdddd".to_vec();
        let beta = b"1111222233334444".to_vec();
        let set = synthetic_set(&[("alpha.bin", &alpha), ("beta.bin", &beta)], 4);
        let candidate = dir.path().join("alpha.bin");
        fs::write(&candidate, b"aaaa2222ccccxxxx").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(
            locations[5],
            Some((candidate.clone(), 4, 4, BlockLocationKind::Canonical))
        );
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_with_segment_boundary_damage() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let blocks: Vec<Vec<u8>> = (0..8u8)
            .map(|seed| seeded_block(seed.wrapping_add(53), slice_size))
            .collect();
        let target: Vec<u8> = blocks.concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        // With two-window segments, window 1 is the last of segment 0 and
        // window 2 the first of segment 1; damaging both spans the boundary.
        let mut damaged = target.clone();
        damaged[slice_size..slice_size * 3].fill(0xEE);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(locations[1], None);
        assert_eq!(locations[2], None);
        for index in [0usize, 3, 4, 5, 6, 7] {
            assert_eq!(
                locations[index],
                Some((
                    candidate.clone(),
                    index as u64 * slice_size as u64,
                    slice_size as u64,
                    BlockLocationKind::Canonical
                ))
            );
        }
    }

    #[test]
    fn ordered_parallel_scan_matches_serial_with_adjacent_damage_mid_segment() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let blocks: Vec<Vec<u8>> = (0..10u8)
            .map(|seed| seeded_block(seed.wrapping_add(101), slice_size))
            .collect();
        let target: Vec<u8> = blocks.concat();
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        // Adjacent damaged windows 3 and 4 sit inside a single default-size
        // segment, so the gap resync starts and realigns without crossing a
        // segment boundary.
        let mut damaged = target.clone();
        damaged[slice_size * 3..slice_size * 5].fill(0xEE);
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, _) = assert_ordered_scan_parity(&state, &candidate);

        assert_eq!(locations[3], None);
        assert_eq!(locations[4], None);
        assert!(locations.iter().filter(|entry| entry.is_some()).count() == 8);
    }

    #[test]
    fn ordered_parallel_scan_facts_allocation_is_checked() {
        let fact_size = std::mem::size_of::<AlignedWindowFacts>();
        assert_eq!(ordered_scan_facts_allocation_bytes(0), Some(0));
        assert_eq!(ordered_scan_facts_allocation_bytes(3), Some(fact_size * 3));
        assert_eq!(ordered_scan_facts_allocation_bytes(usize::MAX), None);
    }

    /// Smallest working-memory limit whose admission still leaves room for
    /// `match_bytes` of retained match entries. Searched rather than derived:
    /// the read buffers shrink as the limit does, so the match budget is not
    /// monotone in the limit and has no closed form. `match_bytes` is a sound
    /// floor for the search — the budget can never exceed the whole limit.
    fn smallest_limit_admitting_matches(
        window_count: usize,
        segment_windows: usize,
        slice_size: usize,
        max_crc_bucket: usize,
        match_bytes: usize,
        search_span: usize,
    ) -> usize {
        let workers = ordered_scan_workers(window_count, segment_windows);
        (match_bytes..=match_bytes + search_span)
            .find(|limit| {
                ordered_scan_admission(
                    window_count,
                    segment_windows,
                    slice_size,
                    max_crc_bucket,
                    workers,
                    *limit,
                )
                .is_some_and(|admission| admission.match_budget >= match_bytes)
            })
            .expect("no limit inside the search span admits the scan")
    }

    #[test]
    fn ordered_parallel_scan_falls_back_when_facts_exceed_memory_limit() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let target = seeded_block(76, slice_size);
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        let mut oversized = target.clone();
        oversized.resize(slice_size * 9, 0xEE);
        fs::write(&candidate, oversized).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let facts_bytes = ordered_scan_facts_allocation_bytes(9).unwrap();
        // Only the first window matches the set's single block.
        let retained_bytes = std::mem::size_of::<u32>();
        let admitting_limit = smallest_limit_admitting_matches(
            9,
            2,
            slice_size,
            state.hash_table.max_crc_bucket,
            retained_bytes,
            64 * 1024,
        );
        assert!(facts_bytes < admitting_limit);

        let (parallel_locations, parallel_stats) =
            scan_ordered_parallel_direct_with_memory_limit(&state, &candidate, 2, admitting_limit);
        assert_eq!(parallel_stats.mode, FileScanMode::OrderedCanonicalParallel);

        for starved_limit in [admitting_limit - 1, facts_bytes - 1] {
            let (fallback_locations, fallback_stats) =
                scan_ordered_parallel_direct_with_memory_limit(
                    &state,
                    &candidate,
                    2,
                    starved_limit,
                );
            assert_eq!(fallback_stats.mode, FileScanMode::OrderedCanonical);
            assert_eq!(fallback_locations, parallel_locations);
        }
    }

    /// The admission gap the fixed-header budget missed: Phase A retains one
    /// `Vec<u32>` of matching slice indices per aligned window, so a recovery
    /// set with many byte-identical slices multiplies retained bytes far past
    /// the header cost the old accounting checked. 256 duplicate slices over
    /// 2,048 aligned windows is 48 KiB of headers against 2 MiB of retained
    /// entries.
    #[test]
    fn ordered_parallel_scan_refuses_duplicate_slice_match_blowup() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let duplicate_count = 256usize;
        let window_count = 2048usize;
        let segment_windows = 128usize;

        let duplicate = seeded_block(211, slice_size);
        let dupes: Vec<u8> = std::iter::repeat_n(duplicate.as_slice(), duplicate_count)
            .flatten()
            .copied()
            .collect();
        // Every slice of the recorded target is unique, so the candidate's
        // windows can only match the duplicate pool.
        let mut target = Vec::with_capacity(window_count * slice_size);
        for index in 0..window_count {
            target.extend_from_slice(&(index as u32).to_le_bytes());
            target.resize((index + 1) * slice_size, 0x5A);
        }
        let set = synthetic_set(
            &[("dupes.bin", &dupes), ("target.bin", &target)],
            slice_size as u64,
        );
        let candidate = dir.path().join("target.bin");
        let damaged: Vec<u8> = std::iter::repeat_n(duplicate.as_slice(), window_count)
            .flatten()
            .copied()
            .collect();
        fs::write(&candidate, damaged).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        assert_eq!(state.hash_table.max_crc_bucket, duplicate_count);

        let retained_bytes = window_count * duplicate_count * std::mem::size_of::<u32>();
        let facts_bytes = ordered_scan_facts_allocation_bytes(window_count).unwrap();
        assert!(facts_bytes * 16 < retained_bytes);

        let admitting_limit = smallest_limit_admitting_matches(
            window_count,
            segment_windows,
            slice_size,
            duplicate_count,
            retained_bytes,
            8 * 1024 * 1024,
        );
        // One byte short of the retained demand, yet far past what the old
        // header-only accounting checked: this is the shape that used to stay
        // in the parallel scanner while holding 2 MiB it never budgeted. The
        // one-byte gap pins the admission budget to the true retained size
        // rather than merely somewhere near it.
        let starved_limit = admitting_limit - 1;
        assert!(facts_bytes < starved_limit);
        let starved = ordered_scan_admission(
            window_count,
            segment_windows,
            slice_size,
            duplicate_count,
            ordered_scan_workers(window_count, segment_windows),
            starved_limit,
        )
        .unwrap();
        assert_eq!(starved.match_budget, retained_bytes - 1);

        let (serial_locations, serial_stats) = scan_ordered_serial_direct(&state, &candidate);

        let (parallel_locations, parallel_stats) = scan_ordered_parallel_direct_with_memory_limit(
            &state,
            &candidate,
            segment_windows,
            admitting_limit,
        );
        assert_eq!(parallel_stats.mode, FileScanMode::OrderedCanonicalParallel);
        assert_eq!(parallel_locations, serial_locations);
        assert_eq!(
            scan_stat_counters(parallel_stats),
            scan_stat_counters(serial_stats)
        );

        let (refused_locations, refused_stats) = scan_ordered_parallel_direct_with_memory_limit(
            &state,
            &candidate,
            segment_windows,
            starved_limit,
        );
        assert_eq!(refused_stats.mode, FileScanMode::OrderedCanonical);
        assert_eq!(refused_locations, serial_locations);
        assert_eq!(
            scan_stat_counters(refused_stats),
            scan_stat_counters(serial_stats)
        );
    }

    #[test]
    fn ordered_parallel_scan_handles_single_window_file() {
        let dir = tempdir().unwrap();
        let slice_size = 64usize;
        let target = seeded_block(77, slice_size);
        let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, &target).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (locations, stats) = assert_ordered_scan_parity(&state, &candidate);
        assert_eq!(
            locations[0],
            Some((
                candidate.clone(),
                0,
                slice_size as u64,
                BlockLocationKind::Canonical
            ))
        );
        assert_eq!(stats.jumps_taken, 1);
        assert_eq!(stats.windows_stepped, 0);

        // Damaged single window: the failed step off the only full window
        // must end the scan without counting a step, in both modes.
        fs::write(&candidate, vec![0xEE; slice_size]).unwrap();
        let (damaged_locations, damaged_stats) = assert_ordered_scan_parity(&state, &candidate);
        assert_eq!(damaged_locations[0], None);
        assert_eq!(damaged_stats.windows_stepped, 0);
        assert_eq!(damaged_stats.jumps_taken, 0);
    }

    #[test]
    fn full_state_scan_with_renamed_copy_matches_between_thread_pools() {
        let slice_size = 64usize;
        let blocks: Vec<Vec<u8>> = (0..6u8)
            .map(|seed| seeded_block(seed.wrapping_add(151), slice_size))
            .collect();
        let mut data: Vec<u8> = blocks.concat();
        data.extend_from_slice(b"short-tail");

        let run_scan = |threads: usize| {
            let dir = tempdir().unwrap();
            let set = synthetic_set(&[("target.bin", &data)], slice_size as u64);
            let mut damaged = data.clone();
            damaged[slice_size * 2..slice_size * 3].fill(0xEE);
            fs::write(dir.path().join("target.bin"), &damaged).unwrap();
            fs::write(dir.path().join("renamed-copy.bin"), &data).unwrap();

            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let mut state = RepairState::from_set(dir.path(), set).unwrap();
            let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
            pool.install(|| state.scan(&options)).unwrap();
            let verification = state.verification_result();
            let locations: Vec<Option<(u64, u64, BlockLocationKind, String)>> = state
                .blocks
                .iter()
                .map(|block| {
                    block.location.as_ref().map(|location| {
                        (
                            location.offset,
                            location.len,
                            location.kind,
                            location
                                .path()
                                .expect("scanned location is a path")
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .into_owned(),
                        )
                    })
                })
                .collect();
            let statuses: Vec<String> = verification
                .files
                .iter()
                .map(|file| match &file.status {
                    FileStatus::Renamed(path) => {
                        format!("Renamed({})", path.file_name().unwrap().to_string_lossy())
                    }
                    status => format!("{status:?}"),
                })
                .collect();
            (
                locations,
                statuses,
                verification.total_missing_blocks,
                verification
                    .files
                    .iter()
                    .map(|file| file.valid_slices.clone())
                    .collect::<Vec<_>>(),
            )
        };

        // One thread forces the serial ordered scanner through the
        // dispatcher; four threads take the parallel path.
        let serial = run_scan(1);
        let parallel = run_scan(4);
        assert_eq!(parallel.0, serial.0);
        assert_eq!(parallel.1, serial.1);
        assert_eq!(parallel.2, serial.2);
        assert_eq!(parallel.3, serial.3);
        assert_eq!(serial.2, 0, "complete renamed copy supplies every block");
    }

    struct ParityLcg(u64);

    impl ParityLcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound.max(1)
        }
    }

    #[test]
    fn ordered_parallel_scan_randomized_parity_matches_serial() {
        let slice_size = 64usize;
        let mut rng = ParityLcg(0x5EED_CAFE_F00D_D00D);

        for iteration in 0..24 {
            let dir = tempdir().unwrap();
            let block_count = 4 + rng.below(8) as usize;
            // A small seed alphabet makes duplicate block content likely.
            let mut target = Vec::new();
            for _ in 0..block_count {
                target.extend_from_slice(&seeded_block(rng.below(4) as u8, slice_size));
            }
            if rng.below(2) == 0 {
                let tail_len = 1 + rng.below(slice_size as u64 - 1) as usize;
                target.extend((0..tail_len).map(|_| rng.below(256) as u8));
            }
            let set = synthetic_set(&[("target.bin", &target)], slice_size as u64);

            let mut damaged = target.clone();
            for _ in 0..=rng.below(3) {
                if damaged.is_empty() {
                    break;
                }
                match rng.below(4) {
                    0 => {
                        // In-place corruption.
                        let start = rng.below(damaged.len() as u64) as usize;
                        let len = (1 + rng.below(2 * slice_size as u64) as usize)
                            .min(damaged.len() - start);
                        for byte in &mut damaged[start..start + len] {
                            *byte ^= 0x5A;
                        }
                    }
                    1 => {
                        // Insertion.
                        let at = rng.below(damaged.len() as u64 + 1) as usize;
                        let len = 1 + rng.below(2 * slice_size as u64) as usize;
                        let junk: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
                        damaged.splice(at..at, junk);
                    }
                    2 => {
                        // Deletion.
                        let start = rng.below(damaged.len() as u64) as usize;
                        let len = (1 + rng.below(2 * slice_size as u64) as usize)
                            .min(damaged.len() - start);
                        damaged.drain(start..start + len);
                    }
                    _ => {
                        // Duplicate a source block's content at a random spot.
                        if damaged.len() >= slice_size {
                            let source = rng.below(block_count as u64) as usize * slice_size;
                            let at = rng.below((damaged.len() - slice_size) as u64 + 1) as usize;
                            let copy = target[source..source + slice_size].to_vec();
                            damaged[at..at + slice_size].copy_from_slice(&copy);
                        }
                    }
                }
            }

            let candidate = dir.path().join("target.bin");
            fs::write(&candidate, &damaged).unwrap();
            let state = RepairState::from_set(dir.path(), set).unwrap();

            let (serial_locations, serial_stats) = scan_ordered_serial_direct(&state, &candidate);
            let default_segment = ordered_scan_segment_windows(slice_size);
            for segment_windows in [2usize, default_segment] {
                let (parallel_locations, parallel_stats) =
                    scan_ordered_parallel_direct(&state, &candidate, segment_windows);
                assert_eq!(
                    parallel_locations,
                    serial_locations,
                    "iteration {iteration}: locations diverged (segment_windows={segment_windows}, damaged_len={})",
                    damaged.len()
                );
                assert_eq!(
                    scan_stat_counters(parallel_stats),
                    scan_stat_counters(serial_stats),
                    "iteration {iteration}: counters diverged (segment_windows={segment_windows}, damaged_len={})",
                    damaged.len()
                );
            }
        }
    }

    #[test]
    fn buffered_generic_scan_can_skip_long_extra_miss_runs_when_enabled() {
        let dir = tempdir().unwrap();
        let slice_size = 128 * 1024u64;
        let target: Vec<u8> = (0..slice_size as usize)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect();
        let set = synthetic_set(&[("target.bin", &target)], slice_size);
        let candidate_data = vec![0xA5; slice_size as usize * 6];
        let candidate = dir.path().join("unrelated-extra.bin");
        fs::write(&candidate, &candidate_data).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let (default_locations, default_stats) = scan_with_buffered_options(
            &state,
            &candidate,
            BlockLocationKind::Extra,
            candidate_data.len(),
            ScanSkipOptions {
                skip_data: false,
                skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
            },
        );
        let (skip_locations, skip_stats) = scan_with_buffered_options(
            &state,
            &candidate,
            BlockLocationKind::Extra,
            candidate_data.len(),
            ScanSkipOptions {
                skip_data: true,
                skip_leeway: ORDERED_SCAN_DEFAULT_SKIP_LEEWAY,
            },
        );

        assert_eq!(skip_locations, default_locations);
        assert!(skip_locations.iter().all(Option::is_none));
        assert_eq!(default_stats.jumps_taken, 0);
        assert!(skip_stats.jumps_taken > 0);
        assert!(skip_stats.windows_stepped < default_stats.windows_stepped / 2);
        assert!(skip_stats.max_consecutive_steps <= ORDERED_SCAN_DEFAULT_SKIP_LEEWAY * 2);
    }

    #[test]
    fn buffered_scan_finds_block_across_refill_overlap() {
        let dir = tempdir().unwrap();
        let target: Vec<u8> = (0..64u32)
            .map(|value| (value as u8).wrapping_mul(5).wrapping_add(9))
            .collect();
        let set = synthetic_set(&[("target.bin", &target)], 64);
        let mut candidate_data = vec![0xAA; 150];
        candidate_data.extend_from_slice(&target);
        candidate_data.extend_from_slice(&[0x55; 37]);
        let candidate = dir.path().join("cross-boundary.bin");
        fs::write(&candidate, candidate_data).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();

        scanner
            .scan_file_buffered_with_target(
                &candidate,
                BlockLocationKind::Extra,
                &state.files,
                &state.file_index_by_id,
                &mut blocks,
                80,
            )
            .unwrap();

        let location = blocks[0].location.as_ref().unwrap();
        assert_eq!(location.path(), Some(candidate.as_path()));
        assert_eq!(location.offset, 150);
    }

    #[test]
    fn shifted_short_block_checks_match_mmap_and_buffered() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"ABCDEFGHxx12345JUNK").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();

        let mmap = scan_with_mmap(&state, &candidate, BlockLocationKind::Canonical);
        let buffered = scan_with_buffered(&state, &candidate, BlockLocationKind::Canonical, 8);

        assert_eq!(buffered, mmap);
        assert_eq!(
            buffered[1],
            Some((candidate.clone(), 10, 5, BlockLocationKind::Canonical))
        );
    }

    #[test]
    fn large_slice_scanner_uses_mmap_fallback_and_remains_correct() {
        let dir = tempdir().unwrap();
        let slice_size = (SCANNER_MMAP_FALLBACK_SLICE_BYTES + 1) as u64;
        let data = (0..slice_size as usize)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(1))
            .collect::<Vec<_>>();
        let set = synthetic_set(&[("large.bin", &data)], slice_size);
        let candidate = dir.path().join("large.bin");
        fs::write(&candidate, &data).unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let mut blocks = state.blocks.clone();

        assert!(scanner_uses_mmap_fallback(slice_size));
        scanner
            .scan_file(
                &candidate,
                BlockLocationKind::Canonical,
                &state.files,
                &state.file_index_by_id,
                &mut blocks,
            )
            .unwrap();

        assert!(blocks.iter().all(|block| block.location.is_some()));
    }

    #[test]
    fn scan_finds_complete_renamed_file_and_copy_only_repair_installs_canonical() {
        let dir = tempdir().unwrap();
        let data = b"block-zero--block-one--tail".to_vec();
        let set = synthetic_set(&[("nested/movie.r00", &data)], 8);
        let renamed = dir.path().join("scrambled.bin");
        fs::write(&renamed, &data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert!(!state.files_are_canonical_complete());
        assert_eq!(
            state
                .outcome(
                    Par2RepairStatus::RepairPossible,
                    0,
                    0,
                    PacketDiagnostics::default(),
                    ScanDiagnostics::default(),
                    verification.clone(),
                )
                .files_renamed,
            1
        );

        let wrong_block_source = dir.path().join("wrong-block.bin");
        fs::write(&wrong_block_source, vec![0u8; data.len()]).unwrap();
        let file = state
            .files
            .iter()
            .find(|file| file.safe_name == "nested/movie.r00")
            .unwrap();
        state.blocks[file.first_block].location = Some(BlockLocation {
            source: SourceLocation::Path(wrong_block_source),
            offset: 0,
            len: state.blocks[file.first_block].expected_len,
            kind: BlockLocationKind::Extra,
        });

        let repair = state.repair(&options, &verification).unwrap();
        let access = DiskFileAccess::new(repair.install_dir.clone(), &state.set);
        let post = verify_all(&state.set, &access);
        assert_eq!(post.total_missing_blocks, 0);

        state.install_repaired_files(&repair, &options).unwrap();
        assert_eq!(fs::read(dir.path().join("nested/movie.r00")).unwrap(), data);
        assert!(renamed.exists());
    }

    #[test]
    fn scan_uses_partial_blocks_from_extra_file() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbccccdddd".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        fs::write(dir.path().join("partial.bin"), b"xxxxbbbbzzzzdddd").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 2);
        assert_eq!(
            state
                .blocks
                .iter()
                .filter(|block| block.location.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn scan_parallel_extra_batch_merges_partial_blocks() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbccccdddd".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        let first = dir.path().join("first.partial");
        let second = dir.path().join("second.partial");
        fs::write(&first, b"aaaaxxxxccccyyyy").unwrap();
        fs::write(&second, b"zzzzbbbbqqqqdddd").unwrap();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let scan = pool.install(|| state.scan(&options)).unwrap();
        let verification = state.verification_result();

        assert_eq!(scan.files_scanned, 2);
        assert_eq!(scan.blocks_found, 4);
        assert_eq!(verification.total_missing_blocks, 0);
        assert_eq!(
            state.blocks[0]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(first.as_path())
        );
        assert_eq!(
            state.blocks[1]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(second.as_path())
        );
        assert_eq!(
            state.blocks[2]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(first.as_path())
        );
        assert_eq!(
            state.blocks[3]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(second.as_path())
        );
    }

    #[test]
    fn copy_only_repair_assembles_mixed_target_from_extra_blocks() {
        let dir = tempdir().unwrap();
        let target = b"aaaabbbbccccdddd".to_vec();
        let set = synthetic_set(&[("target.bin", &target)], 4);
        fs::write(dir.path().join("target.bin"), b"aaaaxxxxccccyyyy").unwrap();
        fs::write(dir.path().join("extra.bin"), b"zzzzbbbbqqqqdddd").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert!(!state.files_are_canonical_complete());
        assert!(matches!(
            verification.repairable,
            Repairability::Repairable {
                blocks_needed: 0,
                ..
            }
        ));

        let repair = state.repair(&options, &verification).unwrap();
        state.install_repaired_files(&repair, &options).unwrap();
        assert_eq!(fs::read(dir.path().join("target.bin")).unwrap(), target);
    }

    #[test]
    fn copy_only_repair_corrects_swapped_complete_files() {
        let dir = tempdir().unwrap();
        let alpha = b"alpha---alpha---".to_vec();
        let beta = b"beta----beta----".to_vec();
        let set = synthetic_set(&[("alpha.bin", &alpha), ("beta.bin", &beta)], 8);
        fs::write(dir.path().join("alpha.bin"), &beta).unwrap();
        fs::write(dir.path().join("beta.bin"), &alpha).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert_eq!(
            state
                .files
                .iter()
                .filter(|file| file.complete_location.is_some())
                .count(),
            2
        );
        assert!(!state.files_are_canonical_complete());

        let repair = state.repair(&options, &verification).unwrap();
        state.install_repaired_files(&repair, &options).unwrap();
        assert_eq!(fs::read(dir.path().join("alpha.bin")).unwrap(), alpha);
        assert_eq!(fs::read(dir.path().join("beta.bin")).unwrap(), beta);
    }

    #[test]
    fn scan_skips_extra_candidates_when_canonical_files_are_complete() {
        let dir = tempdir().unwrap();
        let data = b"complete-target".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        fs::write(dir.path().join("target.bin"), &data).unwrap();
        fs::write(dir.path().join("aaa-extra.bin"), b"unrelated extra data").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let scan = state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(scan.files_scanned, 1);
        assert_eq!(scan.bytes_scanned, data.len() as u64);
        assert_eq!(verification.total_missing_blocks, 0);
        assert!(state.files_are_canonical_complete());
        assert!(matches!(verification.repairable, Repairability::NotNeeded));
    }

    #[test]
    fn scan_skips_par2_marker_extra_paths() {
        let dir = tempdir().unwrap();
        let data = b"complete-target-hidden-in-par2-path".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        let marker_paths = [
            dir.path().join("extra.par2"),
            dir.path().join("extra.PAR2"),
            dir.path().join("extra.par2.bak"),
        ];
        for path in &marker_paths {
            fs::write(path, &data).unwrap();
        }

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.extra_paths.extend(marker_paths.iter().cloned());
        let scan = state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(scan.files_scanned, 0);
        assert_eq!(verification.total_missing_blocks, state.blocks.len() as u32);
        assert!(state.blocks.iter().all(|block| block.location.is_none()));
    }

    #[test]
    fn scan_ignores_zero_byte_extra_as_complete_source() {
        let dir = tempdir().unwrap();
        let set = synthetic_set(&[("target.bin", b"")], 4);
        let extra = dir.path().join("renamed-empty.bin");
        fs::write(&extra, []).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.extra_paths.push(extra);
        let scan = state.scan(&options).unwrap();

        assert_eq!(scan.files_scanned, 1);
        assert!(state.files[0].complete_location.is_none());
    }

    #[test]
    fn scan_canonicalizes_explicit_extra_paths_before_deduping() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("base");
        fs::create_dir(&base).unwrap();
        let data = b"complete-target-from-extra".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        let extra = dir.path().join("extra.bin");
        fs::write(&extra, &data).unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();

        let mut state = RepairState::from_set(&base, set).unwrap();
        let mut options = Par2RepairerOptions::new(base, Vec::new());
        options.extra_paths.push(extra.clone());
        options
            .extra_paths
            .push(dir.path().join("subdir").join("..").join("extra.bin"));
        let scan = state.scan(&options).unwrap();
        let verification = state.verification_result();
        let canonical_extra = canonical_extra_path(&extra);

        assert_eq!(scan.files_scanned, 1);
        assert_eq!(verification.total_missing_blocks, 0);
        assert_eq!(
            state.blocks[0]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(canonical_extra.as_path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_follow_symlinked_extra_directories() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("base");
        let outside = dir.path().join("outside");
        fs::create_dir(&base).unwrap();
        fs::create_dir(&outside).unwrap();

        let data = b"outside-complete-target".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        fs::write(outside.join("candidate.bin"), &data).unwrap();
        symlink(&outside, base.join("linked-outside")).unwrap();

        let mut state = RepairState::from_set(&base, set).unwrap();
        let options = Par2RepairerOptions::new(base.clone(), Vec::new());
        let scan = state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(scan.files_scanned, 0);
        assert_eq!(verification.total_missing_blocks, state.blocks.len() as u32);
        assert!(state.blocks.iter().all(|block| block.location.is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn scan_does_not_follow_explicit_symlinked_extra_files() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let base = dir.path().join("base");
        fs::create_dir(&base).unwrap();
        let data = b"symlinked-complete-target".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        let outside = dir.path().join("outside.bin");
        let linked = base.join("linked-extra.bin");
        fs::write(&outside, &data).unwrap();
        symlink(&outside, &linked).unwrap();

        let mut state = RepairState::from_set(&base, set).unwrap();
        let mut options = Par2RepairerOptions::new(base, Vec::new());
        options.extra_paths.push(linked);
        let scan = state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(scan.files_scanned, 0);
        assert_eq!(verification.total_missing_blocks, state.blocks.len() as u32);
        assert!(state.blocks.iter().all(|block| block.location.is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn scan_skips_unreadable_extra_directories() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let base = dir.path().join("base");
        let closed = base.join("closed");
        fs::create_dir_all(&closed).unwrap();

        let data = b"visible-complete-target".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 4);
        let visible = base.join("candidate.bin");
        fs::write(&visible, &data).unwrap();

        let original_perms = fs::metadata(&closed).unwrap().permissions();
        let mut closed_perms = original_perms.clone();
        closed_perms.set_mode(0o0);
        fs::set_permissions(&closed, closed_perms).unwrap();

        let mut state = RepairState::from_set(&base, set).unwrap();
        let options = Par2RepairerOptions::new(base.clone(), Vec::new());
        let scan = state.scan(&options);

        fs::set_permissions(&closed, original_perms).unwrap();

        let scan = scan.unwrap();
        assert_eq!(scan.files_scanned, 1);
        assert_eq!(
            state.blocks[0]
                .location
                .as_ref()
                .and_then(|location| location.path()),
            Some(visible.as_path())
        );
    }

    #[test]
    fn duplicate_basenames_in_different_directories_stay_distinct() {
        let dir = tempdir().unwrap();
        let first = b"first---payload".to_vec();
        let second = b"second--payload".to_vec();
        let set = synthetic_set(
            &[
                ("season1/episode.mkv", &first),
                ("season2/episode.mkv", &second),
            ],
            8,
        );
        fs::create_dir_all(dir.path().join("season1")).unwrap();
        fs::create_dir_all(dir.path().join("season2")).unwrap();
        fs::write(dir.path().join("season1/episode.mkv"), &first).unwrap();
        fs::write(dir.path().join("season2/episode.mkv"), &second).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert!(state.files_are_canonical_complete());
        assert!(matches!(verification.repairable, Repairability::NotNeeded));
    }

    #[test]
    fn recoverable_file_without_ifsc_verifies_by_full_hash() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        set.slice_checksums.clear();
        fs::write(dir.path().join("target.bin"), &data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Complete)
        ));
        assert!(matches!(verification.repairable, Repairability::NotNeeded));
    }

    #[test]
    fn large_recoverable_file_without_ifsc_does_not_skip_full_hash() {
        let dir = tempdir().unwrap();
        let data = (0..CANONICAL_COMPLETE_HASH_SKIP_BYTES + 17)
            .map(|idx| (idx % 251) as u8)
            .collect::<Vec<_>>();
        let mut set = synthetic_set(&[("target.bin", &data)], 64);
        set.slice_checksums.clear();
        fs::write(dir.path().join("target.bin"), &data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.files[0].block_count, 0);
        assert_eq!(verification.total_missing_blocks, 0);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Complete)
        ));
        assert!(matches!(verification.repairable, Repairability::NotNeeded));
    }

    #[test]
    fn recoverable_file_without_ifsc_rejects_wrong_existing_target() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        set.slice_checksums.clear();
        fs::write(dir.path().join("target.bin"), b"ccccdddd").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.files[0].block_count, 0);
        assert_eq!(verification.total_missing_blocks, 2);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Damaged(2))
        ));
        assert!(matches!(
            verification.repairable,
            Repairability::Insufficient { .. }
        ));
    }

    #[test]
    fn recoverable_file_without_ifsc_is_repairable_with_enough_parity() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        set.slice_checksums.clear();
        for exponent in 0..2u32 {
            set.recovery_slices.insert(
                exponent,
                crate::par2_set::RecoverySlice {
                    exponent,
                    data: bytes::Bytes::from(vec![0u8; 4]).into(),
                },
            );
        }
        fs::write(dir.path().join("target.bin"), b"ccccdddd").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.files[0].block_count, 0);
        assert_eq!(verification.total_missing_blocks, 2);
        assert!(matches!(
            verification.repairable,
            Repairability::Repairable {
                blocks_needed: 2,
                blocks_available: 2
            }
        ));
    }

    #[test]
    fn recoverable_file_with_invalid_ifsc_stays_visible_but_unrepairable() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        let file_id = set.recovery_file_ids[0];
        set.slice_checksums.get_mut(&file_id).unwrap().pop();

        let state = RepairState::from_set(dir.path(), set).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.files[0].block_count, 0);
        assert_eq!(verification.total_missing_blocks, 2);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Missing)
        ));
        assert!(matches!(
            verification.repairable,
            Repairability::Insufficient { .. }
        ));
    }

    #[test]
    fn recoverable_file_with_invalid_ifsc_verifies_by_full_hash() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        let file_id = set.recovery_file_ids[0];
        set.slice_checksums.get_mut(&file_id).unwrap().pop();
        fs::write(dir.path().join("target.bin"), &data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.files[0].block_count, 0);
        assert_eq!(verification.total_missing_blocks, 0);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Complete)
        ));
        assert!(matches!(verification.repairable, Repairability::NotNeeded));
    }

    #[test]
    fn recoverable_file_without_description_is_discarded() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        let file_id = set.recovery_file_ids[0];
        set.files.remove(&file_id);
        set.slice_checksums.remove(&file_id);

        let state = RepairState::from_set(dir.path(), set).unwrap();
        let verification = state.verification_result();

        assert_eq!(state.inconsistent_packets, 1);
        assert_eq!(state.discarded_recoverable_files, 1);
        assert!(state.files.is_empty());
        assert_eq!(verification.files.len(), 0);
        assert_eq!(verification.total_missing_blocks, 0);
        assert!(matches!(
            verification.repairable,
            Repairability::Insufficient { .. }
        ));
        assert!(!state.files_are_canonical_complete());
    }

    #[test]
    fn recovery_packet_with_wrong_size_is_discarded_from_capacity() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        set.recovery_slices.insert(
            0,
            crate::par2_set::RecoverySlice {
                exponent: 0,
                data: crate::packet::recovery::RecoverySliceData::InMemory(
                    bytes::Bytes::from_static(b"bad"),
                ),
            },
        );

        let state = RepairState::from_set(dir.path(), set).unwrap();

        assert_eq!(state.discarded_recovery_blocks, 1);
        assert_eq!(state.set.recovery_block_count(), 0);
    }

    #[test]
    fn recoverable_file_without_ifsc_can_be_copy_only_adopted() {
        let dir = tempdir().unwrap();
        let data = b"aaaabbbb".to_vec();
        let mut set = synthetic_set(&[("target.bin", &data)], 4);
        set.slice_checksums.clear();
        fs::write(dir.path().join("renamed.bin"), &data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        assert!(matches!(
            verification.files.first().map(|file| &file.status),
            Some(FileStatus::Renamed(_))
        ));
        assert!(matches!(
            verification.repairable,
            Repairability::Repairable {
                blocks_needed: 0,
                ..
            }
        ));

        let repair = state.repair(&options, &verification).unwrap();
        state.install_repaired_files(&repair, &options).unwrap();

        assert_eq!(fs::read(dir.path().join("target.bin")).unwrap(), data);
    }

    #[test]
    fn install_repaired_files_does_not_replace_a_directory() {
        let dir = tempdir().unwrap();
        let data = b"target--target--".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        let extra = dir.path().join("target.extra");
        let target = dir.path().join("target.bin");
        fs::write(&extra, &data).unwrap();
        fs::create_dir(&target).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.extra_paths = vec![extra.clone()];
        state.scan(&options).unwrap();
        let verification = state.verification_result();
        let repair = state.repair(&options, &verification).unwrap();
        let error = state
            .install_repaired_files(&repair, &options)
            .expect_err("a repair must not replace an existing directory");

        assert!(matches!(error, Par2Error::Io(_)));
        assert!(target.is_dir());
        assert_eq!(fs::read(extra).unwrap(), data);
    }

    #[cfg(unix)]
    #[test]
    fn install_repaired_files_rolls_back_previous_targets_on_later_error() {
        let dir = tempdir().unwrap();
        let first = b"first---first---".to_vec();
        let second = b"second--second--".to_vec();
        let first_damaged = b"damaged-first---".to_vec();
        let set = synthetic_set(&[("first.bin", &first), ("second.bin", &second)], 8);
        let first_extra = dir.path().join("first.extra");
        let second_extra = dir.path().join("second.extra");
        let dangling_target = dir.path().join("missing-link-target.bin");

        fs::write(dir.path().join("first.bin"), &first_damaged).unwrap();
        fs::write(&first_extra, &first).unwrap();
        fs::write(&second_extra, &second).unwrap();
        std::os::unix::fs::symlink(&dangling_target, dir.path().join("second.bin")).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let mut options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        options.extra_paths = vec![first_extra, second_extra];
        state.scan(&options).unwrap();
        let verification = state.verification_result();

        assert_eq!(verification.total_missing_blocks, 0);
        let repair = state.repair(&options, &verification).unwrap();
        let error = state
            .install_repaired_files(&repair, &options)
            .expect_err("dangling second symlink target should fail install");

        assert!(matches!(error, Par2Error::Io(_)));
        assert_eq!(
            fs::read(dir.path().join("first.bin")).unwrap(),
            first_damaged
        );
        assert!(
            fs::symlink_metadata(dir.path().join("second.bin"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".weaver-par2-backup."))
        );
    }

    #[test]
    fn short_block_scan_matches_canonical_offset_with_trailing_garbage() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        fs::write(dir.path().join("target.bin"), b"ABCDEFGH12345JUNK").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();

        let file = state
            .files
            .iter()
            .find(|file| file.safe_name == "target.bin")
            .unwrap();
        let last_block = &state.blocks[file.first_block + file.block_count - 1];
        let location = last_block.location.as_ref().unwrap();
        assert_eq!(
            location.path(),
            Some(dir.path().join("target.bin").as_path())
        );
        assert_eq!(location.offset, 8);
    }

    #[test]
    fn short_block_scan_matches_shifted_extra_file_data() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        fs::write(dir.path().join("interior.bin"), b"xxxx12345yyyy").unwrap();
        fs::write(dir.path().join("tail.bin"), b"zzzz12345").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        state.scan(&options).unwrap();

        let file = state
            .files
            .iter()
            .find(|file| file.safe_name == "target.bin")
            .unwrap();
        let last_block = &state.blocks[file.first_block + file.block_count - 1];
        let location = last_block.location.as_ref().unwrap();
        assert_eq!(
            location.path(),
            Some(dir.path().join("interior.bin").as_path())
        );
        assert_eq!(location.offset, 4);
    }

    /// Distinct pseudo-random bytes per seed, so no two synthetic files ever
    /// share block content by accident.
    fn relocation_filler(seed: u64, len: usize) -> Vec<u8> {
        let mut value = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                (value & 0xFF) as u8
            })
            .collect()
    }

    /// A set of `count` files, each `full_slices` whole slices plus a terminal
    /// short slice of `short_len` bytes, written to disk under their canonical
    /// names with one whole slice corrupted so no whole-file hash match can
    /// short-circuit the block scan.
    fn damaged_canonical_short_block_set(
        dir: &Path,
        slice_size: u64,
        full_slices: usize,
        tails: &[usize],
    ) -> Par2FileSet {
        let sources = tails
            .iter()
            .enumerate()
            .map(|(index, tail)| {
                (
                    format!("part{index}.bin"),
                    relocation_filler(index as u64 + 1, full_slices * slice_size as usize + tail),
                )
            })
            .collect::<Vec<_>>();
        let described = sources
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect::<Vec<_>>();
        let set = synthetic_set(&described, slice_size);
        for (name, data) in &sources {
            let mut damaged = data.clone();
            damaged[slice_size as usize..2 * slice_size as usize].fill(0xEE);
            fs::write(dir.join(name), damaged).unwrap();
        }
        set
    }

    fn short_block_of<'a>(state: &'a RepairState, safe_name: &str) -> &'a SourceBlock {
        let file = state
            .files
            .iter()
            .find(|file| file.safe_name == safe_name)
            .expect("described file");
        &state.blocks[file.first_block + file.block_count - 1]
    }

    fn distinct_short_lengths(state: &RepairState) -> Vec<u64> {
        let mut lengths = state
            .hash_table
            .short_blocks
            .iter()
            .map(|index| state.blocks[*index].expected_len)
            .collect::<Vec<_>>();
        lengths.sort_unstable();
        lengths.dedup();
        lengths
    }

    /// The common case, and the shape that used to be quadratic: every file
    /// carries a terminal short block at its own slice offset, so the targeted
    /// checks place all of them and the exhaustive relocation search is never
    /// entered — even though every candidate is damaged elsewhere and so still
    /// holds unexplained bytes.
    #[test]
    fn canonical_terminal_short_blocks_never_enter_the_relocation_search() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let set = damaged_canonical_short_block_set(dir.path(), slice_size, 3, &[21, 21, 21, 21]);

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        assert_eq!(distinct_short_lengths(&state), vec![21]);
        for index in 0..4 {
            let block = short_block_of(&state, &format!("part{index}.bin"));
            let location = block
                .location
                .as_ref()
                .expect("terminal short block placed");
            assert_eq!(location.offset, 3 * slice_size);
            assert_eq!(
                location.path(),
                Some(dir.path().join(format!("part{index}.bin")).as_path())
            );
        }
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 0);
        assert_eq!(diagnostics.short_relocation_windows_stepped, 0);
        assert_eq!(diagnostics.short_relocation_bytes_read, 0);
    }

    /// The measured production shape: many files sharing one short length plus
    /// a final file with a different one. Two distinct lengths used to mean two
    /// whole-file sweeps *per candidate*; now they mean none.
    #[test]
    fn two_distinct_short_lengths_never_enter_the_relocation_search() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let set = damaged_canonical_short_block_set(dir.path(), slice_size, 3, &[21, 21, 21, 37]);

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        assert_eq!(distinct_short_lengths(&state), vec![21, 37]);
        for index in 0..4 {
            let block = short_block_of(&state, &format!("part{index}.bin"));
            let location = block
                .location
                .as_ref()
                .expect("terminal short block placed");
            assert_eq!(location.offset, 3 * slice_size);
        }
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 0);
        assert_eq!(diagnostics.short_relocation_windows_stepped, 0);
    }

    /// A fully obfuscated download: no canonical name exists, so every file is
    /// an extra candidate and every short block is unplaced when the candidate
    /// scan starts. The tail check still places each one at its own slice
    /// offset inside its renamed container, so the merged state closes them all
    /// and no candidate is swept. This is the second-pass blow-up case.
    #[test]
    fn an_all_obfuscated_set_never_enters_the_relocation_search() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let sources = (0..4u64)
            .map(|index| {
                (
                    format!("part{index}.bin"),
                    relocation_filler(index + 1, 3 * slice_size as usize + 21),
                )
            })
            .collect::<Vec<_>>();
        let described = sources
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect::<Vec<_>>();
        let set = synthetic_set(&described, slice_size);
        for (index, (_, data)) in sources.iter().enumerate() {
            let mut damaged = data.clone();
            damaged[slice_size as usize..2 * slice_size as usize].fill(0xEE);
            fs::write(dir.path().join(format!("{index:02}.obfuscated")), damaged).unwrap();
        }

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        for index in 0..4 {
            let block = short_block_of(&state, &format!("part{index}.bin"));
            let location = block
                .location
                .as_ref()
                .expect("terminal short block placed");
            assert_eq!(location.offset, 3 * slice_size);
            assert_eq!(
                location.path(),
                Some(dir.path().join(format!("{index:02}.obfuscated")).as_path())
            );
            assert_eq!(location.kind, BlockLocationKind::Extra);
        }
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 0);
        assert_eq!(diagnostics.short_relocation_windows_stepped, 0);
    }

    /// The structural guard behind every counter assertion above: none of the
    /// per-candidate scan entry points runs the exhaustive relocation search
    /// itself. Each one scans a private pre-merge snapshot, so a search there
    /// cannot see what other candidates already placed — which is exactly how
    /// it became quadratic. A displaced short block must therefore survive the
    /// scan phase unplaced, and be found only when the deferred pass asks.
    #[test]
    fn the_candidate_scan_phase_defers_the_relocation_search() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"ABCDEFGHxx12345JUNK").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);
        let baseline = state.blocks.clone();
        let lookup = SourceFileScanLookup {
            files: &state.files,
            file_index_by_id: &state.file_index_by_id,
        };
        let target_file = state
            .files
            .iter()
            .find(|file| file.safe_path == candidate)
            .expect("described file");

        let mut generic = ScanBlockState::new(&baseline);
        scanner
            .scan_file_with_state_options(
                &candidate,
                BlockLocationKind::Canonical,
                &state.files,
                &state.file_index_by_id,
                &mut generic,
                ScanSkipOptions::disabled(),
            )
            .unwrap();
        let mut ordered = ScanBlockState::new(&baseline);
        scanner
            .scan_file_ordered_canonical_state(
                &candidate,
                BlockLocationKind::Canonical,
                lookup,
                target_file,
                &mut ordered,
                ScanSkipOptions::disabled(),
                true,
                DEFAULT_REPAIR_MEMORY_LIMIT,
                None,
                &[],
            )
            .unwrap();
        let mut mapped = ScanBlockState::new(&baseline);
        scanner
            .scan_file_mmap_with_state_options(
                &candidate,
                BlockLocationKind::Canonical,
                &state.files,
                &state.file_index_by_id,
                &mut mapped,
                ScanSkipOptions::disabled(),
            )
            .unwrap();

        for scanned in [&generic, &ordered, &mapped] {
            assert!(scanned.location(0).is_some(), "aligned block still placed");
            assert!(
                scanned.location(1).is_none(),
                "scan phase must not relocate short blocks"
            );
        }

        let stats = scanner
            .relocate_open_short_blocks_in(&candidate, BlockLocationKind::Canonical, &mut generic)
            .unwrap();

        assert_eq!(stats.blocks_placed, 1);
        assert!(stats.windows_stepped > 0);
        assert!(stats.bytes_read > 0);
        assert_eq!(
            generic.location(1).map(|location| location.offset),
            Some(10)
        );
    }

    /// Scanning only ever produces path locations, so an access-backed hold —
    /// evidence no scan could have made — must survive a scan match rather
    /// than lose to one. The relocation sweep is the one recording site that
    /// could break that: "open" means only that a hold is not at the block's
    /// own slice offset, and an access-backed hold at any other offset is
    /// open. The sweep must decline it even with matching bytes in hand.
    #[test]
    fn relocation_never_displaces_an_access_backed_incumbent() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        let candidate = dir.path().join("target.bin");
        fs::write(&candidate, b"ABCDEFGHxx12345JUNK").unwrap();
        let state = RepairState::from_set(dir.path(), set).unwrap();
        let scanner = RollingBlockScanner::new(&state.hash_table, state.set.slice_size);

        let mut baseline = state.blocks.clone();
        let held = BlockLocation {
            source: SourceLocation::Access(baseline[1].file_id),
            offset: 3,
            len: baseline[1].expected_len,
            kind: BlockLocationKind::Canonical,
        };
        assert_ne!(
            held.offset,
            u64::from(baseline[1].local_index) * state.set.slice_size,
            "the hold must not be at the block's own slice offset"
        );
        baseline[1].location = Some(held.clone());

        let mut blocks = ScanBlockState::new(&baseline);
        assert!(
            open_short_blocks(&state.hash_table, &blocks, state.set.slice_size)[1],
            "a hold away from the block's slice offset leaves it open"
        );

        let stats = scanner
            .relocate_open_short_blocks_in(&candidate, BlockLocationKind::Canonical, &mut blocks)
            .unwrap();

        assert!(
            stats.windows_stepped > 0,
            "the candidate carrying the matching bytes really was swept"
        );
        assert_eq!(stats.blocks_placed, 0);
        assert_eq!(blocks.location(1), Some(&held));
    }

    /// The regression a plain "canonical candidates skip the search" gate would
    /// cause: the short block really is displaced inside its own canonically
    /// named file, so neither the owner-offset check nor the tail check reaches
    /// it and only the deferred search can.
    #[test]
    fn a_shifted_short_block_inside_a_canonical_file_is_still_found() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        fs::write(dir.path().join("target.bin"), b"ABCDEFGHxx12345JUNK").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        let location = short_block_of(&state, "target.bin")
            .location
            .as_ref()
            .expect("displaced short block placed");
        assert_eq!(
            location.path(),
            Some(dir.path().join("target.bin").as_path())
        );
        assert_eq!(location.offset, 10);
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 1);
        assert_eq!(diagnostics.short_relocation_blocks_placed, 1);
        assert!(diagnostics.short_relocation_windows_stepped > 0);
        assert!(diagnostics.short_relocation_bytes_read > 0);
    }

    /// The same displacement in an obfuscated extra file: the owning file is
    /// gone and the copy carries a trailing suffix, so the short block sits at
    /// neither the owner offset nor the candidate tail.
    #[test]
    fn a_shifted_short_block_inside_an_extra_file_is_still_found() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        fs::write(dir.path().join("obfuscated.dat"), b"xxABCDEFGH12345TRAILER").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        let location = short_block_of(&state, "target.bin")
            .location
            .as_ref()
            .expect("displaced short block placed");
        assert_eq!(
            location.path(),
            Some(dir.path().join("obfuscated.dat").as_path())
        );
        assert_eq!(location.offset, 10);
        assert_eq!(location.kind, BlockLocationKind::Extra);
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 1);
        assert_eq!(diagnostics.short_relocation_blocks_placed, 1);
    }

    /// Two equally valid copies: the search runs in candidate order and stops
    /// as soon as the block is settled, so the first candidate wins and the
    /// second is never swept.
    #[test]
    fn relocation_settles_on_the_first_candidate_that_carries_the_block() {
        let dir = tempdir().unwrap();
        let data = b"ABCDEFGH12345".to_vec();
        let set = synthetic_set(&[("target.bin", &data)], 8);
        fs::write(dir.path().join("aaa.dat"), b"ABCDEFGH12345TRAILER").unwrap();
        fs::write(dir.path().join("zzz.dat"), b"ABCDEFGH12345TRAILER").unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        let location = short_block_of(&state, "target.bin")
            .location
            .as_ref()
            .expect("displaced short block placed");
        assert_eq!(location.path(), Some(dir.path().join("aaa.dat").as_path()));
        assert_eq!(location.offset, 8);
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 1);
    }

    /// A short block whose owner is missing outright stays unplaced, and the
    /// one candidate the pass could have swept is skipped because the merged
    /// state already accounts for every byte of it. This is the guard: an
    /// unresolvable short block must not turn intact candidates into work.
    #[test]
    fn an_explained_candidate_is_never_swept_for_a_missing_short_block() {
        let dir = tempdir().unwrap();
        // Large enough that the canonical whole-file hash check is skipped, so
        // the intact file really does reach the block scan and become a
        // relocation target rather than an early complete-file match.
        let slice_size = 256 * 1024u64;
        let present = relocation_filler(1, 4 * slice_size as usize + 1000);
        let absent = relocation_filler(2, slice_size as usize + 77);
        let set = synthetic_set(
            &[("present.bin", &present), ("absent.bin", &absent)],
            slice_size,
        );
        fs::write(dir.path().join("present.bin"), &present).unwrap();

        let mut state = RepairState::from_set(dir.path(), set).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();

        assert_eq!(
            short_block_of(&state, "present.bin")
                .location
                .as_ref()
                .map(|location| location.offset),
            Some(4 * slice_size)
        );
        assert!(short_block_of(&state, "absent.bin").location.is_none());
        assert_eq!(diagnostics.short_relocation_candidates_scanned, 0);
        assert_eq!(diagnostics.short_relocation_candidates_skipped, 1);
        assert_eq!(diagnostics.short_relocation_windows_stepped, 0);
    }

    #[test]
    fn inventory_discards_conflicting_recovery_only_packets() {
        let dir = tempdir().unwrap();
        let main_body = {
            let mut body = Vec::new();
            body.extend_from_slice(&4u64.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body
        };
        let active_set_id = checksum::md5(&main_body);
        fs::write(
            dir.path().join("active.par2"),
            make_full_packet(crate::packet::header::TYPE_MAIN, &main_body, active_set_id),
        )
        .unwrap();

        let mut recovery_body = Vec::new();
        recovery_body.extend_from_slice(&0u32.to_le_bytes());
        recovery_body.extend_from_slice(&[0xAA; 4]);
        let conflicting_recovery = dir.path().join("other.vol00+01.par2");
        fs::write(
            &conflicting_recovery,
            make_full_packet(
                crate::packet::header::TYPE_RECOVERY,
                &recovery_body,
                [9; 16],
            ),
        )
        .unwrap();

        let mut options = Par2RepairerOptions::new(
            dir.path().to_path_buf(),
            vec![dir.path().join("active.par2")],
        );
        options.recovery_paths.push(conflicting_recovery);
        let repairer = Par2Repairer::new(options);
        let inventory = repairer.load_inventory().unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 0);
        assert_eq!(inventory.diagnostics.conflicting_packets, 1);
    }

    #[test]
    fn inventory_counts_duplicate_packets_without_changing_first_wins() {
        let dir = tempdir().unwrap();
        let main_body = {
            let mut body = Vec::new();
            body.extend_from_slice(&4u64.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body
        };
        let active_set_id = checksum::md5(&main_body);
        let main_packet =
            make_full_packet(crate::packet::header::TYPE_MAIN, &main_body, active_set_id);
        let mut par2_file = Vec::new();
        par2_file.extend_from_slice(&main_packet);
        par2_file.extend_from_slice(&main_packet);
        fs::write(dir.path().join("active.par2"), par2_file).unwrap();

        let repairer = Par2Repairer::new(Par2RepairerOptions::new(
            dir.path().to_path_buf(),
            vec![dir.path().join("active.par2")],
        ));
        let inventory = repairer.load_inventory().unwrap();

        assert_eq!(inventory.diagnostics.packets_loaded, 2);
        assert_eq!(inventory.diagnostics.duplicate_packets, 1);
        assert_eq!(inventory.set.recovery_file_ids.len(), 0);
    }

    /// One Main packet with `slice_size`, no files.
    fn empty_main_packet(slice_size: u64) -> (Vec<u8>, [u8; 16]) {
        let mut body = Vec::new();
        body.extend_from_slice(&slice_size.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let rsid = checksum::md5(&body);
        (
            make_full_packet(crate::packet::header::TYPE_MAIN, &body, rsid),
            rsid,
        )
    }

    fn recovery_packet(exponent: u32, payload: &[u8], rsid: [u8; 16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&exponent.to_le_bytes());
        body.extend_from_slice(payload);
        make_full_packet(crate::packet::header::TYPE_RECOVERY, &body, rsid)
    }

    /// A `.par2` file holding one Main packet followed by `count` minimal
    /// recovery packets with consecutive exponents.
    fn write_recovery_run(path: &Path, exponents: std::ops::Range<u32>) -> [u8; 16] {
        let (main, rsid) = empty_main_packet(4);
        let mut stream = main;
        stream.reserve(exponents.len() * 72);
        for exponent in exponents {
            stream.extend_from_slice(&recovery_packet(exponent, &[0xAB; 4], rsid));
        }
        fs::write(path, &stream).unwrap();
        rsid
    }

    fn repairer_for(dir: &Path, par2: Vec<PathBuf>) -> Par2RepairerOptions {
        Par2RepairerOptions::new(dir.to_path_buf(), par2)
    }

    /// The reported amplification: a ~4.5 MiB file of 65,537 minimal recovery
    /// packets. It must load under the default budget, keep exactly the usable
    /// exponents, and refuse the one packet whose exponent is outside the GF
    /// domain — without ever materialising the packet stream.
    #[test]
    fn inventory_loads_a_sixty_five_thousand_packet_recovery_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("amplify.par2");
        // 0..=65_535 are usable; 65_536 is one past the domain, which is what
        // makes this 65,537 packets rather than 65,536.
        write_recovery_run(&path, 0..65_537);
        assert!(fs::metadata(&path).unwrap().len() > 4 * 1024 * 1024);

        let inventory = Par2Repairer::new(repairer_for(dir.path(), vec![path]))
            .load_inventory()
            .unwrap();

        assert_eq!(
            inventory.set.recovery_block_count(),
            crate::packet::RECOVERY_EXPONENT_DOMAIN as u32
        );
        assert!(
            inventory
                .set
                .recovery_slices
                .contains_key(&crate::packet::MAX_RECOVERY_EXPONENT)
        );
        assert!(
            !inventory
                .set
                .recovery_slices
                .contains_key(&(crate::packet::MAX_RECOVERY_EXPONENT + 1))
        );
        // Main plus every packet the file held, out-of-domain one included.
        assert_eq!(inventory.diagnostics.packets_loaded, 65_538);
        assert_eq!(inventory.diagnostics.duplicate_packets, 0);
        assert_eq!(inventory.diagnostics.conflicting_packets, 0);
    }

    /// The same file, one packet over a configured retained-packet limit.
    #[test]
    fn inventory_refuses_one_packet_past_the_configured_retained_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("run.par2");
        write_recovery_run(&path, 0..64);

        // Main plus 64 recovery blocks is 65 retained packets.
        let mut options = repairer_for(dir.path(), vec![path.clone()]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(65);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();
        assert_eq!(inventory.set.recovery_block_count(), 64);

        let mut options = repairer_for(dir.path(), vec![path]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(64);
        let error = Par2Repairer::new(options).load_inventory().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    /// Two `.par2` inputs that each fit on their own but do not fit together.
    /// One budget spans the load, so the second file is what trips it.
    #[test]
    fn inventory_budget_is_shared_across_every_par2_input() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("first.par2");
        let second = dir.path().join("second.par2");
        write_recovery_run(&first, 0..32);
        write_recovery_run(&second, 32..64);

        let limits = PacketScanLimits::default().with_max_retained_packets(40);
        let mut options = repairer_for(dir.path(), vec![first.clone()]);
        options.packet_scan_limits = limits;
        assert_eq!(
            Par2Repairer::new(options)
                .load_inventory()
                .unwrap()
                .set
                .recovery_block_count(),
            32
        );

        let mut options = repairer_for(dir.path(), vec![first.clone(), second.clone()]);
        options.packet_scan_limits = limits;
        let error = Par2Repairer::new(options).load_inventory().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));

        // No partial inventory is reachable: the load either returns a complete
        // Par2FileSet or it returns an error carrying none.
        let mut options = repairer_for(dir.path(), vec![first, second]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(65);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();
        assert_eq!(inventory.set.recovery_block_count(), 64);
    }

    /// Duplicates are scan work, not retention: a set replicated many times
    /// over must still fit a budget sized for its logical inventory.
    #[test]
    fn inventory_duplicates_spend_work_budget_but_not_retention_budget() {
        let dir = tempdir().unwrap();
        let (main, rsid) = empty_main_packet(4);
        let recovery = recovery_packet(0, &[0xAB; 4], rsid);
        let mut stream = main.clone();
        for _ in 0..500 {
            stream.extend_from_slice(&main);
            stream.extend_from_slice(&recovery);
        }
        let path = dir.path().join("redundant.par2");
        fs::write(&path, &stream).unwrap();

        let mut options = repairer_for(dir.path(), vec![path]);
        // Exactly the logical inventory: one Main and one recovery block.
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(2);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 1);
        assert_eq!(inventory.diagnostics.packets_loaded, 1_001);
        assert_eq!(inventory.diagnostics.duplicate_packets, 999);
    }

    /// The examined meter counts packets the inventory never keeps, so a stream
    /// that is nothing but redundancy still has a ceiling.
    #[test]
    fn inventory_examined_meter_bounds_pure_redundancy() {
        let dir = tempdir().unwrap();
        let (main, rsid) = empty_main_packet(4);
        let recovery = recovery_packet(0, &[0xAB; 4], rsid);
        let mut stream = main;
        for _ in 0..64 {
            stream.extend_from_slice(&recovery);
        }
        let path = dir.path().join("redundant.par2");
        fs::write(&path, &stream).unwrap();

        let mut options = repairer_for(dir.path(), vec![path]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_examined_packets(16);
        let error = Par2Repairer::new(options).load_inventory().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    /// An input with no Main packet anywhere leaves every packet staged. The
    /// stage still has to be flushed so the load reports the real reason.
    #[test]
    fn inventory_without_a_main_packet_reports_the_missing_main() {
        let dir = tempdir().unwrap();
        let mut stream = Vec::new();
        for exponent in 0..8u32 {
            stream.extend_from_slice(&recovery_packet(exponent, &[0xAB; 4], [0x5C; 16]));
        }
        let path = dir.path().join("mainless.par2");
        fs::write(&path, &stream).unwrap();

        let error = Par2Repairer::new(repairer_for(dir.path(), vec![path]))
            .load_inventory()
            .unwrap_err();
        assert!(matches!(error, Par2Error::NoMainPacket));
    }

    /// Packets that precede the first Main packet cannot be filtered yet, so
    /// they are staged. Staging is budgeted like anything else.
    #[test]
    fn packets_staged_before_the_first_main_are_charged_to_the_budget() {
        let dir = tempdir().unwrap();
        let (main, rsid) = empty_main_packet(4);
        // Recovery packets first, then the Main packet: the layout par2cmdline
        // actually writes for a volume file.
        let mut stream = Vec::new();
        for exponent in 0..32u32 {
            stream.extend_from_slice(&recovery_packet(exponent, &[0xAB; 4], rsid));
        }
        stream.extend_from_slice(&main);
        let path = dir.path().join("recovery-first.par2");
        fs::write(&path, &stream).unwrap();

        let mut options = repairer_for(dir.path(), vec![path.clone()]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(33);
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();
        assert_eq!(inventory.set.recovery_block_count(), 32);
        assert_eq!(inventory.diagnostics.packets_loaded, 33);

        let mut options = repairer_for(dir.path(), vec![path]);
        options.packet_scan_limits = PacketScanLimits::default().with_max_retained_packets(16);
        let error = Par2Repairer::new(options).load_inventory().unwrap_err();
        assert!(matches!(error, Par2Error::ResourceLimitExceeded { .. }));
    }

    /// Every packet of a conflicting volume is counted and discarded, and the
    /// volume contributes nothing, so it is not offered for purge.
    #[test]
    fn inventory_discards_a_whole_conflicting_volume_and_leaves_it_unpurged() {
        let dir = tempdir().unwrap();
        let active = dir.path().join("active.par2");
        write_recovery_run(&active, 0..4);

        let mut foreign_body = Vec::new();
        foreign_body.extend_from_slice(&8u64.to_le_bytes());
        foreign_body.extend_from_slice(&0u32.to_le_bytes());
        let foreign_rsid = checksum::md5(&foreign_body);
        let mut foreign = make_full_packet(
            crate::packet::header::TYPE_MAIN,
            &foreign_body,
            foreign_rsid,
        );
        for exponent in 0..4u32 {
            foreign.extend_from_slice(&recovery_packet(exponent, &[0xCD; 8], foreign_rsid));
        }
        let foreign_path = dir.path().join("foreign.par2");
        fs::write(&foreign_path, &foreign).unwrap();

        let mut options = repairer_for(dir.path(), vec![active.clone()]);
        options.recovery_paths.push(foreign_path.clone());
        let inventory = Par2Repairer::new(options).load_inventory().unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 4);
        assert_eq!(inventory.diagnostics.conflicting_packets, 5);
        assert_eq!(inventory.diagnostics.packets_loaded, 5);
        // The conflicting volume is a `.par2` path, so it stays purgeable by
        // name exactly as before, while contributing nothing.
        assert_eq!(inventory.purge_paths, vec![active, foreign_path]);
    }

    #[test]
    fn inventory_scanning_stops_when_cancelled() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("run.par2");
        write_recovery_run(&path, 0..256);

        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut options = repairer_for(dir.path(), vec![path]);
        options.cancel = Some(cancel);
        let error = Par2Repairer::new(options).load_inventory().unwrap_err();
        assert!(matches!(error, Par2Error::Cancelled));
    }

    /// Cancellation asserted after the last packet is read still has to be
    /// observed, before the set is assembled and handed back.
    #[test]
    fn inventory_construction_observes_cancellation_after_the_last_packet() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("run.par2");
        write_recovery_run(&path, 0..8);

        let cancel = CancellationToken::new();
        let budget =
            PacketScanBudget::with_cancellation(PacketScanLimits::default(), Some(cancel.clone()));
        let mut loader = InventoryLoader::new(&budget);
        loader.begin_file(path.clone(), true);
        scan_packets_from_path_bounded(&path, &budget, &mut loader).unwrap();
        loader.end_file(false);

        cancel.cancel();
        assert!(matches!(loader.finish(), Err(Par2Error::Cancelled)));
    }

    /// The inventory keeps recovery payloads file-backed, and the deferred
    /// packet-hash check still works against the interned volume path.
    #[test]
    fn inventory_recovery_payloads_stay_file_backed_and_still_validate() {
        let dir = tempdir().unwrap();
        let (main, rsid) = empty_main_packet(8);
        let mut stream = main;
        for exponent in 0..4u32 {
            stream.extend_from_slice(&recovery_packet(exponent, &[0xC3; 8], rsid));
        }
        let path = dir.path().join("volume.par2");
        fs::write(&path, &stream).unwrap();

        let inventory = Par2Repairer::new(repairer_for(dir.path(), vec![path]))
            .load_inventory()
            .unwrap();

        assert_eq!(inventory.set.recovery_block_count(), 4);
        for (exponent, slice) in &inventory.set.recovery_slices {
            assert!(slice.data.as_bytes().is_none(), "payload stays on disk");
            assert_eq!(slice.data.to_vec().unwrap(), vec![0xC3; 8]);
            assert!(slice.data.validate_packet_hash(&rsid, *exponent).unwrap());
        }
    }

    #[cfg(feature = "slow-tests")]
    #[test]
    fn crate_fixture_missing_volume_repairs_and_reverifies_clean() {
        let temp = copy_fixture_dir("rar5_lz_plain");
        fs::remove_file(temp.path().join("fixture_rar5_lz_plain.part4.rar")).unwrap();

        let par2_paths = collect_paths(temp.path(), "fixture_rar5_lz_plain_repair", "par2");
        let mut preview = Par2RepairerOptions::new(temp.path().to_path_buf(), par2_paths.clone());
        preview.repair = false;
        let preview_outcome = Par2Repairer::new(preview).verify_or_repair().unwrap();
        assert_eq!(preview_outcome.status, Par2RepairStatus::RepairPossible);
        assert!(preview_outcome.verification.total_missing_blocks > 0);

        let outcome = Par2Repairer::new(Par2RepairerOptions::new(
            temp.path().to_path_buf(),
            par2_paths.clone(),
        ))
        .verify_or_repair()
        .unwrap();

        assert_eq!(outcome.status, Par2RepairStatus::Repaired);
        assert_eq!(outcome.verification.total_missing_blocks, 0);

        let mut reverify = Par2RepairerOptions::new(temp.path().to_path_buf(), par2_paths);
        reverify.repair = false;
        let clean = Par2Repairer::new(reverify).verify_or_repair().unwrap();
        assert_eq!(clean.status, Par2RepairStatus::Verified, "{clean:#?}");
        assert_eq!(clean.verification.total_missing_blocks, 0, "{clean:#?}");
    }

    #[test]
    fn scan_carry_applies_when_disk_unchanged_and_refuses_on_drift() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let set = synthetic_set(&[("data.bin", &file_data)], slice_size);
        fs::write(dir.path().join("data.bin"), &file_data).unwrap();

        let mut state = RepairState::from_set(dir.path(), set.clone()).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();
        let carry = state.scan_carry(&diagnostics);
        let baseline = format!("{:?}", state.verification_result());

        let mut fresh = RepairState::from_set(dir.path(), set.clone()).unwrap();
        let applied = fresh.try_apply_carry(&carry);
        assert!(applied.is_some(), "carry must apply to an unchanged tree");
        assert_eq!(
            format!("{:?}", fresh.verification_result()),
            baseline,
            "carried state must reproduce the scanned verification"
        );

        // Rewriting a file with identical content still changes its mtime;
        // any observed drift must refuse the carry.
        let reference = fs::read(dir.path().join("data.bin")).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        fs::write(dir.path().join("data.bin"), &reference).unwrap();
        let mut drifted = RepairState::from_set(dir.path(), set).unwrap();
        assert!(
            drifted.try_apply_carry(&carry).is_none(),
            "mtime drift must invalidate the carry"
        );
    }

    #[test]
    fn stale_scan_carry_falls_back_to_fresh_scan() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..1024u32).map(|i| ((i * 7 + 3) % 251) as u8).collect();
        let set = synthetic_set(&[("data.bin", &file_data)], slice_size);
        let data_path = dir.path().join("data.bin");

        let mut damaged = file_data.clone();
        damaged[..64].fill(0);
        fs::write(&data_path, &damaged).unwrap();

        let mut analyze = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        analyze.file_set = Some(set.clone());
        analyze.repair = false;
        let (analyze_outcome, carry) = Par2Repairer::new(analyze)
            .verify_or_repair_carrying()
            .unwrap();
        assert!(analyze_outcome.verification.total_missing_blocks > 0);
        let carry = carry.expect("carrying pass returns scan state");

        // The damage is healed out-of-band with the same file length. Some
        // filesystems can leave the stat snapshot indistinguishable, so an
        // execute pass may apply the carry first. It must still fresh-retry
        // before returning stale terminal state.
        fs::write(&data_path, &file_data).unwrap();
        restore_carried_modified_time(&carry, &data_path);
        let mut execute = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        execute.file_set = Some(set);
        execute.repair = true;
        execute.scan_carry = Some(carry);
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();
        assert_eq!(outcome.status, Par2RepairStatus::Verified, "{outcome:#?}");
        assert!(outcome.carry.carry_attempted);
        assert!(outcome.carry.carry_applied);
        assert!(outcome.carry.carry_retried_fresh);
        assert_eq!(
            outcome.carry.carry_retry_reason,
            Some(CarryRetryReason::RepairRequested)
        );
    }

    #[test]
    fn stale_verified_scan_carry_retries_before_reporting_success() {
        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let file_data: Vec<u8> = (0..1024u32).map(|i| ((i * 11 + 5) % 251) as u8).collect();
        let par2_path = write_synthetic_par2_file(
            dir.path(),
            "data.par2",
            &[("data.bin", &file_data)],
            slice_size,
        );
        let data_path = dir.path().join("data.bin");
        fs::write(&data_path, &file_data).unwrap();

        let mut analyze =
            Par2RepairerOptions::new(dir.path().to_path_buf(), vec![par2_path.clone()]);
        analyze.repair = false;
        let (analyze_outcome, carry) = Par2Repairer::new(analyze)
            .verify_or_repair_carrying()
            .unwrap();
        assert_eq!(analyze_outcome.status, Par2RepairStatus::Verified);
        let carry = carry.expect("carrying pass returns scan state");

        let mut damaged = file_data;
        damaged[..64].fill(0);
        fs::write(&data_path, &damaged).unwrap();
        restore_carried_modified_time(&carry, &data_path);

        let mut execute =
            Par2RepairerOptions::new(dir.path().to_path_buf(), vec![par2_path.clone()]);
        execute.repair = true;
        execute.purge = true;
        execute.scan_carry = Some(carry);
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();
        assert_eq!(
            outcome.status,
            Par2RepairStatus::Insufficient,
            "{outcome:#?}"
        );
        assert_eq!(outcome.verification.total_missing_blocks, 1);
        assert!(outcome.carry.carry_attempted);
        assert!(outcome.carry.carry_applied);
        assert!(outcome.carry.carry_retried_fresh);
        assert_eq!(
            outcome.carry.carry_retry_reason,
            Some(CarryRetryReason::RepairRequested)
        );
        assert!(
            par2_path.exists(),
            "speculative carried Verified must not purge PAR2 files before fresh verification fails"
        );
    }

    /// A carried copy-only repair whose source was rewritten to the same
    /// length *and* had its mtime restored is exactly the change a stat
    /// fingerprint cannot see. The pre-mutation gate accepts it — correctly,
    /// on the evidence available to it — and the validated read that a
    /// consumed carry always takes then catches it on the bytes, before
    /// anything is installed. The retry reason therefore names the changed
    /// input rather than the bare repair request.
    #[test]
    fn carried_repair_request_fresh_scans_before_mutation() {
        let dir = tempdir().unwrap();
        let slice_size = 8u64;
        let file_data = b"alpha---beta----".to_vec();
        let set = synthetic_set(&[("target.bin", &file_data)], slice_size);
        let extra_path = dir.path().join("renamed.bin");
        fs::write(&extra_path, &file_data).unwrap();

        let mut analyze = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        analyze.file_set = Some(set.clone());
        analyze.repair = false;
        analyze.extra_paths = vec![extra_path.clone()];
        let (preview, carry) = Par2Repairer::new(analyze)
            .verify_or_repair_carrying()
            .unwrap();
        assert_eq!(preview.status, Par2RepairStatus::RepairPossible);
        assert_eq!(preview.verification.total_missing_blocks, 0);
        let carry = carry.expect("analyze pass carries renamed source state");

        let stale_source = b"wrong---blocks--".to_vec();
        assert_eq!(stale_source.len(), file_data.len());
        fs::write(&extra_path, stale_source).unwrap();
        restore_carried_modified_time(&carry, &canonical_extra_path(&extra_path));

        let mut execute = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        execute.file_set = Some(set);
        execute.extra_paths = vec![extra_path];
        execute.scan_carry = Some(carry);
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

        assert_eq!(
            outcome.status,
            Par2RepairStatus::Insufficient,
            "{outcome:#?}"
        );
        assert!(
            !dir.path().join("target.bin").exists(),
            "stale carried copy-only source must not be installed before a fresh scan"
        );
        assert!(outcome.carry.carry_attempted);
        assert!(outcome.carry.carry_applied);
        assert!(outcome.carry.carry_retried_fresh);
        assert!(!outcome.carry.carry_consumed_for_repair);
        assert_eq!(
            outcome.carry.carry_retry_reason,
            Some(CarryRetryReason::RepairInputChanged)
        );
    }

    /// A small real PAR2 set with real recovery volumes, so repairs against it
    /// are genuine Reed-Solomon reconstructions rather than whole-file copies.
    fn create_recoverable_set(dir: &Path, files: &[(&str, &[u8])]) {
        let sources: Vec<PathBuf> = files
            .iter()
            .map(|(name, bytes)| {
                let path = dir.join(name);
                fs::write(&path, bytes).unwrap();
                path
            })
            .collect();
        let mut options = crate::create::Par2CreatorOptions::with_output(
            dir.join("set"),
            Some(dir.to_path_buf()),
            sources,
        );
        options.block_sizing = crate::create::BlockSizing::Bytes(64);
        options.recovery_amount = crate::create::RecoveryAmount::Count(16);
        let creator = crate::create::Par2Creator::new(options);
        let plan = creator.plan().unwrap();
        creator.create(&plan).unwrap();
    }

    fn par2_paths_in(dir: &Path) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                is_par2_path(&path).then_some(path)
            })
            .collect();
        paths.sort();
        paths
    }

    fn copy_flat_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    fn damage_first_slice(path: &Path) {
        let mut bytes = fs::read(path).unwrap();
        bytes[..64].fill(0);
        fs::write(path, bytes).unwrap();
    }

    fn bump_modified_time(path: &Path) {
        let modified = fs::metadata(path).unwrap().modified().unwrap();
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified + Duration::from_secs(1)))
            .unwrap();
    }

    /// One way a repair input can change, named for assertion messages.
    type InputMutation = (&'static str, fn(&Path));

    /// Every way a repair input can change that a `stat` call can see. Each
    /// entry mutates the file at the given path.
    fn stat_visible_input_mutations() -> Vec<InputMutation> {
        vec![
            ("mtime bump", bump_modified_time),
            ("same-length content change", |path| {
                let len = fs::metadata(path).unwrap().len() as usize;
                fs::write(path, vec![0xA5u8; len]).unwrap();
                // A write's automatic mtime update is not portable enough to
                // make this same-length rewrite stat-visible on its own.
                bump_modified_time(path);
            }),
            ("truncate", |path| {
                let len = fs::metadata(path).unwrap().len();
                fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(len / 2)
                    .unwrap();
            }),
            ("append", |path| {
                let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(&[0x5Au8; 64]).unwrap();
            }),
            ("rename away", |path| {
                fs::rename(path, path.with_file_name("moved-aside.dat")).unwrap();
            }),
            ("delete", |path| {
                fs::remove_file(path).unwrap();
            }),
        ]
    }

    fn scanned_state_with_carry(dir: &Path, set: &Par2FileSet) -> (RepairState, ScanCarry) {
        let mut state = RepairState::from_set(dir, set.clone()).unwrap();
        let options = Par2RepairerOptions::new(dir.to_path_buf(), Vec::new());
        let diagnostics = state.scan(&options).unwrap();
        let carry = state.scan_carry(&diagnostics);
        (state, carry)
    }

    /// The carry exists so the execute pass costs nothing. On an unchanged
    /// tree it must repair on the analysis it was handed rather than reading
    /// the whole set a second time, and the bytes it writes must be exactly
    /// the bytes the two-scan path writes.
    ///
    /// `carry_applied` says this pass installed carried state — which is the
    /// arm that excludes running `scan` at all — and `!carry_retried_fresh`
    /// says no second pass ran either, so between them no scan happened here.
    #[test]
    fn carried_repair_consumes_the_analysis_without_a_second_scan() {
        let alpha: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let beta: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 11) % 241) as u8).collect();

        let carried_dir = tempdir().unwrap();
        let fresh_dir = tempdir().unwrap();
        create_recoverable_set(
            carried_dir.path(),
            &[("alpha.bin", &alpha), ("beta.bin", &beta)],
        );
        copy_flat_dir(carried_dir.path(), fresh_dir.path());
        for dir in [carried_dir.path(), fresh_dir.path()] {
            damage_first_slice(&dir.join("alpha.bin"));
        }

        let par2 = par2_paths_in(carried_dir.path());
        let mut analyze = Par2RepairerOptions::new(carried_dir.path().to_path_buf(), par2.clone());
        analyze.repair = false;
        let (preview, carry) = Par2Repairer::new(analyze)
            .verify_or_repair_carrying()
            .unwrap();
        assert_eq!(preview.status, Par2RepairStatus::RepairPossible);
        assert!(preview.verification.total_missing_blocks > 0);
        assert!(!preview.scan.carried, "the analyze pass scans for real");
        let carry = carry.expect("analyze pass carries scan state");

        let mut execute = Par2RepairerOptions::new(carried_dir.path().to_path_buf(), par2);
        execute.scan_carry = Some(carry);
        let carried_outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

        assert_eq!(
            carried_outcome.status,
            Par2RepairStatus::Repaired,
            "{carried_outcome:#?}"
        );
        assert!(carried_outcome.carry.carry_applied);
        assert!(carried_outcome.carry.carry_consumed_for_repair);
        assert!(
            !carried_outcome.carry.carry_retried_fresh,
            "consuming the carry means no second scan: {carried_outcome:#?}"
        );
        assert_eq!(carried_outcome.carry.carry_retry_reason, None);
        assert!(
            carried_outcome.scan.carried,
            "the reported scan counters belong to the analyze pass"
        );

        let fresh_outcome = Par2Repairer::new(Par2RepairerOptions::new(
            fresh_dir.path().to_path_buf(),
            par2_paths_in(fresh_dir.path()),
        ))
        .verify_or_repair()
        .unwrap();
        assert_eq!(fresh_outcome.status, Par2RepairStatus::Repaired);
        assert!(!fresh_outcome.carry.carry_attempted);

        for (name, original) in [("alpha.bin", &alpha), ("beta.bin", &beta)] {
            let carried_bytes = fs::read(carried_dir.path().join(name)).unwrap();
            let fresh_bytes = fs::read(fresh_dir.path().join(name)).unwrap();
            assert_eq!(carried_bytes, *original, "{name} must be restored");
            assert_eq!(
                carried_bytes, fresh_bytes,
                "{name} must be byte-identical across the carried and fresh repair paths"
            );
        }
    }

    /// A repair input that changed visibly between the two passes must send
    /// the execute pass back to a real scan, and must still repair correctly
    /// from what it finds there. The carry never applies in these cases: the
    /// snapshot check at the top of the pass already refuses, which is why the
    /// outcome records no retry — one pass, one honest scan.
    #[test]
    fn stat_visible_input_change_between_passes_falls_back_to_a_fresh_scan() {
        let alpha: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let beta: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 11) % 241) as u8).collect();

        let master = tempdir().unwrap();
        create_recoverable_set(master.path(), &[("alpha.bin", &alpha), ("beta.bin", &beta)]);

        for (label, mutate) in stat_visible_input_mutations() {
            let dir = tempdir().unwrap();
            copy_flat_dir(master.path(), dir.path());
            damage_first_slice(&dir.path().join("alpha.bin"));

            let par2 = par2_paths_in(dir.path());
            let mut analyze = Par2RepairerOptions::new(dir.path().to_path_buf(), par2.clone());
            analyze.repair = false;
            let (preview, carry) = Par2Repairer::new(analyze)
                .verify_or_repair_carrying()
                .unwrap();
            assert_eq!(preview.status, Par2RepairStatus::RepairPossible, "{label}");
            let carry = carry.expect("analyze pass carries scan state");

            mutate(&dir.path().join("beta.bin"));

            let mut execute = Par2RepairerOptions::new(dir.path().to_path_buf(), par2);
            execute.scan_carry = Some(carry);
            let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

            assert_eq!(
                outcome.status,
                Par2RepairStatus::Repaired,
                "{label} must still repair: {outcome:#?}"
            );
            assert!(outcome.carry.carry_attempted, "{label}");
            assert!(
                !outcome.carry.carry_applied,
                "{label}: visible drift must refuse the carry outright"
            );
            assert!(!outcome.carry.carry_consumed_for_repair, "{label}");
            assert!(
                !outcome.scan.carried,
                "{label}: the pass must report its own scan"
            );
            assert_eq!(
                fs::read(dir.path().join("alpha.bin")).unwrap(),
                alpha,
                "{label}"
            );
            assert_eq!(
                fs::read(dir.path().join("beta.bin")).unwrap(),
                beta,
                "{label}"
            );
        }
    }

    /// The pre-mutation gate itself, exercised directly: it runs immediately
    /// before repair mutates anything, and it is the check that licenses
    /// skipping the scan. Reaching its refusal arms end-to-end is not possible
    /// through the public entry point — the snapshot check at the top of the
    /// pass sees the same drift first — so the arms are pinned here.
    #[test]
    fn carry_repair_gate_refuses_every_stat_visible_change_to_an_input() {
        let file_data: Vec<u8> = (0..1024u32).map(|i| ((i * 3 + 1) % 251) as u8).collect();

        for (label, mutate) in stat_visible_input_mutations() {
            let dir = tempdir().unwrap();
            let data_path = dir.path().join("data.bin");
            fs::write(&data_path, &file_data).unwrap();
            let set = synthetic_set(&[("data.bin", &file_data)], 64);

            let (state, carry) = scanned_state_with_carry(dir.path(), &set);
            assert_eq!(
                state.carry_repair_inputs_unchanged(&carry),
                Ok(()),
                "{label}: an untouched tree must pass the gate"
            );

            mutate(&data_path);
            assert_eq!(
                state.carry_repair_inputs_unchanged(&carry),
                Err(CarryRetryReason::RepairInputChanged),
                "{label} must refuse the carry before mutation"
            );
        }
    }

    /// An access-backed input has no filesystem identity to re-stat, and a
    /// carry records no serving-handle generation, so there is no honest
    /// signal that the bytes behind it are still the ones the scan read. The
    /// gate refuses rather than guessing, whatever the path-backed inputs say.
    #[test]
    fn carry_repair_gate_refuses_an_access_backed_input() {
        let dir = tempdir().unwrap();
        let file_data: Vec<u8> = (0..1024u32).map(|i| ((i * 5 + 9) % 251) as u8).collect();
        fs::write(dir.path().join("data.bin"), &file_data).unwrap();
        let set = synthetic_set(&[("data.bin", &file_data)], 64);

        let (mut state, carry) = scanned_state_with_carry(dir.path(), &set);
        assert_eq!(state.carry_repair_inputs_unchanged(&carry), Ok(()));

        let file_id = state.files[0].file_id;
        let block = state.blocks.last_mut().expect("scanned block");
        block
            .location
            .as_mut()
            .expect("block resolved to the canonical file")
            .source = SourceLocation::Access(file_id);

        assert_eq!(
            state.carry_repair_inputs_unchanged(&carry),
            Err(CarryRetryReason::RepairInputNotFingerprinted)
        );
    }

    /// The whole point of the carry on a real set: the execute pass reads no
    /// source bytes to analyse, repairs on the analysis it was handed, and
    /// still re-verifies clean afterwards.
    #[cfg(feature = "slow-tests")]
    #[test]
    fn carried_scan_execute_repairs_and_reverifies_clean() {
        let temp = copy_fixture_dir("rar5_lz_plain");
        fs::remove_file(temp.path().join("fixture_rar5_lz_plain.part4.rar")).unwrap();
        let par2_paths = collect_paths(temp.path(), "fixture_rar5_lz_plain_repair", "par2");

        let mut analyze = Par2RepairerOptions::new(temp.path().to_path_buf(), par2_paths.clone());
        analyze.repair = false;
        let (preview, carry) = Par2Repairer::new(analyze)
            .verify_or_repair_carrying()
            .unwrap();
        assert_eq!(preview.status, Par2RepairStatus::RepairPossible);
        let carry = carry.expect("analyze pass carries scan state");

        let mut execute = Par2RepairerOptions::new(temp.path().to_path_buf(), par2_paths.clone());
        execute.scan_carry = Some(carry);
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();
        assert_eq!(outcome.status, Par2RepairStatus::Repaired);
        assert_eq!(outcome.verification.total_missing_blocks, 0);
        assert!(outcome.carry.carry_attempted);
        assert!(outcome.carry.carry_applied);
        assert!(
            outcome.carry.carry_consumed_for_repair,
            "an unchanged tree must repair on the carried analysis"
        );
        assert!(
            !outcome.carry.carry_retried_fresh,
            "consuming the carry means no second scan: {outcome:#?}"
        );
        assert_eq!(outcome.carry.carry_retry_reason, None);
        assert!(
            outcome.scan.carried,
            "the reported scan counters belong to the analyze pass"
        );

        let mut reverify = Par2RepairerOptions::new(temp.path().to_path_buf(), par2_paths);
        reverify.repair = false;
        let clean = Par2Repairer::new(reverify).verify_or_repair().unwrap();
        assert_eq!(clean.status, Par2RepairStatus::Verified, "{clean:#?}");
        assert_eq!(clean.verification.total_missing_blocks, 0, "{clean:#?}");
    }

    // --- Externally-constructed carries -----------------------------------

    /// The set the repairer itself would load from `par2_paths`, so a carry
    /// built against it is built against the same layout the repair will use.
    fn loaded_set(dir: &Path, par2_paths: &[PathBuf]) -> Par2FileSet {
        let options = Par2RepairerOptions::new(dir.to_path_buf(), par2_paths.to_vec());
        Par2Repairer::new(options)
            .load_inventory()
            .expect("load PAR2 inventory")
            .set
    }

    /// A host's own verification of `set` under `dir`, plus the stat
    /// fingerprints captured for it — the two inputs
    /// [`ScanCarry::from_verification`] takes.
    ///
    /// The fingerprints are captured after the read, which is the honest
    /// order: a file that changed *during* the read ends up with a fingerprint
    /// that no longer matches what the read saw only if it changed again, and
    /// a file that changed after it is exactly what the gate exists to catch.
    fn host_verification(
        dir: &Path,
        set: &Par2FileSet,
    ) -> (VerificationResult, HashMap<FileId, FileStatFingerprint>) {
        let access = DiskFileAccess::new(dir.to_path_buf(), set);
        let verification = verify::verify_selected_file_ids(set, &access, &set.recovery_file_ids);
        let fingerprints = set
            .recovery_file_ids
            .iter()
            .filter_map(|file_id| {
                let desc = set.files.get(file_id)?;
                let fingerprint = FileStatFingerprint::capture_path(dir.join(&desc.filename))?;
                Some((*file_id, fingerprint))
            })
            .collect();
        (verification, fingerprints)
    }

    fn external_carry(dir: &Path, set: &Par2FileSet) -> ScanCarry {
        let (verification, fingerprints) = host_verification(dir, set);
        ScanCarry::from_verification(dir, set, &verification, &fingerprints)
            .expect("host verification builds a carry")
    }

    /// The point of the whole feature: a host that already read the payload
    /// hands its verification across the boundary, and the repair runs on it
    /// without reading the set a second time. `carry_consumed_for_repair`
    /// with no `carry_retried_fresh` is the single-read shape, and the bytes
    /// written must be the bytes the ordinary two-pass path writes.
    #[test]
    fn external_carry_repairs_on_the_host_analysis_without_a_scan() {
        let alpha: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let beta: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 11) % 241) as u8).collect();

        let carried_dir = tempdir().unwrap();
        let fresh_dir = tempdir().unwrap();
        create_recoverable_set(
            carried_dir.path(),
            &[("alpha.bin", &alpha), ("beta.bin", &beta)],
        );
        copy_flat_dir(carried_dir.path(), fresh_dir.path());
        for dir in [carried_dir.path(), fresh_dir.path()] {
            damage_first_slice(&dir.join("alpha.bin"));
        }

        let par2 = par2_paths_in(carried_dir.path());
        let set = loaded_set(carried_dir.path(), &par2);
        let (verification, fingerprints) = host_verification(carried_dir.path(), &set);
        assert!(
            verification.total_missing_blocks > 0,
            "the host's own pass must see the damage: {verification:#?}"
        );
        let carry =
            ScanCarry::from_verification(carried_dir.path(), &set, &verification, &fingerprints)
                .expect("host verification builds a carry");
        assert_eq!(
            carry.diagnostics.bytes_scanned, 0,
            "this crate read nothing to build the carry"
        );
        assert!(
            carry.diagnostics.bytes_skipped_by_evidence > 0,
            "the bytes behind the carried verdicts are disclosed as unread"
        );

        let mut execute = Par2RepairerOptions::new(carried_dir.path().to_path_buf(), par2);
        execute.scan_carry = Some(Arc::new(carry));
        let carried_outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

        assert_eq!(
            carried_outcome.status,
            Par2RepairStatus::Repaired,
            "{carried_outcome:#?}"
        );
        assert!(carried_outcome.carry.carry_applied);
        assert!(
            carried_outcome.carry.carry_consumed_for_repair,
            "an unchanged tree must repair on the host's analysis: {carried_outcome:#?}"
        );
        assert!(
            !carried_outcome.carry.carry_retried_fresh,
            "consuming the carry means no scan happened here: {carried_outcome:#?}"
        );
        assert!(carried_outcome.scan.carried);

        let fresh_outcome = Par2Repairer::new(Par2RepairerOptions::new(
            fresh_dir.path().to_path_buf(),
            par2_paths_in(fresh_dir.path()),
        ))
        .verify_or_repair()
        .unwrap();
        assert_eq!(fresh_outcome.status, Par2RepairStatus::Repaired);

        for (name, original) in [("alpha.bin", &alpha), ("beta.bin", &beta)] {
            let carried_bytes = fs::read(carried_dir.path().join(name)).unwrap();
            assert_eq!(carried_bytes, *original, "{name} must be restored");
            assert_eq!(
                carried_bytes,
                fs::read(fresh_dir.path().join(name)).unwrap(),
                "{name} must be byte-identical across the external-carry and fresh paths"
            );
        }
    }

    /// The trust contract's first defence. The host attested that `beta.bin`
    /// was intact and fingerprinted it; the file then changed at the same
    /// length with a moved mtime. `stat` can see that, so the snapshot gate
    /// refuses the carry outright and the pass scans for real — the
    /// attestation costs the scan it was meant to save and nothing else.
    #[test]
    fn external_carry_with_a_stat_visible_change_falls_back_to_a_fresh_scan() {
        let alpha: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let beta: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 11) % 241) as u8).collect();

        let dir = tempdir().unwrap();
        create_recoverable_set(dir.path(), &[("alpha.bin", &alpha), ("beta.bin", &beta)]);
        damage_first_slice(&dir.path().join("alpha.bin"));

        let par2 = par2_paths_in(dir.path());
        let set = loaded_set(dir.path(), &par2);
        let carry = external_carry(dir.path(), &set);

        // Same length, moved mtime: the change a stat call can see.
        bump_modified_time(&dir.path().join("beta.bin"));

        let mut execute = Par2RepairerOptions::new(dir.path().to_path_buf(), par2);
        execute.scan_carry = Some(Arc::new(carry));
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

        assert_eq!(outcome.status, Par2RepairStatus::Repaired, "{outcome:#?}");
        assert!(outcome.carry.carry_attempted);
        assert!(
            !outcome.carry.carry_applied,
            "a fingerprint that no longer matches must refuse the carry outright: {outcome:#?}"
        );
        assert!(!outcome.carry.carry_consumed_for_repair);
        assert!(
            !outcome.scan.carried,
            "the pass must report the scan it actually ran"
        );
        assert_eq!(fs::read(dir.path().join("alpha.bin")).unwrap(), alpha);
        assert_eq!(fs::read(dir.path().join("beta.bin")).unwrap(), beta);
    }

    /// The trust contract's last defence, and the one that makes a false
    /// attestation harmless rather than merely unlikely to be believed.
    ///
    /// Here the host attested `beta.bin` intact, its bytes were then replaced
    /// at the same length, and its mtime was restored — the one drift a stat
    /// fingerprint provably cannot see. Both stat gates therefore accept, on
    /// the evidence available to them, and the repair proceeds on the carried
    /// analysis. The validated read that a consumed carry always takes then
    /// catches the change on the bytes, against `beta.bin`'s own IFSC
    /// checksums, before anything is installed: the pass retries from a fresh
    /// scan naming the changed input, and the output is correct.
    #[test]
    fn external_carry_validated_read_catches_a_stat_invisible_byte_flip() {
        let alpha: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let beta: Vec<u8> = (0..512u32).map(|i| ((i * 7 + 11) % 241) as u8).collect();

        let dir = tempdir().unwrap();
        create_recoverable_set(dir.path(), &[("alpha.bin", &alpha), ("beta.bin", &beta)]);
        damage_first_slice(&dir.path().join("alpha.bin"));

        let par2 = par2_paths_in(dir.path());
        let set = loaded_set(dir.path(), &par2);
        let carry = external_carry(dir.path(), &set);

        let beta_path = dir.path().join("beta.bin");
        let mut flipped = beta.clone();
        flipped[100] ^= 0xFF;
        fs::write(&beta_path, &flipped).unwrap();
        restore_carried_modified_time(&carry, &beta_path);

        let mut execute = Par2RepairerOptions::new(dir.path().to_path_buf(), par2);
        execute.scan_carry = Some(Arc::new(carry));
        let outcome = Par2Repairer::new(execute).verify_or_repair().unwrap();

        assert!(outcome.carry.carry_applied, "{outcome:#?}");
        assert!(
            outcome.carry.carry_retried_fresh,
            "the validated read must send the pass back to a real scan: {outcome:#?}"
        );
        assert_eq!(
            outcome.carry.carry_retry_reason,
            Some(CarryRetryReason::RepairInputChanged),
            "{outcome:#?}"
        );
        assert!(
            !outcome.carry.carry_consumed_for_repair,
            "a repair that read a changed source did not consume the carry"
        );
        // Whatever the retried pass could make of the tree, the one thing that
        // must never happen is a file written from bytes nothing checked.
        assert_ne!(
            fs::read(&beta_path).unwrap(),
            flipped,
            "the corrupted source must not survive as the installed file"
        );
    }

    /// A carry built from a host verification must place missing and damaged
    /// files in exactly the internal states a real scan of the same tree
    /// produces, or repair would treat a target as an input. Comparing the
    /// two verification results end to end is the check: they are what every
    /// downstream decision reads.
    #[test]
    fn external_carry_reproduces_a_native_scan_for_missing_and_damaged_files() {
        let intact: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let damaged_source: Vec<u8> = (0..1024u32).map(|i| ((i * 3 + 1) % 251) as u8).collect();
        let gone: Vec<u8> = (0..1024u32).map(|i| ((i * 5 + 2) % 251) as u8).collect();

        let dir = tempdir().unwrap();
        let slice_size = 64u64;
        let set = synthetic_set(
            &[
                ("intact.bin", &intact),
                ("damaged.bin", &damaged_source),
                ("gone.bin", &gone),
            ],
            slice_size,
        );
        fs::write(dir.path().join("intact.bin"), &intact).unwrap();
        let mut damaged = damaged_source.clone();
        damaged[128..192].fill(0);
        fs::write(dir.path().join("damaged.bin"), &damaged).unwrap();
        // `gone.bin` is never written.

        let mut scanned = RepairState::from_set(dir.path(), set.clone()).unwrap();
        let options = Par2RepairerOptions::new(dir.path().to_path_buf(), Vec::new());
        scanned.scan(&options).unwrap();
        let native = format!("{:?}", scanned.verification_result());

        let carry = external_carry(dir.path(), &set);
        let mut carried = RepairState::from_set(dir.path(), set).unwrap();
        assert!(
            carried.try_apply_carry(&carry).is_some(),
            "a carry built from an unchanged tree must apply"
        );
        assert_eq!(
            format!("{:?}", carried.verification_result()),
            native,
            "an external carry must reproduce the scan's verdicts exactly"
        );
    }

    /// An attestation that contradicts itself, or the set it claims to
    /// describe, is a caller bug and is refused rather than absorbed: a carry
    /// this crate could not make sense of is the one thing that must never
    /// reach a repair.
    #[test]
    fn external_carry_refuses_inconsistent_attestations() {
        let data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let dir = tempdir().unwrap();
        let set = synthetic_set(&[("data.bin", &data)], 64);
        fs::write(dir.path().join("data.bin"), &data).unwrap();
        let (verification, fingerprints) = host_verification(dir.path(), &set);
        assert!(matches!(verification.files[0].status, FileStatus::Complete));

        let build = |verification: &VerificationResult,
                     fingerprints: &HashMap<FileId, FileStatFingerprint>| {
            ScanCarry::from_verification(dir.path(), &set, verification, fingerprints)
        };

        assert!(
            build(&verification, &fingerprints).is_ok(),
            "the consistent attestation must build"
        );

        let mut short = verification.clone();
        short.files[0].valid_slices.pop();
        assert!(matches!(
            build(&short, &fingerprints),
            Err(ExternalCarryError::SliceCountMismatch { .. })
        ));

        let mut miscounted = verification.clone();
        miscounted.files[0].missing_slice_count = 1;
        assert!(matches!(
            build(&miscounted, &fingerprints),
            Err(ExternalCarryError::DamagedCountMismatch { .. })
        ));

        let mut lying_complete = verification.clone();
        lying_complete.files[0].valid_slices[0] = false;
        lying_complete.files[0].missing_slice_count = 1;
        assert!(matches!(
            build(&lying_complete, &fingerprints),
            Err(ExternalCarryError::IncompleteCompleteFile { .. })
        ));

        let mut renamed = verification.clone();
        renamed.files[0].status = FileStatus::Renamed(dir.path().join("elsewhere.bin"));
        assert!(matches!(
            build(&renamed, &fingerprints),
            Err(ExternalCarryError::RelocatedFile { .. })
        ));

        let mut missing_with_content = verification.clone();
        missing_with_content.files[0].status = FileStatus::Missing;
        assert!(matches!(
            build(&missing_with_content, &fingerprints),
            Err(ExternalCarryError::MissingFileWithContent { .. })
        ));

        assert!(
            matches!(
                build(&verification, &HashMap::new()),
                Err(ExternalCarryError::UnfingerprintedFile { .. })
            ),
            "a present file with no fingerprint has nothing for the gate to check"
        );

        let mut uncovered = verification.clone();
        uncovered.files.clear();
        assert!(matches!(
            build(&uncovered, &fingerprints),
            Err(ExternalCarryError::UncoveredFile { .. })
        ));

        let mut unknown = verification.clone();
        let mut stranger = unknown.files[0].clone();
        stranger.file_id = FileId::from_bytes([0xEE; 16]);
        unknown.files.push(stranger);
        assert!(matches!(
            build(&unknown, &fingerprints),
            Err(ExternalCarryError::UnknownFile { .. })
        ));

        let mut duplicated = verification.clone();
        duplicated.files.push(duplicated.files[0].clone());
        assert!(matches!(
            build(&duplicated, &fingerprints),
            Err(ExternalCarryError::DuplicateFile { .. })
        ));
    }

    /// The carried files and blocks replace the receiving state's own, so a
    /// carry laid out from a different set must never be installed. File IDs
    /// nearly settle it; the recovery set ID and slice size close what they
    /// leave open.
    #[test]
    fn external_carry_from_another_set_is_refused() {
        let data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("data.bin"), &data).unwrap();

        let coarse = synthetic_set(&[("data.bin", &data)], 128);
        let carry = external_carry(dir.path(), &coarse);

        let mut fine_set = synthetic_set(&[("data.bin", &data)], 64);
        fine_set.recovery_set_id = RecoverySetId::from_bytes([9; 16]);
        let mut fine = RepairState::from_set(dir.path(), fine_set).unwrap();
        assert!(
            fine.try_apply_carry(&carry).is_none(),
            "a carry from another set must not be installed"
        );
    }
}
