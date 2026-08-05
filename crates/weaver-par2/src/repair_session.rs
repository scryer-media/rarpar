//! Retained PAR2 repair orchestration.
//!
//! Unlike [`crate::repairer::Par2Repairer`], this API keeps parsed packet
//! metadata and verified source locations across assessment and repair. It
//! deliberately retains no open file handles or mapped data; repair reopens
//! and validates every source as bytes are copied or consumed.
//!
//! # Sources that are not files
//!
//! A session reads its sources either from the filesystem — the default, and
//! byte-for-byte the behaviour this API has always had — or through a
//! [`FileAccess`] handle supplied by
//! [`Par2RepairSessionOptions::with_source_access`]. The second form exists
//! for sets whose sources have no paths at all: bytes still arriving over a
//! network, or served out of somewhere that never became a file.
//!
//! The two arms differ in more than plumbing:
//!
//! - An access-backed session performs **no source scanning**. There is no
//!   directory to walk, so [`Par2RepairSession::analyze`] resolves exactly what
//!   evidence has named and leaves the rest unresolved.
//! - Evidence for an access-backed source is named by [`FileId`]
//!   ([`Par2RepairSession::add_slice_evidence_for_file`]), never by path.
//! - Committed-file evidence stays physical-only; see
//!   [`Par2RepairSession::add_committed_file`].
//!
//! Repair *outputs* are always real files in either arm. Only clean-source
//! reads virtualize.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;

use crate::error::Par2Error;
use crate::evidence::CommittedFileEvidence;
use crate::packet::{Packet, scan_packets_from_path_with_set_ids};
use crate::par2_set::MergeResult;
use crate::repair::{DEFAULT_REPAIR_MEMORY_LIMIT, repair_matrix_resource_limit_reason};
use crate::repairer::{
    PacketDiagnostics, Par2RepairOutcome, Par2RepairStatus, Par2Repairer, Par2RepairerOptions,
    RepairInstall, RepairState, RepairVerificationAccess, ScanDiagnostics, SourceLocation,
};
use crate::session::{SliceEvidence, SliceEvidenceStrength};
use crate::types::{CancellationToken, FileId, ProgressCallback};
use crate::verify::{self, FileAccess, FileStatus, Repairability, VerificationResult};

/// Default upper bound for memory owned by a retained repair session.
pub const DEFAULT_RETAINED_STATE_LIMIT: usize = 64 * 1024 * 1024;

/// Options used to open a [`Par2RepairSession`].
///
/// Build one with [`Par2RepairSessionOptions::new`] (filesystem sources) or
/// [`Par2RepairSessionOptions::with_source_access`] (sources served by a
/// [`FileAccess`] handle), then set the fields you care about. The type is
/// `#[non_exhaustive]`: it will keep gaining fields, so construct it through a
/// constructor rather than a struct literal.
///
/// ```no_run
/// use par2_rs::Par2RepairSessionOptions;
/// use std::path::PathBuf;
///
/// let mut options = Par2RepairSessionOptions::new(
///     PathBuf::from("/downloads/release"),
///     vec![PathBuf::from("/downloads/release/release.par2")],
/// );
/// options.retained_state_limit = 8 * 1024 * 1024;
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct Par2RepairSessionOptions {
    /// Where repair *output* lands, and — for filesystem sessions only — where
    /// source scanning looks. An access-backed session never reads from here.
    pub base_dir: PathBuf,
    /// The primary PAR2 files. Adjacent volumes are deliberately not loaded
    /// here; add them later with [`Par2RepairSession::merge_recovery_paths`].
    pub par2_paths: Vec<PathBuf>,
    /// Explicit recovery volumes to merge immediately after opening.
    pub recovery_paths: Vec<PathBuf>,
    pub extra_paths: Vec<PathBuf>,
    pub memory_limit: Option<usize>,
    pub retained_state_limit: usize,
    pub rename_only: bool,
    pub scan_skip_data: bool,
    pub scan_skip_leeway: u64,
    pub cancel: Option<CancellationToken>,
    pub progress: Option<ProgressCallback>,
    /// Handle serving this set's sources. `None` — the default — reads sources
    /// from the filesystem under `base_dir`. When present, every source read
    /// goes through the handle and no source is ever opened by path.
    pub source_access: Option<Arc<dyn FileAccess + Send + Sync>>,
}

impl Par2RepairSessionOptions {
    /// Options for a session whose sources are files under `base_dir`.
    pub fn new(base_dir: PathBuf, par2_paths: Vec<PathBuf>) -> Self {
        Self {
            base_dir,
            par2_paths,
            ..Self::default()
        }
    }

    /// Options for a session whose sources are served by `source_access`
    /// rather than read from disk.
    ///
    /// `base_dir` still names where repair output is staged and installed, and
    /// `par2_paths` are still read as files — only the protected *sources*
    /// move behind the handle.
    ///
    /// ```no_run
    /// use par2_rs::{MemoryFileAccess, Par2RepairSessionOptions};
    /// use std::path::PathBuf;
    /// use std::sync::Arc;
    ///
    /// let access = Arc::new(MemoryFileAccess::new());
    /// let options = Par2RepairSessionOptions::with_source_access(
    ///     PathBuf::from("/var/tmp/repair-scratch"),
    ///     vec![PathBuf::from("/downloads/release/release.par2")],
    ///     access,
    /// );
    /// assert!(options.source_access.is_some());
    /// ```
    pub fn with_source_access(
        base_dir: PathBuf,
        par2_paths: Vec<PathBuf>,
        source_access: Arc<dyn FileAccess + Send + Sync>,
    ) -> Self {
        Self {
            base_dir,
            par2_paths,
            source_access: Some(source_access),
            ..Self::default()
        }
    }
}

impl Default for Par2RepairSessionOptions {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::new(),
            par2_paths: Vec::new(),
            recovery_paths: Vec::new(),
            extra_paths: Vec::new(),
            memory_limit: Some(DEFAULT_REPAIR_MEMORY_LIMIT),
            retained_state_limit: DEFAULT_RETAINED_STATE_LIMIT,
            rename_only: false,
            scan_skip_data: false,
            scan_skip_leeway: 64,
            cancel: None,
            progress: None,
            source_access: None,
        }
    }
}

/// Diagnostics accumulated by the retained session.
///
/// `#[non_exhaustive]`: counters get added as the session learns to report
/// more. Read the fields you need; do not match the struct exhaustively.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Par2RepairSessionDiagnostics {
    pub packets: PacketDiagnostics,
    pub scan: ScanDiagnostics,
    pub source_scan_passes: u32,
    pub retained_bytes: usize,
    pub committed_sources: u32,
    pub slice_evidence: u32,
    pub quick_proof_hits: u32,
    pub quick_proof_fallbacks: u32,
    pub live_slices: u32,
    pub recovery_paths_merged: u32,
    pub recovery_packets_rejected: u32,
    pub repair_validation_bytes: u64,
    pub analyzed: bool,
    /// Slice evidence retained by [`FileId`] rather than by path. Always zero
    /// on a filesystem session.
    pub access_slice_evidence: u32,
    /// Current source-coverage generation; see
    /// [`Par2RepairSession::source_generation`].
    pub source_generation: u64,
}

/// Errors specific to retaining PAR2 source analysis between calls.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Par2SessionError {
    #[error("invalid retained-session state: {reason}")]
    InvalidState { reason: &'static str },

    #[error("source changed before or during repair: {path}")]
    SourceChanged { path: PathBuf },

    #[error(
        "retained PAR2 session state requires {required_bytes} bytes, exceeding the {limit_bytes} byte limit"
    )]
    RetainedStateLimitExceeded {
        limit_bytes: usize,
        required_bytes: usize,
    },

    #[error("committed evidence does not match a recoverable PAR2 file: {logical_name}")]
    EvidenceDoesNotMatch { logical_name: String },

    #[error(transparent)]
    Par2(#[from] Par2Error),
}

/// Stateful PAR2 repair engine retaining only owned packet metadata and
/// source-location evidence between calls.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedSliceEvidence {
    source: SourceLocation,
    valid: bool,
}

pub struct Par2RepairSession {
    options: Par2RepairSessionOptions,
    state: RepairState,
    packet_diagnostics: PacketDiagnostics,
    committed: Vec<CommittedFileEvidence>,
    slice_evidence: HashMap<(FileId, u32), RetainedSliceEvidence>,
    merged_recovery_paths: HashSet<PathBuf>,
    sources_scanned: bool,
    source_generation: u64,
    diagnostics: Par2RepairSessionDiagnostics,
    assessment: Option<Par2RepairOutcome>,
}

impl Par2RepairSession {
    /// Open the primary packet set without eagerly selecting adjacent recovery
    /// volumes. Any explicit recovery paths are merged afterward.
    pub fn open(mut options: Par2RepairSessionOptions) -> Result<Self, Par2SessionError> {
        let explicit_recovery = std::mem::take(&mut options.recovery_paths);
        let repairer = Par2Repairer::new(repairer_options(&options, false));
        let inventory = repairer.load_inventory_without_adjacent_recovery()?;
        let required_bytes =
            RepairState::estimated_retained_bytes_from_set(&options.base_dir, &inventory.set);
        if required_bytes > options.retained_state_limit {
            return Err(Par2SessionError::RetainedStateLimitExceeded {
                limit_bytes: options.retained_state_limit,
                required_bytes,
            });
        }
        let state = RepairState::from_set_with_access(
            &options.base_dir,
            inventory.set,
            options.source_access.clone(),
        )?;
        let mut session = Self {
            options,
            state,
            packet_diagnostics: inventory.diagnostics,
            committed: Vec::new(),
            slice_evidence: HashMap::new(),
            merged_recovery_paths: HashSet::new(),
            sources_scanned: false,
            source_generation: 0,
            diagnostics: Par2RepairSessionDiagnostics::default(),
            assessment: None,
        };
        session.refresh_diagnostics();
        session.enforce_retained_limit()?;
        if !explicit_recovery.is_empty() {
            session.merge_recovery_paths(explicit_recovery)?;
        }
        Ok(session)
    }

    /// Whether this session reads its sources through a [`FileAccess`] handle
    /// instead of the filesystem.
    pub fn is_access_backed(&self) -> bool {
        self.options.source_access.is_some()
    }

    /// Add independently captured committed-file evidence. Full MD5 evidence
    /// seeds a whole-file location. Contiguous CRC32 + 16 KiB evidence is
    /// quick-proved against its captured path and also seeds a complete file.
    ///
    /// # This evidence class is physical by definition
    ///
    /// Committed-file evidence is admitted on a stat fingerprint — device,
    /// inode, mtime and length, captured when the evidence was taken and
    /// re-checked before every analysis, merge and repair. That gate is not an
    /// implementation limit that a virtual source happens to fail; it *is* the
    /// definition of the class. The claim being made is "the file I hashed is
    /// still the same file, unmoved and unrewritten", and only a filesystem
    /// object can carry that claim.
    ///
    /// A source served through a [`FileAccess`] handle has no device, no inode
    /// and no mtime. Its staleness is governed by the handle's own coverage
    /// (see [`Par2RepairSession::source_generation`]), not by `stat`. So an
    /// access-backed session refuses this evidence outright, with a named
    /// reason, rather than letting the stat gate refuse it incidentally.
    /// Feed wire evidence for such sources with
    /// [`Par2RepairSession::add_slice_evidence_for_file`] instead.
    pub fn add_committed_file(
        &mut self,
        evidence: CommittedFileEvidence,
    ) -> Result<(), Par2SessionError> {
        if self.is_access_backed() {
            self.diagnostics.quick_proof_fallbacks =
                self.diagnostics.quick_proof_fallbacks.saturating_add(1);
            return Err(Par2SessionError::InvalidState {
                reason: "committed-file evidence is physical-only: it is admitted by a stat \
                         fingerprint, which an access-backed source cannot carry",
            });
        }
        match evidence_stat_matches(&evidence) {
            Ok(true) => {}
            Ok(false) => {
                self.diagnostics.quick_proof_fallbacks =
                    self.diagnostics.quick_proof_fallbacks.saturating_add(1);
                return Err(Par2SessionError::EvidenceDoesNotMatch {
                    logical_name: evidence.logical_name().to_owned(),
                });
            }
            Err(error) => {
                self.diagnostics.quick_proof_fallbacks =
                    self.diagnostics.quick_proof_fallbacks.saturating_add(1);
                return Err(error);
            }
        }
        let targets = self.evidence_targets(&evidence);
        if targets.len() != 1 {
            self.diagnostics.quick_proof_fallbacks =
                self.diagnostics.quick_proof_fallbacks.saturating_add(1);
            return Err(Par2SessionError::EvidenceDoesNotMatch {
                logical_name: evidence.logical_name().to_owned(),
            });
        }
        let source = SourceLocation::Path(evidence.path().to_path_buf());
        let path_budget = self
            .state
            .complete_location_budget(targets[0], &source)
            .ok_or_else(|| Par2SessionError::EvidenceDoesNotMatch {
                logical_name: evidence.logical_name().to_owned(),
            })?;
        let projected = self
            .estimated_retained_bytes()
            .saturating_add(committed_evidence_bytes(&evidence))
            .saturating_add(path_budget);
        self.ensure_limit(projected)?;
        if !self.state.seed_complete_location(targets[0], source) {
            return Err(Par2SessionError::EvidenceDoesNotMatch {
                logical_name: evidence.logical_name().to_owned(),
            });
        }
        self.diagnostics.quick_proof_hits = self.diagnostics.quick_proof_hits.saturating_add(1);
        self.committed.push(evidence);
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
        Ok(())
    }

    /// Add a settled IFSC verdict from [`crate::session::VerificationSession`]
    /// for the file at `path`. Only valid slices seed a source block; an
    /// invalid verdict invalidates prior locations for the supplied path.
    ///
    /// Use [`Self::add_slice_evidence_for_file`] for sources served by a
    /// [`FileAccess`] handle, which have no path to name.
    pub fn add_slice_evidence(
        &mut self,
        path: impl Into<PathBuf>,
        evidence: SliceEvidence,
    ) -> Result<(), Par2SessionError> {
        self.retain_slice_evidence(SourceLocation::Path(path.into()), evidence)
    }

    /// Add a settled IFSC verdict for a source named only by its PAR2
    /// [`FileId`] — the form used when sources are served by a [`FileAccess`]
    /// handle rather than found on disk.
    ///
    /// The identifier comes from the evidence itself, so there is nothing to
    /// pass but the verdict. As with the path-keyed form, only
    /// [`SliceEvidenceStrength::Crc32AndMd5`] evidence may seed repair input,
    /// and an invalid verdict clears any location previously held for that
    /// slice.
    ///
    /// This requires an access-backed session: without a handle there is no
    /// way to read the bytes a [`FileId`] names, and quietly falling back to
    /// `base_dir` would reintroduce exactly the filesystem coupling the handle
    /// exists to remove.
    ///
    /// ```no_run
    /// # use par2_rs::{MemoryFileAccess, Par2RepairSession, Par2RepairSessionOptions};
    /// # use std::path::PathBuf;
    /// # use std::sync::Arc;
    /// # fn demo(evidence: par2_rs::SliceEvidence) -> Result<(), par2_rs::Par2SessionError> {
    /// let access = Arc::new(MemoryFileAccess::new());
    /// let mut session = Par2RepairSession::open(Par2RepairSessionOptions::with_source_access(
    ///     PathBuf::from("/var/tmp/repair-scratch"),
    ///     vec![PathBuf::from("/downloads/release/release.par2")],
    ///     access,
    /// ))?;
    /// session.add_slice_evidence_for_file(evidence)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_slice_evidence_for_file(
        &mut self,
        evidence: SliceEvidence,
    ) -> Result<(), Par2SessionError> {
        if !self.is_access_backed() {
            return Err(Par2SessionError::InvalidState {
                reason: "FileId-keyed slice evidence requires a session opened with a \
                         source-access handle",
            });
        }
        self.retain_slice_evidence(SourceLocation::Access(evidence.file_id()), evidence)
    }

    fn retain_slice_evidence(
        &mut self,
        source: SourceLocation,
        evidence: SliceEvidence,
    ) -> Result<(), Par2SessionError> {
        if evidence.recovery_set_id() != self.state.set.recovery_set_id {
            return Err(Par2Error::ConflictingRecoverySet.into());
        }
        if evidence.strength() != SliceEvidenceStrength::Crc32AndMd5 {
            return Err(Par2SessionError::InvalidState {
                reason: "CRC32-only slice evidence cannot seed repair input",
            });
        }
        let key = (evidence.file_id(), evidence.slice_index());
        let retained = RetainedSliceEvidence {
            source,
            valid: evidence.is_valid(),
        };
        if self.slice_evidence.get(&key) == Some(&retained) {
            return Ok(());
        }
        let Some(location_budget) = self.state.block_location_budget(
            evidence.file_id(),
            evidence.slice_index(),
            &retained.source,
        ) else {
            return Err(Par2SessionError::EvidenceDoesNotMatch {
                logical_name: format!(
                    "PAR2 file {} slice {}",
                    evidence.file_id(),
                    evidence.slice_index()
                ),
            });
        };
        let key_bytes = std::mem::size_of_val(&key);
        let projected = self
            .estimated_retained_bytes()
            .saturating_add(key_bytes)
            .saturating_add(retained_slice_evidence_bytes(&retained))
            .saturating_add(if evidence.is_valid() {
                location_budget
            } else {
                0
            });
        self.ensure_limit(projected)?;
        if let Some(old) = self.slice_evidence.get(&key) {
            invalidate_source_in_state(&mut self.state, &old.source);
        }
        self.slice_evidence.insert(key, retained.clone());
        if evidence.is_valid() {
            self.state.seed_block_location(
                evidence.file_id(),
                evidence.slice_index(),
                retained.source,
            );
        } else {
            invalidate_source_in_state(&mut self.state, &retained.source);
        }
        self.diagnostics.live_slices = self.diagnostics.live_slices.saturating_add(1);
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
        Ok(())
    }

    /// Analyze sources once. Repeated calls return the cached assessment.
    ///
    /// A filesystem session scans `base_dir` for anything evidence has not
    /// already resolved. An **access-backed session never scans**: there is no
    /// directory that holds its sources, so a walk would at best waste I/O and
    /// at worst bind the set to unrelated files that happen to share a name.
    /// Blocks that no evidence has named simply stay unresolved, and the
    /// caller decides what to do about them.
    pub fn analyze(&mut self) -> Result<Par2RepairOutcome, Par2SessionError> {
        self.ensure_committed_sources_unchanged()?;
        if let Some(assessment) = &self.assessment {
            return Ok(assessment.clone());
        }
        let scan = if self.is_access_backed() {
            // No scan pass is counted, and no scan byte is read: the whole
            // point of an access-backed session is that `base_dir` holds no
            // sources to find.
            self.state.refresh_access_file_states();
            self.sources_scanned = true;
            ScanDiagnostics::default()
        } else if self.sources_scanned {
            self.diagnostics.scan.clone()
        } else {
            let scan = self
                .state
                .scan_unresolved(&repairer_options(&self.options, false))?;
            self.sources_scanned = true;
            self.diagnostics.source_scan_passes =
                self.diagnostics.source_scan_passes.saturating_add(1);
            scan
        };
        self.diagnostics.scan = scan.clone();
        let assessment = self.build_assessment(scan, 0, 0)?;
        let required_bytes = self
            .estimated_retained_bytes()
            .saturating_add(assessment_bytes(&assessment));
        if let Err(error) = self.ensure_limit(required_bytes) {
            self.invalidate_all_sources();
            return Err(error);
        }
        self.assessment = Some(assessment.clone());
        self.refresh_diagnostics();
        Ok(assessment)
    }

    /// Return the cached assessment. Call [`Self::analyze`] first.
    pub fn assessment(&self) -> Result<&Par2RepairOutcome, Par2SessionError> {
        self.assessment
            .as_ref()
            .ok_or(Par2SessionError::InvalidState {
                reason: "analyze must complete before requesting an assessment",
            })
    }

    /// Parse only paths not previously merged, then merge their recovery
    /// packets in place. Existing source locations and scan accounting remain
    /// valid because recovery-only additions cannot alter source bytes.
    pub fn merge_recovery_paths<I, P>(&mut self, paths: I) -> Result<MergeResult, Par2SessionError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.ensure_committed_sources_unchanged()?;
        let new_paths = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .filter(|path| !self.merged_recovery_paths.contains(path))
            .collect::<Vec<_>>();
        if new_paths.is_empty() {
            return Ok(MergeResult {
                new_recovery_slices: 0,
                duplicates_ignored: 0,
            });
        }
        let mut packets = Vec::new();
        let mut rejected = 0u32;
        let mut metadata_changed = false;
        for path in &new_paths {
            for scanned in scan_packets_from_path_with_set_ids(path)? {
                if scanned.recovery_set_id != self.state.set.recovery_set_id {
                    return Err(Par2Error::ConflictingRecoverySet.into());
                }
                let packet = scanned.packet;
                metadata_changed |= match &packet {
                    Packet::FileDescription(description) => {
                        !self.state.set.files.contains_key(&description.file_id)
                    }
                    Packet::InputFileSliceChecksum(checksums) => !self
                        .state
                        .set
                        .slice_checksums
                        .contains_key(&checksums.file_id),
                    _ => false,
                };
                match packet {
                    Packet::RecoverySlice(recovery)
                        if recovery.data.len() as u64 == self.state.set.slice_size =>
                    {
                        packets.push(Packet::RecoverySlice(recovery));
                    }
                    Packet::RecoverySlice(_) | Packet::Unknown { .. } => {
                        rejected = rejected.saturating_add(1);
                    }
                    metadata => packets.push(metadata),
                }
            }
        }
        let new_path_bytes = retained_path_bytes(&new_paths);
        let retained_without_state_or_assessment = self
            .estimated_retained_bytes()
            .saturating_sub(self.state.estimated_retained_bytes())
            .saturating_sub(self.assessment.as_ref().map_or(0, assessment_bytes));
        let packets_loaded = packets.len() as u32;
        let merged_paths = new_paths.len() as u32;
        let mut candidate_set = self.state.set.clone();
        let result = candidate_set.merge_packets(packets)?;
        if metadata_changed {
            let mut candidate_state = RepairState::from_set(&self.options.base_dir, candidate_set)?;
            for evidence in &self.committed {
                apply_committed_evidence_to_state(&mut candidate_state, evidence);
            }
            apply_slice_evidence_to_state(&mut candidate_state, &self.slice_evidence);
            let required_bytes = retained_without_state_or_assessment
                .saturating_add(candidate_state.estimated_retained_bytes())
                .saturating_add(new_path_bytes);
            self.ensure_limit(required_bytes)?;
            self.state = candidate_state;
            self.sources_scanned = false;
        } else {
            let required_bytes = retained_without_state_or_assessment
                .saturating_add(self.state.estimated_retained_bytes_with_set(&candidate_set))
                .saturating_add(new_path_bytes);
            self.ensure_limit(required_bytes)?;
            self.state.set = candidate_set;
        }
        self.merged_recovery_paths.extend(new_paths);
        self.packet_diagnostics.packets_loaded = self
            .packet_diagnostics
            .packets_loaded
            .saturating_add(packets_loaded);
        self.packet_diagnostics.duplicate_packets = self
            .packet_diagnostics
            .duplicate_packets
            .saturating_add(result.duplicates_ignored);
        self.diagnostics.recovery_paths_merged = self
            .diagnostics
            .recovery_paths_merged
            .saturating_add(merged_paths);
        self.diagnostics.recovery_packets_rejected = self
            .diagnostics
            .recovery_packets_rejected
            .saturating_add(rejected);
        // Recovery-only packets preserve the source scan. Newly discovered
        // FileDesc/IFSC metadata rebuilds the source map and requires one new
        // analysis pass because the protected file set itself changed.
        self.assessment = None;
        self.refresh_diagnostics();
        Ok(result)
    }

    /// Repair using the retained assessment. Source bytes are checked inline
    /// as blocks are staged and as streamed reconstruction reads consume them.
    pub fn repair(&mut self) -> Result<Par2RepairOutcome, Par2SessionError> {
        self.ensure_committed_sources_unchanged()?;
        let assessment = self.assessment()?.clone();
        if !matches!(assessment.status, Par2RepairStatus::RepairPossible) {
            return Ok(assessment);
        }
        let repair_options = repairer_options(&self.options, true);
        let repair = match self
            .state
            .repair_validated(&repair_options, &assessment.verification)
        {
            Ok(repair) => repair,
            Err(error @ Par2Error::InsufficientRecoveryData { .. }) => {
                let rejected = self.discard_unusable_recovery_packets();
                if rejected == 0 {
                    return Err(map_par2_error(error));
                }
                self.diagnostics.recovery_packets_rejected = self
                    .diagnostics
                    .recovery_packets_rejected
                    .saturating_add(rejected);
                let outcome = self.build_assessment(self.diagnostics.scan.clone(), 0, 0)?;
                self.assessment = Some(outcome.clone());
                self.refresh_diagnostics();
                return Ok(outcome);
            }
            Err(error) => return Err(map_par2_error(error)),
        };
        let validation_bytes = repair.validation_bytes;
        let result = self.finish_repair(repair, assessment.verification, repair_options);
        match result {
            Ok(outcome) => {
                self.diagnostics.repair_validation_bytes = self
                    .diagnostics
                    .repair_validation_bytes
                    .saturating_add(validation_bytes);
                self.assessment = Some(outcome.clone());
                self.refresh_diagnostics();
                Ok(outcome)
            }
            Err(error) => Err(map_par2_error(error)),
        }
    }

    /// Forget retained locations for one path. Packet metadata and other
    /// sources stay available for a later unresolved-only analysis.
    ///
    /// This is the disk-side invalidation and it names a disk object; it
    /// cannot reach an access-backed source, which has no path. Use
    /// [`Self::invalidate_file`] for those.
    pub fn invalidate_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        self.state.invalidate_path(path);
        self.committed.retain(|evidence| evidence.path() != path);
        self.slice_evidence
            .retain(|_, evidence| !evidence.source.is_path(path));
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
    }

    /// Forget every retained location and every piece of evidence belonging to
    /// one PAR2 file, whichever kind of source backs it.
    ///
    /// This is the identity-keyed invalidation: it names the *file* in the
    /// recovery set rather than a place on disk, so it is the right call when
    /// a virtual source stops being trustworthy. Packet metadata, recovery
    /// packets and every other file's evidence survive, so the next
    /// [`Self::analyze`] re-resolves only what this dropped.
    ///
    /// Returns `true` when something was actually forgotten.
    pub fn invalidate_file(&mut self, file_id: FileId) -> bool {
        let mut changed = self.state.invalidate_file(file_id);
        let before_committed = self.committed.len();
        let state = &self.state;
        self.committed
            .retain(|evidence| evidence_targets_in_state(state, evidence) != vec![file_id]);
        changed |= self.committed.len() != before_committed;
        let before_slices = self.slice_evidence.len();
        self.slice_evidence
            .retain(|(key_id, _), _| *key_id != file_id);
        changed |= self.slice_evidence.len() != before_slices;
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
        changed
    }

    /// Forget every retained source location and evidence while retaining the
    /// parsed packet set and lazily selected recovery packets.
    ///
    /// Also advances [`Self::source_generation`], because forgetting every
    /// source is by definition a coverage change.
    pub fn invalidate_all_sources(&mut self) {
        self.state.invalidate_all_sources();
        self.committed.clear();
        self.slice_evidence.clear();
        self.sources_scanned = false;
        self.assessment = None;
        self.source_generation = self.source_generation.saturating_add(1);
        self.refresh_diagnostics();
    }

    /// The current source-coverage generation, starting at 0.
    ///
    /// This is a monotonic counter, not a walk over anything. A caller that
    /// serves virtual sources holds the generation it last fed evidence under
    /// and compares: unchanged means every access-backed location the session
    /// holds is still the one it seeded, so nothing needs re-feeding. It never
    /// goes backwards, and it is the session's whole answer to "is my view
    /// still current?".
    pub fn source_generation(&self) -> u64 {
        self.source_generation
    }

    /// Retire every access-backed source at once and return the new
    /// generation.
    ///
    /// This is the counterpart to [`Self::invalidate_path`] for sources that
    /// have no path: when a serving handle's coverage moves — a router
    /// re-plans, a cache is dropped — one call retires everything read through
    /// it, without the caller enumerating identifiers. Physical locations and
    /// committed-file evidence are untouched, because nothing about them
    /// changed.
    pub fn invalidate_access_sources(&mut self) -> u64 {
        self.state.invalidate_access_sources();
        self.slice_evidence
            .retain(|_, evidence| !evidence.source.is_access());
        self.sources_scanned = false;
        self.assessment = None;
        self.source_generation = self.source_generation.saturating_add(1);
        self.refresh_diagnostics();
        self.source_generation
    }

    /// Conservative upper bound on the heap this session owns.
    ///
    /// Every mutation projects this figure forward before it applies, so a
    /// caller budgeting several sessions against one ceiling can trust it.
    /// Access-backed retention is counted the same way as path-backed
    /// retention, and it is genuinely smaller: a [`FileId`] is 16 inline bytes
    /// where a path owns its own allocation.
    pub fn estimated_retained_bytes(&self) -> usize {
        self.state
            .estimated_retained_bytes()
            .saturating_add(
                self.committed
                    .iter()
                    .map(committed_evidence_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(
                self.slice_evidence
                    .iter()
                    .map(|(key, evidence)| {
                        std::mem::size_of_val(key)
                            .saturating_add(retained_slice_evidence_bytes(evidence))
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.merged_recovery_paths
                    .iter()
                    .map(|path| retained_path_buf_bytes(path))
                    .sum::<usize>(),
            )
            .saturating_add(self.assessment.as_ref().map_or(0, assessment_bytes))
    }

    pub fn diagnostics(&self) -> &Par2RepairSessionDiagnostics {
        &self.diagnostics
    }

    fn finish_repair(
        &self,
        repair: RepairInstall,
        verification: VerificationResult,
        options: Par2RepairerOptions,
    ) -> Result<Par2RepairOutcome, Par2Error> {
        let access = RepairVerificationAccess::new(
            &self.state.files,
            &repair.install_dir,
            &repair.staged_file_ids,
            self.options.source_access.clone(),
        );
        let staged_ids = self
            .state
            .set
            .recovery_file_ids
            .iter()
            .filter(|file_id| repair.staged_file_ids.contains(file_id))
            .copied()
            .collect::<Vec<_>>();
        let post_staged =
            verify::verify_repaired_file_ids_parallel(&self.state.set, &access, &staged_ids);
        let post = verify::merge_verification_results(&self.state.set, &verification, post_staged);
        if post.total_missing_blocks > 0
            || !post
                .files
                .iter()
                .all(|file| matches!(file.status, FileStatus::Complete))
        {
            let _ = fs::remove_dir_all(&repair.install_dir);
            return Err(Par2Error::ReedSolomonError {
                reason: format!(
                    "post-repair verification failed: {} blocks remain damaged",
                    post.total_missing_blocks
                ),
            });
        }
        if let Err(error) = self.state.install_repaired_files(&repair, &options) {
            let _ = fs::remove_dir_all(&repair.install_dir);
            return Err(error);
        }
        let _ = fs::remove_dir_all(&repair.install_dir);
        Ok(self.state.outcome(
            Par2RepairStatus::Repaired,
            repair.bytes_copied,
            repair.bytes_reconstructed,
            self.packet_diagnostics.clone(),
            self.diagnostics.scan.clone(),
            post,
        ))
    }

    fn build_assessment(
        &self,
        scan: ScanDiagnostics,
        bytes_copied: u64,
        bytes_reconstructed: u64,
    ) -> Result<Par2RepairOutcome, Par2SessionError> {
        let mut verification = self.state.verification_result();
        if let Some(reason) = repair_matrix_resource_limit_reason(
            &self.state.set,
            &verification,
            self.options.memory_limit,
        )? {
            verification.repairable = Repairability::ResourceLimited { reason };
        }
        let status = if verification.total_missing_blocks == 0
            && self.state.files_are_canonical_complete()
        {
            Par2RepairStatus::Verified
        } else {
            match &verification.repairable {
                Repairability::NotNeeded => Par2RepairStatus::Verified,
                Repairability::Repairable { .. } => Par2RepairStatus::RepairPossible,
                Repairability::Insufficient { .. } => Par2RepairStatus::Insufficient,
                Repairability::ResourceLimited { .. } => Par2RepairStatus::ResourceLimited,
            }
        };
        Ok(self.state.outcome(
            status,
            bytes_copied,
            bytes_reconstructed,
            self.packet_diagnostics.clone(),
            scan,
            verification,
        ))
    }

    fn evidence_targets(&self, evidence: &CommittedFileEvidence) -> Vec<FileId> {
        evidence_targets_in_state(&self.state, evidence)
    }

    fn discard_unusable_recovery_packets(&mut self) -> u32 {
        let recovery_set_id = self.state.set.recovery_set_id;
        let before = self.state.set.recovery_slices.len();
        self.state.set.recovery_slices.retain(|exponent, recovery| {
            recovery
                .data
                .validate_packet_hash(recovery_set_id.as_bytes(), *exponent)
                .unwrap_or(false)
        });
        u32::try_from(before.saturating_sub(self.state.set.recovery_slices.len()))
            .unwrap_or(u32::MAX)
    }

    fn ensure_committed_sources_unchanged(&self) -> Result<(), Par2SessionError> {
        for evidence in &self.committed {
            if !evidence_stat_matches(evidence)? {
                return Err(Par2SessionError::SourceChanged {
                    path: evidence.path().to_path_buf(),
                });
            }
        }
        Ok(())
    }

    fn ensure_limit(&self, required_bytes: usize) -> Result<(), Par2SessionError> {
        if required_bytes > self.options.retained_state_limit {
            return Err(Par2SessionError::RetainedStateLimitExceeded {
                limit_bytes: self.options.retained_state_limit,
                required_bytes,
            });
        }
        Ok(())
    }

    fn enforce_retained_limit(&self) -> Result<(), Par2SessionError> {
        self.ensure_limit(self.estimated_retained_bytes())
    }

    fn refresh_diagnostics(&mut self) {
        self.diagnostics.packets = self.packet_diagnostics.clone();
        self.diagnostics.retained_bytes = self.estimated_retained_bytes();
        self.diagnostics.committed_sources = self.committed.len() as u32;
        self.diagnostics.slice_evidence = self.slice_evidence.len() as u32;
        self.diagnostics.access_slice_evidence = self
            .slice_evidence
            .values()
            .filter(|evidence| evidence.source.is_access())
            .count() as u32;
        self.diagnostics.source_generation = self.source_generation;
        self.diagnostics.analyzed = self.assessment.is_some();
    }
}

fn evidence_targets_in_state(state: &RepairState, evidence: &CommittedFileEvidence) -> Vec<FileId> {
    state
        .files
        .iter()
        .filter(|file| {
            file.recoverable
                && file.length == evidence.expected_length()
                && evidence
                    .bound_file_id()
                    .is_none_or(|file_id| file.file_id == file_id)
                && evidence.full_md5().map_or_else(
                    || {
                        evidence.hash_16k() == Some(file.hash_16k)
                            && evidence.assembly_crc32().is_some_and(|crc32| {
                                state.set.expected_file_crc32(file.file_id) == Some(crc32)
                            })
                    },
                    |full_md5| full_md5 == file.hash_full,
                )
        })
        .map(|file| file.file_id)
        .collect()
}

fn apply_committed_evidence_to_state(
    state: &mut RepairState,
    evidence: &CommittedFileEvidence,
) -> bool {
    let targets = evidence_targets_in_state(state, evidence);
    if targets.len() != 1 {
        return false;
    }
    state.seed_complete_location(
        targets[0],
        SourceLocation::Path(evidence.path().to_path_buf()),
    )
}

fn apply_slice_evidence_to_state(
    state: &mut RepairState,
    slice_evidence: &HashMap<(FileId, u32), RetainedSliceEvidence>,
) {
    for (&(file_id, slice_index), evidence) in slice_evidence {
        if evidence.valid {
            state.seed_block_location(file_id, slice_index, evidence.source.clone());
        }
    }
}

/// Drop retained locations backed by `source`. Paths invalidate by path;
/// access-backed sources invalidate by the file identity they name, which is
/// the only handle they have.
fn invalidate_source_in_state(state: &mut RepairState, source: &SourceLocation) {
    match source {
        SourceLocation::Path(path) => {
            state.invalidate_path(path);
        }
        SourceLocation::Access(file_id) => {
            state.invalidate_file(*file_id);
        }
    }
}

fn repairer_options(options: &Par2RepairSessionOptions, repair: bool) -> Par2RepairerOptions {
    let mut out = Par2RepairerOptions::new(options.base_dir.clone(), options.par2_paths.clone());
    out.extra_paths = options.extra_paths.clone();
    out.repair = repair;
    out.memory_limit = options.memory_limit;
    out.rename_only = options.rename_only;
    out.scan_skip_data = options.scan_skip_data;
    out.scan_skip_leeway = options.scan_skip_leeway;
    out.cancel = options.cancel.clone();
    out.progress = options.progress.clone();
    out
}

fn evidence_stat_matches(evidence: &CommittedFileEvidence) -> Result<bool, Par2SessionError> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(evidence.path()).map_err(|_| Par2SessionError::SourceChanged {
        path: evidence.path().to_path_buf(),
    })?;
    let fingerprint = evidence.stat_fingerprint();
    Ok(!(metadata.len() != evidence.expected_length()
        || metadata.len() != fingerprint.length()
        || metadata.modified().ok() != fingerprint.modified()
        || {
            #[cfg(unix)]
            {
                metadata.dev() != fingerprint.device() || metadata.ino() != fingerprint.inode()
            }
            #[cfg(not(unix))]
            {
                false
            }
        }))
}

fn map_par2_error(error: Par2Error) -> Par2SessionError {
    match error {
        Par2Error::Io(source) => {
            let message = source.to_string();
            if let Some(path) = message.strip_prefix("PAR2 source changed: ") {
                return Par2SessionError::SourceChanged {
                    path: PathBuf::from(path),
                };
            }
            Par2SessionError::Par2(Par2Error::Io(source))
        }
        error => Par2SessionError::Par2(error),
    }
}

fn committed_evidence_bytes(evidence: &CommittedFileEvidence) -> usize {
    std::mem::size_of::<CommittedFileEvidence>()
        .saturating_add(evidence.path().as_os_str().len())
        .saturating_add(evidence.logical_name().len())
}

/// Bytes retained per slice verdict: the record itself plus whatever its
/// source owns on the heap. A path owns its bytes; a [`FileId`] lives inline
/// in the record and owns nothing further.
fn retained_slice_evidence_bytes(evidence: &RetainedSliceEvidence) -> usize {
    std::mem::size_of::<RetainedSliceEvidence>().saturating_add(match &evidence.source {
        SourceLocation::Path(path) => path.as_os_str().len(),
        SourceLocation::Access(_) => 0,
    })
}

fn retained_path_buf_bytes(path: &Path) -> usize {
    std::mem::size_of::<PathBuf>().saturating_add(path.as_os_str().len())
}

fn retained_path_bytes(paths: &[PathBuf]) -> usize {
    paths.iter().map(|path| retained_path_buf_bytes(path)).sum()
}

fn assessment_bytes(outcome: &Par2RepairOutcome) -> usize {
    std::mem::size_of::<Par2RepairOutcome>().saturating_add(
        outcome
            .verification
            .files
            .iter()
            .map(|file| {
                std::mem::size_of_val(file)
                    .saturating_add(file.filename.capacity())
                    .saturating_add(file.valid_slices.capacity())
            })
            .sum::<usize>(),
    )
}

const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Par2RepairSession>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;
    use crate::evidence::ContiguousAssemblyProof;
    use crate::packet::RecoverySliceData;
    use crate::par2_set::{FileDescription, Par2FileSet, RecoverySlice};
    use crate::session::SliceEvidenceStrength;
    use crate::types::{RecoverySetId, SliceChecksum};
    use crate::verify::MemoryFileAccess;
    use std::collections::BTreeMap;

    fn session_from_set(options: Par2RepairSessionOptions, set: Par2FileSet) -> Par2RepairSession {
        Par2RepairSession {
            state: RepairState::from_set_with_access(
                &options.base_dir,
                set,
                options.source_access.clone(),
            )
            .unwrap(),
            options,
            packet_diagnostics: PacketDiagnostics::default(),
            committed: Vec::new(),
            slice_evidence: HashMap::new(),
            merged_recovery_paths: HashSet::new(),
            sources_scanned: false,
            source_generation: 0,
            diagnostics: Par2RepairSessionDiagnostics::default(),
            assessment: None,
        }
    }

    fn empty_session(recovery_set_id: RecoverySetId) -> Par2RepairSession {
        session_from_set(
            Par2RepairSessionOptions::default(),
            Par2FileSet {
                recovery_set_id,
                slice_size: 4,
                recovery_file_ids: Vec::new(),
                non_recovery_file_ids: Vec::new(),
                files: HashMap::new(),
                slice_checksums: HashMap::new(),
                recovery_slices: BTreeMap::new(),
                creator: None,
            },
        )
    }

    fn single_file_set(
        recovery_set_id: RecoverySetId,
        file_id: FileId,
        filename: &str,
        payload: &[u8],
        slice_size: usize,
    ) -> Par2FileSet {
        let description = FileDescription {
            file_id,
            hash_full: checksum::md5(payload),
            hash_16k: checksum::md5(&payload[..payload.len().min(16 * 1024)]),
            length: payload.len() as u64,
            par2_name: filename.to_owned(),
            filename: filename.to_owned(),
        };
        let checksums = payload
            .chunks(slice_size)
            .map(|slice| {
                let mut state = checksum::SliceChecksumState::new();
                state.update(slice);
                let (crc32, md5) = state.finalize(Some(slice_size as u64));
                SliceChecksum { crc32, md5 }
            })
            .collect();
        Par2FileSet {
            recovery_set_id,
            slice_size: slice_size as u64,
            recovery_file_ids: vec![file_id],
            non_recovery_file_ids: Vec::new(),
            files: HashMap::from([(file_id, description)]),
            slice_checksums: HashMap::from([(file_id, checksums)]),
            recovery_slices: BTreeMap::new(),
            creator: None,
        }
    }

    fn write_packet(
        path: &Path,
        recovery_set_id: RecoverySetId,
        packet_type: &[u8; 16],
        body: &[u8],
    ) {
        let mut hash_input = Vec::with_capacity(32 + body.len());
        hash_input.extend_from_slice(recovery_set_id.as_bytes());
        hash_input.extend_from_slice(packet_type);
        hash_input.extend_from_slice(body);
        let mut packet = Vec::with_capacity(crate::packet::HEADER_SIZE + body.len());
        packet.extend_from_slice(crate::packet::MAGIC);
        packet.extend_from_slice(
            &(crate::packet::HEADER_SIZE as u64 + body.len() as u64).to_le_bytes(),
        );
        packet.extend_from_slice(&checksum::md5(&hash_input));
        packet.extend_from_slice(recovery_set_id.as_bytes());
        packet.extend_from_slice(packet_type);
        packet.extend_from_slice(body);
        fs::write(path, packet).unwrap();
    }

    fn write_creator_packet(path: &Path, recovery_set_id: RecoverySetId, creator_len: usize) {
        let mut body = vec![b'x'; creator_len];
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        write_packet(
            path,
            recovery_set_id,
            crate::packet::header::TYPE_CREATOR,
            &body,
        );
    }

    #[test]
    fn rejects_slice_evidence_from_another_recovery_set() {
        let set_id = RecoverySetId::from_bytes([1; 16]);
        let mut session = empty_session(set_id);
        let evidence = SliceEvidence::for_test(
            RecoverySetId::from_bytes([2; 16]),
            FileId::from_bytes([3; 16]),
            0,
            true,
            SliceEvidenceStrength::Crc32AndMd5,
        );

        assert!(matches!(
            session.add_slice_evidence("payload.bin", evidence),
            Err(Par2SessionError::Par2(Par2Error::ConflictingRecoverySet))
        ));
    }

    #[test]
    fn rejects_crc_only_slice_evidence_for_repair() {
        let set_id = RecoverySetId::from_bytes([1; 16]);
        let mut session = empty_session(set_id);
        let evidence = SliceEvidence::for_test(
            set_id,
            FileId::from_bytes([3; 16]),
            0,
            true,
            SliceEvidenceStrength::Crc32Only,
        );

        assert!(matches!(
            session.add_slice_evidence("payload.bin", evidence),
            Err(Par2SessionError::InvalidState { .. })
        ));
    }

    #[test]
    fn assessment_and_repair_require_analysis() {
        let mut session = empty_session(RecoverySetId::from_bytes([1; 16]));

        assert!(matches!(
            session.assessment(),
            Err(Par2SessionError::InvalidState { .. })
        ));
        assert!(matches!(
            session.repair(),
            Err(Par2SessionError::InvalidState { .. })
        ));
    }

    #[test]
    fn analyze_limit_rejection_discards_scanned_locations() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"data";
        fs::write(dir.path().join("payload.bin"), payload).unwrap();
        let recovery_set_id = RecoverySetId::from_bytes([1; 16]);
        let file_id = FileId::from_bytes([2; 16]);
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            single_file_set(recovery_set_id, file_id, "payload.bin", payload, 4),
        );
        session.options.retained_state_limit = session.estimated_retained_bytes();

        assert!(matches!(
            session.analyze(),
            Err(Par2SessionError::RetainedStateLimitExceeded { .. })
        ));
        assert!(!session.sources_scanned);
        assert!(session.assessment.is_none());
        assert!(
            session
                .state
                .blocks
                .iter()
                .all(|block| block.location.is_none())
        );
        assert!(session.estimated_retained_bytes() <= session.options.retained_state_limit);
    }

    #[test]
    fn creator_only_recovery_merge_obeys_exact_retained_limit_transactionally() {
        let dir = tempfile::tempdir().unwrap();
        let recovery_set_id = RecoverySetId::from_bytes([7; 16]);
        let path = dir.path().join("creator.vol.par2");
        write_creator_packet(&path, recovery_set_id, 64 * 1024);
        let mut session = empty_session(recovery_set_id);
        let before = session.estimated_retained_bytes();
        session.options.retained_state_limit =
            before.saturating_add(retained_path_buf_bytes(&path));

        assert!(matches!(
            session.merge_recovery_paths([&path]),
            Err(Par2SessionError::RetainedStateLimitExceeded { .. })
        ));
        assert!(session.state.set.creator.is_none());
        assert!(session.merged_recovery_paths.is_empty());
        assert_eq!(session.diagnostics().recovery_paths_merged, 0);
        assert_eq!(session.estimated_retained_bytes(), before);
    }

    #[test]
    fn strong_slice_evidence_uses_its_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"live";
        let path = dir.path().join("payload.bin");
        fs::write(&path, payload).unwrap();
        let set_id = RecoverySetId::from_bytes([1; 16]);
        let file_id = FileId::from_bytes([3; 16]);
        let mut files = HashMap::new();
        files.insert(
            file_id,
            FileDescription {
                file_id,
                hash_full: checksum::md5(payload),
                hash_16k: checksum::md5(payload),
                length: payload.len() as u64,
                par2_name: "payload.bin".to_owned(),
                filename: "payload.bin".to_owned(),
            },
        );
        let mut slice_checksums = HashMap::new();
        slice_checksums.insert(
            file_id,
            vec![SliceChecksum {
                crc32: checksum::crc32(payload),
                md5: checksum::md5(payload),
            }],
        );
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            Par2FileSet {
                recovery_set_id: set_id,
                slice_size: payload.len() as u64,
                recovery_file_ids: vec![file_id],
                non_recovery_file_ids: Vec::new(),
                files,
                slice_checksums,
                recovery_slices: BTreeMap::new(),
                creator: None,
            },
        );
        let evidence =
            SliceEvidence::for_test(set_id, file_id, 0, true, SliceEvidenceStrength::Crc32AndMd5);

        session.add_slice_evidence(&path, evidence).unwrap();
        assert_eq!(session.diagnostics().live_slices, 1);
        assert_eq!(
            session.analyze().unwrap().status,
            Par2RepairStatus::Verified
        );
        let scan_passes = session.diagnostics().source_scan_passes;
        session.add_slice_evidence(&path, evidence).unwrap();
        assert_eq!(session.diagnostics().live_slices, 1);
        assert_eq!(session.diagnostics().source_scan_passes, scan_passes);
        assert!(session.assessment().is_ok());
        session.invalidate_path(&path);
        assert_eq!(session.diagnostics().slice_evidence, 0);
    }

    #[test]
    fn unusable_lazy_recovery_updates_assessment_without_rescanning_sources() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"data";
        let recovery_path = dir.path().join("recovery.bin");
        fs::write(&recovery_path, b"bad!").unwrap();
        let set_id = RecoverySetId::from_bytes([1; 16]);
        let file_id = FileId::from_bytes([3; 16]);
        let mut files = HashMap::new();
        files.insert(
            file_id,
            FileDescription {
                file_id,
                hash_full: checksum::md5(payload),
                hash_16k: checksum::md5(payload),
                length: payload.len() as u64,
                par2_name: "payload.bin".to_owned(),
                filename: "payload.bin".to_owned(),
            },
        );
        let mut slice_checksums = HashMap::new();
        slice_checksums.insert(
            file_id,
            vec![SliceChecksum {
                crc32: checksum::crc32(payload),
                md5: checksum::md5(payload),
            }],
        );
        let mut recovery_slices = BTreeMap::new();
        recovery_slices.insert(
            0,
            RecoverySlice {
                exponent: 0,
                data: RecoverySliceData::file_backed_with_hash(
                    recovery_path,
                    0,
                    payload.len(),
                    [0; 16],
                ),
            },
        );
        recovery_slices.insert(
            1,
            RecoverySlice {
                exponent: 1,
                data: RecoverySliceData::file_backed_with_hash(
                    dir.path().join("missing-recovery.bin"),
                    0,
                    payload.len(),
                    [0; 16],
                ),
            },
        );
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            Par2FileSet {
                recovery_set_id: set_id,
                slice_size: payload.len() as u64,
                recovery_file_ids: vec![file_id],
                non_recovery_file_ids: Vec::new(),
                files,
                slice_checksums,
                recovery_slices,
                creator: None,
            },
        );

        assert_eq!(
            session.analyze().unwrap().status,
            Par2RepairStatus::RepairPossible
        );
        let scan_passes = session.diagnostics().source_scan_passes;
        let outcome = session.repair().unwrap();
        assert_eq!(outcome.status, Par2RepairStatus::Insufficient);
        assert_eq!(session.diagnostics().source_scan_passes, scan_passes);
        assert_eq!(session.diagnostics().recovery_packets_rejected, 2);
        assert!(!dir.path().join("payload.bin").exists());
    }

    #[test]
    fn renamed_full_md5_evidence_requires_unique_or_explicit_identity() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"same-content";
        let path = dir.path().join("download-name.bin");
        fs::write(&path, payload).unwrap();
        let set_id = RecoverySetId::from_bytes([1; 16]);
        let first_id = FileId::from_bytes([2; 16]);
        let second_id = FileId::from_bytes([3; 16]);
        let description = |file_id, name: &str| FileDescription {
            file_id,
            hash_full: checksum::md5(payload),
            hash_16k: checksum::md5(payload),
            length: payload.len() as u64,
            par2_name: name.to_owned(),
            filename: name.to_owned(),
        };
        let files = HashMap::from([
            (first_id, description(first_id, "original-a.bin")),
            (second_id, description(second_id, "original-b.bin")),
        ]);
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            Par2FileSet {
                recovery_set_id: set_id,
                slice_size: payload.len() as u64,
                recovery_file_ids: vec![first_id, second_id],
                non_recovery_file_ids: Vec::new(),
                files,
                slice_checksums: HashMap::new(),
                recovery_slices: BTreeMap::new(),
                creator: None,
            },
        );
        let ambiguous = CommittedFileEvidence::from_full_md5_path(
            &path,
            "download-name.bin",
            payload.len() as u64,
            checksum::md5(payload),
            None,
        )
        .unwrap();

        assert!(matches!(
            session.add_committed_file(ambiguous),
            Err(Par2SessionError::EvidenceDoesNotMatch { .. })
        ));
        assert_eq!(session.diagnostics().quick_proof_fallbacks, 1);

        let bound = CommittedFileEvidence::from_full_md5_path(
            &path,
            "download-name.bin",
            payload.len() as u64,
            checksum::md5(payload),
            Some(first_id),
        )
        .unwrap();
        session.add_committed_file(bound).unwrap();
        assert_eq!(session.diagnostics().quick_proof_hits, 1);
    }

    #[test]
    fn committed_evidence_fingerprint_is_rechecked_before_cached_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"registered-source";
        let path = dir.path().join("renamed.bin");
        fs::write(&path, payload).unwrap();
        let set_id = RecoverySetId::from_bytes([0x51; 16]);
        let file_id = FileId::from_bytes([0x52; 16]);
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            single_file_set(set_id, file_id, "canonical.bin", payload, payload.len()),
        );
        let evidence = CommittedFileEvidence::from_full_md5_path(
            &path,
            "renamed.bin",
            payload.len() as u64,
            checksum::md5(payload),
            Some(file_id),
        )
        .unwrap();
        session.add_committed_file(evidence).unwrap();
        assert_eq!(
            session.analyze().unwrap().status,
            Par2RepairStatus::RepairPossible
        );

        fs::write(&path, b"registered-source-changed").unwrap();
        assert!(matches!(
            session.analyze(),
            Err(Par2SessionError::SourceChanged { path: changed }) if changed == path
        ));
        assert!(matches!(
            session.repair(),
            Err(Par2SessionError::SourceChanged { path: changed }) if changed == path
        ));
    }

    #[test]
    fn evidence_budget_rejection_is_transactional() {
        let dir = tempfile::tempdir().unwrap();
        let mut parent = dir.path().to_path_buf();
        for index in 0..8 {
            parent.push(format!("long-evidence-component-{index:02}-xxxxxxxx"));
        }
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("renamed.bin");
        let payload = vec![0xA5; 64];
        fs::write(&path, &payload).unwrap();
        let set_id = RecoverySetId::from_bytes([0x61; 16]);
        let file_id = FileId::from_bytes([0x62; 16]);
        let mut session = session_from_set(
            Par2RepairSessionOptions {
                base_dir: dir.path().to_path_buf(),
                ..Par2RepairSessionOptions::default()
            },
            single_file_set(set_id, file_id, "canonical.bin", &payload, 1),
        );
        let evidence = CommittedFileEvidence::from_full_md5_path(
            &path,
            "renamed.bin",
            payload.len() as u64,
            checksum::md5(&payload),
            Some(file_id),
        )
        .unwrap();
        let before = session.estimated_retained_bytes();
        session.options.retained_state_limit =
            before.saturating_add(committed_evidence_bytes(&evidence));

        assert!(matches!(
            session.add_committed_file(evidence),
            Err(Par2SessionError::RetainedStateLimitExceeded { .. })
        ));
        assert_eq!(session.estimated_retained_bytes(), before);
        assert!(session.committed.is_empty());
        assert!(
            session
                .state
                .files
                .iter()
                .all(|file| file.complete_location.is_none())
        );
        assert!(
            session
                .state
                .blocks
                .iter()
                .all(|block| block.location.is_none())
        );

        let slice =
            SliceEvidence::for_test(set_id, file_id, 0, true, SliceEvidenceStrength::Crc32AndMd5);
        session.options.retained_state_limit = before;
        assert!(matches!(
            session.add_slice_evidence(&path, slice),
            Err(Par2SessionError::RetainedStateLimitExceeded { .. })
        ));
        assert_eq!(session.estimated_retained_bytes(), before);
        assert!(session.slice_evidence.is_empty());
        assert!(session.state.blocks[0].location.is_none());
    }

    #[test]
    fn retained_limit_defaults_to_64_mib() {
        assert_eq!(
            Par2RepairSessionOptions::default().retained_state_limit,
            DEFAULT_RETAINED_STATE_LIMIT
        );
    }

    #[test]
    fn retained_preflight_accounts_for_large_block_maps() {
        let file_id = FileId::from_bytes([7; 16]);
        let mut files = HashMap::new();
        files.insert(
            file_id,
            FileDescription {
                file_id,
                hash_full: [0; 16],
                hash_16k: [0; 16],
                length: 8_192 * 4,
                par2_name: "large.bin".to_owned(),
                filename: "large.bin".to_owned(),
            },
        );
        let mut slice_checksums = HashMap::new();
        slice_checksums.insert(
            file_id,
            vec![
                SliceChecksum {
                    crc32: 0,
                    md5: [0; 16],
                };
                8_192
            ],
        );
        let set = Par2FileSet {
            recovery_set_id: RecoverySetId::from_bytes([1; 16]),
            slice_size: 4,
            recovery_file_ids: vec![file_id],
            non_recovery_file_ids: Vec::new(),
            files,
            slice_checksums,
            recovery_slices: BTreeMap::new(),
            creator: None,
        };

        let preflight = RepairState::estimated_retained_bytes_from_set(Path::new("."), &set);
        let state = RepairState::from_set(Path::new("."), set).unwrap();
        assert!(preflight > 1024 * 1024);
        assert!(preflight >= state.estimated_retained_bytes());
    }

    fn access_session(
        dir: &Path,
        set: Par2FileSet,
        access: Arc<dyn FileAccess + Send + Sync>,
    ) -> Par2RepairSession {
        let mut options = Par2RepairSessionOptions::new(dir.to_path_buf(), Vec::new());
        options.source_access = Some(access);
        session_from_set(options, set)
    }

    fn strong_evidence(
        set_id: RecoverySetId,
        file_id: FileId,
        slice_index: u32,
        valid: bool,
    ) -> SliceEvidence {
        SliceEvidence::for_test(
            set_id,
            file_id,
            slice_index,
            valid,
            SliceEvidenceStrength::Crc32AndMd5,
        )
    }

    /// A session over virtual sources resolves what evidence named and nothing
    /// else, and never records a scan pass — `base_dir` holds no sources.
    #[test]
    fn access_backed_analysis_resolves_evidence_without_scanning() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"eight-bytes-of-payload!!";
        let set_id = RecoverySetId::from_bytes([0x11; 16]);
        let file_id = FileId::from_bytes([0x12; 16]);
        // A decoy with the right name and length sits where a scan would find
        // it. Its bytes are wrong, so resolving through it would be visible.
        fs::write(dir.path().join("payload.bin"), vec![0xEE; payload.len()]).unwrap();
        let mut memory = MemoryFileAccess::new();
        memory.add_file(file_id, payload.to_vec());
        let mut session = access_session(
            dir.path(),
            single_file_set(set_id, file_id, "payload.bin", payload, 8),
            Arc::new(memory),
        );

        session
            .add_slice_evidence_for_file(strong_evidence(set_id, file_id, 0, true))
            .unwrap();
        let assessment = session.analyze().unwrap();

        assert_eq!(assessment.status, Par2RepairStatus::Insufficient);
        assert_eq!(assessment.available_blocks, 1);
        assert_eq!(assessment.missing_blocks, 2);
        assert_eq!(session.diagnostics().source_scan_passes, 0);
        assert_eq!(session.diagnostics().scan.files_scanned, 0);
        assert_eq!(session.diagnostics().scan.bytes_scanned, 0);
        assert_eq!(session.diagnostics().access_slice_evidence, 1);
    }

    /// All slices seeded through the handle promote the file to complete, with
    /// no `stat` on the decoy that shares its name.
    #[test]
    fn fully_seeded_access_file_verifies_without_touching_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"sixteen-byte-pay";
        let set_id = RecoverySetId::from_bytes([0x21; 16]);
        let file_id = FileId::from_bytes([0x22; 16]);
        fs::write(dir.path().join("payload.bin"), vec![0xEE; payload.len()]).unwrap();
        let mut memory = MemoryFileAccess::new();
        memory.add_file(file_id, payload.to_vec());
        let mut session = access_session(
            dir.path(),
            single_file_set(set_id, file_id, "payload.bin", payload, 8),
            Arc::new(memory),
        );

        for slice_index in 0..2 {
            session
                .add_slice_evidence_for_file(strong_evidence(set_id, file_id, slice_index, true))
                .unwrap();
        }

        assert_eq!(
            session.analyze().unwrap().status,
            Par2RepairStatus::Verified
        );
    }

    #[test]
    fn invalidate_file_forgets_access_locations_and_resets_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"sixteen-byte-pay";
        let set_id = RecoverySetId::from_bytes([0x31; 16]);
        let file_id = FileId::from_bytes([0x32; 16]);
        let mut memory = MemoryFileAccess::new();
        memory.add_file(file_id, payload.to_vec());
        let mut session = access_session(
            dir.path(),
            single_file_set(set_id, file_id, "payload.bin", payload, 8),
            Arc::new(memory),
        );
        let empty_bytes = session.estimated_retained_bytes();
        for slice_index in 0..2 {
            session
                .add_slice_evidence_for_file(strong_evidence(set_id, file_id, slice_index, true))
                .unwrap();
        }
        session.analyze().unwrap();
        let seeded_bytes = session.estimated_retained_bytes();
        assert!(seeded_bytes > empty_bytes);

        assert!(session.invalidate_file(file_id));

        assert!(session.slice_evidence.is_empty());
        assert_eq!(session.diagnostics().slice_evidence, 0);
        assert_eq!(session.diagnostics().access_slice_evidence, 0);
        assert!(session.assessment.is_none());
        assert!(matches!(
            session.assessment(),
            Err(Par2SessionError::InvalidState { .. })
        ));
        assert!(
            session
                .state
                .blocks
                .iter()
                .all(|block| block.location.is_none())
        );
        assert!(
            session
                .state
                .files
                .iter()
                .all(|file| file.complete_location.is_none())
        );
        assert!(session.estimated_retained_bytes() < seeded_bytes);
        assert!(!session.invalidate_file(file_id));
    }

    /// The generation is the cheap thing a caller compares. Bumping it retires
    /// every virtual location at once and leaves physical ones alone.
    #[test]
    fn access_source_generation_bump_retires_only_virtual_locations() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"sixteen-byte-pay";
        let path = dir.path().join("payload.bin");
        fs::write(&path, payload).unwrap();
        let set_id = RecoverySetId::from_bytes([0x41; 16]);
        let file_id = FileId::from_bytes([0x42; 16]);
        let mut memory = MemoryFileAccess::new();
        memory.add_file(file_id, payload.to_vec());
        let mut session = access_session(
            dir.path(),
            single_file_set(set_id, file_id, "payload.bin", payload, 8),
            Arc::new(memory),
        );
        assert_eq!(session.source_generation(), 0);

        session
            .add_slice_evidence(&path, strong_evidence(set_id, file_id, 0, true))
            .unwrap();
        session
            .add_slice_evidence_for_file(strong_evidence(set_id, file_id, 1, true))
            .unwrap();
        assert_eq!(session.diagnostics().slice_evidence, 2);
        assert_eq!(session.diagnostics().access_slice_evidence, 1);
        let seeded_bytes = session.estimated_retained_bytes();

        assert_eq!(session.invalidate_access_sources(), 1);

        assert_eq!(session.source_generation(), 1);
        assert_eq!(session.diagnostics().source_generation, 1);
        assert_eq!(session.diagnostics().slice_evidence, 1);
        assert_eq!(session.diagnostics().access_slice_evidence, 0);
        assert!(session.state.blocks[0].location.is_some());
        assert!(session.state.blocks[1].location.is_none());
        assert!(session.estimated_retained_bytes() < seeded_bytes);

        // Monotonic: a second bump moves forward, never back.
        assert_eq!(session.invalidate_access_sources(), 2);
        assert!(session.state.blocks[0].location.is_some());
    }

    /// A FileId owns no heap, but the record holding it does. The budget must
    /// see that record, or a session could retain evidence for free.
    #[test]
    fn access_keyed_slice_evidence_obeys_the_retained_limit() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"sixteen-byte-pay";
        let set_id = RecoverySetId::from_bytes([0x51; 16]);
        let file_id = FileId::from_bytes([0x52; 16]);
        let mut memory = MemoryFileAccess::new();
        memory.add_file(file_id, payload.to_vec());
        let mut session = access_session(
            dir.path(),
            single_file_set(set_id, file_id, "payload.bin", payload, 8),
            Arc::new(memory),
        );
        let before = session.estimated_retained_bytes();
        session.options.retained_state_limit = before;

        assert!(matches!(
            session.add_slice_evidence_for_file(strong_evidence(set_id, file_id, 0, true)),
            Err(Par2SessionError::RetainedStateLimitExceeded { .. })
        ));
        assert_eq!(session.estimated_retained_bytes(), before);
        assert!(session.slice_evidence.is_empty());
        assert!(session.state.blocks[0].location.is_none());

        // One record's worth of headroom is exactly enough for one record.
        let record_bytes = std::mem::size_of::<(FileId, u32)>()
            .saturating_add(std::mem::size_of::<RetainedSliceEvidence>());
        session.options.retained_state_limit = before.saturating_add(record_bytes);
        session
            .add_slice_evidence_for_file(strong_evidence(set_id, file_id, 0, true))
            .unwrap();
        assert_eq!(session.diagnostics().access_slice_evidence, 1);
    }

    #[test]
    fn contiguous_evidence_stat_binding_rejects_size_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("assembled.bin");
        let original = b"contiguous-article-data";
        fs::write(&path, original).unwrap();
        let proof = ContiguousAssemblyProof::try_new(
            original.len() as u64,
            original.len() as u64,
            original.len() as u64,
            false,
            false,
            false,
            true,
        )
        .unwrap();
        let evidence = CommittedFileEvidence::from_contiguous_assembly_path(
            &path,
            "assembled.bin",
            original.len() as u64,
            checksum::crc32(original),
            checksum::md5(original),
            proof,
            None,
        )
        .unwrap();
        assert!(evidence_stat_matches(&evidence).unwrap());

        fs::write(&path, b"contiguous-article-data!").unwrap();
        assert!(!evidence_stat_matches(&evidence).unwrap());
    }
}
