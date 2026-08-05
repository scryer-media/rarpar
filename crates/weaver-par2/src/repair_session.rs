//! Retained PAR2 repair orchestration.
//!
//! Unlike [`crate::repairer::Par2Repairer`], this API keeps parsed packet
//! metadata and verified source locations across assessment and repair. It
//! deliberately retains no open file handles or mapped data; repair reopens
//! and validates every source as bytes are copied or consumed.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::error::Par2Error;
use crate::evidence::CommittedFileEvidence;
use crate::packet::{Packet, scan_packets_from_path_with_set_ids};
use crate::par2_set::MergeResult;
use crate::repair::{DEFAULT_REPAIR_MEMORY_LIMIT, repair_matrix_resource_limit_reason};
use crate::repairer::{
    PacketDiagnostics, Par2RepairOutcome, Par2RepairStatus, Par2Repairer, Par2RepairerOptions,
    RepairInstall, RepairState, RepairVerificationAccess, ScanDiagnostics,
};
use crate::session::{SliceEvidence, SliceEvidenceStrength};
use crate::types::{CancellationToken, FileId, ProgressCallback};
use crate::verify::{self, FileStatus, Repairability, VerificationResult};

/// Default upper bound for memory owned by a retained repair session.
pub const DEFAULT_RETAINED_STATE_LIMIT: usize = 64 * 1024 * 1024;

/// Options used to open a [`Par2RepairSession`].
#[derive(Clone)]
pub struct Par2RepairSessionOptions {
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
}

impl Par2RepairSessionOptions {
    pub fn new(base_dir: PathBuf, par2_paths: Vec<PathBuf>) -> Self {
        Self {
            base_dir,
            par2_paths,
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
        }
    }
}

/// Diagnostics accumulated by the retained session.
#[derive(Debug, Clone, Default)]
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
    path: PathBuf,
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
        let state = RepairState::from_set(&options.base_dir, inventory.set)?;
        let mut session = Self {
            options,
            state,
            packet_diagnostics: inventory.diagnostics,
            committed: Vec::new(),
            slice_evidence: HashMap::new(),
            merged_recovery_paths: HashSet::new(),
            sources_scanned: false,
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

    /// Add independently captured committed-file evidence. Full MD5 evidence
    /// seeds a whole-file location. Contiguous CRC32 + 16 KiB evidence is
    /// quick-proved against its captured path and also seeds a complete file.
    pub fn add_committed_file(
        &mut self,
        evidence: CommittedFileEvidence,
    ) -> Result<(), Par2SessionError> {
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
        let path_budget = self
            .state
            .complete_location_path_budget(targets[0], evidence.path())
            .ok_or_else(|| Par2SessionError::EvidenceDoesNotMatch {
                logical_name: evidence.logical_name().to_owned(),
            })?;
        let projected = self
            .estimated_retained_bytes()
            .saturating_add(committed_evidence_bytes(&evidence))
            .saturating_add(path_budget);
        self.ensure_limit(projected)?;
        if !self
            .state
            .seed_complete_location(targets[0], evidence.path().to_path_buf())
        {
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
    pub fn add_slice_evidence(
        &mut self,
        path: impl Into<PathBuf>,
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
            path: path.into(),
            valid: evidence.is_valid(),
        };
        if self.slice_evidence.get(&key) == Some(&retained) {
            return Ok(());
        }
        let Some(location_budget) = self.state.block_location_path_budget(
            evidence.file_id(),
            evidence.slice_index(),
            &retained.path,
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
            self.state.invalidate_path(&old.path);
        }
        self.slice_evidence.insert(key, retained.clone());
        if evidence.is_valid() {
            self.state.seed_block_location(
                evidence.file_id(),
                evidence.slice_index(),
                retained.path,
            );
        } else {
            self.state.invalidate_path(&retained.path);
        }
        self.diagnostics.live_slices = self.diagnostics.live_slices.saturating_add(1);
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
        Ok(())
    }

    /// Analyze sources once. Repeated calls return the cached assessment.
    pub fn analyze(&mut self) -> Result<Par2RepairOutcome, Par2SessionError> {
        self.ensure_committed_sources_unchanged()?;
        if let Some(assessment) = &self.assessment {
            return Ok(assessment.clone());
        }
        let scan = if self.sources_scanned {
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
    pub fn invalidate_path(&mut self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        self.state.invalidate_path(path);
        self.committed.retain(|evidence| evidence.path() != path);
        self.slice_evidence
            .retain(|_, evidence| evidence.path != path);
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
    }

    /// Forget every retained source location and evidence while retaining the
    /// parsed packet set and lazily selected recovery packets.
    pub fn invalidate_all_sources(&mut self) {
        self.state.invalidate_all_sources();
        self.committed.clear();
        self.slice_evidence.clear();
        self.sources_scanned = false;
        self.assessment = None;
        self.refresh_diagnostics();
    }

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
    state.seed_complete_location(targets[0], evidence.path().to_path_buf())
}

fn apply_slice_evidence_to_state(
    state: &mut RepairState,
    slice_evidence: &HashMap<(FileId, u32), RetainedSliceEvidence>,
) {
    for (&(file_id, slice_index), evidence) in slice_evidence {
        if evidence.valid {
            state.seed_block_location(file_id, slice_index, evidence.path.clone());
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

fn retained_slice_evidence_bytes(evidence: &RetainedSliceEvidence) -> usize {
    std::mem::size_of::<RetainedSliceEvidence>().saturating_add(evidence.path.as_os_str().len())
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
    use std::collections::BTreeMap;

    fn session_from_set(options: Par2RepairSessionOptions, set: Par2FileSet) -> Par2RepairSession {
        Par2RepairSession {
            state: RepairState::from_set(&options.base_dir, set).unwrap(),
            options,
            packet_diagnostics: PacketDiagnostics::default(),
            committed: Vec::new(),
            slice_evidence: HashMap::new(),
            merged_recovery_paths: HashSet::new(),
            sources_scanned: false,
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
