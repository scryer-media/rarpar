//! Retained PAR3 analysis for filesystem and virtual sources.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use crate::evidence::{ExtentVerdict, FileEvidence, verify_source};
use crate::ingest::{IncrementalSet, IngestedPacket, MergeEffect, PayloadKind, PayloadRef};
use crate::layout::{BlockLayout, ExtentKind};
use crate::packet::{BlockRange, PacketBody};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, Reservation};
use crate::source::{SourceAccess, SourceId, ensure_snapshot, read_exact_at};
use crate::{Fingerprint, InputSetId, Packet, Par3Set};

#[path = "session_data.rs"]
mod data;

/// Readiness of one retained assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairStatus {
    /// Start, Root or referenced children have not all arrived.
    IncompleteMetadata,
    /// All protected files are verified.
    Complete,
    /// Enough verified data and compatible recovery are available.
    Ready,
    /// More compatible recovery is needed.
    NeedRecovery,
    /// No executable matrix covers the losses.
    Unsupported,
}

/// What a recovery downloader needs for one matrix and interleaved cohort.
#[derive(Clone, Debug)]
pub struct RecoveryRequirement {
    /// Matrix fingerprint; blocks from other matrices cannot satisfy this need.
    pub matrix: Fingerprint,
    /// Cohort index, zero for noninterleaved codes.
    pub cohort: u64,
    /// Number of cohorts. Global recovery indices satisfy `index % cohorts == cohort`.
    pub cohorts: u64,
    /// Lost input blocks in this cohort.
    pub lost: u64,
    /// Available, distinct compatible recovery indices.
    pub available: Vec<u64>,
    /// Minimum additional recovery blocks in this specific cohort.
    pub additional: u64,
}

/// One file's current state in an assessment.
#[derive(Clone, Debug)]
pub struct AssessedFile {
    /// Authenticated relative path.
    pub path: String,
    /// Explicit source binding, if present.
    pub source: Option<SourceId>,
    /// Whether all protected data is verified at its expected length.
    pub complete: bool,
    /// Consecutive verified bytes from the start of the file.
    pub verified_prefix: u64,
    /// Unknown or damaged file-coordinate ranges.
    pub unresolved: Vec<Range<u64>>,
}

/// Retained assessment. Recovery-only merges rebuild availability, not evidence.
#[derive(Debug)]
pub struct RepairAssessment {
    /// Current repair readiness.
    pub status: RepairStatus,
    /// Files in resolved path order.
    pub files: Vec<AssessedFile>,
    /// Lost logical input blocks, counted once despite aliases.
    pub lost_blocks: Vec<u64>,
    /// Download requirements for the selected matrix, by cohort.
    pub requirements: Vec<RecoveryRequirement>,
    pub(crate) matrix: Option<Packet>,
    pub(crate) recovery: Vec<PayloadRef>,
    _reservation: Reservation,
}

/// Cheap retained-session lifecycle diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionDiagnostics {
    /// Calls which produced a new assessment.
    pub assessments: u64,
    /// Calls which reused the entire assessment without any source reads.
    pub assessment_reuses: u64,
    /// Source files read by authoritative verification.
    pub source_verifications: u64,
    /// Metadata layouts actually rebuilt.
    pub layout_rebuilds: u64,
    /// Data payloads checked against the current layout, excluding cached reuse.
    pub data_validations: u64,
}

/// Retained engine state. No source file handles are retained by the session.
pub struct Par3RepairSession {
    pub(crate) options: ExecutionOptions,
    pub(crate) access: Arc<dyn SourceAccess>,
    pub(crate) input: IncrementalSet,
    pub(crate) set: Option<Par3Set>,
    pub(crate) layout: Option<Arc<BlockLayout>>,
    pub(crate) bindings: BTreeMap<String, SourceId>,
    binding_memory: BTreeMap<String, Reservation>,
    pub(crate) evidence: BTreeMap<String, FileEvidence>,
    pub(crate) placements: BTreeMap<(usize, usize), crate::placement::PlacedExtent>,
    pub(crate) assessment: Option<RepairAssessment>,
    metadata_dirty: bool,
    data_dirty: bool,
    data_checked: BTreeMap<Fingerprint, data::DataAdmission>,
    data_blocks: BTreeMap<u64, PayloadRef>,
    diagnostics: SessionDiagnostics,
}

impl Par3RepairSession {
    /// Open an empty session for a known input-set identifier. Packet carriers
    /// may use a different source provider from the protected files.
    pub fn new(
        id: InputSetId,
        access: Arc<dyn SourceAccess>,
        options: ExecutionOptions,
    ) -> EngineResult<Self> {
        let input = IncrementalSet::new(id, options.clone())?;
        Ok(Self {
            options,
            access,
            input,
            set: None,
            layout: None,
            bindings: BTreeMap::new(),
            binding_memory: BTreeMap::new(),
            evidence: BTreeMap::new(),
            placements: BTreeMap::new(),
            assessment: None,
            metadata_dirty: true,
            data_dirty: true,
            data_checked: BTreeMap::new(),
            data_blocks: BTreeMap::new(),
            diagnostics: SessionDiagnostics::default(),
        })
    }

    /// Admit an authenticated packet. Replays preserve the assessment unchanged.
    pub fn merge(&mut self, packet: IngestedPacket) -> EngineResult<MergeEffect> {
        let is_data = packet
            .payload()
            .is_some_and(|payload| matches!(payload.kind(), PayloadKind::Data { .. }));
        if !self.input.contains(&packet.hash()) {
            self.admit_retained(packet.retained_bytes())?;
        }
        let effect = self.input.merge(packet)?;
        match effect {
            MergeEffect::Replay => {}
            MergeEffect::Payload => {
                self.assessment = None;
                self.data_dirty |= is_data;
            }
            MergeEffect::Metadata => {
                self.metadata_dirty = true;
                self.assessment = None;
            }
        }
        Ok(effect)
    }

    /// Bind an authenticated relative filename to a source selected by the host.
    /// Bindings may precede metadata; no path is opened implicitly.
    pub fn bind_file(&mut self, path: &str, source: SourceId) -> EngineResult<()> {
        self.options.cancel.check()?;
        if self.bindings.get(path) == Some(&source) {
            return Ok(());
        }
        if !self.binding_memory.contains_key(path) {
            let bytes = path
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(256))
                .ok_or(EngineError::ResourceLimit("source bindings"))?;
            self.admit_retained(bytes)?;
            let reservation = self.options.memory.reserve(bytes)?;
            self.binding_memory.insert(path.to_owned(), reservation);
        }
        self.bindings.insert(path.to_owned(), source);
        self.evidence.remove(path);
        self.assessment = None;
        Ok(())
    }

    /// Invalidate evidence after replacement or rebinding. Use `source_arrived`
    /// to retain verified ranges when holes are filled in the same generation.
    pub fn invalidate_source(&mut self, source: SourceId) {
        self.evidence
            .retain(|_, evidence| evidence.source != source);
        self.placements
            .retain(|_, evidence| evidence.source != source);
        self.assessment = None;
    }

    /// Admit a BLAKE3-confirmed placement from an explicitly searched candidate.
    pub fn add_placement(
        &mut self,
        mut placement: crate::placement::PlacedExtent,
    ) -> EngineResult<()> {
        self.refresh_layout()?;
        let layout = self
            .layout
            .as_ref()
            .ok_or(EngineError::InvalidState("metadata is incomplete"))?;
        if placement.layout != layout.identity {
            return Err(EngineError::InvalidState(
                "placement belongs to another layout",
            ));
        }
        ensure_snapshot(self.access.as_ref(), placement.source, placement.snapshot)?;
        if !self
            .placements
            .contains_key(&(placement.file, placement.extent))
        {
            self.admit_retained(512)?;
        }
        placement.rehome(&self.options)?;
        self.placements
            .insert((placement.file, placement.extent), placement);
        self.assessment = None;
        Ok(())
    }

    /// Verify newly available ranges without rereading already verified extents.
    /// A changed generation is rejected; invalidate it explicitly or reassess.
    pub fn source_arrived(&mut self, source: SourceId) -> EngineResult<()> {
        self.refresh_layout()?;
        self.assessment = None;
        let Some(layout) = &self.layout else {
            return Ok(());
        };
        for evidence in self
            .evidence
            .values_mut()
            .filter(|evidence| evidence.source == source)
        {
            *evidence = crate::evidence::verify_arrivals(
                Arc::clone(layout),
                evidence,
                self.access.as_ref(),
                &self.options,
            )?;
        }
        Ok(())
    }

    /// Resolve currently available metadata, returning `None` while incomplete.
    pub fn layout(&mut self) -> EngineResult<Option<Arc<BlockLayout>>> {
        self.refresh_layout()?;
        Ok(self.layout.as_ref().map(Arc::clone))
    }

    fn refresh_layout(&mut self) -> EngineResult<()> {
        if !self.metadata_dirty {
            return Ok(());
        }
        let Some(set) = self.input.metadata()? else {
            return Ok(());
        };
        let mut options = self.options.clone();
        options.retained_bytes = options.retained_bytes.saturating_sub(self.retained_bytes());
        let layout = Arc::new(BlockLayout::new(&set, &options)?);
        if self
            .layout
            .as_ref()
            .is_none_or(|previous| previous.identity != layout.identity)
        {
            self.evidence.clear();
            self.placements.clear();
            self.data_checked.clear();
            self.data_blocks.clear();
            self.data_dirty = true;
        }
        self.layout = Some(layout);
        self.set = Some(set);
        self.metadata_dirty = false;
        self.diagnostics.layout_rebuilds += 1;
        Ok(())
    }

    /// Export retained evidence without rereading the protected source. Persist
    /// the returned digest in a trusted host manifest, separate from untrusted
    /// checkpoint bytes. A changed source generation is rejected.
    pub fn checkpoint_file(
        &mut self,
        path: &str,
    ) -> EngineResult<Option<crate::evidence::EvidenceCheckpoint>> {
        self.refresh_layout()?;
        let Some(evidence) = self.evidence.get(path) else {
            return Ok(None);
        };
        ensure_snapshot(self.access.as_ref(), evidence.source, evidence.snapshot)?;
        evidence.checkpoint(&self.options).map(Some)
    }

    /// Replay a checkpoint whose digest was retained in trusted host metadata.
    /// Never derive `trusted_digest` from the replay bytes themselves. Metadata
    /// and bindings must already be supplied; no source bytes are reread. The
    /// source identity, generation, logical length and authenticated layout must
    /// still match. No partially hashed work is restored.
    pub fn replay_evidence(&mut self, bytes: &[u8], trusted_digest: [u8; 32]) -> EngineResult<()> {
        self.refresh_layout()?;
        let layout = self
            .layout
            .as_ref()
            .ok_or(EngineError::InvalidState("metadata is incomplete"))?;
        let evidence = FileEvidence::from_checkpoint(bytes, trusted_digest, layout, &self.options)?;
        self.add_evidence(evidence)
    }

    /// Seed evidence generated by `StreamingVerifier` or restored from a
    /// checkpoint anchored by the host's trusted persistence metadata.
    pub fn add_evidence(&mut self, mut evidence: FileEvidence) -> EngineResult<()> {
        self.refresh_layout()?;
        let layout = self
            .layout
            .as_ref()
            .ok_or(EngineError::InvalidState("metadata is incomplete"))?;
        evidence.check_layout(layout)?;
        let path = &layout.files[evidence.file].path;
        if self.bindings.get(path) != Some(&evidence.source) {
            return Err(EngineError::InvalidState(
                "evidence source is not bound to this file",
            ));
        }
        ensure_snapshot(self.access.as_ref(), evidence.source, evidence.snapshot)?;
        let previous = self
            .evidence
            .get(path)
            .map_or(0, FileEvidence::retained_bytes);
        self.admit_retained(evidence.retained_bytes().saturating_sub(previous))?;
        evidence.rehome(&self.options)?;
        self.evidence.insert(path.clone(), evidence);
        self.assessment = None;
        Ok(())
    }

    /// Assess losses and precise recovery requirements. Unchanged evidence costs
    /// only source snapshot checks; a recovery merge never triggers source reads.
    pub fn assess(&mut self) -> EngineResult<&RepairAssessment> {
        let _progress = self.options.stage(crate::runtime::Stage::Assess)?;
        match self.input.discard_changed_payloads() {
            Ok(0) => {}
            Ok(_) => {
                self.assessment = None;
                self.data_dirty = true;
            }
            Err(error) => {
                self.assessment = None;
                self.data_dirty = true;
                return Err(error);
            }
        }
        self.refresh_layout()?;
        self.refresh_data()?;
        let stale: Vec<_> = self
            .evidence
            .iter()
            .filter_map(
                |(path, evidence)| match self.access.snapshot(evidence.source) {
                    Ok(snapshot) if snapshot == Some(evidence.snapshot) => None,
                    other => Some((path.clone(), other)),
                },
            )
            .collect();
        for (path, snapshot) in stale {
            snapshot?;
            self.evidence.remove(&path);
            self.assessment = None;
        }
        let mut stale_placements = Vec::new();
        for (key, placement) in &self.placements {
            if self.access.snapshot(placement.source)? != Some(placement.snapshot) {
                stale_placements.push(*key);
            }
        }
        for key in stale_placements {
            self.placements.remove(&key);
            self.assessment = None;
        }
        if self.assessment.is_some() {
            self.diagnostics.assessment_reuses += 1;
            return self
                .assessment
                .as_ref()
                .ok_or(EngineError::InvalidState("missing cached assessment"));
        }
        let Some(layout) = self.layout.as_ref().map(Arc::clone) else {
            self.admit_retained(512)?;
            self.assessment = Some(RepairAssessment {
                status: RepairStatus::IncompleteMetadata,
                files: Vec::new(),
                lost_blocks: Vec::new(),
                requirements: Vec::new(),
                matrix: None,
                recovery: Vec::new(),
                _reservation: self.options.memory.reserve(512)?,
            });
            return Ok(self.assessment.as_ref().expect("stored assessment"));
        };
        let cost = usize::try_from(layout.block_count)
            .ok()
            .and_then(|count| count.checked_mul(64))
            .and_then(|count| count.checked_add(layout.files.len().checked_mul(1024)?))
            .ok_or(EngineError::ResourceLimit("assessment blocks"))?;
        self.admit_retained(cost)?;
        let reservation = self.options.memory.reserve(cost)?;
        let mut files = Vec::with_capacity(layout.files.len());
        for (index, file) in layout.files.iter().enumerate() {
            self.options.cancel.check()?;
            let source = self.bindings.get(&file.path).copied();
            if !self.evidence.contains_key(&file.path)
                && let Some(source) = source
                && self.access.snapshot(source)?.is_some()
            {
                let mut options = self.options.clone();
                options.retained_bytes = options
                    .retained_bytes
                    .saturating_sub(self.retained_bytes())
                    .saturating_sub(cost);
                let evidence = verify_source(
                    Arc::clone(&layout),
                    index,
                    self.access.as_ref(),
                    source,
                    &options,
                )?;
                self.diagnostics.source_verifications += 1;
                self.evidence.insert(file.path.clone(), evidence);
            }
            let evidence = self.evidence.get(&file.path);
            files.push(AssessedFile {
                path: file.path.clone(),
                source,
                complete: evidence.is_some_and(FileEvidence::protected_complete),
                verified_prefix: evidence
                    .map(|proof| proof.verified_prefix(&layout))
                    .transpose()?
                    .unwrap_or(0),
                unresolved: evidence
                    .map(|proof| proof.unresolved_ranges(&layout))
                    .transpose()?
                    .unwrap_or_else(|| std::iter::once(0..file.len).collect()),
            });
        }
        let data = self.data_payloads();
        let mut lost = Vec::new();
        for block in 0..layout.block_count {
            self.options.cancel.check()?;
            if !data.contains_key(&block) && !self.block_available(&layout, block) {
                lost.push(block);
            }
        }
        let (matrix, requirements, recovery) = self.select_matrix(&layout, &lost)?;
        let status = if files.iter().all(|file| file.complete) {
            RepairStatus::Complete
        } else if lost.is_empty() {
            RepairStatus::Ready
        } else if matrix.is_none() {
            RepairStatus::Unsupported
        } else if requirements.iter().any(|need| need.additional != 0) {
            RepairStatus::NeedRecovery
        } else {
            RepairStatus::Ready
        };
        self.assessment = Some(RepairAssessment {
            status,
            files,
            lost_blocks: lost,
            requirements,
            matrix,
            recovery,
            _reservation: reservation,
        });
        self.diagnostics.assessments += 1;
        Ok(self.assessment.as_ref().expect("stored assessment"))
    }

    fn block_available(&self, layout: &BlockLayout, block: u64) -> bool {
        let Some(locations) = layout.blocks.get(&block) else {
            return false;
        };
        let mut required = Vec::new();
        let mut available = Vec::new();
        for location in locations {
            let file = &layout.files[location.file];
            let extent = &file.extents[location.extent];
            let ExtentKind::Block { offset, .. } = extent.kind else {
                continue;
            };
            let range = offset..offset + extent.range.end - extent.range.start;
            required.push(range.clone());
            if self
                .placements
                .contains_key(&(location.file, location.extent))
                || self
                    .evidence
                    .get(&file.path)
                    .is_some_and(|proof| proof.verdicts[location.extent] == ExtentVerdict::Intact)
            {
                available.push(range);
            }
        }
        let required = union(required);
        let available = union(available);
        required.iter().all(|need| {
            available
                .iter()
                .any(|have| have.start <= need.start && have.end >= need.end)
        })
    }

    pub(crate) fn data_payloads(&self) -> &BTreeMap<u64, PayloadRef> {
        &self.data_blocks
    }

    fn select_matrix(
        &self,
        layout: &BlockLayout,
        lost: &[u64],
    ) -> EngineResult<(Option<Packet>, Vec<RecoveryRequirement>, Vec<PayloadRef>)> {
        let set = self.set.as_ref().expect("layout has a set");
        let mut best: Option<(u64, Packet, Vec<RecoveryRequirement>, Vec<PayloadRef>)> = None;
        for packet in set.matrix_packets() {
            let (range, cohorts, capacity) = match packet.body() {
                PacketBody::CauchyMatrix(matrix) => {
                    let capacity = match set.galois_field().size {
                        1 => 256u64,
                        2 => 65536,
                        _ => continue,
                    };
                    if layout.block_count >= capacity {
                        continue;
                    }
                    (matrix.range, 1, capacity - layout.block_count)
                }
                PacketBody::FftMatrix(matrix) => {
                    let Some(cohorts) = matrix.interleave.checked_add(1) else {
                        continue;
                    };
                    let covered = block_range(matrix.range, layout.block_count)?;
                    let Ok(geometry) = crate::fft::FftGeometry::new(
                        (covered.end - covered.start).div_ceil(cohorts),
                        matrix.max_recovery_blocks_log2,
                    ) else {
                        continue;
                    };
                    if geometry.field_bytes() != set.galois_field().size as usize
                        && !(geometry.is_trivial() && set.galois_field().size == 0)
                    {
                        continue;
                    }
                    if (geometry.capacity() as u64).checked_mul(cohorts).is_none() {
                        continue;
                    }
                    (matrix.range, cohorts, geometry.capacity() as u64)
                }
                _ => continue,
            };
            let covered = block_range(range, layout.block_count)?;
            if lost.iter().any(|index| !covered.contains(index)) {
                continue;
            }
            let mut unique: BTreeMap<u64, Option<PayloadRef>> = BTreeMap::new();
            for payload in self.input.payloads() {
                if let PayloadKind::Recovery {
                    root,
                    matrix,
                    index,
                } = payload.kind()
                    && root == set.root_hash()
                    && matrix == packet.hash()
                    && index < capacity * cohorts
                    && payload.len() <= layout.block_size
                {
                    unique
                        .entry(index)
                        .and_modify(|entry| *entry = None)
                        .or_insert_with(|| Some(payload.clone()));
                }
            }
            let mut requirements = Vec::new();
            let mut selected = Vec::new();
            let mut deficit = 0u64;
            let mut losses_by_cohort = BTreeMap::<u64, u64>::new();
            for index in lost {
                *losses_by_cohort.entry(index % cohorts).or_default() += 1;
            }
            for (cohort, count) in losses_by_cohort {
                let available: Vec<u64> = unique
                    .iter()
                    .filter_map(|(index, payload)| {
                        (index % cohorts == cohort && payload.is_some()).then_some(*index)
                    })
                    .collect();
                let additional = count.saturating_sub(available.len() as u64);
                deficit = deficit.saturating_add(additional);
                if additional == 0 {
                    selected.extend(
                        available
                            .iter()
                            .take(count as usize)
                            .filter_map(|index| unique[index].clone()),
                    );
                }
                requirements.push(RecoveryRequirement {
                    matrix: packet.hash(),
                    cohort,
                    cohorts,
                    lost: count,
                    available,
                    additional,
                });
            }
            if best.as_ref().is_none_or(|previous| deficit < previous.0) {
                best = Some((deficit, packet.clone(), requirements, selected));
            }
        }
        Ok(best
            .map(|(_, matrix, requirements, recovery)| (Some(matrix), requirements, recovery))
            .unwrap_or_default())
    }

    /// Reconstruct damaged files into an explicitly selected output directory.
    /// Sources remain read-only; verified temporary outputs are installed only
    /// after their complete protected-data hashes match.
    pub fn repair(
        &mut self,
        output: &Path,
        backup: bool,
    ) -> EngineResult<crate::session_repair::SessionRepairReport> {
        let _progress = self.options.stage(crate::runtime::Stage::Repair)?;
        self.assess()?;
        crate::session_repair::repair(self, output, backup)
    }

    /// Current diagnostics; reading them performs no work.
    #[must_use]
    pub fn diagnostics(&self) -> SessionDiagnostics {
        self.diagnostics
    }

    /// Total reservations on this session's possibly shared budget.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.options.memory.used()
    }

    /// Conservative retained state across packets, layouts, evidence, bindings,
    /// placements and assessment. The resolved set is included in packet costs.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.input
            .retained_bytes()
            .saturating_add(
                self.data_checked
                    .len()
                    .saturating_mul(data::ADMISSION_BYTES),
            )
            .saturating_add(
                self.layout
                    .as_ref()
                    .map_or(0, |layout| layout.retained_bytes()),
            )
            .saturating_add(
                self.evidence
                    .values()
                    .map(FileEvidence::retained_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(
                self.binding_memory
                    .values()
                    .map(Reservation::bytes)
                    .sum::<usize>(),
            )
            .saturating_add(self.placements.len().saturating_mul(512))
            .saturating_add(
                self.assessment
                    .as_ref()
                    .map_or(0, |assessment| assessment._reservation.bytes()),
            )
    }

    fn admit_retained(&self, additional: usize) -> EngineResult<()> {
        if self
            .retained_bytes()
            .checked_add(additional)
            .is_none_or(|total| total > self.options.retained_bytes)
        {
            return Err(EngineError::ResourceLimit(
                "aggregate retained session state",
            ));
        }
        Ok(())
    }

    pub(crate) fn read_block(
        &self,
        block: u64,
        offset: u64,
        out: &mut [u8],
        covered: &mut [u8],
    ) -> EngineResult<()> {
        let layout = self.layout.as_ref().expect("prepared layout");
        out.fill(0);
        covered.fill(0);
        if let Some(payload) = self.data_payloads().get(&block) {
            payload.read_at(offset, out)?;
            return Ok(());
        }
        let locations = layout
            .blocks
            .get(&block)
            .ok_or(EngineError::InvalidState("unresolved input block"))?;
        let stripe_end = offset + out.len() as u64;
        for location in locations {
            let file = &layout.files[location.file];
            let extent = &file.extents[location.extent];
            let ExtentKind::Block {
                offset: block_offset,
                ..
            } = extent.kind
            else {
                continue;
            };
            let (source, snapshot, source_offset) =
                if let Some(placement) = self.placements.get(&(location.file, location.extent)) {
                    (placement.source, placement.snapshot, placement.offset)
                } else if let Some(proof) = self.evidence.get(&file.path)
                    && proof.verdicts[location.extent] == ExtentVerdict::Intact
                {
                    (proof.source, proof.snapshot, extent.range.start)
                } else {
                    continue;
                };
            let start = offset.max(block_offset);
            let end = stripe_end.min(block_offset + extent.range.end - extent.range.start);
            if start >= end {
                continue;
            }
            let begin = (start - offset) as usize;
            let finish = (end - offset) as usize;
            ensure_snapshot(self.access.as_ref(), source, snapshot)?;
            if covered[begin..finish].iter().any(|value| *value != 0) {
                let _scratch = self.options.memory.reserve(4096)?;
                let mut scratch = [0; 4096];
                let mut position = begin;
                while position < finish {
                    self.options.cancel.check()?;
                    let take = (finish - position).min(scratch.len());
                    read_exact_at(
                        &self.options.diagnostics,
                        self.access.as_ref(),
                        source,
                        source_offset + start - block_offset + (position - begin) as u64,
                        &mut scratch[..take],
                    )?;
                    for (index, &byte) in scratch[..take].iter().enumerate() {
                        if covered[position + index] != 0 && out[position + index] != byte {
                            return Err(EngineError::InvalidState(
                                "contradictory authenticated alias bytes",
                            ));
                        }
                        out[position + index] = byte;
                    }
                    position += take;
                }
            } else {
                read_exact_at(
                    &self.options.diagnostics,
                    self.access.as_ref(),
                    source,
                    source_offset + start - block_offset,
                    &mut out[begin..finish],
                )?;
            }
            ensure_snapshot(self.access.as_ref(), source, snapshot)?;
            covered[begin..finish].fill(1);
        }
        for location in locations {
            let extent = &layout.files[location.file].extents[location.extent];
            let ExtentKind::Block {
                offset: block_offset,
                ..
            } = extent.kind
            else {
                continue;
            };
            let start = offset.max(block_offset);
            let end = stripe_end.min(block_offset + extent.range.end - extent.range.start);
            if start < end
                && covered[(start - offset) as usize..(end - offset) as usize].contains(&0)
            {
                return Err(EngineError::InvalidState(
                    "input block has unavailable protected bytes",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn block_range(range: BlockRange, count: u64) -> EngineResult<Range<u64>> {
    if range.covers_all() {
        return Ok(0..count);
    }
    if range.first >= range.end || range.end > count {
        return Err(EngineError::InvalidState("invalid matrix input range"));
    }
    Ok(range.first..range.end)
}

fn union(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<u64>> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}
