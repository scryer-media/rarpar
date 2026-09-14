//! Retained PAR3 analysis for filesystem and virtual sources.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use crate::evidence::{ExtentVerdict, FileEvidence, verify_source};
use crate::ingest::{IncrementalSet, IngestedPacket, MergeEffect, PayloadKind, PayloadRef};
use crate::layout::BlockLayout;
use crate::packet::{BlockRange, PacketBody};
use crate::runtime::{EngineError, EngineResult, ExecutionOptions, MemoryCategory, Reservation};
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
    /// Admissible global recovery-index span. Only indices congruent to `cohort`
    /// modulo `cohorts` belong to this requirement; skip those already available.
    /// This describes codec capacity, not a claim that a carrier exists remotely.
    pub recovery_indices: Range<u64>,
    /// Lost input blocks in this cohort.
    pub lost: u64,
    /// Available, distinct compatible recovery indices.
    pub available: Vec<u64>,
    /// Minimum additional recovery blocks in this specific cohort.
    pub additional: u64,
    /// How many of `additional` a host has already declared it is fetching,
    /// through [`Par3RepairSession::note_recovery_in_flight`]. Indices that
    /// have since arrived are not counted here; they are in `available`.
    pub in_flight: u64,
    /// `additional` less `in_flight`: what still has to be asked for. Zero
    /// means the cohort is fully spoken for even though it is not yet ready.
    pub outstanding: u64,
    /// Exactly `outstanding` admissible indices in this cohort that are
    /// neither available nor in flight, lowest first. A host can fetch these
    /// and reassess without ever requesting the same index twice.
    pub next_indices: Vec<u64>,
}

/// What a candidate matrix covers, and how its recovery indices divide into
/// cohorts. Derived once per candidate and never retained.
struct MatrixGeometry {
    covered: Range<u64>,
    cohorts: u64,
    capacity: u64,
    block_size: u64,
}

/// Read a candidate matrix's geometry, or `None` when this build cannot
/// execute it. Reading a candidate allocates nothing.
fn matrix_geometry(
    set: &Par3Set,
    layout: &BlockLayout,
    packet: &Packet,
) -> EngineResult<Option<MatrixGeometry>> {
    let (range, cohorts, capacity) = match packet.body() {
        PacketBody::CauchyMatrix(matrix) => {
            let capacity = match set.galois_field().size {
                1 => 256u64,
                2 => 65536,
                _ => return Ok(None),
            };
            let capacity = cauchy_recovery_capacity(matrix.range, layout.block_count, capacity)?;
            if capacity == 0 {
                return Ok(None);
            }
            (matrix.range, 1, capacity)
        }
        PacketBody::FftMatrix(matrix) => {
            let Some(cohorts) = matrix.interleave.checked_add(1) else {
                return Ok(None);
            };
            let covered = block_range(matrix.range, layout.block_count)?;
            let Ok(geometry) = crate::fft::FftGeometry::new(
                (covered.end - covered.start).div_ceil(cohorts),
                matrix.max_recovery_blocks_log2,
            ) else {
                return Ok(None);
            };
            if geometry.validate_field(set.galois_field()).is_err() {
                return Ok(None);
            }
            if (geometry.capacity() as u64).checked_mul(cohorts).is_none() {
                return Ok(None);
            }
            (matrix.range, cohorts, geometry.capacity() as u64)
        }
        _ => return Ok(None),
    };
    Ok(Some(MatrixGeometry {
        covered: block_range(range, layout.block_count)?,
        cohorts,
        capacity,
        block_size: layout.block_size,
    }))
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
    set_memory: Option<Reservation>,
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
    /// Recovery indices the host has declared it is acquiring, by matrix. This
    /// is the continuation that keeps a reassessment from asking twice.
    recovery_in_flight: BTreeMap<Fingerprint, std::collections::BTreeSet<u64>>,
    in_flight_memory: Option<Reservation>,
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
            set_memory: None,
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
            recovery_in_flight: BTreeMap::new(),
            in_flight_memory: None,
            diagnostics: SessionDiagnostics::default(),
        })
    }

    /// Admit an authenticated packet. Replays preserve the assessment unchanged.
    /// A refusal is counted once, by cause, on [`ExecutionDiagnostics`].
    pub fn merge(&mut self, packet: IngestedPacket) -> EngineResult<MergeEffect> {
        let outcome = self.merge_admitted(packet);
        if let Err(error) = &outcome {
            self.options.diagnostics.note_refusal(error);
        }
        outcome
    }

    fn merge_admitted(&mut self, packet: IngestedPacket) -> EngineResult<MergeEffect> {
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
                .checked_mul(3)
                .and_then(|n| n.checked_add(512))
                .ok_or(EngineError::resource_limit("source bindings"))?;
            self.admit_retained(bytes)?;
            let reservation = self
                .options
                .memory
                .reserve_as(MemoryCategory::Assessment, bytes)?;
            self.binding_memory.insert(path.to_owned(), reservation);
        }
        self.bindings.insert(path.to_owned(), source);
        self.evidence.remove(path);
        self.assessment = None;
        Ok(())
    }

    /// Declare recovery indices this host is acquiring for `matrix`, so the
    /// next assessment does not ask for them again.
    ///
    /// The state is a continuation, not a promise: an index that never arrives
    /// simply keeps appearing as `in_flight` until the host retracts it with
    /// [`Self::forget_recovery_in_flight`], and an index that does arrive moves
    /// to `available` on its own. The set is bounded and charged; declaring
    /// more indices than the budget admits is refused rather than truncated.
    pub fn note_recovery_in_flight(
        &mut self,
        matrix: Fingerprint,
        indices: &[u64],
    ) -> EngineResult<()> {
        self.options.cancel.check()?;
        let entry = self.recovery_in_flight.entry(matrix).or_default();
        let added = indices
            .iter()
            .filter(|index| !entry.contains(index))
            .count();
        if added == 0 {
            return Ok(());
        }
        let held = self.in_flight_memory.as_ref().map_or(0, Reservation::bytes);
        let growth = added
            .checked_mul(IN_FLIGHT_INDEX_BYTES)
            .ok_or(EngineError::resource_limit("recovery acquisition state"))?;
        self.admit_retained(growth)?;
        match &mut self.in_flight_memory {
            Some(reservation) => reservation.grow_by(growth)?,
            slot => {
                *slot = Some(
                    self.options
                        .memory
                        .reserve_as(MemoryCategory::Assessment, held + growth)?,
                );
            }
        }
        let entry = self.recovery_in_flight.entry(matrix).or_default();
        entry.extend(indices.iter().copied());
        self.assessment = None;
        Ok(())
    }

    /// Retract recovery indices that are no longer being acquired. Passing an
    /// empty slice retracts every index recorded for `matrix`.
    pub fn forget_recovery_in_flight(&mut self, matrix: Fingerprint, indices: &[u64]) {
        let removed = match self.recovery_in_flight.get_mut(&matrix) {
            None => 0,
            Some(entry) if indices.is_empty() => std::mem::take(entry).len(),
            Some(entry) => indices.iter().filter(|index| entry.remove(index)).count(),
        };
        if removed == 0 {
            return;
        }
        self.recovery_in_flight.retain(|_, set| !set.is_empty());
        if let Some(reservation) = &mut self.in_flight_memory {
            let keep = reservation
                .bytes()
                .saturating_sub(removed.saturating_mul(IN_FLIGHT_INDEX_BYTES));
            reservation.shrink_to(keep);
            if keep == 0 {
                self.in_flight_memory = None;
            }
        }
        self.assessment = None;
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
    /// A refusal is counted once, by cause, on [`ExecutionDiagnostics`].
    pub fn layout(&mut self) -> EngineResult<Option<Arc<BlockLayout>>> {
        if let Err(error) = self.refresh_layout() {
            self.options.diagnostics.note_refusal(&error);
            return Err(error);
        }
        Ok(self.layout.as_ref().map(Arc::clone))
    }

    fn refresh_layout(&mut self) -> EngineResult<()> {
        if !self.metadata_dirty {
            return Ok(());
        }
        let remaining = self
            .options
            .retained_bytes
            .saturating_sub(self.retained_bytes());
        let Some((set, set_memory)) = self.input.metadata_accounted(remaining)? else {
            return Ok(());
        };
        let mut options = self.options.clone();
        options.retained_bytes = remaining.saturating_sub(set_memory.bytes());
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
        self.set_memory = Some(set_memory);
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
    ///
    /// A refusal is counted once, by cause, on [`ExecutionDiagnostics`]. This is
    /// the boundary a host sees, so a request refused deep inside the stage is
    /// reported here exactly once rather than at every frame it passes.
    pub fn assess(&mut self) -> EngineResult<&RepairAssessment> {
        if let Err(error) = self.refresh_assessment() {
            self.options.diagnostics.note_refusal(&error);
            return Err(error);
        }
        Ok(self.assessment.as_ref().expect("stored assessment"))
    }

    fn refresh_assessment(&mut self) -> EngineResult<()> {
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
        let mut changed = false;
        let mut failure = None;
        let mut current = |source, expected| match self.access.snapshot(source) {
            Ok(snapshot) => {
                let valid = snapshot == Some(expected);
                changed |= !valid;
                valid
            }
            Err(error) => {
                changed = true;
                failure.get_or_insert(error);
                false
            }
        };
        self.evidence
            .retain(|_, evidence| current(evidence.source, evidence.snapshot));
        self.placements
            .retain(|_, placement| current(placement.source, placement.snapshot));
        if changed {
            self.assessment = None;
        }
        if let Some(error) = failure {
            return Err(error.into());
        }
        if self.assessment.is_some() {
            self.diagnostics.assessment_reuses += 1;
            return if self.assessment.is_some() {
                Ok(())
            } else {
                Err(EngineError::InvalidState("missing cached assessment"))
            };
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
                _reservation: self
                    .options
                    .memory
                    .reserve_as(MemoryCategory::Assessment, 512)?,
            });
            return Ok(());
        };
        // Assessment holds two different things with two different lifetimes,
        // and charging them as one made the transient part permanent. `scratch`
        // covers what the walk allocates and drops — the loss vector as it
        // doubles, the per-block coverage unions, the file roster as it grows.
        // It is released before this call returns. What the assessment keeps is
        // measured from the structures actually built and charged separately,
        // so the resident cost after assessing is a function of files and
        // losses rather than of the block count.
        let scratch_bytes = assessment_scratch_bytes(&layout)
            .ok_or(EngineError::resource_limit("assessment working set"))?;
        let scratch = self
            .options
            .memory
            .reserve_as(MemoryCategory::Assessment, scratch_bytes)?;
        self.verify_missing_sources(&layout, scratch_bytes)?;
        let mut files = Vec::with_capacity(layout.files.len());
        for file in &layout.files {
            self.options.cancel.check()?;
            let source = self.bindings.get(&file.path).copied();
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
        // Charge what survives, measured, and only then release the walk's
        // working set. Both exist at this instant and the ledger says so.
        let retained_bytes = assessment_retained_bytes(&files, &lost, &requirements, &recovery)
            .ok_or(EngineError::resource_limit("assessment result"))?;
        self.admit_retained(retained_bytes)?;
        let reservation = self
            .options
            .memory
            .reserve_as(MemoryCategory::Assessment, retained_bytes)?;
        drop(scratch);
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
        Ok(())
    }

    fn block_available(&self, layout: &BlockLayout, block: u64) -> bool {
        let Some(locations) = layout.locations(block) else {
            return false;
        };
        let mut required = Vec::new();
        let mut available = Vec::new();
        for location in locations.iter() {
            let file = &layout.files[location.file];
            let Some(extent) = file.extents.range(location.extent) else {
                continue;
            };
            let Some((_, offset)) = file.extents.block_at(location.extent) else {
                continue;
            };
            let range = offset..offset + extent.end - extent.start;
            required.push(range.clone());
            if self
                .placements
                .contains_key(&(location.file, location.extent))
                || self.evidence.get(&file.path).is_some_and(|proof| {
                    proof.verdicts.get(location.extent) == Some(ExtentVerdict::Intact)
                })
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
        // Scoring never materialises a candidate. Only a deficit and an
        // identity cross from one iteration to the next, so two candidates'
        // requirement lists, availability maps and payload references are never
        // alive at the same time; the winner alone is built, once, below.
        let mut best: Option<(u64, Fingerprint)> = None;
        for packet in set.matrix_packets() {
            self.options.cancel.check()?;
            let Some(geometry) = matrix_geometry(set, layout, packet)? else {
                continue;
            };
            if lost.iter().any(|index| !geometry.covered.contains(index)) {
                continue;
            }
            let (_charge, present) = self.distinct_recovery(set, packet.hash(), &geometry)?;
            let (_cohort_charge, losses) = self.losses_by_cohort(lost, geometry.cohorts)?;
            let mut deficit = 0u64;
            for (cohort, count) in &losses {
                let available = present
                    .iter()
                    .filter(|(index, usable)| **usable && *index % geometry.cohorts == *cohort)
                    .count() as u64;
                deficit = deficit.saturating_add(count.saturating_sub(available));
            }
            if best
                .as_ref()
                .is_none_or(|(previous, _)| deficit < *previous)
            {
                best = Some((deficit, packet.hash()));
            }
        }
        let Some((_, winner)) = best else {
            return Ok(Default::default());
        };
        let packet = set
            .matrix_packets()
            .iter()
            .find(|packet| packet.hash() == winner)
            .ok_or(EngineError::InvalidState("selected matrix disappeared"))?;
        let geometry = matrix_geometry(set, layout, packet)?.ok_or(EngineError::InvalidState(
            "selected matrix is no longer executable",
        ))?;

        // The winner, and only the winner, is materialised with its payload
        // references attached.
        let (_charge, usable) = self.usable_recovery(set, packet.hash(), &geometry)?;
        let (_cohort_charge, losses) = self.losses_by_cohort(lost, geometry.cohorts)?;
        let in_flight = self.recovery_in_flight.get(&winner);
        let mut requirements = Vec::with_capacity(losses.len());
        let mut selected = Vec::new();
        for (cohort, count) in losses {
            self.options.cancel.check()?;
            let available: Vec<u64> = usable
                .iter()
                .filter_map(|(index, payload)| {
                    (index % geometry.cohorts == cohort && payload.is_some()).then_some(*index)
                })
                .collect();
            let additional = count.saturating_sub(available.len() as u64);
            if additional == 0 {
                selected.extend(
                    available
                        .iter()
                        .take(count as usize)
                        .filter_map(|index| usable[index].clone()),
                );
            }
            // What the host has already asked for does not need asking for
            // again, so a reassessment after a recovery-only merge advances the
            // plan instead of restating it.
            let claimed = |index: &u64| {
                usable.get(index).is_some_and(Option::is_some)
                    || in_flight.is_some_and(|set| set.contains(index))
            };
            let pending = in_flight.map_or(0, |set| {
                set.iter()
                    .filter(|index| {
                        *index % geometry.cohorts == cohort
                            && !usable.get(index).is_some_and(Option::is_some)
                    })
                    .count() as u64
            });
            let outstanding = additional.saturating_sub(pending);
            let mut next_indices = Vec::with_capacity(outstanding as usize);
            let mut index = cohort;
            let ceiling = geometry.capacity.saturating_mul(geometry.cohorts);
            while next_indices.len() as u64 != outstanding && index < ceiling {
                if !claimed(&index) {
                    next_indices.push(index);
                }
                index = index.saturating_add(geometry.cohorts);
            }
            requirements.push(RecoveryRequirement {
                matrix: winner,
                cohort,
                cohorts: geometry.cohorts,
                recovery_indices: cohort..ceiling,
                lost: count,
                available,
                additional,
                in_flight: pending,
                outstanding,
                next_indices,
            });
        }
        Ok((Some(packet.clone()), requirements, selected))
    }

    /// Lost blocks grouped by cohort, with the map charged for its lifetime.
    /// At most one entry per cohort survives, and a cohort exists only because
    /// a lost block falls in it, so the map is bounded by the losses.
    fn losses_by_cohort(
        &self,
        lost: &[u64],
        cohorts: u64,
    ) -> EngineResult<(Reservation, BTreeMap<u64, u64>)> {
        let entries = usize::try_from(cohorts)
            .unwrap_or(usize::MAX)
            .min(lost.len());
        let charge = self.options.memory.reserve_as(
            MemoryCategory::Assessment,
            entries
                .checked_mul(crate::packet::btree_entry_bytes::<u64, u64>())
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(EngineError::resource_limit("assessment cohorts"))?,
        )?;
        let mut losses = BTreeMap::<u64, u64>::new();
        for index in lost {
            *losses.entry(index % cohorts).or_default() += 1;
        }
        Ok((charge, losses))
    }

    /// Which recovery indices this matrix has exactly one payload for. Scoring
    /// only needs to know that, so no payload reference is cloned.
    fn distinct_recovery(
        &self,
        set: &Par3Set,
        matrix: Fingerprint,
        geometry: &MatrixGeometry,
    ) -> EngineResult<(Reservation, BTreeMap<u64, bool>)> {
        let charge = self.recovery_map_charge::<bool>()?;
        let mut present = BTreeMap::new();
        for index in self.recovery_indices(set, matrix, geometry) {
            present
                .entry(index)
                .and_modify(|usable| *usable = false)
                .or_insert(true);
        }
        Ok((charge, present))
    }

    /// The same index map as `distinct_recovery`, carrying the payload for each
    /// index a single payload claims. Built for the selected matrix only.
    fn usable_recovery(
        &self,
        set: &Par3Set,
        matrix: Fingerprint,
        geometry: &MatrixGeometry,
    ) -> EngineResult<(Reservation, BTreeMap<u64, Option<PayloadRef>>)> {
        let charge = self.recovery_map_charge::<Option<PayloadRef>>()?;
        let mut usable: BTreeMap<u64, Option<PayloadRef>> = BTreeMap::new();
        for payload in self.input.payloads() {
            if let PayloadKind::Recovery {
                root,
                matrix: claimed,
                index,
            } = payload.kind()
                && root == set.root_hash()
                && claimed == matrix
                && index < geometry.capacity.saturating_mul(geometry.cohorts)
                && payload.len() <= geometry.block_size
            {
                usable
                    .entry(index)
                    .and_modify(|entry| *entry = None)
                    .or_insert_with(|| Some(payload.clone()));
            }
        }
        Ok((charge, usable))
    }

    /// One recovery index per payload that claims this matrix, undeduplicated.
    fn recovery_indices<'a>(
        &'a self,
        set: &'a Par3Set,
        matrix: Fingerprint,
        geometry: &'a MatrixGeometry,
    ) -> impl Iterator<Item = u64> + 'a {
        self.input
            .payloads()
            .filter_map(move |payload| match payload.kind() {
                PayloadKind::Recovery {
                    root,
                    matrix: claimed,
                    index,
                } if root == set.root_hash()
                    && claimed == matrix
                    && index < geometry.capacity.saturating_mul(geometry.cohorts)
                    && payload.len() <= geometry.block_size =>
                {
                    Some(index)
                }
                _ => None,
            })
    }

    /// One index map, bounded by the payloads that could populate it. Recovery
    /// payloads are already admitted and counted, so this does not scale with
    /// the block count.
    fn recovery_map_charge<V>(&self) -> EngineResult<Reservation> {
        let payloads = self.input.payloads().count();
        self.options.memory.reserve_as(
            MemoryCategory::Assessment,
            payloads
                .checked_mul(crate::packet::btree_entry_bytes::<u64, V>())
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or(EngineError::resource_limit("assessment recovery map"))?,
        )
    }

    /// Check readiness, ordinary-repair layout support, and configured
    /// codec/handle ceilings without staging files.
    /// This reuses retained analysis. A successful check does not reserve future
    /// allocations or guarantee that sources remain unchanged until execution.
    pub fn validate_repair(&mut self) -> EngineResult<()> {
        self.options.validate()?;
        self.assess()?;
        let assessment = self.assessment.as_ref().expect("assessed session");
        if assessment.status == RepairStatus::Complete {
            return Ok(());
        }
        if assessment.status != RepairStatus::Ready {
            return Err(EngineError::InvalidState("repair is not ready"));
        }
        if self
            .layout
            .as_ref()
            .expect("ready layout")
            .files
            .iter()
            .any(|file| (0..file.extents.len()).any(|extent| file.extents.is_unprotected(extent)))
        {
            return Err(EngineError::Unsupported(
                "unprotected ranges require explicit self-repair",
            ));
        }
        if matches!(
            assessment.matrix.as_ref().map(|packet| packet.body()),
            Some(PacketBody::CauchyMatrix(_))
        ) && assessment.lost_blocks.len() as u64 > self.options.max_cauchy_lost_blocks
        {
            return Err(EngineError::resource_limit("Cauchy lost blocks"));
        }
        if self.options.open_handles < 2 {
            return Err(EngineError::resource_limit(
                "repair requires two open handles",
            ));
        }
        Ok(())
    }

    fn verify_missing_sources(
        &mut self,
        layout: &Arc<BlockLayout>,
        cost: usize,
    ) -> EngineResult<()> {
        use rayon::prelude::*;
        let mut pool = None;
        let mut pool_initialized = false;
        let mut cursor = 0;
        while cursor < layout.files.len() {
            let mut batch = Vec::new();
            let mut probe_error = None;
            // Probe only the next execution batch. Snapshots can consume a
            // cumulative read budget, so do not preflight the whole layout.
            while cursor < layout.files.len() {
                let index = cursor;
                cursor += 1;
                let file = &layout.files[index];
                if self.evidence.contains_key(&file.path) {
                    continue;
                }
                let Some(source) = self.bindings.get(&file.path).copied() else {
                    continue;
                };
                let admission = (|| -> EngineResult<Option<Reservation>> {
                    if self.access.snapshot(source)?.is_none() {
                        return Ok(None);
                    }
                    // Cover roster growth and result bookkeeping before allocation.
                    self.options
                        .memory
                        .reserve_as(
                            MemoryCategory::Assessment,
                            size_of::<(usize, SourceId, Reservation)>() * 4,
                        )
                        .map(Some)
                })();
                match admission {
                    Ok(Some(reservation)) => batch.push((index, source, reservation)),
                    Ok(None) => continue,
                    Err(error) => {
                        probe_error = Some(error);
                        break;
                    }
                }
                if !pool_initialized {
                    pool_initialized = true;
                    let maximum = layout.files[index..]
                        .iter()
                        .filter(|file| {
                            !self.evidence.contains_key(&file.path)
                                && self.bindings.contains_key(&file.path)
                        })
                        .count();
                    match crate::runtime::WorkerPool::for_work_with_scratch(
                        &self.options,
                        maximum,
                        128 << 10,
                    ) {
                        Ok(admitted) => pool = admitted,
                        Err(EngineError::ResourceLimit(_)) => {}
                        Err(error) => {
                            probe_error = Some(error);
                            break;
                        }
                    }
                }
                let width = pool
                    .as_ref()
                    .map_or(1, |pool| pool.pool().current_num_threads());
                if batch.len() >= width {
                    break;
                }
            }
            if batch.is_empty() {
                return probe_error.map_or(Ok(()), Err);
            }
            // A batch shorter than the pool width because the layout ran out of
            // unverified files is not a narrowing; only a refused probe is.
            let width = pool
                .as_ref()
                .map_or(1, |pool| pool.pool().current_num_threads());
            let wanted = if probe_error.is_some() {
                width.max(batch.len().saturating_add(1))
            } else {
                batch.len()
            };
            self.options.diagnostics.note_batch(batch.len(), wanted);
            let mut options = self.options.clone();
            options.retained_bytes = options
                .retained_bytes
                .saturating_sub(self.retained_bytes())
                .saturating_sub(cost)
                / batch.len();
            let verify = |&(index, source, _): &(usize, SourceId, Reservation)| {
                verify_source(
                    Arc::clone(layout),
                    index,
                    self.access.as_ref(),
                    source,
                    &options,
                )
            };
            let results: Vec<_> = match &pool {
                Some(pool) => pool
                    .pool()
                    .install(|| batch.par_iter().map(verify).collect()),
                None => batch.iter().map(verify).collect(),
            };
            if results
                .iter()
                .any(|result| matches!(result, Err(EngineError::ResourceLimit(_))))
            {
                // Return worker stacks before attempting the serial fallback.
                // A failed parallel admission must not reserve the capacity
                // that its own retry needs.
                drop(pool.take());
            }
            // Successful peers retain evidence while a failed source retries.
            // Include those unmerged results in the retry's retained allowance.
            let mut pending_retained: usize = results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .map(FileEvidence::retained_bytes)
                .sum();
            // Merge in layout order after workers exit. Check each generation
            // at acceptance, including after an earlier source's serial retry.
            let mut first_error = None;
            for (&(index, source, _), result) in batch.iter().zip(results) {
                let accepted = (|| -> EngineResult<FileEvidence> {
                    let (evidence, needs_acceptance_check) = match result {
                        Err(EngineError::ResourceLimit(_)) => {
                            let mut options = self.options.clone();
                            options.retained_bytes = options
                                .retained_bytes
                                .saturating_sub(self.retained_bytes())
                                .saturating_sub(cost)
                                .saturating_sub(pending_retained);
                            (
                                verify_source(
                                    Arc::clone(layout),
                                    index,
                                    self.access.as_ref(),
                                    source,
                                    &options,
                                )?,
                                false,
                            )
                        }
                        Ok(evidence) => {
                            pending_retained -= evidence.retained_bytes();
                            (evidence, batch.len() > 1)
                        }
                        Err(error) => return Err(error),
                    };
                    if needs_acceptance_check {
                        ensure_snapshot(
                            self.access.as_ref(),
                            evidence.source(),
                            evidence.snapshot(),
                        )?;
                    }
                    Ok(evidence)
                })();
                let evidence = match accepted {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                };
                self.diagnostics.source_verifications += 1;
                self.evidence
                    .insert(layout.files[index].path.clone(), evidence);
            }
            if let Some(error) = first_error.or(probe_error) {
                return Err(error);
            }
        }
        Ok(())
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
        // `assess` already counts its own refusals; only the repair's are added.
        self.assess()?;
        let outcome = crate::session_repair::repair(self, output, backup);
        if let Err(error) = &outcome {
            self.options.diagnostics.note_refusal(error);
        }
        outcome
    }

    /// Change CPU and stripe limits between operations without discarding
    /// authenticated metadata or generation-bound verification evidence.
    /// The exclusive borrow prevents changes while an operation is running.
    pub fn set_execution_limits(
        &mut self,
        workers: usize,
        stripe_bytes: usize,
    ) -> EngineResult<()> {
        let mut options = self.options.clone();
        options.workers = workers;
        options.stripe_bytes = stripe_bytes;
        options.validate()?;
        self.options.workers = workers;
        self.options.stripe_bytes = stripe_bytes;
        Ok(())
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
    /// placements, the independently reserved resolved set, and assessment.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.input
            .retained_bytes()
            .saturating_add(self.set_memory.as_ref().map_or(0, Reservation::bytes))
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
            .saturating_add(self.in_flight_memory.as_ref().map_or(0, Reservation::bytes))
            .saturating_add(
                self.assessment
                    .as_ref()
                    .map_or(0, |assessment| assessment._reservation.bytes()),
            )
    }

    fn admit_retained(&self, additional: usize) -> EngineResult<()> {
        let held = self.retained_bytes();
        if held
            .checked_add(additional)
            .is_none_or(|total| total > self.options.retained_bytes)
        {
            // A per-session ceiling drawn on by this session alone. Report the
            // total it would need under that ceiling rather than the increment:
            // the bytes already held are its own and never release while it
            // lives, so a refusal here can never be waited out.
            return Err(EngineError::budget_limit(
                "aggregate retained session state",
                held.saturating_add(additional),
                self.options.retained_bytes,
                self.options.retained_bytes.saturating_sub(held),
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
            .locations(block)
            .ok_or(EngineError::InvalidState("unresolved input block"))?;
        let stripe_end = offset + out.len() as u64;
        for location in locations.iter() {
            let file = &layout.files[location.file];
            let Some(extent) = file.extents.range(location.extent) else {
                continue;
            };
            let Some((_, block_offset)) = file.extents.block_at(location.extent) else {
                continue;
            };
            let (source, snapshot, source_offset) =
                if let Some(placement) = self.placements.get(&(location.file, location.extent)) {
                    (placement.source, placement.snapshot, placement.offset)
                } else if let Some(proof) = self.evidence.get(&file.path)
                    && proof.verdicts.get(location.extent) == Some(ExtentVerdict::Intact)
                {
                    (proof.source, proof.snapshot, extent.start)
                } else {
                    continue;
                };
            let start = offset.max(block_offset);
            let end = stripe_end.min(block_offset + extent.end - extent.start);
            if start >= end {
                continue;
            }
            let begin = (start - offset) as usize;
            let finish = (end - offset) as usize;
            ensure_snapshot(self.access.as_ref(), source, snapshot)?;
            if covered[begin..finish].iter().any(|value| *value != 0) {
                let _scratch = self
                    .options
                    .memory
                    .reserve_as(MemoryCategory::SourceScratch, 4096)?;
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
        for location in locations.iter() {
            let extents = &layout.files[location.file].extents;
            let Some(extent) = extents.range(location.extent) else {
                continue;
            };
            let Some((_, block_offset)) = extents.block_at(location.extent) else {
                continue;
            };
            let start = offset.max(block_offset);
            let end = stripe_end.min(block_offset + extent.end - extent.start);
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

fn cauchy_recovery_capacity(range: BlockRange, count: u64, field_size: u64) -> EngineResult<u64> {
    let covered = block_range(range, count)?;
    // Columns retain their absolute block indices. Recovery row r uses
    // MAX - r, so the initial collision-free rows end at field_size - end.
    Ok(field_size.saturating_sub(covered.end))
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

/// Bytes `assess` allocates while it runs and does not keep.
///
/// Three things grow inside the walk. The loss vector takes one `u64` per lost
/// block and can end up holding every block, and it doubles as it grows, so it
/// is charged at twice the block count. The file roster is built by pushing,
/// so it too is charged at twice what it ends up holding, including the
/// unresolved ranges each entry carries — in the worst case one per extent.
/// And `block_available` builds, sorts and merges two range lists per block:
/// those are freed each call, so only the widest block's lists are charged.
fn assessment_scratch_bytes(layout: &BlockLayout) -> Option<usize> {
    const UNION_LISTS: usize = 4;
    let losses = usize::try_from(layout.block_count)
        .ok()?
        .checked_mul(size_of::<u64>())?
        .checked_mul(2)?;
    let roster = layout.files.iter().try_fold(0usize, |total, file| {
        total
            .checked_add(size_of::<AssessedFile>())?
            .checked_add(file.path.len())?
            .checked_add(file.extents.len().checked_mul(size_of::<Range<u64>>())?)
    })?;
    let aliases = layout
        .widest_block()
        .checked_mul(size_of::<Range<u64>>())?
        .checked_mul(UNION_LISTS * 2)?;
    losses
        .checked_add(roster.checked_mul(2)?)?
        .checked_add(aliases)?
        .checked_add(crate::set::RESOLUTION_BASE_BYTES)
}

/// Bytes the finished assessment keeps, measured from what it built.
///
/// Every term is a real container capacity: the roster and its unresolved
/// ranges, one `u64` per lost block, one requirement per cohort with the
/// recovery indices it names, and the payload references the selection kept.
/// The matrix packet is charged by its owning session, not here.
fn assessment_retained_bytes(
    files: &[AssessedFile],
    lost: &Vec<u64>,
    requirements: &[RecoveryRequirement],
    recovery: &Vec<PayloadRef>,
) -> Option<usize> {
    let roster = files.iter().try_fold(0usize, |total, file| {
        total
            .checked_add(size_of::<AssessedFile>())?
            .checked_add(file.path.capacity())?
            .checked_add(
                file.unresolved
                    .capacity()
                    .checked_mul(size_of::<Range<u64>>())?,
            )
    })?;
    let needs = requirements.iter().try_fold(0usize, |total, need| {
        total
            .checked_add(size_of::<RecoveryRequirement>())?
            .checked_add(need.available.capacity().checked_mul(size_of::<u64>())?)?
            .checked_add(need.next_indices.capacity().checked_mul(size_of::<u64>())?)
    })?;
    roster
        .checked_add(lost.capacity().checked_mul(size_of::<u64>())?)?
        .checked_add(needs)?
        .checked_add(recovery.capacity().checked_mul(size_of::<PayloadRef>())?)?
        .checked_add(size_of::<RepairAssessment>())?
        .checked_add(ASSESSMENT_BASE_BYTES)
}

/// Fixed allowance for the assessment's own bookkeeping and the matrix clone's
/// header, independent of the set's geometry.
const ASSESSMENT_BASE_BYTES: usize = 4096;

/// One declared in-flight recovery index: a `BTreeSet` node slot plus the map
/// entry amortised over the indices a matrix usually carries.
const IN_FLIGHT_INDEX_BYTES: usize = 2 * size_of::<u64>() + 48;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cauchy::element;
    use crate::gf::{Gf8, Gf16};

    struct AcceptanceSource {
        inner: crate::source::MemorySourceAccess,
        snapshots: Vec<std::sync::atomic::AtomicUsize>,
        work: crate::runtime::ScanWorkBudget,
        retry: bool,
        fail_snapshot: Option<(SourceId, usize)>,
        mutate_on_retry: bool,
        changed: std::sync::atomic::AtomicBool,
    }

    impl SourceAccess for AcceptanceSource {
        fn snapshot(
            &self,
            source: SourceId,
        ) -> std::io::Result<Option<crate::source::SourceSnapshot>> {
            use std::sync::atomic::Ordering::SeqCst;
            let call = self.snapshots[source.0 as usize].fetch_add(1, SeqCst) + 1;
            if self.fail_snapshot == Some((source, call)) {
                return Err(std::io::Error::other("injected source failure"));
            }
            if self.retry && source == SourceId(0) {
                if call == 2 {
                    return Err(EngineError::resource_limit("injected worker pressure").into_io());
                }
                if call == 3 && self.mutate_on_retry {
                    self.changed.store(true, SeqCst);
                }
            }
            let mut snapshot = self.inner.snapshot(source)?;
            if let Some(snapshot) = &mut snapshot {
                // Model the full-file snapshot cost of an unpinned Windows source.
                self.work
                    .charge(snapshot.len as usize + 1)
                    .map_err(EngineError::into_io)?;
                if source == SourceId(1) && self.changed.load(SeqCst) {
                    snapshot.generation += 1;
                }
            }
            Ok(snapshot)
        }

        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read_at(source, offset, out)
        }

        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<Range<u64>>> {
            self.inner.next_available(source, offset)
        }
    }

    #[test]
    fn serial_acceptance_avoids_redundant_snapshot_work() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        for mode in ["serial", "no_pool", "retry", "mutated_peer"] {
            let options = ExecutionOptions {
                workers: if mode == "serial" { 1 } else { 2 },
                memory: crate::runtime::MemoryBudget::new(if mode == "no_pool" {
                    512 << 10
                } else {
                    64 << 20
                }),
                ..ExecutionOptions::default()
            };
            let set = crate::test_reference::gf8_set();
            let layout = Arc::new(BlockLayout::new(&set, &options).unwrap());
            assert_eq!(layout.files.len(), 3);
            let retry = matches!(mode, "retry" | "mutated_peer");
            let mut inner = crate::source::MemorySourceAccess::default();
            for (index, file) in layout.files.iter().enumerate() {
                inner.insert(SourceId(index as u64), 1, vec![0; file.len as usize].into());
            }
            let expected: u64 = layout
                .files
                .iter()
                .enumerate()
                .map(|(index, file)| (file.len + 1) * if retry && index == 1 { 4 } else { 3 })
                .sum();
            let access = Arc::new(AcceptanceSource {
                inner,
                snapshots: (0..3).map(|_| AtomicUsize::new(0)).collect(),
                work: crate::runtime::ScanWorkBudget::new(expected),
                retry,
                fail_snapshot: None,
                mutate_on_retry: mode == "mutated_peer",
                changed: AtomicBool::new(false),
            });
            let mut session =
                Par3RepairSession::new(set.input_set_id(), access.clone(), options).unwrap();
            for (index, file) in layout.files.iter().enumerate() {
                session
                    .bind_file(&file.path, SourceId(index as u64))
                    .unwrap();
            }
            let result = session.verify_missing_sources(&layout, 0);
            if mode == "mutated_peer" {
                assert!(matches!(
                    result,
                    Err(EngineError::SourceChanged(SourceId(1)))
                ));
                assert!(!session.evidence.contains_key(&layout.files[1].path));
            } else {
                result.unwrap();
                assert_eq!(session.evidence.len(), 3, "{mode}");
                assert_eq!(access.work.used(), expected, "{mode}");
                assert_eq!(access.snapshots[2].load(SeqCst), 3, "{mode}");
            }
        }
    }

    #[test]
    fn verification_retains_progress_before_later_errors() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        for mode in ["budget", "probe", "peer", "retry"] {
            let options = ExecutionOptions {
                workers: if mode == "budget" { 1 } else { 2 },
                ..ExecutionOptions::default()
            };
            let set = crate::test_reference::gf8_set();
            let layout = Arc::new(BlockLayout::new(&set, &options).unwrap());
            let mut inner = crate::source::MemorySourceAccess::default();
            for (index, file) in layout.files.iter().enumerate() {
                inner.insert(SourceId(index as u64), 1, vec![0; file.len as usize].into());
            }
            let access = Arc::new(AcceptanceSource {
                inner,
                snapshots: (0..3).map(|_| AtomicUsize::new(0)).collect(),
                work: crate::runtime::ScanWorkBudget::new(if mode == "budget" {
                    3 * (layout.files[0].len + 1)
                } else {
                    u64::MAX
                }),
                retry: mode == "retry",
                fail_snapshot: match mode {
                    "probe" => Some((SourceId(1), 1)),
                    "peer" => Some((SourceId(0), 2)),
                    "retry" => Some((SourceId(0), 3)),
                    _ => None,
                },
                mutate_on_retry: false,
                changed: AtomicBool::new(false),
            });
            let mut session =
                Par3RepairSession::new(set.input_set_id(), access.clone(), options).unwrap();
            for (index, file) in layout.files.iter().enumerate() {
                session
                    .bind_file(&file.path, SourceId(index as u64))
                    .unwrap();
            }
            let result = session.verify_missing_sources(&layout, 0);
            if mode == "budget" {
                assert!(matches!(result, Err(EngineError::ResourceLimit(_))));
            } else {
                assert!(matches!(result, Err(EngineError::Io(_))));
            }
            let retained = if matches!(mode, "peer" | "retry") {
                1
            } else {
                0
            };
            assert!(
                session.evidence.contains_key(&layout.files[retained].path),
                "{mode}"
            );
            let calls = access.snapshots[retained].load(SeqCst);
            // A repeated failure must not reread evidence that was accepted.
            let _ = session.verify_missing_sources(&layout, 0);
            assert_eq!(access.snapshots[retained].load(SeqCst), calls, "{mode}");
        }
    }

    #[test]
    fn review_empty_verification_rosters_need_no_spare_memory() {
        use crate::source::MemorySourceAccess;
        let set = crate::test_reference::gf8_set();
        for mode in ["unbound", "unavailable", "cached", "pending"] {
            let options = ExecutionOptions::default();
            let budget = options.memory.clone();
            let layout = Arc::new(BlockLayout::new(&set, &options).unwrap());
            assert!(!layout.files.is_empty());
            let mut access = MemorySourceAccess::default();
            if matches!(mode, "cached" | "pending") {
                for (index, file) in layout.files.iter().enumerate() {
                    access.insert(SourceId(index as u64), 1, vec![0; file.len as usize].into());
                }
            }
            let access = Arc::new(access);
            let mut session =
                Par3RepairSession::new(set.input_set_id(), access.clone(), options.clone())
                    .unwrap();
            if mode != "unbound" {
                for (index, file) in layout.files.iter().enumerate() {
                    let id = SourceId(index as u64);
                    session.bind_file(&file.path, id).unwrap();
                    if mode == "cached" {
                        let evidence =
                            verify_source(layout.clone(), index, access.as_ref(), id, &options)
                                .unwrap();
                        session.evidence.insert(file.path.clone(), evidence);
                    }
                }
            }
            let before = budget.used();
            let held = budget.reserve(budget.available()).unwrap();
            let result = session.verify_missing_sources(&layout, 0);
            if mode == "pending" {
                assert!(matches!(result, Err(EngineError::ResourceLimit(_))));
            } else {
                result.unwrap();
            }
            drop(held);
            assert_eq!(
                budget.used(),
                before,
                "roster reservations must be returned"
            );
        }
    }

    #[test]
    fn cauchy_prefix_capacity_ignores_blocks_outside_the_matrix() {
        let range = BlockRange { first: 0, end: 10 };
        for count in [250, 70_000] {
            let capacity = cauchy_recovery_capacity(range, count, 256).unwrap();
            assert_eq!(capacity, 246);
            assert!(100 < capacity);
            for block in 0..10 {
                assert!(element(&Gf8::default(), block, 100).is_ok());
                assert!(element(&Gf8::default(), block, capacity - 1).is_ok());
            }
            assert!(element(&Gf8::default(), 9, capacity).is_err());
        }
    }

    #[test]
    fn cauchy_subrange_capacity_preserves_absolute_column_indices() {
        let range = BlockRange {
            first: 230,
            end: 240,
        };
        let capacity = cauchy_recovery_capacity(range, 250, 256).unwrap();
        assert_eq!(capacity, 16);
        for block in 230..240 {
            assert!(element(&Gf8::default(), block, capacity - 1).is_ok());
        }
        assert!(element(&Gf8::default(), 239, capacity).is_err());

        let range = BlockRange {
            first: 65_000,
            end: 65_010,
        };
        let capacity = cauchy_recovery_capacity(range, 70_000, 65_536).unwrap();
        assert_eq!(capacity, 526);
        for block in 65_000..65_010 {
            assert!(element(&Gf16::default(), block, capacity - 1).is_ok());
        }
        assert!(element(&Gf16::default(), 65_009, capacity).is_err());
    }

    #[test]
    fn cauchy_capacity_keeps_full_set_limits_and_rejects_invalid_ranges() {
        let all = BlockRange { first: 0, end: 0 };
        assert_eq!(cauchy_recovery_capacity(all, 250, 256).unwrap(), 6);
        assert_eq!(cauchy_recovery_capacity(all, 65_530, 65_536).unwrap(), 6);
        assert_eq!(cauchy_recovery_capacity(all, 256, 256).unwrap(), 0);
        assert_eq!(cauchy_recovery_capacity(all, 257, 256).unwrap(), 0);
        for range in [
            BlockRange { first: 10, end: 10 },
            BlockRange { first: 10, end: 9 },
            BlockRange { first: 0, end: 251 },
        ] {
            assert!(cauchy_recovery_capacity(range, 250, 256).is_err());
        }
    }
}
