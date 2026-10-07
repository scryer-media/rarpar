//! Striped repair and verified installation for retained sessions.

use crate::runtime::{EngineFile as File, ExecutionOptions, MemoryCategory, OpenBudgeted};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use rayon::prelude::*;

use crate::evidence::ExtentVerdict;
use crate::gf::{Field, Gf8, Gf16, MulAccBatch};
use crate::layout::BlockLayout;
use crate::packet::PacketBody;
use crate::repair_tree::{Destination, RepairTree};
use crate::runtime::{EngineError, EngineResult};
use crate::session::{Par3RepairSession, RepairStatus, block_range};
use crate::source::{OwedChecks, SourceAccess};

/// One verified output installed by a retained repair session.
#[derive(Clone, Debug)]
pub struct InstalledFile {
    /// Final destination selected by the caller.
    pub path: PathBuf,
    /// Backup retained for the previous destination, when requested.
    pub backup: Option<PathBuf>,
}

/// Successful repair outputs. A partial installation failure carries its paths
/// in [`EngineError::RepairInterrupted`].
#[derive(Clone, Debug, Default)]
pub struct SessionRepairReport {
    /// Installed files, each proven against the authenticated layout from the
    /// bytes the repair wrote (and, for a staged clone, its source's snapshot),
    /// or read back where that proof did not apply.
    pub installed: Vec<InstalledFile>,
    /// Logical lost blocks reconstructed once, regardless of aliases.
    pub reconstructed_blocks: u64,
}

/// File synchronization policy for retained-session repair.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RepairDurability {
    /// Preserve the default: synchronize each staged output file once before
    /// installation, and a destination-local copy once before it is renamed
    /// into place. This does not synchronize parent directories or promise
    /// atomic installation of the complete set across a crash.
    #[default]
    SyncFiles,
    /// Flush application buffers without requesting durable storage barriers.
    /// Every staged output is still checked against the authenticated layout
    /// before installation, but a crash after installation can leave a
    /// partial or stale file under the destination name. The host must own
    /// the barrier, for example by synchronizing the outputs it was given.
    Buffered,
}

struct StagedFile {
    index: usize,
    destination: Option<Destination>,
    stage_name: Option<OsString>,
    temporary: PathBuf,
    /// When the staged file is a clone of this output's verified source, or
    /// is that source itself patched in place, that source's verdicts: see
    /// [`Self::holds`].
    cloned: Option<Arc<crate::evidence::ExtentVerdicts>>,
    /// Set when the output is its own source, repaired in place: see
    /// [`in_place_source`].
    in_place: Option<InPlace>,
}

/// An output repaired in place: the file it is, and the source it was read
/// as, whose snapshots this repair's own writes move on.
#[derive(Clone, Copy)]
struct InPlace {
    identity: crate::repair_tree::FileIdentity,
    source: crate::source::SourceId,
}

impl StagedFile {
    /// Whether the clone this output was staged from already holds extent
    /// `extent`: a block extent with its own fingerprint, which the evidence
    /// for the cloned file holds intact. Such an extent is never written, and
    /// a block every output holds this way is never read to be copied.
    fn holds(&self, extents: &crate::layout::FileExtents, extent: usize) -> bool {
        self.cloned
            .as_ref()
            .is_some_and(|verdicts| held(verdicts, extents, extent))
    }
}

fn held(
    verdicts: &crate::evidence::ExtentVerdicts,
    extents: &crate::layout::FileExtents,
    extent: usize,
) -> bool {
    verdicts.get(extent) == Some(ExtentVerdict::Intact)
        && extents.block_at(extent).is_some()
        && matches!(
            extents.get(extent).map(|item| item.kind),
            Some(crate::layout::ExtentKind::Block {
                fingerprint: Some(_),
                ..
            })
        )
}

/// The evidence output `index` may be staged from by cloning the source that
/// evidence verified, on the targets that clone. It must be this file's
/// evidence for this layout and hold at least one extent the clone would spare
/// writing, and the file must have no unprotected range: a fresh stage leaves
/// those zero, where a clone would keep whatever the original had there.
///
/// Whether the source's registry hands over the very file this evidence
/// verified is settled by [`RepairTree::create_stage_from`] from that
/// registry's own handle.
fn clone_source<'a>(
    session: &'a Par3RepairSession,
    layout: &BlockLayout,
    index: usize,
) -> Option<&'a crate::evidence::FileEvidence> {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return None;
    }
    let file = &layout.files[index];
    let evidence = session.evidence.get(&file.path)?;
    if evidence.file != index || evidence.check_layout(layout).is_err() {
        return None;
    }
    let extents = &file.extents;
    if (0..extents.len()).any(|extent| extents.is_unprotected(extent)) {
        return None;
    }
    (0..extents.len())
        .any(|extent| held(&evidence.verdicts, extents, extent))
        .then_some(evidence)
}

/// Whether output `index`, staged from `evidence` by [`clone_source`] and
/// not cloned, may instead be repaired in place, writing only the extents
/// that evidence does not hold intact. With `backup` off its destination is
/// to be replaced anyway; [`RepairTree::prepare_in_place`] then settles that
/// the destination is that very source.
///
/// Nothing else this repair reads may come from that source: no placed
/// extent and no other file's evidence, which could name the ranges the
/// patch rewrites, and no payload. The extents read from it as intact are
/// never written, so its own reads are unaffected by the patch. Its snapshot
/// moves with the repair's own writes, so it no longer vouches for the file;
/// instead the output is read back whole against the File packet before it
/// is reported (see [`StagedProof::new`]).
///
/// A patch interrupted part way leaves the file with some damaged extents
/// already rewritten and every intact extent as it was: it verifies as
/// damaged, and repairs, exactly as before.
fn in_place_source(
    session: &Par3RepairSession,
    evidence: &crate::evidence::FileEvidence,
    backup: bool,
) -> bool {
    !backup
        && session
            .placements
            .values()
            .all(|placed| placed.source != evidence.source)
        && session
            .evidence
            .values()
            .all(|other| other.file == evidence.file || other.source != evidence.source)
        && session.assessment.as_ref().is_some_and(|assessment| {
            assessment
                .recovery
                .iter()
                .chain(session.data_payloads().values())
                .all(|payload| !payload.reads_from(&session.access, evidence.source))
        })
}

/// Whether some output being staged still needs bytes of `block` written:
/// it names the block in an extent its clone does not already hold.
fn needs_write(layout: &BlockLayout, outputs: &[StagedFile], block: u64) -> bool {
    layout.locations(block).is_some_and(|locations| {
        locations.iter().any(|location| {
            outputs.iter().any(|target| {
                target.index == location.file
                    && !target.holds(&layout.files[location.file].extents, location.extent)
            })
        })
    })
}

/// Whether one of `outputs` is `source` patched in place.
fn patched_in_place(outputs: &[StagedFile], source: crate::source::SourceId) -> bool {
    outputs.iter().any(|target| {
        target
            .in_place
            .is_some_and(|in_place| in_place.source == source)
    })
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// An exclusively created disposable file, removed on every exit path.
pub(crate) struct ScratchFile(PathBuf);

impl ScratchFile {
    pub(crate) fn new(destination: &Path, options: &ExecutionOptions) -> EngineResult<Self> {
        stage_path(destination, options).map(Self)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(crate) fn repair(
    session: &mut Par3RepairSession,
    output: &Path,
    backup: bool,
    durability: RepairDurability,
) -> EngineResult<SessionRepairReport> {
    let mut installed = Vec::new();
    let mut temporary = Vec::new();
    match repair_inner(
        session,
        output,
        backup,
        durability,
        &mut installed,
        &mut temporary,
    ) {
        Ok(reconstructed_blocks) => Ok(SessionRepairReport {
            installed,
            reconstructed_blocks,
        }),
        Err(cause) if !installed.is_empty() || !temporary.is_empty() => {
            Err(EngineError::RepairInterrupted {
                installed,
                temporary,
                cause: Box::new(cause),
            })
        }
        Err(error) => Err(error),
    }
}

fn repair_inner(
    session: &mut Par3RepairSession,
    output: &Path,
    backup: bool,
    durability: RepairDurability,
    installed: &mut Vec<InstalledFile>,
    temporary_outputs: &mut Vec<PathBuf>,
) -> EngineResult<u64> {
    session.validate_repair()?;
    let assessment = session
        .assessment
        .as_ref()
        .ok_or(EngineError::InvalidState("repair has no assessment"))?;
    if assessment.status == RepairStatus::Complete {
        return Ok(0);
    }
    let layout = session.layout.as_ref().expect("ready layout");
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    // Every payload is authenticated before its bytes are used, by the read
    // that consumes it where that read takes the whole payload.
    let checks = PayloadChecks::new(session);
    checks.before_walk(session.options.stripe_bytes, layout.block_size, None)?;
    let path_cost = assessment
        .files
        .iter()
        .filter(|file| !file.complete)
        .try_fold(0usize, |sum, file| {
            output
                .as_os_str()
                .len()
                .checked_mul(6)
                .and_then(|n| n.checked_add(file.path.len().checked_mul(4)?))
                .and_then(|n| n.checked_add(2048))
                .and_then(|n| n.checked_add(sum))
        })
        .ok_or(EngineError::resource_limit("repair output paths"))?;
    let _paths = session
        .options
        .memory
        .reserve_as(MemoryCategory::OutputStaging, path_cost)?;
    // Every destination is resolved before any file is staged. Whether a path
    // can be written under `output` is a property of the set and the output
    // directory, not of how far the repair has got, so it is settled up front.
    // Resolving inside the staging loop instead means a rule broken by the
    // second file surfaces only after the first has been staged, and the host
    // sees `RepairInterrupted` with a temporary left on disk where it should
    // see a bare `UnsafePath` saying this set can never be written here.
    // The destinations cost one path each, and the fold below one more, which
    // the `path_cost` reservation above already covers four times over.
    let mut destinations = Vec::with_capacity(
        assessment
            .files
            .iter()
            .filter(|file| !file.complete)
            .count(),
    );
    for file in &assessment.files {
        crate::paths::validate_relative_path(&file.path)?;
    }
    let tree = RepairTree::new_budgeted(
        output,
        assessment.files.iter().map(|file| file.path.as_str()),
        &session.options,
    )?;
    let result = (|| {
        refuse_aliased_destinations(&tree, &assessment.files)?;
        for (index, file) in assessment.files.iter().enumerate() {
            if file.complete {
                continue;
            }
            session.options.cancel.check()?;
            destinations.push((index, repair_destination(&tree, &file.path)?));
        }
        let mut staged = Vec::with_capacity(destinations.len());
        for (index, destination) in destinations {
            session.options.cancel.check()?;
            // An output whose registry hands over the local file its evidence
            // verified is staged as a clone of that file where the filesystem
            // allows, and the repair writes only what the clone lacks.
            let source = clone_source(session, layout, index);
            let (stage_name, temporary, cloned) = tree.create_stage_from(
                index,
                layout.files[index].len,
                &session.options,
                temporary_outputs,
                source.map(|evidence| {
                    (
                        session.access.as_ref() as &dyn SourceAccess,
                        evidence.source,
                        evidence.snapshot,
                    )
                }),
            )?;
            let cloned = match source {
                Some(evidence) if cloned => {
                    // The clone holds the file as it was when it was taken;
                    // this ties it to the bytes the evidence verified.
                    crate::source::ensure_snapshot(
                        session.access.as_ref(),
                        evidence.source,
                        evidence.snapshot,
                    )?;
                    Some(Arc::clone(&evidence.verdicts))
                }
                _ => None,
            };
            // Where the file cannot be cloned and is to be replaced without
            // a backup, it is patched where it stands: only the extents its
            // evidence does not hold are written, instead of the whole file.
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if cloned.is_none()
                && let Some(evidence) = source
                && in_place_source(session, evidence, backup)
                && let Some(identity) = tree.prepare_in_place(
                    &destination,
                    layout.files[index].len,
                    &session.options,
                    (session.access.as_ref(), evidence.source, evidence.snapshot),
                )?
            {
                tree.discard_stage(&stage_name, &temporary, temporary_outputs);
                session.options.diagnostics.note_in_place();
                staged.push(StagedFile {
                    index,
                    temporary: destination.display.clone(),
                    destination: Some(destination),
                    stage_name: None,
                    cloned: Some(Arc::clone(&evidence.verdicts)),
                    in_place: Some(InPlace {
                        identity,
                        source: evidence.source,
                    }),
                });
                continue;
            }
            staged.push(StagedFile {
                index,
                destination: Some(destination),
                stage_name: Some(stage_name),
                temporary,
                cloned,
                in_place: None,
            });
        }
        let proof = StagedProof::new(layout, &staged, &session.options);
        // A whole-file fingerprint the proof cannot check already disagrees
        // with intact extents: only the read-back can refuse that output.
        for (slot, target) in staged.iter().enumerate() {
            let path = &layout.files[target.index].path;
            if session.evidence.get(path).is_some_and(|evidence| {
                evidence.file == target.index && evidence.contradicts_itself()
            }) {
                proof.doubt(slot);
            }
        }
        if assessment.lost_blocks.is_empty() {
            copy_available(session, &checks, layout, Some(&tree), &staged, &proof)?;
        } else if let Some(PacketBody::FftMatrix(matrix)) =
            assessment.matrix.as_ref().map(|packet| packet.body())
        {
            reconstruct_fft(
                session,
                &checks,
                layout,
                Some(&tree),
                &staged,
                &proof,
                matrix,
            )?;
        } else {
            let field_bytes = crate::gf::construction_cost(
                &session.set.as_ref().expect("ready set").galois_field(),
            );
            let _field_reservation = session
                .options
                .memory
                .reserve_as(MemoryCategory::CodecTables, field_bytes)?;
            let field =
                crate::gf::for_set(&session.set.as_ref().expect("ready set").galois_field())?;
            match field {
                crate::gf::AnyField::Gf8(field) => reconstruct(
                    session,
                    &checks,
                    layout,
                    Some(&tree),
                    &staged,
                    &proof,
                    field,
                )?,
                crate::gf::AnyField::Gf16(field) => reconstruct(
                    session,
                    &checks,
                    layout,
                    Some(&tree),
                    &staged,
                    &proof,
                    field,
                )?,
            }
        }
        checks.finish()?;
        finish_staged(session, layout, Some(&tree), &staged, &proof, durability)?;
        drop(proof);
        for evidence in session.evidence.values() {
            if patched_in_place(&staged, evidence.source) {
                continue;
            }
            crate::source::ensure_snapshot(
                session.access.as_ref(),
                evidence.source,
                evidence.snapshot,
            )?;
        }
        for target in staged {
            session.options.cancel.check()?;
            // Patched, synchronized and read back where it stands.
            if target.in_place.is_some() {
                installed.push(InstalledFile {
                    path: target.destination.expect("tree destination").display,
                    backup: None,
                });
                continue;
            }
            let saved = tree.install(
                target.stage_name.as_deref().expect("tree staging name"),
                target.destination.as_ref().expect("tree destination"),
                backup,
                durability,
            )?;
            temporary_outputs.retain(|path| path != &target.temporary);
            installed.push(InstalledFile {
                path: target.destination.expect("tree destination").display,
                backup: saved,
            });
        }
        Ok(assessment.lost_blocks.len() as u64)
    })();
    if result.is_err() {
        if checks.refused() {
            // A payload that no longer matches its packet refuses the repair
            // as it did when every payload was authenticated before anything
            // was staged: nothing was installed, and the staged outputs are
            // removed rather than handed to the host to clean up.
            tree.discard_temporary_outputs(temporary_outputs);
        }
        tree.sanitize_temporary_outputs(temporary_outputs)?;
    }
    result
}

/// Private scratch operation for self-repair. The unprotected gap remains
/// unavailable to callers until the self-repair operation fills and validates it.
pub(crate) fn stage_embedded(
    session: &mut Par3RepairSession,
    temporary: &Path,
    durability: RepairDurability,
) -> EngineResult<u64> {
    if session
        .layout()?
        .is_some_and(|layout| layout.files.len() != 1)
    {
        return Err(EngineError::Unsupported(
            "embedded repair requires one file",
        ));
    }
    stage_embedded_files(session, &[temporary.to_owned()], durability)
}

/// Stage every file of an embedded set, file `k` to `temporaries[k]`, which
/// must already exist. Unprotected gaps are left zero for the caller to fill.
pub(crate) fn stage_embedded_files(
    session: &mut Par3RepairSession,
    temporaries: &[std::path::PathBuf],
    durability: RepairDurability,
) -> EngineResult<u64> {
    session.options.validate()?;
    if !matches!(
        session.assess()?.status,
        RepairStatus::Ready | RepairStatus::Complete
    ) {
        return Err(EngineError::InvalidState("embedded repair is not ready"));
    }
    if session.options.open_handles < 3 {
        return Err(EngineError::resource_limit(
            "embedded repair requires three handles",
        ));
    }
    let layout = session.layout.as_ref().expect("assessed layout");
    if layout.files.len() != temporaries.len() {
        return Err(EngineError::InvalidState("embedded repair targets"));
    }
    let assessment = session.assessment.as_ref().expect("assessment");
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    // Every payload is authenticated before its bytes are used, by the read
    // that consumes it where that read takes the whole payload.
    let checks = PayloadChecks::new(session);
    checks.before_walk(session.options.stripe_bytes, layout.block_size, None)?;
    let targets: Vec<StagedFile> = temporaries
        .iter()
        .enumerate()
        .map(|(index, temporary)| StagedFile {
            index,
            destination: None,
            stage_name: None,
            temporary: temporary.clone(),
            cloned: None,
            in_place: None,
        })
        .collect();
    for (file, temporary) in layout.files.iter().zip(temporaries) {
        OpenOptions::new()
            .write(true)
            .open_budgeted(temporary, &session.options)?
            .set_len(file.len)?;
    }
    let proof = StagedProof::new(layout, &targets, &session.options);
    if assessment.lost_blocks.is_empty() {
        copy_available(session, &checks, layout, None, &targets, &proof)?;
    } else if layout.block_count != 0 {
        let set = session.set.as_ref().expect("assessed set");
        let _field = session.options.memory.reserve_as(
            MemoryCategory::CodecTables,
            crate::gf::construction_cost(&set.galois_field()),
        )?;
        match crate::gf::for_set(&set.galois_field())? {
            crate::gf::AnyField::Gf8(field) => {
                reconstruct(session, &checks, layout, None, &targets, &proof, field)?
            }
            crate::gf::AnyField::Gf16(field) => {
                reconstruct(session, &checks, layout, None, &targets, &proof, field)?
            }
        }
    }
    checks.finish()?;
    finish_staged(session, layout, None, &targets, &proof, durability)?;
    drop(proof);
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    Ok(assessment.lost_blocks.len() as u64)
}

/// The payloads one repair consumes, each authenticated once before any of its
/// bytes are used.
///
/// A read that takes a whole payload, which is every read of it once one
/// stripe covers the block, is authenticated over the bytes it read, so the
/// packet is fetched once rather than once to hash and again to use. Any other
/// read authenticates its packet first, in a pass of its own, as every payload
/// once was before the repair began; later stripes of that payload then read
/// it as before. Nothing is decoded or written from a payload before its hash
/// has matched, and a mismatch refuses the repair as it always has.
/// [`Self::finish`] authenticates whatever the codec never read, so a repair
/// still refuses a set carrying a payload that no longer matches its packet.
struct PayloadChecks<'a> {
    session: &'a Par3RepairSession,
    /// Payloads already authenticated: `(is data, block or recovery index)`.
    done: Mutex<std::collections::BTreeSet<(bool, u64)>>,
    /// Whether an authentication refused the repair.
    refused: AtomicBool,
}

impl<'a> PayloadChecks<'a> {
    fn new(session: &'a Par3RepairSession) -> Self {
        Self {
            session,
            done: Mutex::new(std::collections::BTreeSet::new()),
            refused: AtomicBool::new(false),
        }
    }

    fn key(payload: &crate::ingest::PayloadRef) -> (bool, u64) {
        match payload.kind() {
            crate::ingest::PayloadKind::Data { index } => (true, index),
            crate::ingest::PayloadKind::Recovery { index, .. } => (false, index),
        }
    }

    /// Whether a payload's authentication is what ended the repair.
    fn refused(&self) -> bool {
        self.refused.load(Ordering::Relaxed)
    }

    fn refusing(&self, checked: EngineResult<()>) -> EngineResult<()> {
        if checked.is_err() {
            self.refused.store(true, Ordering::Relaxed);
        }
        checked
    }

    fn checked(&self, key: (bool, u64)) -> bool {
        self.done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&key)
    }

    fn note(&self, key: (bool, u64)) {
        self.done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key);
    }

    /// Read `payload` from `offset` into `out`, zero past its end, once the
    /// packet is known to match its hash.
    fn read(
        &self,
        payload: &crate::ingest::PayloadRef,
        offset: u64,
        out: &mut [u8],
    ) -> EngineResult<()> {
        let session = self.session;
        let key = Self::key(payload);
        if !self.checked(key) {
            if offset == 0 && out.len() as u64 >= payload.len() {
                self.refusing(session.input.read_payload(payload, &session.options, out))?;
                self.note(key);
                return Ok(());
            }
            self.authenticate(payload, Some(out))?;
        }
        out.fill(0);
        payload.read_at(offset, out)?;
        Ok(())
    }

    /// Authenticate `payload` in a pass of its own. The codec's stripes may
    /// hold the budget that pass reserves its buffer from, so `scratch`, a
    /// buffer the codec already holds, serves instead when it is refused.
    fn authenticate(
        &self,
        payload: &crate::ingest::PayloadRef,
        scratch: Option<&mut [u8]>,
    ) -> EngineResult<()> {
        let session = self.session;
        let checked = match (
            session.input.validate_payload(payload, &session.options),
            scratch,
        ) {
            (Err(EngineError::ResourceLimit(_)), Some(scratch)) => session
                .input
                .validate_payload_in(payload, &session.options, scratch),
            (checked, _) => checked,
        };
        self.refusing(checked)?;
        self.note(Self::key(payload));
        Ok(())
    }

    /// Before a codec walking `stripe`-wide reads starts: a stripe narrower
    /// than the block reads no payload whole, so every payload is
    /// authenticated now, in the order and passes it always was, rather than
    /// one at a time between the codec's reads. A repair configured narrower
    /// than its block calls this before it stages anything, with no scratch,
    /// exactly where every payload was once authenticated.
    fn before_walk(
        &self,
        stripe: usize,
        block_size: u64,
        mut scratch: Option<&mut [u8]>,
    ) -> EngineResult<()> {
        if stripe as u64 >= block_size {
            return Ok(());
        }
        let session = self.session;
        let assessment = session.assessment.as_ref().expect("assessment");
        for payload in assessment
            .recovery
            .iter()
            .chain(session.data_payloads().values())
        {
            if !self.checked(Self::key(payload)) {
                self.authenticate(payload, scratch.as_deref_mut())?;
            }
        }
        Ok(())
    }

    /// [`Par3RepairSession::read_block`], with a block carried in a data
    /// packet read through [`Self::read`].
    fn read_block(
        &self,
        block: u64,
        offset: u64,
        out: &mut [u8],
        covered: &mut [u8],
        owed: Option<&OwedChecks>,
    ) -> EngineResult<()> {
        match self.session.data_payloads().get(&block) {
            Some(payload) => self.read(payload, offset, out),
            None => self.session.read_block(block, offset, out, covered, owed),
        }
    }

    /// Authenticate every payload the repair selected and never read.
    fn finish(&self) -> EngineResult<()> {
        let session = self.session;
        let assessment = session.assessment.as_ref().expect("assessment");
        for payload in assessment
            .recovery
            .iter()
            .chain(session.data_payloads().values())
        {
            let key = Self::key(payload);
            if !self.checked(key) {
                self.refusing(session.input.validate_payload(payload, &session.options))?;
                self.note(key);
            }
        }
        Ok(())
    }
}

fn copy_available(
    session: &Par3RepairSession,
    checks: &PayloadChecks<'_>,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    outputs: &[StagedFile],
    proof: &StagedProof,
) -> EngineResult<()> {
    let mut progress = session.options.stage(crate::runtime::Stage::Repair)?;
    // Data packets, aliases and inline-only files require no field or matrix.
    // In particular, the reference emits field size zero for degenerate codes.
    let size = session.options.stripe_bytes.min(64 << 10);
    let _memory = session
        .options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size * 2)?;
    let mut bytes = vec![0; size];
    let mut covered = vec![0; size];
    let mut copied = false;
    let writers = StageWriters::new(tree, session, outputs, proof);
    for (block, _) in layout.blocks() {
        // A block every staged clone already holds is not read at all.
        if !needs_write(layout, outputs, block) {
            continue;
        }
        copied = true;
        let mut offset = 0;
        while offset < layout.block_size {
            session.options.cancel.check()?;
            let take = (layout.block_size - offset).min(size as u64) as usize;
            checks.read_block(
                block,
                offset,
                &mut bytes[..take],
                &mut covered[..take],
                Some(writers.owed()),
            )?;
            scatter(&writers, layout, outputs, block, offset, &bytes[..take])?;
            progress.advance(take as u64);
            offset += take as u64;
        }
    }
    // One check per source read, after the whole copy and before anything it
    // staged is verified or installed.
    writers.settle()?;
    // A block wider than the copy window is walked in windows, and each window
    // covers a different part of it, so no byte is fetched twice: what costs is
    // the extra walk. It is one walk over the copied blocks however many there
    // are, so it is counted once here rather than once per block — taken inside
    // the loop it reported N passes for a single extra pass over N blocks.
    // `reread_bytes` stays reserved for bytes genuinely fetched again.
    if copied {
        for _ in 1..layout.block_size.div_ceil(size as u64) {
            session.options.diagnostics.note_stripe_pass();
        }
    }
    Ok(())
}

/// Arithmetic owed on one set of staged stripes in a Cauchy repair pass.
#[derive(Clone, Copy)]
enum StagedWork {
    /// The set holds this many surviving blocks to fold into every syndrome.
    Fold(usize),
    /// The set holds recovery rows `first..first + count`, each added to its
    /// own syndrome.
    Recovery { first: usize, count: usize },
}

/// Bytes building the Cauchy inverse costs at its peak.
///
/// [`crate::cauchy::inverse_coefficients`] returns the `n` by `n` inverse and,
/// while it computes it, holds four vectors of `n` symbols — the two node sets
/// and their weight vectors. The per-row allowance also covers the recovery row
/// bookkeeping the solve is driven from.
fn cauchy_coefficient_bytes<F: Field>(n: usize) -> Option<usize> {
    n.checked_mul(n)?
        .checked_mul(F::SYMBOL_BYTES)?
        .checked_add(n.checked_mul(64)?)
}

fn reconstruct<F>(
    session: &Par3RepairSession,
    checks: &PayloadChecks<'_>,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    outputs: &[StagedFile],
    proof: &StagedProof,
    field: F,
) -> EngineResult<()>
where
    F: MulAccBatch + Sync,
    F::Symbol: Send + Sync,
{
    let mut progress = session.options.stage(crate::runtime::Stage::Decode)?;
    let assessment = session.assessment.as_ref().expect("assessment");
    let lost = &assessment.lost_blocks;
    // One `u64` per selected recovery row, collected from an exactly sized
    // iterator, so the vector is allocated once at its final capacity.
    let _rows = session.options.memory.reserve_as(
        MemoryCategory::CodecScratch,
        assessment
            .recovery
            .len()
            .checked_mul(size_of::<u64>())
            .and_then(|n| n.checked_add(256))
            .ok_or(EngineError::resource_limit("recovery row indices"))?,
    )?;
    let rows: Vec<u64> = assessment
        .recovery
        .iter()
        .map(|payload| match payload.kind() {
            crate::ingest::PayloadKind::Recovery { index, .. } => index,
            _ => unreachable!("selected recovery packet"),
        })
        .collect();
    let coverage = match assessment.matrix.as_ref().map(|packet| packet.body()) {
        Some(PacketBody::CauchyMatrix(matrix)) => block_range(matrix.range, layout.block_count)?,
        None if lost.is_empty() => 0..layout.block_count,
        _ => return Err(EngineError::Unsupported("matrix execution")),
    };
    if !layout.block_size.is_multiple_of(F::SYMBOL_BYTES as u64) {
        return Err(EngineError::InvalidState("block size is not field aligned"));
    }
    let n = lost.len();
    if n as u64 > session.options.max_cauchy_lost_blocks {
        return Err(EngineError::resource_limit("Cauchy lost blocks"));
    }
    let coefficient_bytes = cauchy_coefficient_bytes::<F>(n)
        .ok_or(EngineError::resource_limit("Cauchy coefficients"))?;
    let _coefficients = session
        .options
        .memory
        .reserve_as(MemoryCategory::CodecTables, coefficient_bytes)?;
    let inverse = crate::cauchy::inverse_coefficients(&field, lost, &rows)?;
    let rows = rows.as_slice();
    // Recovered rows are produced and scattered a tile at a time. The syndrome
    // bank has to stay whole — every output row reads all of it — but the
    // output bank only has to be as wide as the rows being solved right now,
    // so the row payload is `(n + tile)` stripes instead of `2n`. The tile is
    // the width the workers can actually use, so no parallelism is given up,
    // and a serial repair keeps exactly one output row alive.
    //
    // The pool is admitted before the tile is chosen, against the headroom a
    // serial repair needs: `n` syndrome rows, one output row and three stripes
    // of overhead, plus the row headers of the `n + 1` vectors that bank holds.
    // The headers are part of what the stripe admission charges, so leaving
    // them out of the headroom let a pool be admitted into the bytes the
    // headers need and then refused a repair that would have run serially.
    // `for_work` narrows the worker count under pressure and returns `None`
    // when fewer than two fit, so the requested `workers` is not what the
    // repair gets. Tiling by the request would size the output bank for rows no
    // worker exists to fill, reserving `workers` stripes for a repair that runs
    // on one thread.
    let serial_rows = n
        .checked_add(1)
        .ok_or(EngineError::resource_limit("repair stripes"))?;
    let serial_headroom = n
        .checked_add(4)
        .and_then(|buffers| buffers.checked_mul(F::SYMBOL_BYTES))
        .and_then(|bytes| bytes.checked_add(serial_rows.checked_mul(size_of::<Vec<u8>>())?))
        .ok_or(EngineError::resource_limit("minimum repair stripe"))?;
    let mut pool = crate::runtime::WorkerPool::for_work(&session.options, n, serial_headroom)?;
    let target = session
        .options
        .stripe_bytes
        .min(usize::try_from(layout.block_size).unwrap_or(usize::MAX));
    // Admit the stripe bank at the tile the pool can actually use; if even that
    // is refused, the pool's own stacks are the likeliest thing standing in the
    // way, so give them back and try once more at the serial width. A repair
    // that fits on one thread must not be refused because a pool was admitted
    // in front of it. `spare` bytes are held back from the stripes on top of
    // the bank's own overhead and handed back once the stripe is sized.
    let admit =
        |tile: usize, spare: usize| -> EngineResult<(usize, usize, crate::runtime::Reservation)> {
            let buffer_count = n
                .checked_add(tile)
                .and_then(|count| count.checked_add(3))
                .ok_or(EngineError::resource_limit("repair stripes"))?;
            let bank_headers = n
                .checked_add(tile)
                .and_then(|rows| rows.checked_mul(size_of::<Vec<u8>>()))
                .ok_or(EngineError::resource_limit("repair stripes"))?;
            let overhead = bank_headers
                .checked_add(spare)
                .ok_or(EngineError::resource_limit("repair stripes"))?;
            let (stripe, mut buffers) = session.options.memory.reserve_stripes_with_overhead(
                MemoryCategory::CodecScratch,
                target,
                buffer_count,
                F::SYMBOL_BYTES,
                overhead,
            )?;
            buffers.shrink_to(buffers.bytes() - spare);
            Ok((stripe, buffer_count, buffers))
        };
    let mut tile = pool
        .as_ref()
        .map_or(1, crate::runtime::WorkerPool::current_num_threads)
        .min(n);
    let mut admitted = match admit(tile, 0) {
        Ok(admitted) => admitted,
        Err(EngineError::ResourceLimit(_)) if pool.is_some() => {
            pool = None;
            tile = 1;
            session.options.diagnostics.note_workers(1, n);
            admit(tile, 0)?
        }
        Err(error) => return Err(error),
    };
    // The staged proof's frontiers are reserved next, before anything that
    // only saves time takes spare budget: without them every staged output
    // reads back. A pool whose wider bank left too little for them gives way
    // to the serial bank, as it does to a repair that fits only serially, but
    // only when the serial bank at the full stripe would leave room for them.
    // Otherwise the bank is sized again with room held back for them; a
    // narrower stripe splits no extent the symbol width does not, so the
    // frontiers at that width bound what any stripe needs.
    let mut reserved = proof.reserve_frontiers(admitted.0 as u64);
    if !reserved
        && let Some(stacks) = pool
            .as_ref()
            .map(crate::runtime::WorkerPool::reserved_bytes)
    {
        let full = target / F::SYMBOL_BYTES * F::SYMBOL_BYTES;
        // What `admit(1)` charges at the full stripe.
        let serial = serial_rows
            .checked_add(3)
            .and_then(|buffers| buffers.checked_mul(full))
            .and_then(|bytes| bytes.checked_add(serial_rows.checked_mul(size_of::<Vec<u8>>())?));
        let room = session
            .options
            .memory
            .available()
            .saturating_add(stacks)
            .saturating_add(admitted.2.bytes());
        let fits = serial
            .zip(proof.frontier_bytes(full as u64))
            .and_then(|(serial, frontiers)| serial.checked_add(frontiers))
            .is_some_and(|need| need <= room);
        if fits {
            drop(admitted);
            pool = None;
            tile = 1;
            session.options.diagnostics.note_workers(1, n);
            admitted = admit(tile, 0)?;
            reserved = proof.reserve_frontiers(admitted.0 as u64);
        }
    }
    if !reserved && let Some(spare) = proof.frontier_bytes(F::SYMBOL_BYTES as u64) {
        // A bank that cannot leave the room keeps the stripe it had, and the
        // outputs read back as before.
        drop(admitted);
        admitted = match admit(tile, spare) {
            Ok(narrower) => narrower,
            Err(EngineError::ResourceLimit(_)) => admit(tile, 0)?,
            Err(error) => return Err(error),
        };
        proof.reserve_frontiers(admitted.0 as u64);
    }
    let (stripe, buffer_count, _buffers) = admitted;
    session
        .options
        .diagnostics
        .note_stripe(stripe, buffer_count, target);
    tracing::debug!(
        stripe_bytes = stripe,
        buffer_count,
        "PAR3 Cauchy stripe admitted"
    );
    session
        .options
        .diagnostics
        .note_tiling(stripe, buffer_count, tile);
    // Surviving stripes are folded into the syndromes a group at a time, so
    // the workers meet once per group and each folds the whole group into its
    // rows with one grouped multiply-accumulate. The extra stripes come only
    // out of what the bank left, beyond a stripe of slack, so they never
    // narrow the stripe, the tile or the pool; with no room for a second one
    // this is the walk one stripe at a time.
    let contributing = coverage
        .clone()
        .filter(|block| lost.binary_search(block).is_err())
        .count();
    let mut group = crate::gf::BATCH_SOURCES.min(contributing).min(
        1 + session
            .options
            .memory
            .available()
            .saturating_sub(crate::runtime::SOURCE_GROUP_SLACK)
            / stripe,
    );
    let _group = if group > 1 {
        match session
            .options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, (group - 1) * stripe)
        {
            Ok(reservation) => Some(reservation),
            Err(_) => {
                group = 1;
                None
            }
        }
    } else {
        group = 1;
        None
    };
    // With a pool, a second set of `group` stripes lets the calling thread read
    // the next group while the workers scatter and fold the last one. It comes
    // out of what is left after the first set, beyond the same slack; without
    // room for it, or without workers to overlap with, the walk alternates
    // between reading and folding as before.
    let _read_ahead = if pool.is_some()
        && session
            .options
            .memory
            .available()
            .saturating_sub(crate::runtime::SOURCE_GROUP_SLACK)
            / stripe
            >= group
    {
        session
            .options
            .memory
            .reserve_as(MemoryCategory::CodecScratch, group * stripe)
            .ok()
    } else {
        None
    };
    let sets = 1 + usize::from(_read_ahead.is_some());
    let writers = StageWriters::new(tree, session, outputs, proof);
    // With both, and every output held open ahead, the workers also scatter
    // each set they fold: its writes and the proof's hashing of them leave the
    // calling thread, which then only reads, and the hashing of the set's
    // blocks runs in parallel (the writes still take turns on the handle
    // lock). Otherwise the walk reads, writes and folds one block after
    // another on the calling thread, as before.
    let deferred = pool.is_some() && sets == 2 && writers.hold(outputs)?;
    tracing::debug!(group, sets, deferred, "PAR3 Cauchy syndrome group admitted");
    let mut syndromes = vec![vec![0u8; stripe]; n];
    let mut recovered = vec![vec![0u8; stripe]; tile];
    let mut inputs = vec![vec![0u8; stripe]; group * sets];
    let mut covered = vec![0u8; stripe];
    checks.before_walk(stripe, layout.block_size, Some(&mut covered))?;
    let parallel = pool.as_ref().map(crate::runtime::WorkerPool::pool);
    let mut offset = 0;
    while offset < layout.block_size {
        session.options.cancel.check()?;
        let take = (layout.block_size - offset).min(stripe as u64) as usize;
        if offset != 0 {
            // A stripe narrower than the block means every surviving block is
            // read once more, for the next slice of it. That is one extra walk
            // over the source however many blocks it covers, so it is counted
            // here, once, and not once per block. The passes read disjoint
            // slices, so this is an extra walk and not a byte fetched twice.
            session.options.diagnostics.note_stripe_pass();
        }
        for syndrome in &mut syndromes {
            syndrome[..take].fill(0);
        }
        // The work for one staged set, which reads nothing: fold surviving
        // block `members[k]`, held in `held[k]`, into every syndrome row, or
        // add recovery row `first + k` to its own syndrome. A deferred set is
        // also scattered here, its blocks in parallel alongside the fold.
        let work = |syndromes: &mut [Vec<u8>],
                    job: StagedWork,
                    members: &[u64],
                    held: &[Vec<u8>]|
         -> EngineResult<()> {
            match job {
                StagedWork::Fold(count) => {
                    let members = &members[..count];
                    let mut sources: [&[u8]; crate::gf::BATCH_SOURCES] =
                        [&[]; crate::gf::BATCH_SOURCES];
                    for (source, bytes) in sources.iter_mut().zip(&held[..count]) {
                        *source = &bytes[..take];
                    }
                    let sources = &sources[..count];
                    let apply = |(syndrome, row): (&mut Vec<u8>, &u64)| -> EngineResult<()> {
                        session.options.cancel.check()?;
                        let mut factors = [F::Symbol::default(); crate::gf::BATCH_SOURCES];
                        for (factor, block) in factors.iter_mut().zip(members) {
                            *factor = crate::cauchy::element(&field, *block, *row)?;
                        }
                        // A set of one calls the single-source kernel itself:
                        // inlined through the batch fallback it compiles to a
                        // slower loop.
                        if let [source] = sources {
                            field.mul_acc(&mut syndrome[..take], source, factors[0]);
                        } else {
                            field.mul_acc_batch(&mut syndrome[..take], sources, &factors[..count]);
                        }
                        Ok(())
                    };
                    let Some(pool) = parallel else {
                        return syndromes.iter_mut().zip(rows.iter()).try_for_each(apply);
                    };
                    pool.install(|| {
                        let mut fold = move || {
                            syndromes
                                .par_iter_mut()
                                .zip(rows.par_iter())
                                .try_for_each(apply)
                        };
                        if !deferred {
                            return fold();
                        }
                        let (written, folded) = rayon::join(
                            || {
                                held[..count]
                                    .par_iter()
                                    .zip(members.par_iter())
                                    .try_for_each(|(bytes, block)| {
                                        session.options.cancel.check()?;
                                        scatter(
                                            &writers,
                                            layout,
                                            outputs,
                                            *block,
                                            offset,
                                            &bytes[..take],
                                        )
                                    })
                            },
                            fold,
                        );
                        written.and(folded)
                    })
                }
                StagedWork::Recovery { first, count } => {
                    let add = |(syndrome, payload): (&mut Vec<u8>, &Vec<u8>)| {
                        for (to, from) in syndrome[..take].iter_mut().zip(&payload[..take]) {
                            *to ^= from;
                        }
                    };
                    let rows = &mut syndromes[first..first + count];
                    match parallel {
                        Some(pool) => pool.install(|| {
                            rows.par_iter_mut()
                                .zip(held[..count].par_iter())
                                .for_each(add)
                        }),
                        None => rows.iter_mut().zip(&held[..count]).for_each(add),
                    }
                    Ok(())
                }
            }
        };
        // Read the next set: surviving blocks in order until a group is held,
        // then the recovery rows a set at a time. Every read of the pass
        // happens here, on the calling thread, in the order the walk has
        // always had. So does every write, unless the set is deferred to the
        // workers, who then write its blocks while this thread reads the
        // next set; the lost blocks are still written here, after the solve.
        let (mut next_block, mut next_row) = (0u64, 0usize);
        let mut fill = |set: &mut [Vec<u8>],
                        members: &mut [u64; crate::gf::BATCH_SOURCES]|
         -> EngineResult<Option<StagedWork>> {
            let mut held = 0;
            while next_block < layout.block_count {
                session.options.cancel.check()?;
                let block = next_block;
                next_block += 1;
                if lost.binary_search(&block).is_ok() {
                    continue;
                }
                // Every block the matrix covers is read for the syndromes, even
                // where a staged clone already holds it and its scatter writes
                // nothing; a block outside it is read only to be written.
                if !coverage.contains(&block) && !needs_write(layout, outputs, block) {
                    continue;
                }
                checks.read_block(
                    block,
                    offset,
                    &mut set[held][..take],
                    &mut covered[..take],
                    Some(writers.owed()),
                )?;
                // A block outside the matrix is held by no set, so it is
                // written here whether or not the sets are deferred.
                if !deferred || !coverage.contains(&block) {
                    scatter(&writers, layout, outputs, block, offset, &set[held][..take])?;
                }
                if coverage.contains(&block) {
                    // One code-matrix element per surviving block per recovery
                    // row, recomputed on every stripe pass. Counted here so the
                    // report can say what that costs before anything caches it.
                    session
                        .options
                        .diagnostics
                        .note_factors(rows.len() as u64, 0);
                    members[held] = block;
                    held += 1;
                    if held == set.len() {
                        return Ok(Some(StagedWork::Fold(held)));
                    }
                }
            }
            if held != 0 {
                return Ok(Some(StagedWork::Fold(held)));
            }
            let first = next_row;
            for input in set.iter_mut() {
                let Some(payload) = assessment.recovery.get(next_row) else {
                    break;
                };
                checks.read(payload, offset, &mut input[..take])?;
                next_row += 1;
            }
            Ok((next_row != first).then_some(StagedWork::Recovery {
                first,
                count: next_row - first,
            }))
        };
        let (mut staged, mut spare) = inputs.split_at_mut(group);
        let mut staged_members = [0u64; crate::gf::BATCH_SOURCES];
        let mut spare_members = staged_members;
        let mut job = fill(staged, &mut staged_members)?;
        while let Some(current) = job {
            job = match parallel {
                // The workers take this set while the calling thread fills the
                // other; the two meet before the sets trade places. A failed
                // fold or write still lets the set being read finish, and is
                // reported ahead of anything that read ran into.
                Some(pool) if !spare.is_empty() => {
                    let mut done = Ok(());
                    let next = {
                        let (held, members, syndromes, done) =
                            (&*staged, &staged_members, &mut syndromes[..], &mut done);
                        pool.in_place_scope(|scope| {
                            scope.spawn(move |_| *done = work(syndromes, current, members, held));
                            fill(spare, &mut spare_members)
                        })
                    };
                    done?;
                    std::mem::swap(&mut staged, &mut spare);
                    std::mem::swap(&mut staged_members, &mut spare_members);
                    next?
                }
                _ => {
                    work(&mut syndromes, current, &staged_members, staged)?;
                    fill(staged, &mut staged_members)?
                }
            };
        }
        // Solve and scatter the lost columns a tile at a time. Columns are
        // still visited in order and each is written exactly once, so the
        // staged bytes and the writes that produce them are unchanged.
        let mut base = 0;
        while base < n {
            let width = tile.min(n - base);
            let recover = |(slot, bytes): (usize, &mut Vec<u8>)| -> EngineResult<()> {
                let column = base + slot;
                session.options.cancel.check()?;
                bytes[..take].fill(0);
                // Every syndrome row feeds this column: a group of them at a
                // time goes through one grouped multiply-accumulate.
                for (first, group) in (0..n)
                    .step_by(crate::gf::BATCH_SOURCES)
                    .zip(syndromes.chunks(crate::gf::BATCH_SOURCES))
                {
                    session.options.cancel.check()?;
                    let mut sources: [&[u8]; crate::gf::BATCH_SOURCES] =
                        [&[]; crate::gf::BATCH_SOURCES];
                    for (source, syndrome) in sources.iter_mut().zip(group) {
                        *source = &syndrome[..take];
                    }
                    let factors = &inverse[column * n + first..column * n + first + group.len()];
                    field.mul_acc_batch(&mut bytes[..take], &sources[..group.len()], factors);
                }
                Ok(())
            };
            if let Some(pool) = &pool {
                pool.pool().install(|| {
                    recovered[..width]
                        .par_iter_mut()
                        .enumerate()
                        .try_for_each(recover)
                })?;
            } else {
                recovered[..width]
                    .iter_mut()
                    .enumerate()
                    .try_for_each(recover)?;
            }
            for (index, bytes) in lost[base..base + width].iter().zip(&recovered[..width]) {
                scatter(&writers, layout, outputs, *index, offset, &bytes[..take])?;
                session.options.diagnostics.note_reconstructed(take);
                progress.advance(take as u64);
                session.options.cancel.check()?;
            }
            base += width;
        }
        // Every source this pass read is checked once, here, so a change
        // within or between passes ends the repair before anything is installed.
        writers.settle()?;
        offset += take as u64;
    }
    Ok(())
}

fn fft_codec_with_source_stripes(
    geometry: crate::fft::FftGeometry,
    options: ExecutionOptions,
    block_size: u64,
    recovery_count: usize,
) -> EngineResult<(crate::fft::FftCodec, usize, crate::runtime::Reservation)> {
    let mut codec = crate::fft::FftCodec::new(geometry, options)?;
    let (stripe, scratch) = codec.reserve_source_stripes(block_size, recovery_count)?;
    Ok((codec, stripe, scratch))
}

fn reconstruct_fft(
    session: &Par3RepairSession,
    checks: &PayloadChecks<'_>,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    outputs: &[StagedFile],
    proof: &StagedProof,
    matrix: &crate::packet::FftMatrixPacket,
) -> EngineResult<()> {
    use crate::fft::{FftGeometry, FftInput};
    use crate::ingest::PayloadKind;
    let assessment = session.assessment.as_ref().expect("assessment");
    let coverage = block_range(matrix.range, layout.block_count)?;
    let cohorts = matrix
        .interleave
        .checked_add(1)
        .ok_or(EngineError::InvalidState("FFT cohort overflow"))?;
    let geometry = FftGeometry::new(
        (coverage.end - coverage.start).div_ceil(cohorts),
        matrix.max_recovery_blocks_log2,
    )?;
    let (codec, stripe, _scratch) = fft_codec_with_source_stripes(
        geometry,
        session.options.clone(),
        layout.block_size,
        assessment.recovery.len(),
    )?;
    let mut covered = vec![0; stripe];
    let mut bytes = vec![0; stripe];
    checks.before_walk(stripe, layout.block_size, Some(&mut bytes))?;
    let writers = StageWriters::new(tree, session, outputs, proof);
    // The proof's frontiers are reserved by the first decode, once its
    // stripe is known and before it reads anything: the first stripe pass
    // opens one for every extent the stripes split and only the last closes
    // them, so taken as they open they found only what the bank left, and
    // where that was too little every staged output read back. They are
    // counted over every extent still unproven, the later cohorts' too.
    let frontiers = ProofFrontiers {
        proof,
        reserved: std::cell::Cell::new(false),
    };
    // Copy only required output ranges outside damaged cohorts. Damaged cohorts
    // copy their intact ranges as their bytes are consumed by the decoder.
    for block in 0..layout.block_count {
        if coverage.contains(&block)
            && assessment
                .lost_blocks
                .iter()
                .any(|lost| lost % cohorts == block % cohorts)
        {
            continue;
        }
        if !needs_write(layout, outputs, block) {
            continue;
        }
        let mut offset = 0;
        while offset < layout.block_size {
            session.options.cancel.check()?;
            let take = (layout.block_size - offset).min(stripe as u64) as usize;
            checks.read_block(
                block,
                offset,
                &mut bytes[..take],
                &mut covered[..take],
                Some(writers.owed()),
            )?;
            scatter(&writers, layout, outputs, block, offset, &bytes[..take])?;
            offset += take as u64;
        }
    }
    writers.settle()?;
    for need in &assessment.requirements {
        let first = coverage.start + (need.cohort + cohorts - coverage.start % cohorts) % cohorts;
        let lost: Vec<usize> = assessment
            .lost_blocks
            .iter()
            .filter(|index| **index % cohorts == need.cohort)
            .map(|index| ((index - first) / cohorts) as usize)
            .collect();
        let recovery: std::collections::BTreeMap<usize, _> = assessment
            .recovery
            .iter()
            .filter_map(|payload| {
                if let PayloadKind::Recovery { index, .. } = payload.kind()
                    && index % cohorts == need.cohort
                {
                    Some(((index / cohorts) as usize, payload))
                } else {
                    None
                }
            })
            .collect();
        let indices: Vec<usize> = recovery.keys().copied().collect();
        // Every surviving block the decoder reads is also written to the
        // staged outputs. With workers, and every output held open ahead,
        // the decoder hands those writes and the proof's hashing of them to
        // its workers, a batch of rows at a time, so the calling thread only
        // reads; otherwise each block is written as it is read, as before.
        let held = codec.worker_count() > 1 && writers.hold(outputs)?;
        let decoded = {
            let consume = |row, offset, bytes: &[u8]| match row {
                FftInput::Original(local) => {
                    let block = first + local as u64 * cohorts;
                    if block >= coverage.end {
                        Ok(())
                    } else {
                        scatter(&writers, layout, outputs, block, offset, bytes)
                    }
                }
                FftInput::Recovery(_) => Ok(()),
            };
            codec.decode_held(
                layout.block_size,
                &lost,
                &indices,
                |row, offset, out| {
                    match row {
                        FftInput::Original(local) => {
                            let block = first + local as u64 * cohorts;
                            if block >= coverage.end {
                                out.fill(0);
                            } else {
                                checks.read_block(
                                    block,
                                    offset,
                                    out,
                                    &mut covered[..out.len()],
                                    Some(writers.owed()),
                                )?;
                                if !held {
                                    consume(row, offset, out)?;
                                }
                            }
                        }
                        FftInput::Recovery(index) => {
                            checks.read(recovery[&index], offset, out)?;
                        }
                    }
                    Ok(())
                },
                held.then_some(&consume),
                |local, offset, bytes| {
                    scatter(
                        &writers,
                        layout,
                        outputs,
                        first + local as u64 * cohorts,
                        offset,
                        bytes,
                    )
                },
                Some(&frontiers),
            )
        };
        if held {
            writers.release();
        }
        decoded?;
        writers.settle()?;
    }
    Ok(())
}

/// The staged proof's frontiers as an FFT decode holds them; reserved once.
struct ProofFrontiers<'a, 'b> {
    proof: &'a StagedProof<'b>,
    reserved: std::cell::Cell<bool>,
}

impl crate::fft::StripeHold for ProofFrontiers<'_, '_> {
    fn bytes(&self, stripe: usize) -> Option<usize> {
        if self.reserved.get() {
            return Some(0);
        }
        self.proof.frontier_bytes(stripe as u64)
    }

    fn reserve(&self, stripe: usize) -> bool {
        if !self.reserved.get() && self.proof.reserve_frontiers(stripe as u64) {
            self.reserved.set(true);
        }
        self.reserved.get()
    }
}

fn open_staged(
    tree: Option<&RepairTree>,
    target: &StagedFile,
    read: bool,
    write: bool,
    options: &ExecutionOptions,
) -> EngineResult<File> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let (Some(tree), Some(in_place), Some(destination)) =
        (tree, target.in_place, target.destination.as_ref())
    {
        return tree.open_in_place(destination, in_place.identity, read, write, options);
    }
    match (tree, target.stage_name.as_deref()) {
        (Some(tree), Some(name)) => tree.open_stage(name, read, write, options),
        (None, None) => OpenOptions::new()
            .read(read)
            .write(write)
            .open_budgeted(&target.temporary, options),
        _ => Err(EngineError::InvalidState("inconsistent repair staging")),
    }
}

/// Staged outputs held open for one reconstruction pass rather than reopened
/// for every extent written. At most a quarter of the handle budget, and at
/// least one, stays open; the least recently written closes first, and an
/// acquirer the budget would otherwise refuse closes them too.
///
/// Reads recorded in [`Self::owed`] are checked against their snapshots once
/// per pass, when the pass calls [`Self::settle`], and every pass settles
/// before anything it staged can be verified or installed. A staged file may
/// briefly hold bytes from a source that has since changed, but such a file
/// only ever ends in [`EngineError::SourceChanged`] with nothing installed.
///
/// Every successful write is also recorded in the [`StagedProof`]. The inline
/// tails [`finish_staged`] writes bypass these writers and record themselves
/// there directly.
struct StageWriters<'a> {
    tree: Option<&'a RepairTree>,
    options: &'a ExecutionOptions,
    access: &'a dyn SourceAccess,
    owed: OwedChecks,
    /// Sources this repair patches in place, whose snapshots its own writes
    /// move on; their outputs are read back instead.
    patched: Vec<crate::source::SourceId>,
    capacity: usize,
    open: Arc<OpenWriters>,
    proof: &'a StagedProof<'a>,
}

#[derive(Default)]
struct OpenWriters {
    slots: Mutex<WriterSlots>,
    /// Set by [`StageWriters::hold`]: the slots hold every output of a walk
    /// whose workers write, and nothing closes them.
    held: AtomicBool,
}

#[derive(Default)]
struct WriterSlots {
    files: Vec<(usize, File, u64)>,
    clock: u64,
}

impl WriterSlots {
    fn take_lru(&mut self) -> Option<File> {
        let position = (0..self.files.len()).min_by_key(|&position| self.files[position].2)?;
        Some(self.files.swap_remove(position).1)
    }
}

impl crate::runtime::IdleHandles for OpenWriters {
    // A writer is idle whenever no write holds the lock and the slots are
    // not held for a walk whose workers write.
    fn close_idle(&self) -> bool {
        if self.held.load(Ordering::Acquire) {
            return false;
        }
        let Ok(mut slots) = self.slots.try_lock() else {
            return false;
        };
        let closed = slots.take_lru();
        drop(slots);
        closed.is_some()
    }
}

impl<'a> StageWriters<'a> {
    fn new(
        tree: Option<&'a RepairTree>,
        session: &'a Par3RepairSession,
        outputs: &[StagedFile],
        proof: &'a StagedProof<'a>,
    ) -> Self {
        let options = &session.options;
        let open = Arc::<OpenWriters>::default();
        let weak: Weak<OpenWriters> = Arc::downgrade(&open);
        options.handles.register_idle(weak);
        Self {
            tree,
            options,
            access: session.access.as_ref(),
            owed: OwedChecks::default(),
            patched: outputs
                .iter()
                .filter_map(|target| target.in_place.map(|in_place| in_place.source))
                .collect(),
            capacity: (options.open_handles.min(options.handles.limit()) / 4).max(1),
            open,
            proof,
        }
    }

    /// Source reads not yet checked; each pass settles them at its end.
    fn owed(&self) -> &OwedChecks {
        &self.owed
    }

    fn settle(&self) -> EngineResult<()> {
        self.owed.settle_except(self.access, &self.patched)
    }

    /// Hold every output open for a walk whose workers write them, so that no
    /// worker ever opens a handle: at the budget's ceiling a worker could
    /// neither close the reader the calling thread is switching nor wait for
    /// it, and a repair that completes on one thread would fail at random.
    /// Returns `false` when the outputs do not all fit the writer capacity or
    /// the budget would not keep two handles free beyond them for the calling
    /// thread's reads; the walk then writes on the calling thread as before,
    /// and nothing was opened for the refusal, so that walk opens what it
    /// always did. Only a budget shared with another user can change between
    /// the check and the opens; what that leaves open stays as the usual
    /// cache.
    fn hold(&self, outputs: &[StagedFile]) -> EngineResult<bool> {
        if outputs.len() > self.capacity {
            return Ok(false);
        }
        let mut slots = self
            .open
            .slots
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let handles = &self.options.handles;
        let room = |slots: &WriterSlots| {
            let unopened = outputs
                .iter()
                .filter(|target| {
                    !slots
                        .files
                        .iter()
                        .any(|(index, _, _)| *index == target.index)
                })
                .count();
            handles.used().saturating_add(unopened + 2) <= handles.limit()
        };
        if !room(&slots) {
            return Ok(false);
        }
        for target in outputs {
            match self.position(&mut slots, target, false) {
                Ok(_) => {}
                Err(EngineError::ResourceLimit(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        if !room(&slots) {
            return Ok(false);
        }
        self.open.held.store(true, Ordering::Release);
        Ok(true)
    }

    /// End a hold: the walk's workers write no more, and what the slots
    /// keep open is the usual cache again, which a budget may close.
    fn release(&self) {
        self.open.held.store(false, Ordering::Release);
    }

    /// The slot holding `target` open, opened if it is not; the write
    /// clock has moved on to this use. With `evict`, a slot past the
    /// capacity, or one the budget needs, closes to make room.
    fn position(
        &self,
        slots: &mut WriterSlots,
        target: &StagedFile,
        evict: bool,
    ) -> EngineResult<usize> {
        slots.clock += 1;
        let clock = slots.clock;
        if let Some(position) = slots
            .files
            .iter()
            .position(|(index, _, _)| *index == target.index)
        {
            slots.files[position].2 = clock;
            return Ok(position);
        }
        if evict && slots.files.len() >= self.capacity {
            drop(slots.take_lru());
        }
        let file = loop {
            match open_staged(self.tree, target, false, true, self.options) {
                Ok(file) => break file,
                Err(EngineError::ResourceLimit(_)) if evict && !slots.files.is_empty() => {
                    drop(slots.take_lru());
                }
                Err(error) => return Err(error),
            }
        };
        slots.files.push((target.index, file, clock));
        Ok(slots.files.len() - 1)
    }

    /// Write `bytes` at `offset` of the staged output in `slot`, the part of
    /// its extent `extent` starting `relative` bytes into that extent.
    fn write(
        &self,
        slot: usize,
        target: &StagedFile,
        extent: usize,
        relative: u64,
        offset: u64,
        bytes: &[u8],
    ) -> EngineResult<()> {
        let mut slots = self
            .open
            .slots
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let position = self.position(&mut slots, target, true)?;
        slots.files[position].1.write_all_at(offset, bytes)?;
        drop(slots);
        // Recorded after the handle lock is released, so the hashing of one
        // write never holds up another. The proof needs the pieces of an
        // extent in order, which the walks guarantee themselves: an extent is
        // written at most once per pass, and a pass joins every write it
        // handed the workers before the next begins.
        self.proof.record(slot, extent, relative, bytes);
        Ok(())
    }
}

fn scatter(
    writers: &StageWriters,
    layout: &BlockLayout,
    outputs: &[StagedFile],
    block: u64,
    offset: u64,
    bytes: &[u8],
) -> EngineResult<()> {
    let Some(locations) = layout.locations(block) else {
        return Ok(());
    };
    for location in locations.iter() {
        let Some(slot) = outputs
            .iter()
            .position(|target| target.index == location.file)
        else {
            continue;
        };
        let target = &outputs[slot];
        let extents = &layout.files[location.file].extents;
        if target.holds(extents, location.extent) {
            continue;
        }
        let Some(extent) = extents.range(location.extent) else {
            continue;
        };
        let Some((_, block_offset)) = extents.block_at(location.extent) else {
            continue;
        };
        let start = offset.max(block_offset);
        let end = (offset + bytes.len() as u64).min(block_offset + extent.end - extent.start);
        if start >= end {
            continue;
        }
        writers.write(
            slot,
            target,
            location.extent,
            start - block_offset,
            extent.start + start - block_offset,
            &bytes[(start - offset) as usize..(end - offset) as usize],
        )?;
    }
    Ok(())
}

fn verify_staged(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    target: &StagedFile,
) -> EngineResult<()> {
    // A large output is hashed in mebibyte reads split across a small
    // admitted pool, as disk verification hashes a large source; the
    // fingerprint is the same either way.
    let large = layout.files[target.index].len >= crate::hash::PARALLEL_SOURCE_BYTES;
    let pool = if large {
        match crate::runtime::WorkerPool::for_work(
            &session.options,
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
            .install(|| read_back(session, layout, tree, target, true)),
        None => read_back(session, layout, tree, target, false),
    }
}

/// [`verify_staged`]'s read: `parallel` only from inside an admitted pool.
fn read_back(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    target: &StagedFile,
    parallel: bool,
) -> EngineResult<()> {
    let mut progress = session.options.stage(crate::runtime::Stage::Verify)?;
    let expected = &layout.files[target.index];
    let memory = &session.options.memory;
    let wide = crate::hash::PARALLEL_HASH_BYTES;
    let reservation = match parallel {
        true => match memory.reserve_as(MemoryCategory::SourceScratch, wide) {
            Ok(reservation) if memory.available() >= 128 << 10 => Some(reservation),
            Ok(_) | Err(EngineError::ResourceLimit(_)) => None,
            Err(error) => return Err(error),
        },
        false => None,
    };
    let (_buffer, size) = match reservation {
        Some(reservation) => (reservation, wide),
        None => {
            let size = session.options.stripe_bytes.min(64 << 10);
            (
                memory.reserve_as(MemoryCategory::SourceScratch, size)?,
                size,
            )
        }
    };
    let parallel = parallel && size >= wide;
    let mut buffer = vec![0u8; size];
    let mut file = open_staged(tree, target, true, false, &session.options)?;
    let mut hash = crate::FingerprintHasher::new();
    // Adjacent protected extents are read as one run, so a run of small
    // blocks still fills the buffer.
    let mut read_run = |range: std::ops::Range<u64>| -> EngineResult<()> {
        file.seek(SeekFrom::Start(range.start))?;
        let mut remaining = range.end - range.start;
        while remaining != 0 {
            session.options.cancel.check()?;
            let take = remaining.min(size as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            hash.update_admitted(&buffer[..take], parallel);
            progress.advance(take as u64);
            remaining -= take as u64;
        }
        Ok(())
    };
    let mut run: Option<std::ops::Range<u64>> = None;
    for index in 0..expected.extents.len() {
        if expected.extents.is_unprotected(index) {
            continue;
        }
        let range = expected.extents.range(index).expect("bounded extent");
        match &mut run {
            Some(open) if open.end == range.start => open.end = range.end,
            _ => {
                if let Some(done) = run.replace(range) {
                    read_run(done)?;
                }
            }
        }
    }
    if let Some(done) = run {
        read_run(done)?;
    }
    if file.metadata()?.len() != expected.len
        || expected.fingerprint == [0; 16]
        || hash.finalize() != expected.fingerprint
    {
        return Err(EngineError::InvalidState(if target.in_place.is_some() {
            "file repaired in place failed protected-data verification"
        } else {
            "rebuilt file failed protected-data verification; temporary retained"
        }));
    }
    Ok(())
}

/// Write the inline tails, synchronize under [`RepairDurability::SyncFiles`],
/// and check every staged output before anything is installed.
///
/// Which check is exact. Every protected extent of an output has an
/// authenticated fingerprint: the set's block checksum for a whole block, the
/// File packet's own fingerprint for a described tail, and the bytes themselves
/// for an inline tail. [`StagedProof`] hashes the bytes each write hands the
/// kernel, in order from the start of the extent, and proves an extent only
/// when that hash matches. The staged file is created by this repair at its
/// final length and only these writes touch its protected ranges, so an output
/// whose every protected extent is proven holds exactly the bytes the
/// authenticated layout describes, which is what the read-back below
/// established by hashing them again from disk. Anything less certain — bytes
/// out of order or written twice, an extent without a fingerprint, an extent
/// never written, a mismatch, a frontier the budget refuses, or a File packet
/// with no whole-file fingerprint — falls back to that read-back, so a staged
/// file built from wrong bytes is refused exactly as before.
///
/// A staged clone is the other way an extent is proven. Such an output was
/// staged as a clone of the local file its source's registry handed over,
/// taken from that handle once its metadata matched the snapshot of the source
/// the evidence verified, and that source was checked against the same
/// snapshot right after the clone and is checked again before installation. A
/// Unix snapshot is the file's identity and change time, so, provided the
/// change time moves with every write, which [`crate::source::SourceSnapshot`]
/// already assumes, the clone holds the bytes the evidence verified. Nothing
/// re-reads a cloned extent: it is proven by that metadata alone. Every
/// extent that evidence holds intact against the extent's own fingerprint is
/// therefore proven without being written, sits inside both the source and
/// the final length, so the resize to that length leaves it alone, and is never
/// written by the repair. Every other protected extent — lost or damaged, past
/// the source's end, inline, or without its own fingerprint — is written and
/// proven as above, or the output reads back.
///
/// The proof never checks the whole-file fingerprint, so metadata that
/// contradicts itself — per-extent fingerprints every byte matches, under a
/// whole-file fingerprint those same bytes do not — is routed to the read-back
/// whenever the evidence already shows it, and the read-back refuses it as
/// before. Where damage hid the contradiction from the evidence, the proof
/// installs the bytes every extent's fingerprint vouches for, the rule
/// [`crate::evidence::StreamingVerifier`] already applies to a file whose bytes
/// it saw out of order; the next repair of that file then fails instead of
/// installing it again.
fn finish_staged(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    tree: Option<&RepairTree>,
    staged: &[StagedFile],
    proof: &StagedProof,
    durability: RepairDurability,
) -> EngineResult<()> {
    for (slot, target) in staged.iter().enumerate() {
        let extents = &layout.files[target.index].extents;
        let inline = (0..extents.len()).any(|index| extents.inline_bytes(index).is_some());
        if !inline && durability == RepairDurability::Buffered {
            continue;
        }
        // Inline tails need no source and no recovery equation.
        let mut file = open_staged(tree, target, false, true, &session.options)?;
        for index in 0..extents.len() {
            if let Some(bytes) = extents.inline_bytes(index) {
                let range = extents.range(index).expect("bounded extent");
                file.seek(SeekFrom::Start(range.start))?;
                file.write_all(bytes)?;
                proof.record(slot, index, 0, bytes);
            }
        }
        if durability == RepairDurability::SyncFiles {
            file.sync_all()?;
        }
    }
    for (slot, target) in staged.iter().enumerate() {
        if !proof.proves(slot) {
            verify_staged(session, layout, tree, target)?;
        }
    }
    Ok(())
}

/// What the staged writes prove about each staged output, one entry per slot
/// of the outputs being staged. See [`finish_staged`] for why a proven output
/// needs no read-back.
struct StagedProof<'a> {
    layout: &'a BlockLayout,
    state: Mutex<ProofState>,
}

struct ProofState {
    outputs: Vec<OutputProof>,
    /// Proven-extent bits and open frontiers; `None` when the budget refused
    /// them, and then every output reads back.
    reservation: Option<crate::runtime::Reservation>,
}

struct OutputProof {
    index: usize,
    /// Something could not be proven; this output reads back.
    doubt: bool,
    /// Protected extents not yet proven.
    unproven: usize,
    proven: Vec<u64>,
    /// Extents written in more than one piece, hashed up to `next`.
    partial: HashMap<usize, PartialProof>,
    /// Frontiers reserved ahead of the walk and not yet opened.
    prepaid: usize,
}

struct PartialProof {
    next: u64,
    /// `None` while [`StagedProof::record`] hashes a piece outside the lock.
    hasher: Option<crate::FingerprintHasher>,
}

/// Budget for one open frontier and its map entry.
const PARTIAL_PROOF_BYTES: usize = 2 * std::mem::size_of::<(usize, PartialProof)>();

/// A write the proof admitted, hashed outside the lock and then closed.
///
/// Both carry a hasher by value: it lives on the stack of the one `record`
/// call that borrows it, and boxing it would cost an allocation per write.
#[allow(clippy::large_enum_variant)]
enum Admitted {
    /// The write covers its whole extent.
    Whole,
    /// The write continues a frontier, whose hasher it borrows; `closes` when
    /// it reaches the end of the extent.
    Frontier {
        hasher: crate::FingerprintHasher,
        closes: bool,
    },
}

/// What the hashing of an admitted write found.
#[allow(clippy::large_enum_variant)]
enum Hashed {
    /// A whole write: the extent's fingerprint.
    Whole(crate::Fingerprint),
    /// The frontier reached the end of the extent: its fingerprint.
    Closed(crate::Fingerprint),
    /// The frontier moved on: the hasher goes back.
    Frontier(crate::FingerprintHasher),
}

impl<'a> StagedProof<'a> {
    fn new(layout: &'a BlockLayout, outputs: &[StagedFile], options: &ExecutionOptions) -> Self {
        let bits = outputs.iter().try_fold(0usize, |sum, target| {
            let words = layout.files[target.index].extents.len().div_ceil(64);
            sum.checked_add(words.checked_mul(8)?)?
                .checked_add(std::mem::size_of::<OutputProof>())
        });
        let reservation = bits.and_then(|bytes| {
            options
                .memory
                .reserve_as(MemoryCategory::OutputStaging, bytes)
                .ok()
        });
        let outputs = outputs
            .iter()
            .map(|target| {
                let file = &layout.files[target.index];
                let mut unproven = (0..file.extents.len())
                    .filter(|&index| !file.extents.is_unprotected(index))
                    .count();
                // A file patched in place is read back whole: its snapshot no
                // longer vouches for the extents the patch did not write.
                let doubt = reservation.is_none()
                    || unproven == 0
                    || file.fingerprint == [0; 16]
                    || target.in_place.is_some();
                let mut proven = if doubt {
                    Vec::new()
                } else {
                    vec![0; file.extents.len().div_ceil(64)]
                };
                // What a staged clone holds is proven by the evidence for the
                // file it cloned; see `finish_staged`.
                if !doubt && target.cloned.is_some() {
                    for index in 0..file.extents.len() {
                        if target.holds(&file.extents, index) {
                            proven[index / 64] |= 1u64 << (index % 64);
                            unproven -= 1;
                        }
                    }
                }
                OutputProof {
                    index: target.index,
                    doubt,
                    unproven,
                    proven,
                    partial: HashMap::new(),
                    prepaid: 0,
                }
            })
            .collect();
        Self {
            layout,
            state: Mutex::new(ProofState {
                outputs,
                reservation,
            }),
        }
    }

    /// Record `bytes` written `relative` bytes into extent `extent` of the
    /// output in `slot`.
    ///
    /// The bytes are hashed outside the lock, so writes to different extents
    /// hash in parallel. The pieces of one extent must still arrive in order
    /// and one at a time: a second piece admitted while the first is being
    /// hashed finds its frontier's hasher on loan and gives the output up,
    /// as an out-of-order piece does.
    fn record(&self, slot: usize, extent: usize, relative: u64, bytes: &[u8]) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let admitted = {
            let ProofState {
                outputs,
                reservation,
            } = &mut *state;
            let Some(output) = outputs.get_mut(slot) else {
                return;
            };
            if output.doubt {
                return;
            }
            let extents = &self.layout.files[output.index].extents;
            match output.admit(extents, extent, relative, bytes.len() as u64, reservation) {
                Some(admitted) => admitted,
                None => {
                    output.give_up(reservation);
                    return;
                }
            }
        };
        drop(state);
        let hashed = match admitted {
            Admitted::Whole => Hashed::Whole(crate::fingerprint(bytes)),
            Admitted::Frontier { mut hasher, closes } => {
                hasher.update(bytes);
                if closes {
                    Hashed::Closed(hasher.finalize())
                } else {
                    Hashed::Frontier(hasher)
                }
            }
        };
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        let Some(output) = outputs.get_mut(slot) else {
            return;
        };
        // Given up while the piece was hashed: nothing to close.
        if output.doubt {
            return;
        }
        let extents = &self.layout.files[output.index].extents;
        if !output.close(extents, extent, bytes.len() as u64, hashed, reservation) {
            output.give_up(reservation);
        }
    }

    /// Frontiers a walk in stripes of `stripe` bytes opens in each output: one
    /// for every extent it writes in more than one piece, with their bytes,
    /// or `None` when those overflow.
    fn frontiers(&self, outputs: &[OutputProof], stripe: u64) -> Option<(Vec<usize>, usize)> {
        // An extent lies within one block, so a stripe as wide as a block
        // writes every extent whole.
        if stripe == 0 || stripe >= self.layout.block_size {
            return Some((vec![0; outputs.len()], 0));
        }
        let counts: Vec<usize> = outputs
            .iter()
            .map(|output| {
                if output.doubt {
                    return 0;
                }
                let extents = &self.layout.files[output.index].extents;
                (0..extents.len())
                    .filter(|&index| output.proven[index / 64] & (1u64 << (index % 64)) == 0)
                    .filter(|&index| {
                        let (Some(range), Some((_, at))) =
                            (extents.range(index), extents.block_at(index))
                        else {
                            return false;
                        };
                        let len = range.end - range.start;
                        len != 0 && at / stripe != (at + len - 1) / stripe
                    })
                    .count()
            })
            .collect();
        let bytes = counts.iter().try_fold(0usize, |sum, &count| {
            sum.checked_add(count.checked_mul(PARTIAL_PROOF_BYTES)?)
        })?;
        Some((counts, bytes))
    }

    /// Bytes [`Self::reserve_frontiers`] would take for `stripe`.
    fn frontier_bytes(&self, stripe: u64) -> Option<usize> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.reservation.as_ref()?;
        self.frontiers(&state.outputs, stripe)
            .map(|(_, bytes)| bytes)
    }

    /// Reserve now a frontier for every extent a walk in stripes of `stripe`
    /// bytes writes in more than one piece. The first pass opens them all and
    /// only the last closes them, so a walk that takes spare budget for
    /// itself must not take these bytes, or the proof gives up and every
    /// output reads back. Returns `false` when they do not fit; frontiers are
    /// then reserved as they open, as before.
    fn reserve_frontiers(&self, stripe: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.reservation.is_none() {
            return true;
        }
        let Some((counts, bytes)) = self.frontiers(&state.outputs, stripe) else {
            return false;
        };
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        if bytes != 0
            && reservation
                .as_mut()
                .is_none_or(|reservation| reservation.grow_by(bytes).is_err())
        {
            return false;
        }
        for (output, count) in outputs.iter_mut().zip(counts) {
            output.prepaid += count;
        }
        true
    }

    /// Read the output in `slot` back whatever its writes prove.
    fn doubt(&self, slot: usize) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        if let Some(output) = outputs.get_mut(slot) {
            output.give_up(reservation);
        }
    }

    /// Whether every protected byte of the output in `slot` is proven.
    fn proves(&self, slot: usize) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .outputs
            .get(slot)
            .is_some_and(|output| !output.doubt && output.unproven == 0)
    }
}

impl OutputProof {
    /// Nothing more is learnt from this output: it reads back, and its
    /// frontiers go.
    fn give_up(&mut self, reservation: &mut Option<crate::runtime::Reservation>) {
        if let Some(reservation) = reservation.as_mut() {
            let held = (self.partial.len() + self.prepaid) * PARTIAL_PROOF_BYTES;
            reservation.shrink_to(reservation.bytes() - held);
        }
        self.doubt = true;
        self.partial = HashMap::new();
        self.prepaid = 0;
    }

    /// Admit one write of `len` bytes into the proof, lending it the hasher
    /// it continues, or say it cannot be proven. A frontier opened here holds
    /// its budget until [`Self::close`] returns the hasher or finishes it.
    fn admit(
        &mut self,
        extents: &crate::layout::FileExtents,
        extent: usize,
        relative: u64,
        len: u64,
        reservation: &mut Option<crate::runtime::Reservation>,
    ) -> Option<Admitted> {
        let range = extents.range(extent)?;
        let extent_len = range.end - range.start;
        let (word, bit) = (extent / 64, 1u64 << (extent % 64));
        if self.proven[word] & bit != 0 {
            return None;
        }
        let end = relative.checked_add(len).filter(|&end| end <= extent_len)?;
        let closes = end == extent_len;
        match self.partial.get_mut(&extent) {
            Some(partial) => {
                if partial.next != relative {
                    return None;
                }
                // On loan: another piece of this extent is still being hashed.
                let hasher = partial.hasher.take()?;
                Some(Admitted::Frontier { hasher, closes })
            }
            None if relative != 0 => None,
            None if closes => Some(Admitted::Whole),
            None => {
                if self.prepaid != 0 {
                    self.prepaid -= 1;
                } else {
                    reservation.as_mut()?.grow_by(PARTIAL_PROOF_BYTES).ok()?;
                }
                self.partial.insert(
                    extent,
                    PartialProof {
                        next: 0,
                        hasher: None,
                    },
                );
                Some(Admitted::Frontier {
                    hasher: crate::FingerprintHasher::new(),
                    closes,
                })
            }
        }
    }

    /// Close the write [`Self::admit`] admitted, now hashed: return the
    /// frontier's hasher, or prove the extent by its fingerprint, or say it
    /// cannot be proven. An extent proven, or a frontier opened for it, while
    /// the write was being hashed means the extent was written twice, which
    /// cannot be proven either.
    fn close(
        &mut self,
        extents: &crate::layout::FileExtents,
        extent: usize,
        len: u64,
        hashed: Hashed,
        reservation: &mut Option<crate::runtime::Reservation>,
    ) -> bool {
        let (word, bit) = (extent / 64, 1u64 << (extent % 64));
        if self.proven[word] & bit != 0 {
            return false;
        }
        let actual = match hashed {
            Hashed::Frontier(hasher) => {
                let Some(partial) = self.partial.get_mut(&extent) else {
                    return false;
                };
                partial.hasher = Some(hasher);
                partial.next += len;
                return true;
            }
            Hashed::Whole(actual) => {
                if self.partial.contains_key(&extent) {
                    return false;
                }
                actual
            }
            Hashed::Closed(actual) => {
                if self.partial.remove(&extent).is_none() {
                    return false;
                }
                if let Some(reservation) = reservation.as_mut() {
                    reservation.shrink_to(reservation.bytes() - PARTIAL_PROOF_BYTES);
                }
                actual
            }
        };
        let expected = match extents.get(extent).map(|extent| extent.kind) {
            Some(crate::layout::ExtentKind::Block {
                fingerprint: Some(fingerprint),
                ..
            }) => fingerprint,
            Some(crate::layout::ExtentKind::Inline(bytes)) => crate::fingerprint(&bytes),
            _ => return false,
        };
        if actual != expected {
            return false;
        }
        self.proven[word] |= bit;
        self.unproven -= 1;
        true
    }
}

/// Find the first pair of destinations a filesystem may merge under `key`.
fn destination_collision(
    files: &[crate::session::AssessedFile],
    key: impl Fn(&str) -> String,
) -> Option<(usize, usize)> {
    let mut folded: HashMap<String, usize> = HashMap::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        if let Some(first) = folded.insert(key(&file.path), index)
            && (!files[first].complete || !file.complete)
        {
            return Some((first, index));
        }
    }
    None
}

fn collision_aliases(
    tree: &RepairTree,
    files: &[crate::session::AssessedFile],
    key: impl Fn(&str) -> String,
) -> EngineResult<bool> {
    collision_aliases_by(files, key, |first, second| {
        Ok(tree.paths_alias(first, second)?)
    })
}

fn collision_aliases_by(
    files: &[crate::session::AssessedFile],
    key: impl Fn(&str) -> String,
    mut probe: impl FnMut(&str, &str) -> EngineResult<bool>,
) -> EngineResult<bool> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, file) in files.iter().enumerate() {
        let previous = groups.entry(key(&file.path)).or_default();
        for &first in previous.iter() {
            if (!files[first].complete || !file.complete) && probe(&files[first].path, &file.path)?
            {
                return Ok(true);
            }
        }
        previous.push(index);
    }
    Ok(false)
}

/// Refuse a set whose paths the destination filesystem cannot tell apart.
///
/// Case and Unicode-normalization collisions belong to the mounted filesystem,
/// not the operating system. Candidate pairs are found in memory, then probed
/// in their actual destination parents before any output is created.
fn refuse_aliased_destinations(
    tree: &RepairTree,
    files: &[crate::session::AssessedFile],
) -> EngineResult<()> {
    if destination_collision(files, str::to_owned).is_some()
        || collision_aliases(tree, files, crate::paths::case_folded)?
        || collision_aliases(tree, files, crate::repair_tree::normalization_key)?
        || collision_aliases(tree, files, crate::repair_tree::case_normalization_key)?
    {
        return Err(EngineError::InvalidState(
            "repair destinations resolve to the same filesystem path",
        ));
    }
    Ok(())
}

/// Resolve a destination and refuse any existing symbolic-link leaf before
/// reconstruction creates a temporary output.
fn repair_destination(tree: &RepairTree, relative: &str) -> EngineResult<Destination> {
    let destination = tree.destination(relative)?;
    tree.check_existing_destination(&destination)?;
    Ok(destination)
}

/// Resolve one set-carried relative path inside `base`, creating parents.
///
/// The name-safety rules in [`crate::paths`] are applied to the whole path
/// before the first directory is created, so a path that breaks a rule in a
/// late component never leaves a partial tree behind, and no output byte is
/// ever written under a name the engine would refuse. The rules are the same
/// ones set creation applies, and the same on every platform; what remains
/// here is the part that must consult the filesystem, which is the refusal to
/// follow a symbolic link out of `base`.
#[cfg(test)]
pub(crate) fn contained_destination(base: &Path, relative: &str) -> EngineResult<PathBuf> {
    crate::paths::validate_relative_path(relative)?;
    let tree = RepairTree::new(base, std::iter::once(relative))?;
    Ok(repair_destination(&tree, relative)?.display)
}

pub(crate) fn stage_path(destination: &Path, options: &ExecutionOptions) -> EngineResult<PathBuf> {
    let parent = destination
        .parent()
        .ok_or(EngineError::InvalidState("output has no parent"))?;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".par3-repair-{sequence}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open_budgeted(&temporary, options)
        {
            Ok(_) => return Ok(temporary),
            Err(EngineError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(EngineError::resource_limit("temporary output names"))
}

/// Create a staging file under a name [`stage_path`] would choose, as a clone
/// of the open file `source`; `None` when the filesystem cannot clone it here,
/// and the caller stages with [`stage_path`] instead.
#[cfg(target_os = "macos")]
pub(crate) fn clone_stage_path(
    destination: &Path,
    source: &impl std::os::fd::AsFd,
) -> EngineResult<Option<PathBuf>> {
    use crate::repair_tree::clone;
    let parent = destination
        .parent()
        .ok_or(EngineError::InvalidState("output has no parent"))?;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".par3-repair-{sequence}.tmp"));
        #[cfg(test)]
        let refused = crate::repair_tree::REFUSE_CLONES.with(std::cell::Cell::get);
        #[cfg(not(test))]
        let refused = false;
        let cloned = if refused {
            Err(std::io::Error::from_raw_os_error(libc::EXDEV))
        } else {
            clone::clone_path(source, &temporary)
        };
        match cloned {
            Ok(()) => return Ok(Some(temporary)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) if clone::unsupported(&error) => {
                tracing::debug!(%error, "PAR3 staging copies instead of cloning");
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(EngineError::resource_limit("temporary output names"))
}

// Keep the two supported scalar field representations checked by this module's
// generic execution bounds even on targets without SIMD.
const _: fn() = || {
    fn supported<F: Field + Sync>()
    where
        F::Symbol: Send + Sync,
    {
    }
    supported::<Gf8>();
    supported::<Gf16>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_fft_source_stripes_leave_room_for_gf16_decode_state() {
        let options = ExecutionOptions {
            memory: crate::runtime::MemoryBudget::new(1 << 20),
            stripe_bytes: 1 << 20,
            workers: 1,
            ..ExecutionOptions::default()
        };
        let budget = options.memory.clone();
        let geometry = crate::fft::FftGeometry::new(129, 7).unwrap();
        assert_eq!(geometry.field_bytes(), 2);
        let (codec, stripe, scratch) =
            fft_codec_with_source_stripes(geometry, options, 256 << 10, 1).unwrap();
        assert!(stripe > 0 && stripe <= 256 << 10 && stripe.is_multiple_of(2));
        // Another session may consume the sizing headroom before decode.
        // Admission must fail safely, without output or leaked reservations,
        // and the same codec must remain usable after the peer returns memory.
        let peer = budget.reserve(budget.available()).unwrap();
        let held = budget.used();
        let blocked = codec.decode(
            2,
            &[0],
            &[0],
            |_, _, _| panic!("no source reads before decode admission"),
            |_, _, _| panic!("no output before decode admission"),
        );
        assert!(matches!(blocked, Err(EngineError::ResourceLimit(_))));
        assert_eq!(budget.used(), held);
        drop(peer);
        let mut repaired = Vec::new();
        codec
            .decode(
                2,
                &[0],
                &[0],
                |_, _, out| {
                    out.fill(0);
                    Ok(())
                },
                |index, offset, out| {
                    assert_eq!((index, offset), (0, 0));
                    repaired.extend_from_slice(out);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(repaired, [0, 0]);
        assert!(budget.used() <= budget.limit());
        drop((codec, scratch));
        assert_eq!(budget.used(), 0);
    }

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn replacement_keeps_expected_bytes(backup: bool) {
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "par3-install-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let destination = directory.0.join("damaged.bin");
        let existing_backup = directory.0.join("damaged.bin.1");
        std::fs::write(&destination, b"damaged bytes").unwrap();
        std::fs::write(&existing_backup, b"earlier backup").unwrap();
        let options = ExecutionOptions::default();
        let tree = RepairTree::new(&directory.0, ["damaged.bin"]).unwrap();
        let resolved = tree.destination("damaged.bin").unwrap();
        let (stage_name, temporary) = tree
            .create_stage(0, b"verified repaired bytes".len() as u64, &options)
            .unwrap();
        std::fs::write(&temporary, b"verified repaired bytes").unwrap();

        let saved = tree
            .install(&stage_name, &resolved, backup, RepairDurability::SyncFiles)
            .unwrap();

        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"verified repaired bytes"
        );
        assert!(!temporary.exists());
        assert_eq!(std::fs::read(&existing_backup).unwrap(), b"earlier backup");
        if backup {
            let expected = directory.0.join("damaged.bin.2");
            assert_eq!(saved.as_deref(), Some(expected.as_path()));
            assert_eq!(std::fs::read(expected).unwrap(), b"damaged bytes");
        } else {
            assert!(saved.is_none());
            assert!(!directory.0.join("damaged.bin.2").exists());
        }
    }

    #[test]
    fn install_replaces_an_existing_file_with_a_numbered_backup() {
        replacement_keeps_expected_bytes(true);
    }

    #[test]
    fn install_replaces_an_existing_file_without_a_backup() {
        replacement_keeps_expected_bytes(false);
    }

    fn scratch(name: &str) -> TestDirectory {
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "par3-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        directory
    }

    fn refused(base: &Path, relative: &str) -> crate::paths::PathRule {
        match contained_destination(base, relative) {
            Err(EngineError::UnsafePath(violation)) => {
                assert!(
                    relative.starts_with(&violation.path),
                    "the refusal names the path it refused, truncated at most"
                );
                violation.rule
            }
            other => panic!("{relative:?} should be refused as unsafe, got {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_destination_is_still_resolved_and_its_parents_created() {
        let directory = scratch("destination");
        let base = &directory.0;
        let resolved = contained_destination(base, "season 1/ep 01.mkv").unwrap();
        assert_eq!(resolved, base.join("season 1").join("ep 01.mkv"));
        assert!(base.join("season 1").is_dir());
        // The leaf itself is never created here, only its parents.
        assert!(!resolved.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_leaf_is_refused_before_staging() {
        let directory = scratch("destination-leaf-link");
        let base = &directory.0;
        let victim = base.join("victim.bin");
        std::fs::write(&victim, b"outside bytes").unwrap();
        std::os::unix::fs::symlink(&victim, base.join("damaged.bin")).unwrap();

        let error = contained_destination(base, "damaged.bin").unwrap_err();
        assert!(matches!(
            error,
            EngineError::Io(ref error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(std::fs::read(&victim).unwrap(), b"outside bytes");
        assert!(std::fs::read_dir(base).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".par3-stage-")
        }));
    }

    #[test]
    fn every_unsafe_destination_class_is_refused_by_the_shared_rule_table() {
        use crate::paths::PathRule;
        let directory = scratch("unsafe-destination");
        let base = &directory.0;
        for (relative, rule) in [
            ("", PathRule::Empty),
            ("a//b", PathRule::Empty),
            ("out/", PathRule::Empty),
            ("/etc/passwd", PathRule::Absolute),
            ("C:/Windows/System32", PathRule::Absolute),
            ("c:hosts", PathRule::Absolute),
            ("./file", PathRule::CurrentDirectory),
            ("../escape", PathRule::ParentDirectory),
            ("a/../../escape", PathRule::ParentDirectory),
            ("a\\b", PathRule::Backslash),
            ("a:b", PathRule::Absolute),
            ("ab:c", PathRule::Colon),
            ("dir/stream:$DATA", PathRule::Colon),
            ("what?.bin", PathRule::ForbiddenCharacter),
            ("star*.bin", PathRule::ForbiddenCharacter),
            ("quote\".bin", PathRule::ForbiddenCharacter),
            ("less<.bin", PathRule::ForbiddenCharacter),
            ("more>.bin", PathRule::ForbiddenCharacter),
            ("pipe|.bin", PathRule::ForbiddenCharacter),
            ("deep/dir/glob*", PathRule::ForbiddenCharacter),
            ("nul\u{0}byte", PathRule::Control),
            ("bell\u{7}", PathRule::Control),
            ("CON", PathRule::ReservedDevice),
            ("con.txt", PathRule::ReservedDevice),
            ("deep/dir/LPT9.tar.gz", PathRule::ReservedDevice),
            ("trailing ", PathRule::TrailingSpaceOrDot),
            ("trailing.", PathRule::TrailingSpaceOrDot),
            ("dir./file", PathRule::TrailingSpaceOrDot),
        ] {
            assert_eq!(refused(base, relative), rule, "{relative:?}");
        }
        assert_eq!(
            refused(base, &"n".repeat(crate::paths::MAX_COMPONENT_BYTES + 1)),
            PathRule::ComponentTooLong
        );
        assert_eq!(
            refused(base, &"a/".repeat(crate::paths::MAX_PATH_BYTES)),
            PathRule::PathTooLong
        );
        // Nothing was created on the way to any of those refusals.
        assert_eq!(std::fs::read_dir(base).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_name_this_filesystem_would_have_accepted_is_still_refused() {
        // Every one of these is a legal file name on unix, so the refusal is
        // the engine's alone: it must not depend on the host noticing.
        let directory = scratch("hostile-but-legal");
        let base = &directory.0;
        for legal in ["con.txt", "COM1", "a\\b", "a:b", "trailing.", "trailing "] {
            let native = base.join(legal);
            std::fs::write(&native, b"proof this name is legal here").unwrap();
            assert!(native.exists(), "{legal:?} should be a legal unix name");
            std::fs::remove_file(&native).unwrap();
            assert!(
                matches!(
                    contained_destination(base, legal),
                    Err(EngineError::UnsafePath(_))
                ),
                "{legal:?} should still be refused"
            );
        }
    }

    #[test]
    fn a_late_unsafe_component_creates_no_directories_at_all() {
        let directory = scratch("no-partial-tree");
        let base = &directory.0;
        assert!(matches!(
            contained_destination(base, "keep/these/../escape"),
            Err(EngineError::UnsafePath(_))
        ));
        assert!(!base.join("keep").exists());
        assert_eq!(std::fs::read_dir(base).unwrap().count(), 0);
    }
}

#[cfg(test)]
mod charge_tests {
    use super::*;
    use crate::gf::{Gf8, Gf16};
    use crate::runtime::{MemoryBudget, MemoryCategory};

    /// The coefficient charge is taken before `inverse_coefficients` runs, so
    /// it has to cover the vectors that solve builds as well as the inverse it
    /// keeps — and must not ask for so much more that a solvable set is refused.
    #[test]
    fn cauchy_coefficient_charge_covers_the_solve_and_what_it_returns() {
        for n in [1usize, 17, 256, 4096] {
            let lost: Vec<u64> = (0..n as u64).collect();
            let rows: Vec<u64> = (0..n as u64).collect();
            let gf16 = Gf16::default();
            let inverse = crate::cauchy::inverse_coefficients(&gf16, &lost, &rows).unwrap();
            // What the solve holds at its peak: the returned inverse plus the
            // four `n`-symbol vectors it is built from.
            let retained = inverse.capacity() * size_of::<u16>();
            let peak = retained + 4 * n * size_of::<u16>();
            let charge = cauchy_coefficient_bytes::<Gf16>(n).unwrap();
            assert!(
                charge >= peak,
                "{n} lost blocks charge {charge} for a {peak} byte solve"
            );
            assert!(
                charge < peak * 2 + 4096,
                "{n} lost blocks charge {charge}, far above their {peak} byte solve"
            );
            assert!(
                charge > retained,
                "the charge must outlast nothing but the peak"
            );
        }
        // GF(2^8) symbols are half the width, and the charge must follow.
        assert!(
            cauchy_coefficient_bytes::<Gf8>(256).unwrap()
                < cauchy_coefficient_bytes::<Gf16>(256).unwrap()
        );
    }

    /// The stripe banks are vectors of vectors. Their row headers do not scale
    /// with the stripe, so a small stripe and many lost blocks must still be
    /// charged for every header. Output tiling narrows the recovered bank from
    /// `n` rows to `tile` rows; the charge must follow that too.
    #[test]
    fn cauchy_stripe_banks_charge_their_row_headers_as_well_as_their_bytes() {
        for (n, limit) in [(4usize, 1 << 20), (512, 8 << 20), (4096, 64 << 20)] {
            let options = ExecutionOptions {
                memory: MemoryBudget::new(limit),
                workers: 1,
                stripe_bytes: 4096,
                ..ExecutionOptions::default()
            };
            // Exactly the shape `reconstruct` computes: the syndrome bank keeps
            // every row, the output bank keeps one tile.
            let tile = options.workers.max(1).min(n);
            let buffer_count = n + tile + 3;
            let bank_headers = (n + tile) * size_of::<Vec<u8>>();
            assert!(
                buffer_count < n * 2 + 3,
                "tiling did not narrow the {n}-row bank"
            );
            let (stripe, reservation) = options
                .memory
                .reserve_stripes_with_overhead(
                    MemoryCategory::CodecScratch,
                    options.stripe_bytes,
                    buffer_count,
                    Gf16::SYMBOL_BYTES,
                    bank_headers,
                )
                .unwrap();

            // Exactly what `reconstruct` allocates once the charge is granted.
            let syndromes = vec![vec![0u8; stripe]; n];
            let recovered = vec![vec![0u8; stripe]; tile];
            let input = vec![0u8; stripe];
            let covered = vec![0u8; stripe];
            let bank = |bank: &Vec<Vec<u8>>| {
                bank.capacity() * size_of::<Vec<u8>>()
                    + bank.iter().map(Vec::capacity).sum::<usize>()
            };
            let measured =
                bank(&syndromes) + bank(&recovered) + input.capacity() + covered.capacity();
            assert!(
                reservation.bytes() >= measured,
                "{n} lost blocks charge {} for {measured} bytes of stripe banks",
                reservation.bytes()
            );
            assert!(
                reservation.bytes() < measured * 2,
                "{n} lost blocks charge {}, more than twice their {measured} bytes",
                reservation.bytes()
            );
            drop((syndromes, recovered, input, covered));
            drop(reservation);
            assert_eq!(options.memory.used(), 0);
            assert_eq!(options.memory.ledger().current(), 0);
        }
    }
    /// PR #73 round 4, finding D. A set naming two paths one filesystem would
    /// merge is found before anything is staged. The finder is pure — it reads
    /// the assessment only — so it is asked here directly; what the repair
    /// then does about a collision depends on the destination, and is the
    /// subject of the test below.
    #[test]
    fn destinations_that_differ_only_by_letter_case_are_found() {
        let assessed = |path: &str, complete: bool| crate::session::AssessedFile {
            path: path.to_owned(),
            source: None,
            complete,
            verified_prefix: 0,
            unresolved: Vec::new(),
        };

        assert_eq!(
            destination_collision(
                &[assessed("a/Readme", false), assessed("a/notes", false)],
                crate::paths::case_folded,
            ),
            None,
            "two names that share nothing"
        );
        assert_eq!(
            destination_collision(
                &[assessed("one/Readme", false), assessed("two/README", false),],
                crate::paths::case_folded,
            ),
            None,
            "one spelling in two directories is two paths"
        );
        assert_eq!(
            destination_collision(
                &[assessed("a/Readme", false), assessed("a/README", false),],
                crate::paths::case_folded,
            ),
            Some((0, 1)),
            "two outputs would be written to one file"
        );

        // A file already whole on disk is just as lost if another file's output
        // lands on its name.
        assert_eq!(
            destination_collision(
                &[assessed("a/Readme", true), assessed("a/README", false)],
                crate::paths::case_folded,
            ),
            Some((0, 1)),
            "an output would land on a file that is already whole"
        );

        // Two files that are both complete are written nowhere, so nothing is
        // at risk and the repair is not refused for a collision it never makes.
        assert_eq!(
            destination_collision(
                &[assessed("a/Readme", true), assessed("a/README", true)],
                crate::paths::case_folded,
            ),
            None,
            "nothing is staged, so nothing collides"
        );
    }

    /// PR #73 round 4, finding D, and the CI fix that followed it. A set naming
    /// `Readme` and `README` is legitimate — a case-sensitive producer makes
    /// one — so the refusal belongs to the destination, not to the set. The
    /// preflight asks the directory it is about to write into, and must leave
    /// no probe behind either way. The expected answer is whatever this
    /// machine's temporary directory actually does, which the test discovers
    /// the same way the preflight does.
    #[test]
    fn a_case_folded_pair_is_refused_only_where_the_destination_folds_case() {
        let tree = crate::test_reference::TempTree::new("case-folded-destinations");
        let assessed = |path: &str| crate::session::AssessedFile {
            path: path.to_owned(),
            source: None,
            complete: false,
            verified_prefix: 0,
            unresolved: Vec::new(),
        };
        let entries = || {
            let mut names: Vec<String> = std::fs::read_dir(tree.path())
                .expect("the destination is readable")
                .map(|entry| {
                    entry
                        .expect("an entry")
                        .file_name()
                        .to_string_lossy()
                        .into()
                })
                .collect();
            names.sort();
            names
        };

        let repair_tree = RepairTree::new(tree.path(), ["Readme", "README"]).unwrap();
        refuse_aliased_destinations(&repair_tree, &[assessed("Readme"), assessed("notes")])
            .expect("two names that share nothing");
        let folds = repair_tree.paths_alias("Readme", "README").unwrap();
        let outcome =
            refuse_aliased_destinations(&repair_tree, &[assessed("Readme"), assessed("README")]);
        if folds {
            let error = outcome.expect_err("two outputs would be written to one file here");
            assert!(
                matches!(error, EngineError::InvalidState(reason) if reason.contains("same filesystem path")),
                "refused for the wrong reason: {error}"
            );
        } else {
            outcome.expect("two distinct files on a case-sensitive destination");
        }
        drop(repair_tree);
        assert!(
            entries().is_empty(),
            "the case probe was left behind: {:?}",
            entries()
        );
    }

    #[test]
    fn canonically_equivalent_unicode_names_follow_destination_semantics() {
        let tree = crate::test_reference::TempTree::new("normalized-destinations");
        let composed = "caf\u{e9}.bin";
        let decomposed = "cafe\u{301}.bin";
        let assessed = |path: &str| crate::session::AssessedFile {
            path: path.to_owned(),
            source: None,
            complete: false,
            verified_prefix: 0,
            unresolved: Vec::new(),
        };
        let repair_tree = RepairTree::new(tree.path(), [composed, decomposed]).unwrap();
        let aliases = repair_tree.paths_alias(composed, decomposed).unwrap();
        let outcome =
            refuse_aliased_destinations(&repair_tree, &[assessed(composed), assessed(decomposed)]);
        assert_eq!(outcome.is_err(), aliases);
    }

    #[test]
    fn every_collision_group_and_pair_is_probed_until_an_alias_is_found() {
        let files: Vec<_> = ["a/Readme", "a/README", "b/File", "b/FILE", "b/file"]
            .into_iter()
            .map(|path| crate::session::AssessedFile {
                path: path.to_owned(),
                source: None,
                complete: false,
                verified_prefix: 0,
                unresolved: Vec::new(),
            })
            .collect();
        let mut probed = Vec::new();
        let aliases = collision_aliases_by(&files, crate::paths::case_folded, |first, second| {
            probed.push((first.to_owned(), second.to_owned()));
            Ok(first == "b/File" && second == "b/file")
        })
        .unwrap();
        assert!(aliases);
        assert_eq!(
            probed,
            vec![
                ("a/Readme".into(), "a/README".into()),
                ("b/File".into(), "b/FILE".into()),
                ("b/File".into(), "b/file".into()),
            ]
        );
    }
}

#[cfg(test)]
mod proof_tests {
    //! A staged output is installed without a read-back only when its writes
    //! proved every protected extent; anything else must read it back.
    use super::*;
    use crate::layout::ExtentKind;
    use crate::runtime::MemoryBudget;

    struct Case {
        layout: BlockLayout,
        staged: Vec<StagedFile>,
        /// Per protected extent of each staged output: index and its bytes.
        extents: Vec<Vec<(usize, Vec<u8>)>>,
    }

    /// Every file of the GF(2^8) reference set, staged.
    fn case() -> Case {
        let layout = BlockLayout::new(
            &crate::test_reference::gf8_set(),
            &ExecutionOptions::default(),
        )
        .unwrap();
        let contents = crate::test_reference::gf8_contents();
        let mut staged = Vec::new();
        let mut extents = Vec::new();
        for (index, file) in layout.files.iter().enumerate() {
            let bytes = &contents
                .iter()
                .find(|(name, _)| *name == file.path)
                .expect("reference contents")
                .1;
            staged.push(StagedFile {
                index,
                destination: None,
                stage_name: None,
                temporary: PathBuf::new(),
                cloned: None,
                in_place: None,
            });
            let mut protected = Vec::new();
            for extent in 0..file.extents.len() {
                let item = file.extents.get(extent).unwrap();
                match item.kind {
                    ExtentKind::Block {
                        fingerprint: Some(_),
                        ..
                    }
                    | ExtentKind::Inline(_) => {}
                    ExtentKind::Unprotected => continue,
                    ExtentKind::Block { .. } => panic!("the reference set fingerprints extents"),
                }
                let range = item.range.start as usize..item.range.end as usize;
                protected.push((extent, bytes[range].to_vec()));
            }
            assert!(!protected.is_empty(), "{}", file.path);
            extents.push(protected);
        }
        Case {
            layout,
            staged,
            extents,
        }
    }

    fn options(budget: usize) -> ExecutionOptions {
        ExecutionOptions {
            memory: MemoryBudget::new(budget),
            ..ExecutionOptions::default()
        }
    }

    fn proven(case: &Case, proof: &StagedProof) -> Vec<bool> {
        (0..case.staged.len())
            .map(|slot| proof.proves(slot))
            .collect()
    }

    #[test]
    fn whole_or_in_order_writes_prove_every_output_and_release_their_frontiers() {
        let case = case();
        for piece in [usize::MAX, 1000, 1] {
            let options = options(1 << 20);
            let proof = StagedProof::new(&case.layout, &case.staged, &options);
            let base = options.memory.used();
            for (slot, extents) in case.extents.iter().enumerate() {
                for (extent, bytes) in extents {
                    for (at, chunk) in bytes.chunks(piece.min(bytes.len())).enumerate() {
                        let relative = (at * piece.min(bytes.len())) as u64;
                        proof.record(slot, *extent, relative, chunk);
                    }
                }
            }
            assert!(proven(&case, &proof).iter().all(|&ok| ok), "{piece}");
            assert_eq!(options.memory.used(), base, "{piece}: a frontier leaked");
            drop(proof);
            assert_eq!(options.memory.used(), 0);
        }
    }

    #[test]
    fn anything_short_of_proof_reads_the_output_back() {
        let case = case();
        let slot = case
            .extents
            .iter()
            .position(|extents| extents.iter().any(|(_, bytes)| bytes.len() > 1))
            .expect("an extent longer than a byte");
        let (target, _) = case.extents[slot]
            .iter()
            .find(|(_, bytes)| bytes.len() > 1)
            .cloned()
            .unwrap();
        type Write = fn(&StagedProof, usize, usize, &[u8]);
        let wrong: [(&str, Write); 5] = [
            ("missing", |_, _, _, _| {}),
            ("flipped", |proof, slot, extent, bytes| {
                let mut bytes = bytes.to_vec();
                bytes[0] ^= 1;
                proof.record(slot, extent, 0, &bytes);
            }),
            ("out of order", |proof, slot, extent, bytes| {
                let half = bytes.len() / 2;
                proof.record(slot, extent, half as u64, &bytes[half..]);
                proof.record(slot, extent, 0, &bytes[..half]);
            }),
            ("rewritten", |proof, slot, extent, bytes| {
                proof.record(slot, extent, 0, bytes);
                proof.record(slot, extent, 0, bytes);
            }),
            ("past its end", |proof, slot, extent, bytes| {
                let mut bytes = bytes.to_vec();
                bytes.push(0);
                proof.record(slot, extent, 0, &bytes);
            }),
        ];
        for (name, write) in wrong {
            let options = options(1 << 20);
            let proof = StagedProof::new(&case.layout, &case.staged, &options);
            for (at, extents) in case.extents.iter().enumerate() {
                for (extent, bytes) in extents {
                    if at == slot && *extent == target {
                        write(&proof, at, *extent, bytes);
                    } else {
                        proof.record(at, *extent, 0, bytes);
                    }
                }
            }
            let proven = proven(&case, &proof);
            for (at, ok) in proven.into_iter().enumerate() {
                assert_eq!(ok, at != slot, "{name}: output {at}");
            }
        }
    }

    #[test]
    fn a_proof_the_budget_refuses_reads_every_output_back() {
        let case = case();
        // No room for the proven-extent bits: nothing is proven.
        let options = options(0);
        let proof = StagedProof::new(&case.layout, &case.staged, &options);
        for (slot, extents) in case.extents.iter().enumerate() {
            for (extent, bytes) in extents {
                proof.record(slot, *extent, 0, bytes);
            }
        }
        assert!(proven(&case, &proof).iter().all(|&ok| !ok));
        // Room for the bits but not a frontier: an extent written in pieces
        // cannot be proven, while one written whole still is.
        let probe = options_with_bits(&case);
        let proof = StagedProof::new(&case.layout, &case.staged, &probe);
        for (slot, extents) in case.extents.iter().enumerate() {
            for (extent, bytes) in extents {
                if bytes.len() > 1 {
                    proof.record(slot, *extent, 0, &bytes[..1]);
                    proof.record(slot, *extent, 1, &bytes[1..]);
                } else {
                    proof.record(slot, *extent, 0, bytes);
                }
            }
        }
        for (slot, extents) in case.extents.iter().enumerate() {
            let pieces = extents.iter().any(|(_, bytes)| bytes.len() > 1);
            assert_eq!(proof.proves(slot), !pieces, "output {slot}");
        }
    }

    /// The workers of a deferred set record their writes at once: pieces of
    /// different extents hash outside the lock, in parallel, and the proof
    /// still proves every output and releases every frontier.
    #[test]
    fn concurrent_records_of_different_extents_prove_every_output() {
        let case = case();
        for piece in [usize::MAX, 7] {
            let options = options(1 << 20);
            let proof = StagedProof::new(&case.layout, &case.staged, &options);
            let base = options.memory.used();
            // Every piece of every extent, in order within its extent; the
            // extents are dealt round-robin to the threads.
            let threads = 4;
            std::thread::scope(|scope| {
                for thread in 0..threads {
                    let (proof, case) = (&proof, &case);
                    scope.spawn(move || {
                        for (slot, extents) in case.extents.iter().enumerate() {
                            for (extent, bytes) in extents {
                                if *extent % threads != thread {
                                    continue;
                                }
                                let step = piece.min(bytes.len());
                                for (at, chunk) in bytes.chunks(step).enumerate() {
                                    proof.record(slot, *extent, (at * step) as u64, chunk);
                                }
                            }
                        }
                    });
                }
            });
            assert!(proven(&case, &proof).iter().all(|&ok| ok), "{piece}");
            assert_eq!(options.memory.used(), base, "{piece}: a frontier leaked");
        }
    }

    /// A second piece of an extent admitted while the first is still being
    /// hashed cannot be ordered behind it, so the output reads back, and the
    /// late close of the first piece changes nothing.
    #[test]
    fn a_piece_admitted_while_its_frontier_is_on_loan_gives_the_output_up() {
        let case = case();
        let slot = case
            .extents
            .iter()
            .position(|extents| extents.iter().any(|(_, bytes)| bytes.len() > 1))
            .expect("an extent longer than a byte");
        let (extent, bytes) = case.extents[slot]
            .iter()
            .find(|(_, bytes)| bytes.len() > 1)
            .cloned()
            .unwrap();
        let options = options(1 << 20);
        let proof = StagedProof::new(&case.layout, &case.staged, &options);
        let base = options.memory.used();
        let half = bytes.len() / 2;
        let extents = &case.layout.files[case.staged[slot].index].extents;
        let mut state = proof.state.lock().unwrap();
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        let output = &mut outputs[slot];
        let first = output
            .admit(extents, extent, 0, half as u64, reservation)
            .expect("the first piece opens a frontier");
        let Admitted::Frontier {
            mut hasher,
            closes: false,
        } = first
        else {
            panic!("the first piece is a frontier that does not close");
        };
        assert!(options.memory.used() > base, "the frontier took no budget");
        assert!(
            output
                .admit(
                    extents,
                    extent,
                    half as u64,
                    (bytes.len() - half) as u64,
                    reservation
                )
                .is_none(),
            "the second piece was admitted over a lent hasher"
        );
        output.give_up(reservation);
        assert!(output.doubt);
        hasher.update(&bytes[..half]);
        assert!(!output.close(
            extents,
            extent,
            half as u64,
            Hashed::Frontier(hasher),
            reservation
        ));
        drop(state);
        assert!(!proof.proves(slot));
        assert_eq!(options.memory.used(), base, "giving up kept the frontier");
    }

    /// An extent written whole twice at once, or whole while a piece of it is
    /// in flight, was written twice: whichever write closes second cannot be
    /// proven, as a repeated write never could.
    #[test]
    fn writes_overlapping_in_flight_cannot_prove_their_extent() {
        let case = case();
        let slot = case
            .extents
            .iter()
            .position(|extents| extents.iter().any(|(_, bytes)| bytes.len() > 1))
            .expect("an extent longer than a byte");
        let (extent, bytes) = case.extents[slot]
            .iter()
            .find(|(_, bytes)| bytes.len() > 1)
            .cloned()
            .unwrap();
        let len = bytes.len() as u64;
        let extents = &case.layout.files[case.staged[slot].index].extents;
        let digest = crate::fingerprint(&bytes);
        // Whole twice: the first close proves, the second gives up.
        let twice = options(1 << 20);
        let proof = StagedProof::new(&case.layout, &case.staged, &twice);
        let mut state = proof.state.lock().unwrap();
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        let output = &mut outputs[slot];
        for _ in 0..2 {
            assert!(matches!(
                output.admit(extents, extent, 0, len, reservation),
                Some(Admitted::Whole)
            ));
        }
        let unproven = output.unproven;
        assert!(output.close(extents, extent, len, Hashed::Whole(digest), reservation));
        assert_eq!(output.unproven, unproven - 1);
        assert!(!output.close(extents, extent, len, Hashed::Whole(digest), reservation));
        assert_eq!(output.unproven, unproven - 1);
        drop(state);
        drop(proof);
        // Whole while a piece is in flight: the piece's frontier is there when
        // the whole write closes, and the whole write closes nothing.
        let options = options(1 << 20);
        let proof = StagedProof::new(&case.layout, &case.staged, &options);
        let base = options.memory.used();
        let mut state = proof.state.lock().unwrap();
        let ProofState {
            outputs,
            reservation,
        } = &mut *state;
        let output = &mut outputs[slot];
        assert!(matches!(
            output.admit(extents, extent, 0, len, reservation),
            Some(Admitted::Whole)
        ));
        let Some(Admitted::Frontier { hasher, .. }) =
            output.admit(extents, extent, 0, len / 2, reservation)
        else {
            panic!("the piece opens a frontier");
        };
        assert!(!output.close(extents, extent, len, Hashed::Whole(digest), reservation));
        output.give_up(reservation);
        drop(hasher);
        drop(state);
        assert!(!proof.proves(slot));
        assert_eq!(options.memory.used(), base, "giving up kept the frontier");
    }

    /// A budget holding exactly the proof's bits.
    fn options_with_bits(case: &Case) -> ExecutionOptions {
        let roomy = options(1 << 20);
        let proof = StagedProof::new(&case.layout, &case.staged, &roomy);
        let bits = roomy.memory.used();
        drop(proof);
        options(bits)
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod clone_tests {
    //! A clone the filesystem refuses stages by copying, with the same bytes.
    use super::*;
    use crate::repair_tree::REFUSE_CLONES;
    use crate::source::{DiskSourceAccess, SourceId};
    use crate::test_reference::{TempTree, cauchy_block_set, scanned_packets};

    /// What one repair of a damaged `input.bin` cost.
    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        clones: u64,
        in_place: u64,
        read: u64,
        written: u64,
    }

    /// Repair a damaged `input.bin` (one 64 KiB block of 16 flipped) into its
    /// own directory, with or without a backup, while `linked` keeps a second
    /// name for it that must keep the damaged bytes.
    fn repair_in_place(refuse: bool, backup: bool, linked: bool) -> Outcome {
        let block = 64u64 << 10;
        let tree = TempTree::new("clone-refused");
        let set = cauchy_block_set(16, block, 2, b"PAR3 refused clone", &tree);
        let bytes = &set.contents[0].1;
        let mut damaged = bytes.clone();
        damaged[5 * block as usize + 9] ^= 0x40;
        let inputs = TempTree::new("clone-refused-inputs");
        let options = ExecutionOptions {
            workers: 1,
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        let source = inputs.write("input.bin", &damaged);
        let link = TempTree::new("clone-refused-link");
        if linked {
            std::fs::hard_link(&source, link.path().join("other.bin")).unwrap();
        }
        access.insert(SourceId(1), source);
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let before = options.diagnostics.file_io();
        REFUSE_CLONES.with(|refused| refused.set(refuse));
        let report = session.repair(inputs.path(), backup);
        REFUSE_CLONES.with(|refused| refused.set(false));
        assert_eq!(report.unwrap().installed.len(), 1);
        let after = options.diagnostics.file_io();
        assert_eq!(
            &std::fs::read(inputs.path().join("input.bin")).unwrap(),
            bytes
        );
        if linked {
            assert_eq!(
                std::fs::read(link.path().join("other.bin")).unwrap(),
                damaged,
                "a second name for the source was changed"
            );
        }
        Outcome {
            clones: options.diagnostics.file_clones(),
            in_place: options.diagnostics.file_in_place_repairs(),
            read: after.read_bytes - before.read_bytes,
            written: after.write_bytes - before.write_bytes,
        }
    }

    /// Without a clone or a backup to keep, only the damaged block is written,
    /// into the source itself, which is then read back whole.
    #[test]
    fn a_refused_clone_without_a_backup_patches_only_the_damaged_block() {
        let (len, block) = (16u64 * (64 << 10), 64u64 << 10);
        let expected = if cfg!(any(target_os = "macos", target_os = "linux")) {
            Outcome {
                clones: 0,
                in_place: 1,
                read: len - block + len,
                written: block,
            }
        } else {
            Outcome {
                clones: 0,
                in_place: 0,
                read: len - block,
                written: len,
            }
        };
        assert_eq!(repair_in_place(true, false, false), expected);
    }

    /// A backup keeps the damaged file under its own name, so a refused clone
    /// still copies the whole file, with the same bytes.
    #[test]
    fn a_refused_clone_with_a_backup_falls_back_to_a_full_copy() {
        let (len, block) = (16u64 * (64 << 10), 64u64 << 10);
        let outcome = repair_in_place(true, true, false);
        assert_eq!(
            outcome,
            Outcome {
                clones: 0,
                in_place: 0,
                read: len - block,
                written: len,
            },
            "the surviving blocks once, and nothing read back"
        );
    }

    /// A source with a second name is never patched: that name keeps the
    /// damaged bytes and the repaired file is a full copy.
    #[test]
    fn a_hard_linked_source_is_copied_rather_than_patched() {
        let len = 16u64 * (64 << 10);
        let outcome = repair_in_place(true, false, true);
        assert_eq!((outcome.in_place, outcome.written), (0, len));
    }

    /// A clone the filesystem takes still wins over a patch.
    #[test]
    fn a_clone_is_preferred_to_a_patch() {
        let outcome = repair_in_place(false, false, false);
        if cfg!(target_os = "macos") || outcome.clones == 1 {
            assert_eq!(
                (outcome.clones, outcome.in_place, outcome.written),
                (1, 0, 64 << 10)
            );
        }
    }

    /// A disk registry that serves its files but hands over none of them.
    struct NoFile(DiskSourceAccess);

    impl SourceAccess for NoFile {
        fn snapshot(
            &self,
            source: SourceId,
        ) -> std::io::Result<Option<crate::source::SourceSnapshot>> {
            self.0.snapshot(source)
        }
        fn read_at(&self, source: SourceId, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.read_at(source, offset, out)
        }
        fn next_available(
            &self,
            source: SourceId,
            offset: u64,
        ) -> std::io::Result<Option<std::ops::Range<u64>>> {
            self.0.next_available(source, offset)
        }
        fn open_sequential(
            &self,
            source: SourceId,
        ) -> std::io::Result<Option<Box<dyn std::io::Read + Send>>> {
            self.0.open_sequential(source)
        }
    }

    /// Repair a damaged `input.bin` in place through a registry that hands
    /// over its file or not: (files opened by the repair, clones).
    fn repair_opens(hand_over: bool, refuse: bool, backup: bool) -> (u64, u64) {
        let block = 64u64 << 10;
        let tree = TempTree::new("clone-opens");
        let set = cauchy_block_set(16, block, 2, b"PAR3 clone opens", &tree);
        let mut damaged = set.contents[0].1.clone();
        damaged[5 * block as usize + 9] ^= 0x40;
        let inputs = TempTree::new("clone-opens-inputs");
        let options = ExecutionOptions {
            workers: 1,
            ..ExecutionOptions::default()
        };
        let mut disk = DiskSourceAccess::with_options(options.clone());
        disk.insert(SourceId(1), inputs.write("input.bin", &damaged));
        let access: Arc<dyn SourceAccess> = if hand_over {
            Arc::new(disk)
        } else {
            Arc::new(NoFile(disk))
        };
        let mut session = Par3RepairSession::new(set.id, access, options.clone()).unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let opens = options.diagnostics.file_opens();
        REFUSE_CLONES.with(|refused| refused.set(refuse));
        let report = session.repair(inputs.path(), backup);
        REFUSE_CLONES.with(|refused| refused.set(false));
        assert_eq!(report.unwrap().installed.len(), 1);
        assert_eq!(
            &std::fs::read(inputs.path().join("input.bin")).unwrap(),
            &set.contents[0].1
        );
        assert_eq!(
            options.diagnostics.file_in_place_repairs(),
            0,
            "a file the registry did not hand over was patched"
        );
        (
            options.diagnostics.file_opens() - opens,
            options.diagnostics.file_clones(),
        )
    }

    /// A clone is tried from the registry's cached handle, so one the
    /// filesystem refuses costs no open: such a repair opens exactly what one
    /// that never tries a clone does.
    #[test]
    fn a_refused_clone_opens_no_more_files_than_the_copy_it_falls_back_to() {
        let refused = repair_opens(true, true, true);
        let never_tried = repair_opens(false, false, true);
        assert_eq!(refused, never_tried);
        assert_eq!(refused.1, 0);
    }

    /// Only a file the registry hands over can be patched; one it serves by
    /// reads alone is copied even without a backup.
    #[test]
    fn a_source_not_handed_over_is_never_patched() {
        assert_eq!(repair_opens(false, false, false).1, 0);
    }

    /// A reflink filesystem can refuse one file with `EINVAL` (an inline
    /// extent, say) and clone the next, so that refusal does not turn clones
    /// off for the rest of the repair.
    #[test]
    fn a_file_refused_with_einval_leaves_clones_on_for_the_next_output() {
        use crate::repair_tree::REFUSE_NEXT_CLONE;
        use crate::test_reference::many_block_set;
        let tree = TempTree::new("clone-einval");
        let set = many_block_set(2, 16, 0, 4, b"PAR3 einval clone", &tree);
        let inputs = TempTree::new("clone-einval-inputs");
        let options = ExecutionOptions {
            workers: 1,
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        for (index, (name, bytes)) in set.contents.iter().enumerate() {
            let mut damaged = bytes.clone();
            damaged[70] ^= 0x80;
            access.insert(SourceId(index as u64 + 1), inputs.write(name, &damaged));
        }
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        for (index, (name, _)) in set.contents.iter().enumerate() {
            session.bind_file(name, SourceId(index as u64 + 1)).unwrap();
        }
        for path in &set.paths {
            for packet in scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        REFUSE_NEXT_CLONE.with(|refused| refused.set(Some(libc::EINVAL)));
        let report = session.repair(inputs.path(), false);
        REFUSE_NEXT_CLONE.with(|refused| refused.set(None));
        assert_eq!(report.unwrap().installed.len(), 2);
        for (name, bytes) in &set.contents {
            assert_eq!(&std::fs::read(inputs.path().join(name)).unwrap(), bytes);
        }
        let clones = options.diagnostics.file_clones();
        if cfg!(target_os = "macos") || clones != 0 {
            assert_eq!(clones, 1, "the second output was not cloned");
        }
    }

    /// A source whose ACL denies its owner writes is repaired in place, from
    /// a clone or a copy, and leaves no temporary behind.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_source_denying_writes_by_acl_is_still_repaired_in_place() {
        let block = 64u64 << 10;
        let tree = TempTree::new("clone-acl");
        let set = cauchy_block_set(16, block, 2, b"PAR3 acl clone", &tree);
        let bytes = &set.contents[0].1;
        let mut damaged = bytes.clone();
        damaged[5 * block as usize + 9] ^= 0x40;
        let inputs = TempTree::new("clone-acl-inputs");
        let source = inputs.write("input.bin", &damaged);
        crate::test_reference::deny_owner_writes(&source, true);
        let options = ExecutionOptions {
            workers: 1,
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        access.insert(SourceId(1), source.clone());
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Ready);
        let report = session.repair(inputs.path(), false);
        let left: Vec<_> = std::fs::read_dir(inputs.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        for path in &left {
            crate::test_reference::deny_owner_writes(path, false);
        }
        assert_eq!(report.unwrap().installed.len(), 1);
        assert_eq!(left, vec![source.clone()], "a temporary was left behind");
        assert_eq!(&std::fs::read(&source).unwrap(), bytes);
    }
}

#[cfg(test)]
mod contradiction_tests {
    //! Metadata that contradicts itself is refused by the read-back.
    use super::*;
    use crate::repair_tree::REFUSE_CLONES;
    use crate::source::{DiskSourceAccess, SourceId};
    use crate::test_reference::{TempTree, cauchy_block_set, scanned_packets};

    /// An output whose evidence says every protected extent is intact while
    /// the whole-file fingerprint is not (made so here in memory, after an
    /// honest verification of a regenerated set, since no packet may be
    /// edited) is read back before installation instead of being proven from
    /// its writes. A real contradiction then fails that read-back, so repair
    /// errors instead of installing the file and reporting it ready again.
    #[test]
    fn an_output_whose_evidence_contradicts_itself_is_read_back() {
        let block = 64u64 << 10;
        let tree = TempTree::new("contradiction");
        let set = cauchy_block_set(16, block, 2, b"PAR3 contradiction", &tree);
        let bytes = &set.contents[0].1;
        let len = bytes.len() as u64;
        let inputs = TempTree::new("contradiction-inputs");
        let output = TempTree::new("contradiction-output");
        let options = ExecutionOptions {
            workers: 1,
            ..ExecutionOptions::default()
        };
        let mut access = DiskSourceAccess::with_options(options.clone());
        access.insert(SourceId(1), inputs.write("input.bin", bytes));
        let mut session =
            Par3RepairSession::new(set.id, Arc::new(access), options.clone()).unwrap();
        session.bind_file("input.bin", SourceId(1)).unwrap();
        for path in &set.paths {
            for packet in scanned_packets(std::fs::read(path).unwrap(), &options) {
                session.merge(packet).unwrap();
            }
        }
        assert_eq!(session.assess().unwrap().status, RepairStatus::Complete);
        let evidence = session.evidence.get_mut("input.bin").unwrap();
        assert_eq!(evidence.whole_matches, Some(true));
        evidence.whole_matches = Some(false);
        assert!(evidence.contradicts_itself());
        session.assessment = None;
        let assessment = session.assess().unwrap();
        assert_eq!(assessment.status, RepairStatus::Ready);
        assert!(assessment.lost_blocks.is_empty());
        let before = options.diagnostics.file_io().read_bytes;
        REFUSE_CLONES.with(|refused| refused.set(true));
        let report = session.repair(output.path(), false);
        REFUSE_CLONES.with(|refused| refused.set(false));
        assert_eq!(report.unwrap().installed.len(), 1);
        assert_eq!(
            &std::fs::read(output.path().join("input.bin")).unwrap(),
            bytes
        );
        // The copy reads the source once; the read-back reads the output.
        assert_eq!(
            options.diagnostics.file_io().read_bytes - before,
            2 * len,
            "the output was not read back"
        );
    }
}
