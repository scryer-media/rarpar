//! Striped repair and verified installation for retained sessions.

use crate::runtime::{EngineFile as File, ExecutionOptions, MemoryCategory, OpenBudgeted};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::gf::{Field, Gf8, Gf16};
use crate::layout::BlockLayout;
use crate::packet::PacketBody;
use crate::runtime::{EngineError, EngineResult};
use crate::session::{Par3RepairSession, RepairStatus, block_range};

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
    /// Independently verified, installed files.
    pub installed: Vec<InstalledFile>,
    /// Logical lost blocks reconstructed once, regardless of aliases.
    pub reconstructed_blocks: u64,
}

struct StagedFile {
    index: usize,
    destination: PathBuf,
    temporary: PathBuf,
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
) -> EngineResult<SessionRepairReport> {
    let mut installed = Vec::new();
    let mut temporary = Vec::new();
    match repair_inner(session, output, backup, &mut installed, &mut temporary) {
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
    for payload in assessment
        .recovery
        .iter()
        .chain(session.data_payloads().values())
    {
        payload.validate(&session.options)?;
    }
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
    let mut staged = Vec::new();
    for (index, file) in assessment.files.iter().enumerate() {
        if file.complete {
            continue;
        }
        session.options.cancel.check()?;
        let destination = contained_destination(output, &file.path)?;
        let temporary = stage_path(&destination, &session.options)?;
        temporary_outputs.push(temporary.clone());
        OpenOptions::new()
            .write(true)
            .open_budgeted(&temporary, &session.options)?
            .set_len(layout.files[index].len)?;
        staged.push(StagedFile {
            index,
            destination,
            temporary,
        });
    }
    if assessment.lost_blocks.is_empty() {
        copy_available(session, layout, &staged)?;
    } else if let Some(PacketBody::FftMatrix(matrix)) =
        assessment.matrix.as_ref().map(|packet| packet.body())
    {
        reconstruct_fft(session, layout, &staged, matrix)?;
    } else {
        let field_bytes =
            crate::gf::construction_cost(&session.set.as_ref().expect("ready set").galois_field());
        let _field_reservation = session
            .options
            .memory
            .reserve_as(MemoryCategory::CodecTables, field_bytes)?;
        let field = crate::gf::for_set(&session.set.as_ref().expect("ready set").galois_field())?;
        match field {
            crate::gf::AnyField::Gf8(field) => reconstruct(session, layout, &staged, field)?,
            crate::gf::AnyField::Gf16(field) => reconstruct(session, layout, &staged, field)?,
        }
    }
    // Inline tails need no source and no recovery equation.
    for target in &staged {
        let mut file = OpenOptions::new()
            .write(true)
            .open_budgeted(&target.temporary, &session.options)?;
        let extents = &layout.files[target.index].extents;
        for index in 0..extents.len() {
            if let Some(bytes) = extents.inline_bytes(index) {
                let range = extents.range(index).expect("bounded extent");
                file.seek(SeekFrom::Start(range.start))?;
                file.write_all(bytes)?;
            }
        }
        file.sync_all()?;
    }
    for target in &staged {
        verify_staged(session, layout, target)?;
    }
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    for target in staged {
        session.options.cancel.check()?;
        let saved = install(&target.temporary, &target.destination, backup)?;
        temporary_outputs.retain(|path| path != &target.temporary);
        installed.push(InstalledFile {
            path: target.destination,
            backup: saved,
        });
    }
    Ok(assessment.lost_blocks.len() as u64)
}

/// Private scratch operation for self-repair. The unprotected gap remains
/// unavailable to callers until the self-repair operation fills and validates it.
pub(crate) fn stage_embedded(
    session: &mut Par3RepairSession,
    temporary: &Path,
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
    if layout.files.len() != 1 {
        return Err(EngineError::Unsupported(
            "embedded repair requires one file",
        ));
    }
    let assessment = session.assessment.as_ref().expect("assessment");
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    for payload in assessment
        .recovery
        .iter()
        .chain(session.data_payloads().values())
    {
        payload.validate(&session.options)?;
    }
    let targets = [StagedFile {
        index: 0,
        destination: temporary.to_owned(),
        temporary: temporary.to_owned(),
    }];
    OpenOptions::new()
        .write(true)
        .open_budgeted(temporary, &session.options)?
        .set_len(layout.files[0].len)?;
    if assessment.lost_blocks.is_empty() {
        copy_available(session, layout, &targets)?;
    } else if layout.block_count != 0 {
        let set = session.set.as_ref().expect("assessed set");
        let _field = session.options.memory.reserve_as(
            MemoryCategory::CodecTables,
            crate::gf::construction_cost(&set.galois_field()),
        )?;
        match crate::gf::for_set(&set.galois_field())? {
            crate::gf::AnyField::Gf8(field) => reconstruct(session, layout, &targets, field)?,
            crate::gf::AnyField::Gf16(field) => reconstruct(session, layout, &targets, field)?,
        }
    }
    let mut output = OpenOptions::new()
        .write(true)
        .open_budgeted(temporary, &session.options)?;
    let extents = &layout.files[0].extents;
    for index in 0..extents.len() {
        if let Some(bytes) = extents.inline_bytes(index) {
            let range = extents.range(index).expect("bounded extent");
            output.seek(SeekFrom::Start(range.start))?;
            output.write_all(bytes)?;
        }
    }
    output.sync_all()?;
    drop(output);
    verify_staged(session, layout, &targets[0])?;
    for evidence in session.evidence.values() {
        crate::source::ensure_snapshot(
            session.access.as_ref(),
            evidence.source,
            evidence.snapshot,
        )?;
    }
    Ok(assessment.lost_blocks.len() as u64)
}

fn copy_available(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    outputs: &[StagedFile],
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
    for (block, locations) in layout.blocks() {
        if !locations
            .iter()
            .any(|location| outputs.iter().any(|target| target.index == location.file))
        {
            continue;
        }
        let mut offset = 0;
        while offset < layout.block_size {
            session.options.cancel.check()?;
            let take = (layout.block_size - offset).min(size as u64) as usize;
            session.read_block(block, offset, &mut bytes[..take], &mut covered[..take])?;
            if offset != 0 {
                // A block wider than the copy window is read once per window.
                session.options.diagnostics.note_reread(take);
            }
            scatter(
                &session.options,
                layout,
                outputs,
                block,
                offset,
                &bytes[..take],
            )?;
            progress.advance(take as u64);
            offset += take as u64;
        }
    }
    Ok(())
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
    layout: &BlockLayout,
    outputs: &[StagedFile],
    field: F,
) -> EngineResult<()>
where
    F: Field + Sync,
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
    // Recovered rows are produced and scattered a tile at a time. The syndrome
    // bank has to stay whole — every output row reads all of it — but the
    // output bank only has to be as wide as the rows being solved right now,
    // so the row payload is `(n + tile)` stripes instead of `2n`. The tile is
    // the width the workers can actually use, so no parallelism is given up,
    // and a serial repair keeps exactly one output row alive.
    let tile = session.options.workers.max(1).min(n);
    let buffer_count = n
        .checked_add(tile)
        .and_then(|count| count.checked_add(3))
        .ok_or(EngineError::resource_limit("repair stripes"))?;
    let bank_headers = n
        .checked_add(tile)
        .and_then(|rows| rows.checked_mul(size_of::<Vec<u8>>()))
        .ok_or(EngineError::resource_limit("repair stripes"))?;
    let pool = crate::runtime::WorkerPool::for_work(
        &session.options,
        n,
        buffer_count
            .checked_mul(F::SYMBOL_BYTES)
            .ok_or(EngineError::resource_limit("minimum repair stripe"))?,
    )?;
    let target = session
        .options
        .stripe_bytes
        .min(usize::try_from(layout.block_size).unwrap_or(usize::MAX));
    let (stripe, _buffers) = session.options.memory.reserve_stripes_with_overhead(
        MemoryCategory::CodecScratch,
        target,
        buffer_count,
        F::SYMBOL_BYTES,
        bank_headers,
    )?;
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
    let mut syndromes = vec![vec![0u8; stripe]; n];
    let mut recovered = vec![vec![0u8; stripe]; tile];
    let mut input = vec![0u8; stripe];
    let mut covered = vec![0u8; stripe];
    let mut offset = 0;
    while offset < layout.block_size {
        session.options.cancel.check()?;
        let take = (layout.block_size - offset).min(stripe as u64) as usize;
        for syndrome in &mut syndromes {
            syndrome[..take].fill(0);
        }
        for block in 0..layout.block_count {
            session.options.cancel.check()?;
            if lost.binary_search(&block).is_ok() {
                continue;
            }
            session.read_block(block, offset, &mut input[..take], &mut covered[..take])?;
            if offset != 0 {
                // A stripe narrower than the block means the surviving blocks
                // are read once per pass. That is the cost of the bounded
                // working set, and it is reported rather than hidden.
                session.options.diagnostics.note_reread(take);
            }
            scatter(
                &session.options,
                layout,
                outputs,
                block,
                offset,
                &input[..take],
            )?;
            if coverage.contains(&block) {
                let apply = |(syndrome, row): (&mut Vec<u8>, &u64)| -> EngineResult<()> {
                    session.options.cancel.check()?;
                    let factor = crate::cauchy::element(&field, block, *row)?;
                    field.mul_acc(&mut syndrome[..take], &input[..take], factor);
                    Ok(())
                };
                if let Some(pool) = &pool {
                    pool.pool().install(|| {
                        syndromes
                            .par_iter_mut()
                            .zip(rows.par_iter())
                            .try_for_each(apply)
                    })?;
                } else {
                    syndromes.iter_mut().zip(rows.iter()).try_for_each(apply)?;
                }
            }
        }
        for (row, payload) in assessment.recovery.iter().enumerate() {
            input[..take].fill(0);
            payload.read_at(offset, &mut input[..take])?;
            for (to, from) in syndromes[row][..take].iter_mut().zip(&input[..take]) {
                *to ^= from;
            }
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
                for (row, syndrome) in syndromes.iter().enumerate() {
                    session.options.cancel.check()?;
                    field.mul_acc(
                        &mut bytes[..take],
                        &syndrome[..take],
                        inverse[column * n + row],
                    );
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
                scatter(
                    &session.options,
                    layout,
                    outputs,
                    *index,
                    offset,
                    &bytes[..take],
                )?;
                session.options.diagnostics.note_reconstructed(take);
                progress.advance(take as u64);
                session.options.cancel.check()?;
            }
            base += width;
        }
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
    layout: &BlockLayout,
    outputs: &[StagedFile],
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
        if !layout.locations(block).is_some_and(|locations| {
            locations
                .iter()
                .any(|location| outputs.iter().any(|output| output.index == location.file))
        }) {
            continue;
        }
        let mut offset = 0;
        while offset < layout.block_size {
            session.options.cancel.check()?;
            let take = (layout.block_size - offset).min(stripe as u64) as usize;
            session.read_block(block, offset, &mut bytes[..take], &mut covered[..take])?;
            scatter(
                &session.options,
                layout,
                outputs,
                block,
                offset,
                &bytes[..take],
            )?;
            offset += take as u64;
        }
    }
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
        codec.decode(
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
                            session.read_block(block, offset, out, &mut covered[..out.len()])?;
                            scatter(&session.options, layout, outputs, block, offset, out)?;
                        }
                    }
                    FftInput::Recovery(index) => {
                        out.fill(0);
                        recovery[&index].read_at(offset, out)?;
                    }
                }
                Ok(())
            },
            |local, offset, bytes| {
                scatter(
                    &session.options,
                    layout,
                    outputs,
                    first + local as u64 * cohorts,
                    offset,
                    bytes,
                )
            },
        )?;
    }
    Ok(())
}

fn scatter(
    options: &ExecutionOptions,
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
        let Some(target) = outputs.iter().find(|target| target.index == location.file) else {
            continue;
        };
        let extents = &layout.files[location.file].extents;
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
        let mut file = OpenOptions::new()
            .write(true)
            .open_budgeted(&target.temporary, options)?;
        file.seek(SeekFrom::Start(extent.start + start - block_offset))?;
        file.write_all(&bytes[(start - offset) as usize..(end - offset) as usize])?;
    }
    Ok(())
}

fn verify_staged(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    target: &StagedFile,
) -> EngineResult<()> {
    let mut progress = session.options.stage(crate::runtime::Stage::Verify)?;
    let expected = &layout.files[target.index];
    let size = session.options.stripe_bytes.min(64 << 10);
    let _buffer = session
        .options
        .memory
        .reserve_as(MemoryCategory::SourceScratch, size)?;
    let mut buffer = vec![0u8; size];
    let mut file = File::open(&target.temporary, &session.options)?;
    let mut hash = crate::FingerprintHasher::new();
    for index in 0..expected.extents.len() {
        if expected.extents.is_unprotected(index) {
            continue;
        }
        let range = expected.extents.range(index).expect("bounded extent");
        file.seek(SeekFrom::Start(range.start))?;
        let mut remaining = range.end - range.start;
        while remaining != 0 {
            session.options.cancel.check()?;
            let take = remaining.min(size as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            hash.update(&buffer[..take]);
            progress.advance(take as u64);
            remaining -= take as u64;
        }
    }
    if file.metadata()?.len() != expected.len
        || expected.fingerprint == [0; 16]
        || hash.finalize() != expected.fingerprint
    {
        return Err(EngineError::InvalidState(
            "rebuilt file failed protected-data verification; temporary retained",
        ));
    }
    Ok(())
}

pub(crate) fn contained_destination(base: &Path, relative: &str) -> EngineResult<PathBuf> {
    let mut path = base.to_path_buf();
    let parts: Vec<_> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." || *part == ".." || part.contains(['\\', ':']) {
            return Err(EngineError::InvalidState("invalid output path component"));
        }
        path.push(part);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EngineError::InvalidState(
                    "output path contains a symbolic link",
                ));
            }
            Ok(metadata) if index + 1 < parts.len() && !metadata.is_dir() => {
                return Err(EngineError::InvalidState(
                    "output parent is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if index + 1 < parts.len() {
                    std::fs::create_dir(&path)?;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

pub(crate) fn stage_path(destination: &Path, options: &ExecutionOptions) -> EngineResult<PathBuf> {
    let parent = destination
        .parent()
        .ok_or(EngineError::InvalidState("output has no parent"))?;
    for _ in 0..128 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".par3-repair-{}-{sequence}.tmp",
            std::process::id()
        ));
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

pub(crate) fn install(
    temporary: &Path,
    destination: &Path,
    backup: bool,
) -> EngineResult<Option<PathBuf>> {
    let mut saved = None;
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(EngineError::InvalidState(
                "destination is not a regular file",
            ));
        }
        Ok(_) if backup => {
            for index in 1..=100_000 {
                let mut name = destination.as_os_str().to_os_string();
                name.push(format!(".{index}"));
                let path = PathBuf::from(name);
                match std::fs::hard_link(destination, &path) {
                    Ok(()) => {
                        saved = Some(path);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            if saved.is_none() {
                return Err(EngineError::resource_limit("backup names"));
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Rust replaces an existing regular file on Windows as well as Unix.
    // Keep the destination in place until the verified stage is installed.
    std::fs::rename(temporary, destination)?;
    Ok(saved)
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
        let temporary = directory.0.join("verified.tmp");
        let existing_backup = directory.0.join("damaged.bin.1");
        std::fs::write(&destination, b"damaged bytes").unwrap();
        std::fs::write(&temporary, b"verified repaired bytes").unwrap();
        std::fs::write(&existing_backup, b"earlier backup").unwrap();

        let saved = install(&temporary, &destination, backup).unwrap();

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
}
