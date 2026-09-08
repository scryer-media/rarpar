//! Striped repair and verified installation for retained sessions.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::gf::{Field, Gf8, Gf16};
use crate::layout::{BlockLayout, ExtentKind};
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
    pub(crate) fn new(destination: &Path) -> EngineResult<Self> {
        stage_path(destination).map(Self)
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
    session.options.validate()?;
    let assessment = session
        .assessment
        .as_ref()
        .ok_or(EngineError::InvalidState("repair has no assessment"))?;
    if assessment.status == RepairStatus::Complete {
        return Ok(0);
    }
    if assessment.status != RepairStatus::Ready {
        return Err(EngineError::InvalidState("repair is not ready"));
    }
    if session.options.open_handles < 2 {
        return Err(EngineError::ResourceLimit(
            "repair requires two open handles",
        ));
    }
    let layout = session.layout.as_ref().expect("ready layout");
    if layout.files.iter().any(|file| {
        file.extents
            .iter()
            .any(|extent| matches!(extent.kind, ExtentKind::Unprotected))
    }) {
        return Err(EngineError::Unsupported(
            "unprotected ranges require explicit self-repair",
        ));
    }
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
    let mut staged = Vec::new();
    for (index, file) in assessment.files.iter().enumerate() {
        if file.complete {
            continue;
        }
        session.options.cancel.check()?;
        let destination = contained_destination(output, &file.path)?;
        let temporary = stage_path(&destination)?;
        temporary_outputs.push(temporary.clone());
        OpenOptions::new()
            .write(true)
            .open(&temporary)?
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
        let field_bytes = if session.set.as_ref().expect("ready set").galois_field().size == 2 {
            512 << 10
        } else {
            4096
        };
        let _field_reservation = session.options.memory.reserve(field_bytes)?;
        let field = crate::gf::for_set(&session.set.as_ref().expect("ready set").galois_field())?;
        match field {
            crate::gf::AnyField::Gf8(field) => reconstruct(session, layout, &staged, field)?,
            crate::gf::AnyField::Gf16(field) => reconstruct(session, layout, &staged, field)?,
        }
    }
    // Inline tails need no source and no recovery equation.
    for target in &staged {
        let mut file = OpenOptions::new().write(true).open(&target.temporary)?;
        for extent in &layout.files[target.index].extents {
            if let ExtentKind::Inline(bytes) = &extent.kind {
                file.seek(SeekFrom::Start(extent.range.start))?;
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
        return Err(EngineError::ResourceLimit(
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
        .open(temporary)?
        .set_len(layout.files[0].len)?;
    if assessment.lost_blocks.is_empty() {
        copy_available(session, layout, &targets)?;
    } else if layout.block_count != 0 {
        let set = session.set.as_ref().expect("assessed set");
        let _field = session
            .options
            .memory
            .reserve(if set.galois_field().size == 2 {
                512 << 10
            } else {
                4096
            })?;
        match crate::gf::for_set(&set.galois_field())? {
            crate::gf::AnyField::Gf8(field) => reconstruct(session, layout, &targets, field)?,
            crate::gf::AnyField::Gf16(field) => reconstruct(session, layout, &targets, field)?,
        }
    }
    let mut output = OpenOptions::new().write(true).open(temporary)?;
    for extent in &layout.files[0].extents {
        if let ExtentKind::Inline(bytes) = &extent.kind {
            output.seek(SeekFrom::Start(extent.range.start))?;
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
    // Data packets, aliases and inline-only files require no field or matrix.
    // In particular, the reference emits field size zero for degenerate codes.
    let size = session.options.stripe_bytes.min(64 << 10);
    let _memory = session.options.memory.reserve(size * 2)?;
    let mut bytes = vec![0; size];
    let mut covered = vec![0; size];
    for (&block, locations) in &layout.blocks {
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
            scatter(layout, outputs, block, offset, &bytes[..take])?;
            offset += take as u64;
        }
    }
    Ok(())
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
    let assessment = session.assessment.as_ref().expect("assessment");
    let lost = &assessment.lost_blocks;
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
    let coefficient_bytes = n
        .checked_mul(n)
        .and_then(|count| count.checked_mul(F::SYMBOL_BYTES))
        .and_then(|bytes| bytes.checked_add(n.checked_mul(64)?))
        .ok_or(EngineError::ResourceLimit("Cauchy coefficients"))?;
    let _coefficients = session.options.memory.reserve(coefficient_bytes)?;
    let inverse = crate::cauchy::inverse_coefficients(&field, lost, &rows)?;
    let worker_bytes = session
        .options
        .workers
        .checked_mul(256 << 10)
        .ok_or(EngineError::ResourceLimit("worker stacks"))?;
    let _workers = session.options.memory.reserve(worker_bytes)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(session.options.workers)
        .stack_size(256 << 10)
        .build()
        .map_err(|_| EngineError::ResourceLimit("worker pool"))?;
    let buffer_count = n
        .checked_mul(2)
        .and_then(|count| count.checked_add(3))
        .ok_or(EngineError::ResourceLimit("repair stripes"))?;
    let stripe = session
        .options
        .stripe_bytes
        .min(session.options.memory.available() / buffer_count)
        .min(usize::try_from(layout.block_size).unwrap_or(usize::MAX));
    let stripe = stripe / F::SYMBOL_BYTES * F::SYMBOL_BYTES;
    if stripe == 0 {
        return Err(EngineError::ResourceLimit("minimum repair stripe"));
    }
    let _buffers = session.options.memory.reserve(buffer_count * stripe)?;
    let mut syndromes = vec![vec![0u8; stripe]; n];
    let mut recovered = vec![vec![0u8; stripe]; n];
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
            scatter(layout, outputs, block, offset, &input[..take])?;
            if coverage.contains(&block) {
                pool.install(|| {
                    syndromes.par_iter_mut().zip(rows.par_iter()).try_for_each(
                        |(syndrome, row)| -> crate::Result<()> {
                            let factor = crate::cauchy::element(&field, block, *row)?;
                            field.mul_acc(&mut syndrome[..take], &input[..take], factor);
                            Ok(())
                        },
                    )
                })?;
            }
        }
        for (row, payload) in assessment.recovery.iter().enumerate() {
            input[..take].fill(0);
            payload.read_at(offset, &mut input[..take])?;
            for (to, from) in syndromes[row][..take].iter_mut().zip(&input[..take]) {
                *to ^= from;
            }
        }
        pool.install(|| {
            recovered
                .par_iter_mut()
                .enumerate()
                .for_each(|(column, bytes)| {
                    bytes[..take].fill(0);
                    for (row, syndrome) in syndromes.iter().enumerate() {
                        field.mul_acc(
                            &mut bytes[..take],
                            &syndrome[..take],
                            inverse[column * n + row],
                        );
                    }
                })
        });
        for (index, bytes) in lost.iter().zip(&recovered) {
            scatter(layout, outputs, *index, offset, &bytes[..take])?;
        }
        offset += take as u64;
    }
    Ok(())
}

fn reconstruct_fft(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    outputs: &[StagedFile],
    matrix: &crate::packet::FftMatrixPacket,
) -> EngineResult<()> {
    use crate::fft::{FftCodec, FftGeometry, FftInput};
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
    let stripe = session
        .options
        .stripe_bytes
        .min(64 << 10)
        .min(layout.block_size as usize);
    let _scratch = session.options.memory.reserve(
        stripe
            .checked_mul(2)
            .ok_or(EngineError::ResourceLimit("FFT source stripes"))?,
    )?;
    let mut covered = vec![0; stripe];
    let mut bytes = vec![0; stripe];
    let mut options = session.options.clone();
    options.stripe_bytes = stripe;
    let codec = FftCodec::new(geometry, options)?;
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
        if !layout.blocks.get(&block).is_some_and(|locations| {
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
            scatter(layout, outputs, block, offset, &bytes[..take])?;
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
                            scatter(layout, outputs, block, offset, out)?;
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
    layout: &BlockLayout,
    outputs: &[StagedFile],
    block: u64,
    offset: u64,
    bytes: &[u8],
) -> EngineResult<()> {
    let Some(locations) = layout.blocks.get(&block) else {
        return Ok(());
    };
    for location in locations {
        let Some(target) = outputs.iter().find(|target| target.index == location.file) else {
            continue;
        };
        let extent = &layout.files[location.file].extents[location.extent];
        let ExtentKind::Block {
            offset: block_offset,
            ..
        } = extent.kind
        else {
            continue;
        };
        let start = offset.max(block_offset);
        let end =
            (offset + bytes.len() as u64).min(block_offset + extent.range.end - extent.range.start);
        if start >= end {
            continue;
        }
        let mut file = OpenOptions::new().write(true).open(&target.temporary)?;
        file.seek(SeekFrom::Start(extent.range.start + start - block_offset))?;
        file.write_all(&bytes[(start - offset) as usize..(end - offset) as usize])?;
    }
    Ok(())
}

fn verify_staged(
    session: &Par3RepairSession,
    layout: &BlockLayout,
    target: &StagedFile,
) -> EngineResult<()> {
    let expected = &layout.files[target.index];
    let size = session.options.stripe_bytes.min(64 << 10);
    let _buffer = session.options.memory.reserve(size)?;
    let mut buffer = vec![0u8; size];
    let mut file = File::open(&target.temporary)?;
    let mut hash = crate::FingerprintHasher::new();
    for extent in &expected.extents {
        if matches!(extent.kind, ExtentKind::Unprotected) {
            continue;
        }
        file.seek(SeekFrom::Start(extent.range.start))?;
        let mut remaining = extent.range.end - extent.range.start;
        while remaining != 0 {
            session.options.cancel.check()?;
            let take = remaining.min(size as u64) as usize;
            file.read_exact(&mut buffer[..take])?;
            hash.update(&buffer[..take]);
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

pub(crate) fn stage_path(destination: &Path) -> EngineResult<PathBuf> {
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
            .open(&temporary)
        {
            Ok(_) => return Ok(temporary),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(EngineError::ResourceLimit("temporary output names"))
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
                return Err(EngineError::ResourceLimit("backup names"));
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
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
