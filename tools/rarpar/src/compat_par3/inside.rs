//! Verifying and repairing a file whose PAR3 packets live inside it, after a
//! ZIP or 7z archive's own bytes (par3cmdline's `vs` and `rs`).
//!
//! par3cmdline judges such a file by its protected chunks alone, counts the
//! packet region as unavailable once the file is damaged, and rebuilds it by
//! restoring the protected bytes and then copying every complete packet it
//! still finds in the damaged file, in order, into the packet region.
//!
//! The File packet's chunk list says which layout a file has, so repair never
//! guesses from bytes that may be damaged. par3cmdline's layout has one
//! unprotected chunk, the packets, either last (7z) or followed only by a copy
//! of the chunk before it (a ZIP's end records); par3-rs's self-repair takes
//! that shape. Any other single gap, such as the strict ZIP layout of `rarpar
//! par3 archive --strict-zip`, where the central directory and end records
//! follow the packets once, is rebuilt here from the recovery blocks.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use std::collections::BTreeMap;

use par3_rs::gf::{AnyField, Field};
use par3_rs::ingest::PayloadRef;
use par3_rs::inside::{ContainerLimits, SelfRepairPlan};
use par3_rs::layout::{ExtentKind, FileLayout};
use par3_rs::runtime::{EngineError, ExecutionOptions};
use par3_rs::session::Par3RepairSession;
use par3_rs::{ChunkDescription, Decoder, Fingerprint, FingerprintHasher, Geometry, InputSetId};

const MAGIC: &[u8; 8] = b"PAR3\0PKT";
const HEADER: usize = 48;

/// How a file with unprotected chunks stands, the way par3cmdline judges it.
pub(super) struct Standing {
    /// Every protected chunk is intact where the File packet places it.
    pub complete: bool,
    /// Bytes par3cmdline reports as available when the file is damaged.
    pub available: u64,
    /// Input-block slices found intact at their own offsets.
    pub found: Vec<Range<u64>>,
}

/// Whether the file has a chunk no input block covers ("PAR inside").
pub(super) fn has_unprotected(file: &FileLayout) -> bool {
    file.extents
        .iter()
        .any(|extent| extent.kind == ExtentKind::Unprotected)
}

/// Judge a file with unprotected chunks from the engine's unresolved ranges.
///
/// The file is complete when every protected extent verified within the
/// file's current size; bytes past the protected data are not looked at. A
/// damaged file's available bytes are the verified leading run plus every
/// intact block slice; unprotected and inline bytes after the first damage
/// count as unavailable, as par3cmdline's slide search counts them.
pub(super) fn assess(file: &FileLayout, unresolved: &[Range<u64>], size: u64) -> Standing {
    let intact = |range: &Range<u64>| {
        range.end <= size
            && !unresolved
                .iter()
                .any(|bad| bad.start < range.end && range.start < bad.end)
    };
    let mut complete = true;
    let mut prefix = 0;
    let mut leading = true;
    let mut found = Vec::new();
    for extent in file.extents.iter() {
        if extent.kind == ExtentKind::Unprotected {
            continue;
        }
        let ok = intact(&extent.range);
        if ok && matches!(extent.kind, ExtentKind::Block { .. }) {
            found.push(extent.range.clone());
        }
        if !ok {
            complete = false;
            leading = false;
        } else if leading {
            prefix = extent.range.end;
        }
    }
    // Union of the leading run and the found slices, within the file.
    let mut spans: Vec<Range<u64>> = found.clone();
    spans.push(0..prefix);
    spans.sort_by_key(|span| span.start);
    let mut available = 0;
    let mut reach = 0;
    for span in spans {
        let start = span.start.max(reach).min(size);
        let end = span.end.min(size);
        if end > start {
            available += end - start;
        }
        reach = reach.max(span.end);
    }
    Standing {
        complete,
        available,
        found,
    }
}

/// Whether a file's chunks are laid out as par3cmdline lays out a set inside an
/// archive: one unprotected chunk, either last or followed only by a copy of
/// the chunk before it.
pub(super) fn par3cmdline_layout(chunks: &[ChunkDescription]) -> bool {
    let mut gaps = chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| matches!(chunk, ChunkDescription::Unprotected { .. }));
    let Some((at, _)) = gaps.next() else {
        return false;
    };
    if gaps.next().is_some() {
        return false;
    }
    match &chunks[at + 1..] {
        [] => true,
        [copy] => at > 0 && chunks[at - 1] == *copy,
        _ => false,
    }
}

/// par3cmdline's temporary name for the repaired file.
fn temporary_name(id: InputSetId) -> String {
    let mut name = String::from("par3_");
    for byte in id.as_bytes() {
        name.push_str(&format!("{byte:02X}"));
    }
    name.push_str("_0.tmp");
    name
}

/// Rebuild `path` in place: restore its protected data, refill its packet
/// region the way par3cmdline does, keep the damaged file as `path.1`.
/// Returns whether the rebuilt file was installed.
pub(super) fn self_repair(
    session: &mut Par3RepairSession,
    base: &Path,
    path: &Path,
    id: InputSetId,
    matrix: Fingerprint,
    file: &FileLayout,
    found: &[Range<u64>],
) -> Result<bool, EngineError> {
    let Some(gap) = file
        .extents
        .iter()
        .find(|extent| extent.kind == ExtentKind::Unprotected)
        .map(|extent| extent.range)
    else {
        return Err(EngineError::InvalidState("no unprotected chunk"));
    };
    let temporary = base.join(temporary_name(id));
    // par3cmdline creates this name afresh, replacing whatever held it.
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let plan = SelfRepairPlan::replacement(session, matrix, &[], ContainerLimits::default())?;
    plan.execute(session, &temporary, base)?;

    let output = OpenOptions::new().write(true).open(&temporary)?;
    install(path, output, &temporary, gap, found)
}

/// Fill the packet gap of the rebuilt file at `temporary` the way par3cmdline
/// does, then install it over `path`, keeping the damaged file as `path.1`.
fn install(
    path: &Path,
    mut output: File,
    temporary: &Path,
    gap: Range<u64>,
    found: &[Range<u64>],
) -> Result<bool, EngineError> {
    output.seek(SeekFrom::Start(gap.start))?;
    let copied = copy_complete_packets(path, &mut output, gap.end - gap.start, found)?;
    if copied > gap.end - gap.start {
        // par3cmdline's rebuilt file would not match the File packet.
        drop(output);
        std::fs::remove_file(temporary)?;
        return Ok(false);
    }
    let mut zeros = vec![0u8; 64 << 10];
    let mut left = gap.end - gap.start - copied;
    while left > 0 {
        let take = left.min(zeros.len() as u64) as usize;
        output.write_all(&zeros[..take])?;
        left -= take as u64;
    }
    zeros.clear();
    output.sync_all()?;
    drop(output);

    // As par3cmdline does on this platform: the damaged file becomes `.1`,
    // replacing any earlier backup of that name.
    let mut backup = path.as_os_str().to_owned();
    backup.push(".1");
    std::fs::rename(path, &backup)?;
    std::fs::rename(temporary, path)?;
    Ok(true)
}

/// A recovery block the set holds: its matrix, index and stored bytes.
pub(super) struct Recovery {
    pub matrix: Fingerprint,
    pub index: u64,
    pub payload: PayloadRef,
}

/// The set facts [`rebuild`] works from.
pub(super) struct Rebuild<'a> {
    pub block_size: u64,
    pub block_count: u64,
    pub field: &'a par3_rs::GaloisField,
    /// The Cauchy matrix the recovery blocks are used under.
    pub matrix: Fingerprint,
    pub recovery: &'a [Recovery],
    /// Lost input blocks, from the session's assessment.
    pub lost: &'a [u64],
    pub options: &'a ExecutionOptions,
}

/// Rebuild `path` in place when its layout is not par3cmdline's: solve its
/// lost input blocks from the recovery blocks, write every protected extent,
/// check the protected bytes against the File packet's fingerprint, refill the
/// packet gap as par3cmdline does, and keep the damaged file as `path.1`.
/// Returns whether the rebuilt file was installed.
pub(super) fn rebuild(
    set: &Rebuild<'_>,
    base: &Path,
    path: &Path,
    id: InputSetId,
    file: &FileLayout,
    found: &[Range<u64>],
) -> Result<bool, EngineError> {
    let mut gaps = file
        .extents
        .iter()
        .filter(|extent| extent.kind == ExtentKind::Unprotected)
        .map(|extent| extent.range);
    let (Some(gap), None) = (gaps.next(), gaps.next()) else {
        return Err(EngineError::Unsupported("ambiguous embedded packet gaps"));
    };
    let block_size = usize::try_from(set.block_size)
        .map_err(|_| EngineError::Unsupported("block size beyond memory"))?;
    // Where each input block's bytes sit in the file.
    let mut blocks: BTreeMap<u64, Vec<(Range<u64>, usize)>> = BTreeMap::new();
    for extent in file.extents.iter() {
        if let ExtentKind::Block { index, offset, .. } = extent.kind {
            blocks
                .entry(index)
                .or_default()
                .push((extent.range, offset as usize));
        }
    }
    let mut source = File::open(path)?;
    let recovered = if set.lost.is_empty() {
        BTreeMap::new()
    } else {
        match par3_rs::gf::for_set(set.field)? {
            AnyField::Gf8(field) => solve(field, set, block_size, &blocks, &mut source)?,
            AnyField::Gf16(field) => solve(field, set, block_size, &blocks, &mut source)?,
        }
    };

    let temporary = base.join(temporary_name(id));
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    output.set_len(file.len)?;
    let mut hasher = FingerprintHasher::new();
    let mut buffer = vec![0u8; 1 << 20];
    for extent in file.extents.iter() {
        let range = extent.range;
        match &extent.kind {
            ExtentKind::Unprotected => continue,
            ExtentKind::Inline(bytes) => {
                output.seek(SeekFrom::Start(range.start))?;
                output.write_all(bytes)?;
                hasher.update(bytes);
            }
            ExtentKind::Block { index, offset, .. } => {
                output.seek(SeekFrom::Start(range.start))?;
                let len = (range.end - range.start) as usize;
                if let Some(block) = recovered.get(index) {
                    let bytes = &block[*offset as usize..*offset as usize + len];
                    output.write_all(bytes)?;
                    hasher.update(bytes);
                } else {
                    source.seek(SeekFrom::Start(range.start))?;
                    let mut left = len;
                    while left > 0 {
                        let take = left.min(buffer.len());
                        source.read_exact(&mut buffer[..take])?;
                        output.write_all(&buffer[..take])?;
                        hasher.update(&buffer[..take]);
                        left -= take;
                    }
                }
            }
        }
    }
    drop(source);
    if file.fingerprint != Fingerprint::default() && hasher.finalize() != file.fingerprint {
        drop(output);
        std::fs::remove_file(&temporary)?;
        return Err(EngineError::InvalidState(
            "rebuilt embedded data is incomplete",
        ));
    }
    install(path, output, &temporary, gap, found)
}

/// Solve the lost blocks in `field`, from every other input block as the
/// damaged file holds it and the first recovery blocks the decoder chooses.
fn solve<F: Field>(
    field: F,
    set: &Rebuild<'_>,
    block_size: usize,
    blocks: &BTreeMap<u64, Vec<(Range<u64>, usize)>>,
    source: &mut File,
) -> Result<BTreeMap<u64, Vec<u8>>, EngineError> {
    let rows: BTreeMap<u64, &PayloadRef> = set
        .recovery
        .iter()
        .filter(|recovery| recovery.matrix == set.matrix)
        .map(|recovery| (recovery.index, &recovery.payload))
        .collect();
    let geometry = Geometry {
        block_size: set.block_size,
        input_blocks: set.block_count,
        recovery_blocks: rows.keys().next_back().map_or(0, |last| last + 1),
        first_recovery: 0,
    };
    let available: Vec<u64> = rows.keys().copied().collect();
    let mut decoder = Decoder::new(field, geometry, set.lost, &available)?;
    let mut block = vec![0u8; block_size];
    for index in 0..set.block_count {
        if set.lost.binary_search(&index).is_ok() {
            continue;
        }
        block.fill(0);
        for (range, offset) in blocks.get(&index).map(Vec::as_slice).unwrap_or_default() {
            let len = (range.end - range.start) as usize;
            source.seek(SeekFrom::Start(range.start))?;
            source.read_exact(&mut block[*offset..*offset + len])?;
        }
        decoder.add_input_block(index, &block)?;
    }
    for index in decoder.recovery_rows().to_vec() {
        let payload = rows[&index];
        payload.validate(set.options)?;
        block.fill(0);
        let len = (payload.len() as usize).min(block_size);
        payload.read_at(0, &mut block[..len])?;
        decoder.add_recovery_block(index, &block)?;
    }
    Ok(decoder
        .solve()?
        .into_iter()
        .map(|block| (block.index(), block.into_data()))
        .collect())
}

/// Copy every complete packet found in `source` to `output`, in file order,
/// until `limit` bytes have been copied, as par3cmdline's `copy_inside_data`
/// does: it reads a buffer the size of the packet region rounded up to 4 KiB,
/// skipping intact input slices that start a read, and checks each packet's
/// fingerprint before copying it.
fn copy_complete_packets(
    source: &Path,
    output: &mut File,
    limit: u64,
    found: &[Range<u64>],
) -> io::Result<u64> {
    let capacity = usize::try_from((limit + 4095) & !4095)
        .map_err(|_| io::Error::other("packet region too large"))?;
    let mut buffer = vec![0u8; capacity];
    let mut input = File::open(source)?;
    let mut file_offset = 0u64;
    let mut total = 0u64;
    while total < limit {
        // Skip found slices that overlap the next packet header position.
        let mut index = 0;
        while index < found.len() {
            let slice = &found[index];
            if slice.end > file_offset && slice.start < file_offset + HEADER as u64 {
                file_offset = slice.end;
                index = 0;
                continue;
            }
            index += 1;
        }
        input.seek(SeekFrom::Start(file_offset))?;
        let (mut filled, mut at_end) = fill(&mut input, &mut buffer)?;
        let mut offset = 0usize;
        while offset + HEADER < filled {
            if &buffer[offset..offset + 8] != MAGIC {
                offset += 1;
                continue;
            }
            let length = u64::from_le_bytes(buffer[offset + 24..offset + 32].try_into().unwrap());
            if length <= HEADER as u64 {
                offset += 8;
                continue;
            }
            if (offset as u64).saturating_add(length) > filled as u64 {
                buffer.copy_within(offset..filled, 0);
                file_offset += offset as u64;
                let kept = filled - offset;
                let (more, end) = fill(&mut input, &mut buffer[kept..kept + offset])?;
                at_end |= end;
                filled = kept + more;
                offset = 0;
                if length > filled as u64 {
                    offset += 8;
                    continue;
                }
            }
            let end = offset + length as usize;
            let hash = par3_rs::fingerprint(&buffer[offset + 24..end]);
            if hash[..] != buffer[offset + 8..offset + 24] {
                offset += 8;
                continue;
            }
            output.write_all(&buffer[offset..end])?;
            total += length;
            offset = end;
        }
        file_offset += offset as u64;
        if at_end {
            break;
        }
    }
    Ok(total)
}

/// Read until `buffer` is full or the file ends, as `fread` does.
fn fill(input: &mut File, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => return Ok((filled, true)),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok((filled, false))
}
