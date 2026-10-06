//! Verifying and repairing a file whose PAR3 packets live inside it, after a
//! ZIP or 7z archive's own bytes (par3cmdline's `vs` and `rs`).
//!
//! par3cmdline judges such a file by its protected chunks alone, counts the
//! packet region as unavailable once the file is damaged, and rebuilds it by
//! restoring the protected bytes and then copying every complete packet it
//! still finds in the damaged file, in order, into the packet region.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use par3_rs::inside::{ContainerLimits, SelfRepairPlan};
use par3_rs::layout::{ExtentKind, FileLayout};
use par3_rs::runtime::EngineError;
use par3_rs::session::Par3RepairSession;
use par3_rs::{Fingerprint, InputSetId};

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

    let mut output = OpenOptions::new().write(true).open(&temporary)?;
    output.seek(SeekFrom::Start(gap.start))?;
    let copied = copy_complete_packets(path, &mut output, gap.end - gap.start, found)?;
    if copied > gap.end - gap.start {
        // par3cmdline's rebuilt file would not match the File packet.
        drop(output);
        std::fs::remove_file(&temporary)?;
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
    std::fs::rename(&temporary, path)?;
    Ok(true)
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
