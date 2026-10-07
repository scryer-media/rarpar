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
    // Windows' rename does not replace an existing file; clear the old
    // backup first so a second repair behaves as on every other platform.
    match std::fs::remove_file(&backup) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    std::fs::rename(path, &backup)?;
    std::fs::rename(&temporary, path)?;
    Ok(true)
}

/// Copy every complete packet found in `source` to `output`, in file order,
/// until `limit` bytes have been copied, as par3cmdline's `copy_inside_data`
/// does: it reads a window the size of the packet region rounded up to 4 KiB,
/// skipping intact input slices that start a read, and checks each packet's
/// fingerprint before copying it.
///
/// The window is followed exactly but never held in memory: the region can be
/// far larger than the archive, and its size comes from untrusted metadata.
/// Bytes are read through a bounded cache, and a packet is hashed and then
/// copied in bounded pieces.
fn copy_complete_packets(
    source: &Path,
    output: &mut File,
    limit: u64,
    found: &[Range<u64>],
) -> io::Result<u64> {
    let capacity = limit
        .checked_add(4095)
        .map(|size| size & !4095)
        .ok_or_else(|| io::Error::other("packet region too large"))?;
    let mut input = Reader::open(source)?;
    let file_len = input.len;
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
        // The window `fread` would fill: `filled` bytes from `file_offset`.
        let remaining = file_len.saturating_sub(file_offset);
        let mut filled = remaining.min(capacity);
        let mut at_end = remaining < capacity || filled == 0;
        let mut offset = 0u64;
        while offset + (HEADER as u64) < filled {
            let header = input.bytes(file_offset + offset, HEADER)?;
            if &header[..8] != MAGIC {
                offset += 1;
                continue;
            }
            let length = u64::from_le_bytes(header[24..32].try_into().unwrap());
            let stored: [u8; 16] = header[8..24].try_into().unwrap();
            if length <= HEADER as u64 {
                offset += 8;
                continue;
            }
            if offset.saturating_add(length) > filled {
                // Slide the window to start at this header, keeping its size.
                file_offset += offset;
                let left = file_len.saturating_sub(file_offset);
                // `fread` topping the window back up hit the end of the file.
                at_end |= left < filled;
                filled = filled.min(left);
                offset = 0;
                if length > filled {
                    offset += 8;
                    continue;
                }
            }
            let at = file_offset + offset;
            let mut hash = par3_rs::hash::FingerprintHasher::new();
            input.stream(at + 24, length - 24, |piece| {
                hash.update(piece);
                Ok(())
            })?;
            if hash.finalize()[..] != stored[..] {
                offset += 8;
                continue;
            }
            input.stream(at, length, |piece| output.write_all(piece))?;
            total += length;
            offset += length;
        }
        file_offset += offset;
        if at_end {
            break;
        }
    }
    Ok(total)
}

/// Bounded reads at any offset of the damaged file.
struct Reader {
    file: File,
    len: u64,
    /// File offset of `cache[0]`.
    start: u64,
    cache: Vec<u8>,
}

/// The most of the damaged file held at once.
const READ_CHUNK: usize = 1 << 20;

impl Reader {
    fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            start: 0,
            cache: Vec::new(),
        })
    }

    /// `count` bytes at `at`, which the caller knows lie within the file.
    fn bytes(&mut self, at: u64, count: usize) -> io::Result<&[u8]> {
        let end = at + count as u64;
        if at < self.start || end > self.start + self.cache.len() as u64 {
            self.start = at;
            let take = (self.len - at).min(READ_CHUNK as u64) as usize;
            self.cache.resize(take.max(count), 0);
            self.file.seek(SeekFrom::Start(at))?;
            let (read, _) = fill(&mut self.file, &mut self.cache)?;
            self.cache.truncate(read);
            if read < count {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        let from = (at - self.start) as usize;
        Ok(&self.cache[from..from + count])
    }

    /// Hand `length` bytes from `at` to `each`, a bounded piece at a time.
    fn stream(
        &mut self,
        mut at: u64,
        length: u64,
        mut each: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let end = at + length;
        while at < end {
            let take = (end - at).min(READ_CHUNK as u64) as usize;
            each(self.bytes(at, take)?)?;
            at += take as u64;
        }
        Ok(())
    }
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
