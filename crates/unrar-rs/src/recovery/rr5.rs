//! RAR5 recovery record: check a volume against the `RR` record it carries,
//! and repair the volume from it.
//!
//! `rar a -rr[N]` and `rar rr[N]` give every RAR5 volume a service block named
//! `RR` that holds Reed-Solomon parity over the volume's own bytes.
//! [`locate_rar5_recovery_record`] finds the record,
//! [`check_rar5_recovery_record`] reports which parts of the volume and of the
//! record no longer match their checksums, and
//! [`repair_rar5_recovery_record`] writes a copy of the volume with the damaged
//! parts rebuilt. None of them writes a record: a damaged record chunk is
//! reported and copied as it is, as `rar r` documents for its own repair.
//!
//! # Format
//!
//! The record protects the volume's bytes `0..P`, where `P` is the volume
//! offset of the `RR` service header: everything before that header, from
//! offset 0, so an SFX module, the signature, the main header, every file and
//! service block and a `QO` block. The `RR` header, the record, the end of
//! archive block and any padding after it are not protected.
//!
//! `0..P` is cut into `ND` data units of `U` bytes, the last one shorter. RAR
//! sets `ND = min(200, ceil(P / 1024))` and `U = ceil(P / ND)` rounded up to
//! even, so units are about 1 KiB in a volume under 200 KiB and `P / 200`
//! above that, and `-rrN` gives `NR = max(1, floor(ND * N / 100))` parity
//! units of `U` bytes, `N` from 1 to 1000. The code is the one RAR5 recovery
//! volumes use, over GF(2^16) with polynomial `0x1100B` on little-endian
//! 16-bit words: parity unit `k` is the sum over data units `d` of
//! `inv((ND + k) xor d) * unit[d]`, the last data unit zero-padded to `U`.
//!
//! The `RR` header's data area is the record: the parity units in order, each
//! cut into slices of at most 64 KiB, each slice behind its own header, which
//! makes a chunk. The same cut applies to the data units: slice `s` of a
//! chunk belongs with the bytes `s * 64 KiB..` of every data unit, and the
//! chunk's CRC list covers those. Integers are little-endian.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | `0x00` | 4 | `{RB}` |
//! | `0x04` | 8 | CRC-64/XZ of the chunk from `0x0c` to its end |
//! | `0x0c` | 4 | chunk size: header size plus slice length |
//! | `0x10` | 4 | header size, `0x48 + 8 * ND` |
//! | `0x14` | 2 | `01 01` in every record seen |
//! | `0x16` | 8 | slice offset in the parity unit, a multiple of 64 KiB |
//! | `0x1e` | 4 | `min(65536, L - slice offset)` for the last data unit's length `L`, the subtraction modulo 2^64 |
//! | `0x22` | 8 | `P` |
//! | `0x2a` | 8 | `U` |
//! | `0x32` | 8 | record bytes per parity unit: slices times header size, plus `U` |
//! | `0x3a` | 2 | `ND` |
//! | `0x3c` | 2 | `NR` |
//! | `0x3e` | 2 | the chunk's parity unit, from 0 |
//! | `0x40` | `8 * ND` | CRC64 of this slice of each data unit, unpadded (zero for a slice past the unit's end): the CRC-64/XZ polynomial and reflection, zero initial value, no final xor |
//! | `0x40 + 8 * ND` | 8 | record id, random for every record |
//! | `0x48 + 8 * ND` | slice length | parity bytes |
//!
//! Every chunk repeats the whole header, so one intact chunk gives the layout
//! of the record, and one intact chunk per slice gives the CRC of every
//! data unit. Each volume of a multivolume archive carries its own record
//! over its own bytes, found through its own main header's locator. An SFX
//! module is protected like any other bytes and its locator works. With
//! `-hp` the `RR` header is encrypted and the record is not, so the record
//! is found by scanning back from the end of the volume instead of through
//! the main header's locator.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crc_fast::{CrcAlgorithm, Digest};
use reedsolomon_rs::rar5::Rar5RsCoder;

use crate::header::common::{HeaderType, read_raw_header};
use crate::types::ArchiveFormat;

/// Every chunk of a record starts with these bytes.
const MAGIC: [u8; 4] = *b"{RB}";
/// Bytes of a chunk header before the data unit CRCs.
const FIXED_LEN: usize = 0x40;
/// A parity unit is stored in slices of at most this many bytes.
const SLICE: u64 = 0x1_0000;
/// Bytes read at a time while scanning, hashing data units and copying.
const BLOCK: usize = 1 << 20;
/// Most bytes the `RR` service header may take between the protected bytes and
/// the record. RAR writes 23 to 25, and 48 with `-hp`.
const MAX_HEADER_GAP: u64 = 1024;
/// A RAR5 recovery code has at most this many data and parity units together.
const MAX_UNITS: u64 = 65_535;
/// Candidates that look like chunks but fail their CRC64 before a backward
/// scan gives up. Each costs one chunk of hashing, so this bounds the work a
/// volume full of false `{RB}` marks can cause.
const MAX_FAILED_CANDIDATES: usize = 1024;

/// Where a volume's recovery record and the bytes it protects lie.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rar5RecoveryLayout {
    /// The record protects the volume's bytes `0..protected_size`, which is
    /// also where its `RR` service header starts.
    pub protected_size: u64,
    /// Volume offset of the record: the `RR` header's data area.
    pub record_offset: u64,
    /// Bytes of the record.
    pub record_size: u64,
    /// Bytes per data unit. The last unit holds what remains.
    pub unit_size: u64,
    /// Data units the protected bytes are cut into.
    pub data_units: u32,
    /// Parity units in the record, each `unit_size` long.
    pub parity_units: u32,
    /// Slices each parity unit is stored in, 64 KiB each but the last.
    pub slices: u32,
    /// Whether the main header's locator led to the record. Otherwise it was
    /// found by scanning back from the end of the volume, which `-hp` always
    /// needs because its main header is encrypted.
    pub from_locator: bool,
}

/// A volume checked against its recovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rar5RecoveryCheck {
    pub layout: Rar5RecoveryLayout,
    /// Data units whose bytes no longer match the CRC64 the record keeps for
    /// them, ascending.
    pub damaged_units: Vec<u32>,
    /// Record chunks that fail their CRC64 or disagree with the rest of the
    /// record, as `(parity unit, slice)`, ascending. A repair does not use
    /// them and does not rewrite them.
    pub damaged_chunks: Vec<(u32, u32)>,
    /// Slices none of whose chunks is intact, ascending. The CRC64s of that
    /// slice of every data unit are lost with them, so damage confined to
    /// such a slice is neither noticed in `damaged_units` nor repairable.
    pub unverified_slices: Vec<u32>,
}

impl Rar5RecoveryCheck {
    /// Whether every data unit matches its CRC64 and every record chunk
    /// passes its own.
    pub fn is_intact(&self) -> bool {
        self.damaged_units.is_empty() && self.damaged_chunks.is_empty()
    }

    /// Whether a repair is sure to rebuild every damaged data unit: each slice
    /// keeps at least as many intact chunks as there are damaged units. When it
    /// does not, a repair still rebuilds the slices that do and succeeds when
    /// the damage lies only in those.
    pub fn is_repairable(&self) -> bool {
        let damaged = self.damaged_units.len();
        if damaged == 0 {
            return true;
        }
        let parity = self.layout.parity_units as usize;
        let mut lost = vec![0usize; self.layout.slices as usize];
        for &(_, slice) in &self.damaged_chunks {
            lost[slice as usize] += 1;
        }
        lost.iter().all(|&lost| parity - lost >= damaged)
    }
}

/// Why finding, checking or repairing from a RAR5 recovery record stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum Rar5RecoveryError {
    /// Reading the volume or writing the repaired copy failed.
    Io(io::Error),
    /// No chunk of a RAR5 recovery record passes its CRC64.
    NoRecord,
    /// The intact chunks place the record where it cannot be.
    Inconsistent { reason: String },
    /// Damaged data units that could not be rebuilt, because the slices their
    /// damage touches keep too few intact chunks. Nothing was written.
    Unrepairable {
        check: Box<Rar5RecoveryCheck>,
        unrebuilt: Vec<u32>,
    },
}

impl std::fmt::Display for Rar5RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "I/O error: {source}"),
            Self::NoRecord => f.write_str("no intact RAR5 recovery record chunk found"),
            Self::Inconsistent { reason } => {
                write!(f, "inconsistent RAR5 recovery record: {reason}")
            }
            Self::Unrepairable { check, unrebuilt } => write!(
                f,
                "{} of {} damaged data units cannot be rebuilt from the RAR5 recovery record",
                unrebuilt.len(),
                check.damaged_units.len()
            ),
        }
    }
}

impl std::error::Error for Rar5RecoveryError {}

impl From<io::Error> for Rar5RecoveryError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Find a RAR5 volume's recovery record without checking anything else.
///
/// Through the main header's locator this reads the signature, the main
/// header, the `RR` header and the record's first chunk. Without a usable
/// locator it scans back from the end of the volume, which normally ends at
/// the record's last chunk, a few bytes from the end.
pub fn locate_rar5_recovery_record<R: Read + Seek>(
    volume: &mut R,
) -> Result<Rar5RecoveryLayout, Rar5RecoveryError> {
    let len = volume.seek(SeekFrom::End(0))?;
    let located = locate(volume, len, &mut Vec::new())?;
    Ok(located.layout())
}

/// Check a RAR5 volume against its recovery record.
///
/// Reads the volume once: every data unit, to compare with the CRC64 the
/// record keeps for it, and every chunk of the record, to know which parity a
/// repair could use. It holds one 1 MiB buffer, one chunk and the CRC list.
pub fn check_rar5_recovery_record<R: Read + Seek>(
    volume: &mut R,
) -> Result<Rar5RecoveryCheck, Rar5RecoveryError> {
    let len = volume.seek(SeekFrom::End(0))?;
    Ok(scan(volume, len)?.check())
}

/// Write `volume` to `output` with every damaged data unit rebuilt from the
/// recovery record, and return what the check before the rebuild found.
///
/// The bytes from [`protected_size`](Rar5RecoveryLayout::protected_size) on,
/// which are the `RR` header, the record and the end of archive block, are
/// copied as they are, damaged chunks included. Every rebuilt unit must match
/// its CRC64 before anything is written, so `output` gets nothing when the
/// repair falls short.
///
/// Reads the volume three times (check, rebuild, copy) and holds one
/// [`unit_size`](Rar5RecoveryLayout::unit_size) buffer per damaged unit.
pub fn repair_rar5_recovery_record<R: Read + Seek, W: Write>(
    volume: &mut R,
    output: &mut W,
) -> Result<Rar5RecoveryCheck, Rar5RecoveryError> {
    let len = volume.seek(SeekFrom::End(0))?;
    let scan = scan(volume, len)?;
    let check = scan.check();
    let rebuilt = rebuild(volume, &scan, &check)?;

    let mut buf = vec![0u8; BLOCK];
    let mut pos = 0u64;
    for (unit, bytes) in scan.damaged_units.iter().zip(&rebuilt) {
        let at = u64::from(*unit) * scan.record.unit_size;
        copy_range(volume, pos, at, output, &mut buf)?;
        output.write_all(bytes)?;
        pos = at + bytes.len() as u64;
    }
    copy_range(volume, pos, len, output, &mut buf)?;
    Ok(check)
}

/// The record as one intact chunk states it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    protected_size: u64,
    unit_size: u64,
    data_units: u16,
    parity_units: u16,
    header_size: u64,
    row_size: u64,
    marker: [u8; 2],
    record_id: [u8; 8],
}

impl Record {
    fn slices(&self) -> u64 {
        self.unit_size.div_ceil(SLICE)
    }

    fn slice_len(&self, slice: u64) -> u64 {
        SLICE.min(self.unit_size - slice * SLICE)
    }

    /// Offset of a chunk from the start of the record.
    fn chunk_offset(&self, row: u64, slice: u64) -> u64 {
        row * self.row_size + slice * (self.header_size + SLICE)
    }

    fn size(&self) -> u64 {
        u64::from(self.parity_units) * self.row_size
    }

    fn unit_len(&self, unit: u64) -> u64 {
        self.unit_size
            .min(self.protected_size - unit * self.unit_size)
    }

    /// Bytes of slice `slice` of data unit `unit`: the unit's bytes from
    /// `slice * 64 KiB`, at most 64 KiB, none past the unit's end.
    fn unit_slice_len(&self, unit: u64, slice: u64) -> u64 {
        self.unit_len(unit)
            .saturating_sub(slice * SLICE)
            .min(self.slice_len(slice))
    }
}

/// A chunk that passed its CRC64.
struct Chunk {
    record: Record,
    row: u16,
    slice: u64,
    /// CRC64 of this slice of every data unit.
    slice_crcs: Vec<u64>,
}

/// A record and where it starts.
struct Located {
    record: Record,
    start: u64,
    from_locator: bool,
}

impl Located {
    fn layout(&self) -> Rar5RecoveryLayout {
        let record = &self.record;
        Rar5RecoveryLayout {
            protected_size: record.protected_size,
            record_offset: self.start,
            record_size: record.size(),
            unit_size: record.unit_size,
            data_units: u32::from(record.data_units),
            parity_units: u32::from(record.parity_units),
            slices: record.slices() as u32,
            from_locator: self.from_locator,
        }
    }
}

/// A record found and the volume checked against it.
struct Scan {
    located: Located,
    record: Record,
    /// Row-major: parity unit, then slice.
    chunk_ok: Vec<bool>,
    /// Per slice, the CRC64 of that slice of every data unit, from the first
    /// intact chunk of the slice; `None` when the slice has no intact chunk.
    slice_crcs: Vec<Option<Vec<u64>>>,
    damaged_units: Vec<u32>,
}

impl Scan {
    fn check(&self) -> Rar5RecoveryCheck {
        let slices = self.record.slices() as usize;
        let damaged_chunks = self
            .chunk_ok
            .iter()
            .enumerate()
            .filter(|(_, ok)| !**ok)
            .map(|(index, _)| ((index / slices) as u32, (index % slices) as u32))
            .collect();
        let unverified_slices = self
            .slice_crcs
            .iter()
            .enumerate()
            .filter(|(_, crcs)| crcs.is_none())
            .map(|(slice, _)| slice as u32)
            .collect();
        Rar5RecoveryCheck {
            layout: self.located.layout(),
            damaged_units: self.damaged_units.clone(),
            damaged_chunks,
            unverified_slices,
        }
    }
}

fn scan<R: Read + Seek>(volume: &mut R, len: u64) -> Result<Scan, Rar5RecoveryError> {
    let mut buf = Vec::new();
    let located = locate(volume, len, &mut buf)?;
    let record = located.record.clone();
    let slices = record.slices();
    let mut chunk_ok = Vec::with_capacity((u64::from(record.parity_units) * slices) as usize);
    let mut slice_crcs: Vec<Option<Vec<u64>>> = vec![None; slices as usize];
    for row in 0..u64::from(record.parity_units) {
        for slice in 0..slices {
            let pos = located
                .start
                .saturating_add(record.chunk_offset(row, slice));
            let chunk = read_chunk(volume, len, pos, &mut buf)?.filter(|chunk| {
                u64::from(chunk.row) == row && chunk.slice == slice && chunk.record == record
            });
            if let Some(chunk) = &chunk {
                slice_crcs[slice as usize].get_or_insert_with(|| chunk.slice_crcs.clone());
            }
            chunk_ok.push(chunk.is_some());
        }
    }
    let damaged_units = damaged_units(volume, &record, &slice_crcs)?;
    Ok(Scan {
        located,
        record,
        chunk_ok,
        slice_crcs,
        damaged_units,
    })
}

/// Find one intact chunk, through the locator or by scanning back from the
/// end, and place the record from it.
fn locate<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    buf: &mut Vec<u8>,
) -> Result<Located, Rar5RecoveryError> {
    if let Some((header_offset, data_offset)) = locator(volume)
        && let Some(chunk) = read_chunk(volume, len, data_offset, buf)?
        && chunk.row == 0
        && chunk.slice == 0
        && chunk.record.protected_size == header_offset
    {
        return placed(chunk.record, data_offset, len, true);
    }

    let (chunk, pos) = scan_back(volume, len, buf)?.ok_or(Rar5RecoveryError::NoRecord)?;
    let start = pos
        .checked_sub(chunk.record.chunk_offset(u64::from(chunk.row), chunk.slice))
        .ok_or_else(|| inconsistent(format!("chunk at {pos} is too early for its place")))?;
    placed(chunk.record, start, len, false)
}

fn placed(
    record: Record,
    start: u64,
    len: u64,
    from_locator: bool,
) -> Result<Located, Rar5RecoveryError> {
    let protected = record.protected_size;
    if start <= protected || start - protected > MAX_HEADER_GAP {
        return Err(inconsistent(format!(
            "record at {start} does not follow the RR header at {protected}"
        )));
    }
    if record.size() > len {
        return Err(inconsistent(format!(
            "a {} byte record in a {len} byte volume",
            record.size()
        )));
    }
    Ok(Located {
        record,
        start,
        from_locator,
    })
}

/// The offsets of the `RR` header and of its data area, when the main header's
/// locator points at an `RR` service header.
fn locator<R: Read + Seek>(volume: &mut R) -> Option<(u64, u64)> {
    volume.seek(SeekFrom::Start(0)).ok()?;
    if crate::signature::read_signature(volume).ok()? != ArchiveFormat::Rar5 {
        return None;
    }
    let main = read_raw_header(volume).ok()??;
    if main.header_type != HeaderType::MainArchive {
        return None;
    }
    let offset = crate::header::main_archive::parse(&main)
        .ok()?
        .recovery_record_offset?;
    volume.seek(SeekFrom::Start(offset)).ok()?;
    let raw = read_raw_header(volume).ok()??;
    if raw.header_type != HeaderType::Service {
        return None;
    }
    let data_offset = raw
        .offset
        .checked_add(4 + raw.header_size_vint_len as u64)?
        .checked_add(raw.header_size)?;
    let service = crate::header::parse_service_from_raw(&raw, data_offset).ok()?;
    (service.header.service_name() == "RR").then_some((raw.offset, data_offset))
}

/// The intact chunk nearest the end of the volume, and where it is.
fn scan_back<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    buf: &mut Vec<u8>,
) -> io::Result<Option<(Chunk, u64)>> {
    let finder = memchr::memmem::FinderRev::new(&MAGIC);
    let mut block = Vec::new();
    let mut failed = 0usize;
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(BLOCK as u64);
        // Three bytes past `end` catch a mark that straddles it.
        let stop = len.min(end + MAGIC.len() as u64 - 1);
        block.resize((stop - start) as usize, 0);
        read_exact_at(volume, start, &mut block)?;
        for hit in finder.rfind_iter(&block) {
            let pos = start + hit as u64;
            if pos >= end {
                continue;
            }
            match read_chunk_counted(volume, len, pos, buf)? {
                Candidate::Chunk(chunk) => return Ok(Some((chunk, pos))),
                Candidate::Failed => {
                    failed += 1;
                    if failed >= MAX_FAILED_CANDIDATES {
                        return Ok(None);
                    }
                }
                Candidate::NotChunk => {}
            }
        }
        end = start;
    }
    Ok(None)
}

enum Candidate {
    /// Not even the fixed header of a chunk.
    NotChunk,
    /// A plausible header whose CRC64 or layout fails.
    Failed,
    Chunk(Chunk),
}

fn read_chunk<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    pos: u64,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Chunk>> {
    Ok(match read_chunk_counted(volume, len, pos, buf)? {
        Candidate::Chunk(chunk) => Some(chunk),
        Candidate::NotChunk | Candidate::Failed => None,
    })
}

/// Read the chunk at `pos` when there is one: the mark, plausible sizes, and
/// a CRC64 that matches.
fn read_chunk_counted<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    pos: u64,
    buf: &mut Vec<u8>,
) -> io::Result<Candidate> {
    if pos
        .checked_add(FIXED_LEN as u64)
        .is_none_or(|end| end > len)
    {
        return Ok(Candidate::NotChunk);
    }
    buf.resize(FIXED_LEN, 0);
    read_exact_at(volume, pos, buf)?;
    if buf[..4] != MAGIC {
        return Ok(Candidate::NotChunk);
    }
    let chunk_size = u64::from(u32_at(buf, 0x0c));
    let header_size = u64::from(u32_at(buf, 0x10));
    let data_units = u64::from(u16_at(buf, 0x3a));
    if data_units == 0
        || header_size != FIXED_LEN as u64 + 8 * data_units + 8
        || chunk_size <= header_size
        || chunk_size - header_size > SLICE
        || pos.checked_add(chunk_size).is_none_or(|end| end > len)
    {
        return Ok(Candidate::NotChunk);
    }
    buf.resize(chunk_size as usize, 0);
    read_exact_at(volume, pos + FIXED_LEN as u64, &mut buf[FIXED_LEN..])?;
    Ok(match parse_chunk(buf) {
        Some(chunk) => Candidate::Chunk(chunk),
        None => Candidate::Failed,
    })
}

/// Parse one whole chunk whose sizes [`read_chunk_counted`] has checked.
fn parse_chunk(chunk: &[u8]) -> Option<Chunk> {
    if chunk_crc(&chunk[12..]) != u64_at(chunk, 4) {
        return None;
    }
    let header_size = u64::from(u32_at(chunk, 0x10));
    let slice_offset = u64_at(chunk, 0x16);
    let protected_size = u64_at(chunk, 0x22);
    let unit_size = u64_at(chunk, 0x2a);
    let row_size = u64_at(chunk, 0x32);
    let data_units = u16_at(chunk, 0x3a);
    let parity_units = u16_at(chunk, 0x3c);
    let row = u16_at(chunk, 0x3e);
    let nd = u64::from(data_units);
    if parity_units == 0
        || row >= parity_units
        || nd + u64::from(parity_units) > MAX_UNITS
        || unit_size == 0
        || !unit_size.is_multiple_of(2)
        || !slice_offset.is_multiple_of(SLICE)
        || slice_offset >= unit_size
        || chunk.len() as u64 - header_size != SLICE.min(unit_size - slice_offset)
    {
        return None;
    }
    let slices = unit_size.div_ceil(SLICE);
    if slices
        .checked_mul(header_size)
        .and_then(|bytes| bytes.checked_add(unit_size))
        != Some(row_size)
    {
        return None;
    }
    u64::from(parity_units).checked_mul(row_size)?;
    // `ND` units of `U` bytes cover exactly `0..P`, none of them empty.
    let before_last = (nd - 1).checked_mul(unit_size)?;
    if protected_size <= before_last || protected_size - before_last > unit_size {
        return None;
    }
    let crcs = &chunk[FIXED_LEN..FIXED_LEN + 8 * nd as usize];
    let id_at = FIXED_LEN + 8 * nd as usize;
    Some(Chunk {
        record: Record {
            protected_size,
            unit_size,
            data_units,
            parity_units,
            header_size,
            row_size,
            marker: [chunk[0x14], chunk[0x15]],
            record_id: chunk[id_at..id_at + 8].try_into().ok()?,
        },
        row,
        slice: slice_offset / SLICE,
        slice_crcs: crcs.chunks_exact(8).map(|crc| u64_at(crc, 0)).collect(),
    })
}

/// The data units a slice of whose bytes misses the CRC64 the record keeps
/// for it, read in one pass over `0..P`. A slice without a CRC list is not
/// checked.
fn damaged_units<R: Read + Seek>(
    volume: &mut R,
    record: &Record,
    slice_crcs: &[Option<Vec<u64>>],
) -> io::Result<Vec<u32>> {
    let mut damaged = Vec::new();
    let mut buf = vec![0u8; BLOCK];
    volume.seek(SeekFrom::Start(0))?;
    let mut digest = unit_digest();
    let mut unit = 0u64;
    let mut slice = 0u64;
    let mut left = record.unit_slice_len(0, 0);
    let mut remaining = record.protected_size;
    while remaining > 0 {
        let n = remaining.min(BLOCK as u64) as usize;
        volume.read_exact(&mut buf[..n])?;
        remaining -= n as u64;
        let mut data = &buf[..n];
        while !data.is_empty() {
            let take = left.min(data.len() as u64) as usize;
            digest.update(&data[..take]);
            data = &data[take..];
            left -= take as u64;
            if left == 0 {
                let expected = slice_crcs[slice as usize]
                    .as_ref()
                    .map(|crcs| crcs[unit as usize]);
                if expected.is_some_and(|crc| crc != unit_crc(&digest))
                    && damaged.last() != Some(&(unit as u32))
                {
                    damaged.push(unit as u32);
                }
                digest = unit_digest();
                slice += 1;
                if slice * SLICE >= record.unit_len(unit) {
                    unit += 1;
                    slice = 0;
                }
                if unit < u64::from(record.data_units) {
                    left = record.unit_slice_len(unit, slice);
                }
            }
        }
    }
    Ok(damaged)
}

/// Whether a rebuilt data unit matches every CRC64 the record keeps for its
/// slices.
fn unit_matches(record: &Record, slice_crcs: &[Option<Vec<u64>>], unit: u32, bytes: &[u8]) -> bool {
    slice_crcs.iter().enumerate().all(|(slice, crcs)| {
        let Some(crcs) = crcs else {
            return true;
        };
        let from = slice as u64 * SLICE;
        let len = record.unit_slice_len(u64::from(unit), slice as u64);
        let mut digest = unit_digest();
        digest.update(
            bytes
                .get(from as usize..(from + len) as usize)
                .unwrap_or(&[]),
        );
        unit_crc(&digest) == crcs[unit as usize]
    })
}

/// The damaged units rebuilt, in the order of `check.damaged_units`.
///
/// Each slice is decoded with the first intact chunks of that slice standing
/// in for the damaged units, so a damaged chunk costs only its own slice. A
/// slice with too few intact chunks keeps the damaged bytes, and the CRC64 of
/// every rebuilt unit decides whether the damage missed those slices.
fn rebuild<R: Read + Seek>(
    volume: &mut R,
    scan: &Scan,
    check: &Rar5RecoveryCheck,
) -> Result<Vec<Vec<u8>>, Rar5RecoveryError> {
    let damaged = &scan.damaged_units;
    if damaged.is_empty() {
        return Ok(Vec::new());
    }
    let record = &scan.record;
    let nd = usize::from(record.data_units);
    let nr = usize::from(record.parity_units);
    let slices = record.slices() as usize;
    let unit_size = usize::try_from(record.unit_size)
        .map_err(|_| inconsistent(format!("{} byte units", record.unit_size)))?;

    let mut valid = vec![true; nd + nr];
    for &unit in damaged {
        valid[unit as usize] = false;
    }
    // One decoder per pattern of intact chunks; for each slice, the decoder
    // and the parity units that stand in for the damaged units there.
    let mut coders: Vec<(Vec<bool>, Rar5RsCoder)> = Vec::new();
    let mut plan: Vec<Option<(usize, Vec<u64>)>> = Vec::with_capacity(slices);
    for slice in 0..slices {
        let intact: Vec<bool> = (0..nr)
            .map(|row| scan.chunk_ok[row * slices + slice])
            .collect();
        let rows: Vec<u64> = (0..nr as u64)
            .filter(|&row| intact[row as usize])
            .take(damaged.len())
            .collect();
        if rows.len() < damaged.len() {
            plan.push(None);
            continue;
        }
        let coder = match coders.iter().position(|(pattern, _)| *pattern == intact) {
            Some(coder) => coder,
            None => {
                valid[nd..].copy_from_slice(&intact);
                let coder = Rar5RsCoder::new_decoder(nd, nr, &valid)
                    .ok_or_else(|| inconsistent("no decoder for the intact chunks".into()))?;
                coders.push((intact, coder));
                coders.len() - 1
            }
        };
        plan.push(Some((coder, rows)));
    }

    let mut rebuilt = vec![vec![0u8; unit_size]; damaged.len()];
    if plan.iter().any(Option::is_some) {
        let mut input = vec![0u8; SLICE as usize];
        let mut next = 0usize;
        for unit in 0..nd {
            let is_damaged = damaged.get(next) == Some(&(unit as u32));
            for (slice, step) in plan.iter().enumerate() {
                let Some((coder, rows)) = step else {
                    continue;
                };
                let slice = slice as u64;
                let len = record.slice_len(slice) as usize;
                let input = &mut input[..len];
                if is_damaged {
                    let at = scan.located.start
                        + record.chunk_offset(rows[next], slice)
                        + record.header_size;
                    read_exact_at(volume, at, input)?;
                } else {
                    read_unit_slice(volume, record, unit as u64, slice, input)?;
                }
                let from = (slice * SLICE) as usize;
                let mut outputs: Vec<&mut [u8]> = rebuilt
                    .iter_mut()
                    .map(|bytes| &mut bytes[from..from + len])
                    .collect();
                coders[*coder].1.update_outputs(unit, input, &mut outputs);
            }
            if is_damaged {
                next += 1;
            }
        }
    }
    // A slice nothing could decode keeps the bytes the volume has.
    for (slice, step) in plan.iter().enumerate() {
        if step.is_some() {
            continue;
        }
        let slice = slice as u64;
        let from = (slice * SLICE) as usize;
        let len = record.slice_len(slice) as usize;
        for (&unit, bytes) in damaged.iter().zip(rebuilt.iter_mut()) {
            read_unit_slice(
                volume,
                record,
                u64::from(unit),
                slice,
                &mut bytes[from..from + len],
            )?;
        }
    }

    let mut unrebuilt = Vec::new();
    for (&unit, bytes) in damaged.iter().zip(rebuilt.iter_mut()) {
        bytes.truncate(record.unit_len(u64::from(unit)) as usize);
        if !unit_matches(record, &scan.slice_crcs, unit, bytes) {
            unrebuilt.push(unit);
        }
    }
    if !unrebuilt.is_empty() {
        return Err(Rar5RecoveryError::Unrepairable {
            check: Box::new(check.clone()),
            unrebuilt,
        });
    }
    Ok(rebuilt)
}

/// Read one slice of a data unit, zeros past the unit's end.
fn read_unit_slice<R: Read + Seek>(
    volume: &mut R,
    record: &Record,
    unit: u64,
    slice: u64,
    into: &mut [u8],
) -> io::Result<()> {
    let from = slice * SLICE;
    let have = record
        .unit_len(unit)
        .saturating_sub(from)
        .min(into.len() as u64) as usize;
    read_exact_at(volume, unit * record.unit_size + from, &mut into[..have])?;
    into[have..].fill(0);
    Ok(())
}

fn copy_range<R: Read + Seek, W: Write>(
    volume: &mut R,
    from: u64,
    to: u64,
    output: &mut W,
    buf: &mut [u8],
) -> io::Result<()> {
    volume.seek(SeekFrom::Start(from))?;
    let mut left = to.saturating_sub(from);
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        volume.read_exact(&mut buf[..n])?;
        output.write_all(&buf[..n])?;
        left -= n as u64;
    }
    Ok(())
}

fn read_exact_at<R: Read + Seek>(volume: &mut R, pos: u64, into: &mut [u8]) -> io::Result<()> {
    volume.seek(SeekFrom::Start(pos))?;
    volume.read_exact(into)
}

fn inconsistent(reason: String) -> Rar5RecoveryError {
    Rar5RecoveryError::Inconsistent { reason }
}

/// A data unit's CRC64: the CRC-64/XZ polynomial and reflection, but a zero
/// initial value and no final xor.
fn unit_digest() -> Digest {
    Digest::new_with_init_state(CrcAlgorithm::Crc64Xz, 0)
}

fn unit_crc(digest: &Digest) -> u64 {
    // `Digest` applies CRC-64/XZ's final xor, which the unit CRC does not have.
    digest.finalize() ^ u64::MAX
}

/// A chunk's CRC64: CRC-64/XZ.
fn chunk_crc(bytes: &[u8]) -> u64 {
    crc_fast::checksum(CrcAlgorithm::Crc64Xz, bytes)
}

/// The record RAR would write for the volume's bytes `0..P` with this
/// record's geometry: every chunk header, every data unit CRC64 and every
/// parity byte computed from the protected bytes. The random record id is the
/// one field copied from `record`. The tests compare this with the record
/// RAR wrote, byte for byte.
#[cfg(test)]
fn recompute_record<R: Read + Seek>(volume: &mut R, record: &Record) -> io::Result<Vec<u8>> {
    let nd = usize::from(record.data_units);
    let nr = usize::from(record.parity_units);
    let unit_size = record.unit_size as usize;
    let encoder = Rar5RsCoder::new_encoder(nd, nr).expect("parse_chunk bounds the geometry");
    let slices = record.unit_size.div_ceil(SLICE);
    let mut parity = vec![vec![0u8; unit_size]; nr];
    // Per slice, the CRC64 of that slice of every data unit; a slice past a
    // unit's end is empty and hashes to zero.
    let mut crcs = vec![Vec::with_capacity(nd); slices as usize];
    let mut unit = vec![0u8; unit_size];
    volume.seek(SeekFrom::Start(0))?;
    for d in 0..nd {
        let len = record.unit_len(d as u64) as usize;
        volume.read_exact(&mut unit[..len])?;
        unit[len..].fill(0);
        for (slice, crcs) in crcs.iter_mut().enumerate() {
            let from = (slice * SLICE as usize).min(len);
            let to = ((slice + 1) * SLICE as usize).min(len);
            let mut digest = unit_digest();
            digest.update(&unit[from..to]);
            crcs.push(unit_crc(&digest));
        }
        let mut outputs: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
        encoder.update_outputs(d, &unit, &mut outputs);
    }

    let header_size = (FIXED_LEN + 8 * nd + 8) as u64;
    let row_size = slices * header_size + record.unit_size;
    let last = record.unit_len(nd as u64 - 1);
    let mut out = Vec::with_capacity((u64::from(record.parity_units) * row_size) as usize);
    for (k, row) in parity.iter().enumerate() {
        for slice in 0..slices {
            let offset = slice * SLICE;
            let len = SLICE.min(record.unit_size - offset);
            let start = out.len();
            out.extend_from_slice(&MAGIC);
            out.extend_from_slice(&[0u8; 8]);
            out.extend_from_slice(&((header_size + len) as u32).to_le_bytes());
            out.extend_from_slice(&(header_size as u32).to_le_bytes());
            out.extend_from_slice(&[1, 1]);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(SLICE.min(last.wrapping_sub(offset)) as u32).to_le_bytes());
            out.extend_from_slice(&record.protected_size.to_le_bytes());
            out.extend_from_slice(&record.unit_size.to_le_bytes());
            out.extend_from_slice(&row_size.to_le_bytes());
            out.extend_from_slice(&record.data_units.to_le_bytes());
            out.extend_from_slice(&record.parity_units.to_le_bytes());
            out.extend_from_slice(&(k as u16).to_le_bytes());
            for crc in &crcs[slice as usize] {
                out.extend_from_slice(&crc.to_le_bytes());
            }
            out.extend_from_slice(&record.record_id);
            out.extend_from_slice(&row[offset as usize..(offset + len) as usize]);
            let crc = chunk_crc(&out[start + 12..]);
            out[start + 4..start + 12].copy_from_slice(&crc.to_le_bytes());
        }
    }
    Ok(out)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    use super::*;

    /// A data unit's CRC64 the slow way: the CRC-64/XZ polynomial,
    /// reflected, from a zero register and without a final xor.
    fn reference_unit_crc(bytes: &[u8]) -> u64 {
        let mut crc = 0u64;
        for &b in bytes {
            crc ^= u64::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xC96C_5795_D787_0F42
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar5")
            .join(name);
        fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    const FIXTURES: [&str; 7] = [
        "rar5_recovery.rar",
        "rar5_mv_store_rr.part1.rar",
        "rar5_mv_store_rr.part2.rar",
        "rar5_mv_store_rr.part3.rar",
        "rar5_mv_store_rr.part4.rar",
        "rar5_mv_store_rr.part5.rar",
        "rar5_mv_store_rr.part6.rar",
    ];

    /// The geometry RAR chooses for `P` protected bytes at `percent`: as
    /// many data units of about 1 KiB as fit, at most 200, and `percent` of
    /// them as parity, at least one.
    fn expected_geometry(protected: u64, percent: u64) -> (u16, u64, u16) {
        let nd = protected.div_ceil(1024).clamp(1, 200);
        let unit = protected.div_ceil(nd).next_multiple_of(2);
        let nr = (nd * percent / 100).max(1);
        (nd as u16, unit, nr as u16)
    }

    fn located(bytes: &[u8]) -> Located {
        let mut cursor = Cursor::new(bytes);
        locate(&mut cursor, bytes.len() as u64, &mut Vec::new()).expect("a record")
    }

    fn stored_record<'a>(bytes: &'a [u8], located: &Located) -> &'a [u8] {
        let start = located.start as usize;
        &bytes[start..start + located.record.size() as usize]
    }

    fn recomputed(bytes: &[u8], located: &Located) -> Vec<u8> {
        recompute_record(&mut Cursor::new(bytes), &located.record).unwrap()
    }

    fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
        a.iter().zip(b).position(|(x, y)| x != y)
    }

    fn percent_from_headers(bytes: &[u8]) -> Option<u64> {
        let archive = crate::archive::RarArchive::open(Cursor::new(bytes.to_vec())).ok()?;
        archive
            .metadata()
            .recovery_records
            .first()?
            .recovery_percent
    }

    fn check(bytes: &[u8]) -> Rar5RecoveryCheck {
        check_rar5_recovery_record(&mut Cursor::new(bytes)).expect("a record")
    }

    fn repair(bytes: &[u8]) -> Result<(Rar5RecoveryCheck, Vec<u8>), Rar5RecoveryError> {
        let mut out = Vec::new();
        let check = repair_rar5_recovery_record(&mut Cursor::new(bytes), &mut out)?;
        Ok((check, out))
    }

    /// Deterministic bytes for damage: xorshift64 from a fixed seed.
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[derive(Clone, Copy)]
    enum Damage {
        Zero,
        Noise,
    }

    fn damaged(bytes: &[u8], ranges: &[(u64, u64)], how: Damage) -> Vec<u8> {
        let mut copy = bytes.to_vec();
        for (i, &(from, len)) in ranges.iter().enumerate() {
            let range = from as usize..(from + len) as usize;
            match how {
                Damage::Zero => copy[range].fill(0),
                Damage::Noise => {
                    copy[range].copy_from_slice(&noise(0x9E37_79B9 + i as u64, len as usize))
                }
            }
        }
        copy
    }

    /// `(offset, len)` of a whole data unit.
    fn unit_range(layout: &Rar5RecoveryLayout, unit: u32) -> (u64, u64) {
        let from = u64::from(unit) * layout.unit_size;
        (from, layout.unit_size.min(layout.protected_size - from))
    }

    #[test]
    fn unit_crc_is_zero_init_without_final_xor_and_chunk_crc_is_crc64_xz() {
        let samples: [&[u8]; 4] = [b"", b"123456789", &[0u8; 1000], &noise(7, 70_001)];
        for sample in samples {
            let mut digest = unit_digest();
            digest.update(sample);
            assert_eq!(unit_crc(&digest), reference_unit_crc(sample));
        }
        assert_eq!(chunk_crc(b"123456789"), 0x995D_C9BB_DF19_39FA);
        // The two differ: a zero register and no xor against CRC-64/XZ.
        assert_ne!(reference_unit_crc(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn fixture_records_recompute_byte_for_byte() {
        for name in FIXTURES {
            let bytes = fixture(name);
            let located = located(&bytes);
            assert!(located.from_locator, "{name}: locator");
            let record = &located.record;
            assert_eq!(record.marker, [1, 1], "{name}");
            let percent = percent_from_headers(&bytes).expect("RR percent in the service header");
            assert_eq!(
                (record.data_units, record.unit_size, record.parity_units),
                expected_geometry(record.protected_size, percent),
                "{name}: geometry for P={} at {percent}%",
                record.protected_size
            );
            let stored = stored_record(&bytes, &located);
            let ours = recomputed(&bytes, &located);
            assert_eq!(ours.len(), stored.len(), "{name}: record length");
            assert_eq!(
                first_difference(&ours, stored),
                None,
                "{name}: first differing byte"
            );
            // After the record: the 8-byte end of archive header, then only
            // the zero padding a `-v` volume gets up to its size.
            let after = (located.start + record.size()) as usize;
            assert_eq!(bytes[after + 4..after + 7], [3, 5, 4], "{name}: end header");
            assert!(
                bytes[after + 8..].iter().all(|&b| b == 0),
                "{name}: padding"
            );
            let check = check(&bytes);
            assert!(check.is_intact(), "{name}: {check:?}");
            assert_eq!(check.layout, located.layout());
        }
    }

    #[test]
    fn fixture_geometry_is_what_rar_chose() {
        let single = located(&fixture("rar5_recovery.rar")).layout();
        assert_eq!(
            (single.data_units, single.parity_units, single.slices),
            (1, 1, 1)
        );
        assert_eq!((single.protected_size, single.record_offset), (154, 177));
        assert_eq!(single.record_size, 0x50 + 154);
        // `-rr5p -v4k`: 2869 protected bytes in a 4096-byte volume give three
        // 958-byte units and one parity unit, since 5% of 3 rounds to none.
        let part1 = located(&fixture("rar5_mv_store_rr.part1.rar")).layout();
        assert_eq!((part1.data_units, part1.parity_units), (3, 1));
        assert_eq!(part1.unit_size, 958);
        assert_eq!((part1.protected_size, part1.record_offset), (2869, 2892));
        let part6 = located(&fixture("rar5_mv_store_rr.part6.rar")).layout();
        assert_eq!((part6.protected_size, part6.unit_size), (2584, 862));
    }

    #[test]
    fn repairs_one_damaged_unit_anywhere_in_a_fixture() {
        let original = fixture("rar5_mv_store_rr.part3.rar");
        let layout = located(&original).layout();
        assert_eq!(layout.parity_units, 1);
        for unit in 0..layout.data_units {
            for how in [Damage::Zero, Damage::Noise] {
                let (from, len) = unit_range(&layout, unit);
                // Part of the unit, never the whole, so the CRC must notice.
                let hurt = damaged(&original, &[(from + 3, len / 2)], how);
                let check = check(&hurt);
                assert_eq!(check.damaged_units, [unit]);
                assert!(check.damaged_chunks.is_empty());
                assert!(check.is_repairable());
                let (_, repaired) = repair(&hurt).unwrap();
                assert_eq!(repaired, original, "unit {unit}");
            }
        }
    }

    #[test]
    fn repairs_a_damaged_signature_and_main_header() {
        let original = fixture("rar5_mv_store_rr.part1.rar");
        let hurt = damaged(&original, &[(0, 40)], Damage::Noise);
        let check = check(&hurt);
        assert!(!check.layout.from_locator);
        assert_eq!(check.damaged_units, [0]);
        let (_, repaired) = repair(&hurt).unwrap();
        assert_eq!(repaired, original);
    }

    #[test]
    fn repairs_the_whole_protected_range_of_a_one_unit_record() {
        let original = fixture("rar5_recovery.rar");
        let layout = located(&original).layout();
        let hurt = damaged(&original, &[(0, layout.protected_size)], Damage::Zero);
        let (check, repaired) = repair(&hurt).unwrap();
        assert_eq!(check.damaged_units, [0]);
        assert_eq!(repaired, original);
    }

    #[test]
    fn over_capacity_damage_is_refused_and_nothing_written() {
        let original = fixture("rar5_mv_store_rr.part2.rar");
        let layout = located(&original).layout();
        let (a, _) = unit_range(&layout, 0);
        let (b, _) = unit_range(&layout, 2);
        let hurt = damaged(&original, &[(a + 1, 8), (b + 1, 8)], Damage::Noise);
        let check = check(&hurt);
        assert_eq!(check.damaged_units, [0, 2]);
        assert!(!check.is_repairable());
        let mut out = Vec::new();
        let err = repair_rar5_recovery_record(&mut Cursor::new(&hurt), &mut out).unwrap_err();
        match err {
            Rar5RecoveryError::Unrepairable { unrebuilt, .. } => assert_eq!(unrebuilt, [0, 2]),
            other => panic!("{other}"),
        }
        assert!(out.is_empty());
    }

    #[test]
    fn a_damaged_chunk_is_reported_and_copied_as_it_is() {
        let original = fixture("rar5_mv_store_rr.part4.rar");
        let layout = located(&original).layout();
        // Inside the parity bytes of the only chunk.
        let hurt = damaged(
            &original,
            &[(layout.record_offset + 0x60, 4)],
            Damage::Noise,
        );
        let err = locate_rar5_recovery_record(&mut Cursor::new(&hurt)).unwrap_err();
        assert!(matches!(err, Rar5RecoveryError::NoRecord), "{err}");
    }

    #[test]
    fn damage_after_the_record_is_outside_its_reach() {
        let original = fixture("rar5_mv_store_rr.part5.rar");
        let layout = located(&original).layout();
        let end = layout.record_offset + layout.record_size;
        let hurt = damaged(&original, &[(end + 1, 2)], Damage::Noise);
        let check = check(&hurt);
        assert!(check.is_intact());
        let (_, repaired) = repair(&hurt).unwrap();
        assert_eq!(repaired, hurt);
    }

    #[test]
    fn a_damaged_rr_header_is_bridged_by_the_backward_scan() {
        let original = fixture("rar5_mv_store_rr.part6.rar");
        let layout = located(&original).layout();
        let gap = layout.record_offset - layout.protected_size;
        let hurt = damaged(&original, &[(layout.protected_size, gap)], Damage::Noise);
        let check = check(&hurt);
        assert!(!check.layout.from_locator);
        assert!(check.is_intact());
        assert_eq!(check.layout.record_offset, layout.record_offset);
    }

    #[test]
    fn a_volume_without_a_record_is_no_record() {
        // The fixture cut before its `RR` header: an archive without a record.
        let whole = fixture("rar5_recovery.rar");
        let bytes = &whole[..located(&whole).record.protected_size as usize];
        let err = locate_rar5_recovery_record(&mut Cursor::new(bytes)).unwrap_err();
        assert!(matches!(err, Rar5RecoveryError::NoRecord));
        let err = locate_rar5_recovery_record(&mut Cursor::new(b"")).unwrap_err();
        assert!(matches!(err, Rar5RecoveryError::NoRecord));
    }

    // Everything below reads RARLAB-written scratch archives from the
    // directory `RR5_SCRATCH_DIR` names and does nothing without it, so the
    // committed suite stays fixture-only. With `RR5_ORACLE_DIR` set as well,
    // damaged copies and our repairs are written there for `rar r`.

    fn scratch_dir() -> Option<PathBuf> {
        std::env::var_os("RR5_SCRATCH_DIR").map(PathBuf::from)
    }

    fn scratch_archives(dir: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for sub in ["out", "out2"] {
            let Ok(entries) = fs::read_dir(dir.join(sub)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if name.ends_with(".rar") || name.ends_with(".sfx") {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        paths
    }

    /// The `-rr` percent a scratch archive was written with, from its name.
    fn percent_from_name(name: &str) -> u64 {
        let tag = name
            .split('_')
            .find(|part| part.starts_with("rr"))
            .expect("an _rrN_ tag");
        let tag = tag.split('.').next().unwrap();
        match &tag[2..] {
            "def" => 3,
            digits => digits.trim_end_matches('p').parse().unwrap(),
        }
    }

    #[test]
    fn scratch_sweep_recomputes_every_rarlab_record_byte_for_byte() {
        let Some(dir) = scratch_dir() else {
            eprintln!("RR5_SCRATCH_DIR unset: skipped");
            return;
        };
        let mut failures = Vec::new();
        let mut seen = 0;
        for path in scratch_archives(&dir) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).unwrap();
            let mut cursor = Cursor::new(&bytes);
            let located = match locate(&mut cursor, bytes.len() as u64, &mut Vec::new()) {
                Ok(located) => located,
                Err(e) => {
                    failures.push(format!("{name}: {e}"));
                    continue;
                }
            };
            seen += 1;
            let record = &located.record;
            let layout = located.layout();
            let encrypted_headers = name.contains("_hp");
            let percent = percent_from_name(&name);
            let header_percent = percent_from_headers(&bytes);
            let stored = stored_record(&bytes, &located);
            let ours = recomputed(&bytes, &located);
            let diff = first_difference(&ours, stored);
            let exact = ours.len() == stored.len() && diff.is_none();
            let check = check_rar5_recovery_record(&mut Cursor::new(&bytes)).unwrap();
            let tail = bytes.len() as u64 - (located.start + record.size());
            eprintln!(
                "{name}: P={} ND={} U={} NR={} slices={} record=[{}, {}) tail={tail} locator={} marker={:?} rr%={percent} hdr%={header_percent:?} exact={exact}",
                record.protected_size,
                record.data_units,
                record.unit_size,
                record.parity_units,
                layout.slices,
                located.start,
                located.start + record.size(),
                located.from_locator,
                record.marker,
            );
            if !exact {
                failures.push(format!(
                    "{name}: recompute differs, lengths {} vs {}, first at {diff:?}",
                    ours.len(),
                    stored.len()
                ));
            }
            let expected = expected_geometry(record.protected_size, percent);
            if (record.data_units, record.unit_size, record.parity_units) != expected {
                failures.push(format!(
                    "{name}: geometry (ND,U,NR)=({},{},{}) expected {expected:?} for P={} at {percent}%",
                    record.data_units, record.unit_size, record.parity_units, record.protected_size
                ));
            }
            if located.from_locator == encrypted_headers {
                failures.push(format!("{name}: locator {}", located.from_locator));
            }
            if !encrypted_headers && header_percent != Some(percent) {
                failures.push(format!("{name}: header percent {header_percent:?}"));
            }
            if record.marker != [1, 1] {
                failures.push(format!("{name}: marker {:?}", record.marker));
            }
            if !check.is_intact() {
                failures.push(format!("{name}: {check:?}"));
            }
            // An 8-byte end header, or a 32-byte encrypted one with `-hp`,
            // then only a `-v` volume's zero padding.
            let end_header = if encrypted_headers { 32 } else { 8 };
            let after = (located.start + record.size() + end_header) as usize;
            if tail < end_header || !bytes[after..].iter().all(|&b| b == 0) {
                failures.push(format!("{name}: {tail} bytes after the record"));
            }
        }
        assert!(seen >= 100, "only {seen} scratch archives");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    struct Case {
        name: &'static str,
        archive: &'static str,
        how: Damage,
        ranges: fn(&Rar5RecoveryLayout) -> Vec<(u64, u64)>,
        /// Units the check must report damaged, and whether a repair must
        /// give back the original.
        units: fn(&Rar5RecoveryLayout) -> Vec<u32>,
        repairable: bool,
        /// Whether a record chunk is damaged.
        record_hit: bool,
    }

    impl Case {
        /// Whether the damage reaches past `P`: the `RR` header, the record
        /// or the end of archive block, which a repair copies as they are.
        fn hits_unprotected(&self, layout: &Rar5RecoveryLayout) -> bool {
            (self.ranges)(layout)
                .iter()
                .any(|&(from, len)| from + len > layout.protected_size)
        }
    }

    fn units(layout: &Rar5RecoveryLayout, units: &[u32]) -> Vec<(u64, u64)> {
        units
            .iter()
            .map(|&u| {
                let (from, len) = unit_range(layout, u);
                (from + len / 3, len / 3)
            })
            .collect()
    }

    fn chunk_range(layout: &Rar5RecoveryLayout, row: u32, slice: u32) -> (u64, u64) {
        let header = 0x48 + 8 * u64::from(layout.data_units);
        let slice_len = SLICE.min(layout.unit_size - u64::from(slice) * SLICE);
        let row_size = u64::from(layout.slices) * header + layout.unit_size;
        let at = layout.record_offset
            + u64::from(row) * row_size
            + u64::from(slice) * (header + SLICE)
            + header;
        (at + 16, slice_len.min(64))
    }

    const CASES: &[Case] = &[
        Case {
            name: "zero_3_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Zero,
            ranges: |l| units(l, &[5, 77, 150]),
            units: |_| vec![5, 77, 150],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "noise_capacity_10_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[0, 1, 30, 31, 32, 99, 120, 160, 198, 199]),
            units: |_| vec![0, 1, 30, 31, 32, 99, 120, 160, 198, 199],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "noise_11_units_over_capacity",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[0, 1, 30, 31, 32, 99, 120, 160, 190, 198, 199]),
            units: |_| vec![0, 1, 30, 31, 32, 99, 120, 160, 190, 198, 199],
            repairable: false,
            record_hit: false,
        },
        Case {
            name: "contiguous_run_of_7_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| vec![(l.unit_size * 100 + 10, l.unit_size * 6 + 1)],
            units: |_| (100..107).collect(),
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "signature_and_start",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Zero,
            ranges: |_| vec![(0, 64)],
            units: |_| vec![0],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "last_unit_tail",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| vec![(l.protected_size - 5, 5)],
            units: |l| vec![l.data_units - 1],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "chunk_damaged_plus_9_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| {
                let mut r = units(l, &[2, 3, 4, 5, 6, 7, 8, 9, 10]);
                r.push(chunk_range(l, 0, 0));
                r
            },
            units: |_| (2..=10).collect(),
            repairable: true,
            record_hit: true,
        },
        Case {
            name: "chunk_damaged_plus_10_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| {
                let mut r = units(l, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
                r.push(chunk_range(l, 4, 0));
                r
            },
            units: |_| (2..=11).collect(),
            repairable: false,
            record_hit: true,
        },
        Case {
            name: "rr_header_and_2_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| {
                let mut r = units(l, &[40, 41]);
                r.push((l.protected_size, l.record_offset - l.protected_size));
                r
            },
            units: |_| vec![40, 41],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "hp_2_units",
            archive: "out2/v720_hp_100k_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[0, 50]),
            units: |_| vec![0, 50],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "p_3_units",
            archive: "out2/v624_p_100k_rr5p.rar",
            how: Damage::Zero,
            ranges: |l| units(l, &[10, 11, 97]),
            units: |_| vec![10, 11, 97],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "mv_part2_1_unit",
            archive: "out2/v720_mv3m_rr5p.part2.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[100]),
            units: |_| vec![100],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "sfx_2_units",
            archive: "out2/v720_sfx_100k_rr5p.sfx",
            how: Damage::Noise,
            ranges: |l| units(l, &[0, 199]),
            units: |_| vec![0, 199],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "sliced_40m_2_units_spanning_slices",
            archive: "out2/v720_40m_rr3.rar",
            how: Damage::Noise,
            ranges: |l| {
                vec![
                    (l.unit_size * 17 + 0x1_0000 - 100, 300),
                    (l.unit_size * 150, 10),
                ]
            },
            units: |_| vec![17, 150],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "sliced_40m_chunk_slice2_row0_plus_5_units",
            archive: "out2/v720_40m_rr3.rar",
            how: Damage::Zero,
            ranges: |l| {
                let mut r = units(l, &[0, 60, 61, 62, 199]);
                r.push(chunk_range(l, 0, 2));
                r
            },
            units: |_| vec![0, 60, 61, 62, 199],
            repairable: true,
            record_hit: true,
        },
        Case {
            name: "sliced_40m_6_units_at_capacity",
            archive: "out2/v720_40m_rr3.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[3, 4, 5, 100, 101, 199]),
            units: |_| vec![3, 4, 5, 100, 101, 199],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "wrap_13m_2_units",
            archive: "out2/v720_13m_rr1.rar",
            how: Damage::Noise,
            ranges: |l| units(l, &[0, 199]),
            units: |_| vec![0, 199],
            repairable: true,
            record_hit: false,
        },
    ];

    #[test]
    fn scratch_damage_cases_repair_to_the_original_up_to_capacity() {
        let Some(dir) = scratch_dir() else {
            eprintln!("RR5_SCRATCH_DIR unset: skipped");
            return;
        };
        let oracle = std::env::var_os("RR5_ORACLE_DIR").map(PathBuf::from);
        if let Some(oracle) = &oracle {
            fs::create_dir_all(oracle).unwrap();
        }
        let mut failures = Vec::new();
        for case in CASES {
            let original = fs::read(dir.join(case.archive)).unwrap();
            let layout = located(&original).layout();
            let hurt = damaged(&original, &(case.ranges)(&layout), case.how);
            let expected_units = (case.units)(&layout);
            let check = check_rar5_recovery_record(&mut Cursor::new(&hurt)).unwrap();
            let mut problems = Vec::new();
            if check.damaged_units != expected_units {
                problems.push(format!("damaged units {:?}", check.damaged_units));
            }
            if check.damaged_chunks.is_empty() == case.record_hit {
                problems.push(format!("damaged chunks {:?}", check.damaged_chunks));
            }
            if check.is_repairable() != case.repairable {
                problems.push(format!("is_repairable {}", check.is_repairable()));
            }
            let mut out = Vec::new();
            let result = repair_rar5_recovery_record(&mut Cursor::new(&hurt), &mut out);
            match (result, case.repairable) {
                (Ok(_), true) => {
                    let want = if case.hits_unprotected(&layout) {
                        // Protected bytes from the original, the rest as damaged.
                        let mut want = original.clone();
                        want[layout.protected_size as usize..]
                            .copy_from_slice(&hurt[layout.protected_size as usize..]);
                        want
                    } else {
                        original.clone()
                    };
                    if out != want {
                        problems.push(format!(
                            "repair differs at {:?}",
                            first_difference(&out, &want)
                        ));
                    }
                }
                (Ok(_), false) => problems.push("repaired over capacity".into()),
                (Err(Rar5RecoveryError::Unrepairable { unrebuilt, .. }), false) => {
                    if !out.is_empty() {
                        problems.push("wrote output on failure".into());
                    }
                    eprintln!("{}: unrepairable, unrebuilt {unrebuilt:?}", case.name);
                }
                (Err(e), _) => problems.push(format!("error {e}")),
            }
            eprintln!(
                "{}: units {:?} chunks {:?} repairable {} -> {}",
                case.name,
                check.damaged_units,
                check.damaged_chunks,
                check.is_repairable(),
                if problems.is_empty() { "ok" } else { "FAILED" }
            );
            if let Some(oracle) = &oracle {
                let ext = if case.archive.ends_with(".sfx") {
                    "sfx"
                } else {
                    "rar"
                };
                fs::write(oracle.join(format!("{}.{ext}", case.name)), &hurt).unwrap();
                if !out.is_empty() {
                    fs::write(oracle.join(format!("{}.ours.{ext}", case.name)), &out).unwrap();
                }
            }
            if !problems.is_empty() {
                failures.push(format!("{}: {}", case.name, problems.join("; ")));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
