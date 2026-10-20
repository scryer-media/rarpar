//! The RAR5 recovery record: the `RR` service block `rar a -rr[N]` and
//! `rar rr[N]` give every RAR5 volume, Reed-Solomon parity over the volume's
//! own bytes.
//!
//! A data unit is checked and rebuilt slice by slice: each 64 KiB slice of
//! it has its own CRC64 in the record and its own parity chunks, so damage
//! in one slice uses only that slice's intact chunks, and a rebuilt slice is
//! kept only once it matches its CRC64. A chunk that fails its own CRC64 is
//! reported as damaged parity and never used or rewritten, as `rar r`
//! documents for its own repair.
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
//!
//! A record is held to what RAR writes: at most 200 data units, of the even
//! size `ceil(P / ND)` rounded up, which also bounds the work and memory a
//! hostile header can ask for.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufReader, Read, Seek, SeekFrom};

use crc_fast::{CrcAlgorithm, Digest};
use reedsolomon_rs::rar5::Rar5RsCoder;

use super::record::{
    Examination, Probe, RecoveryRecordLayout, RecoveryRecordPatch, SCAN_LOOKAHEAD, read_exact_at,
    scan_back,
};
use crate::error::{RarError, RarResult};
use crate::header::common::{HeaderType, read_raw_header};
use crate::types::ArchiveFormat;

/// Every chunk of a record starts with these bytes.
const MAGIC: [u8; 4] = *b"{RB}";
/// Bytes of a chunk header before the data unit CRCs.
const FIXED_LEN: usize = 0x40;
/// A parity unit is stored, and a data unit checked, in slices of at most
/// this many bytes.
const SLICE: u64 = 0x1_0000;
/// Bytes read at a time while hashing the protected bytes.
const BLOCK: usize = 1 << 20;
/// Most bytes the `RR` service header may take between the protected bytes
/// and the record. RAR writes 23 to 25, and 48 with `-hp`.
const MAX_HEADER_GAP: u64 = 1024;
/// Most data units RAR cuts the protected bytes into.
const MAX_DATA_UNITS: u64 = 200;
/// A RAR5 recovery code has at most this many data and parity units together.
const MAX_UNITS: u64 = 65_535;

// A scan judges a candidate chunk's fixed header from the bytes it shows.
const _: () = assert!(FIXED_LEN <= SCAN_LOOKAHEAD);

/// The record's shape, which every chunk header repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Geometry {
    protected_size: u64,
    unit_size: u64,
    data_units: u16,
    parity_units: u16,
    header_size: u64,
    /// Record bytes per parity unit: its chunks' headers and its `U` bytes.
    row_size: u64,
    marker: [u8; 2],
    record_id: [u8; 8],
}

impl Geometry {
    fn slices(&self) -> u64 {
        self.unit_size.div_ceil(SLICE)
    }

    fn slice_len(&self, slice: u64) -> u64 {
        SLICE.min(self.unit_size - slice * SLICE)
    }

    /// Where a chunk starts, from the start of the record.
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
    geometry: Geometry,
    row: u16,
    slice: u64,
    /// CRC64 of this slice of every data unit.
    slice_crcs: Vec<u64>,
}

/// A record placed where its geometry says it must sit: just past an `RR`
/// header at `P`, wholly inside the volume, so every offset below is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    geometry: Geometry,
    /// Where the record starts: the `RR` header's data area.
    start: u64,
    found_by_scan: bool,
}

/// What the record's chunks say.
struct Chunks {
    rows: u64,
    slices: u64,
    /// Whether each chunk passes its CRC64 and agrees with the record,
    /// row-major: parity unit, then slice.
    intact: Vec<bool>,
    /// Per slice, the CRC64 of that slice of every data unit, from the
    /// slice's first intact chunk; `None` when no chunk of it is intact.
    crcs: Vec<Option<Vec<u64>>>,
}

impl Chunks {
    fn is_intact(&self, row: u64, slice: u64) -> bool {
        self.intact[(row * self.slices + slice) as usize]
    }

    fn intact_rows(&self, slice: u64) -> impl Iterator<Item = u64> + '_ {
        (0..self.rows).filter(move |&row| self.is_intact(row, slice))
    }
}

impl Record {
    fn place(geometry: Geometry, start: u64, len: u64, found_by_scan: bool) -> Option<Self> {
        let protected = geometry.protected_size;
        let fits = start > protected
            && start - protected <= MAX_HEADER_GAP
            && start
                .checked_add(geometry.size())
                .is_some_and(|end| end <= len);
        fits.then_some(Self {
            geometry,
            start,
            found_by_scan,
        })
    }

    fn end(&self) -> u64 {
        self.start + self.geometry.size()
    }

    fn chunk_at(&self, row: u64, slice: u64) -> u64 {
        self.start + self.geometry.chunk_offset(row, slice)
    }

    pub(super) fn layout(&self) -> RecoveryRecordLayout {
        let geometry = &self.geometry;
        RecoveryRecordLayout {
            format: ArchiveFormat::Rar5,
            protected_size: geometry.protected_size,
            record_offset: self.start,
            record_size: geometry.size(),
            unit_size: geometry.unit_size,
            data_units: u64::from(geometry.data_units),
            parity_units: u64::from(geometry.parity_units),
            found_by_scan: self.found_by_scan,
        }
    }

    /// Check the volume against the record, and with `rebuild` rebuild every
    /// damaged slice when each has enough intact chunks. Reads every chunk
    /// once and the protected bytes once, then, to rebuild, that slice of
    /// every data unit once per damaged slice: at most the protected bytes
    /// once more.
    pub(super) fn examine<R: Read + Seek>(
        &self,
        volume: &mut R,
        rebuild: bool,
    ) -> RarResult<Examination> {
        let mut out = Examination::new(self.layout());
        let chunks = self.read_chunks(volume)?;
        let (damaged, unchecked_bytes) = self.check_units(volume, &chunks)?;

        let assessment = &mut out.assessment;
        assessment.unchecked_bytes = unchecked_bytes;
        assessment.damaged_parity = (0..chunks.rows)
            .filter(|&row| (0..chunks.slices).any(|slice| !chunks.is_intact(row, slice)))
            .collect();
        for (&slice, units) in &damaged {
            assessment.damaged_units.extend(units);
            if units.len() > chunks.intact_rows(slice).count() {
                assessment.unrepairable_units.extend(units);
            }
        }

        if rebuild && out.assessment.unrepairable_units.is_empty() {
            let mut decoders = HashMap::new();
            for (&slice, units) in &damaged {
                self.rebuild_slice(volume, &chunks, slice, units, &mut decoders, &mut out)?;
            }
        }
        Ok(out)
    }

    fn read_chunks<R: Read + Seek>(&self, volume: &mut R) -> RarResult<Chunks> {
        let geometry = &self.geometry;
        let rows = u64::from(geometry.parity_units);
        let slices = geometry.slices();
        let mut intact = Vec::with_capacity((rows * slices) as usize);
        let mut crcs = vec![None; slices as usize];
        let mut buf = Vec::new();
        for row in 0..rows {
            for slice in 0..slices {
                let chunk = read_chunk(volume, self.end(), self.chunk_at(row, slice), &mut buf)?
                    .filter(|chunk| {
                        u64::from(chunk.row) == row
                            && chunk.slice == slice
                            && chunk.geometry == *geometry
                    });
                intact.push(chunk.is_some());
                if let Some(chunk) = chunk {
                    crcs[slice as usize].get_or_insert(chunk.slice_crcs);
                }
            }
        }
        Ok(Chunks {
            rows,
            slices,
            intact,
            crcs,
        })
    }

    /// Hash every data unit slice by slice, in one pass over `0..P`. Gives
    /// the damaged slices, each with its damaged units ascending, and the
    /// bytes of slices that have no CRC64 left to check against.
    fn check_units<R: Read + Seek>(
        &self,
        volume: &mut R,
        chunks: &Chunks,
    ) -> RarResult<(BTreeMap<u64, Vec<u64>>, u64)> {
        let geometry = &self.geometry;
        volume.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(BLOCK, &mut *volume);
        let mut piece = vec![0u8; geometry.slice_len(0) as usize];
        let mut damaged: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut unchecked = 0;
        for unit in 0..u64::from(geometry.data_units) {
            for slice in 0..chunks.slices {
                let len = geometry.unit_slice_len(unit, slice);
                if len == 0 {
                    break;
                }
                let piece = &mut piece[..len as usize];
                reader.read_exact(piece)?;
                match &chunks.crcs[slice as usize] {
                    Some(crcs) if slice_crc(piece) != crcs[unit as usize] => {
                        damaged.entry(slice).or_default().push(unit);
                    }
                    Some(_) => {}
                    None => unchecked += len,
                }
            }
        }
        Ok((damaged, unchecked))
    }

    /// Rebuild slice `slice` of the damaged `units`, the first intact chunks
    /// of the slice standing in for them in order, and keep each rebuilt
    /// piece that matches its CRC64. One that does not is unrepairable.
    fn rebuild_slice<R: Read + Seek>(
        &self,
        volume: &mut R,
        chunks: &Chunks,
        slice: u64,
        units: &[u64],
        decoders: &mut HashMap<Vec<bool>, Rar5RsCoder>,
        out: &mut Examination,
    ) -> RarResult<()> {
        let geometry = &self.geometry;
        let data_units = usize::from(geometry.data_units);
        let crcs = chunks.crcs[slice as usize]
            .as_ref()
            .ok_or_else(|| RarError::internal("damage found in an unchecked RAR5 slice"))?;
        let rows: Vec<u64> = chunks.intact_rows(slice).take(units.len()).collect();
        let mut valid = vec![true; data_units];
        for &unit in units {
            valid[unit as usize] = false;
        }
        valid.extend((0..chunks.rows).map(|row| chunks.is_intact(row, slice)));
        let decoder = match decoders.entry(valid) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let decoder = Rar5RsCoder::new_decoder(
                    data_units,
                    usize::from(geometry.parity_units),
                    entry.key(),
                )
                .ok_or_else(|| RarError::internal("no RAR5 decoder for the intact chunks"))?;
                entry.insert(decoder)
            }
        };

        let len = geometry.slice_len(slice) as usize;
        let mut input = vec![0u8; len];
        let mut rebuilt = vec![vec![0u8; len]; units.len()];
        let mut next = 0;
        for unit in 0..u64::from(geometry.data_units) {
            if units.get(next) == Some(&unit) {
                let parity = self.chunk_at(rows[next], slice) + geometry.header_size;
                read_exact_at(volume, parity, &mut input)?;
                next += 1;
            } else {
                self.read_unit_slice(volume, unit, slice, &mut input)?;
            }
            let mut outputs: Vec<&mut [u8]> = rebuilt.iter_mut().map(Vec::as_mut_slice).collect();
            decoder.update_outputs(unit as usize, &input, &mut outputs);
        }

        for (mut bytes, &unit) in rebuilt.into_iter().zip(units) {
            bytes.truncate(geometry.unit_slice_len(unit, slice) as usize);
            if slice_crc(&bytes) == crcs[unit as usize] {
                out.patches.push(RecoveryRecordPatch {
                    unit,
                    offset: unit * geometry.unit_size + slice * SLICE,
                    bytes,
                });
            } else {
                out.assessment.unrepairable_units.push(unit);
            }
        }
        Ok(())
    }

    /// Read one slice of a data unit, zeros past the unit's end.
    fn read_unit_slice<R: Read + Seek>(
        &self,
        volume: &mut R,
        unit: u64,
        slice: u64,
        into: &mut [u8],
    ) -> RarResult<()> {
        let have = self.geometry.unit_slice_len(unit, slice) as usize;
        let at = unit * self.geometry.unit_size + slice * SLICE;
        read_exact_at(volume, at, &mut into[..have])?;
        into[have..].fill(0);
        Ok(())
    }
}

/// Find the record from one intact chunk: the one the main header's
/// locator leads to, else the chunk nearest the end of the volume that
/// places a record where it can be.
pub(super) fn locate<R: Read + Seek>(volume: &mut R, len: u64) -> RarResult<Option<Record>> {
    let mut buf = Vec::new();
    if let Some((header_offset, data_offset)) = locator(volume)
        && let Some(chunk) = read_chunk(volume, len, data_offset, &mut buf)?
        && chunk.row == 0
        && chunk.slice == 0
        && chunk.geometry.protected_size == header_offset
        && let Some(record) = Record::place(chunk.geometry, data_offset, len, false)
    {
        return Ok(Some(record));
    }
    scan_back(volume, len, &MAGIC, |volume, pos, head| {
        let Some(size) = plausible(head, pos, len) else {
            return Ok(Probe::Skip);
        };
        let record = read_whole_chunk(volume, pos, size, &mut buf)?.and_then(|chunk| {
            let offset = chunk
                .geometry
                .chunk_offset(u64::from(chunk.row), chunk.slice);
            Record::place(chunk.geometry, pos.checked_sub(offset)?, len, true)
        });
        Ok(record.map_or(Probe::Reject, Probe::Found))
    })
}

/// The offsets of the `RR` header and of its data area, when the main
/// header's locator points at an `RR` service header.
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

/// The chunk at `pos`, when there is one ending by `limit`.
fn read_chunk<R: Read + Seek>(
    volume: &mut R,
    limit: u64,
    pos: u64,
    buf: &mut Vec<u8>,
) -> RarResult<Option<Chunk>> {
    if pos
        .checked_add(FIXED_LEN as u64)
        .is_none_or(|end| end > limit)
    {
        return Ok(None);
    }
    let mut head = [0u8; FIXED_LEN];
    read_exact_at(volume, pos, &mut head)?;
    match plausible(&head, pos, limit) {
        Some(size) => read_whole_chunk(volume, pos, size, buf),
        None => Ok(None),
    }
}

fn read_whole_chunk<R: Read + Seek>(
    volume: &mut R,
    pos: u64,
    size: usize,
    buf: &mut Vec<u8>,
) -> RarResult<Option<Chunk>> {
    buf.resize(size, 0);
    read_exact_at(volume, pos, buf)?;
    Ok(parse_chunk(buf))
}

/// The size of the chunk whose first bytes are `head`, when its mark and
/// sizes are those of a chunk ending by `limit`. Costs no read.
fn plausible(head: &[u8], pos: u64, limit: u64) -> Option<usize> {
    if head.len() < FIXED_LEN || head[..4] != MAGIC {
        return None;
    }
    let chunk_size = u64::from(u32_at(head, 0x0c));
    let header_size = u64::from(u32_at(head, 0x10));
    let data_units = u64::from(u16_at(head, 0x3a));
    ((1..=MAX_DATA_UNITS).contains(&data_units)
        && header_size == FIXED_LEN as u64 + 8 * data_units + 8
        && chunk_size > header_size
        && chunk_size - header_size <= SLICE
        && pos.checked_add(chunk_size).is_some_and(|end| end <= limit))
    .then_some(chunk_size as usize)
}

/// Parse one whole chunk whose sizes [`plausible`] has checked: its CRC64
/// and a geometry RAR would write.
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
        || protected_size == 0
        || unit_size != protected_size.div_ceil(nd).next_multiple_of(2)
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
    if protected_size <= (nd - 1).checked_mul(unit_size)? {
        return None;
    }
    let crcs = &chunk[FIXED_LEN..FIXED_LEN + 8 * nd as usize];
    let id_at = FIXED_LEN + 8 * nd as usize;
    Some(Chunk {
        geometry: Geometry {
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

/// The CRC64 the record keeps for a slice of a data unit: the CRC-64/XZ
/// polynomial and reflection, but a zero initial value and no final xor.
fn slice_crc(bytes: &[u8]) -> u64 {
    let mut digest = Digest::new_with_init_state(CrcAlgorithm::Crc64Xz, 0);
    digest.update(bytes);
    // `Digest` applies CRC-64/XZ's final xor, which this CRC does not have.
    digest.finalize() ^ u64::MAX
}

/// A chunk's CRC64: CRC-64/XZ.
fn chunk_crc(bytes: &[u8]) -> u64 {
    crc_fast::checksum(CrcAlgorithm::Crc64Xz, bytes)
}

/// The record RAR would write for the volume's bytes `0..P` with this
/// geometry: every chunk header, every data unit CRC64 and every parity
/// byte computed from the protected bytes. The random record id is the one
/// field copied. The tests compare this with the record RAR wrote, byte
/// for byte.
#[cfg(test)]
fn recompute_record<R: Read + Seek>(volume: &mut R, geometry: &Geometry) -> RarResult<Vec<u8>> {
    let nd = usize::from(geometry.data_units);
    let nr = usize::from(geometry.parity_units);
    let unit_size = geometry.unit_size as usize;
    let encoder = Rar5RsCoder::new_encoder(nd, nr).expect("parse_chunk bounds the geometry");
    let slices = geometry.slices();
    let mut parity = vec![vec![0u8; unit_size]; nr];
    // Per slice, the CRC64 of that slice of every data unit; a slice past a
    // unit's end is empty and hashes to zero.
    let mut crcs = vec![Vec::with_capacity(nd); slices as usize];
    let mut unit = vec![0u8; unit_size];
    volume.seek(SeekFrom::Start(0))?;
    for d in 0..nd {
        let len = geometry.unit_len(d as u64) as usize;
        volume.read_exact(&mut unit[..len])?;
        unit[len..].fill(0);
        for (slice, crcs) in crcs.iter_mut().enumerate() {
            let from = (slice * SLICE as usize).min(len);
            let to = ((slice + 1) * SLICE as usize).min(len);
            crcs.push(slice_crc(&unit[from..to]));
        }
        let mut outputs: Vec<&mut [u8]> = parity.iter_mut().map(Vec::as_mut_slice).collect();
        encoder.update_outputs(d, &unit, &mut outputs);
    }

    let header_size = (FIXED_LEN + 8 * nd + 8) as u64;
    let row_size = slices * header_size + geometry.unit_size;
    let last = geometry.unit_len(nd as u64 - 1);
    let mut out = Vec::with_capacity((u64::from(geometry.parity_units) * row_size) as usize);
    for (k, row) in parity.iter().enumerate() {
        for slice in 0..slices {
            let offset = slice * SLICE;
            let len = geometry.slice_len(slice);
            let start = out.len();
            out.extend_from_slice(&MAGIC);
            out.extend_from_slice(&[0u8; 8]);
            out.extend_from_slice(&((header_size + len) as u32).to_le_bytes());
            out.extend_from_slice(&(header_size as u32).to_le_bytes());
            out.extend_from_slice(&[1, 1]);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(SLICE.min(last.wrapping_sub(offset)) as u32).to_le_bytes());
            out.extend_from_slice(&geometry.protected_size.to_le_bytes());
            out.extend_from_slice(&geometry.unit_size.to_le_bytes());
            out.extend_from_slice(&row_size.to_le_bytes());
            out.extend_from_slice(&geometry.data_units.to_le_bytes());
            out.extend_from_slice(&geometry.parity_units.to_le_bytes());
            out.extend_from_slice(&(k as u16).to_le_bytes());
            for crc in &crcs[slice as usize] {
                out.extend_from_slice(&crc.to_le_bytes());
            }
            out.extend_from_slice(&geometry.record_id);
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

    use super::super::record::test_support::{fixture, noise, scratch_dir};
    use super::*;
    use crate::recovery::{
        RecoveryRecordAssessment, RecoveryRecordRepair, assess_recovery_record,
        locate_recovery_record, repair_from_recovery_record,
    };

    const SCRATCH: &str = "RR5_SCRATCH_DIR";

    /// A slice CRC64 the slow way: the CRC-64/XZ polynomial, reflected,
    /// from a zero register and without a final xor.
    fn reference_slice_crc(bytes: &[u8]) -> u64 {
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

    const FIXTURES: [&str; 7] = [
        "rar5_recovery.rar",
        "rar5_mv_store_rr.part1.rar",
        "rar5_mv_store_rr.part2.rar",
        "rar5_mv_store_rr.part3.rar",
        "rar5_mv_store_rr.part4.rar",
        "rar5_mv_store_rr.part5.rar",
        "rar5_mv_store_rr.part6.rar",
    ];

    fn rar5(name: &str) -> Vec<u8> {
        fixture("rar5", name)
    }

    /// The geometry RAR chooses for `P` protected bytes at `percent`: as
    /// many data units of about 1 KiB as fit, at most 200, and `percent` of
    /// them as parity, at least one.
    fn expected_geometry(protected: u64, percent: u64) -> (u16, u64, u16) {
        let nd = protected.div_ceil(1024).clamp(1, MAX_DATA_UNITS);
        let unit = protected.div_ceil(nd).next_multiple_of(2);
        let nr = (nd * percent / 100).max(1);
        (nd as u16, unit, nr as u16)
    }

    fn record(bytes: &[u8]) -> Record {
        locate(&mut Cursor::new(bytes), bytes.len() as u64)
            .unwrap()
            .expect("a record")
    }

    fn layout(bytes: &[u8]) -> RecoveryRecordLayout {
        locate_recovery_record(&mut Cursor::new(bytes), None)
            .unwrap()
            .expect("a record")
    }

    fn stored<'a>(bytes: &'a [u8], record: &Record) -> &'a [u8] {
        &bytes[record.start as usize..record.end() as usize]
    }

    fn recomputed(bytes: &[u8], record: &Record) -> Vec<u8> {
        recompute_record(&mut Cursor::new(bytes), &record.geometry).unwrap()
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

    fn assess(bytes: &[u8]) -> RecoveryRecordAssessment {
        assess_recovery_record(&mut Cursor::new(bytes), None)
            .unwrap()
            .expect("a record")
    }

    /// The repair and the repaired copy it writes, which writing the repair
    /// into the volume itself must give too.
    fn repaired(bytes: &[u8]) -> (RecoveryRecordRepair, Vec<u8>) {
        let repair = repair_from_recovery_record(&mut Cursor::new(bytes), None)
            .unwrap()
            .expect("a record");
        let mut copy = Vec::new();
        repair
            .write_repaired_copy(&mut Cursor::new(bytes), &mut copy)
            .unwrap();
        let mut in_place = Cursor::new(bytes.to_vec());
        repair.write_in_place(&mut in_place).unwrap();
        assert!(
            in_place.into_inner() == copy,
            "in place differs from the copy"
        );
        (repair, copy)
    }

    fn refused(bytes: &[u8]) -> Vec<u64> {
        match repair_from_recovery_record(&mut Cursor::new(bytes), None) {
            Err(RarError::RecoveryRecordInsufficient { units, .. }) => units,
            other => panic!("{other:?}"),
        }
    }

    #[derive(Clone, Copy)]
    enum Damage {
        Zero,
        Noise,
        /// Flip the low bit of every byte.
        Flip,
    }

    fn damaged(bytes: &[u8], ranges: &[(u64, u64)], how: Damage) -> Vec<u8> {
        let mut copy = bytes.to_vec();
        for (i, &(from, len)) in ranges.iter().enumerate() {
            let range = &mut copy[from as usize..(from + len) as usize];
            match how {
                Damage::Zero => range.fill(0),
                Damage::Noise => range.copy_from_slice(&noise(i as u64 + 1, len as usize)),
                Damage::Flip => range.iter_mut().for_each(|b| *b ^= 1),
            }
        }
        copy
    }

    /// `(offset, len)` of a whole data unit.
    fn unit_range(layout: &RecoveryRecordLayout, unit: u64) -> (u64, u64) {
        let range = layout.unit_range(unit);
        (range.start, range.end - range.start)
    }

    #[test]
    fn slice_crc_is_zero_init_without_final_xor_and_chunk_crc_is_crc64_xz() {
        let samples: [&[u8]; 4] = [b"", b"123456789", &[0u8; 1000], &noise(7, 70_001)];
        for sample in samples {
            assert_eq!(slice_crc(sample), reference_slice_crc(sample));
        }
        assert_eq!(chunk_crc(b"123456789"), 0x995D_C9BB_DF19_39FA);
        // The two differ: a zero register and no xor against CRC-64/XZ.
        assert_ne!(reference_slice_crc(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn fixture_records_recompute_byte_for_byte() {
        for name in FIXTURES {
            let bytes = rar5(name);
            let record = record(&bytes);
            assert!(!record.found_by_scan, "{name}: locator");
            let geometry = &record.geometry;
            assert_eq!(geometry.marker, [1, 1], "{name}");
            let percent = percent_from_headers(&bytes).expect("RR percent in the service header");
            assert_eq!(
                (
                    geometry.data_units,
                    geometry.unit_size,
                    geometry.parity_units
                ),
                expected_geometry(geometry.protected_size, percent),
                "{name}: geometry for P={} at {percent}%",
                geometry.protected_size
            );
            let stored = stored(&bytes, &record);
            let ours = recomputed(&bytes, &record);
            assert_eq!(ours.len(), stored.len(), "{name}: record length");
            assert_eq!(
                first_difference(&ours, stored),
                None,
                "{name}: first differing byte"
            );
            // After the record: the 8-byte end of archive header, then only
            // the zero padding a `-v` volume gets up to its size.
            let after = record.end() as usize;
            assert_eq!(bytes[after + 4..after + 7], [3, 5, 4], "{name}: end header");
            assert!(
                bytes[after + 8..].iter().all(|&b| b == 0),
                "{name}: padding"
            );
            let assessment = assess(&bytes);
            assert!(assessment.is_intact(), "{name}: {assessment:?}");
            assert_eq!(assessment.layout, record.layout());
        }
    }

    #[test]
    fn fixture_geometry_is_what_rar_chose() {
        let bytes = rar5("rar5_recovery.rar");
        let single = layout(&bytes);
        assert_eq!((single.data_units, single.parity_units), (1, 1));
        assert_eq!(record(&bytes).geometry.slices(), 1);
        assert_eq!((single.protected_size, single.record_offset), (154, 177));
        assert_eq!(single.record_size, 0x50 + 154);
        // `-rr5p -v4k`: 2869 protected bytes in a 4096-byte volume give three
        // 958-byte units and one parity unit, since 5% of 3 rounds to none.
        let part1 = layout(&rar5("rar5_mv_store_rr.part1.rar"));
        assert_eq!((part1.data_units, part1.parity_units), (3, 1));
        assert_eq!(part1.unit_size, 958);
        assert_eq!((part1.protected_size, part1.record_offset), (2869, 2892));
        let part6 = layout(&rar5("rar5_mv_store_rr.part6.rar"));
        assert_eq!((part6.protected_size, part6.unit_size), (2584, 862));
    }

    #[test]
    fn repairs_one_damaged_unit_anywhere_in_a_fixture() {
        let original = rar5("rar5_mv_store_rr.part3.rar");
        let layout = layout(&original);
        assert_eq!(layout.parity_units, 1);
        for unit in 0..layout.data_units {
            for how in [Damage::Zero, Damage::Noise] {
                let (from, len) = unit_range(&layout, unit);
                // Part of the unit, never the whole, so the CRC must notice.
                let hurt = damaged(&original, &[(from + 3, len / 2)], how);
                let assessment = assess(&hurt);
                assert_eq!(assessment.damaged_units, [unit]);
                assert!(assessment.damaged_parity.is_empty());
                assert!(assessment.is_repairable());
                let (repair, fixed) = repaired(&hurt);
                assert_eq!(repair.patches.len(), 1);
                assert_eq!(repair.patches[0].offset, from);
                assert!(fixed == original, "unit {unit}");
            }
        }
    }

    #[test]
    fn repairs_a_damaged_signature_and_main_header() {
        let original = rar5("rar5_mv_store_rr.part1.rar");
        let hurt = damaged(&original, &[(0, 40)], Damage::Noise);
        let assessment = assess(&hurt);
        assert!(assessment.layout.found_by_scan);
        assert_eq!(assessment.damaged_units, [0]);
        assert!(repaired(&hurt).1 == original);
    }

    #[test]
    fn repairs_the_whole_protected_range_of_a_one_unit_record() {
        let original = rar5("rar5_recovery.rar");
        let layout = layout(&original);
        let hurt = damaged(&original, &[(0, layout.protected_size)], Damage::Zero);
        let (repair, fixed) = repaired(&hurt);
        assert_eq!(repair.assessment.damaged_units, [0]);
        assert!(fixed == original);
    }

    #[test]
    fn over_capacity_damage_is_refused() {
        let original = rar5("rar5_mv_store_rr.part2.rar");
        let layout = layout(&original);
        let (a, _) = unit_range(&layout, 0);
        let (b, _) = unit_range(&layout, 2);
        let hurt = damaged(&original, &[(a + 1, 8), (b + 1, 8)], Damage::Noise);
        let assessment = assess(&hurt);
        assert_eq!(assessment.damaged_units, [0, 2]);
        assert_eq!(assessment.unrepairable_units, [0, 2]);
        assert!(!assessment.is_repairable());
        assert_eq!(refused(&hurt), [0, 2]);
    }

    #[test]
    fn a_record_whose_only_chunk_is_damaged_is_no_record() {
        let original = rar5("rar5_mv_store_rr.part4.rar");
        let layout = layout(&original);
        // Inside the parity bytes of the only chunk.
        let hurt = damaged(
            &original,
            &[(layout.record_offset + 0x60, 4)],
            Damage::Noise,
        );
        let mut cursor = Cursor::new(&hurt);
        assert_eq!(locate_recovery_record(&mut cursor, None).unwrap(), None);
        assert_eq!(assess_recovery_record(&mut cursor, None).unwrap(), None);
    }

    #[test]
    fn damage_after_the_record_is_outside_its_reach() {
        let original = rar5("rar5_mv_store_rr.part5.rar");
        let layout = layout(&original);
        let end = layout.record_range().end;
        let hurt = damaged(&original, &[(end + 1, 2)], Damage::Noise);
        assert!(assess(&hurt).is_intact());
        let (repair, fixed) = repaired(&hurt);
        assert!(repair.patches.is_empty());
        assert!(fixed == hurt);
    }

    #[test]
    fn a_damaged_rr_header_is_bridged_by_the_backward_scan() {
        let original = rar5("rar5_mv_store_rr.part6.rar");
        let layout = layout(&original);
        let gap = layout.record_offset - layout.protected_size;
        let hurt = damaged(&original, &[(layout.protected_size, gap)], Damage::Noise);
        let assessment = assess(&hurt);
        assert!(assessment.layout.found_by_scan);
        assert!(assessment.is_intact());
        assert_eq!(assessment.layout.record_offset, layout.record_offset);
    }

    /// A CRC-valid chunk of another record after the end of the volume,
    /// with the `RR` header damaged so the backward scan meets the foreign
    /// chunk first: it cannot sit there, so the scan passes it and finds
    /// the volume's own record.
    #[test]
    fn a_foreign_chunk_after_the_record_does_not_stop_the_scan() {
        let original = rar5("rar5_mv_store_rr.part1.rar");
        let other = rar5("rar5_recovery.rar");
        let other_record = record(&other);
        let mut hurt = original.clone();
        hurt[2869..2892].fill(0x55);
        hurt.extend_from_slice(stored(&other, &other_record));
        let layout = layout(&hurt);
        assert!(layout.found_by_scan);
        assert_eq!(layout.record_offset, 2892);
    }

    // Everything below reads RARLAB-written scratch archives from the
    // directory `RR5_SCRATCH_DIR` names and does nothing without it, so the
    // committed suite stays fixture-only. With `RR5_ORACLE_DIR` set as well,
    // damaged copies and our repairs are written there for `rar r`.

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
        let Some(dir) = scratch_dir(SCRATCH) else {
            eprintln!("{SCRATCH} unset: skipped");
            return;
        };
        let mut failures = Vec::new();
        let mut seen = 0;
        for path in scratch_archives(&dir) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).unwrap();
            let Some(record) = locate(&mut Cursor::new(&bytes), bytes.len() as u64).unwrap() else {
                failures.push(format!("{name}: no record"));
                continue;
            };
            seen += 1;
            let geometry = &record.geometry;
            let encrypted_headers = name.contains("_hp");
            let percent = percent_from_name(&name);
            let header_percent = percent_from_headers(&bytes);
            let stored = stored(&bytes, &record);
            let ours = recomputed(&bytes, &record);
            let diff = first_difference(&ours, stored);
            let exact = ours.len() == stored.len() && diff.is_none();
            let assessment = assess(&bytes);
            let tail = bytes.len() as u64 - record.end();
            eprintln!(
                "{name}: P={} ND={} U={} NR={} slices={} record=[{}, {}) tail={tail} scan={} marker={:?} rr%={percent} hdr%={header_percent:?} exact={exact}",
                geometry.protected_size,
                geometry.data_units,
                geometry.unit_size,
                geometry.parity_units,
                geometry.slices(),
                record.start,
                record.end(),
                record.found_by_scan,
                geometry.marker,
            );
            if !exact {
                failures.push(format!(
                    "{name}: recompute differs, lengths {} vs {}, first at {diff:?}",
                    ours.len(),
                    stored.len()
                ));
            }
            let expected = expected_geometry(geometry.protected_size, percent);
            if (
                geometry.data_units,
                geometry.unit_size,
                geometry.parity_units,
            ) != expected
            {
                failures.push(format!(
                    "{name}: geometry (ND,U,NR)=({},{},{}) expected {expected:?} for P={} at {percent}%",
                    geometry.data_units,
                    geometry.unit_size,
                    geometry.parity_units,
                    geometry.protected_size
                ));
            }
            // Only `-hp`, whose main header is encrypted, needs the scan.
            if record.found_by_scan != encrypted_headers {
                failures.push(format!("{name}: found by scan {}", record.found_by_scan));
            }
            if !encrypted_headers && header_percent != Some(percent) {
                failures.push(format!("{name}: header percent {header_percent:?}"));
            }
            if geometry.marker != [1, 1] {
                failures.push(format!("{name}: marker {:?}", geometry.marker));
            }
            if !assessment.is_intact() {
                failures.push(format!("{name}: {assessment:?}"));
            }
            // An 8-byte end header, or a 32-byte encrypted one with `-hp`,
            // then only a `-v` volume's zero padding.
            let end_header = if encrypted_headers { 32 } else { 8 };
            let after = (record.end() + end_header) as usize;
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
        ranges: fn(&RecoveryRecordLayout) -> Vec<(u64, u64)>,
        /// Units the assessment must report damaged.
        units: fn(&RecoveryRecordLayout) -> Vec<u64>,
        /// Whether a repair must give back the original.
        repairable: bool,
        /// Whether a record chunk is damaged.
        record_hit: bool,
    }

    impl Case {
        /// Whether the damage reaches past `P`: the `RR` header, the record
        /// or the end of archive block, which a repair leaves as they are.
        fn hits_unprotected(&self, layout: &RecoveryRecordLayout) -> bool {
            (self.ranges)(layout)
                .iter()
                .any(|&(from, len)| from + len > layout.protected_size)
        }
    }

    /// The middle third of each unit.
    fn thirds(layout: &RecoveryRecordLayout, units: &[u64]) -> Vec<(u64, u64)> {
        units
            .iter()
            .map(|&u| {
                let (from, len) = unit_range(layout, u);
                (from + len / 3, len / 3)
            })
            .collect()
    }

    /// Some parity bytes of the chunk of parity unit `row` and slice
    /// `slice`.
    fn chunk_range(layout: &RecoveryRecordLayout, row: u64, slice: u64) -> (u64, u64) {
        let header = 0x48 + 8 * layout.data_units;
        let slice_len = SLICE.min(layout.unit_size - slice * SLICE);
        let row_size = layout.unit_size.div_ceil(SLICE) * header + layout.unit_size;
        let at = layout.record_offset + row * row_size + slice * (header + SLICE) + header;
        (at + 16, slice_len.min(64))
    }

    const CASES: &[Case] = &[
        Case {
            name: "zero_3_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Zero,
            ranges: |l| thirds(l, &[5, 77, 150]),
            units: |_| vec![5, 77, 150],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "noise_capacity_10_units",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| thirds(l, &[0, 1, 30, 31, 32, 99, 120, 160, 198, 199]),
            units: |_| vec![0, 1, 30, 31, 32, 99, 120, 160, 198, 199],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "noise_11_units_over_capacity",
            archive: "out/v720_1m_rr5p.rar",
            how: Damage::Noise,
            ranges: |l| thirds(l, &[0, 1, 30, 31, 32, 99, 120, 160, 190, 198, 199]),
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
                let mut r = thirds(l, &[2, 3, 4, 5, 6, 7, 8, 9, 10]);
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
                let mut r = thirds(l, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
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
                let mut r = thirds(l, &[40, 41]);
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
            ranges: |l| thirds(l, &[0, 50]),
            units: |_| vec![0, 50],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "p_3_units",
            archive: "out2/v624_p_100k_rr5p.rar",
            how: Damage::Zero,
            ranges: |l| thirds(l, &[10, 11, 97]),
            units: |_| vec![10, 11, 97],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "mv_part2_1_unit",
            archive: "out2/v720_mv3m_rr5p.part2.rar",
            how: Damage::Noise,
            ranges: |l| thirds(l, &[100]),
            units: |_| vec![100],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "sfx_2_units",
            archive: "out2/v720_sfx_100k_rr5p.sfx",
            how: Damage::Noise,
            ranges: |l| thirds(l, &[0, 199]),
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
                    (l.unit_size * 17 + SLICE - 100, 300),
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
                let mut r = thirds(l, &[0, 60, 61, 62, 199]);
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
            ranges: |l| thirds(l, &[3, 4, 5, 100, 101, 199]),
            units: |_| vec![3, 4, 5, 100, 101, 199],
            repairable: true,
            record_hit: false,
        },
        Case {
            name: "wrap_13m_2_units",
            archive: "out2/v720_13m_rr1.rar",
            how: Damage::Noise,
            ranges: |l| thirds(l, &[0, 199]),
            units: |_| vec![0, 199],
            repairable: true,
            record_hit: false,
        },
        // Two parity units, two slices per unit: units 5 and 6 damaged in
        // the first slice and unit 7 in the second. Three damaged units in
        // all, but no slice has more than its two parity chunks rebuild.
        Case {
            name: "wrap_13m_independent_slices",
            archive: "out2/v720_13m_rr1.rar",
            how: Damage::Flip,
            ranges: |l| {
                vec![
                    (5 * l.unit_size + 10, 1),
                    (6 * l.unit_size + 10, 1),
                    (7 * l.unit_size + SLICE, 1),
                ]
            },
            units: |_| vec![5, 6, 7],
            repairable: true,
            record_hit: false,
        },
    ];

    #[test]
    fn scratch_damage_cases_repair_to_the_original_up_to_capacity() {
        let Some(dir) = scratch_dir(SCRATCH) else {
            eprintln!("{SCRATCH} unset: skipped");
            return;
        };
        let oracle = std::env::var_os("RR5_ORACLE_DIR").map(PathBuf::from);
        if let Some(oracle) = &oracle {
            fs::create_dir_all(oracle).unwrap();
        }
        let mut failures = Vec::new();
        for case in CASES {
            let original = fs::read(dir.join(case.archive)).unwrap();
            let layout = layout(&original);
            let hurt = damaged(&original, &(case.ranges)(&layout), case.how);
            let assessment = assess(&hurt);
            let mut problems = Vec::new();
            if assessment.damaged_units != (case.units)(&layout) {
                problems.push(format!("damaged units {:?}", assessment.damaged_units));
            }
            if assessment.damaged_parity.is_empty() == case.record_hit {
                problems.push(format!("damaged parity {:?}", assessment.damaged_parity));
            }
            if assessment.is_repairable() != case.repairable {
                problems.push(format!("is_repairable {}", assessment.is_repairable()));
            }
            let mut out = Vec::new();
            match repair_from_recovery_record(&mut Cursor::new(&hurt), None) {
                Ok(Some(repair)) if case.repairable => {
                    repair
                        .write_repaired_copy(&mut Cursor::new(&hurt), &mut out)
                        .unwrap();
                    let mut want = original.clone();
                    if case.hits_unprotected(&layout) {
                        // Protected bytes from the original, the rest as damaged.
                        let p = layout.protected_size as usize;
                        want[p..].copy_from_slice(&hurt[p..]);
                    }
                    if out != want {
                        problems.push(format!(
                            "repair differs at {:?}",
                            first_difference(&out, &want)
                        ));
                    }
                }
                Ok(Some(_)) => problems.push("repaired over capacity".into()),
                Err(RarError::RecoveryRecordInsufficient { units, .. }) if !case.repairable => {
                    eprintln!("{}: refused, units {units:?}", case.name);
                }
                other => problems.push(format!("repair gave {other:?}")),
            }
            eprintln!(
                "{}: units {:?} parity {:?} repairable {} -> {}",
                case.name,
                assessment.damaged_units,
                assessment.damaged_parity,
                assessment.is_repairable(),
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
