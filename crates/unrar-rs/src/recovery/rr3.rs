//! The RAR 2.9-4.x in-archive recovery record: the `RR` service block that
//! `rar a -rr` (and `rar rr`) appends to a RAR3 volume so `rar r` can put
//! damaged 512-byte sectors back.
//!
//! Everything here was worked out from the bytes RARLAB's `rar` writes;
//! reference UnRAR only names the block (`SUBHEAD_TYPE_RR`) and never reads
//! its payload. The layout, as every record this crate has seen states it:
//!
//! ```text
//! protected bytes   [0 .. RR header)                N = ceil(len / 512) sectors
//! RR header         RAR3 NEWSUB (0x7A) file header, name "RR", sub-data:
//!                     "Protect+"  u32 LE recovery_sectors  u64 LE total_blocks
//! RR data area      total_blocks x u16 LE   sector checksum
//!                   recovery_sectors x 512  parity sector
//! ```
//!
//! A sector's checksum is the low 16 bits of the CRC32 register RAR keeps
//! while hashing the sector (`CRC32(0xFFFFFFFF, sector, 512)` in RARLAB's
//! idiom, that is the IEEE CRC32 *before* its final inversion). The last
//! sector is padded with zeros to 512 bytes for the checksum and the parity.
//! Parity sector `k` is the XOR of every protected sector `i` with
//! `i % recovery_sectors == k`, so a slot repairs one lost sector, and the
//! checksums say which sector that is.
//!
//! The record protects every byte of the file before its own header, an SFX
//! stub included (the first sector is the first 512 bytes of the file, not
//! of the signature). The header, the
//! data area and whatever follows (the end-of-archive header) are outside it.
//! An archive whose headers are encrypted (`-hp`) carries the same record, in
//! the clear, after an encrypted RR header; locating it then needs the
//! password, as it does for `rar r`.
//!
//! This crate repairs from the record; it never writes or alters one.

use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;

use crate::error::{RarError, RarResult};
use crate::rar4::header::{
    RawRar4Header, parse_file_header, rar4_header_crc16, read_raw_header,
    read_raw_header_encrypted, skip_forward,
};
use crate::rar4::types::{Rar4HeaderType, archive_flags};
use crate::types::ArchiveFormat;

/// The protected unit: RAR hashes and XORs the archive in 512-byte sectors.
pub const RR3_SECTOR_SIZE: usize = 512;
/// The mark that opens the RR header's sub-data.
pub const RR3_MARK: [u8; 8] = *b"Protect+";
/// The service name of the record's header.
pub const RR3_SERVICE_NAME: &str = "RR";
/// Sub-data length: mark, `u32` recovery sectors, `u64` total blocks.
const RR3_SUBDATA_LEN: usize = 8 + 4 + 8;
/// The bytes a scan looks for: the service name then the mark, which sit
/// together in every RR header this crate has seen.
const RR3_SCAN_NEEDLE: &[u8; 10] = b"RRProtect+";
/// A scan reads the volume in windows this large (plus the overlap).
const RR3_SCAN_WINDOW: usize = 1 << 20;
/// Read the protected range in chunks of this many sectors.
const RR3_CHUNK_SECTORS: usize = 256;

/// A located RAR3 recovery record: where its header, data and protected
/// range sit in the volume and what the header states.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rr3Record {
    /// Where the RAR3 signature starts (past any SFX stub).
    pub signature_offset: u64,
    /// Where the RR header starts. With encrypted headers, where its salt
    /// starts.
    pub header_offset: u64,
    /// The header's size as stored (the plaintext size for `-hp`).
    pub header_size: u16,
    /// The header's RAR3 file-header flags.
    pub header_flags: u16,
    /// The header's `FileCRC` field, carried and never checked: it is not the
    /// CRC32 of the data area, the checksum list, the parity, the protected
    /// range, the sub-data or the header, nor of any contiguous byte range of
    /// the archive file under any seed or inversion convention (the ignored
    /// `crc_hunt` test swept them all with no hit). RARLAB tooling does not
    /// appear to check it either: `rar r` and `rar t` behave the same on
    /// damaged copies whether or not the record's sectors were touched.
    pub header_file_crc: u32,
    /// The header's `FileTime` field (DOS format).
    pub header_file_time: u32,
    /// The header's `UnpVer`, `Method`, `HostOS` and `FileAttr` fields.
    pub header_unpack_version: u8,
    pub header_method: u8,
    pub header_host_os: u8,
    pub header_attributes: u32,
    /// The header's unpacked-size field.
    pub header_unpacked_size: u64,
    /// Where the data area (checksums then parity) starts.
    pub data_offset: u64,
    /// The data area's size as the header's packed size states it.
    pub data_size: u64,
    /// How many parity sectors the record holds.
    pub recovery_sectors: u32,
    /// How many protected sectors the record covers, as the header states.
    pub total_blocks: u64,
    /// The main header's flags (for `VOLUME`, `RECOVERY`, `ENCRYPTED_HEADERS`).
    pub main_flags: u16,
    /// Whether the archive's headers are encrypted (`-hp`).
    pub headers_encrypted: bool,
    /// Where the end-of-archive header starts, when the walk reached one.
    pub end_header_offset: Option<u64>,
    /// How the record was located.
    pub located_by: Rr3Located,
}

/// How a record was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rr3Located {
    /// By walking the headers from the signature.
    HeaderWalk,
    /// By scanning the bytes for the header, as `rar r` does when the
    /// headers before it are damaged.
    Scan,
}

impl Rr3Record {
    /// The protected bytes: from the start of the file (an SFX stub
    /// included) to the RR header.
    pub fn protected_range(&self) -> Range<u64> {
        0..self.header_offset
    }

    /// How many bytes the record protects.
    pub fn protected_len(&self) -> u64 {
        self.header_offset
    }

    /// How many sectors the protected range spans, from its length.
    pub fn sector_count(&self) -> u64 {
        self.protected_len().div_ceil(RR3_SECTOR_SIZE as u64)
    }

    /// The bytes of the record: header through data area.
    pub fn record_range(&self) -> Range<u64> {
        self.header_offset..self.data_offset + self.data_size
    }

    /// Where the checksum list starts.
    pub fn checksums_offset(&self) -> u64 {
        self.data_offset
    }

    /// Where the parity sectors start.
    pub fn parity_offset(&self) -> u64 {
        self.data_offset + 2 * self.total_blocks
    }

    /// The data area size the stated counts imply.
    pub fn expected_data_size(&self) -> u64 {
        2 * self.total_blocks + u64::from(self.recovery_sectors) * RR3_SECTOR_SIZE as u64
    }

    /// Whether the header's counts agree with the protected range and the
    /// data area size.
    pub fn is_consistent(&self) -> bool {
        self.recovery_sectors > 0
            && self.total_blocks == self.sector_count()
            && self.data_size == self.expected_data_size()
    }

    /// The absolute byte range of protected sector `index` (the last one is
    /// shorter than a sector).
    pub fn sector_range(&self, index: u64) -> Range<u64> {
        let start = index * RR3_SECTOR_SIZE as u64;
        start..(start + RR3_SECTOR_SIZE as u64).min(self.header_offset)
    }

    /// Which parity slot protected sector `index` folds into.
    pub fn slot_of(&self, index: u64) -> u64 {
        index % u64::from(self.recovery_sectors.max(1))
    }

    /// The absolute byte range of parity sector `slot`.
    pub fn parity_range(&self, slot: u64) -> Range<u64> {
        let start = self.parity_offset() + slot * RR3_SECTOR_SIZE as u64;
        start..start + RR3_SECTOR_SIZE as u64
    }

    /// The bytes a verifier needs in memory: the checksum list.
    pub fn verify_memory(&self) -> u64 {
        2 * self.total_blocks + RR3_SECTOR_SIZE as u64
    }

    /// The bytes a repairer needs in memory beyond the checksum list, when
    /// `slots` slots each lost one sector: one accumulator per slot.
    pub fn repair_memory(&self, slots: u64) -> u64 {
        self.verify_memory() + slots * 2 * RR3_SECTOR_SIZE as u64
    }
}

/// The checksum the record stores for one sector: the low 16 bits of the
/// CRC32 register (IEEE CRC32 before the final inversion). A sector shorter
/// than 512 bytes is hashed as if zero-padded to 512.
pub fn rr3_sector_checksum(sector: &[u8]) -> u16 {
    let raw = if sector.len() >= RR3_SECTOR_SIZE {
        !crate::crc::hash(&sector[..RR3_SECTOR_SIZE])
    } else {
        let mut padded = [0u8; RR3_SECTOR_SIZE];
        padded[..sector.len()].copy_from_slice(sector);
        !crate::crc::hash(&padded)
    };
    raw as u16
}

/// The header fields an RR service header carries, read from a parsed
/// NEWSUB header; `None` when it is not an RR header.
fn rr3_from_header(
    raw: &RawRar4Header,
    header_offset: u64,
    data_offset: u64,
) -> RarResult<Option<Rr3Fields>> {
    if raw.header_type != Rar4HeaderType::NewSub {
        return Ok(None);
    }
    let header = parse_file_header(raw)?;
    if header.name != RR3_SERVICE_NAME {
        return Ok(None);
    }
    let Some(sub) = header.service_subdata.as_deref() else {
        return Err(RarError::corrupt("RAR3 RR header carries no sub-data"));
    };
    if sub.len() < RR3_SUBDATA_LEN {
        return Err(RarError::corrupt(format!(
            "RAR3 RR header sub-data is {} bytes, expected {RR3_SUBDATA_LEN}",
            sub.len()
        )));
    }
    if sub[..8] != RR3_MARK {
        return Err(RarError::corrupt(format!(
            "RAR3 RR header mark is {:02x?}, expected {RR3_MARK:02x?}",
            &sub[..8]
        )));
    }
    let recovery_sectors = u32::from_le_bytes(sub[8..12].try_into().unwrap());
    let total_blocks = u64::from_le_bytes(sub[12..20].try_into().unwrap());
    let host_os = raw.data[15];
    let unpack_version = raw.data[24];
    let method = raw.data[25];
    Ok(Some(Rr3Fields {
        header_offset,
        header_size: raw.header_size,
        header_flags: raw.flags,
        header_file_crc: header.crc32,
        header_file_time: header.mtime,
        header_unpack_version: unpack_version,
        header_method: method,
        header_host_os: host_os,
        header_attributes: header.attributes,
        header_unpacked_size: header.unpacked_size.unwrap_or(u64::MAX),
        data_offset,
        data_size: header.packed_size,
        recovery_sectors,
        total_blocks,
    }))
}

/// What one RR header states, before the walk adds the archive context.
struct Rr3Fields {
    header_offset: u64,
    header_size: u16,
    header_flags: u16,
    header_file_crc: u32,
    header_file_time: u32,
    header_unpack_version: u8,
    header_method: u8,
    header_host_os: u8,
    header_attributes: u32,
    header_unpacked_size: u64,
    data_offset: u64,
    data_size: u64,
    recovery_sectors: u32,
    total_blocks: u64,
}

impl Rr3Fields {
    fn into_record(
        self,
        signature_offset: u64,
        main_flags: u16,
        headers_encrypted: bool,
        end_header_offset: Option<u64>,
        located_by: Rr3Located,
    ) -> Rr3Record {
        Rr3Record {
            signature_offset,
            header_offset: self.header_offset,
            header_size: self.header_size,
            header_flags: self.header_flags,
            header_file_crc: self.header_file_crc,
            header_file_time: self.header_file_time,
            header_unpack_version: self.header_unpack_version,
            header_method: self.header_method,
            header_host_os: self.header_host_os,
            header_attributes: self.header_attributes,
            header_unpacked_size: self.header_unpacked_size,
            data_offset: self.data_offset,
            data_size: self.data_size,
            recovery_sectors: self.recovery_sectors,
            total_blocks: self.total_blocks,
            main_flags,
            headers_encrypted,
            end_header_offset,
            located_by,
        }
    }
}

/// Locate the recovery record of one RAR3 volume by walking its headers
/// from the signature, as `rar r` does first. `None` when the volume has no
/// record. An archive with encrypted headers needs `password`; without it
/// the walk cannot read past the main header and reports
/// [`RarError::EncryptedArchive`].
///
/// The walk reads the signature, the main header and every header up to the
/// RR header, seeking past each data area, so it touches one header per
/// member: on a stored single-member archive that is three small reads and
/// one seek. A volume whose headers before the record are damaged makes the
/// walk fail; [`scan_rr3_record`] then finds the record by its bytes.
pub fn locate_rr3_record<R: Read + Seek>(
    reader: &mut R,
    password: Option<&str>,
) -> RarResult<Option<Rr3Record>> {
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    if crate::signature::read_signature(reader)? != ArchiveFormat::Rar4 {
        return Err(RarError::corrupt(
            "RAR3 recovery record: not a RAR 2.9-4.x archive",
        ));
    }
    let signature_offset = reader.stream_position().map_err(RarError::from)? - 7;

    let Some(main) = read_raw_header(reader)? else {
        return Err(RarError::corrupt("RAR3 recovery record: no main header"));
    };
    if main.header_type != Rar4HeaderType::Archive {
        return Err(RarError::corrupt(
            "RAR3 recovery record: the first header is not the main header",
        ));
    }
    let main_flags = main.flags;
    skip_forward(reader, main.data_area_size)?;

    if main_flags & archive_flags::ENCRYPTED_HEADERS != 0 {
        let Some(password) = password else {
            return Err(RarError::EncryptedArchive);
        };
        return locate_encrypted(reader, password, signature_offset, main_flags);
    }

    loop {
        let header_offset = reader.stream_position().map_err(RarError::from)?;
        let Some(raw) = read_raw_header(reader)? else {
            return Ok(None);
        };
        if rar4_header_crc16(&raw.data) != u16::from_le_bytes([raw.data[0], raw.data[1]]) {
            return Err(RarError::corrupt(format!(
                "RAR3 header at offset {header_offset} fails its CRC16"
            )));
        }
        let data_offset = header_offset + u64::from(raw.header_size);
        match raw.header_type {
            Rar4HeaderType::EndArchive => return Ok(None),
            Rar4HeaderType::File | Rar4HeaderType::NewSub => {
                if let Some(fields) = rr3_from_header(&raw, header_offset, data_offset)? {
                    let end = data_offset + fields.data_size;
                    let end_header_offset = end_header_at(reader, end)?;
                    return Ok(Some(fields.into_record(
                        signature_offset,
                        main_flags,
                        false,
                        end_header_offset,
                        Rr3Located::HeaderWalk,
                    )));
                }
                let header = parse_file_header(&raw)?;
                skip_forward(reader, header.packed_size)?;
            }
            _ => {
                skip_forward(reader, raw.data_area_size)?;
            }
        }
    }
}

/// Whether an end-of-archive header starts at `offset`, for the record's
/// `end_header_offset`; it is not required.
fn end_header_at<R: Read + Seek>(reader: &mut R, offset: u64) -> RarResult<Option<u64>> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(RarError::from)?;
    let mut common = [0u8; 7];
    if reader.read_exact(&mut common).is_err() {
        return Ok(None);
    }
    Ok((common[2] == 0x7B).then_some(offset))
}

/// The encrypted-header walk: each header is its own 8-byte salt followed
/// by the AES-CBC ciphertext of the header, padded to 16 bytes.
fn locate_encrypted<R: Read + Seek>(
    reader: &mut R,
    password: &str,
    signature_offset: u64,
    main_flags: u16,
) -> RarResult<Option<Rr3Record>> {
    let kdf = crate::crypto::KdfCache::new();
    loop {
        let header_offset = reader.stream_position().map_err(RarError::from)?;
        let mut salt = [0u8; 8];
        match reader.read_exact(&mut salt) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(RarError::from(e)),
        }
        let (key, iv) = kdf.derive_key_rar4(password, Some(&salt));
        let mut decryptor = crate::crypto::Rar4CbcDecryptor::new(&key, &iv);
        let Some(raw) = read_raw_header_encrypted(reader, &mut decryptor)? else {
            return Ok(None);
        };
        let data_offset = reader.stream_position().map_err(RarError::from)?;
        match raw.header_type {
            Rar4HeaderType::EndArchive => return Ok(None),
            Rar4HeaderType::File | Rar4HeaderType::NewSub => {
                if let Some(fields) = rr3_from_header(&raw, header_offset, data_offset)? {
                    let end = data_offset + fields.data_size;
                    // The end header is encrypted too: only say where it would
                    // start, when bytes follow the record.
                    let len = reader.seek(SeekFrom::End(0)).map_err(RarError::from)?;
                    let end_header_offset = (len > end).then_some(end);
                    return Ok(Some(fields.into_record(
                        signature_offset,
                        main_flags,
                        true,
                        end_header_offset,
                        Rr3Located::HeaderWalk,
                    )));
                }
                let header = parse_file_header(&raw)?;
                skip_forward(reader, header.packed_size)?;
            }
            _ => {
                skip_forward(reader, raw.data_area_size)?;
            }
        }
    }
}

/// Find the record by scanning the volume's bytes for its header, for a
/// volume whose headers before the record are damaged (the search `rar r`
/// falls back to). Only a plaintext RR header is found this way; an
/// encrypted one (`-hp`) has no bytes to look for. The header must pass its
/// own CRC16. The signature is located first (the start of the protected
/// range); `None` when no record is found.
///
/// The scan reads the whole volume once, in 1 MiB windows.
pub fn scan_rr3_record<R: Read + Seek>(reader: &mut R) -> RarResult<Option<Rr3Record>> {
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    let signature_offset = match crate::signature::read_signature(reader) {
        Ok(ArchiveFormat::Rar4) => reader.stream_position().map_err(RarError::from)? - 7,
        Ok(_) => {
            return Err(RarError::corrupt(
                "RAR3 recovery record: not a RAR 2.9-4.x archive",
            ));
        }
        // A damaged signature: assume the archive starts at 0, as rar does.
        Err(RarError::InvalidSignature) => 0,
        Err(e) => return Err(e),
    };
    let main_flags = main_flags_at(reader, signature_offset)?;
    let len = reader.seek(SeekFrom::End(0)).map_err(RarError::from)?;
    let overlap = 64;
    let mut window = vec![0u8; RR3_SCAN_WINDOW + overlap];
    let mut carried = 0usize;
    // Scan from the start of the file, not the signature: with one slot
    // the parity sector is a copy of sector 0, signature included, and a
    // damaged sector 0 makes that copy the first signature found.
    let mut window_start = 0u64;
    reader
        .seek(SeekFrom::Start(window_start))
        .map_err(RarError::from)?;
    loop {
        let got = read_up_to(reader, &mut window[carried..])?;
        let filled = carried + got;
        if filled < RR3_SCAN_NEEDLE.len() {
            return Ok(None);
        }
        let mut search = 0usize;
        while let Some(found) = window[search..filled]
            .windows(RR3_SCAN_NEEDLE.len())
            .position(|w| w == RR3_SCAN_NEEDLE)
        {
            let name_at = search + found;
            // The name sits 32 bytes into the header, or 40 with LARGE.
            for name_offset in [32usize, 40] {
                let Some(header_at) = name_at.checked_sub(name_offset) else {
                    continue;
                };
                let absolute = window_start + header_at as u64;
                if let Some(record) =
                    record_at(reader, absolute, signature_offset, main_flags, len)?
                {
                    return Ok(Some(record));
                }
            }
            search = name_at + 1;
        }
        if got == 0 {
            return Ok(None);
        }
        // Keep the tail so a needle across the window boundary is seen.
        let keep = filled.min(overlap);
        window.copy_within(filled - keep..filled, 0);
        window_start += (filled - keep) as u64;
        carried = keep;
        reader
            .seek(SeekFrom::Start(window_start + carried as u64))
            .map_err(RarError::from)?;
    }
}

/// The main header's flags at `signature_offset + 7`, or 0 when it cannot
/// be read (the scan does not depend on it).
fn main_flags_at<R: Read + Seek>(reader: &mut R, signature_offset: u64) -> RarResult<u16> {
    reader
        .seek(SeekFrom::Start(signature_offset + 7))
        .map_err(RarError::from)?;
    let mut common = [0u8; 7];
    if reader.read_exact(&mut common).is_err() || common[2] != 0x73 {
        return Ok(0);
    }
    Ok(u16::from_le_bytes([common[3], common[4]]))
}

fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> RarResult<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(RarError::from(e)),
        }
    }
    Ok(filled)
}

/// Try to read an RR header at `offset`; `None` when the bytes there are
/// not a CRC-valid RR header.
fn record_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    signature_offset: u64,
    main_flags: u16,
    len: u64,
) -> RarResult<Option<Rr3Record>> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(RarError::from)?;
    let raw = match read_raw_header(reader) {
        Ok(Some(raw)) => raw,
        Ok(None) | Err(_) => return Ok(None),
    };
    if raw.header_type != Rar4HeaderType::NewSub
        || rar4_header_crc16(&raw.data) != u16::from_le_bytes([raw.data[0], raw.data[1]])
    {
        return Ok(None);
    }
    let data_offset = offset + u64::from(raw.header_size);
    let Some(fields) = rr3_from_header(&raw, offset, data_offset).ok().flatten() else {
        return Ok(None);
    };
    let end = data_offset + fields.data_size;
    let end_header_offset = if end < len {
        end_header_at(reader, end)?
    } else {
        None
    };
    // A signature found at or past the header is a copy inside the record
    // (one slot's parity is sector 0 itself): the real one is damaged, and
    // the archive starts at 0.
    let signature_offset = if signature_offset < offset {
        signature_offset
    } else {
        0
    };
    Ok(Some(fields.into_record(
        signature_offset,
        main_flags,
        false,
        end_header_offset,
        Rr3Located::Scan,
    )))
}

/// Call `f` with every protected sector in order, each padded with zeros to
/// 512 bytes, and its index.
fn for_each_sector<R: Read + Seek>(
    reader: &mut R,
    record: &Rr3Record,
    mut f: impl FnMut(u64, &[u8; RR3_SECTOR_SIZE]) -> RarResult<()>,
) -> RarResult<()> {
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    let total = record.protected_len();
    let mut buf = vec![0u8; RR3_CHUNK_SECTORS * RR3_SECTOR_SIZE];
    let mut done = 0u64;
    let mut index = 0u64;
    while done < total {
        let want = ((total - done).min(buf.len() as u64)) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(|e| RarError::corrupt(format!("RAR3 protected range short: {e}")))?;
        let whole = want / RR3_SECTOR_SIZE;
        for sector in buf[..whole * RR3_SECTOR_SIZE].chunks_exact(RR3_SECTOR_SIZE) {
            f(index, sector.try_into().unwrap())?;
            index += 1;
        }
        let rest = want - whole * RR3_SECTOR_SIZE;
        if rest > 0 {
            let mut last = [0u8; RR3_SECTOR_SIZE];
            last[..rest].copy_from_slice(&buf[whole * RR3_SECTOR_SIZE..want]);
            f(index, &last)?;
            index += 1;
        }
        done += want as u64;
    }
    Ok(())
}

/// Recompute the record's whole data area (checksum list then parity) from
/// the protected bytes, as RAR wrote it. Comparing the result with the
/// stored data area is the byte-exact check of the format. Memory: the
/// whole data area.
pub fn compute_rr3_data<R: Read + Seek>(reader: &mut R, record: &Rr3Record) -> RarResult<Vec<u8>> {
    let slots = record.recovery_sectors as usize;
    if slots == 0 {
        return Err(RarError::corrupt(
            "RAR3 recovery record states zero recovery sectors",
        ));
    }
    let sectors = record.sector_count() as usize;
    let mut out = vec![0u8; 2 * sectors + slots * RR3_SECTOR_SIZE];
    let (checksums, parity) = out.split_at_mut(2 * sectors);
    for_each_sector(reader, record, |index, sector| {
        let i = index as usize;
        checksums[2 * i..2 * i + 2].copy_from_slice(&rr3_sector_checksum(sector).to_le_bytes());
        let slot = i % slots;
        let acc = &mut parity[slot * RR3_SECTOR_SIZE..(slot + 1) * RR3_SECTOR_SIZE];
        xor_into(acc, sector);
        Ok(())
    })?;
    Ok(out)
}

/// Read the stored data area.
pub fn read_rr3_data<R: Read + Seek>(reader: &mut R, record: &Rr3Record) -> RarResult<Vec<u8>> {
    reader
        .seek(SeekFrom::Start(record.data_offset))
        .map_err(RarError::from)?;
    let mut data = vec![0u8; record.data_size as usize];
    reader
        .read_exact(&mut data)
        .map_err(|e| RarError::corrupt(format!("RAR3 recovery record data short: {e}")))?;
    Ok(data)
}

fn xor_into(acc: &mut [u8], sector: &[u8]) {
    for (a, s) in acc.iter_mut().zip(sector) {
        *a ^= s;
    }
}

/// One protected sector whose stored checksum does not match its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rr3DamagedSector {
    /// The sector's index in the protected range.
    pub index: u64,
    /// Its absolute byte range in the volume.
    pub range: Range<u64>,
    /// The parity slot it folds into.
    pub slot: u64,
    /// The checksum the record stores for it.
    pub stored: u16,
    /// The checksum its bytes give now.
    pub actual: u16,
}

/// What a record says about its volume: which protected sectors fail their
/// checksum, grouped by what the parity can do about them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rr3Assessment {
    /// Every sector whose checksum fails, in order.
    pub damaged: Vec<Rr3DamagedSector>,
    /// Parity slots whose stored sector does not equal the XOR of their
    /// intact data sectors, among slots with no damaged data sector: the
    /// parity itself is damaged there. Empty when `parity_checked` is false.
    pub parity_damaged: Vec<u64>,
    /// Whether the parity sectors were checked (it costs one accumulator
    /// per slot).
    pub parity_checked: bool,
}

impl Rr3Assessment {
    /// Whether every protected sector and every checked parity sector is
    /// intact.
    pub fn is_intact(&self) -> bool {
        self.damaged.is_empty() && self.parity_damaged.is_empty()
    }

    /// The damaged sectors the parity can restore: alone in their slot.
    pub fn recoverable(&self) -> Vec<&Rr3DamagedSector> {
        self.damaged
            .iter()
            .filter(|d| self.slot_damage_count(d.slot) == 1)
            .collect()
    }

    /// The damaged sectors the parity cannot restore: two or more share a
    /// slot.
    pub fn unrecoverable(&self) -> Vec<&Rr3DamagedSector> {
        self.damaged
            .iter()
            .filter(|d| self.slot_damage_count(d.slot) > 1)
            .collect()
    }

    fn slot_damage_count(&self, slot: u64) -> usize {
        self.damaged.iter().filter(|d| d.slot == slot).count()
    }
}

/// Check every protected sector against the record's checksum list, and,
/// when `check_parity`, every parity sector whose data sectors are all
/// intact. Memory: the checksum list, plus one 512-byte accumulator per
/// recovery sector when `check_parity`. The protected range is read once.
pub fn assess_rr3<R: Read + Seek>(
    reader: &mut R,
    record: &Rr3Record,
    check_parity: bool,
) -> RarResult<Rr3Assessment> {
    if !record.is_consistent() {
        return Err(RarError::corrupt(format!(
            "RAR3 recovery record is inconsistent: {} sectors of {} protected bytes, {} recovery sectors, {} data bytes",
            record.total_blocks,
            record.protected_len(),
            record.recovery_sectors,
            record.data_size
        )));
    }
    let checksums = read_checksums(reader, record)?;
    let slots = record.recovery_sectors as usize;
    let mut acc = if check_parity {
        vec![0u8; slots * RR3_SECTOR_SIZE]
    } else {
        Vec::new()
    };
    let mut damaged = Vec::new();
    for_each_sector(reader, record, |index, sector| {
        let actual = rr3_sector_checksum(sector);
        let stored = checksums[index as usize];
        if actual != stored {
            damaged.push(Rr3DamagedSector {
                index,
                range: record.sector_range(index),
                slot: record.slot_of(index),
                stored,
                actual,
            });
        }
        if check_parity {
            let slot = index as usize % slots;
            xor_into(
                &mut acc[slot * RR3_SECTOR_SIZE..(slot + 1) * RR3_SECTOR_SIZE],
                sector,
            );
        }
        Ok(())
    })?;
    let mut parity_damaged = Vec::new();
    if check_parity {
        reader
            .seek(SeekFrom::Start(record.parity_offset()))
            .map_err(RarError::from)?;
        let mut stored = [0u8; RR3_SECTOR_SIZE];
        for slot in 0..slots {
            reader
                .read_exact(&mut stored)
                .map_err(|e| RarError::corrupt(format!("RAR3 parity short: {e}")))?;
            let clean = !damaged.iter().any(|d| d.slot == slot as u64);
            if clean && stored[..] != acc[slot * RR3_SECTOR_SIZE..(slot + 1) * RR3_SECTOR_SIZE] {
                parity_damaged.push(slot as u64);
            }
        }
    }
    Ok(Rr3Assessment {
        damaged,
        parity_damaged,
        parity_checked: check_parity,
    })
}

fn read_checksums<R: Read + Seek>(reader: &mut R, record: &Rr3Record) -> RarResult<Vec<u16>> {
    reader
        .seek(SeekFrom::Start(record.checksums_offset()))
        .map_err(RarError::from)?;
    let mut raw = vec![0u8; 2 * record.total_blocks as usize];
    reader
        .read_exact(&mut raw)
        .map_err(|e| RarError::corrupt(format!("RAR3 checksum list short: {e}")))?;
    Ok(raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// What a repair did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rr3RepairReport {
    /// The assessment the repair worked from.
    pub assessment: Rr3Assessment,
    /// Sectors rebuilt from parity whose rebuilt bytes match the stored
    /// checksum, in order.
    pub repaired: Vec<u64>,
    /// Sectors alone in their slot whose rebuilt bytes still fail the stored
    /// checksum: the parity sector, another sector of the slot or the
    /// checksum entry is also wrong. They are written as they were.
    pub rebuilt_mismatch: Vec<u64>,
    /// Sectors sharing a slot with another damaged sector, written as they
    /// were.
    pub unrecoverable: Vec<u64>,
    /// How many bytes were written: the whole input.
    pub bytes_written: u64,
}

impl Rr3RepairReport {
    /// Whether every damaged sector was repaired.
    pub fn is_complete(&self) -> bool {
        self.rebuilt_mismatch.is_empty() && self.unrecoverable.is_empty()
    }
}

/// Repair a volume from its record: copy the whole input to `writer`, with
/// every damaged sector that is alone in its parity slot replaced by the
/// XOR of its parity sector and the slot's other sectors. A rebuilt sector
/// is written only when it then matches its stored checksum; everything
/// else (an unrecoverable sector, the record, the end header) is copied
/// as it is, which is what `rar r` does too. Memory: the checksum list and
/// one accumulator per slot being rebuilt. The input is read three times:
/// to assess, to accumulate, to copy.
pub fn repair_rr3<R: Read + Seek, W: Write>(
    reader: &mut R,
    record: &Rr3Record,
    writer: &mut W,
) -> RarResult<Rr3RepairReport> {
    let assessment = assess_rr3(reader, record, false)?;
    let checksums = read_checksums(reader, record)?;
    let recoverable: Vec<u64> = assessment.recoverable().iter().map(|d| d.index).collect();
    let unrecoverable: Vec<u64> = assessment.unrecoverable().iter().map(|d| d.index).collect();

    // One accumulator per slot being rebuilt, seeded with its parity.
    let mut rebuilt: Vec<(u64, u64, [u8; RR3_SECTOR_SIZE])> = Vec::new();
    for &index in &recoverable {
        let slot = record.slot_of(index);
        reader
            .seek(SeekFrom::Start(record.parity_range(slot).start))
            .map_err(RarError::from)?;
        let mut acc = [0u8; RR3_SECTOR_SIZE];
        reader
            .read_exact(&mut acc)
            .map_err(|e| RarError::corrupt(format!("RAR3 parity short: {e}")))?;
        rebuilt.push((index, slot, acc));
    }
    if !rebuilt.is_empty() {
        for_each_sector(reader, record, |index, sector| {
            let slot = record.slot_of(index);
            if let Some(entry) = rebuilt
                .iter_mut()
                .find(|(target, s, _)| *s == slot && *target != index)
            {
                xor_into(&mut entry.2, sector);
            }
            Ok(())
        })?;
    }
    let mut repaired = Vec::new();
    let mut rebuilt_mismatch = Vec::new();
    let mut replacements: Vec<(u64, [u8; RR3_SECTOR_SIZE])> = Vec::new();
    for (index, _, acc) in rebuilt {
        if rr3_sector_checksum(&acc) == checksums[index as usize] {
            repaired.push(index);
            replacements.push((index, acc));
        } else {
            rebuilt_mismatch.push(index);
        }
    }

    // Copy everything, substituting the rebuilt sectors.
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    let len = reader.seek(SeekFrom::End(0)).map_err(RarError::from)?;
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    let mut buf = vec![0u8; RR3_CHUNK_SECTORS * RR3_SECTOR_SIZE];
    let mut pos = 0u64;
    let mut next = 0usize;
    replacements.sort_by_key(|(index, _)| *index);
    while pos < len {
        let want = ((len - pos).min(buf.len() as u64)) as usize;
        reader
            .read_exact(&mut buf[..want])
            .map_err(RarError::from)?;
        let chunk = pos..pos + want as u64;
        while next < replacements.len() {
            let (index, bytes) = &replacements[next];
            let range = record.sector_range(*index);
            if range.start >= chunk.end {
                break;
            }
            // A sector never straddles a chunk: chunks are sector multiples
            // from offset 0 and sectors start at the signature; an SFX stub
            // breaks that alignment, so clip to the chunk on both sides.
            let lo = range.start.max(chunk.start);
            let hi = range.end.min(chunk.end);
            if lo < hi {
                let src = (lo - range.start) as usize..(hi - range.start) as usize;
                let dst = (lo - chunk.start) as usize..(hi - chunk.start) as usize;
                buf[dst].copy_from_slice(&bytes[src]);
            }
            if range.end <= chunk.end {
                next += 1;
            } else {
                break;
            }
        }
        writer.write_all(&buf[..want]).map_err(RarError::from)?;
        pos += want as u64;
    }
    Ok(Rr3RepairReport {
        assessment,
        repaired,
        rebuilt_mismatch,
        unrecoverable,
        bytes_written: len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar4")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// Every scratch archive under `$UNRAR_RS_RR3_SCRATCH` (the directory
    /// holding `out624/`, `pct624/`, `out720/`), or none when unset.
    fn scratch_archives() -> Vec<PathBuf> {
        let Ok(root) = std::env::var("UNRAR_RS_RR3_SCRATCH") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for dir in ["out624", "pct624", "out720"] {
            let Ok(entries) = std::fs::read_dir(Path::new(&root).join(dir)) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "rar" | "sfx" | "r00" | "r01") {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }

    fn password_for(path: &Path) -> Option<&'static str> {
        path.file_name()
            .and_then(|n| n.to_str())
            .filter(|n| n.contains("_hp"))
            .map(|_| "secret")
    }

    #[test]
    fn fixture_record_recomputes_byte_exact() {
        let bytes = fixture("rar4_recovery.rar");
        let mut cur = Cursor::new(bytes.clone());
        let record = locate_rr3_record(&mut cur, None).unwrap().unwrap();
        assert_eq!(record.signature_offset, 0);
        assert_eq!(record.located_by, Rr3Located::HeaderWalk);
        assert!(record.is_consistent(), "{record:#?}");
        assert_eq!(record.recovery_sectors, 1);
        assert_eq!(record.total_blocks, record.sector_count());
        let stored = read_rr3_data(&mut cur, &record).unwrap();
        let computed = compute_rr3_data(&mut cur, &record).unwrap();
        assert_eq!(stored, computed);
        let scanned = scan_rr3_record(&mut cur).unwrap().unwrap();
        assert_eq!(scanned.header_offset, record.header_offset);
        assert_eq!(scanned.located_by, Rr3Located::Scan);
        let assessment = assess_rr3(&mut cur, &record, true).unwrap();
        assert!(assessment.is_intact(), "{assessment:?}");
    }

    #[test]
    fn scratch_records_recompute_byte_exact() {
        let archives = scratch_archives();
        if archives.is_empty() {
            eprintln!("UNRAR_RS_RR3_SCRATCH unset or empty: skipping");
            return;
        }
        let mut failures = Vec::new();
        for path in &archives {
            let mut file = std::fs::File::open(path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let record = match locate_rr3_record(&mut file, password_for(path)) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    eprintln!("{name}: no record");
                    continue;
                }
                Err(e) => {
                    eprintln!("{name}: locate failed: {e}");
                    failures.push(name);
                    continue;
                }
            };
            let stored = read_rr3_data(&mut file, &record).unwrap();
            let computed = compute_rr3_data(&mut file, &record).unwrap();
            let exact = stored == computed;
            let first_diff = stored.iter().zip(&computed).position(|(a, b)| a != b);
            eprintln!(
                "{name}: sig={} hdr={} data={}+{} rs={} tb={} secs={} consistent={} enc={} end={:?} fcrc={:#010x} ftime={:#010x} unp={} host={} ver={} method={:#x} attr={:#x} flags={:#06x} hsize={} exact={exact} first_diff={first_diff:?}",
                record.signature_offset,
                record.header_offset,
                record.data_offset,
                record.data_size,
                record.recovery_sectors,
                record.total_blocks,
                record.sector_count(),
                record.is_consistent(),
                record.headers_encrypted,
                record.end_header_offset,
                record.header_file_crc,
                record.header_file_time,
                record.header_unpacked_size,
                record.header_host_os,
                record.header_unpack_version,
                record.header_method,
                record.header_attributes,
                record.header_flags,
                record.header_size,
            );
            if !exact || !record.is_consistent() {
                failures.push(name.clone());
            }
            if !record.headers_encrypted {
                let scanned = scan_rr3_record(&mut file).unwrap();
                if scanned.as_ref().map(|r| r.header_offset) != Some(record.header_offset) {
                    eprintln!("{name}: scan disagrees: {scanned:?}");
                    failures.push(name.clone());
                }
            }
            let assessment = assess_rr3(&mut file, &record, true).unwrap();
            if !assessment.is_intact() {
                eprintln!("{name}: not intact: {assessment:?}");
                failures.push(name.clone());
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Hunt for what the RR header's FileCRC field covers.
    #[test]
    fn scratch_file_crc_candidates() {
        let archives = scratch_archives();
        if archives.is_empty() {
            return;
        }
        for path in archives.iter().take(6) {
            let bytes = std::fs::read(path).unwrap();
            let mut cur = Cursor::new(bytes.clone());
            let Ok(Some(record)) = locate_rr3_record(&mut cur, password_for(path)) else {
                continue;
            };
            if record.headers_encrypted {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let target = record.header_file_crc;
            let hdr = &bytes[record.header_offset as usize..record.data_offset as usize];
            let area = &bytes
                [record.data_offset as usize..(record.data_offset + record.data_size) as usize];
            let tb = record.total_blocks as usize;
            let (cks, par) = area.split_at(2 * tb);
            let prot = &bytes[..record.header_offset as usize];
            let mut padded = prot.to_vec();
            padded.resize(tb * RR3_SECTOR_SIZE, 0);
            let mut hdr_zero = hdr.to_vec();
            hdr_zero[16..20].fill(0);
            let mut full32 = Vec::new();
            let mut full32n = Vec::new();
            for s in padded.chunks(RR3_SECTOR_SIZE) {
                let c = crate::crc::hash(s);
                full32.extend_from_slice(&(!c).to_le_bytes());
                full32n.extend_from_slice(&c.to_le_bytes());
            }
            let whole = &bytes[..(record.data_offset + record.data_size) as usize];
            let after = &bytes[(record.data_offset + record.data_size) as usize..];
            let cands: Vec<(&str, Vec<u8>)> = vec![
                ("area", area.to_vec()),
                ("cks", cks.to_vec()),
                ("par", par.to_vec()),
                ("par+cks", [par, cks].concat()),
                ("prot", prot.to_vec()),
                ("padded", padded.clone()),
                ("full32", full32),
                ("full32n", full32n),
                ("hdr", hdr.to_vec()),
                ("hdr[2..]", hdr[2..].to_vec()),
                ("hdr_zero", hdr_zero.clone()),
                ("hdr_zero[2..]", hdr_zero[2..].to_vec()),
                ("hdr+area", [hdr, area].concat()),
                ("hdr_zero+area", [&hdr_zero[..], area].concat()),
                ("sub", hdr[hdr.len() - 20..].to_vec()),
                ("sub+area", [&hdr[hdr.len() - 20..], area].concat()),
                ("whole", whole.to_vec()),
                ("prot+area", [prot, area].concat()),
                ("after", after.to_vec()),
                ("prot+hdr", [prot, hdr].concat()),
                ("all", bytes.clone()),
            ];
            let mut hits = Vec::new();
            for (label, data) in &cands {
                let c = crate::crc::hash(data);
                if c == target {
                    hits.push(format!("{label} std"));
                }
                if !c == target {
                    hits.push(format!("{label} raw"));
                }
                // The RAR idiom seeded with 0 instead of 0xFFFFFFFF.
                let seeded0 = {
                    let mut h = crc_fast::Digest::new_with_init_state(
                        crc_fast::CrcAlgorithm::Crc32IsoHdlc,
                        u64::from(!0u32),
                    );
                    h.update(data);
                    h.finalize() as u32
                };
                if seeded0 == target || !seeded0 == target {
                    hits.push(format!("{label} seed0"));
                }
            }
            eprintln!("{name}: fcrc={target:#010x} hits={hits:?} hdr={}", hex(hdr));
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

#[cfg(test)]
mod repair_tests {
    use super::*;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rar4")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn scratch_root() -> Option<PathBuf> {
        std::env::var("UNRAR_RS_RR3_SCRATCH")
            .ok()
            .map(PathBuf::from)
    }

    /// Deterministic noise for damage: a byte stream from a small LCG.
    fn noise(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    /// Locate by header walk, falling back to the byte scan as `rar r` does.
    fn locate(bytes: &[u8], password: Option<&str>) -> Option<Rr3Record> {
        let mut cur = Cursor::new(bytes.to_vec());
        match locate_rr3_record(&mut cur, password) {
            Ok(Some(r)) => Some(r),
            _ => scan_rr3_record(&mut cur).ok().flatten(),
        }
    }

    fn repair(bytes: &[u8], password: Option<&str>) -> (Vec<u8>, Rr3RepairReport, Rr3Record) {
        let record = locate(bytes, password).expect("record");
        let mut cur = Cursor::new(bytes.to_vec());
        let mut out = Vec::new();
        let report = repair_rr3(&mut cur, &record, &mut out).unwrap();
        (out, report, record)
    }

    /// Damage `sectors` of `original`: zero them or fill them with noise.
    fn damage(original: &[u8], record: &Rr3Record, sectors: &[u64], zero: bool) -> Vec<u8> {
        let mut bytes = original.to_vec();
        for &s in sectors {
            let r = record.sector_range(s);
            let (lo, hi) = (r.start as usize, r.end as usize);
            if zero {
                bytes[lo..hi].fill(0);
            } else {
                bytes[lo..hi].copy_from_slice(&noise(s + 1, hi - lo));
            }
        }
        bytes
    }

    /// The fixture's record protects one partial sector: the 152 bytes
    /// before the RR header, hashed and XORed as if zero-padded to 512.
    #[test]
    fn fixture_repairs_its_single_partial_sector() {
        let original = fixture("rar4_recovery.rar");
        let record = locate(&original, None).unwrap();
        assert_eq!(record.recovery_sectors, 1);
        assert_eq!(record.sector_count(), 1, "{record:?}");
        assert_eq!(record.protected_len(), 152);
        assert_eq!(record.sector_range(0), 0..152);
        for zero in [true, false] {
            let damaged = damage(&original, &record, &[0], zero);
            assert_ne!(damaged, original);
            let (fixed, report, _) = repair(&damaged, None);
            assert_eq!(report.repaired, vec![0], "{report:?}");
            assert!(report.is_complete());
            assert_eq!(fixed, original, "zero={zero}");
        }
        // Damage the end of the partial sector only (the main header and
        // the file header are intact, so the walk still finds the record).
        let mut damaged = original.clone();
        damaged[140..152].fill(0xAA);
        let mut cur = Cursor::new(damaged.clone());
        let walked = locate_rr3_record(&mut cur, None).unwrap().unwrap();
        assert_eq!(walked.located_by, Rr3Located::HeaderWalk);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.repaired, vec![0]);
        assert_eq!(fixed, original);
    }

    #[test]
    fn fixture_sector_zero_is_found_by_scan() {
        let original = fixture("rar4_recovery.rar");
        let record = locate(&original, None).unwrap();
        let damaged = damage(&original, &record, &[0], true);
        let mut cur = Cursor::new(damaged.clone());
        assert!(locate_rr3_record(&mut cur, None).is_err());
        let scanned = scan_rr3_record(&mut cur).unwrap().unwrap();
        assert_eq!(scanned.located_by, Rr3Located::Scan);
        assert_eq!(scanned.header_offset, record.header_offset);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.repaired, vec![0]);
        assert_eq!(fixed, original);
    }

    #[test]
    fn fixture_damaged_checksum_entry_blocks_the_rebuild() {
        let original = fixture("rar4_recovery.rar");
        let record = locate(&original, None).unwrap();
        let mut damaged = damage(&original, &record, &[0], true);
        // The record's only checksum entry is overwritten too: the sector
        // rebuilt from parity cannot be confirmed, so it is left as it is.
        let at = record.checksums_offset() as usize;
        damaged[at..at + 2].copy_from_slice(&[0xFF, 0xFF]);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.rebuilt_mismatch, vec![0]);
        assert!(report.repaired.is_empty());
        assert!(!report.is_complete());
        assert_eq!(fixed, damaged);
    }

    #[test]
    fn fixture_damaged_parity_is_reported_by_assess() {
        let original = fixture("rar4_recovery.rar");
        let record = locate(&original, None).unwrap();
        let mut damaged = original.clone();
        let at = record.parity_range(0).start as usize + 100;
        damaged[at] ^= 0x55;
        let mut cur = Cursor::new(damaged.clone());
        let assessment = assess_rr3(&mut cur, &record, true).unwrap();
        assert!(assessment.damaged.is_empty());
        assert_eq!(assessment.parity_damaged, vec![0]);
        let (fixed, report, _) = repair(&damaged, None);
        assert!(report.repaired.is_empty());
        assert_eq!(fixed, damaged, "the record is never rewritten");
    }

    #[test]
    fn fixture_damage_after_the_record_is_outside_it() {
        let original = fixture("rar4_recovery.rar");
        let record = locate(&original, None).unwrap();
        let end = record.end_header_offset.unwrap() as usize;
        let mut damaged = original.clone();
        damaged[end..].fill(0);
        let mut cur = Cursor::new(damaged.clone());
        let assessment = assess_rr3(&mut cur, &record, true).unwrap();
        assert!(assessment.is_intact());
    }

    /// In-memory damage cases on the scratch `a05_rr10.rar` (587 sectors,
    /// 10 slots): repaired bytes must equal the original up to capacity.
    #[test]
    fn scratch_a05_in_memory_damage_matrix() {
        let Some(root) = scratch_root() else {
            return;
        };
        let original = std::fs::read(root.join("out624/a05_rr10.rar")).unwrap();
        let record = locate(&original, None).unwrap();
        assert_eq!((record.recovery_sectors, record.sector_count()), (10, 587));
        let last = record.sector_count() - 1;
        let cases: Vec<(&str, Vec<u64>, bool)> = vec![
            ("one zero", vec![100], true),
            ("one random", vec![101], false),
            (
                "ten distinct slots",
                vec![3, 77, 150, 261, 344, 412, 455, 508, 529, 586],
                false,
            ),
            ("contiguous ten", (200..210).collect(), true),
            ("first", vec![0], true),
            ("last partial", vec![last], false),
            ("first and last", vec![0, last], false),
            ("middle", vec![293], false),
        ];
        for (name, sectors, zero) in cases {
            let damaged = damage(&original, &record, &sectors, zero);
            let (fixed, report, _) = repair(&damaged, None);
            assert_eq!(report.repaired, sectors, "{name}: {report:?}");
            assert!(report.is_complete(), "{name}");
            assert_eq!(fixed, original, "{name}");
        }
        // Over capacity: two sectors in slot 3, and eleven contiguous.
        let damaged = damage(&original, &record, &[3, 13], true);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.unrecoverable, vec![3, 13]);
        assert_eq!(fixed, damaged);
        let damaged = damage(&original, &record, &(200..211).collect::<Vec<_>>(), true);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.unrecoverable, vec![200, 210]);
        assert_eq!(report.repaired, (201..210).collect::<Vec<_>>());
        let mut expected = original.clone();
        for s in [200u64, 210] {
            let r = record.sector_range(s);
            expected[r.start as usize..r.end as usize].fill(0);
        }
        assert_eq!(fixed, expected);
        // Damage inside the record: a checksum entry, a parity sector.
        let mut damaged = damage(&original, &record, &[60], true);
        let at = (record.checksums_offset() + 120) as usize;
        damaged[at..at + 2].copy_from_slice(&[0xFF, 0xFF]);
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.rebuilt_mismatch, vec![60]);
        assert_eq!(fixed, damaged);
        let mut damaged = damage(&original, &record, &[50], true);
        let at = record.parity_range(0).start as usize;
        damaged[at..at + 64].copy_from_slice(&noise(7, 64));
        let (fixed, report, _) = repair(&damaged, None);
        assert_eq!(report.rebuilt_mismatch, vec![50]);
        assert_eq!(fixed, damaged);
    }

    /// The `-hp` scratch archive: locating needs the password, the data
    /// area is in the clear, and a repair restores the encrypted bytes.
    #[test]
    fn scratch_hp_needs_password_then_repairs() {
        let Some(root) = scratch_root() else {
            return;
        };
        let original = std::fs::read(root.join("out624/a11_hp.rar")).unwrap();
        let mut cur = Cursor::new(original.clone());
        assert!(matches!(
            locate_rr3_record(&mut cur, None),
            Err(RarError::EncryptedArchive)
        ));
        assert!(scan_rr3_record(&mut cur).unwrap().is_none());
        assert!(locate_rr3_record(&mut cur, Some("wrong")).is_err());
        let record = locate_rr3_record(&mut cur, Some("secret"))
            .unwrap()
            .unwrap();
        assert!(record.headers_encrypted);
        let damaged = damage(&original, &record, &[20], true);
        let (fixed, report, _) = repair(&damaged, Some("secret"));
        assert_eq!(report.repaired, vec![20]);
        assert_eq!(fixed, original);
    }

    /// Every `rar r` oracle case under `$UNRAR_RS_RR3_SCRATCH/oracle/<engine>/<case>/`:
    /// where rar wrote `fixed.*`, our repaired copy must be byte-identical
    /// to it; where rar found no record, we must either find none or say
    /// what we did instead.
    #[test]
    fn scratch_oracle_cross_check() {
        let Some(root) = scratch_root() else {
            return;
        };
        let mut failures = Vec::new();
        for engine in ["r624", "r720"] {
            let Ok(dirs) = std::fs::read_dir(root.join("oracle").join(engine)) else {
                continue;
            };
            let mut dirs: Vec<_> = dirs.flatten().map(|e| e.path()).collect();
            dirs.sort();
            for dir in dirs {
                let case = dir.file_name().unwrap().to_string_lossy().into_owned();
                let Some(damaged_path) = std::fs::read_dir(&dir).unwrap().flatten().find_map(|e| {
                    let p = e.path();
                    let n = p.file_name()?.to_str()?.to_owned();
                    (p.is_file() && !n.ends_with(".log")).then_some(p)
                }) else {
                    continue;
                };
                let damaged = std::fs::read(&damaged_path).unwrap();
                let password = damaged_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .filter(|n| n.contains("_hp"))
                    .map(|_| "secret");
                let out_dir = if password.is_some() { "out_pw" } else { "out" };
                let fixed = std::fs::read_dir(dir.join(out_dir))
                    .ok()
                    .and_then(|d| {
                        d.flatten().map(|e| e.path()).find(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| n.starts_with("fixed."))
                        })
                    })
                    .map(|p| std::fs::read(p).unwrap());
                let mut cur = Cursor::new(damaged.clone());
                let walked = locate_rr3_record(&mut cur, password);
                let record = match &walked {
                    Ok(Some(r)) => Some(r.clone()),
                    _ => scan_rr3_record(&mut cur).unwrap(),
                };
                let ours = record.as_ref().map(|record| {
                    let mut cur = Cursor::new(damaged.clone());
                    let mut out = Vec::new();
                    let report = repair_rr3(&mut cur, record, &mut out).unwrap();
                    (out, report)
                });
                let verdict = match (&fixed, &ours) {
                    (Some(fixed), Some((out, report))) => {
                        let same = fixed == out;
                        if !same {
                            failures.push(format!("{engine}/{case}"));
                        }
                        format!(
                            "rar fixed, ours {} (repaired={:?} mismatch={:?} unrecoverable={:?} located={:?})",
                            if same { "IDENTICAL" } else { "DIFFERS" },
                            report.repaired,
                            report.rebuilt_mismatch,
                            report.unrecoverable,
                            record.as_ref().map(|r| r.located_by)
                        )
                    }
                    (None, Some((out, report))) => format!(
                        "rar found no record; ours located by {:?}, repaired={:?} mismatch={:?} unrecoverable={:?}, output {} the input",
                        record.as_ref().map(|r| r.located_by),
                        report.repaired,
                        report.rebuilt_mismatch,
                        report.unrecoverable,
                        if *out == damaged {
                            "equals"
                        } else {
                            "differs from"
                        }
                    ),
                    (Some(_), None) => {
                        failures.push(format!("{engine}/{case}"));
                        format!("rar fixed, ours found no record (walk: {walked:?})")
                    }
                    (None, None) => format!("neither found a record (walk: {walked:?})"),
                };
                eprintln!("{engine}/{case}: {verdict}");
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// Percent-form sector counts: `rs = 2 + floor((S*p/100 - S/250) / 512)`,
    /// capped at `min(total_blocks, 524288)`, with `S` the protected length,
    /// on every `pct624` archive and the percent-form `out624` ones.
    #[test]
    fn scratch_percent_formula() {
        let Some(root) = scratch_root() else {
            return;
        };
        fn expect(s: u64, tb: u64, p: u64) -> u64 {
            let want = (s * p / 100).saturating_sub(s / 250) / 512 + 2;
            want.min(tb).min(524_288)
        }
        let mut checked = 0;
        let mut failures = Vec::new();
        let mut archives: Vec<PathBuf> = Vec::new();
        for dir in ["pct624", "out624"] {
            if let Ok(d) = std::fs::read_dir(root.join(dir)) {
                archives.extend(d.flatten().map(|e| e.path()));
            }
        }
        archives.sort();
        for path in archives {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let stem = name.trim_end_matches(".rar");
            let (percent, absolute): (Option<u64>, Option<u64>) =
                if let Some(p) = stem.rsplit_once("_p").and_then(|(_, p)| p.parse().ok()) {
                    (Some(p), None)
                } else if let Some(n) = stem.rsplit_once("_n").and_then(|(_, n)| n.parse().ok()) {
                    (None, Some(n))
                } else if stem.ends_with("_default") || stem == "a04_rr" {
                    (Some(3), None)
                } else if let Some(n) = stem
                    .rsplit_once("_rr")
                    .and_then(|(_, n)| n.strip_suffix('p').or_else(|| n.strip_suffix("pct")))
                    .and_then(|n| n.parse().ok())
                {
                    (Some(n), None)
                } else if let Some(n) = stem.rsplit_once("_rr").and_then(|(_, n)| n.parse().ok()) {
                    (None, Some(n))
                } else {
                    continue;
                };
            let mut file = std::fs::File::open(&path).unwrap();
            let record = match locate_rr3_record(&mut file, None) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    assert_eq!(absolute, Some(0), "{name}: no record");
                    checked += 1;
                    continue;
                }
                Err(e) => panic!("{name}: {e}"),
            };
            let s = record.protected_len();
            let tb = record.sector_count();
            let want = match (percent, absolute) {
                (Some(p), _) => expect(s, tb, p),
                (_, Some(n)) => n.min(tb).min(524_288),
                _ => unreachable!(),
            };
            if u64::from(record.recovery_sectors) != want {
                failures.push(format!(
                    "{name}: rs={} want={want} (S={s} tb={tb} p={percent:?} n={absolute:?})",
                    record.recovery_sectors
                ));
            }
            checked += 1;
        }
        eprintln!("percent formula checked on {checked} archives");
        assert!(checked > 60);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// Which header types the RAR3 fixtures and scratch archives carry:
    /// does any writer still emit the 0x78 PROTECT block?
    #[test]
    fn header_types_seen_in_rar3_archives() {
        let mut paths: Vec<PathBuf> = Vec::new();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
        if let Ok(d) = std::fs::read_dir(&fixtures) {
            paths.extend(d.flatten().map(|e| e.path()));
        }
        if let Some(root) = scratch_root() {
            for dir in ["out624", "pct624", "out720"] {
                if let Ok(d) = std::fs::read_dir(root.join(dir)) {
                    paths.extend(d.flatten().map(|e| e.path()));
                }
            }
        }
        paths.sort();
        let mut protect = Vec::new();
        let mut rr = Vec::new();
        let mut walked = 0;
        for path in paths {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "rar" | "sfx" | "exe" | "r00" | "r01") {
                continue;
            }
            let Ok(mut file) = std::fs::File::open(&path) else {
                continue;
            };
            if crate::signature::read_signature(&mut file).ok() != Some(ArchiveFormat::Rar4) {
                continue;
            }
            walked += 1;
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let mut first = true;
            while let Ok(Some(raw)) = read_raw_header(&mut file) {
                if first {
                    first = false;
                    if raw.flags & archive_flags::ENCRYPTED_HEADERS != 0 {
                        break;
                    }
                }
                match raw.header_type {
                    Rar4HeaderType::Recovery => protect.push(name.clone()),
                    Rar4HeaderType::NewSub => {
                        if parse_file_header(&raw).is_ok_and(|h| h.name == RR3_SERVICE_NAME) {
                            rr.push(name.clone());
                        }
                        let Ok(h) = parse_file_header(&raw) else {
                            break;
                        };
                        if skip_forward(&mut file, h.packed_size).is_err() {
                            break;
                        }
                    }
                    Rar4HeaderType::EndArchive => break,
                    Rar4HeaderType::File => {
                        let Ok(h) = parse_file_header(&raw) else {
                            break;
                        };
                        if skip_forward(&mut file, h.packed_size).is_err() {
                            break;
                        }
                    }
                    _ => {
                        if skip_forward(&mut file, raw.data_area_size).is_err() {
                            break;
                        }
                    }
                }
            }
        }
        eprintln!(
            "walked {walked} RAR3 archives: {} with an RR service header, {} with a 0x78 PROTECT block: {protect:?}",
            rr.len(),
            protect.len()
        );
        assert!(walked > 0);
        assert!(protect.is_empty(), "0x78 PROTECT seen in {protect:?}");
    }
}

/// What the RR header's `FileCRC` field covers is not known: this hunt
/// checks the CRC32 of every contiguous byte range of a small scratch
/// archive, and of the zero-padded protected buffer followed by the data
/// area, under four conventions (register seeded with 0 or `!0`, with and
/// without the final inversion). It runs only with `UNRAR_RS_RR3_CRC_HUNT`
/// set, in release mode (it is quadratic), and is `#[ignore]`d so a plain
/// test sweep never pays for it. Result on rar 6.24 output (`a01_rr1.rar`,
/// 23 KiB, and `b_bin_n1.rar`, 20 KiB): no range of either file, of the
/// padded protected buffer plus data area, or of the checksum list as 32-bit
/// CRCs matches the field. The field is carried and not checked.
#[cfg(test)]
mod crc_hunt {
    use super::*;
    use std::io::Cursor;

    const POLY: u32 = 0xEDB8_8320;

    fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *slot = c;
        }
        t
    }

    /// Every (start, end, seed, inverted) whose CRC equals `target`.
    fn hunt(bytes: &[u8], target: u32, label: &str) -> Vec<String> {
        let t = table();
        let mut hits = Vec::new();
        for start in 0..bytes.len() {
            for seed in [0u32, !0u32] {
                let mut reg = seed;
                for (end, &b) in bytes.iter().enumerate().skip(start) {
                    reg = t[((reg ^ u32::from(b)) & 0xFF) as usize] ^ (reg >> 8);
                    if reg == target {
                        hits.push(format!("{label}[{start}..{}] seed={seed:#x} raw", end + 1));
                    }
                    if !reg == target {
                        hits.push(format!(
                            "{label}[{start}..{}] seed={seed:#x} inverted",
                            end + 1
                        ));
                    }
                }
            }
        }
        hits
    }

    #[test]
    #[ignore = "quadratic brute force; set UNRAR_RS_RR3_SCRATCH and UNRAR_RS_RR3_CRC_HUNT and run in release mode"]
    fn file_crc_range_hunt() {
        let (Ok(root), Ok(_)) = (
            std::env::var("UNRAR_RS_RR3_SCRATCH"),
            std::env::var("UNRAR_RS_RR3_CRC_HUNT"),
        ) else {
            return;
        };
        for name in ["out624/a01_rr1.rar", "pct624/b_bin_n1.rar"] {
            let bytes = std::fs::read(std::path::Path::new(&root).join(name)).unwrap();
            let mut cur = Cursor::new(bytes.clone());
            let record = locate_rr3_record(&mut cur, None).unwrap().unwrap();
            let target = record.header_file_crc;
            let mut hits = hunt(&bytes, target, "file");
            let mut padded = bytes[..record.header_offset as usize].to_vec();
            padded.resize(record.sector_count() as usize * RR3_SECTOR_SIZE, 0);
            padded.extend_from_slice(
                &bytes
                    [record.data_offset as usize..(record.data_offset + record.data_size) as usize],
            );
            hits.extend(hunt(&padded, target, "padded+area"));
            // The checksum list as 32-bit CRCs, both conventions, then parity.
            for inverted in [false, true] {
                let mut wide = Vec::new();
                for sector in padded[..record.sector_count() as usize * RR3_SECTOR_SIZE]
                    .chunks(RR3_SECTOR_SIZE)
                {
                    let c = crate::crc::hash(sector);
                    wide.extend_from_slice(&if inverted { c } else { !c }.to_le_bytes());
                }
                wide.extend_from_slice(
                    &bytes[record.parity_offset() as usize
                        ..(record.data_offset + record.data_size) as usize],
                );
                hits.extend(hunt(
                    &wide,
                    target,
                    if inverted {
                        "wide32inv+par"
                    } else {
                        "wide32raw+par"
                    },
                ));
            }
            eprintln!("{name}: target={target:#010x} hits={hits:?}");
        }
    }
}
