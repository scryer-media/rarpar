//! The RAR 2.9-4.x recovery record: the `RR` service block that `rar a -rr`
//! (and `rar rr`) appends to a RAR3 volume so `rar r` can put damaged
//! 512-byte sectors back.
//!
//! Everything here was worked out from the bytes RARLAB's `rar` writes;
//! reference UnRAR only names the block (`SUBHEAD_TYPE_RR`) and never reads
//! its payload. The layout, as every record this crate has seen states it:
//!
//! ```text
//! protected bytes   [0 .. RR header)                N = ceil(P / 512) sectors
//! RR header         RAR3 NEWSUB (0x7A) file header, name "RR", sub-data:
//!                     "Protect+"  u32 LE R (parity sectors)  u64 LE N
//! RR data area      N x u16 LE   sector checksum
//!                   R x 512      parity sector
//! ```
//!
//! A sector's checksum is the low 16 bits of the CRC32 register RAR keeps
//! while hashing the sector (`CRC32(0xFFFFFFFF, sector, 512)` in RARLAB's
//! idiom: the IEEE CRC32 before its final inversion). The last sector is
//! padded with zeros to 512 bytes for the checksum and the parity. Parity
//! sector `k` is the XOR of every protected sector `i` with `i % R == k`, so
//! a slot rebuilds one lost sector, and the checksums say which one.
//!
//! The record protects every byte of the file before its own header, an
//! SFX stub included. An archive whose headers are encrypted (`-hp`) carries
//! the same record, in the clear, after an encrypted `RR` header; finding it
//! then needs the password, as it does for `rar r`. The header's `FileCRC`
//! field is not checked: no CRC32 convention over any byte range of the
//! archive gives it, and `rar r` behaves the same whatever it holds.

use std::io::{Read, Seek, SeekFrom};
use std::ops::Range;

use super::record::{
    Examination, Probe, RecoveryRecordLayout, RecoveryRecordPatch, read_exact_at, scan_back,
    xor_into,
};
use super::{Rar3Walk, Rar3WalkStep, rar3_volume_damage};
use crate::error::{RarError, RarResult};
use crate::rar4::header::{
    RawRar4Header, parse_file_header, rar4_header_crc16, read_raw_header,
    read_raw_header_encrypted, skip_forward,
};
use crate::rar4::types::{Rar4HeaderType, archive_flags};
use crate::types::ArchiveFormat;

/// The protected unit: RAR hashes and XORs a volume in 512-byte sectors.
const SECTOR: usize = 512;
const SECTOR_LEN: u64 = SECTOR as u64;
/// The record header's service name.
const NAME: &str = "RR";
/// The mark that opens the record header's sub-data.
const MARK: &[u8; 8] = b"Protect+";
/// What a scan looks for: the service name, which the sub-data follows.
const NEEDLE: &[u8; 10] = b"RRProtect+";
/// Where the service name starts in the record header: 32 bytes in, or 40
/// with 64-bit sizes.
const NAME_OFFSETS: [u64; 2] = [32, 40];
/// Parity slots whose accumulators one pass over the volume holds: 2 MiB.
const WINDOW_SLOTS: u64 = 4096;
/// Sectors read at a time: 1 MiB.
const BLOCK_SECTORS: u64 = 2048;

/// A record whose header is intact and whose counts agree with where it
/// sits, so every offset below is inside the volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    /// Where the `RR` header starts (where its salt starts with `-hp`): the
    /// protected length `P`.
    header_offset: u64,
    /// Where the checksum list starts.
    data_offset: u64,
    /// `N`, protected sectors.
    sectors: u64,
    /// `R`, parity sectors.
    slots: u64,
    found_by_scan: bool,
}

/// What a pass knows of one parity slot.
#[derive(Debug, Clone)]
enum Slot {
    /// Every sector passes its checksum.
    Clean,
    /// One sector fails: its index, stored checksum and bytes.
    One {
        index: u64,
        stored: u16,
        bytes: Box<[u8; SECTOR]>,
    },
    /// Two or more fail.
    Many,
}

impl Record {
    /// The record an `RR` header states, when the header passes its CRC16
    /// and its counts fit where it sits: `N` sectors cover the bytes before
    /// it, at least one parity sector, and a data area of exactly `2N + 512R`
    /// bytes inside the volume.
    fn from_header(
        raw: &RawRar4Header,
        header_offset: u64,
        data_offset: u64,
        len: u64,
        found_by_scan: bool,
    ) -> Option<Self> {
        if raw.header_type != Rar4HeaderType::NewSub
            || raw.data.len() < 2
            || rar4_header_crc16(&raw.data) != u16::from_le_bytes([raw.data[0], raw.data[1]])
        {
            return None;
        }
        let header = parse_file_header(raw).ok()?;
        let sub = header.service_subdata.as_deref()?;
        if header.name != NAME || sub.get(..8)? != MARK.as_slice() {
            return None;
        }
        let slots = u64::from(u32::from_le_bytes(sub.get(8..12)?.try_into().ok()?));
        let sectors = u64::from_le_bytes(sub.get(12..20)?.try_into().ok()?);
        let size = sectors
            .checked_mul(2)?
            .checked_add(slots.checked_mul(SECTOR_LEN)?)?;
        let fits = data_offset.checked_add(size).is_some_and(|end| end <= len);
        (slots > 0
            && sectors > 0
            && sectors == header_offset.div_ceil(SECTOR_LEN)
            && header.packed_size == size
            && header_offset < data_offset
            && fits)
            .then_some(Self {
                header_offset,
                data_offset,
                sectors,
                slots,
                found_by_scan,
            })
    }

    pub(super) fn layout(&self) -> RecoveryRecordLayout {
        RecoveryRecordLayout {
            format: ArchiveFormat::Rar4,
            protected_size: self.header_offset,
            record_offset: self.data_offset,
            record_size: 2 * self.sectors + self.slots * SECTOR_LEN,
            unit_size: SECTOR_LEN,
            data_units: self.sectors,
            parity_units: self.slots,
            found_by_scan: self.found_by_scan,
        }
    }

    fn sector_range(&self, index: u64) -> Range<u64> {
        let start = index * SECTOR_LEN;
        start..(start + SECTOR_LEN).min(self.header_offset)
    }

    fn checksum_at(&self, index: u64) -> u64 {
        self.data_offset + 2 * index
    }

    fn parity_at(&self, slot: u64) -> u64 {
        self.data_offset + 2 * self.sectors + slot * SECTOR_LEN
    }

    pub(super) fn examine<R: Read + Seek>(
        &self,
        volume: &mut R,
        rebuild: bool,
    ) -> RarResult<Examination> {
        self.examine_in_windows(volume, rebuild, WINDOW_SLOTS)
    }

    /// Check the volume `window` parity slots at a time. One window covers
    /// most records, and the pass is then one read of the protected bytes in
    /// order; a record with more slots takes the sectors of each window's
    /// slots round by round, so every sector is still read once.
    fn examine_in_windows<R: Read + Seek>(
        &self,
        volume: &mut R,
        rebuild: bool,
        window: u64,
    ) -> RarResult<Examination> {
        let mut out = Examination::new(self.layout());
        let mut reader = SectorReader::new();
        let mut first = 0;
        while first < self.slots {
            let slots = first..self.slots.min(first + window);
            first = slots.end;
            self.examine_slots(volume, &mut reader, slots, rebuild, &mut out)?;
        }
        Ok(out)
    }

    /// Check the sectors folding into `slots` and those slots' parity. A
    /// slot with one damaged sector rebuilds it as the parity XOR the slot's
    /// intact sectors, which holds only if it then matches its checksum.
    fn examine_slots<R: Read + Seek>(
        &self,
        volume: &mut R,
        reader: &mut SectorReader,
        slots: Range<u64>,
        rebuild: bool,
        out: &mut Examination,
    ) -> RarResult<()> {
        let width = (slots.end - slots.start) as usize;
        let mut acc = vec![0u8; width * SECTOR];
        let mut state = vec![Slot::Clean; width];
        let mut damaged = Vec::new();
        let slot_of = |index: u64| (index % self.slots - slots.start) as usize;
        let mut visit = |index: u64, sector: &[u8; SECTOR], stored: u16| {
            let slot = slot_of(index);
            if sector_checksum(sector) == stored {
                xor_into(&mut acc[slot * SECTOR..][..SECTOR], sector);
                return;
            }
            damaged.push(index);
            state[slot] = match state[slot] {
                Slot::Clean => Slot::One {
                    index,
                    stored,
                    bytes: Box::new(*sector),
                },
                _ => Slot::Many,
            };
        };
        if width as u64 == self.slots {
            reader.for_each(volume, self, 0..self.sectors, &mut visit)?;
        } else {
            let mut round = 0;
            while round < self.sectors {
                let span =
                    (round + slots.start).min(self.sectors)..(round + slots.end).min(self.sectors);
                reader.for_each(volume, self, span, &mut visit)?;
                round += self.slots;
            }
        }

        let mut parity = vec![0u8; width * SECTOR];
        read_exact_at(volume, self.parity_at(slots.start), &mut parity)?;
        let Examination {
            assessment,
            patches,
        } = out;
        let slices = acc
            .chunks_exact_mut(SECTOR)
            .zip(parity.chunks_exact(SECTOR));
        for (slot, (state, (acc, parity))) in state.iter().zip(slices).enumerate() {
            match state {
                Slot::Clean if acc != parity => {
                    assessment.damaged_parity.push(slots.start + slot as u64);
                }
                Slot::Clean | Slot::Many => {}
                Slot::One {
                    index,
                    stored,
                    bytes,
                } => {
                    xor_into(acc, parity);
                    if acc == bytes.as_slice() {
                        // The parity vouches for the bytes: the checksum
                        // entry is what is damaged.
                        assessment.damaged_checksums.push(*index);
                        continue;
                    }
                    assessment.damaged_units.push(*index);
                    if sector_checksum((&*acc).try_into().expect("a sector")) != *stored {
                        assessment.unrepairable_units.push(*index);
                    } else if rebuild {
                        let range = self.sector_range(*index);
                        patches.push(RecoveryRecordPatch {
                            unit: *index,
                            offset: range.start,
                            bytes: acc[..(range.end - range.start) as usize].to_vec(),
                        });
                    }
                }
            }
        }
        for index in damaged {
            if matches!(state[slot_of(index)], Slot::Many) {
                assessment.damaged_units.push(index);
                assessment.unrepairable_units.push(index);
            }
        }
        Ok(())
    }
}

/// Reads protected sectors with the checksums the record keeps for them.
struct SectorReader {
    data: Vec<u8>,
    sums: Vec<u8>,
}

impl SectorReader {
    fn new() -> Self {
        Self {
            data: vec![0; BLOCK_SECTORS as usize * SECTOR],
            sums: vec![0; BLOCK_SECTORS as usize * 2],
        }
    }

    /// Call `visit` with each protected sector of `sectors` in order,
    /// zero-padded to 512 bytes, and its stored checksum.
    fn for_each<R: Read + Seek>(
        &mut self,
        volume: &mut R,
        record: &Record,
        sectors: Range<u64>,
        visit: &mut impl FnMut(u64, &[u8; SECTOR], u16),
    ) -> RarResult<()> {
        let mut index = sectors.start;
        while index < sectors.end {
            let count = (sectors.end - index).min(BLOCK_SECTORS);
            let from = record.sector_range(index).start;
            let to = record.sector_range(index + count - 1).end;
            let data = &mut self.data[..count as usize * SECTOR];
            let have = (to - from) as usize;
            read_exact_at(volume, from, &mut data[..have])?;
            data[have..].fill(0);
            let sums = &mut self.sums[..2 * count as usize];
            read_exact_at(volume, record.checksum_at(index), sums)?;
            for (sector, sum) in data.chunks_exact(SECTOR).zip(sums.chunks_exact(2)) {
                let sector = sector.try_into().expect("a sector");
                visit(index, sector, u16::from_le_bytes([sum[0], sum[1]]));
                index += 1;
            }
        }
        Ok(())
    }
}

/// The checksum the record keeps for a sector, zero-padded to 512 bytes.
fn sector_checksum(sector: &[u8; SECTOR]) -> u16 {
    !crate::crc::hash(sector) as u16
}

/// Find the record: through the headers when they lead to it, else by
/// scanning back from the end of the volume, as `rar r` falls back to.
pub(super) fn locate<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    password: Option<&str>,
) -> RarResult<Option<Record>> {
    match walk(volume, len, password)? {
        Some(found) => Ok(found),
        None => scan(volume, len),
    }
}

/// Walk the headers from the signature to the record. `Some` with what the
/// headers say, the record or that there is none; `None` when they are
/// damaged before the record. Encrypted headers need `password`.
fn walk<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    password: Option<&str>,
) -> RarResult<Option<Option<Record>>> {
    volume.seek(SeekFrom::Start(0))?;
    let mut walk = Rar3Walk::default();
    loop {
        let step = match walk.step(volume) {
            Ok(step) => step,
            Err(error) if rar3_volume_damage(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        match step {
            Rar3WalkStep::Next => {}
            Rar3WalkStep::Service(raw) => {
                let data_offset = raw.offset + u64::from(raw.header_size);
                if let Some(record) = Record::from_header(&raw, raw.offset, data_offset, len, false)
                {
                    return Ok(Some(Some(record)));
                }
            }
            Rar3WalkStep::End(_) => return Ok(Some(None)),
            Rar3WalkStep::Stopped(_)
                if walk
                    .main_flags
                    .is_some_and(|flags| flags & archive_flags::ENCRYPTED_HEADERS != 0) =>
            {
                let password = password.ok_or(RarError::EncryptedArchive)?;
                return walk_encrypted(volume, len, password).map(Some);
            }
            Rar3WalkStep::Stopped(_) => return Ok(None),
        }
    }
}

/// The walk past an encrypted main header, from where the reader stands:
/// each header is its own 8-byte salt and the AES-CBC ciphertext of the
/// header, padded to 16 bytes. Only the first header can say the password
/// is wrong; a later one that fails its CRC is damaged, and no scan sees an
/// encrypted header, so the record is then not found.
fn walk_encrypted<R: Read + Seek>(
    volume: &mut R,
    len: u64,
    password: &str,
) -> RarResult<Option<Record>> {
    let kdf = crate::crypto::KdfCache::new();
    let mut first = true;
    loop {
        let header_offset = volume.stream_position()?;
        let mut salt = [0u8; 8];
        if let Err(error) = volume.read_exact(&mut salt) {
            return match error.kind() {
                std::io::ErrorKind::UnexpectedEof => Ok(None),
                _ => Err(error.into()),
            };
        }
        let (key, iv) = kdf.derive_key_rar4(password, Some(&salt));
        let mut decryptor = crate::crypto::Rar4CbcDecryptor::new(&key, &iv);
        let raw = match read_raw_header_encrypted(volume, &mut decryptor) {
            Ok(Some(raw)) => raw,
            Ok(None) => return Ok(None),
            Err(RarError::InvalidPassword) if !first => return Ok(None),
            Err(error) if rar3_volume_damage(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        first = false;
        let data_offset = volume.stream_position()?;
        let skip = match raw.header_type {
            Rar4HeaderType::EndArchive => return Ok(None),
            Rar4HeaderType::File | Rar4HeaderType::NewSub => {
                if let Some(record) =
                    Record::from_header(&raw, header_offset, data_offset, len, false)
                {
                    return Ok(Some(record));
                }
                match parse_file_header(&raw) {
                    Ok(header) => header.packed_size,
                    Err(error) if rar3_volume_damage(&error) => return Ok(None),
                    Err(error) => return Err(error),
                }
            }
            _ => raw.data_area_size,
        };
        if skip_forward(volume, skip).is_err() {
            return Ok(None);
        }
    }
}

/// Find the record by its header's bytes, nearest the end of the volume
/// first. Only a plaintext header can be found this way.
fn scan<R: Read + Seek>(volume: &mut R, len: u64) -> RarResult<Option<Record>> {
    scan_back(volume, len, NEEDLE, |volume, name_at, _| {
        for name_offset in NAME_OFFSETS {
            let Some(header_offset) = name_at.checked_sub(name_offset) else {
                continue;
            };
            // The header type first, so a stray needle costs one small read.
            let mut common = [0u8; 7];
            if read_exact_at(volume, header_offset, &mut common).is_err()
                || Rar4HeaderType::from(common[2]) != Rar4HeaderType::NewSub
            {
                continue;
            }
            volume.seek(SeekFrom::Start(header_offset))?;
            let Ok(Some(raw)) = read_raw_header(volume) else {
                continue;
            };
            let data_offset = header_offset + u64::from(raw.header_size);
            if let Some(record) = Record::from_header(&raw, header_offset, data_offset, len, true) {
                return Ok(Probe::Found(record));
            }
        }
        Ok(Probe::Reject)
    })
}

#[cfg(test)]
impl Record {
    /// The data area as RAR writes it for the protected bytes: every
    /// sector's checksum, then every parity sector.
    fn recompute<R: Read + Seek>(&self, volume: &mut R) -> Vec<u8> {
        let mut checksums = Vec::with_capacity(2 * self.sectors as usize);
        let mut parity = vec![0u8; self.slots as usize * SECTOR];
        let slots = self.slots;
        SectorReader::new()
            .for_each(volume, self, 0..self.sectors, &mut |index, sector, _| {
                checksums.extend_from_slice(&sector_checksum(sector).to_le_bytes());
                let slot = (index % slots) as usize;
                xor_into(&mut parity[slot * SECTOR..][..SECTOR], sector);
            })
            .unwrap();
        checksums.extend_from_slice(&parity);
        checksums
    }

    /// The data area as stored.
    fn stored(&self, volume: &[u8]) -> Vec<u8> {
        let size = self.layout().record_size as usize;
        volume[self.data_offset as usize..][..size].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    use super::super::record::test_support::{fixture, noise, scratch_dir};
    use super::*;
    use crate::recovery::{
        RecoveryRecordAssessment, RecoveryRecordRepair, assess_recovery_record,
        locate_recovery_record, repair_from_recovery_record,
    };

    const SCRATCH: &str = "UNRAR_RS_RR3_SCRATCH";

    fn original() -> Option<Vec<u8>> {
        fixture("rar4", "rar4_recovery.rar")
    }

    fn record(bytes: &[u8], password: Option<&str>) -> Record {
        locate(&mut Cursor::new(bytes), bytes.len() as u64, password)
            .unwrap()
            .expect("a record")
    }

    fn assess(bytes: &[u8], password: Option<&str>) -> RecoveryRecordAssessment {
        assess_recovery_record(&mut Cursor::new(bytes), password)
            .unwrap()
            .expect("a record")
    }

    /// The repair and the repaired copy it writes.
    fn repaired(bytes: &[u8], password: Option<&str>) -> (RecoveryRecordRepair, Vec<u8>) {
        let repair = repair_from_recovery_record(&mut Cursor::new(bytes), password)
            .unwrap()
            .expect("a record");
        let mut out = Vec::new();
        repair
            .write_repaired_copy(&mut Cursor::new(bytes), &mut out)
            .unwrap();
        (repair, out)
    }

    fn refused(bytes: &[u8], password: Option<&str>) -> Vec<u64> {
        match repair_from_recovery_record(&mut Cursor::new(bytes), password) {
            Err(RarError::RecoveryRecordInsufficient { units, .. }) => units,
            other => panic!("{other:?}"),
        }
    }

    fn patched_units(repair: &RecoveryRecordRepair) -> Vec<u64> {
        repair.patches.iter().map(|patch| patch.unit).collect()
    }

    /// Damage `sectors` of `original`: zero them, or fill them with noise.
    fn damage(original: &[u8], sectors: &[u64], zero: bool) -> Vec<u8> {
        let layout = locate_recovery_record(&mut Cursor::new(original), None)
            .unwrap()
            .unwrap();
        let mut bytes = original.to_vec();
        for &sector in sectors {
            let range = layout.unit_range(sector);
            let range = range.start as usize..range.end as usize;
            if zero {
                bytes[range].fill(0);
            } else {
                let len = range.len();
                bytes[range].copy_from_slice(&noise(sector + 1, len));
            }
        }
        bytes
    }

    #[test]
    fn fixture_record_recomputes_byte_exact() {
        let Some(bytes) = original() else {
            return;
        };
        let record = record(&bytes, None);
        assert!(!record.found_by_scan);
        assert_eq!((record.sectors, record.slots), (1, 1));
        assert_eq!(
            record.stored(&bytes),
            record.recompute(&mut Cursor::new(&bytes))
        );
        let scanned = scan(&mut Cursor::new(&bytes), bytes.len() as u64)
            .unwrap()
            .unwrap();
        assert!(scanned.found_by_scan);
        assert_eq!(scanned.header_offset, record.header_offset);
        assert!(assess(&bytes, None).is_intact());
    }

    /// The fixture protects one partial sector: the 152 bytes before the
    /// `RR` header, hashed and XORed as if zero-padded to 512.
    #[test]
    fn fixture_repairs_its_single_partial_sector() {
        let Some(original) = original() else {
            return;
        };
        for zero in [true, false] {
            let damaged = damage(&original, &[0], zero);
            assert_ne!(damaged, original);
            let (repair, fixed) = repaired(&damaged, None);
            assert_eq!(repair.assessment.damaged_units, [0]);
            assert_eq!(patched_units(&repair), [0]);
            assert_eq!(repair.patches[0].bytes.len(), 152);
            assert_eq!(fixed, original, "zero={zero}");
        }
        // The end of the sector only: the headers stay intact, so the walk
        // still finds the record.
        let mut damaged = original.clone();
        damaged[140..152].fill(0xAA);
        assert!(!record(&damaged, None).found_by_scan);
        let (repair, fixed) = repaired(&damaged, None);
        assert_eq!(fixed, original);
        let mut in_place = Cursor::new(damaged);
        repair.write_in_place(&mut in_place).unwrap();
        assert_eq!(in_place.into_inner(), original);
    }

    #[test]
    fn a_damaged_signature_is_bridged_by_the_scan() {
        let Some(original) = original() else {
            return;
        };
        let damaged = damage(&original, &[0], true);
        let layout = locate_recovery_record(&mut Cursor::new(&damaged), None)
            .unwrap()
            .unwrap();
        assert!(layout.found_by_scan);
        assert_eq!(layout.protected_size, 152);
        assert_eq!(repaired(&damaged, None).1, original);
    }

    /// A CRC-valid copy of the `RR` header among the protected bytes, with
    /// the signature damaged so the scan finds the record: the copy (which
    /// a forward scan meets first) must not stand in for the record.
    #[test]
    fn a_copy_of_the_header_among_the_protected_bytes_is_not_the_record() {
        let Some(original) = original() else {
            return;
        };
        let mut damaged = original.clone();
        damaged.copy_within(152..206, 60);
        damaged[..7].fill(0);
        let layout = locate_recovery_record(&mut Cursor::new(&damaged), None)
            .unwrap()
            .unwrap();
        assert_eq!(layout.protected_size, 152);
        assert_eq!(repaired(&damaged, None).1, original);
    }

    /// A CRC-valid header stating 2^63 sectors is not a record, and nothing
    /// overflows on the way to saying so.
    #[test]
    fn a_header_with_impossible_counts_is_not_a_record() {
        let Some(mut bytes) = original() else {
            return;
        };
        bytes[152 + 46..152 + 54].copy_from_slice(&(1u64 << 63).to_le_bytes());
        let crc = rar4_header_crc16(&bytes[152..206]);
        bytes[152..154].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            locate_recovery_record(&mut Cursor::new(&bytes), None).unwrap(),
            None
        );
        assert_eq!(
            assess_recovery_record(&mut Cursor::new(&bytes), None).unwrap(),
            None
        );
    }

    /// The sector and its checksum entry both damaged: the rebuilt sector
    /// cannot be confirmed, so the repair is refused and nothing written.
    #[test]
    fn an_unconfirmed_rebuild_is_refused() {
        let Some(original) = original() else {
            return;
        };
        let mut damaged = damage(&original, &[0], true);
        damaged[206..208].copy_from_slice(&[0xFF, 0xFF]);
        let assessment = assess(&damaged, None);
        assert_eq!(assessment.damaged_units, [0]);
        assert_eq!(assessment.unrepairable_units, [0]);
        assert_eq!(refused(&damaged, None), [0]);
    }

    /// The checksum entry alone damaged: the parity vouches for the sector,
    /// so it is reported as a damaged checksum and nothing is rebuilt.
    #[test]
    fn a_damaged_checksum_entry_alone_is_record_damage() {
        let Some(mut damaged) = original() else {
            return;
        };
        damaged[206..208].copy_from_slice(&[0xFF, 0xFF]);
        let assessment = assess(&damaged, None);
        assert!(assessment.damaged_units.is_empty(), "{assessment:?}");
        assert_eq!(assessment.damaged_checksums, [0]);
        assert!(!assessment.is_intact());
        let (repair, fixed) = repaired(&damaged, None);
        assert!(repair.patches.is_empty());
        assert_eq!(fixed, damaged, "the record is never rewritten");
    }

    #[test]
    fn a_damaged_parity_sector_is_reported_and_left() {
        let Some(mut damaged) = original() else {
            return;
        };
        damaged[208 + 100] ^= 0x55;
        let assessment = assess(&damaged, None);
        assert!(assessment.damaged_units.is_empty());
        assert_eq!(assessment.damaged_parity, [0]);
        let (repair, fixed) = repaired(&damaged, None);
        assert!(repair.patches.is_empty());
        assert_eq!(fixed, damaged, "the record is never rewritten");
    }

    #[test]
    fn damage_after_the_record_is_outside_it() {
        let Some(mut damaged) = original() else {
            return;
        };
        damaged[208 + 512..].fill(0);
        assert!(assess(&damaged, None).is_intact());
    }

    // Everything below reads RARLAB-written archives from the directory
    // `UNRAR_RS_RR3_SCRATCH` names (holding `out624/`, `pct624/`, `out720/`
    // and `oracle/`) and does nothing without it, so the committed suite
    // stays fixture-only.

    fn scratch_archives(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for dir in ["out624", "pct624", "out720"] {
            for entry in std::fs::read_dir(root.join(dir)).unwrap().flatten() {
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
    fn scratch_records_recompute_byte_exact() {
        let Some(root) = scratch_dir(SCRATCH) else {
            return;
        };
        let archives = scratch_archives(&root);
        assert!(archives.len() >= 60, "only {} archives", archives.len());
        let mut failures = Vec::new();
        let mut records = 0;
        for path in &archives {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = std::fs::read(path).unwrap();
            let password = password_for(path);
            let mut cursor = Cursor::new(&bytes);
            let record = match locate(&mut cursor, bytes.len() as u64, password) {
                Ok(Some(record)) => record,
                Ok(None) => {
                    eprintln!("{name}: no record");
                    continue;
                }
                Err(e) => {
                    failures.push(format!("{name}: {e}"));
                    continue;
                }
            };
            records += 1;
            if record.found_by_scan || record.stored(&bytes) != record.recompute(&mut cursor) {
                failures.push(format!("{name}: {record:?} does not recompute"));
            }
            if password.is_none() {
                let scanned = scan(&mut cursor, bytes.len() as u64).unwrap();
                if scanned.map(|r| r.header_offset) != Some(record.header_offset) {
                    failures.push(format!("{name}: the scan disagrees"));
                }
            }
            let assessment = assess(&bytes, password);
            if !assessment.is_intact() {
                failures.push(format!("{name}: {assessment:?}"));
            }
        }
        eprintln!("{records} records of {} archives", archives.len());
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// In-memory damage on `a05_rr10.rar` (587 sectors, 10 slots): repaired
    /// bytes equal the original up to capacity, nothing is written past it,
    /// and a pass in narrow windows finds what one wide pass finds.
    #[test]
    fn scratch_a05_in_memory_damage_matrix() {
        let Some(root) = scratch_dir(SCRATCH) else {
            return;
        };
        let original = std::fs::read(root.join("out624/a05_rr10.rar")).unwrap();
        let record = record(&original, None);
        assert_eq!((record.slots, record.sectors), (10, 587));
        let last = record.sectors - 1;
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
        let windowed = |bytes: &[u8], window| {
            record
                .examine_in_windows(&mut Cursor::new(bytes), true, window)
                .unwrap()
        };
        for (name, sectors, zero) in cases {
            let damaged = damage(&original, &sectors, zero);
            let (repair, fixed) = repaired(&damaged, None);
            assert_eq!(patched_units(&repair), sectors, "{name}");
            assert_eq!(fixed, original, "{name}");
            for window in [1, 3, 7] {
                let narrow = windowed(&damaged, window);
                let mut units: Vec<u64> = narrow.patches.iter().map(|p| p.unit).collect();
                units.sort_unstable();
                assert_eq!(units, sectors, "{name} window {window}");
                let mut found = narrow.assessment.damaged_units;
                found.sort_unstable();
                assert_eq!(found, sectors, "{name} window {window}");
            }
        }
        // Over capacity: two sectors in slot 3; eleven contiguous sectors.
        let damaged = damage(&original, &[3, 13], true);
        assert_eq!(refused(&damaged, None), [3, 13]);
        let damaged = damage(&original, &(200..211).collect::<Vec<_>>(), true);
        let assessment = assess(&damaged, None);
        assert_eq!(assessment.damaged_units, (200..211).collect::<Vec<_>>());
        assert_eq!(assessment.unrepairable_units, [200, 210]);
        let mut narrow = windowed(&damaged, 3).assessment.unrepairable_units;
        narrow.sort_unstable();
        assert_eq!(narrow, [200, 210]);
        assert_eq!(refused(&damaged, None), [200, 210]);
        // Damage inside the record: a checksum entry, a parity sector.
        let mut damaged = damage(&original, &[60], true);
        let at = record.checksum_at(60) as usize;
        damaged[at..at + 2].copy_from_slice(&[0xFF, 0xFF]);
        assert_eq!(refused(&damaged, None), [60]);
        let mut damaged = damage(&original, &[50], true);
        let at = record.parity_at(0) as usize;
        damaged[at..at + 64].copy_from_slice(&noise(7, 64));
        assert_eq!(refused(&damaged, None), [50]);
        // A damaged parity sector alone, in a slot with no other damage.
        let mut damaged = original.clone();
        damaged[record.parity_at(4) as usize] ^= 1;
        assert_eq!(assess(&damaged, None).damaged_parity, [4]);
        assert_eq!(windowed(&damaged, 3).assessment.damaged_parity, [4]);
    }

    /// The `-hp` archive: finding the record needs the password, the data
    /// area is in the clear, and a repair restores the encrypted bytes.
    #[test]
    fn scratch_hp_needs_the_password_then_repairs() {
        let Some(root) = scratch_dir(SCRATCH) else {
            return;
        };
        let original = std::fs::read(root.join("out624/a11_hp.rar")).unwrap();
        assert!(matches!(
            locate_recovery_record(&mut Cursor::new(&original), None),
            Err(RarError::EncryptedArchive)
        ));
        assert!(
            scan(&mut Cursor::new(&original), original.len() as u64)
                .unwrap()
                .is_none()
        );
        assert!(locate_recovery_record(&mut Cursor::new(&original), Some("wrong")).is_err());
        let layout = locate_recovery_record(&mut Cursor::new(&original), Some("secret"))
            .unwrap()
            .unwrap();
        let mut damaged = original.clone();
        let range = layout.unit_range(20);
        damaged[range.start as usize..range.end as usize].fill(0);
        let (repair, fixed) = repaired(&damaged, Some("secret"));
        assert_eq!(patched_units(&repair), [20]);
        assert_eq!(fixed, original);
    }

    /// Every `rar r` oracle case under `oracle/<engine>/<case>/`. Where rar
    /// wrote `fixed.*` and we repair, the copies are identical. Where we
    /// refuse, rar left every unit we call unrepairable as it was.
    #[test]
    fn scratch_oracle_cross_check() {
        let Some(root) = scratch_dir(SCRATCH) else {
            return;
        };
        let mut failures = Vec::new();
        let mut cases = 0;
        for engine in ["r624", "r720"] {
            let mut dirs: Vec<_> = std::fs::read_dir(root.join("oracle").join(engine))
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .collect();
            dirs.sort();
            for dir in dirs {
                let case = format!("{engine}/{}", dir.file_name().unwrap().to_string_lossy());
                let Some(damaged_path) = std::fs::read_dir(&dir).unwrap().flatten().find_map(|e| {
                    let p = e.path();
                    let n = p.file_name()?.to_str()?.to_owned();
                    (p.is_file() && !n.ends_with(".log")).then_some(p)
                }) else {
                    continue;
                };
                cases += 1;
                let damaged = std::fs::read(&damaged_path).unwrap();
                let password = password_for(&damaged_path);
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
                let ours = repair_from_recovery_record(&mut Cursor::new(&damaged), password);
                let verdict = match (&fixed, ours) {
                    (Some(fixed), Ok(Some(repair))) => {
                        let mut out = Vec::new();
                        repair
                            .write_repaired_copy(&mut Cursor::new(&damaged), &mut out)
                            .unwrap();
                        if out != *fixed {
                            failures.push(format!("{case}: differs from rar"));
                        }
                        format!("repaired {:?}", patched_units(&repair))
                    }
                    (Some(fixed), Err(RarError::RecoveryRecordInsufficient { units, .. })) => {
                        let layout = locate_recovery_record(&mut Cursor::new(&damaged), password)
                            .unwrap()
                            .unwrap();
                        for &unit in &units {
                            let range = layout.unit_range(unit);
                            let range = range.start as usize..range.end as usize;
                            if fixed.get(range.clone()) != damaged.get(range) {
                                failures.push(format!("{case}: rar rebuilt unit {unit}"));
                            }
                        }
                        format!("refused, unrepairable {units:?}")
                    }
                    (Some(_), other) => {
                        failures.push(format!("{case}: rar repaired, ours {other:?}"));
                        String::new()
                    }
                    (None, other) => format!(
                        "rar found no record; ours {:?}",
                        other.map(|r| r.map(|r| patched_units(&r)))
                    ),
                };
                eprintln!("{case}: {verdict}");
            }
        }
        assert!(cases > 0, "no oracle cases");
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// Percent-form sector counts: `R = 2 + floor((S*p/100 - S/250) / 512)`,
    /// capped at `min(N, 524288)`, with `S` the protected length, on every
    /// `pct624` archive and the percent-form `out624` ones.
    #[test]
    fn scratch_percent_formula() {
        let Some(root) = scratch_dir(SCRATCH) else {
            return;
        };
        fn expect(s: u64, n: u64, p: u64) -> u64 {
            let want = (s * p / 100).saturating_sub(s / 250) / 512 + 2;
            want.min(n).min(524_288)
        }
        let mut checked = 0;
        let mut failures = Vec::new();
        let mut archives: Vec<PathBuf> = Vec::new();
        for dir in ["pct624", "out624"] {
            archives.extend(
                std::fs::read_dir(root.join(dir))
                    .unwrap()
                    .flatten()
                    .map(|e| e.path()),
            );
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
            let bytes = std::fs::read(&path).unwrap();
            let Some(layout) = locate_recovery_record(&mut Cursor::new(&bytes), None).unwrap()
            else {
                assert_eq!(absolute, Some(0), "{name}: no record");
                checked += 1;
                continue;
            };
            let (s, n) = (layout.protected_size, layout.data_units);
            let want = match (percent, absolute) {
                (Some(p), _) => expect(s, n, p),
                (_, Some(r)) => r.min(n).min(524_288),
                _ => unreachable!(),
            };
            if layout.parity_units != want {
                failures.push(format!(
                    "{name}: R={} want={want} (S={s} N={n} p={percent:?} r={absolute:?})",
                    layout.parity_units
                ));
            }
            checked += 1;
        }
        eprintln!("percent formula checked on {checked} archives");
        assert!(checked > 60);
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
