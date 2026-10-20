//! A volume's own recovery record, the one `rar a -rr` and `rar rr` add:
//! find it, check the volume against it, and rebuild damaged bytes from it.
//!
//! RAR 2.9-4.x and RAR5 keep different records (the `rr3` and `rr5`
//! modules each describe their layout) on one plan. The record follows an
//! `RR` service header at volume offset `P` and protects the bytes `0..P`,
//! an SFX module included, cut into data units, each with a checksum in the
//! record, and parity units that rebuild lost data units: 512-byte sectors,
//! a 16-bit checksum each and XOR parity in RAR3; units of about `P / 200`
//! bytes, a CRC64 per 64 KiB slice and GF(2^16) Reed-Solomon parity in
//! RAR5. Nothing from `P` on (the header, the record, the end-of-archive
//! block) is protected, and nothing here writes or alters a record.
//!
//! Each call starts from the volume alone: [`locate_recovery_record`] gives
//! the [`RecoveryRecordLayout`], [`assess_recovery_record`] the damage and
//! what the record can rebuild, and [`repair_from_recovery_record`] the
//! rebuilt bytes, which [`RecoveryRecordRepair`] writes into the volume or
//! into a repaired copy.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

use super::{rr3, rr5};
use crate::error::{RarError, RarResult};
use crate::types::ArchiveFormat;

/// Where a volume's recovery record lies and how it cuts up what it
/// protects. The record's `RR` header sits between the protected bytes and
/// the record, at `protected_size..record_offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecordLayout {
    /// [`ArchiveFormat::Rar4`] for the RAR 2.9-4.x record,
    /// [`ArchiveFormat::Rar5`] for the RAR5 one.
    pub format: ArchiveFormat,
    /// The record protects the volume's bytes `0..protected_size`, which is
    /// where its `RR` header starts.
    pub protected_size: u64,
    /// Where the record starts: the `RR` header's data area.
    pub record_offset: u64,
    /// Bytes of the record.
    pub record_size: u64,
    /// Bytes per data unit; the last unit holds what remains.
    pub unit_size: u64,
    /// Data units the protected bytes are cut into.
    pub data_units: u64,
    /// Parity units the record holds, each `unit_size` long.
    pub parity_units: u64,
    /// Whether the record was found by scanning back from the end of the
    /// volume rather than through the archive's headers: they are damaged,
    /// or encrypted in a RAR5 volume.
    pub found_by_scan: bool,
}

impl RecoveryRecordLayout {
    /// The protected bytes.
    pub fn protected_range(&self) -> Range<u64> {
        0..self.protected_size
    }

    /// The record's bytes.
    pub fn record_range(&self) -> Range<u64> {
        self.record_offset..self.record_offset.saturating_add(self.record_size)
    }

    /// The bytes of data unit `unit`, empty past the last one.
    pub fn unit_range(&self, unit: u64) -> Range<u64> {
        let start = unit.saturating_mul(self.unit_size).min(self.protected_size);
        start
            ..start
                .saturating_add(self.unit_size)
                .min(self.protected_size)
    }
}

/// A volume checked against its recovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecordAssessment {
    /// The record checked against.
    pub layout: RecoveryRecordLayout,
    /// Data units whose bytes fail the checksum the record keeps for them,
    /// ascending.
    pub damaged_units: Vec<u64>,
    /// The damaged units the record cannot rebuild, ascending: their damage
    /// shares parity with other damage, or the parity they need is damaged.
    pub unrepairable_units: Vec<u64>,
    /// Parity units of the record found damaged, ascending: a RAR5 parity
    /// unit with a chunk that fails its CRC64, a RAR3 parity sector that is
    /// not the XOR of its intact data sectors. A repair never uses or
    /// rewrites them.
    pub damaged_parity: Vec<u64>,
    /// Data units whose bytes agree with the parity while the checksum the
    /// RAR3 record keeps for them does not, ascending: the checksum entry is
    /// what is damaged. Always empty for RAR5, whose checksums each chunk
    /// covers with its own CRC64.
    pub damaged_checksums: Vec<u64>,
    /// Protected bytes no checksum survives for, so damage to them goes
    /// unseen: a RAR5 slice every chunk of which is damaged.
    pub unchecked_bytes: u64,
}

impl RecoveryRecordAssessment {
    /// Whether the protected bytes and the record are undamaged, as far as
    /// the record's checksums tell.
    pub fn is_intact(&self) -> bool {
        self.damaged_units.is_empty()
            && self.damaged_parity.is_empty()
            && self.damaged_checksums.is_empty()
            && self.unchecked_bytes == 0
    }

    /// Whether the record rebuilds every damaged unit it can see. Bytes
    /// counted in [`unchecked_bytes`](Self::unchecked_bytes) are outside
    /// this: no checksum survives for them, so a repair copies them as they
    /// are and cannot tell whether they are damaged. A caller that needs the
    /// whole protected range vouched for checks `unchecked_bytes` or
    /// [`is_intact`](Self::is_intact) as well.
    pub fn is_repairable(&self) -> bool {
        self.unrepairable_units.is_empty()
    }
}

/// Every damaged unit of a volume, rebuilt from its recovery record and
/// confirmed against the checksum the record keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecordRepair {
    /// The check the repair worked from. Every damaged unit is repairable.
    pub assessment: RecoveryRecordAssessment,
    /// The rebuilt bytes, ascending and disjoint, all inside the protected
    /// range. Empty when nothing is damaged.
    pub patches: Vec<RecoveryRecordPatch>,
}

/// Bytes of one data unit rebuilt from the record: all of a RAR3 sector, or
/// one damaged 64 KiB slice of a RAR5 unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryRecordPatch {
    /// The data unit the bytes belong to.
    pub unit: u64,
    /// Where they go in the volume.
    pub offset: u64,
    /// The rebuilt bytes.
    pub bytes: Vec<u8>,
}

impl RecoveryRecordRepair {
    /// Write the rebuilt bytes into the damaged volume itself: one write
    /// per patch, nothing else touched.
    pub fn write_in_place<W: Write + Seek>(&self, volume: &mut W) -> RarResult<()> {
        for patch in &self.patches {
            volume.seek(SeekFrom::Start(patch.offset))?;
            volume.write_all(&patch.bytes)?;
        }
        volume.flush()?;
        Ok(())
    }

    /// Copy the damaged volume to `output` with the rebuilt bytes in place
    /// of the damaged ones, every other byte as it is, the record included.
    /// Returns the bytes written: the volume's length.
    pub fn write_repaired_copy<R: Read + Seek, W: Write>(
        &self,
        volume: &mut R,
        output: &mut W,
    ) -> RarResult<u64> {
        volume.seek(SeekFrom::Start(0))?;
        let mut pos = 0u64;
        for patch in &self.patches {
            let gap = patch.offset.checked_sub(pos).ok_or_else(|| {
                RarError::internal("recovery record patches overlap or are out of order")
            })?;
            let copied = io::copy(&mut volume.by_ref().take(gap), output)?;
            if copied != gap {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            let len = patch.bytes.len() as u64;
            volume.seek(SeekFrom::Current(len as i64))?;
            output.write_all(&patch.bytes)?;
            pos = patch.offset + len;
        }
        let rest = io::copy(volume, output)?;
        Ok(pos + rest)
    }
}

/// Find a volume's recovery record and give its layout, without checking
/// anything against it. `None` when the volume has no record this crate
/// can use: none at all, a RAR 1.x-2.x volume, or one whose `RR` header or
/// every chunk is damaged.
///
/// The archive's headers lead to the record when they are intact: four
/// small reads through a RAR5 main header's locator, one read per header up
/// to the `RR` header in RAR3. Otherwise the volume is scanned back from its
/// end for the record. A RAR3 volume with encrypted headers (`-hp`) needs
/// `password` to be walked, as it does for `rar r`; without it the result is
/// [`RarError::EncryptedArchive`], and a wrong one is
/// [`RarError::InvalidPassword`]. A RAR5 record is found without a password.
pub fn locate_recovery_record<R: Read + Seek>(
    volume: &mut R,
    password: Option<&str>,
) -> RarResult<Option<RecoveryRecordLayout>> {
    Ok(find(volume, password)?.map(|record| record.layout()))
}

/// Check a volume against its recovery record: every data unit against its
/// checksum, every parity unit against its own check, and what a repair
/// could rebuild. `None` as for [`locate_recovery_record`].
///
/// Reads the protected bytes once and the record once. Memory is bounded
/// whatever the headers state: a few MiB of buffers in RAR3, one chunk and
/// the CRC lists in RAR5.
pub fn assess_recovery_record<R: Read + Seek>(
    volume: &mut R,
    password: Option<&str>,
) -> RarResult<Option<RecoveryRecordAssessment>> {
    let Some(record) = find(volume, password)? else {
        return Ok(None);
    };
    Ok(Some(record.examine(volume, false)?.assessment))
}

/// Rebuild every damaged unit of a volume from its recovery record. Only
/// reads: the [`RecoveryRecordRepair`] writes the result. `None` as for
/// [`locate_recovery_record`].
///
/// Every rebuilt unit has matched the checksum the record keeps for it.
/// When any damaged unit cannot be rebuilt, the result is
/// [`RarError::RecoveryRecordInsufficient`] naming them, and nothing is
/// rebuilt: a partial repair is not offered. The record itself is never
/// rebuilt or rewritten.
///
/// Reads as [`assess_recovery_record`] does, plus, in RAR5, the slices the
/// damage touches once more. Holds the rebuilt bytes.
pub fn repair_from_recovery_record<R: Read + Seek>(
    volume: &mut R,
    password: Option<&str>,
) -> RarResult<Option<RecoveryRecordRepair>> {
    let Some(record) = find(volume, password)? else {
        return Ok(None);
    };
    let Examination {
        assessment,
        patches,
    } = record.examine(volume, true)?;
    if !assessment.is_repairable() {
        return Err(RarError::RecoveryRecordInsufficient {
            units: assessment.unrepairable_units,
        });
    }
    Ok(Some(RecoveryRecordRepair {
        assessment,
        patches,
    }))
}

/// A record of either format, located.
enum Record {
    Rar3(rr3::Record),
    Rar5(rr5::Record),
}

impl Record {
    fn layout(&self) -> RecoveryRecordLayout {
        match self {
            Self::Rar3(record) => record.layout(),
            Self::Rar5(record) => record.layout(),
        }
    }

    fn examine<R: Read + Seek>(&self, volume: &mut R, rebuild: bool) -> RarResult<Examination> {
        let mut examination = match self {
            Self::Rar3(record) => record.examine(volume, rebuild)?,
            Self::Rar5(record) => record.examine(volume, rebuild)?,
        };
        let assessment = &mut examination.assessment;
        for list in [
            &mut assessment.damaged_units,
            &mut assessment.unrepairable_units,
            &mut assessment.damaged_parity,
            &mut assessment.damaged_checksums,
        ] {
            list.sort_unstable();
            list.dedup();
        }
        examination
            .patches
            .sort_unstable_by_key(|patch| patch.offset);
        if !assessment.is_repairable() {
            examination.patches.clear();
        }
        Ok(examination)
    }
}

/// The volume's record. The signature picks the format; a
/// volume whose signature is damaged is scanned for either.
fn find<R: Read + Seek>(volume: &mut R, password: Option<&str>) -> RarResult<Option<Record>> {
    let len = volume.seek(SeekFrom::End(0))?;
    volume.seek(SeekFrom::Start(0))?;
    Ok(match crate::signature::read_signature(volume) {
        Ok(ArchiveFormat::Rar5) => rr5::locate(volume, len)?.map(Record::Rar5),
        Ok(ArchiveFormat::Rar4) => rr3::locate(volume, len, password)?.map(Record::Rar3),
        Ok(ArchiveFormat::Rar14) => None,
        Err(RarError::Io(error)) if error.kind() != io::ErrorKind::UnexpectedEof => {
            return Err(RarError::Io(error));
        }
        Err(_) => match rr5::locate(volume, len)? {
            Some(record) => Some(Record::Rar5(record)),
            None => rr3::locate(volume, len, password)?.map(Record::Rar3),
        },
    })
}

/// What a backend found: the assessment, and the rebuilt bytes when asked
/// for and every damaged unit was rebuilt. The front end sorts both.
pub(super) struct Examination {
    pub(super) assessment: RecoveryRecordAssessment,
    pub(super) patches: Vec<RecoveryRecordPatch>,
}

impl Examination {
    pub(super) fn new(layout: RecoveryRecordLayout) -> Self {
        Self {
            assessment: RecoveryRecordAssessment {
                layout,
                damaged_units: Vec::new(),
                unrepairable_units: Vec::new(),
                damaged_parity: Vec::new(),
                damaged_checksums: Vec::new(),
                unchecked_bytes: 0,
            },
            patches: Vec::new(),
        }
    }
}

/// What a backward scan's probe made of one occurrence of the needle.
pub(super) enum Probe<T> {
    /// The record.
    Found(T),
    /// Not even the start of a candidate; cost nothing to rule out.
    Skip,
    /// A candidate that cost a read and failed.
    Reject,
}

/// Bytes a backward scan reads at a time.
const SCAN_BLOCK: usize = 1 << 20;
/// Bytes past each occurrence a probe is shown from memory, when the volume
/// has them: a RAR5 chunk's fixed header.
pub(super) const SCAN_LOOKAHEAD: usize = 0x40;
/// Rejected candidates after which a scan gives up. Each costs a read of a
/// header or a chunk, so this bounds the work a volume full of false marks
/// can cause.
const MAX_REJECTED: usize = 1024;

/// Scan `volume[..len]` back from its end for `needle`, nearest the end
/// first, and give each occurrence's offset to `probe` with the bytes from
/// there (at least [`SCAN_LOOKAHEAD`], when the volume has them). The
/// record is the last thing in a volume but its end-of-archive block, so
/// the first candidate that holds is the record, and a copy of a record
/// header among the protected bytes (a stored archive, say) is never met
/// before it.
pub(super) fn scan_back<R: Read + Seek, T>(
    volume: &mut R,
    len: u64,
    needle: &[u8],
    mut probe: impl FnMut(&mut R, u64, &[u8]) -> RarResult<Probe<T>>,
) -> RarResult<Option<T>> {
    let finder = memchr::memmem::FinderRev::new(needle);
    let overlap = SCAN_LOOKAHEAD.max(needle.len() - 1) as u64;
    let mut block = Vec::new();
    let mut rejected = 0usize;
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(SCAN_BLOCK as u64);
        let stop = len.min(end + overlap);
        block.resize((stop - start) as usize, 0);
        read_exact_at(volume, start, &mut block)?;
        for hit in finder.rfind_iter(&block) {
            let pos = start + hit as u64;
            if pos >= end {
                continue;
            }
            match probe(volume, pos, &block[hit..])? {
                Probe::Found(found) => return Ok(Some(found)),
                Probe::Skip => {}
                Probe::Reject => {
                    rejected += 1;
                    if rejected == MAX_REJECTED {
                        return Ok(None);
                    }
                }
            }
        }
        end = start;
    }
    Ok(None)
}

pub(super) fn read_exact_at<R: Read + Seek>(
    volume: &mut R,
    pos: u64,
    into: &mut [u8],
) -> RarResult<()> {
    volume.seek(SeekFrom::Start(pos))?;
    volume.read_exact(into)?;
    Ok(())
}

pub(super) fn xor_into(acc: &mut [u8], bytes: &[u8]) {
    for (a, b) in acc.iter_mut().zip(bytes) {
        *a ^= b;
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use std::path::{Path, PathBuf};

    /// A committed fixture under `tests/fixtures/<dir>`.
    pub(in crate::recovery) fn fixture(dir: &str, name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(dir)
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// Deterministic bytes for damage: xorshift64 from `seed`.
    pub(in crate::recovery) fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// The scratch directory the environment variable `var` names, `None`
    /// when it is unset. A set variable that names no directory, or an
    /// empty one, fails the test rather than skipping it.
    pub(in crate::recovery) fn scratch_dir(var: &str) -> Option<PathBuf> {
        let dir = PathBuf::from(std::env::var_os(var)?);
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{var}={}: {e}", dir.display()))
            .count();
        assert!(entries > 0, "{var}={} is empty", dir.display());
        Some(dir)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::test_support::fixture;
    use super::*;

    #[test]
    fn a_volume_without_a_record_has_none() {
        for bytes in [
            Vec::new(),
            b"not an archive at all".to_vec(),
            fixture("rar5", "rar5_recovery.rar")[..154].to_vec(),
        ] {
            let mut cursor = Cursor::new(bytes);
            assert_eq!(locate_recovery_record(&mut cursor, None).unwrap(), None);
            assert_eq!(assess_recovery_record(&mut cursor, None).unwrap(), None);
            assert_eq!(
                repair_from_recovery_record(&mut cursor, None).unwrap(),
                None
            );
        }
    }

    #[test]
    fn both_formats_give_the_same_shape() {
        let rar4 =
            locate_recovery_record(&mut Cursor::new(fixture("rar4", "rar4_recovery.rar")), None)
                .unwrap()
                .unwrap();
        assert_eq!(rar4.format, ArchiveFormat::Rar4);
        assert_eq!((rar4.protected_size, rar4.record_offset), (152, 206));
        assert_eq!(
            (rar4.unit_size, rar4.data_units, rar4.parity_units),
            (512, 1, 1)
        );
        assert_eq!(rar4.record_size, 2 + 512);
        assert_eq!(rar4.unit_range(0), 0..152);
        assert!(!rar4.found_by_scan);

        let rar5 =
            locate_recovery_record(&mut Cursor::new(fixture("rar5", "rar5_recovery.rar")), None)
                .unwrap()
                .unwrap();
        assert_eq!(rar5.format, ArchiveFormat::Rar5);
        assert_eq!((rar5.protected_size, rar5.record_offset), (154, 177));
        assert_eq!((rar5.data_units, rar5.parity_units), (1, 1));
        assert_eq!(rar5.unit_range(0), 0..154);
        assert_eq!(rar5.unit_range(1), 154..154);
        assert_eq!(rar5.record_range(), 177..177 + 0x50 + 154);
    }

    #[test]
    fn a_repaired_copy_is_the_input_with_the_patches_and_nothing_else() {
        let repair = RecoveryRecordRepair {
            assessment: Examination::new(RecoveryRecordLayout {
                format: ArchiveFormat::Rar4,
                protected_size: 8,
                record_offset: 10,
                record_size: 2,
                unit_size: 2,
                data_units: 4,
                parity_units: 1,
                found_by_scan: false,
            })
            .assessment,
            patches: vec![
                RecoveryRecordPatch {
                    unit: 0,
                    offset: 0,
                    bytes: b"AB".to_vec(),
                },
                RecoveryRecordPatch {
                    unit: 2,
                    offset: 4,
                    bytes: b"CD".to_vec(),
                },
            ],
        };
        let input = b"0123456789xy".to_vec();
        let mut copy = Vec::new();
        let written = repair
            .write_repaired_copy(&mut Cursor::new(&input), &mut copy)
            .unwrap();
        assert_eq!(copy, b"AB23CD6789xy");
        assert_eq!(written, input.len() as u64);
        let mut in_place = Cursor::new(input);
        repair.write_in_place(&mut in_place).unwrap();
        assert_eq!(in_place.into_inner(), copy);

        // A volume shorter than a patch's offset is an error, not a panic.
        let mut short = Vec::new();
        assert!(
            repair
                .write_repaired_copy(&mut Cursor::new(b"01"), &mut short)
                .is_err()
        );
    }

    #[test]
    fn a_scan_gives_up_after_too_many_rejected_candidates() {
        let mut bytes = b"{RB}".repeat(MAX_REJECTED + 10);
        bytes.extend_from_slice(b"tail");
        let len = bytes.len() as u64;
        let mut probed = 0usize;
        let found = scan_back(&mut Cursor::new(bytes), len, b"{RB}", |_, _, _| {
            probed += 1;
            Ok(Probe::<()>::Reject)
        })
        .unwrap();
        assert_eq!(found, None);
        assert_eq!(probed, MAX_REJECTED);
    }

    #[test]
    fn a_scan_sees_a_needle_across_a_block_boundary_once() {
        let mut bytes = vec![0u8; SCAN_BLOCK + 100];
        let at = 100 - 2;
        bytes[at..at + 4].copy_from_slice(b"{RB}");
        let len = bytes.len() as u64;
        let mut seen = Vec::new();
        let found = scan_back(&mut Cursor::new(bytes), len, b"{RB}", |_, pos, tail| {
            assert!(tail.starts_with(b"{RB}"));
            seen.push(pos);
            Ok(Probe::<()>::Skip)
        })
        .unwrap();
        assert_eq!(found, None);
        assert_eq!(seen, [at as u64]);
    }
}
