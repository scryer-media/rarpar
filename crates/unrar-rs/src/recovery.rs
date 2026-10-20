//! RAR recovery-volume restore support.
//!
//! RAR recovery volumes are not PAR2 files. RAR5 uses GF(2^16) Cauchy matrix
//! semantics, while legacy RAR3 uses a byte-wise GF(2^8) erasure coder. This
//! module keeps that restore logic separate from archive extraction so existing
//! extraction APIs remain unchanged.

use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{RarError, RarResult};
use crate::probe::probe_volume;
use crate::types::ArchiveFormat;
use reedsolomon_rs::decode_apply::apply_decode_matrix_gf8;
use reedsolomon_rs::rar3::Rar3RsCoder;
use reedsolomon_rs::rar5::Rar5RsCoder;

mod record;
mod rr3;
mod rr5;
mod stream;

pub use record::{
    RecoveryRecordAssessment, RecoveryRecordLayout, RecoveryRecordPatch, RecoveryRecordRepair,
    assess_recovery_record, locate_recovery_record, repair_from_recovery_record,
};
pub use stream::{
    DataVolumeState, FileVolumeSource, RecoveryVolumeState, RestoreSet, RestoredVolume,
    SliceVolumeSource, StreamRestoreOptions, VolumeAssessment, VolumeRef, VolumeRestoreError,
    VolumeRestoreReport, VolumeSource, assess_volume_set, restore_volume_set,
};

const REV5_SIGN: &[u8; 8] = b"Rar!\x1aRev";
const REV5_PREFIX_LEN: usize = 16;
const MAX_RAR5_VOLUMES: usize = 65_535;
const RAR3_TOTAL_BUFFER_SIZE: usize = 64 * 1024 * 1024;
/// A RAR3 recovery set holds at most 255 data plus recovery volumes, one
/// GF(2^8) symbol each, so one column always fits an array this size.
const MAX_RAR3_SET: usize = Rar3RsCoder::MAX_BLOCK_LEN;
const RAR5_TOTAL_BUFFER_SIZE: usize = 64 * 1024 * 1024;
/// How far past a RAR3 last volume's end-of-archive block reference UnRAR
/// looks for zero padding before it cuts the volume there.
const RAR3_PADDING_PROBE: u64 = 8192;

#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    pub output_dir: Option<PathBuf>,
    pub overwrite_existing: bool,
    pub verify_restored: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            output_dir: None,
            overwrite_existing: false,
            verify_restored: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub format: ArchiveFormat,
    pub restored_paths: Vec<PathBuf>,
    pub used_recovery_paths: Vec<PathBuf>,
    pub missing_volume_numbers: Vec<usize>,
}

/// Outcome of testing one path as a recovery volume.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevTestStatus {
    /// Header parsed and the payload CRC32 matched the header's.
    Ok,
    /// Header parsed, payload CRC32 did not match.
    CrcMismatch {
        /// The CRC32 the volume states: its RAR5 header's, or the last four
        /// bytes of a RAR3 volume.
        expected: u32,
        /// The CRC32 of the bytes it covers, as read.
        actual: u32,
    },
    /// No recovery-volume header this crate recognises (bad signature, header
    /// CRC, version, counts or volume number, or too short).
    InvalidHeader,
    /// A RAR 3.0-style `name<d>_<r>_<p>.rev`, whatever numbers its name
    /// carries: the format has no checksum, so it cannot be tested (reference
    /// UnRAR reports it as an unknown method).
    Unverifiable,
    /// The path is not a `.rev` recovery volume at all (wrong extension).
    NotRecoveryVolume,
    /// The file does not exist.
    Missing,
    /// The file exists but could not be opened or read.
    Unreadable {
        /// The kind of the I/O error that stopped the read.
        kind: std::io::ErrorKind,
    },
}

/// One path's outcome from [`test_recovery_volumes`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RevTestResult {
    /// The path, as given.
    pub path: PathBuf,
    /// `Rar5` for a RAR5 header, `Rar4` for a RAR3 footer or a RAR 3.0-style
    /// name, else `None`.
    pub format: Option<ArchiveFormat>,
    pub status: RevTestStatus,
}

/// What a restore finds in one data volume's slot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataVolumeStatus {
    /// Present and passing the restore's check: a RAR5 volume's size and
    /// CRC32 match the `.rev` table; a RAR3 volume's headers read through to
    /// its end-of-archive header, which numbers it as this volume, and the
    /// data CRC that header states, when it states one, matches. A RAR3
    /// volume whose headers are encrypted shows nothing past its main header
    /// and is taken as valid on that, as reference UnRAR takes it.
    Valid,
    /// No file was found for this slot.
    Missing,
    /// RAR5 only: the file's length differs from the `.rev` table.
    WrongSize { expected: u64, actual: u64 },
    /// RAR5: CRC32 differs from the table. RAR3: the end-of-archive data CRC
    /// failed.
    CrcMismatch,
    /// RAR3: the file is not a volume in the RAR 1.5 to 4.x format, or its
    /// headers are broken: cut short, ending before an end-of-archive header,
    /// or with an end-of-archive header that numbers it as another volume.
    InvalidHeaders,
}

/// One data volume of a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataVolumePlan {
    /// Zero-based data volume index, as
    /// [`RecoveryReport::missing_volume_numbers`] counts them.
    pub index: usize,
    /// The file found for this slot, if any.
    pub path: Option<PathBuf>,
    pub status: DataVolumeStatus,
    /// Where a restore would write this volume when it is not `Valid` (equal
    /// to `path` for a valid volume).
    pub output_path: PathBuf,
    /// The `.bad` name a restore would move an invalid file to before
    /// rebuilding it. `None` when there is no file to move, or when the file
    /// is not the one at `output_path`: a restore leaves such a file where it
    /// is and writes the rebuilt volume to `output_path`.
    pub set_aside_path: Option<PathBuf>,
}

/// One `.rev` of a [`RestorePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryVolumePlan {
    /// Zero-based recovery slot, `volume_number - data_count`: RAR5
    /// `rec_num - data_count`, RAR3 `rec_position - 1`. A RAR5 volume
    /// numbered among the data volumes has slot 0, and a RAR3 one numbered
    /// past the set's recovery volumes a slot from `recovery_count` up;
    /// neither is usable.
    pub slot: usize,
    /// Zero-based position of the volume in the whole set, data volumes
    /// first: RAR5 `rec_num`, RAR3 `data_count + rec_position - 1`.
    pub volume_number: usize,
    pub path: PathBuf,
    pub status: RevTestStatus,
    /// Header consistent with the set, numbered within its recovery slots,
    /// and payload CRC ok. A RAR 3.0-style volume has a consistent name and
    /// no CRC to test, and is usable, as the restore uses it.
    pub usable: bool,
}

/// What [`restore_volumes_from_paths`] would do with the same paths and
/// options, worked out by [`plan_volume_restore`] without writing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestorePlan {
    /// `Rar5`, or `Rar4` for a set with RAR3-style `.rev` volumes, as
    /// [`RecoveryReport::format`] reports it.
    pub format: ArchiveFormat,
    /// Data volumes in the set, as its recovery volumes state it.
    pub data_count: usize,
    /// Recovery volumes in the set, present or not.
    pub recovery_count: usize,
    /// One entry per data volume, in volume order.
    pub data_volumes: Vec<DataVolumePlan>,
    /// Every `.rev` of the set a restore finds, in the order it takes them
    /// (the given paths, then the ones found beside them, in name order),
    /// with `usable` false for one it passes over: a failed CRC32, or a
    /// number outside the set's recovery slots. A `.rev` whose header, or
    /// RAR 3.0-style name, states no set RAR could have written is not
    /// listed, nor is a RAR3 one whose footer fails its CRC32 and states
    /// another set; [`test_recovery_volumes`] reports on any path.
    pub recovery_volumes: Vec<RecoveryVolumePlan>,
    /// The directory a restore writes rebuilt volumes to:
    /// [`RecoveryOptions::output_dir`], else the first path's directory.
    pub output_dir: PathBuf,
}

impl RestorePlan {
    /// The index of every data volume that is not `Valid`: what a restore
    /// would rebuild, listed as [`RecoveryReport::missing_volume_numbers`]
    /// lists them.
    pub fn missing_volume_numbers(&self) -> Vec<usize> {
        self.data_volumes
            .iter()
            .filter(|volume| volume.status != DataVolumeStatus::Valid)
            .map(|volume| volume.index)
            .collect()
    }

    /// How many usable recovery volumes a restore needs: one per data volume
    /// that is not `Valid`.
    pub fn needed(&self) -> usize {
        self.data_volumes
            .iter()
            .filter(|volume| volume.status != DataVolumeStatus::Valid)
            .count()
    }

    /// How many recovery slots hold a usable volume.
    pub fn usable_recovery_count(&self) -> usize {
        let mut slots = self
            .recovery_volumes
            .iter()
            .filter(|volume| volume.usable)
            .map(|volume| volume.slot)
            .collect::<Vec<_>>();
        slots.sort_unstable();
        slots.dedup();
        slots.len()
    }

    /// Whether every data volume is `Valid`, so a restore has nothing to
    /// rebuild.
    pub fn is_complete(&self) -> bool {
        self.needed() == 0
    }

    /// Whether the usable recovery volumes cover every data volume that is
    /// not `Valid`, so a restore can rebuild them all.
    pub fn is_sufficient(&self) -> bool {
        self.needed() <= self.usable_recovery_count()
    }
}

/// Restore missing volume bytes from existing RAR recovery volumes.
///
/// This reconstructs volumes from recovery data. It does not author, compress,
/// build, or otherwise create new RAR archives.
///
/// The set is the one the given paths belong to. Beside each given path, the
/// files whose names have the set's base name and numbering scheme are taken
/// as its volumes, and no others. A given path that is not named as one of
/// the set's volumes, and a second file for a volume another file already
/// fills, are errors naming the paths, so a restore never renames or writes
/// a file that is not the set's.
pub fn restore_volumes_from_paths(
    paths: &[PathBuf],
    options: &RecoveryOptions,
) -> RarResult<RecoveryReport> {
    match survey_recovery_set(paths, options)? {
        RecoverySet::Rar5(set) => restore_rar5(set, options),
        RecoverySet::Rar3(set) => restore_rar3(set, options),
    }
}

/// Work out what [`restore_volumes_from_paths`] would do with the same paths
/// and options, without doing any of it.
///
/// Read-only: files are opened for reading, and nothing is written, renamed
/// or created, not even the output directory. Discovery, slot assignment,
/// validity rules and output naming are the restore's own, from the helpers
/// it calls, so [`RestorePlan::missing_volume_numbers`] are the volumes the
/// restore would rebuild and their `output_path`s are the paths it would
/// report in [`RecoveryReport::restored_paths`]. Every data volume is checked
/// in full, side by side: a RAR5 volume's size and then its CRC32 against the
/// `.rev` table, a RAR3 volume's headers through to its end-of-archive header
/// and the data CRC that header states.
///
/// A set short of usable recovery volumes is not an error here, as it is for
/// the restore: [`RestorePlan::is_sufficient`] reports it, with the counts.
/// That includes a set whose every `.rev` fails its CRC32, which lists them
/// as unusable.
///
/// # Errors
///
/// The errors the restore raises before it decides whether the set is
/// sufficient, with the same messages: no paths; no recovery volumes found;
/// only an embedded recovery record present; recovery volumes from different
/// sets; a given path not named as one of the set's volumes, or naming a
/// data volume past the set's count; two files for one volume; a RAR5 set
/// whose names carry no volume number; a RAR3 set over 255 volumes, or
/// without a data volume whose main header reads; and I/O errors.
///
/// The plan does not foresee what depends on the output names when the
/// restore runs: without [`RecoveryOptions::overwrite_existing`] the restore
/// refuses an existing output or `.bad` backup, and a file that changes
/// between the plan and the restore is judged as it is then.
pub fn plan_volume_restore(paths: &[PathBuf], options: &RecoveryOptions) -> RarResult<RestorePlan> {
    match survey_recovery_set(paths, options)? {
        RecoverySet::Rar5(set) => plan_rar5(set),
        RecoverySet::Rar3(set) => plan_rar3(set),
    }
}

/// Test each path as a recovery volume, the check reference UnRAR makes when
/// it tests a `.rev` file: the header must parse, and the CRC32 it states
/// must match the bytes it covers, which for RAR5 are everything after the
/// header and for a RAR3 volume everything before its trailing CRC32. The
/// signature decides the format, so a RAR5 signature over a header that does
/// not parse is [`RevTestStatus::InvalidHeader`]. A RAR3 `.rev` has no
/// signature and is recognised by the set parameters in its footer: ones RAR
/// could not have written make it `InvalidHeader`, whatever its CRC32. A
/// RAR 3.0-style name without a RAR5 signature is
/// [`RevTestStatus::Unverifiable`], whatever numbers it carries.
///
/// Exactly the given paths are tested, in order, each opened and read once.
/// Unlike [`restore_volumes_from_paths`], nothing is discovered beside them,
/// no path is checked against a set, and nothing is written. The files are
/// read side by side.
///
/// # Errors
///
/// None: every path's outcome is in its own result. A path that does not
/// exist is [`RevTestStatus::Missing`], and one that cannot be opened or read
/// is [`RevTestStatus::Unreadable`], so one bad path never hides the others'
/// results.
pub fn test_recovery_volumes(paths: &[PathBuf]) -> RarResult<Vec<RevTestResult>> {
    Ok(par_map_in_order(paths, |path| test_recovery_volume(path)))
}

/// [`test_recovery_volumes`] for one path.
fn test_recovery_volume(path: &Path) -> RevTestResult {
    let (format, status) = if !is_rev_path(path) {
        (None, RevTestStatus::NotRecoveryVolume)
    } else {
        match test_rev(path) {
            Ok(outcome) => outcome,
            Err(RarError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                (None, RevTestStatus::Missing)
            }
            Err(RarError::Io(error)) => (None, RevTestStatus::Unreadable { kind: error.kind() }),
            Err(_) => (None, RevTestStatus::InvalidHeader),
        }
    };
    RevTestResult {
        path: path.to_path_buf(),
        format,
        status,
    }
}

/// Open the `.rev` at `path` once and test it through that one handle: its
/// header or footer, then the CRC32 of the bytes it covers.
fn test_rev(path: &Path) -> RarResult<(Option<ArchiveFormat>, RevTestStatus)> {
    let file = File::open(path).map_err(RarError::from)?;
    Ok(match read_rev(file, path)? {
        RevRead::Rar5 { payload, .. } => (Some(ArchiveFormat::Rar5), rar5_rev_status(&payload)?.0),
        RevRead::Rar3 { header, payload } => {
            let rev = Rar3Rev {
                header,
                crc: rar3_rev_crc(&payload)?,
            };
            (Some(ArchiveFormat::Rar4), rev.test_status())
        }
        RevRead::Rar3Old => (Some(ArchiveFormat::Rar4), RevTestStatus::Unverifiable),
        RevRead::BrokenRar5 | RevRead::Unrecognised => (None, RevTestStatus::InvalidHeader),
    })
}

/// A recovery set as restore and plan both see it before either decides
/// anything: what fills each slot, and where each rebuilt volume goes.
enum RecoverySet {
    Rar5(Rar5Set),
    Rar3(Rar3Set),
}

/// The recovery-volume format a `.rev` counts toward when a set's format is
/// chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevFormat {
    Rar5,
    Rar3,
}

/// Expand `paths` to the whole set, read every `.rev` among them once, choose
/// the set's format, and place its volumes. This is the first step of both a
/// restore and a plan, and where both refuse a set they cannot work from.
///
/// A `.rev` that was given decides the format before one that was found
/// beside it, and a RAR5 one before a RAR3 one, as reference UnRAR takes the
/// format from the name it is given.
fn survey_recovery_set(paths: &[PathBuf], options: &RecoveryOptions) -> RarResult<RecoverySet> {
    if paths.is_empty() {
        return Err(RarError::CorruptArchive {
            detail: "RAR recovery restore requires at least one path".into(),
        });
    }
    let candidates = expand_recovery_paths(paths)?;

    // Every `.rev` is opened once and its header or footer read, side by
    // side. Its payload is hashed later through the same handle, and only
    // once it is known to be the set's. The results are taken in candidate
    // order, which keeps the first error the one a serial scan would have
    // hit.
    let reads = par_map_in_order(&candidates, |candidate| {
        if is_rev_path(&candidate.path) {
            read_rev_path(&candidate.path).map(Some)
        } else {
            Ok(None)
        }
    })
    .into_iter()
    .collect::<RarResult<Vec<_>>>()?;

    let format = [
        (true, RevFormat::Rar5),
        (true, RevFormat::Rar3),
        (false, RevFormat::Rar5),
        (false, RevFormat::Rar3),
    ]
    .into_iter()
    .find(|&(given, format)| {
        candidates.iter().zip(&reads).any(|(candidate, read)| {
            candidate.given == given && rev_read_format(candidate, read.as_ref()) == Some(format)
        })
    })
    .map(|(_, format)| format);
    match format {
        Some(RevFormat::Rar5) => {
            return survey_rar5_set(&candidates, reads, options).map(RecoverySet::Rar5);
        }
        Some(RevFormat::Rar3) => {
            return survey_rar3_set(&candidates, reads, options).map(RecoverySet::Rar3);
        }
        None => {}
    }

    if let Some(source) = first_embedded_recovery_record_path(&candidates)? {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "embedded {:?} recovery record detected in {}, but this API restores standalone .rev recovery volumes only and does not consume embedded RR/protect data",
                source.format,
                source.path.display()
            ),
        });
    }

    Err(RarError::CorruptArchive {
        detail: "no valid RAR recovery volumes were found".into(),
    })
}

/// The format a `.rev` read counts toward: a RAR5 header, or a RAR3 footer or
/// RAR 3.0-style name whose numbers RAR could have written.
fn rev_read_format(candidate: &Candidate, read: Option<&RevRead>) -> Option<RevFormat> {
    match read? {
        RevRead::Rar5 { .. } => Some(RevFormat::Rar5),
        RevRead::Rar3 { .. } => Some(RevFormat::Rar3),
        RevRead::Rar3Old => parse_old_rar3_rev_name(&candidate.path).map(|_| RevFormat::Rar3),
        RevRead::BrokenRar5 | RevRead::Unrecognised => None,
    }
}

/// `items.iter().map(map).collect()`, run on rayon where the build has
/// worker threads. The results keep the order of `items`, so a caller that
/// walks them in order sees the same first error a serial loop would.
fn par_map_in_order<T, R, F>(items: &[T], map: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync + Send,
{
    if items.len() > 1 && reedsolomon_rs::threading::parallel_enabled() {
        items.par_iter().map(map).collect()
    } else {
        items.iter().map(map).collect()
    }
}

/// A path a restore or plan works from: one it was given, or one found
/// beside a given path.
#[derive(Debug, Clone)]
struct Candidate {
    path: PathBuf,
    given: bool,
}

/// The given paths, each once and in order, then every file found beside
/// them whose name starts as a given path's does. Each directory is listed
/// once, and what is found in it is taken in name order, so the result does
/// not depend on the order a directory lists its entries in.
fn expand_recovery_paths(paths: &[PathBuf]) -> RarResult<Vec<Candidate>> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            candidates.push(Candidate {
                path: path.clone(),
                given: true,
            });
        }
    }

    let mut directories: Vec<(&Path, Vec<String>)> = Vec::new();
    for path in paths {
        let Some(prefix) = recovery_discovery_prefix(path) else {
            continue;
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        match directories.iter_mut().find(|(dir, _)| *dir == parent) {
            Some((_, prefixes)) => {
                if !prefixes.contains(&prefix) {
                    prefixes.push(prefix);
                }
            }
            None => directories.push((parent, vec![prefix])),
        }
    }

    for (parent, prefixes) in directories {
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(RarError::from(err)),
        };
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(RarError::from)?;
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let candidate = entry.path();
            if prefixes
                .iter()
                .any(|prefix| recovery_candidate_matches_prefix(&candidate, prefix))
            {
                found.push(candidate);
            }
        }
        found.sort();
        for path in found {
            if seen.insert(path.clone()) {
                candidates.push(Candidate { path, given: false });
            }
        }
    }

    Ok(candidates)
}

fn recovery_discovery_prefix(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_string_lossy();
    if is_rev_path(path) && !rar3_rev_uses_new_style_footer(path) {
        let trimmed = stem.trim_end_matches(|ch: char| ch.is_ascii_digit() || ch == '_');
        return (!trimmed.is_empty()).then(|| trimmed.to_string());
    }
    if let Some((start, _)) = rar_volume_digit_run(&stem) {
        let prefix = &stem[..start];
        return (!prefix.is_empty()).then(|| prefix.to_string());
    }
    (!stem.is_empty()).then(|| stem.to_string())
}

fn recovery_candidate_matches_prefix(path: &Path, prefix: &str) -> bool {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().starts_with(prefix))
        .unwrap_or(false)
}

/// What one read of a `.rev`'s header or footer found. A recovery volume's
/// payload is left in `payload`, to be hashed through the same handle only
/// once the volume is known to be wanted, so a `.rev` that is not the set's
/// is never read past its header or footer.
enum RevRead {
    /// A RAR5 recovery volume, by its header.
    Rar5 {
        header: Rar5RevHeader,
        payload: RevPayload,
    },
    /// A RAR3 recovery volume, by the set parameters in its footer.
    Rar3 {
        header: Rar3RevHeader,
        payload: RevPayload,
    },
    /// A RAR 3.0-style `name<d>_<r>_<p>.rev`: the name is all it states.
    Rar3Old,
    /// A RAR5 signature over a header that does not parse.
    BrokenRar5,
    /// Nothing this crate recognises as a recovery volume.
    Unrecognised,
}

/// The bytes a `.rev`'s CRC32 covers, still to be read through the handle
/// its header or footer was read from: `len` bytes, or up to the end of the
/// file, from `start`, or from where that read stopped when `start` is
/// `None`.
struct RevPayload {
    file: File,
    start: Option<u64>,
    len: u64,
    expected: u32,
}

impl RevPayload {
    /// The payload's CRC32 and the bytes it covered, from one read through
    /// it: the count is what the read found, so a RAR5 payload's length
    /// needs no other call on the file.
    fn hash(&self) -> RarResult<(u32, u64)> {
        let mut file = &self.file;
        if let Some(start) = self.start {
            file.seek(SeekFrom::Start(start)).map_err(RarError::from)?;
        }
        let mut payload = file.take(self.len);
        let actual = crc32_stream(&mut payload, self.len)?;
        Ok((actual, self.len - payload.limit()))
    }

    /// `None` when the payload's CRC32 is the one the volume states, else
    /// the stated and the computed CRC32.
    fn mismatch(&self) -> RarResult<Option<(u32, u32)>> {
        let (actual, _) = self.hash()?;
        Ok((actual != self.expected).then_some((self.expected, actual)))
    }
}

/// What a RAR5 `.rev`'s payload CRC32 says about it, and the payload's
/// length: the recovery data it carries.
fn rar5_rev_status(payload: &RevPayload) -> RarResult<(RevTestStatus, u64)> {
    let (actual, carried) = payload.hash()?;
    let status = if actual == payload.expected {
        RevTestStatus::Ok
    } else {
        RevTestStatus::CrcMismatch {
            expected: payload.expected,
            actual,
        }
    };
    Ok((status, carried))
}

/// What a RAR3 `.rev`'s footer CRC32 says about it.
fn rar3_rev_crc(payload: &RevPayload) -> RarResult<Rar3RevCrc> {
    Ok(match payload.mismatch()? {
        None => Rar3RevCrc::Matched,
        Some((expected, actual)) => Rar3RevCrc::Mismatch { expected, actual },
    })
}

/// [`read_rev`] for a path. A file gone since it was listed reads as nothing
/// recognisable.
fn read_rev_path(path: &Path) -> RarResult<RevRead> {
    match File::open(path) {
        Ok(file) => read_rev(file, path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(RevRead::Unrecognised),
        Err(err) => Err(RarError::from(err)),
    }
}

/// Read a `.rev`'s header from the start of `file`: its RAR5 header; or,
/// without a RAR5 signature, the RAR 3.0-style name, or else the RAR3 footer
/// in its last seven bytes. A footer whose set parameters RAR could not have
/// written is not read further. The payload is left unread in the returned
/// [`RevPayload`].
fn read_rev(mut file: File, path: &Path) -> RarResult<RevRead> {
    let mut prefix = [0u8; REV5_PREFIX_LEN];
    let read = read_padded(&mut file, &mut prefix)?;
    if read >= REV5_SIGN.len() && prefix[..REV5_SIGN.len()] == *REV5_SIGN {
        if read < REV5_PREFIX_LEN {
            return Ok(RevRead::BrokenRar5);
        }
        let Some(header) = read_rar5_rev_header(&mut file, &prefix)? else {
            return Ok(RevRead::BrokenRar5);
        };
        // The payload runs from the end of the header, where the read now
        // stands, to the end of the file.
        let expected = header.rev_crc;
        return Ok(RevRead::Rar5 {
            header,
            payload: RevPayload {
                file,
                start: None,
                len: u64::MAX,
                expected,
            },
        });
    }
    if !rar3_rev_uses_new_style_footer(path) {
        return Ok(RevRead::Rar3Old);
    }

    // The footer is the last seven bytes: three set parameters, then the
    // CRC32 of everything before the CRC. The volume is streamed through the
    // CRC rather than read whole into memory.
    let len = file.metadata().map_err(RarError::from)?.len();
    if len < 7 {
        return Ok(RevRead::Unrecognised);
    }
    let mut footer = [0u8; 7];
    file.seek(SeekFrom::Start(len - 7))
        .map_err(RarError::from)?;
    if read_padded(&mut file, &mut footer)? < footer.len() {
        return Ok(RevRead::Unrecognised);
    }
    let Some((header, expected)) = parse_rar3_rev_footer(footer) else {
        return Ok(RevRead::Unrecognised);
    };
    Ok(RevRead::Rar3 {
        header,
        payload: RevPayload {
            file,
            start: Some(0),
            len: len - 4,
            expected,
        },
    })
}

/// The set a new-style RAR3 `.rev` footer states, and the CRC32 it stores:
/// the data volume count, the recovery volume count and this volume's
/// position among the recovery volumes, each stored less one, then the
/// CRC32 of every byte before it, little-endian. `None` for parameters RAR
/// could not have written, which reference UnRAR passes over.
fn parse_rar3_rev_footer(footer: [u8; 7]) -> Option<(Rar3RevHeader, u32)> {
    let data_count = footer[0] as usize + 1;
    let rec_count = footer[1] as usize + 1;
    let rec_position = footer[2] as usize + 1;
    if data_count + rec_count > 255 || data_count + rec_position - 1 > 255 {
        return None;
    }
    let header = Rar3RevHeader {
        rec_position,
        rec_count,
        data_count,
        new_style: true,
    };
    Some((header, le_u32(&footer[3..])))
}

/// A volume name split around its volume number, `head` `digits` `tail` `.`
/// `ext`, as in `name.part` `07` `` `.` `rar`. A name whose number starts it
/// has no head, and is not a volume name RAR writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NumberedName {
    head: String,
    digits: String,
    tail: String,
    ext: String,
}

impl NumberedName {
    fn of(path: &Path) -> Option<Self> {
        let stem = path.file_stem()?.to_string_lossy();
        let (start, end) = rar_volume_digit_run(&stem)?;
        if start == 0 {
            return None;
        }
        Some(Self {
            head: stem[..start].to_string(),
            digits: stem[start..end].to_string(),
            tail: stem[end..].to_string(),
            ext: path
                .extension()
                .map(|ext| ext.to_string_lossy().into_owned())
                .unwrap_or_default(),
        })
    }

    /// Whether this name has `pattern`'s name around its number, ignoring
    /// ASCII case as RAR does on a case-insensitive file system.
    fn fits(&self, pattern: &NumberedName) -> bool {
        self.head.eq_ignore_ascii_case(&pattern.head)
            && self.tail.eq_ignore_ascii_case(&pattern.tail)
    }

    /// The volume number, when this name prints it the way a set whose
    /// numbers are `width` digits wide does: zero-padded to `width`, or
    /// longer without a leading zero once it outgrows that width, as RAR's
    /// next-volume naming grows it.
    fn number(&self, width: usize) -> Option<usize> {
        let canonical = self.digits.len() == width
            || (self.digits.len() > width && !self.digits.starts_with('0'));
        canonical.then(|| self.digits.parse().ok()).flatten()
    }

    /// This name's head and tail around `number` printed `width` digits wide,
    /// with `ext`.
    fn with_number(&self, number: usize, width: usize, ext: &str) -> String {
        format!("{}{number:0width$}{}.{ext}", self.head, self.tail)
    }
}

/// The widths a printed volume number allows its set's numbers: exactly its
/// own length when it has a leading zero, else any width up to its length.
fn volume_number_widths(digits: &str) -> (usize, usize) {
    if digits.len() > 1 && digits.starts_with('0') {
        (digits.len(), digits.len())
    } else {
        (1, digits.len())
    }
}

/// The digit width of a set's volume numbers. Every name in `musts` must
/// allow it; the names in `hints` narrow it where they can, in order, and one
/// that would contradict what is settled is passed over. The widest width
/// left is the set's, so a set whose names all print the number without a
/// leading zero counts from `1`. `Err` holds the position in `musts` of the
/// first name that contradicts those before it.
fn volume_number_width<'a>(
    musts: impl IntoIterator<Item = &'a str>,
    hints: impl IntoIterator<Item = &'a str>,
) -> Result<usize, usize> {
    let narrow = |(low, high): (usize, usize), digits: &str| {
        let (min, max) = volume_number_widths(digits);
        let narrowed = (low.max(min), high.min(max));
        (narrowed.0 <= narrowed.1).then_some(narrowed)
    };
    let mut widths = (1, usize::MAX);
    for (position, digits) in musts.into_iter().enumerate() {
        widths = narrow(widths, digits).ok_or(position)?;
    }
    for digits in hints {
        if let Some(narrowed) = narrow(widths, digits) {
            widths = narrowed;
        }
    }
    Ok(if widths.1 == usize::MAX { 1 } else { widths.1 })
}

/// `value` without `prefix`, ignoring ASCII case.
fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

/// Give a slot to candidate `index`, unless another file holds it: the same
/// file under a second spelling is taken once (`Ok(false)`), and a different
/// one is an error naming both.
fn claim_slot(
    slot: &mut Option<usize>,
    index: usize,
    candidates: &[Candidate],
    what: impl FnOnce() -> String,
) -> RarResult<bool> {
    match *slot {
        None => {
            *slot = Some(index);
            Ok(true)
        }
        Some(held) if same_existing_file(&candidates[held].path, &candidates[index].path)? => {
            Ok(false)
        }
        Some(held) => Err(RarError::CorruptArchive {
            detail: format!(
                "{} and {} both claim {}",
                candidates[held].path.display(),
                candidates[index].path.display(),
                what()
            ),
        }),
    }
}

/// The error for a given path that is not named as a volume of the set
/// `set_name` names.
fn foreign_volume_error(path: &Path, set_name: &Path) -> RarError {
    RarError::CorruptArchive {
        detail: format!(
            "{} is not named as a volume of the recovery set of {}",
            path.display(),
            set_name.display()
        ),
    }
}

/// The error for a given path whose name numbers a data volume the set does
/// not have.
fn volume_out_of_range_error(path: &Path, number: usize, data_count: usize) -> RarError {
    RarError::CorruptArchive {
        detail: format!(
            "{} names data volume {number}, but its recovery set has {data_count} data volumes",
            path.display()
        ),
    }
}

/// The file name of `path`, unchanged, for an output beside it.
fn file_name_of(path: &Path) -> &std::ffi::OsStr {
    path.file_name().unwrap_or(path.as_os_str())
}

fn has_rar_extension(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("rar"))
}

#[derive(Debug, Clone)]
struct EmbeddedRecoverySource {
    path: PathBuf,
    format: ArchiveFormat,
}

#[derive(Debug, Clone)]
struct Rar5RevHeader {
    data_count: usize,
    rec_count: usize,
    rec_num: usize,
    rev_crc: u32,
    data_offset: u64,
    data_volumes: Option<Vec<Rar5DataVolumeInfo>>,
}

#[derive(Debug, Clone)]
struct Rar5DataVolumeInfo {
    file_size: u64,
    crc32: u32,
}

#[derive(Debug, Clone)]
struct Rar5DataSlot {
    path: Option<PathBuf>,
    output_path: PathBuf,
    file_size: u64,
    crc32: u32,
    valid: bool,
}

#[derive(Debug, Clone)]
struct Rar5RecoverySlot {
    path: Option<PathBuf>,
    data_offset: u64,
    valid: bool,
}

/// A RAR5 set as restore and plan both see it before either reads a data
/// volume's bytes: what fills each slot, and where a restore would write
/// each data volume.
struct Rar5Set {
    rec_count: usize,
    data_slots: Vec<Rar5DataSlot>,
    recovery_slots: Vec<Rar5RecoverySlot>,
    /// Every `.rev` of the set whose header parses, in the order the survey
    /// takes them, the ones a restore passes over included.
    recovery_volumes: Vec<RecoveryVolumePlan>,
    output_dir: PathBuf,
}

/// Place a RAR5 set's volumes by name, as reference UnRAR does, and name
/// each data volume's output. Restore and plan both start here, so they
/// place and name every volume alike and refuse the same sets.
///
/// The set's name is the one the first given `.rev` or `.rar` prints around
/// its volume number, `name.part` `NN` `.rar`, and the set is the one the
/// first `.rev` of that name with a data volume table describes. A data
/// volume is a file whose name prints its number in the set's name, at the
/// set's digit width. Nothing in a data volume is read here: one whose
/// headers are damaged, or that is too short to have any, is placed like any
/// other and judged by its size and CRC32. A `.rev` of the set's name is
/// placed by the number its header states. A given path not named as one of
/// the set's volumes, or naming a data volume past its count, is an error,
/// and a file found beside the given paths is passed over instead; two files
/// for one volume are an error.
fn survey_rar5_set(
    candidates: &[Candidate],
    reads: Vec<Option<RevRead>>,
    options: &RecoveryOptions,
) -> RarResult<Rar5Set> {
    let names = candidates
        .iter()
        .map(|candidate| NumberedName::of(&candidate.path))
        .collect::<Vec<_>>();
    let rar5_revs = reads
        .iter()
        .map(|read| matches!(read, Some(RevRead::Rar5 { .. })))
        .collect::<Vec<_>>();
    let first_rar5_rev =
        rar5_revs
            .iter()
            .position(|&rar5| rar5)
            .ok_or_else(|| RarError::CorruptArchive {
                detail: "no valid RAR recovery volumes were found".into(),
            })?;
    let unnumbered = || RarError::CorruptArchive {
        detail: format!(
            "RAR5 recovery volume {} has no volume number in its name",
            candidates[first_rar5_rev].path.display()
        ),
    };

    // The set's name, from the first given path that carries one, as
    // reference UnRAR takes it from the name it is given; from the first
    // file found beside them when none does.
    let (source, pattern) = [true, false]
        .into_iter()
        .find_map(|given| {
            (0..candidates.len()).find_map(|index| {
                let name = names[index].as_ref()?;
                let names_a_volume = rar5_revs[index]
                    || (reads[index].is_none() && has_rar_extension(&candidates[index].path));
                (candidates[index].given == given && names_a_volume).then_some((index, name))
            })
        })
        .ok_or_else(unnumbered)?;
    let source_path = &candidates[source].path;
    let fits = |index: usize| names[index].as_ref().is_some_and(|name| name.fits(pattern));

    let defining = (0..candidates.len()).find_map(|index| match &reads[index] {
        Some(RevRead::Rar5 { header, .. }) if fits(index) => header
            .data_volumes
            .as_ref()
            .map(|table| (header.data_count, header.rec_count, table.clone())),
        _ => None,
    });
    let Some((data_count, rec_count, table)) = defining else {
        if (0..candidates.len()).any(|index| rar5_revs[index] && fits(index)) {
            return Err(RarError::CorruptArchive {
                detail: "RAR5 recovery set is missing data volume metadata".into(),
            });
        }
        if names[first_rar5_rev].is_none() {
            return Err(unnumbered());
        }
        return Err(foreign_volume_error(
            source_path,
            &candidates[first_rar5_rev].path,
        ));
    };

    // The data volumes: every file named in the set's name with a `.rar`
    // extension, or with another one over an SFX stub, as reference UnRAR
    // takes them. A given `.rar` named otherwise is not the set's.
    let mut data_members = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if reads[index].is_some() {
            continue;
        }
        if !fits(index) {
            if candidate.given && has_rar_extension(&candidate.path) {
                return Err(foreign_volume_error(&candidate.path, source_path));
            }
            continue;
        }
        let member = has_rar_extension(&candidate.path)
            || match rar5_recovery_data_candidate_allowed(&candidate.path) {
                Ok(allowed) => allowed,
                Err(error) if candidate.given => return Err(error),
                Err(_) => false,
            };
        if member {
            data_members.push(index);
        }
    }

    // The width the set prints its numbers at: the given data volumes'
    // names must agree on it, and the names found beside them and the
    // recovery volumes' names narrow it where they can.
    let digits = |index: usize| {
        names[index]
            .as_ref()
            .map_or("", |name| name.digits.as_str())
    };
    let given_members = data_members
        .iter()
        .copied()
        .filter(|&index| candidates[index].given)
        .collect::<Vec<_>>();
    let found_digits = data_members
        .iter()
        .copied()
        .filter(|&index| !candidates[index].given)
        .chain((0..candidates.len()).filter(|&index| rar5_revs[index] && fits(index)))
        .map(digits);
    let width = volume_number_width(
        given_members.iter().map(|&index| digits(index)),
        found_digits,
    )
    .map_err(|position| {
        foreign_volume_error(&candidates[given_members[position]].path, source_path)
    })?;

    let mut data_claims = vec![None::<usize>; data_count];
    for &index in &data_members {
        let candidate = &candidates[index];
        let Some(number) = names[index].as_ref().and_then(|name| name.number(width)) else {
            if candidate.given {
                return Err(foreign_volume_error(&candidate.path, source_path));
            }
            continue;
        };
        if !(1..=data_count).contains(&number) {
            if candidate.given {
                return Err(volume_out_of_range_error(
                    &candidate.path,
                    number,
                    data_count,
                ));
            }
            continue;
        }
        claim_slot(&mut data_claims[number - 1], index, candidates, || {
            format!("data volume {number} of the recovery set")
        })?;
    }

    // Each `.rev` of the set's name is read through its payload's CRC32,
    // side by side; one named otherwise is never read past its header. The
    // results are taken in path order below, so an I/O error is the first a
    // serial pass would have hit.
    let mut statuses = par_map_in_order(
        &reads.iter().enumerate().collect::<Vec<_>>(),
        |&(index, read)| match read {
            Some(RevRead::Rar5 { payload, .. }) if fits(index) => Some(rar5_rev_status(payload)),
            _ => None,
        },
    );

    // The recovery volumes, placed by the number their headers state. One
    // numbered among the data volumes, or whose payload fails its CRC32, is
    // listed and not used.
    let mut recovery_slots = vec![
        Rar5RecoverySlot {
            path: None,
            data_offset: 0,
            valid: false,
        };
        rec_count
    ];
    let mut recovery_claims = vec![None::<usize>; rec_count];
    let mut recovery_volumes = Vec::new();
    for (index, read) in reads.into_iter().enumerate() {
        let Some(read) = read else {
            continue;
        };
        let candidate = &candidates[index];
        if !fits(index) {
            if candidate.given {
                return Err(foreign_volume_error(&candidate.path, source_path));
            }
            continue;
        }
        let RevRead::Rar5 { header, .. } = read else {
            continue;
        };
        let counts_mismatch = header.data_count != data_count || header.rec_count != rec_count;
        let table_mismatch = header
            .data_volumes
            .as_ref()
            .is_some_and(|volumes| volumes.len() != data_count);
        if counts_mismatch || table_mismatch {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "RAR5 recovery volume {} does not match the first recovery set",
                    candidate.path.display()
                ),
            });
        }
        let Some(status) = statuses[index].take() else {
            continue;
        };
        let (status, carried) = status?;
        let slot = header.rec_num.saturating_sub(data_count);
        let usable = status == RevTestStatus::Ok && header.rec_num >= data_count;
        if usable
            && !claim_slot(&mut recovery_claims[slot], index, candidates, || {
                format!("recovery volume {} of the recovery set", slot + 1)
            })?
        {
            continue;
        }
        // A missing volume is rebuilt at the length the table gives, from
        // the payloads of the usable `.rev`s, which RAR writes as long as the
        // longest volume. A table that gives a volume more than a usable
        // `.rev` carries is not the set's, and would have the restore write
        // past anything the `.rev`s hold.
        if usable
            && let Some((number, info)) = table
                .iter()
                .enumerate()
                .find(|(_, info)| info.file_size > carried)
        {
            return Err(RarError::CorruptArchive {
                detail: format!(
                    "RAR5 recovery volume {} carries {carried} bytes of recovery data, fewer than the {} bytes the set's table gives data volume {}",
                    candidate.path.display(),
                    info.file_size,
                    number + 1
                ),
            });
        }
        recovery_volumes.push(RecoveryVolumePlan {
            slot,
            volume_number: header.rec_num,
            path: candidate.path.clone(),
            status,
            usable,
        });
        if usable {
            recovery_slots[slot] = Rar5RecoverySlot {
                path: Some(candidate.path.clone()),
                data_offset: header.data_offset,
                valid: true,
            };
        }
    }

    // A missing volume is named as reference UnRAR names it: after the
    // first data volume the survey placed, with its extension as spelled
    // when it is `.rar` and `.rar` after an SFX stub; or, with no data
    // volume placed, after the longest name among the set's `.rev`s, with
    // `.rar` and that name's digit width.
    let output_dir = recovery_output_dir(candidates, options);
    let first_member = data_claims.iter().flatten().copied().min();
    let (model, model_width, ext) = match first_member.and_then(|index| names[index].as_ref()) {
        Some(name) => {
            let ext = if name.ext.eq_ignore_ascii_case("rar") {
                name.ext.clone()
            } else {
                "rar".to_string()
            };
            (name, width, ext)
        }
        None => {
            let longest = (0..candidates.len())
                .rev()
                .filter(|&index| rar5_revs[index] && fits(index))
                .filter_map(|index| names[index].as_ref())
                .max_by_key(|name| name.digits.len())
                .unwrap_or(pattern);
            (longest, longest.digits.len(), "rar".to_string())
        }
    };
    let data_slots = table
        .iter()
        .zip(&data_claims)
        .enumerate()
        .map(|(number, (info, claim))| {
            let path = claim.map(|index| candidates[index].path.clone());
            let output_path = match &path {
                Some(path) => output_dir.join(file_name_of(path)),
                None => output_dir.join(model.with_number(number + 1, model_width, &ext)),
            };
            Rar5DataSlot {
                path,
                output_path,
                file_size: info.file_size,
                crc32: info.crc32,
                valid: false,
            }
        })
        .collect();

    Ok(Rar5Set {
        rec_count,
        data_slots,
        recovery_slots,
        recovery_volumes,
        output_dir,
    })
}

fn restore_rar5(set: Rar5Set, options: &RecoveryOptions) -> RarResult<RecoveryReport> {
    let Rar5Set {
        rec_count,
        mut data_slots,
        recovery_slots,
        ..
    } = set;

    // When some volumes are absent or the wrong size and the recovery
    // volumes can cover exactly those, the decode itself reads every other
    // data volume, so it checks their CRC32s on the way through instead of a
    // separate pass reading them first. Only if they all match does it
    // touch anything; otherwise the verdicts it found feed the serial path.
    let size_ok = par_map_in_order(&data_slots, |slot| -> RarResult<bool> {
        Ok(matches!(
            rar5_data_volume_size_check(slot)?,
            Rar5SizeCheck::Matches(_)
        ))
    })
    .into_iter()
    .collect::<RarResult<Vec<_>>>();
    let valid_recovery_count = recovery_slots.iter().filter(|slot| slot.valid).count();
    let folded = match &size_ok {
        Ok(size_ok)
            if (1..=valid_recovery_count).contains(&size_ok.iter().filter(|&&ok| !ok).count()) =>
        {
            restore_rar5_folded(
                &mut data_slots,
                &recovery_slots,
                size_ok,
                rec_count,
                options,
            )?
        }
        _ => Rar5Folded::Unavailable,
    };

    let (missing_volume_numbers, restored) = match folded {
        Rar5Folded::Restored { missing, restored } => (missing, restored),
        Rar5Folded::Verdicts(verdicts) => {
            match restore_rar5_checked(
                &mut data_slots,
                &recovery_slots,
                verdicts.into_iter().map(Ok).collect(),
                rec_count,
                options,
            )? {
                Some(done) => done,
                None => return Ok(rar5_nothing_missing()),
            }
        }
        Rar5Folded::Unavailable => {
            // Each data volume is checked against the table (size, then
            // CRC32) on its own worker; the verdicts are applied in volume
            // order.
            let verdicts = par_map_in_order(&data_slots, |slot| {
                rar5_data_volume_status(slot).map(|status| status == DataVolumeStatus::Valid)
            });
            match restore_rar5_checked(
                &mut data_slots,
                &recovery_slots,
                verdicts,
                rec_count,
                options,
            )? {
                Some(done) => done,
                None => return Ok(rar5_nothing_missing()),
            }
        }
    };

    if options.verify_restored {
        for (&missing_idx, (path, actual)) in missing_volume_numbers.iter().zip(&restored) {
            let expected_crc = data_slots[missing_idx].crc32;
            if *actual != expected_crc {
                return Err(RarError::DataCrcMismatch {
                    member: path.display().to_string(),
                    expected: expected_crc,
                    actual: *actual,
                });
            }
        }
    }
    let restored_paths = restored.into_iter().map(|(path, _)| path).collect();

    let used_recovery_paths = recovery_slots
        .iter()
        .filter(|slot| slot.valid)
        .filter_map(|slot| slot.path.clone())
        .collect();

    Ok(RecoveryReport {
        format: ArchiveFormat::Rar5,
        restored_paths,
        used_recovery_paths,
        missing_volume_numbers,
    })
}

fn rar5_nothing_missing() -> RecoveryReport {
    RecoveryReport {
        format: ArchiveFormat::Rar5,
        restored_paths: Vec::new(),
        used_recovery_paths: Vec::new(),
        missing_volume_numbers: Vec::new(),
    }
}

/// [`plan_volume_restore`] for a RAR5 set.
fn plan_rar5(set: Rar5Set) -> RarResult<RestorePlan> {
    // Every data volume is checked in full, size then CRC32, on its own
    // worker, as the restore's checked path checks it. The verdicts are
    // taken in volume order, so an I/O error is the one the restore raises.
    let statuses = par_map_in_order(&set.data_slots, rar5_data_volume_status)
        .into_iter()
        .collect::<RarResult<Vec<_>>>()?;
    let data_volumes = set
        .data_slots
        .iter()
        .zip(statuses)
        .enumerate()
        .map(|(index, (slot, status))| {
            data_volume_plan(index, slot.path.clone(), status, slot.output_path.clone())
        })
        .collect::<RarResult<Vec<_>>>()?;
    Ok(RestorePlan {
        format: ArchiveFormat::Rar5,
        data_count: set.data_slots.len(),
        recovery_count: set.rec_count,
        data_volumes,
        recovery_volumes: set.recovery_volumes,
        output_dir: set.output_dir,
    })
}

/// What a RAR5 data volume's size, which costs no read of its bytes, says
/// about it.
enum Rar5SizeCheck<'a> {
    /// No file fills the slot, or the file's length differs from the `.rev`
    /// table: the verdict needs nothing more.
    Settled(DataVolumeStatus),
    /// The length matches the table; only the CRC32 of the file at this path
    /// can tell.
    Matches(&'a Path),
}

fn rar5_data_volume_size_check(slot: &Rar5DataSlot) -> RarResult<Rar5SizeCheck<'_>> {
    let Some(path) = &slot.path else {
        return Ok(Rar5SizeCheck::Settled(DataVolumeStatus::Missing));
    };
    // A file gone since it was listed is missing, as one never listed is.
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Rar5SizeCheck::Settled(DataVolumeStatus::Missing));
        }
        Err(err) => return Err(RarError::from(err)),
    };
    if metadata.is_dir() {
        return Err(RarError::Io(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            format!("{} is a directory", path.display()),
        )));
    }
    let actual = metadata.len();
    if actual != slot.file_size {
        return Ok(Rar5SizeCheck::Settled(DataVolumeStatus::WrongSize {
            expected: slot.file_size,
            actual,
        }));
    }
    Ok(Rar5SizeCheck::Matches(path))
}

/// A RAR5 data volume against its `.rev` table entry: its size, and then,
/// when that matches, the CRC32 of its bytes.
fn rar5_data_volume_status(slot: &Rar5DataSlot) -> RarResult<DataVolumeStatus> {
    let path = match rar5_data_volume_size_check(slot)? {
        Rar5SizeCheck::Settled(status) => return Ok(status),
        Rar5SizeCheck::Matches(path) => path,
    };
    let actual = match crc32_file_region(path, 0) {
        Ok(actual) => actual,
        Err(RarError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DataVolumeStatus::Missing);
        }
        Err(err) => return Err(err),
    };
    Ok(if actual == slot.crc32 {
        DataVolumeStatus::Valid
    } else {
        DataVolumeStatus::CrcMismatch
    })
}

/// One data volume's plan entry, from the file that fills its slot, its
/// verdict, and the path a restore writes it to when it is not valid. The
/// `.bad` name comes from [`set_aside_name`], the rule the restore's rename
/// follows.
fn data_volume_plan(
    index: usize,
    path: Option<PathBuf>,
    status: DataVolumeStatus,
    restore_output: PathBuf,
) -> RarResult<DataVolumePlan> {
    let path = path.filter(|_| status != DataVolumeStatus::Missing);
    if status == DataVolumeStatus::Valid
        && let Some(path) = &path
    {
        return Ok(DataVolumePlan {
            index,
            path: Some(path.clone()),
            status,
            output_path: path.clone(),
            set_aside_path: None,
        });
    }
    let set_aside_path = match &path {
        Some(path) => set_aside_name(path, &restore_output)?,
        None => None,
    };
    Ok(DataVolumePlan {
        index,
        path,
        status,
        output_path: restore_output,
        set_aside_path,
    })
}

/// The outcome of [`restore_rar5_folded`].
enum Rar5Folded {
    /// Every size-matching data volume matched its CRC32: the missing ones
    /// (by volume number) are restored, with the CRC32 of what was written.
    Restored {
        missing: Vec<usize>,
        restored: Vec<(PathBuf, u32)>,
    },
    /// Some size-matching data volume failed its CRC32. Nothing was renamed
    /// or left behind; these are every data volume's verdicts.
    Verdicts(Vec<bool>),
    /// The size-based shape is not one the decoder takes; nothing was read.
    Unavailable,
}

/// Restore on the assumption that every data volume of the right size is
/// intact, checking that assumption with the CRC32s the decode computes as
/// it reads them.
///
/// The decode writes to hidden partial files beside the outputs. Only once
/// every CRC32 has matched does the restore act, and then in the serial
/// path's order: bad volumes are renamed to `.bad`, existing outputs are
/// refused, and the partial files are moved into place. A CRC32 failure
/// removes the partial files and hands back the verdicts, so the serial path
/// renames and refuses exactly as it would have after its own checks.
fn restore_rar5_folded(
    data_slots: &mut [Rar5DataSlot],
    recovery_slots: &[Rar5RecoverySlot],
    size_ok: &[bool],
    rec_count: usize,
    options: &RecoveryOptions,
) -> RarResult<Rar5Folded> {
    let data_count = data_slots.len();
    let mut valid_flags = size_ok.to_vec();
    valid_flags.extend(recovery_slots.iter().map(|slot| slot.valid));
    let Some(coder) = Rar5RsCoder::new_decoder(data_count, rec_count, &valid_flags) else {
        return Ok(Rar5Folded::Unavailable);
    };
    for (slot, &ok) in data_slots.iter_mut().zip(size_ok) {
        slot.valid = ok;
    }
    let missing = (0..data_count).filter(|&i| !size_ok[i]).collect::<Vec<_>>();
    let mut partial_paths = Vec::with_capacity(missing.len());
    let mut partials = Vec::with_capacity(missing.len());
    let remove_paths = |paths: &[PathBuf]| {
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    };
    for &i in &missing {
        match create_partial(&data_slots[i].output_path) {
            Ok((path, file)) => {
                partial_paths.push(path.clone());
                partials.push((path, file));
            }
            Err(error) => {
                drop(partials);
                remove_paths(&partial_paths);
                return Err(error);
            }
        }
    }
    let remove_partials = || remove_paths(&partial_paths);

    let pass = match reconstruct_rar5(
        &coder,
        data_slots,
        recovery_slots,
        &missing,
        Rar5Outputs::Created(partials),
        true,
    ) {
        Ok(pass) => pass,
        Err(error) => {
            remove_partials();
            return Err(error);
        }
    };
    let verdicts = data_slots
        .iter()
        .zip(&pass.data_crcs)
        .map(|(slot, crc)| slot.valid && *crc == Some(slot.crc32))
        .collect::<Vec<_>>();
    if verdicts != size_ok {
        remove_partials();
        return Ok(Rar5Folded::Verdicts(verdicts));
    }

    let finish = (|| -> RarResult<()> {
        for &i in &missing {
            rename_invalid_rar5_data_volume(&mut data_slots[i], options)?;
        }
        for &i in &missing {
            let path = &data_slots[i].output_path;
            if path.exists() && !options.overwrite_existing {
                return Err(refuse_existing_restored(path));
            }
        }
        for (partial, &i) in partial_paths.iter().zip(&missing) {
            install_partial(
                partial,
                &data_slots[i].output_path,
                options.overwrite_existing,
            )?;
        }
        Ok(())
    })();
    if let Err(error) = finish {
        remove_partials();
        return Err(error);
    }

    let restored = missing
        .iter()
        .zip(pass.restored)
        .map(|(&i, (_, crc))| (data_slots[i].output_path.clone(), crc))
        .collect();
    Ok(Rar5Folded::Restored { missing, restored })
}

/// The missing data volume numbers, and each restored volume's path with the
/// CRC32 of what was written to it.
type Rar5Restored = (Vec<usize>, Vec<(PathBuf, u32)>);

/// The serial RAR5 path from known data-volume verdicts: refuse a set the
/// recovery volumes cannot cover, rename bad volumes, refuse existing
/// outputs, then decode. `None` when no data volume is missing.
fn restore_rar5_checked(
    data_slots: &mut [Rar5DataSlot],
    recovery_slots: &[Rar5RecoverySlot],
    verdicts: Vec<RarResult<bool>>,
    rec_count: usize,
    options: &RecoveryOptions,
) -> RarResult<Option<Rar5Restored>> {
    for (slot, valid) in data_slots.iter_mut().zip(verdicts) {
        slot.valid = valid?;
    }
    let data_count = data_slots.len();

    let missing_volume_numbers = data_slots
        .iter()
        .enumerate()
        .filter_map(|(idx, slot)| (!slot.valid).then_some(idx))
        .collect::<Vec<_>>();
    if missing_volume_numbers.is_empty() {
        return Ok(None);
    }

    let valid_recovery_count = recovery_slots.iter().filter(|slot| slot.valid).count();
    if missing_volume_numbers.len() > valid_recovery_count {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "insufficient RAR5 recovery volumes: need {}, have {}",
                missing_volume_numbers.len(),
                valid_recovery_count
            ),
        });
    }

    for &missing_idx in &missing_volume_numbers {
        rename_invalid_rar5_data_volume(&mut data_slots[missing_idx], options)?;
    }

    for &missing_idx in &missing_volume_numbers {
        let path = &data_slots[missing_idx].output_path;
        if path.exists() && !options.overwrite_existing {
            return Err(refuse_existing_restored(path));
        }
    }

    let mut valid_flags = data_slots.iter().map(|slot| slot.valid).collect::<Vec<_>>();
    valid_flags.extend(recovery_slots.iter().map(|slot| slot.valid));
    let coder = Rar5RsCoder::new_decoder(data_count, rec_count, &valid_flags).ok_or_else(|| {
        RarError::CorruptArchive {
            detail: "failed to initialize RAR5 recovery decoder".into(),
        }
    })?;

    let output_paths = missing_volume_numbers
        .iter()
        .map(|&idx| data_slots[idx].output_path.clone())
        .collect::<Vec<_>>();
    let pass = reconstruct_rar5(
        &coder,
        data_slots,
        recovery_slots,
        &missing_volume_numbers,
        Rar5Outputs::Paths {
            paths: &output_paths,
            overwrite_existing: options.overwrite_existing,
        },
        false,
    )?;
    Ok(Some((missing_volume_numbers, pass.restored)))
}

fn refuse_existing_restored(path: &Path) -> RarError {
    RarError::CorruptArchive {
        detail: format!(
            "refusing to overwrite existing restored volume {}",
            path.display()
        ),
    }
}

/// Move a finished partial restore to `target`.
///
/// With `overwrite_existing` this is a plain rename, which replaces whatever
/// is at `target`. Without it the existence check the caller made earlier is
/// only advisory: a file created at `target` since then must still win. The
/// partial is therefore hard-linked to `target`, which the filesystem refuses
/// atomically when the name is taken, and the partial name is removed only
/// once the link stands. A taken name is refused like any other existing
/// output, and the file at it is left as it was.
///
/// A filesystem that cannot hard-link (FAT, some network shares) reports an
/// error other than `AlreadyExists`. There `target` is created exclusively,
/// which every filesystem refuses atomically when the name is taken, the
/// partial's bytes are copied into it, and the partial is removed. That costs
/// one extra copy of the volume on such filesystems but never a replaced file.
fn install_partial(partial: &Path, target: &Path, overwrite_existing: bool) -> RarResult<()> {
    if overwrite_existing {
        return std::fs::rename(partial, target).map_err(RarError::from);
    }
    match std::fs::hard_link(partial, target) {
        Ok(()) => std::fs::remove_file(partial).map_err(RarError::from),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(refuse_existing_restored(target))
        }
        Err(_) => copy_partial_exclusively(partial, target),
    }
}

/// Install `partial` at `target` by exclusive create and copy, for
/// filesystems without hard links. A name taken before or during the install
/// is refused and left as it was; a copy that fails part way removes the
/// incomplete `target` and keeps the partial for the caller's cleanup.
fn copy_partial_exclusively(partial: &Path, target: &Path) -> RarResult<()> {
    let mut output = match OpenOptions::new().write(true).create_new(true).open(target) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(refuse_existing_restored(target));
        }
        Err(error) => return Err(RarError::from(error)),
    };
    let copied = File::open(partial)
        .and_then(|mut input| std::io::copy(&mut input, &mut output))
        .and_then(|_| output.sync_all());
    drop(output);
    if let Err(error) = copied {
        let _ = std::fs::remove_file(target);
        return Err(RarError::from(error));
    }
    std::fs::remove_file(partial).map_err(RarError::from)
}

/// How many names [`create_partial`] tries before it gives up.
const PARTIAL_CREATE_ATTEMPTS: usize = 16;

/// Create a fresh hidden sibling of `output` for a speculative restore to
/// write before it knows the restore stands, returning its path and the file.
fn create_partial(output: &Path) -> RarResult<(PathBuf, File)> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(RarError::from)?;
    }
    create_exclusive(|| partial_restore_path(output))
}

/// Create the first of `next_path`'s names that does not exist yet. The
/// create is exclusive, so it never opens, truncates or follows a file or
/// symlink already at a name; such a name is skipped for the next one. The
/// file is open for reading as well, so a restore can read back what it
/// wrote through the same handle.
fn create_exclusive(mut next_path: impl FnMut() -> PathBuf) -> RarResult<(PathBuf, File)> {
    let mut last_error = None;
    for _ in 0..PARTIAL_CREATE_ATTEMPTS {
        let path = next_path();
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(RarError::from(error)),
        }
    }
    Err(RarError::Io(last_error.unwrap_or_else(|| {
        std::io::Error::from(std::io::ErrorKind::AlreadyExists)
    })))
}

/// A hidden sibling name of `output` for a speculative restore. The process
/// id, a per-process counter and the clock's nanoseconds keep restores apart,
/// within a process and across processes, and make the name unpredictable
/// enough that [`create_exclusive`] rarely has to skip one.
fn partial_restore_path(output: &Path) -> PathBuf {
    static NEXT_PARTIAL: AtomicU64 = AtomicU64::new(0);
    let name = output
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let serial = NEXT_PARTIAL.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    output.with_file_name(format!(
        ".{name}.{}.{serial}.{nanos:09}.partial",
        std::process::id()
    ))
}

fn rename_invalid_rar5_data_volume(
    slot: &mut Rar5DataSlot,
    options: &RecoveryOptions,
) -> RarResult<()> {
    if slot.valid {
        return Ok(());
    }
    let Some(path) = slot.path.as_ref() else {
        return Ok(());
    };
    if rename_invalid_data_volume(path, &slot.output_path, options)? {
        slot.path = None;
    }
    Ok(())
}

fn rename_invalid_data_volume(
    invalid_path: &Path,
    output_path: &Path,
    options: &RecoveryOptions,
) -> RarResult<bool> {
    let Some(bad_path) = set_aside_name(invalid_path, output_path)? else {
        return Ok(false);
    };
    if bad_path.exists() {
        if options.overwrite_existing {
            std::fs::remove_file(&bad_path).map_err(RarError::from)?;
        } else {
            return Err(RarError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to overwrite existing bad-volume backup {}",
                    bad_path.display()
                ),
            )));
        }
    }

    std::fs::rename(invalid_path, bad_path).map_err(RarError::from)?;
    Ok(true)
}

/// The name an invalid data volume is moved to before a restore rebuilds it:
/// its own name with `.bad` appended, and only when it is the file at the
/// restore's output name. A volume anywhere else is left where it is, and
/// the rebuilt one is written to the output name beside it.
fn set_aside_name(invalid_path: &Path, output_path: &Path) -> RarResult<Option<PathBuf>> {
    Ok(same_existing_file(invalid_path, output_path)?.then(|| bad_volume_path(invalid_path)))
}

fn same_existing_file(left: &Path, right: &Path) -> RarResult<bool> {
    let left = match std::fs::canonicalize(left) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RarError::from(err)),
    };
    let right = match std::fs::canonicalize(right) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RarError::from(err)),
    };
    Ok(left == right)
}

fn bad_volume_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bad");
    PathBuf::from(name)
}

/// What one RAR5 decode pass produced.
struct Rar5Reconstruction {
    /// Each restored volume's path and the CRC32 of the bytes written to it.
    restored: Vec<(PathBuf, u32)>,
    /// When asked for, the CRC32 of every valid data volume the pass read,
    /// indexed by volume; `None` for the volumes it did not read.
    data_crcs: Vec<Option<u32>>,
}

/// Where [`reconstruct_rar5`] writes the restored volumes.
enum Rar5Outputs<'a> {
    /// Opened once the inputs are: each path is created, or with
    /// `overwrite_existing` truncated where it exists.
    Paths {
        paths: &'a [PathBuf],
        overwrite_existing: bool,
    },
    /// Files the caller already created, with their paths.
    Created(Vec<(PathBuf, File)>),
}

/// Rebuild the missing data volumes into `outputs` (one per entry of
/// `missing_volume_numbers`). With `hash_data`, every data volume the decode
/// reads is hashed on the way through, so a caller that trusted its size can
/// check it against the table without a second read.
fn reconstruct_rar5(
    coder: &Rar5RsCoder,
    data_slots: &[Rar5DataSlot],
    recovery_slots: &[Rar5RecoverySlot],
    missing_volume_numbers: &[usize],
    outputs: Rar5Outputs<'_>,
    hash_data: bool,
) -> RarResult<Rar5Reconstruction> {
    let missing_count = missing_volume_numbers.len();
    let data_count = data_slots.len();
    let max_volume_size = data_slots
        .iter()
        .map(|slot| slot.file_size)
        .max()
        .unwrap_or(0);
    let chunk_size = rar5_chunk_size(
        max_volume_size,
        data_count,
        missing_count,
        RAR5_TOTAL_BUFFER_SIZE,
    );

    let mut data_files = data_slots
        .iter()
        .map(|slot| {
            if slot.valid {
                let path = slot.path.as_ref().ok_or_else(|| RarError::CorruptArchive {
                    detail: "valid RAR5 data slot is missing a path".into(),
                })?;
                File::open(path).map(Some).map_err(RarError::from)
            } else {
                Ok(None)
            }
        })
        .collect::<RarResult<Vec<_>>>()?;

    let mut recovery_files = recovery_slots
        .iter()
        .map(|slot| {
            if slot.valid {
                let path = slot.path.as_ref().ok_or_else(|| RarError::CorruptArchive {
                    detail: "valid RAR5 recovery slot is missing a path".into(),
                })?;
                let mut file = File::open(path).map_err(RarError::from)?;
                file.seek(SeekFrom::Start(slot.data_offset))
                    .map_err(RarError::from)?;
                Ok(Some(file))
            } else {
                Ok(None)
            }
        })
        .collect::<RarResult<Vec<_>>>()?;

    let (restored_paths, mut outputs): (Vec<PathBuf>, Vec<File>) = match outputs {
        Rar5Outputs::Paths {
            paths,
            overwrite_existing,
        } => {
            let mut outputs = Vec::with_capacity(missing_count);
            for path in paths {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(RarError::from)?;
                }
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(overwrite_existing)
                    .create_new(!overwrite_existing)
                    .open(path)
                    .map_err(RarError::from)?;
                outputs.push(file);
            }
            (paths.to_vec(), outputs)
        }
        Rar5Outputs::Created(created) => created.into_iter().unzip(),
    };

    // The file each logical unit is read from: the data volume where it is
    // valid, otherwise the next valid recovery volume, in order. Fixed for
    // the whole restore, so a chunk's units can be read side by side.
    // A data unit also carries its hasher and table size when `hash_data`
    // asks for its CRC32.
    let mut spare_recovery = recovery_files.iter_mut().filter_map(Option::as_mut);
    let mut unit_files = Vec::with_capacity(data_count);
    for (slot, file) in data_slots.iter().zip(data_files.iter_mut()) {
        let unit = if slot.valid {
            let file = file.as_mut().ok_or_else(|| RarError::CorruptArchive {
                detail: "valid RAR5 data slot has no open file".into(),
            })?;
            (file, hash_data.then(crc32fast::Hasher::new), slot.file_size)
        } else {
            let file = spare_recovery
                .next()
                .ok_or_else(|| RarError::CorruptArchive {
                    detail: "RAR5 recovery volume selection exhausted unexpectedly".into(),
                })?;
            (file, None, 0)
        };
        unit_files.push(unit);
    }

    // The spare set is allocated only when a next chunk needs read-ahead.
    // Single-chunk restores need just the current inputs and the outputs.
    let mut input_bufs = vec![vec![0u8; chunk_size]; data_count];
    let mut next_bufs = Vec::new();
    let mut out_bufs = vec![vec![0u8; chunk_size]; missing_count];
    // Each restored volume is hashed as it is written, so verifying it
    // afterwards does not read it back.
    let mut hashers = vec![crc32fast::Hasher::new(); missing_count];
    let output_sizes = missing_volume_numbers
        .iter()
        .map(|&idx| data_slots[idx].file_size)
        .collect::<Vec<_>>();
    let chunk_at = |offset: u64| (max_volume_size - offset).min(chunk_size as u64) as usize;

    let read_chunk = |bufs: &mut [Vec<u8>],
                      units: &mut [(&mut File, Option<crc32fast::Hasher>, u64)],
                      offset: u64|
     -> RarResult<()> {
        let bytes = chunk_at(offset);
        let rs_len = bytes + (bytes & 1);
        par_zip_mut(bufs, units, |input_buf, unit| {
            let (file, hasher, size) = unit;
            // Whole words: a final odd-length chunk ends in the low byte of
            // a word whose high byte comes from every input that holds one,
            // the `.rev`s above all, as reference UnRAR reads whole words of
            // each. `read_padded` zeroes what an input does not fill, as the
            // encoder padded it.
            read_padded(file, &mut input_buf[..rs_len])?;
            if let Some(hasher) = hasher {
                let hash_len = size.saturating_sub(offset).min(bytes as u64);
                hasher.update(&input_buf[..hash_len as usize]);
            }
            Ok(())
        })
        .into_iter()
        .collect()
    };

    let mut processed = 0u64;
    if processed < max_volume_size {
        read_chunk(&mut input_bufs, &mut unit_files, processed)?;
    }
    while processed < max_volume_size {
        let bytes_to_process = chunk_at(processed);
        let rs_len = bytes_to_process + (bytes_to_process & 1);
        let next = processed + bytes_to_process as u64;

        if next < max_volume_size && next_bufs.is_empty() {
            next_bufs = vec![vec![0u8; chunk_size]; data_count];
        }
        let (read_ahead, written) = rayon::join(
            || {
                if next < max_volume_size {
                    read_chunk(&mut next_bufs, &mut unit_files, next)
                } else {
                    Ok(())
                }
            },
            || -> RarResult<()> {
                let units = input_bufs
                    .iter()
                    .map(|buf| &buf[..rs_len])
                    .collect::<Vec<_>>();
                let mut output_slices = out_bufs
                    .iter_mut()
                    .map(|buf| &mut buf[..rs_len])
                    .collect::<Vec<_>>();
                coder.apply_units(&units, &mut output_slices);

                let mut sinks = outputs
                    .iter_mut()
                    .zip(hashers.iter_mut())
                    .zip(output_sizes.iter())
                    .collect::<Vec<_>>();
                par_zip_mut(&mut sinks, &mut out_bufs, |sink, buf| {
                    let ((output, hasher), size) = sink;
                    let write_len = (**size)
                        .saturating_sub(processed)
                        .min(bytes_to_process as u64) as usize;
                    if write_len > 0 {
                        output
                            .write_all(&buf[..write_len])
                            .map_err(RarError::from)?;
                        hasher.update(&buf[..write_len]);
                    }
                    Ok(())
                })
                .into_iter()
                .collect()
            },
        );
        written?;
        read_ahead?;
        std::mem::swap(&mut input_bufs, &mut next_bufs);
        processed = next;
    }

    for output in &mut outputs {
        output.flush().map_err(RarError::from)?;
    }

    Ok(Rar5Reconstruction {
        restored: restored_paths
            .into_iter()
            .zip(hashers.into_iter().map(crc32fast::Hasher::finalize))
            .collect(),
        data_crcs: unit_files
            .into_iter()
            .map(|(_, hasher, _)| hasher.map(crc32fast::Hasher::finalize))
            .collect(),
    })
}

/// The RAR5 decode's chunk length: two input sets and the outputs within
/// `budget` bytes when read-ahead is useful, without allocating past the
/// longest volume's end. The path restore passes [`RAR5_TOTAL_BUFFER_SIZE`];
/// the stream restore passes the caller's memory budget.
fn rar5_chunk_size(
    max_volume_size: u64,
    data_count: usize,
    missing_count: usize,
    budget: usize,
) -> usize {
    let budget = (budget / (2 * data_count + missing_count).max(1)).max(2);
    let budget = budget - (budget & 1);
    let useful = max_volume_size.min(budget as u64) as usize;
    // GF16 needs an even buffer length, including a final odd-byte pad.
    useful + (useful & 1)
}

/// Run `task` over the pairs of two equally long slices, on rayon where the
/// build has worker threads, returning the results in order.
fn par_zip_mut<A, B, R, F>(left: &mut [A], right: &mut [B], task: F) -> Vec<R>
where
    A: Send,
    B: Send,
    R: Send,
    F: Fn(&mut A, &mut B) -> R + Sync + Send,
{
    debug_assert_eq!(left.len(), right.len());
    if left.len() > 1 && reedsolomon_rs::threading::parallel_enabled() {
        left.par_iter_mut()
            .zip(right.par_iter_mut())
            .map(|(a, b)| task(a, b))
            .collect()
    } else {
        left.iter_mut()
            .zip(right.iter_mut())
            .map(|(a, b)| task(a, b))
            .collect()
    }
}

/// Read the rest of a RAR5 `.rev` header from `reader`, whose first
/// [`REV5_PREFIX_LEN`] bytes, `prefix`, have been read and start with the
/// RAR5 signature. The read stops at the end of the header, where the
/// payload starts. `None` when the header does not parse, as reference UnRAR
/// refuses it.
fn read_rar5_rev_header<R: Read>(
    reader: &mut R,
    prefix: &[u8; REV5_PREFIX_LEN],
) -> RarResult<Option<Rar5RevHeader>> {
    let size_bytes = &prefix[REV5_SIGN.len() + 4..REV5_SIGN.len() + 8];
    let block_crc = le_u32(&prefix[REV5_SIGN.len()..REV5_SIGN.len() + 4]);
    let header_size = le_u32(size_bytes) as usize;
    if !(6..=0x100000).contains(&header_size) {
        return Ok(None);
    }

    let mut raw = vec![0u8; header_size];
    if read_padded(reader, &mut raw)? < header_size {
        return Ok(None);
    }
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(size_bytes);
    hasher.update(&raw);
    if hasher.finalize() != block_crc {
        return Ok(None);
    }

    parse_rar5_rev_body(&raw, REV5_PREFIX_LEN as u64 + header_size as u64)
}

/// Parse a RAR5 `.rev` header body. `None` for one reference UnRAR refuses,
/// recovery volume number 0 included (its header reader returns 0 for a
/// header it cannot use), and for one with no data or no recovery volumes.
fn parse_rar5_rev_body(raw: &[u8], data_offset: u64) -> RarResult<Option<Rar5RevHeader>> {
    let mut reader = SliceReader::new(raw);
    let version = match reader.get_u8() {
        Ok(version) => version,
        Err(RarError::CorruptArchive { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    if version != 1 {
        return Ok(None);
    }

    let Some(data_count) = read_rar5_rev_u16(&mut reader)? else {
        return Ok(None);
    };
    let Some(rec_count) = read_rar5_rev_u16(&mut reader)? else {
        return Ok(None);
    };
    let total_count = data_count + rec_count;
    let Some(rec_num) = read_rar5_rev_u16(&mut reader)? else {
        return Ok(None);
    };
    if data_count == 0
        || rec_count == 0
        || total_count > MAX_RAR5_VOLUMES
        || rec_num == 0
        || rec_num >= total_count
    {
        return Ok(None);
    }
    let Some(rev_crc) = read_rar5_rev_u32(&mut reader)? else {
        return Ok(None);
    };

    let table_size = data_count
        .checked_mul(12)
        .ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR5 recovery data table size overflow".into(),
        })?;
    let data_volumes = if raw.len().saturating_sub(reader.pos) >= table_size {
        let mut volumes = Vec::with_capacity(data_count);
        for _ in 0..data_count {
            let Some(file_size) = read_rar5_rev_u64(&mut reader)? else {
                return Ok(None);
            };
            let Some(crc32) = read_rar5_rev_u32(&mut reader)? else {
                return Ok(None);
            };
            volumes.push(Rar5DataVolumeInfo { file_size, crc32 });
        }
        Some(volumes)
    } else {
        None
    };

    Ok(Some(Rar5RevHeader {
        data_count,
        rec_count,
        rec_num,
        rev_crc,
        data_offset,
        data_volumes,
    }))
}

fn read_rar5_rev_u16(reader: &mut SliceReader<'_>) -> RarResult<Option<usize>> {
    match reader.get_u16() {
        Ok(value) => Ok(Some(value as usize)),
        Err(RarError::CorruptArchive { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

fn read_rar5_rev_u32(reader: &mut SliceReader<'_>) -> RarResult<Option<u32>> {
    match reader.get_u32() {
        Ok(value) => Ok(Some(value)),
        Err(RarError::CorruptArchive { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

fn read_rar5_rev_u64(reader: &mut SliceReader<'_>) -> RarResult<Option<u64>> {
    match reader.get_u64() {
        Ok(value) => Ok(Some(value)),
        Err(RarError::CorruptArchive { .. }) => Ok(None),
        Err(err) => Err(err),
    }
}

#[derive(Debug, Clone)]
struct Rar3RevHeader {
    rec_position: usize,
    rec_count: usize,
    data_count: usize,
    new_style: bool,
}

/// A RAR3 `.rev` whose set parameters are plausible, with what its footer
/// CRC32 says about the file.
#[derive(Debug, Clone)]
struct Rar3Rev {
    header: Rar3RevHeader,
    crc: Rar3RevCrc,
}

/// The footer CRC32 of a RAR3 `.rev`, which covers everything before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rar3RevCrc {
    /// An old-style `.rev` names its set in the file name and has no footer
    /// to check.
    Untestable,
    Matched,
    Mismatch {
        expected: u32,
        actual: u32,
    },
}

impl Rar3Rev {
    /// Whether a restore uses this `.rev`. One whose footer CRC32 fails may
    /// carry damaged set parameters as well as damaged recovery data, so it
    /// neither defines the set nor fills a slot.
    fn accepted(&self) -> bool {
        !matches!(self.crc, Rar3RevCrc::Mismatch { .. })
    }

    fn test_status(&self) -> RevTestStatus {
        match self.crc {
            Rar3RevCrc::Untestable => RevTestStatus::Unverifiable,
            Rar3RevCrc::Matched => RevTestStatus::Ok,
            Rar3RevCrc::Mismatch { expected, actual } => {
                RevTestStatus::CrcMismatch { expected, actual }
            }
        }
    }
}

/// What one pass over a RAR3 data volume found.
#[derive(Debug, Clone)]
struct Rar3VolumeScan {
    /// The main header's flags, when the main header was read.
    main_flags: Option<u16>,
    /// The headers and data CRC alone, before the volume is matched to its
    /// slot: `Valid`, `CrcMismatch` or `InvalidHeaders`.
    status: DataVolumeStatus,
    /// The zero-based volume number the end-of-archive header states.
    end_volume_number: Option<u16>,
}

/// Read a RAR3 data volume in one pass, as reference UnRAR checks one before
/// it rebuilds a set: the main header, every header after it through to the
/// end-of-archive header, and the CRC32 of everything before that header
/// when it states one. A volume cut short, with broken headers, or without
/// an end-of-archive header is `InvalidHeaders`, with the main header's
/// flags when they were read. One whose headers are encrypted shows nothing
/// past its main header and is taken as valid on that, as UnRAR takes it.
/// Only an I/O error other than an early end of file is an error.
fn rar3_volume_scan<R: Read + Seek>(reader: &mut R) -> RarResult<Rar3VolumeScan> {
    let mut walk = Rar3Walk::default();
    let walked = rar3_volume_walk(reader, &mut walk);
    rar3_scan_verdict(walk.main_flags, walked)
}

/// A [`Rar3VolumeScan`] from the outcome of a walk that read `main_flags`:
/// an error that says the headers are damaged is the `InvalidHeaders`
/// verdict, and any other error stays an error.
fn rar3_scan_verdict(
    main_flags: Option<u16>,
    walked: RarResult<(DataVolumeStatus, Option<u16>)>,
) -> RarResult<Rar3VolumeScan> {
    match walked {
        Ok((status, end_volume_number)) => Ok(Rar3VolumeScan {
            main_flags,
            status,
            end_volume_number,
        }),
        Err(error) if rar3_volume_damage(&error) => Ok(Rar3VolumeScan {
            main_flags,
            status: DataVolumeStatus::InvalidHeaders,
            end_volume_number: None,
        }),
        Err(error) => Err(error),
    }
}

/// Whether `error`, raised while reading a RAR3 volume's headers, says the
/// headers are damaged rather than that the file could not be read.
fn rar3_volume_damage(error: &RarError) -> bool {
    match error {
        RarError::Io(error) => error.kind() == std::io::ErrorKind::UnexpectedEof,
        RarError::InvalidSignature
        | RarError::UnsupportedFormat { .. }
        | RarError::CorruptArchive { .. }
        | RarError::HeaderCrcMismatch { .. }
        | RarError::BlockHeaderChecksumMismatch { .. }
        | RarError::TruncatedHeader { .. }
        | RarError::TruncatedData { .. }
        | RarError::ResourceLimit { .. } => true,
        _ => false,
    }
}

/// The header walk of [`rar3_volume_scan`] over a reader it can seek back
/// in: the verdict on the headers and data CRC, and the volume number the
/// end-of-archive header states. The data CRC is a second read of
/// everything before that header.
fn rar3_volume_walk<R: Read + Seek>(
    reader: &mut R,
    walk: &mut Rar3Walk,
) -> RarResult<(DataVolumeStatus, Option<u16>)> {
    reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    loop {
        match walk.step(reader)? {
            Rar3WalkStep::Next | Rar3WalkStep::Service(_) => {}
            Rar3WalkStep::Stopped(status) => return Ok((status, None)),
            Rar3WalkStep::End(end) => {
                let status = match end.data_crc {
                    Some(expected) => {
                        reader.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
                        if crc32_stream(reader, end.offset)? == expected {
                            DataVolumeStatus::Valid
                        } else {
                            DataVolumeStatus::CrcMismatch
                        }
                    }
                    None => DataVolumeStatus::Valid,
                };
                return Ok((status, end.volume_number));
            }
        }
    }
}

/// Where a [`Rar3Walk`] stands: before the signature, before the main
/// header, or before one of the headers after it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Rar3WalkAt {
    #[default]
    Signature,
    Main,
    Header,
}

/// The header walk of a RAR3 data volume, one header per step, so the same
/// walk judges a file it can seek back in and bytes streaming past once.
/// A step reads at the reader's position and leaves it at the next header.
#[derive(Debug, Clone, Copy, Default)]
struct Rar3Walk {
    at: Rar3WalkAt,
    /// The main header's flags, once the main header is read.
    main_flags: Option<u16>,
}

/// What one step of a [`Rar3Walk`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rar3WalkStep {
    /// Another header follows.
    Next,
    /// A service header (`NEWSUB`), its data area skipped; another header
    /// follows. The recovery record's `RR` header is one; other walks take
    /// it as [`Next`](Self::Next).
    Service(crate::rar4::header::RawRar4Header),
    /// The walk ended before an end-of-archive header with this verdict:
    /// `InvalidHeaders`, or `Valid` for a volume whose headers are
    /// encrypted.
    Stopped(DataVolumeStatus),
    /// The walk reached the end-of-archive header.
    End(Rar3EndBlock),
}

/// The end-of-archive header a [`Rar3Walk`] reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rar3EndBlock {
    /// Where the header starts; a stated data CRC covers every byte before.
    offset: u64,
    /// Where the block ends, past the header and any data area it declares.
    next: u64,
    /// The CRC32 of every byte before the header, when stated.
    data_crc: Option<u32>,
    /// The zero-based volume number, when stated.
    volume_number: Option<u16>,
}

impl Rar3Walk {
    /// Read the next header, or the signature first.
    fn step<R: Read + Seek>(&mut self, reader: &mut R) -> RarResult<Rar3WalkStep> {
        use crate::rar4::header::{
            parse_end_header, parse_file_header, read_raw_header, skip_forward,
        };
        use crate::rar4::types::{Rar4HeaderType, archive_flags};

        match self.at {
            Rar3WalkAt::Signature => {
                // A RAR 1.4 archive has no end-of-archive header, and no RAR
                // version that writes recovery volumes writes that format.
                if crate::signature::read_signature(reader)? != ArchiveFormat::Rar4 {
                    return Ok(Rar3WalkStep::Stopped(DataVolumeStatus::InvalidHeaders));
                }
                self.at = Rar3WalkAt::Main;
                Ok(Rar3WalkStep::Next)
            }
            Rar3WalkAt::Main => {
                let Some(main) = read_raw_header(reader)? else {
                    return Ok(Rar3WalkStep::Stopped(DataVolumeStatus::InvalidHeaders));
                };
                if main.header_type != Rar4HeaderType::Archive {
                    return Ok(Rar3WalkStep::Stopped(DataVolumeStatus::InvalidHeaders));
                }
                self.main_flags = Some(main.flags);
                if main.flags & archive_flags::ENCRYPTED_HEADERS != 0 {
                    return Ok(Rar3WalkStep::Stopped(DataVolumeStatus::Valid));
                }
                skip_forward(reader, main.data_area_size)?;
                self.at = Rar3WalkAt::Header;
                Ok(Rar3WalkStep::Next)
            }
            Rar3WalkAt::Header => {
                let Some(raw) = read_raw_header(reader)? else {
                    return Ok(Rar3WalkStep::Stopped(DataVolumeStatus::InvalidHeaders));
                };
                match raw.header_type {
                    Rar4HeaderType::File | Rar4HeaderType::NewSub => {
                        let header = parse_file_header(&raw)?;
                        // Forward-only skip: a declared size above `i64::MAX`
                        // would otherwise rewind this walk and loop forever
                        // (fuzz reproducer `timeout-a8693f23`).
                        skip_forward(reader, header.packed_size)?;
                        Ok(if raw.header_type == Rar4HeaderType::NewSub {
                            Rar3WalkStep::Service(raw)
                        } else {
                            Rar3WalkStep::Next
                        })
                    }
                    Rar4HeaderType::EndArchive => {
                        let end = parse_end_header(&raw);
                        Ok(Rar3WalkStep::End(Rar3EndBlock {
                            offset: raw.offset,
                            next: raw
                                .offset
                                .saturating_add(u64::from(raw.header_size))
                                .saturating_add(raw.data_area_size),
                            data_crc: end.data_crc,
                            volume_number: end.volume_number,
                        }))
                    }
                    _ => {
                        skip_forward(reader, raw.data_area_size)?;
                        Ok(Rar3WalkStep::Next)
                    }
                }
            }
        }
    }
}

/// [`rar3_volume_scan`] for a path; `None` when there is no file.
fn rar3_volume_scan_path(path: &Path) -> RarResult<Option<Rar3VolumeScan>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(RarError::from(err)),
    };
    rar3_volume_scan(&mut file).map(Some)
}

/// A scanned volume's verdict in data slot `index`: its own, unless its main
/// header does not mark it a volume or its end-of-archive header numbers it
/// as another one, which makes it `InvalidHeaders`.
fn rar3_volume_status(scan: &Rar3VolumeScan, index: usize) -> DataVolumeStatus {
    use crate::rar4::types::archive_flags;

    if scan.status != DataVolumeStatus::Valid {
        return scan.status.clone();
    }
    let not_a_volume = scan
        .main_flags
        .is_none_or(|flags| flags & archive_flags::VOLUME == 0);
    let misnumbered = scan
        .end_volume_number
        .is_some_and(|number| usize::from(number) != index);
    if not_a_volume || misnumbered {
        DataVolumeStatus::InvalidHeaders
    } else {
        DataVolumeStatus::Valid
    }
}

/// How a RAR3 set names its data volumes, taken from one of them as
/// reference UnRAR takes it from the first volume it opens.
#[derive(Debug, Clone)]
enum Rar3Naming {
    /// `name.part` `N` `.rar`: the volume's name around its number, which
    /// the set prints `width` digits wide.
    New { pattern: NumberedName, width: usize },
    /// `name.rar`, `name.r00`, `name.r01`, ..., or `name.001`, `name.002`,
    /// ... when `numeric`, with upper-case extensions when `upper`.
    Old {
        stem: String,
        numeric: bool,
        upper: bool,
    },
}

impl Rar3Naming {
    /// The naming of the volume at `path`, by the numbering its main header
    /// states. A new-numbering volume must be a `.rar` with a number in its
    /// name.
    fn of(path: &Path, new_numbering: bool) -> Option<Self> {
        if new_numbering {
            let pattern = NumberedName::of(path).filter(|_| has_rar_extension(path))?;
            let width = pattern.digits.len();
            return Some(Self::New { pattern, width });
        }
        let stem = path.file_stem()?.to_string_lossy().into_owned();
        let upper = path.extension().is_some_and(|ext| {
            ext.to_string_lossy()
                .starts_with(|ch: char| ch.is_ascii_uppercase())
        });
        Some(Self::Old {
            stem,
            numeric: old_rar3_numeric_extension_style(path),
            upper,
        })
    }

    /// What every name of the set, its `.rev`s' included, starts with.
    fn base(&self) -> &str {
        match self {
            Self::New { pattern, .. } => &pattern.head,
            Self::Old { stem, .. } => stem,
        }
    }

    /// The file name of data volume `index`, as reference UnRAR's next-volume
    /// naming spells it, the extension in the case of the volume the naming
    /// was taken from.
    fn data_name(&self, index: usize) -> String {
        match self {
            Self::New { pattern, width } => pattern.with_number(index + 1, *width, &pattern.ext),
            Self::Old {
                stem,
                numeric,
                upper,
            } => {
                let ext = if *numeric {
                    old_numeric_rar3_numbered_extension(index)
                } else if index == 0 {
                    "rar".to_string()
                } else {
                    old_rar3_numbered_extension(index)
                };
                let ext = if *upper {
                    ext.to_ascii_uppercase()
                } else {
                    ext
                };
                format!("{stem}.{ext}")
            }
        }
    }

    /// The zero-based data volume the name of `path` numbers in this naming,
    /// ignoring ASCII case; `None` when it is not named as one of the set's
    /// data volumes.
    fn data_index(&self, path: &Path) -> Option<usize> {
        match self {
            Self::New { pattern, width } => {
                if !has_rar_extension(path) {
                    return None;
                }
                let name = NumberedName::of(path)?;
                if !name.fits(pattern) {
                    return None;
                }
                name.number(*width)?.checked_sub(1)
            }
            Self::Old { stem, numeric, .. } => {
                if !path
                    .file_stem()?
                    .to_string_lossy()
                    .eq_ignore_ascii_case(stem)
                {
                    return None;
                }
                parse_old_rar3_extension(&path.extension()?.to_string_lossy(), *numeric)
            }
        }
    }
}

/// The zero-based volume an old-numbering extension numbers, ignoring ASCII
/// case: `rar`, `r00` ... `r99`, `s00` ... in the letter style, `001` ...
/// `999`, `a00` ... in the numeric one.
fn parse_old_rar3_extension(ext: &str, numeric: bool) -> Option<usize> {
    let ext = ext.to_ascii_lowercase();
    let bytes = ext.as_bytes();
    if !numeric && ext == "rar" {
        return Some(0);
    }
    if bytes.len() != 3 || !bytes[1].is_ascii_digit() || !bytes[2].is_ascii_digit() {
        return None;
    }
    let low = usize::from(bytes[1] - b'0') * 10 + usize::from(bytes[2] - b'0');
    match (numeric, bytes[0]) {
        (true, digit @ b'0'..=b'9') => (usize::from(digit - b'0') * 100 + low).checked_sub(1),
        (true, letter @ b'a'..=b'q') => Some(999 + usize::from(letter - b'a') * 100 + low),
        (false, letter @ b'r'..=b'z') => Some(usize::from(letter - b'r') * 100 + low + 1),
        _ => None,
    }
}

/// Whether `path` has an extension a RAR3 data volume can have: `.rar`, or
/// an old-numbering one.
fn has_rar3_data_extension(path: &Path) -> bool {
    has_rar_extension(path)
        || path.extension().is_some_and(|ext| {
            let ext = ext.to_string_lossy();
            parse_old_rar3_extension(&ext, false).is_some()
                || parse_old_rar3_extension(&ext, true).is_some()
        })
}

/// Whether the `.rev` at `path` is one of the RAR3 set whose names start
/// with `base`, and what it states. `None` when it is not: its name must be
/// `base` and the volume's number, or, for a RAR 3.0-style one, `base` and
/// `<data>_<recovery>_<position>`, optionally after an underscore.
/// `Some(None)` when it is the set's by name but states no set parameters a
/// restore can use.
fn rar3_rev_membership(base: &str, path: &Path, read: &RevRead) -> Option<Option<Rar3RevHeader>> {
    let stem = path.file_stem()?.to_string_lossy();
    let rest = strip_prefix_ignore_ascii_case(&stem, base)?;
    let all_digits =
        |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if rar3_rev_uses_new_style_footer(path) {
        if !all_digits(rest) {
            return None;
        }
        return Some(match read {
            RevRead::Rar3 { header, .. } => Some(header.clone()),
            _ => None,
        });
    }
    let numbers = rest.strip_prefix('_').unwrap_or(rest);
    let mut parts = numbers.split('_');
    let (Some(data), Some(rec), Some(position), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if ![data, rec, position].into_iter().all(all_digits) {
        return None;
    }
    let params = (
        parse_rar3_rev_param(data),
        parse_rar3_rev_param(rec),
        parse_rar3_rev_param(position),
    );
    Some(match (read, params) {
        (RevRead::Rar3Old, (Some(data_count), Some(rec_count), Some(rec_position)))
            if data_count + rec_count <= 255 && data_count + rec_position - 1 <= 255 =>
        {
            Some(Rar3RevHeader {
                rec_position,
                rec_count,
                data_count,
                new_style: false,
            })
        }
        _ => None,
    })
}

/// A RAR3 data volume's slot: the file found for it, its verdict, and where
/// a restore writes the volume when it is not valid.
#[derive(Debug, Clone)]
struct Rar3DataSlot {
    path: Option<PathBuf>,
    status: DataVolumeStatus,
    output_path: PathBuf,
}

/// A RAR3 set as restore and plan both see it once every data volume has
/// been checked, before either decides whether the set can be restored.
struct Rar3Set {
    data_count: usize,
    rec_count: usize,
    new_style: bool,
    output_dir: PathBuf,
    /// One entry per data volume, in volume order.
    data_volumes: Vec<Rar3DataSlot>,
    /// The `.rev` the restore uses for each recovery slot.
    recovery_slots: Vec<Option<PathBuf>>,
    /// Every `.rev` of the set with set parameters, in the order the survey
    /// takes them, the ones a restore passes over included.
    recovery_volumes: Vec<RecoveryVolumePlan>,
}

/// Find the RAR3 set's naming, match its `.rev`s to the set the first
/// accepted one describes, check every data volume, and place each volume
/// in its slot. Restore and plan both start here, so they judge and place
/// every volume alike and refuse the same sets.
///
/// The naming comes from the first data volume whose main header marks it
/// a volume and whose name the set's `.rev`s start with, as reference UnRAR
/// takes it from the first archive beside the `.rev` it is given. A `.rev`
/// is the set's when its name is the set's base and a number, or a
/// RAR 3.0-style `<data>_<recovery>_<position>`; a data volume is the set's
/// when its name numbers it in the set's naming. A given path named as no
/// volume of the set, or as a data volume past its count, is an error, and
/// a file found beside the given paths is passed over instead; two files
/// for one volume are an error.
fn survey_rar3_set(
    candidates: &[Candidate],
    reads: Vec<Option<RevRead>>,
    options: &RecoveryOptions,
) -> RarResult<Rar3Set> {
    use crate::rar4::types::archive_flags;

    // Every file that can be a data volume is read once, side by side. The
    // results are taken in path order, so an I/O error is the first a
    // serial pass would have hit.
    let data_like = (0..candidates.len())
        .filter(|&index| reads[index].is_none() && has_rar3_data_extension(&candidates[index].path))
        .collect::<Vec<_>>();
    let mut scans = par_map_in_order(&data_like, |&index| {
        rar3_volume_scan_path(&candidates[index].path)
    })
    .into_iter()
    .map(Some)
    .collect::<Vec<_>>();

    let has_member_rev = |naming: &Rar3Naming| {
        candidates.iter().zip(&reads).any(|(candidate, read)| {
            read.as_ref().is_some_and(|read| {
                matches!(
                    rar3_rev_membership(naming.base(), &candidate.path, read),
                    Some(Some(_))
                )
            })
        })
    };
    let source = data_like.iter().zip(&scans).find_map(|(&index, scan)| {
        let Some(Ok(Some(scan))) = scan else {
            return None;
        };
        let flags = scan.main_flags?;
        if flags & archive_flags::VOLUME == 0 {
            return None;
        }
        let naming = Rar3Naming::of(
            &candidates[index].path,
            flags & archive_flags::NEW_NUMBERING != 0,
        )?;
        has_member_rev(&naming).then_some((index, naming))
    });
    let Some((source, mut naming)) = source else {
        return Err(RarError::CorruptArchive {
            detail: "RAR3 recovery restore requires at least one data volume of the recovery set whose main header can be read".into(),
        });
    };
    let source_path = &candidates[source].path;

    // The width a new-numbering set prints its numbers at: the naming
    // volume's and the given volumes' names must agree on it, and the names
    // found beside them narrow it where they can.
    if let Rar3Naming::New { pattern, width } = &mut naming {
        let named = |index: usize| {
            NumberedName::of(&candidates[index].path)
                .filter(|name| has_rar_extension(&candidates[index].path) && name.fits(pattern))
        };
        let musts = std::iter::once(source)
            .chain(
                data_like
                    .iter()
                    .copied()
                    .filter(|&index| index != source && candidates[index].given),
            )
            .filter_map(|index| Some((index, named(index)?)))
            .collect::<Vec<_>>();
        let hints = data_like
            .iter()
            .copied()
            .filter(|&index| index != source && !candidates[index].given)
            .filter_map(named)
            .collect::<Vec<_>>();
        *width = volume_number_width(
            musts.iter().map(|(_, name)| name.digits.as_str()),
            hints.iter().map(|name| name.digits.as_str()),
        )
        .map_err(|position| {
            foreign_volume_error(&candidates[musts[position].0].path, source_path)
        })?;
    }

    // The `.rev`s of the set's name, each with its footer's CRC32 read
    // through, side by side; one named otherwise is never read past its
    // footer.
    let mut members = Vec::new();
    for (index, (candidate, read)) in candidates.iter().zip(&reads).enumerate() {
        let Some(read) = read else {
            continue;
        };
        match rar3_rev_membership(naming.base(), &candidate.path, read) {
            Some(Some(header)) => members.push((index, header)),
            Some(None) => {}
            None if candidate.given => {
                return Err(foreign_volume_error(&candidate.path, source_path));
            }
            None => {}
        }
    }
    let crcs = par_map_in_order(&members, |(index, _)| match &reads[*index] {
        Some(RevRead::Rar3 { payload, .. }) => rar3_rev_crc(payload),
        _ => Ok(Rar3RevCrc::Untestable),
    });
    let mut revs = Vec::with_capacity(members.len());
    for ((index, header), crc) in members.into_iter().zip(crcs) {
        revs.push((index, Rar3Rev { header, crc: crc? }));
    }

    let Some((_, defining)) = revs
        .iter()
        .find(|(_, rev)| rev.accepted())
        .or_else(|| revs.first())
    else {
        return Err(RarError::CorruptArchive {
            detail: "no valid RAR recovery volumes were found".into(),
        });
    };
    let data_count = defining.header.data_count;
    let rec_count = defining.header.rec_count;
    let new_style = defining.header.new_style;
    if data_count + rec_count > MAX_RAR3_SET {
        return Err(RarError::CorruptArchive {
            detail: "RAR3 recovery set exceeds 255 total volumes".into(),
        });
    }

    // The recovery volumes, placed by the position they state. One whose
    // footer CRC32 failed, or whose position is past the set's recovery
    // volumes, is listed and not used; one that failed its CRC32 and states
    // another set is passed over, as the restore passes over any file that
    // is not a recovery volume.
    let mut recovery_slots = vec![None::<PathBuf>; rec_count];
    let mut recovery_claims = vec![None::<usize>; rec_count];
    let mut recovery_volumes = Vec::new();
    for (index, rev) in revs {
        let header = &rev.header;
        let same_set = header.data_count == data_count
            && header.rec_count == rec_count
            && header.new_style == new_style;
        if !same_set {
            if rev.accepted() {
                return Err(RarError::CorruptArchive {
                    detail: format!(
                        "RAR3 recovery volume {} does not match the first recovery set",
                        candidates[index].path.display()
                    ),
                });
            }
            continue;
        }
        let slot = header.rec_position - 1;
        let usable = rev.accepted() && slot < rec_count;
        if usable
            && !claim_slot(&mut recovery_claims[slot], index, candidates, || {
                format!("recovery volume {} of the recovery set", slot + 1)
            })?
        {
            continue;
        }
        recovery_volumes.push(RecoveryVolumePlan {
            slot,
            volume_number: data_count + slot,
            path: candidates[index].path.clone(),
            status: rev.test_status(),
            usable,
        });
        if usable {
            recovery_slots[slot] = Some(candidates[index].path.clone());
        }
    }

    // The data volumes, placed by the number their names state in the set's
    // naming, each judged by its own scan.
    let mut data_claims = vec![None::<(usize, usize)>; data_count];
    for (position, &index) in data_like.iter().enumerate() {
        let candidate = &candidates[index];
        let Some(volume) = naming.data_index(&candidate.path) else {
            if candidate.given {
                return Err(foreign_volume_error(&candidate.path, source_path));
            }
            continue;
        };
        if volume >= data_count {
            if candidate.given {
                return Err(volume_out_of_range_error(
                    &candidate.path,
                    volume + 1,
                    data_count,
                ));
            }
            continue;
        }
        let mut claim = data_claims[volume].map(|(claimed, _)| claimed);
        if claim_slot(&mut claim, index, candidates, || {
            format!("data volume {} of the recovery set", volume + 1)
        })? {
            data_claims[volume] = Some((index, position));
        }
    }

    let output_dir = recovery_output_dir(candidates, options);
    let mut data_volumes = Vec::with_capacity(data_count);
    for (volume, claim) in data_claims.into_iter().enumerate() {
        let slot = match claim {
            Some((index, position)) => {
                let path = candidates[index].path.clone();
                let status = match scans[position].take() {
                    Some(Ok(Some(scan))) => rar3_volume_status(&scan, volume),
                    Some(Ok(None)) | None => DataVolumeStatus::Missing,
                    Some(Err(error)) => return Err(error),
                };
                Rar3DataSlot {
                    output_path: output_dir.join(file_name_of(&path)),
                    path: Some(path),
                    status,
                }
            }
            None => Rar3DataSlot {
                path: None,
                status: DataVolumeStatus::Missing,
                output_path: output_dir.join(naming.data_name(volume)),
            },
        };
        data_volumes.push(slot);
    }

    Ok(Rar3Set {
        data_count,
        rec_count,
        new_style,
        output_dir,
        data_volumes,
        recovery_slots,
        recovery_volumes,
    })
}

/// Rebuild a RAR3 set's missing and invalid data volumes. Each is written to
/// a hidden partial file beside its output name and, with
/// [`RecoveryOptions::verify_restored`], read back once through the same
/// handle and judged as a data volume in its slot is. Only once every one
/// has been written, and has passed, are the invalid volumes set aside as
/// `.bad`, existing outputs refused, and the partial files moved into place;
/// any failure before that removes the partial files and leaves every other
/// file as it was.
fn restore_rar3(set: Rar3Set, options: &RecoveryOptions) -> RarResult<RecoveryReport> {
    let Rar3Set {
        data_count,
        rec_count,
        new_style,
        data_volumes,
        recovery_slots,
        ..
    } = set;

    let missing_volume_numbers = (0..data_count)
        .filter(|&index| data_volumes[index].status != DataVolumeStatus::Valid)
        .collect::<Vec<_>>();
    if missing_volume_numbers.is_empty() {
        return Ok(RecoveryReport {
            format: ArchiveFormat::Rar4,
            restored_paths: Vec::new(),
            used_recovery_paths: Vec::new(),
            missing_volume_numbers,
        });
    }

    let found_recovery_count = recovery_slots.iter().flatten().count();
    if missing_volume_numbers.len() > found_recovery_count {
        return Err(RarError::CorruptArchive {
            detail: format!(
                "insufficient RAR3 recovery volumes: need {}, have {}",
                missing_volume_numbers.len(),
                found_recovery_count
            ),
        });
    }

    // The reconstruction reads `slots` as the whole set: each valid data
    // volume, `None` for each one to rebuild, then the recovery volumes.
    let slots = data_volumes
        .iter()
        .map(|slot| {
            slot.path
                .clone()
                .filter(|_| slot.status == DataVolumeStatus::Valid)
        })
        .chain(recovery_slots.iter().cloned())
        .collect::<Vec<_>>();

    let mut partial_paths = Vec::with_capacity(missing_volume_numbers.len());
    let mut outputs = Vec::with_capacity(missing_volume_numbers.len());
    let remove_partials = |paths: &[PathBuf]| {
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    };
    for &index in &missing_volume_numbers {
        match create_partial(&data_volumes[index].output_path) {
            Ok((path, file)) => {
                partial_paths.push(path);
                outputs.push(file);
            }
            Err(error) => {
                drop(outputs);
                remove_partials(&partial_paths);
                return Err(error);
            }
        }
    }

    let finish = |mut outputs: Vec<File>| -> RarResult<()> {
        reconstruct_rar3(
            &slots,
            data_count,
            rec_count,
            &missing_volume_numbers,
            &mut outputs,
            new_style,
        )?;
        if options.verify_restored {
            for (output, &index) in outputs.iter_mut().zip(&missing_volume_numbers) {
                let status = rar3_volume_status(&rar3_volume_scan(output)?, index);
                if status != DataVolumeStatus::Valid {
                    return Err(RarError::CorruptArchive {
                        detail: format!(
                            "restored RAR3 volume {} failed verification ({status:?})",
                            data_volumes[index].output_path.display()
                        ),
                    });
                }
            }
        }
        drop(outputs);

        for &index in &missing_volume_numbers {
            let slot = &data_volumes[index];
            if let Some(path) = &slot.path
                && slot.status != DataVolumeStatus::Missing
            {
                rename_invalid_data_volume(path, &slot.output_path, options)?;
            }
        }
        for &index in &missing_volume_numbers {
            let path = &data_volumes[index].output_path;
            if !options.overwrite_existing && path.exists() {
                return Err(refuse_existing_restored(path));
            }
        }
        for (partial, &index) in partial_paths.iter().zip(&missing_volume_numbers) {
            install_partial(
                partial,
                &data_volumes[index].output_path,
                options.overwrite_existing,
            )?;
        }
        Ok(())
    };
    if let Err(error) = finish(outputs) {
        remove_partials(&partial_paths);
        return Err(error);
    }

    let restored_paths = missing_volume_numbers
        .iter()
        .map(|&index| data_volumes[index].output_path.clone())
        .collect();
    Ok(RecoveryReport {
        format: ArchiveFormat::Rar4,
        restored_paths,
        used_recovery_paths: recovery_slots.into_iter().flatten().collect(),
        missing_volume_numbers,
    })
}

/// [`plan_volume_restore`] for a RAR3 set.
fn plan_rar3(set: Rar3Set) -> RarResult<RestorePlan> {
    let data_volumes = set
        .data_volumes
        .into_iter()
        .enumerate()
        .map(|(index, slot)| data_volume_plan(index, slot.path, slot.status, slot.output_path))
        .collect::<RarResult<Vec<_>>>()?;
    Ok(RestorePlan {
        format: ArchiveFormat::Rar4,
        data_count: set.data_count,
        recovery_count: set.rec_count,
        data_volumes,
        recovery_volumes: set.recovery_volumes,
        output_dir: set.output_dir,
    })
}

/// Rebuild the data volumes `missing_volume_numbers` into `outputs`, one
/// open file each, in that order, from the volumes `slots` holds: every data
/// volume, `None` for each one to rebuild, then every recovery volume.
fn reconstruct_rar3(
    slots: &[Option<PathBuf>],
    data_count: usize,
    rec_count: usize,
    missing_volume_numbers: &[usize],
    outputs: &mut [File],
    new_style: bool,
) -> RarResult<()> {
    let total_count = data_count + rec_count;
    if total_count > MAX_RAR3_SET {
        return Err(RarError::CorruptArchive {
            detail: "RAR3 recovery set exceeds 255 total volumes".into(),
        });
    }
    let chunk_size = (RAR3_TOTAL_BUFFER_SIZE / total_count.max(1)).max(1);

    let mut inputs = slots
        .iter()
        .map(|slot| {
            if let Some(path) = slot {
                File::open(path).map(Some).map_err(RarError::from)
            } else {
                Ok(None)
            }
        })
        .collect::<RarResult<Vec<_>>>()?;

    let erasures = (0..total_count)
        .filter(|&idx| slots[idx].is_none())
        .collect::<Vec<_>>();
    let present = (0..total_count)
        .filter(|&idx| slots[idx].is_some())
        .collect::<Vec<_>>();

    // For a fixed erasure set the scalar column decoder is a linear map, so
    // it is derived once as a matrix (by running that decoder on unit
    // vectors) and applied to whole regions with the gf8 kernels. Only the
    // rows of missing data volumes are kept, and only the columns of present
    // volumes: an erased position reads as zero, so its column contributes
    // nothing. The matrix is the decoder's own map, so the bytes are the same
    // ones the per-column decode produced.
    let coder = Rar3RsCoder::new(rec_count).ok_or_else(|| RarError::CorruptArchive {
        detail: "RAR3 recovery set has invalid recovery count".into(),
    })?;
    let matrix = coder.decode_matrix(total_count, &erasures).map(|full| {
        rar3_missing_rows(
            &full,
            total_count,
            &erasures,
            &present,
            missing_volume_numbers,
        )
    });

    let mut buffers = vec![vec![0u8; chunk_size]; present.len()];
    let missing_count = missing_volume_numbers.len();
    let mut restored = vec![vec![0u8; chunk_size]; missing_count];

    // The open file of each present volume, in `present` order, so a
    // chunk's volumes can be read side by side.
    let mut present_files = inputs.iter_mut().flatten().collect::<Vec<_>>();

    loop {
        let reads = par_zip_mut(&mut buffers, &mut present_files, |buffer, file| {
            read_padded(file, buffer)
        });
        let mut max_read = 0usize;
        for read in reads {
            max_read = max_read.max(read?);
        }
        if max_read == 0 {
            break;
        }
        // Reported here rather than up front so a set with nothing to read
        // fails or succeeds exactly as the column decoder did.
        let matrix = matrix.as_ref().ok_or_else(|| RarError::CorruptArchive {
            detail: "RAR3 recovery decoder failed".into(),
        })?;

        let input_refs = buffers
            .iter()
            .map(|buffer| &buffer[..max_read])
            .collect::<Vec<_>>();
        let mut output_refs = restored
            .iter_mut()
            .map(|buffer| &mut buffer[..max_read])
            .collect::<Vec<_>>();
        apply_decode_matrix_gf8(matrix, &input_refs, &mut output_refs);

        let writes = par_zip_mut(outputs, &mut restored, |output, buffer| {
            output
                .write_all(&buffer[..max_read])
                .map_err(RarError::from)
        });
        writes.into_iter().collect::<RarResult<()>>()?;
    }

    for (out_idx, output) in outputs.iter_mut().enumerate() {
        let is_last_data_volume = missing_volume_numbers[out_idx] + 1 == data_count;
        finalize_rar3_restored_output(output, new_style, is_last_data_volume)?;
    }
    Ok(())
}

/// The rows of a full RAR3 decode matrix (one per erasure, one column per
/// volume position) that rebuild the missing data volumes, restricted to the
/// columns of the present volumes, in the order `apply_decode_matrix_gf8`
/// takes them.
fn rar3_missing_rows(
    full: &[u8],
    total: usize,
    erasures: &[usize],
    present: &[usize],
    missing_volume_numbers: &[usize],
) -> Vec<u8> {
    let mut rows = Vec::with_capacity(missing_volume_numbers.len() * present.len());
    for &missing in missing_volume_numbers {
        let row = erasures
            .iter()
            .position(|&era| era == missing)
            .expect("every missing data volume is an erasure");
        rows.extend(present.iter().map(|&col| full[row * total + col]));
    }
    rows
}

fn finalize_rar3_restored_output(
    output: &mut File,
    new_style: bool,
    is_last_data_volume: bool,
) -> RarResult<()> {
    output.flush().map_err(RarError::from)?;

    // RAR 3.10+ recovery sets carry a synthetic 7-byte footer; old-style
    // name#_#_#.rev volumes do not.
    if new_style {
        let len = output.seek(SeekFrom::End(0)).map_err(RarError::from)?;
        if len >= 7 {
            output
                .seek(SeekFrom::Start(len - 7))
                .map_err(RarError::from)?;
            output.write_all(&[0u8; 7]).map_err(RarError::from)?;
            output.flush().map_err(RarError::from)?;
        }
    }

    if is_last_data_volume {
        truncate_rar3_last_volume_padding(output)?;
    }
    Ok(())
}

/// Cut the zero padding a RAR3 recovery set leaves after a rebuilt last
/// volume's end-of-archive block, where reference UnRAR cuts it: at the
/// block's end, when the [`RAR3_PADDING_PROBE`] bytes after it (or all of
/// them, when fewer) are zero. The walk to the block is [`Rar3Walk`]'s, the
/// one the stream restore and the volume scan make, so a member's full
/// 64-bit packed size is skipped. A volume whose headers are encrypted or
/// damaged, or whose signature is not a RAR 1.5-4.x one, cannot be measured
/// and is left as it is: the restore has already written it, and
/// `verify_restored` judges it.
fn truncate_rar3_last_volume_padding(output: &mut File) -> RarResult<()> {
    output.seek(SeekFrom::Start(0)).map_err(RarError::from)?;
    let mut walk = Rar3Walk::default();
    let end = loop {
        match walk.step(output) {
            Ok(Rar3WalkStep::Next | Rar3WalkStep::Service(_)) => {}
            Ok(Rar3WalkStep::Stopped(_)) => return Ok(()),
            Ok(Rar3WalkStep::End(end)) => break end,
            Err(error) if rar3_volume_damage(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    };

    let file_len = output.seek(SeekFrom::End(0)).map_err(RarError::from)?;
    if end.next >= file_len {
        return Ok(());
    }
    output
        .seek(SeekFrom::Start(end.next))
        .map_err(RarError::from)?;
    let mut probe = [0u8; RAR3_PADDING_PROBE as usize];
    let read = output.read(&mut probe).map_err(RarError::from)?;
    if read > 0 && probe[..read].iter().all(|&byte| byte == 0) {
        output.set_len(end.next).map_err(RarError::from)?;
    }
    Ok(())
}

fn rar3_rev_uses_new_style_footer(path: &Path) -> bool {
    let Some(stem) = path.file_stem().map(|stem| stem.to_string_lossy()) else {
        return true;
    };
    let bytes = stem.as_bytes();
    let mut digit_groups = 0usize;
    let mut pos = bytes.len();
    while pos > 0 {
        pos -= 1;
        if bytes[pos].is_ascii_digit() {
            continue;
        }
        if bytes[pos] == b'_' && pos > 0 && bytes[pos - 1].is_ascii_digit() {
            digit_groups += 1;
        } else {
            break;
        }
    }
    digit_groups < 2
}

fn parse_old_rar3_rev_name(path: &Path) -> Option<(usize, usize, usize)> {
    let stem = path.file_stem()?.to_string_lossy();
    let mut parts = stem.rsplitn(3, '_');
    let rec_position = parse_rar3_rev_param(parts.next()?)?;
    let rec_count = parse_rar3_rev_param(parts.next()?)?;
    let data_part = parts.next()?;
    let data_start = data_part
        .as_bytes()
        .iter()
        .rposition(|byte| !byte.is_ascii_digit())
        .map_or(0, |idx| idx + 1);
    let data_count = parse_rar3_rev_param(&data_part[data_start..])?;

    if data_count + rec_count > 255 || data_count + rec_position - 1 > 255 {
        return None;
    }

    Some((data_count, rec_count, rec_position))
}

fn parse_rar3_rev_param(value: &str) -> Option<usize> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = value.parse::<usize>().ok()?;
    (1..=255).contains(&value).then_some(value)
}

fn rar5_recovery_data_candidate_allowed(path: &Path) -> RarResult<bool> {
    if path
        .extension()
        .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("rar"))
    {
        return Ok(true);
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RarError::from(err)),
    };
    match crate::signature::read_signature(&mut file) {
        Ok(ArchiveFormat::Rar5) => {
            let pos = file.stream_position().map_err(RarError::from)?;
            Ok(pos > crate::signature::RAR5_SIGNATURE_LEN as u64)
        }
        Ok(_) | Err(RarError::InvalidSignature) => Ok(false),
        Err(err) => Err(err),
    }
}

fn old_rar3_numeric_extension_style(path: &Path) -> bool {
    let Some(ext) = path.extension().map(|ext| ext.to_string_lossy()) else {
        return false;
    };
    let ext = ext.to_ascii_lowercase();
    let bytes = ext.as_bytes();
    bytes.len() == 3
        && (bytes.iter().all(u8::is_ascii_digit)
            || ((b'a'..b'r').contains(&bytes[0])
                && bytes[1].is_ascii_digit()
                && bytes[2].is_ascii_digit()))
}

fn old_numeric_rar3_numbered_extension(volume_index: usize) -> String {
    if volume_index < 999 {
        format!("{:03}", volume_index + 1)
    } else {
        let rollover = volume_index - 999;
        let prefix = char::from_u32(u32::from(b'a') + (rollover / 100) as u32).unwrap_or('a');
        format!("{prefix}{:02}", rollover % 100)
    }
}

fn old_rar3_numbered_extension(volume_index: usize) -> String {
    let old_index = volume_index - 1;
    let prefix = char::from_u32(u32::from(b'r') + (old_index / 100) as u32).unwrap_or('r');
    format!("{prefix}{:02}", old_index % 100)
}

fn rar_volume_digit_run(value: &str) -> Option<(usize, usize)> {
    let bytes = value.as_bytes();
    let end = bytes.iter().rposition(|b| b.is_ascii_digit())? + 1;
    let start = bytes[..end]
        .iter()
        .rposition(|b| !b.is_ascii_digit())
        .map_or(0, |idx| idx + 1);

    // For names like `name.part##of##.rar`, select the first numeric run after
    // a dot, not the final total count.
    let mut scan = start;
    while scan > 0 && bytes[scan - 1] != b'.' {
        scan -= 1;
        if bytes[scan].is_ascii_digit() {
            let candidate_end = scan + 1;
            let candidate_start = bytes[..candidate_end]
                .iter()
                .rposition(|b| !b.is_ascii_digit())
                .map_or(0, |idx| idx + 1);
            if bytes[..candidate_start].contains(&b'.') {
                return Some((candidate_start, candidate_end));
            }
            break;
        }
    }

    Some((start, end))
}

/// [`RecoveryOptions::output_dir`], else the directory of the first path
/// given.
fn recovery_output_dir(candidates: &[Candidate], options: &RecoveryOptions) -> PathBuf {
    options.output_dir.clone().unwrap_or_else(|| {
        candidates
            .first()
            .and_then(|candidate| candidate.path.parent())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    })
}

fn is_rev_path(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("rev"))
}

fn first_embedded_recovery_record_path(
    candidates: &[Candidate],
) -> RarResult<Option<EmbeddedRecoverySource>> {
    for path in candidates.iter().map(|candidate| &candidate.path) {
        if is_rev_path(path) {
            continue;
        }

        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(RarError::from(err)),
        };

        match probe_volume(&mut file) {
            Ok(probe) if probe.has_recovery_record => {
                return Ok(Some(EmbeddedRecoverySource {
                    path: path.clone(),
                    format: probe.format,
                }));
            }
            Ok(_) | Err(RarError::InvalidSignature) => {}
            Err(RarError::EncryptedArchive) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(None)
}

fn read_padded(reader: &mut impl Read, buf: &mut [u8]) -> RarResult<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(RarError::from(e)),
        }
    }
    if total < buf.len() {
        buf[total..].fill(0);
    }
    Ok(total)
}

fn crc32_file_region(path: &Path, offset: u64) -> RarResult<u32> {
    let mut file = File::open(path).map_err(RarError::from)?;
    file.seek(SeekFrom::Start(offset)).map_err(RarError::from)?;
    crc32_stream(&mut file, u64::MAX)
}

/// Read size for the whole-file CRC passes: large enough that a volume is a
/// few hundred reads rather than tens of thousands, small enough to stay in
/// L2 while it is hashed.
const CRC_READ_SIZE: usize = 256 * 1024;

/// CRC32 of the next `limit` bytes of `reader`, or of everything up to its
/// end when it ends sooner.
fn crc32_stream(reader: &mut impl Read, limit: u64) -> RarResult<u32> {
    let mut remaining = limit;
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; CRC_READ_SIZE];
    while remaining > 0 {
        let max_read = remaining.min(buf.len() as u64) as usize;
        let read = match reader.read(&mut buf[..max_read]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(RarError::from(error)),
        };
        hasher.update(&buf[..read]);
        remaining -= read as u64;
    }
    Ok(hasher.finalize())
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read(&mut self, len: usize) -> RarResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| RarError::CorruptArchive {
                detail: "RAR recovery header offset overflow".into(),
            })?;
        if end > self.data.len() {
            return Err(RarError::CorruptArchive {
                detail: "truncated RAR recovery header".into(),
            });
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn get_u8(&mut self) -> RarResult<u8> {
        Ok(self.read(1)?[0])
    }

    fn get_u16(&mut self) -> RarResult<u16> {
        self.read(2).map(le_u16)
    }

    fn get_u32(&mut self) -> RarResult<u32> {
        self.read(4).map(le_u32)
    }

    fn get_u64(&mut self) -> RarResult<u64> {
        self.read(8).map(le_u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rar5_chunk_capacity_tracks_useful_bytes_with_gf16_padding() {
        for (volume_size, expected) in [
            (0, 0),
            (1, 2),
            (2, 2),
            (3, 4),
            (1_048_576, 1_048_576),
            (3_532_043, 3_532_044),
            (3_532_044, 3_532_044),
            (3_532_045, 3_532_044),
            (u64::MAX, 3_532_044),
        ] {
            assert_eq!(
                rar5_chunk_size(volume_size, 9, 1, RAR5_TOTAL_BUFFER_SIZE),
                expected
            );
        }
    }

    fn rar4_archive_with_recovery_flag() -> Vec<u8> {
        let mut bytes = b"Rar!\x1a\x07\0".to_vec();
        let mut header = vec![0u8; 7];
        header[2] = 0x73; // MAIN_HEAD
        header[3..5].copy_from_slice(&crate::rar4::types::archive_flags::RECOVERY.to_le_bytes());
        header[5..7].copy_from_slice(&7u16.to_le_bytes());
        let crc = (crc32fast::hash(&header[2..]) & 0xFFFF) as u16;
        header[0..2].copy_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes
    }

    fn append_rar4_end_data_crc(bytes: &mut Vec<u8>, corrupt: bool) {
        let mut expected = crc32fast::hash(bytes);
        if corrupt {
            expected ^= 0xFFFF_FFFF;
        }

        let mut header = vec![0u8; 11];
        header[2] = 0x7B; // ENDARC_HEAD
        header[3..5].copy_from_slice(&crate::rar4::types::end_flags::DATA_CRC.to_le_bytes());
        header[5..7].copy_from_slice(&11u16.to_le_bytes());
        header[7..11].copy_from_slice(&expected.to_le_bytes());
        let crc = (crc32fast::hash(&header[2..]) & 0xFFFF) as u16;
        header[0..2].copy_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&header);
    }

    fn build_rar5_rev_from_raw(raw: &[u8]) -> Vec<u8> {
        let mut bytes = REV5_SIGN.to_vec();
        let header_size = raw.len() as u32;
        let mut crc_input = header_size.to_le_bytes().to_vec();
        crc_input.extend_from_slice(raw);
        bytes.extend_from_slice(&crc32fast::hash(&crc_input).to_le_bytes());
        bytes.extend_from_slice(&header_size.to_le_bytes());
        bytes.extend_from_slice(raw);
        bytes
    }

    fn build_rar5_rev_bytes(include_table: bool) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(1); // version
        raw.extend_from_slice(&1u16.to_le_bytes()); // data count
        raw.extend_from_slice(&1u16.to_le_bytes()); // recovery count
        raw.extend_from_slice(&1u16.to_le_bytes()); // recovery volume number
        raw.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes()); // recovery data CRC
        if include_table {
            raw.extend_from_slice(&123u64.to_le_bytes());
            raw.extend_from_slice(&0x1122_3344u32.to_le_bytes());
        }

        build_rar5_rev_from_raw(&raw)
    }

    fn build_rar5_header(header_type: u64, header_flags: u64, type_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&crate::vint::encode_vint(header_type));
        body.extend_from_slice(&crate::vint::encode_vint(header_flags));
        body.extend_from_slice(type_body);

        let header_size = body.len() as u64;
        let header_size_bytes = crate::vint::encode_vint(header_size);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&header_size_bytes);
        hasher.update(&body);

        let mut result = Vec::new();
        result.extend_from_slice(&hasher.finalize().to_le_bytes());
        result.extend_from_slice(&header_size_bytes);
        result.extend_from_slice(&body);
        result
    }

    fn build_probe_rar5_archive(archive_flags: u64, volume_number: Option<u64>) -> Vec<u8> {
        let mut buf = crate::signature::RAR5_SIGNATURE.to_vec();
        let mut main_body = crate::vint::encode_vint(archive_flags);
        if let Some(volume_number) = volume_number {
            main_body.extend_from_slice(&crate::vint::encode_vint(volume_number));
        }
        buf.extend_from_slice(&build_rar5_header(1, 0, &main_body));
        buf.extend_from_slice(&build_rar5_header(5, 0, &crate::vint::encode_vint(0)));
        buf
    }

    fn path_list_contains(candidates: &[Candidate], needle: &Path) -> bool {
        candidates.iter().any(|candidate| candidate.path == needle)
    }

    /// The RAR5 header [`read_rev`] reads from the `.rev` at `path`, if it
    /// reads one.
    fn rar5_rev_header_at(path: &Path) -> Option<Rar5RevHeader> {
        match read_rev(File::open(path).unwrap(), path).unwrap() {
            RevRead::Rar5 { header, .. } => Some(header),
            _ => None,
        }
    }

    /// The RAR3 footer [`read_rev`] reads from the `.rev` at `path`, with
    /// what its CRC32 says, if it reads one.
    fn rar3_footer_rev_at(path: &Path) -> Option<Rar3Rev> {
        match read_rev(File::open(path).unwrap(), path).unwrap() {
            RevRead::Rar3 { header, payload } => Some(Rar3Rev {
                header,
                crc: rar3_rev_crc(&payload).unwrap(),
            }),
            _ => None,
        }
    }

    #[test]
    fn rar_volume_digit_run_finds_part_number() {
        assert_eq!(rar_volume_digit_run("movie.part0007"), Some((10, 14)));
        assert_eq!(rar_volume_digit_run("movie.part01of10"), Some((10, 12)));
        assert_eq!(rar_volume_digit_run("movie"), None);
    }

    #[test]
    fn recovery_path_expansion_discovers_rar5_siblings_from_rev() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("movie.part0002.rev");
        let data = dir.path().join("movie.part0001.rar");
        let next_rev = dir.path().join("movie.part0003.rev");
        let unrelated = dir.path().join("other.part0001.rar");
        for path in [&input, &data, &next_rev, &unrelated] {
            std::fs::write(path, b"x").unwrap();
        }

        let expanded = expand_recovery_paths(std::slice::from_ref(&input)).unwrap();

        assert!(path_list_contains(&expanded, &input));
        assert!(path_list_contains(&expanded, &data));
        assert!(path_list_contains(&expanded, &next_rev));
        assert!(!path_list_contains(&expanded, &unrelated));
    }

    #[test]
    fn recovery_path_expansion_discovers_rar3_old_style_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("movie5_3_1.rev");
        let data = dir.path().join("movie.rar");
        let next_rev = dir.path().join("movie5_3_2.rev");
        let unrelated = dir.path().join("other5_3_1.rev");
        for path in [&input, &data, &next_rev, &unrelated] {
            std::fs::write(path, b"x").unwrap();
        }

        let expanded = expand_recovery_paths(std::slice::from_ref(&input)).unwrap();

        assert!(path_list_contains(&expanded, &input));
        assert!(path_list_contains(&expanded, &data));
        assert!(path_list_contains(&expanded, &next_rev));
        assert!(!path_list_contains(&expanded, &unrelated));
    }

    #[test]
    fn rar5_recovery_data_candidate_accepts_rar_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        std::fs::write(&path, b"not checked before extension acceptance").unwrap();

        assert!(rar5_recovery_data_candidate_allowed(&path).unwrap());
    }

    #[test]
    fn rar5_recovery_data_candidate_rejects_non_rar_direct_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.bin");
        std::fs::write(&path, crate::signature::RAR5_SIGNATURE).unwrap();

        assert!(!rar5_recovery_data_candidate_allowed(&path).unwrap());
    }

    #[test]
    fn rar5_recovery_data_candidate_accepts_non_rar_sfx_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.exe");
        let mut bytes = vec![0xCCu8; 16];
        bytes.extend_from_slice(&crate::signature::RAR5_SIGNATURE);
        std::fs::write(&path, bytes).unwrap();

        assert!(rar5_recovery_data_candidate_allowed(&path).unwrap());
    }

    #[test]
    fn rar5_rev_parser_reads_full_data_volume_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part0002.rev");
        std::fs::write(&path, build_rar5_rev_bytes(true)).unwrap();

        let header = rar5_rev_header_at(&path).unwrap();
        let volumes = header.data_volumes.unwrap();

        assert_eq!(header.data_count, 1);
        assert_eq!(header.rec_count, 1);
        assert_eq!(header.rec_num, 1);
        assert_eq!(volumes[0].file_size, 123);
        assert_eq!(volumes[0].crc32, 0x1122_3344);
    }

    #[test]
    fn rar5_rev_parser_accepts_compact_non_first_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part0002.rev");
        std::fs::write(&path, build_rar5_rev_bytes(false)).unwrap();

        let header = rar5_rev_header_at(&path).unwrap();

        assert_eq!(header.data_count, 1);
        assert_eq!(header.rec_count, 1);
        assert_eq!(header.rec_num, 1);
        assert!(header.data_volumes.is_none());
    }

    #[test]
    fn rar5_rev_parser_ignores_truncated_header_body_like_rar_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part0002.rev");
        let mut bytes = REV5_SIGN.to_vec();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 1]);
        std::fs::write(&path, bytes).unwrap();

        assert!(rar5_rev_header_at(&path).is_none());
    }

    #[test]
    fn rar5_rev_parser_ignores_crc_valid_short_metadata_like_rar_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part0002.rev");
        std::fs::write(&path, build_rar5_rev_from_raw(&[1, 1, 0])).unwrap();

        assert!(rar5_rev_header_at(&path).is_none());
    }

    #[test]
    fn numbered_name_keeps_the_name_around_its_number() {
        let name = NumberedName::of(Path::new("/tmp/movie.part0001.rar")).unwrap();
        assert_eq!(
            (
                name.head.as_str(),
                name.digits.as_str(),
                name.tail.as_str(),
                name.ext.as_str()
            ),
            ("movie.part", "0001", "", "rar")
        );
        assert_eq!(name.with_number(7, 4, "rar"), "movie.part0007.rar");
        assert_eq!(name.with_number(12345, 4, "rar"), "movie.part12345.rar");

        // The first number after the dot is the volume's, not a total count
        // after it.
        let name = NumberedName::of(Path::new("/tmp/movie.part01of10.rar")).unwrap();
        assert_eq!(name.with_number(2, 2, "rar"), "movie.part02of10.rar");

        // A name that is all number is not a volume name RAR writes.
        assert_eq!(NumberedName::of(Path::new("/tmp/0001.rar")), None);
    }

    #[test]
    fn numbered_name_reads_its_number_only_at_the_set_width() {
        let number =
            |name: &str, width: usize| NumberedName::of(Path::new(name)).unwrap().number(width);
        assert_eq!(number("movie.part0001.rar", 4), Some(1));
        assert_eq!(number("movie.part001.rar", 4), None);
        assert_eq!(number("movie.part0001.rar", 2), None);
        assert_eq!(number("movie.part1.rar", 2), None);
        // Past the width, RAR's next-volume naming grows the number.
        assert_eq!(number("movie.part100.rar", 2), Some(100));
        assert_eq!(number("movie.part10.rar", 1), Some(10));

        let pattern = NumberedName::of(Path::new("movie.part01.rar")).unwrap();
        let fits = |name: &str| NumberedName::of(Path::new(name)).unwrap().fits(&pattern);
        assert!(fits("MOVIE.PART7.RAR"));
        assert!(!fits("movie.vol7.rar"));
        assert!(!fits("movie.part7of9.rar"));
    }

    #[test]
    fn volume_number_width_settles_on_what_every_name_allows() {
        // A leading zero fixes the width; a name without one allows any
        // width up to its length, and the widest left is taken.
        assert_eq!(volume_number_width(["01"], []), Ok(2));
        assert_eq!(volume_number_width(["10"], []), Ok(2));
        assert_eq!(volume_number_width(["1", "10"], []), Ok(1));
        assert_eq!(volume_number_width([], []), Ok(1));
        // Names that must fit and contradict each other are refused at the
        // first that does not fit.
        assert_eq!(volume_number_width(["01", "1"], []), Err(1));
        assert_eq!(volume_number_width(["001", "01", "1"], []), Err(1));
        // Hints narrow the width where they can and are passed over where
        // they would contradict it.
        assert_eq!(volume_number_width(["1"], ["01"]), Ok(1));
        assert_eq!(volume_number_width(["10"], ["1"]), Ok(1));
        assert_eq!(volume_number_width([], ["001", "0010"]), Ok(3));
    }

    #[test]
    fn rar5_recovery_renames_invalid_existing_data_volume_like_rar_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        std::fs::write(&path, b"bad data").unwrap();
        let mut slot = Rar5DataSlot {
            path: Some(path.clone()),
            output_path: path.clone(),
            file_size: 100,
            crc32: 0,
            valid: false,
        };

        rename_invalid_rar5_data_volume(&mut slot, &RecoveryOptions::default()).unwrap();

        assert!(slot.path.is_none());
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(bad_volume_path(&path)).unwrap(),
            b"bad data".to_vec()
        );
    }

    #[test]
    fn rar5_recovery_keeps_invalid_source_when_output_dir_differs() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("in").join("movie.part01.rar");
        let output = dir.path().join("out").join("movie.part01.rar");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, b"bad data").unwrap();
        let mut slot = Rar5DataSlot {
            path: Some(source.clone()),
            output_path: output,
            file_size: 100,
            crc32: 0,
            valid: false,
        };

        rename_invalid_rar5_data_volume(&mut slot, &RecoveryOptions::default()).unwrap();

        assert_eq!(slot.path.as_deref(), Some(source.as_path()));
        assert_eq!(std::fs::read(source).unwrap(), b"bad data".to_vec());
    }

    #[test]
    fn rar5_recovery_refuses_to_clobber_existing_bad_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        let bad_path = bad_volume_path(&path);
        std::fs::write(&path, b"bad data").unwrap();
        std::fs::write(&bad_path, b"previous backup").unwrap();
        let mut slot = Rar5DataSlot {
            path: Some(path.clone()),
            output_path: path.clone(),
            file_size: 100,
            crc32: 0,
            valid: false,
        };

        let err = rename_invalid_rar5_data_volume(&mut slot, &RecoveryOptions::default())
            .expect_err("existing .bad backup should be protected");

        assert!(matches!(err, RarError::Io(_)));
        assert!(path.exists());
        assert_eq!(
            std::fs::read(bad_path).unwrap(),
            b"previous backup".to_vec()
        );
    }

    /// A two-data, one-recovery RAR5 set written into `dir` with its first
    /// data volume missing: the second data volume and the `.rev` are
    /// present. Returns the present paths and the bytes the restore must put
    /// at `{stem}.part1.rar`. The recovery payload is arbitrary; the missing
    /// volume is whatever the decoder rebuilds from it, and the table carries
    /// that volume's size and CRC32, so the set is consistent by construction.
    fn synthetic_rar5_set(dir: &Path, stem: &str, seed: u8) -> (Vec<PathBuf>, Vec<u8>) {
        synthetic_rar5_set_with_payload_len(dir, stem, seed, 97)
    }

    fn synthetic_rar5_set_with_payload_len(
        dir: &Path,
        stem: &str,
        seed: u8,
        payload_len: usize,
    ) -> (Vec<PathBuf>, Vec<u8>) {
        let mut second = build_probe_rar5_archive(
            crate::header::main_archive::flags::VOLUME
                | crate::header::main_archive::flags::VOLUME_NUMBER,
            Some(1),
        );
        second.extend((0..payload_len).map(|i| (i as u8).wrapping_mul(7) ^ seed));
        let first_len = second.len() + 23;
        let rs_len = first_len + (first_len & 1);
        // The payload runs to the word the longest volume ends in, as RAR
        // writes it; when that volume is of odd length, the byte past it is
        // the high byte of its last word and takes part in the rebuild.
        let payload = (0..rs_len)
            .map(|i| (i as u8).wrapping_mul(13) ^ seed)
            .collect::<Vec<_>>();

        let coder = Rar5RsCoder::new_decoder(2, 1, &[false, true, true]).unwrap();
        let mut second_unit = second.clone();
        second_unit.resize(rs_len, 0);
        let mut first = vec![0u8; rs_len];
        coder.apply_units(&[&payload, &second_unit], &mut [&mut first[..]]);
        first.truncate(first_len);

        let mut raw = vec![1u8]; // version
        raw.extend_from_slice(&2u16.to_le_bytes()); // data count
        raw.extend_from_slice(&1u16.to_le_bytes()); // recovery count
        raw.extend_from_slice(&2u16.to_le_bytes()); // recovery volume number
        raw.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        for volume in [&first, &second] {
            raw.extend_from_slice(&(volume.len() as u64).to_le_bytes());
            raw.extend_from_slice(&crc32fast::hash(volume).to_le_bytes());
        }
        let mut rev = build_rar5_rev_from_raw(&raw);
        rev.extend_from_slice(&payload);

        let second_path = dir.join(format!("{stem}.part2.rar"));
        let rev_path = dir.join(format!("{stem}.part1.rev"));
        std::fs::write(&second_path, &second).unwrap();
        std::fs::write(&rev_path, &rev).unwrap();
        (vec![second_path, rev_path], first)
    }

    #[test]
    fn rar5_folded_restore_preserves_short_even_and_odd_volume_tails() {
        for payload_len in 0..4 {
            let dir = tempfile::tempdir().unwrap();
            let (paths, expected) =
                synthetic_rar5_set_with_payload_len(dir.path(), "short_tail", 0x63, payload_len);

            let report = restore_volumes_from_paths(&paths, &RecoveryOptions::default()).unwrap();

            let restored = dir.path().join("short_tail.part1.rar");
            assert_eq!(report.restored_paths, vec![restored.clone()]);
            assert_eq!(std::fs::read(restored).unwrap(), expected);
            assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());
        }
    }

    /// A rebuilt volume of odd length ends in the low byte of a word whose
    /// high byte the `.rev` payloads carry past the volume's length, and
    /// with two `.rev`s in the rebuild that high byte reaches the low byte.
    /// Four data volumes, the longest of odd length, and two `.rev`s; data
    /// volumes 1 and 2 are whatever the decoder rebuilds from the rest, so
    /// the set is consistent by construction, and the `.rev` bytes past the
    /// longest volume are chosen so that zeros in their place rebuild a
    /// different last byte.
    #[test]
    fn rar5_restore_reads_the_rev_bytes_past_an_odd_longest_volume() {
        let dir = tempfile::tempdir().unwrap();
        let flags = crate::header::main_archive::flags::VOLUME
            | crate::header::main_archive::flags::VOLUME_NUMBER;
        let first = {
            let mut bytes =
                build_probe_rar5_archive(crate::header::main_archive::flags::VOLUME, None);
            bytes.extend((0..1001usize).map(|i| (i as u8).wrapping_mul(29) ^ 0x51));
            bytes
        };
        let longest = first.len();
        assert!(
            !longest.is_multiple_of(2),
            "the longest volume is of odd length"
        );
        let rs_len = longest + 1;
        let fourth = {
            let mut bytes = build_probe_rar5_archive(flags, Some(3));
            bytes.extend((0..600usize).map(|i| (i as u8).wrapping_mul(31) ^ 0x1D));
            bytes
        };
        let payloads = [0x77u8, 0xC3].map(|seed| {
            (0..rs_len)
                .map(|i| (i as u8).wrapping_mul(13) ^ seed)
                .collect::<Vec<_>>()
        });
        assert!(payloads.iter().all(|payload| payload[longest] != 0));

        let coder =
            Rar5RsCoder::new_decoder(4, 2, &[true, false, false, true, true, true]).unwrap();
        let rebuild = |payloads: &[Vec<u8>]| {
            let mut first_unit = first.clone();
            first_unit.resize(rs_len, 0);
            let mut fourth_unit = fourth.clone();
            fourth_unit.resize(rs_len, 0);
            let mut second = vec![0u8; rs_len];
            let mut third = vec![0u8; rs_len];
            coder.apply_units(
                &[&first_unit, &payloads[0], &payloads[1], &fourth_unit],
                &mut [&mut second[..], &mut third[..]],
            );
            second.truncate(longest);
            third.truncate(longest);
            [second, third]
        };
        let expected = rebuild(&payloads);
        let zeroed = payloads.clone().map(|mut payload| {
            payload[longest] = 0;
            payload
        });
        assert_ne!(
            rebuild(&zeroed).map(|bytes| bytes[longest - 1]),
            expected.each_ref().map(|bytes| bytes[longest - 1]),
            "zeros past the longest volume rebuild other last bytes"
        );

        let volumes = [&first, &expected[0], &expected[1], &fourth];
        let mut paths = Vec::new();
        for (position, payload) in payloads.iter().enumerate() {
            let mut raw = vec![1u8]; // version
            raw.extend_from_slice(&4u16.to_le_bytes()); // data count
            raw.extend_from_slice(&2u16.to_le_bytes()); // recovery count
            raw.extend_from_slice(&(4 + position as u16).to_le_bytes()); // recovery volume number
            raw.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
            for volume in volumes {
                raw.extend_from_slice(&(volume.len() as u64).to_le_bytes());
                raw.extend_from_slice(&crc32fast::hash(volume).to_le_bytes());
            }
            let mut rev = build_rar5_rev_from_raw(&raw);
            rev.extend_from_slice(payload);
            let path = dir
                .path()
                .join(format!("odd_word.part{}.rev", position + 1));
            std::fs::write(&path, &rev).unwrap();
            paths.push(path);
        }
        for (index, volume) in [(0, &first), (3, &fourth)] {
            let path = dir.path().join(format!("odd_word.part{}.rar", index + 1));
            std::fs::write(&path, volume).unwrap();
            paths.push(path);
        }

        let report = restore_volumes_from_paths(&paths, &RecoveryOptions::default()).unwrap();

        let second = dir.path().join("odd_word.part2.rar");
        let third = dir.path().join("odd_word.part3.rar");
        assert_eq!(report.restored_paths, vec![second.clone(), third.clone()]);
        assert_eq!(report.missing_volume_numbers, vec![1, 2]);
        assert!(std::fs::read(second).unwrap() == expected[0]);
        assert!(std::fs::read(third).unwrap() == expected[1]);
        assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());
    }

    #[test]
    fn rar5_folded_restore_preserves_read_ahead_and_a_final_odd_tail() {
        let dir = tempfile::tempdir().unwrap();
        let chunk_size = rar5_chunk_size(u64::MAX, 2, 1, RAR5_TOTAL_BUFFER_SIZE);
        let header_len = build_probe_rar5_archive(
            crate::header::main_archive::flags::VOLUME
                | crate::header::main_archive::flags::VOLUME_NUMBER,
            Some(1),
        )
        .len();
        let (paths, expected) = synthetic_rar5_set_with_payload_len(
            dir.path(),
            "chunk_tail",
            0x74,
            chunk_size + 1 - header_len - 23,
        );
        // The fixture spans the unchanged two-input-set budget. Its expected
        // bytes were reconstructed in one pass, independently of chunking.
        assert_eq!(expected.len(), chunk_size + 1);
        assert!(!expected.len().is_multiple_of(2));

        let report = restore_volumes_from_paths(&paths, &RecoveryOptions::default()).unwrap();

        let restored = dir.path().join("chunk_tail.part1.rar");
        assert_eq!(report.restored_paths, vec![restored.clone()]);
        assert_eq!(std::fs::read(restored).unwrap(), expected);
        assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());
    }

    /// Hidden or `.partial` names in `dir`, other than `keep`.
    fn stray_partials(dir: &Path, keep: &[&Path]) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                (name.starts_with('.') || name.ends_with(".partial"))
                    && !keep.contains(&path.as_path())
            })
            .collect()
    }

    fn restore_into(dir: &Path, overwrite_existing: bool) -> RecoveryOptions {
        RecoveryOptions {
            output_dir: Some(dir.to_path_buf()),
            overwrite_existing,
            verify_restored: true,
        }
    }

    /// The speculative partial used to sit at `.<name>.<pid>.partial` and was
    /// opened truncating, so a file planted there was clobbered. A regular
    /// file at that name must now be left as it is, and the restore must
    /// still land byte for byte with nothing left behind.
    #[test]
    fn rar5_folded_restore_leaves_a_file_at_the_old_partial_name_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, expected) = synthetic_rar5_set(dir.path(), "fixture_alpha", 0x11);
        let output = dir.path().join("fixture_alpha.part1.rar");
        let planted = dir.path().join(format!(
            ".fixture_alpha.part1.rar.{}.partial",
            std::process::id()
        ));
        std::fs::write(&planted, b"not yours").unwrap();

        let report = restore_volumes_from_paths(&paths, &restore_into(dir.path(), false)).unwrap();

        assert_eq!(report.restored_paths, vec![output.clone()]);
        assert!(std::fs::read(&output).unwrap() == expected);
        assert_eq!(std::fs::read(&planted).unwrap(), b"not yours");
        assert_eq!(
            stray_partials(dir.path(), &[&planted]),
            Vec::<PathBuf>::new()
        );
    }

    /// A symlink at the old predictable partial name must be neither
    /// followed nor truncated: its target keeps its bytes.
    #[cfg(unix)]
    #[test]
    fn rar5_folded_restore_does_not_follow_a_symlink_at_the_old_partial_name() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let (paths, expected) = synthetic_rar5_set(dir.path(), "fixture_beta", 0x22);
        let victim = elsewhere.path().join("victim.bin");
        std::fs::write(&victim, b"keep these bytes").unwrap();
        let planted = dir.path().join(format!(
            ".fixture_beta.part1.rar.{}.partial",
            std::process::id()
        ));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        restore_volumes_from_paths(&paths, &restore_into(dir.path(), false)).unwrap();

        assert!(std::fs::read(dir.path().join("fixture_beta.part1.rar")).unwrap() == expected);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep these bytes");
        assert!(
            std::fs::symlink_metadata(&planted)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            stray_partials(dir.path(), &[&planted]),
            Vec::<PathBuf>::new()
        );
    }

    /// The exclusive create skips a taken name, a symlink included, without
    /// opening it, and takes the next one.
    #[test]
    fn create_exclusive_skips_a_taken_name_without_opening_it() {
        let dir = tempfile::tempdir().unwrap();
        let taken = dir.path().join(".taken.partial");
        let fresh = dir.path().join(".fresh.partial");
        std::fs::write(&taken, b"already here").unwrap();
        let mut names = [taken.clone(), fresh.clone()].into_iter();

        let (path, mut file) = create_exclusive(|| names.next().unwrap()).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);

        assert_eq!(path, fresh);
        assert_eq!(std::fs::read(&taken).unwrap(), b"already here");
        assert_eq!(std::fs::read(&fresh).unwrap(), b"new");

        let error = create_exclusive(|| taken.clone()).unwrap_err();
        assert!(
            matches!(&error, RarError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
            "{error}"
        );
        assert_eq!(std::fs::read(&taken).unwrap(), b"already here");
    }

    /// A file that appears at the output name after the restore staged its
    /// partial, and so after the existence check, is refused and kept: the
    /// install never replaces it, and the partial is left for cleanup.
    #[test]
    fn installing_a_partial_refuses_an_output_created_after_staging() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fixture_epsilon.part1.rar");
        let (partial, mut file) = create_partial(&target).unwrap();
        file.write_all(b"restored bytes").unwrap();
        drop(file);
        std::fs::write(&target, b"arrived meanwhile").unwrap();

        let error = install_partial(&partial, &target, false).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("refusing to overwrite existing restored volume"),
            "{error}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"arrived meanwhile");
        assert_eq!(std::fs::read(&partial).unwrap(), b"restored bytes");
    }

    /// The copy install for filesystems without hard links refuses a name
    /// taken before it starts and leaves that file alone, and otherwise
    /// copies the partial's bytes into place and removes the partial.
    #[test]
    fn copying_a_partial_exclusively_never_replaces_a_taken_name() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fixture_zeta.part1.rar");
        let (partial, mut file) = create_partial(&target).unwrap();
        file.write_all(b"restored bytes").unwrap();
        drop(file);
        std::fs::write(&target, b"arrived meanwhile").unwrap();

        let error = copy_partial_exclusively(&partial, &target).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refusing to overwrite existing restored volume"),
            "{error}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"arrived meanwhile");
        assert_eq!(std::fs::read(&partial).unwrap(), b"restored bytes");

        std::fs::remove_file(&target).unwrap();
        copy_partial_exclusively(&partial, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"restored bytes");
        assert!(!partial.exists());
    }

    /// Without a file in the way the install moves the partial into place
    /// and leaves no partial name behind; with `overwrite_existing` it
    /// replaces what is there.
    #[test]
    fn installing_a_partial_moves_it_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("fixture_zeta.part1.rar");
        let (partial, mut file) = create_partial(&target).unwrap();
        file.write_all(b"first restore").unwrap();
        drop(file);
        install_partial(&partial, &target, false).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first restore");
        assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());

        let (partial, mut file) = create_partial(&target).unwrap();
        file.write_all(b"second restore").unwrap();
        drop(file);
        install_partial(&partial, &target, true).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second restore");
        assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());
    }

    /// Two restores of distinct sets into one directory at once in one
    /// process: each lands byte for byte and neither leaves a partial.
    #[test]
    fn rar5_folded_restores_side_by_side_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let sets = [("fixture_gamma", 0x33), ("fixture_delta", 0x44)]
            .map(|(stem, seed)| (stem, synthetic_rar5_set(dir.path(), stem, seed)));
        let options = restore_into(dir.path(), false);

        std::thread::scope(|scope| {
            let handles = sets
                .iter()
                .map(|(_, (paths, _))| scope.spawn(|| restore_volumes_from_paths(paths, &options)))
                .collect::<Vec<_>>();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });

        for (stem, (_, expected)) in &sets {
            let output = dir.path().join(format!("{stem}.part1.rar"));
            assert!(std::fs::read(&output).unwrap() == *expected, "{stem}");
        }
        assert_eq!(stray_partials(dir.path(), &[]), Vec::<PathBuf>::new());
    }

    /// With `overwrite_existing`, a restore into a separate output directory
    /// replaces a target already there on every platform (the install is a
    /// rename onto it), and without it the restore refuses as before.
    #[test]
    fn rar5_folded_restore_replaces_an_existing_target_when_asked() {
        let source = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let (paths, expected) = synthetic_rar5_set(source.path(), "fixture_epsilon", 0x55);
        let target = out.path().join("fixture_epsilon.part1.rar");
        std::fs::write(&target, b"stale volume").unwrap();

        let error = restore_volumes_from_paths(&paths, &restore_into(out.path(), false))
            .expect_err("an existing target without overwrite is refused");
        assert!(
            error
                .to_string()
                .contains("refusing to overwrite existing restored volume"),
            "{error}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"stale volume");
        assert_eq!(stray_partials(out.path(), &[]), Vec::<PathBuf>::new());

        let report = restore_volumes_from_paths(&paths, &restore_into(out.path(), true)).unwrap();

        assert_eq!(report.restored_paths, vec![target.clone()]);
        assert!(std::fs::read(&target).unwrap() == expected);
        assert_eq!(stray_partials(out.path(), &[]), Vec::<PathBuf>::new());
    }

    /// A main header alone is not a volume RAR wrote: the scan needs the
    /// end-of-archive header, and reports the main header's flags either
    /// way.
    #[test]
    fn rar3_volume_scan_needs_an_end_of_archive_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        std::fs::write(&path, rar4_archive_with_recovery_flag()).unwrap();

        let scan = rar3_volume_scan_path(&path).unwrap().unwrap();
        assert_eq!(scan.status, DataVolumeStatus::InvalidHeaders);
        assert_eq!(
            scan.main_flags,
            Some(crate::rar4::types::archive_flags::RECOVERY)
        );
    }

    #[test]
    fn rar3_volume_scan_rejects_bad_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        std::fs::write(&path, b"not a rar").unwrap();

        let scan = rar3_volume_scan_path(&path).unwrap().unwrap();
        assert_eq!(scan.status, DataVolumeStatus::InvalidHeaders);
        assert_eq!(scan.main_flags, None);
    }

    #[test]
    fn rar3_volume_scan_accepts_matching_end_data_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        let mut bytes = rar4_archive_with_recovery_flag();
        append_rar4_end_data_crc(&mut bytes, false);
        std::fs::write(&path, bytes).unwrap();

        let scan = rar3_volume_scan_path(&path).unwrap().unwrap();
        assert_eq!(scan.status, DataVolumeStatus::Valid);
        assert_eq!(scan.end_volume_number, None);
    }

    #[test]
    fn rar3_volume_scan_rejects_mismatched_end_data_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        let mut bytes = rar4_archive_with_recovery_flag();
        append_rar4_end_data_crc(&mut bytes, true);
        std::fs::write(&path, bytes).unwrap();

        let scan = rar3_volume_scan_path(&path).unwrap().unwrap();
        assert_eq!(scan.status, DataVolumeStatus::CrcMismatch);
    }

    #[test]
    fn rar3_volume_scan_reports_no_file_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");

        assert!(rar3_volume_scan_path(&path).unwrap().is_none());
    }

    /// The scan's verdict holds in a slot only for a volume its main header
    /// marks a volume, and whose end-of-archive header, when it numbers the
    /// volume, numbers it as that slot's.
    #[test]
    fn rar3_volume_status_checks_the_volume_flag_and_number() {
        use crate::rar4::types::archive_flags::{ENCRYPTED_HEADERS, VOLUME};
        let scan = |main_flags, status, end_volume_number| Rar3VolumeScan {
            main_flags,
            status,
            end_volume_number,
        };
        let valid = DataVolumeStatus::Valid;
        let invalid = DataVolumeStatus::InvalidHeaders;
        let status = |scan: Rar3VolumeScan, index| rar3_volume_status(&scan, index);

        assert_eq!(status(scan(Some(VOLUME), valid.clone(), Some(2)), 2), valid);
        assert_eq!(status(scan(Some(VOLUME), valid.clone(), None), 2), valid);
        assert_eq!(
            status(scan(Some(VOLUME), valid.clone(), Some(3)), 2),
            invalid
        );
        assert_eq!(status(scan(Some(0), valid.clone(), None), 0), invalid);
        assert_eq!(status(scan(None, valid.clone(), None), 0), invalid);
        assert_eq!(
            status(
                scan(Some(VOLUME | ENCRYPTED_HEADERS), valid.clone(), None),
                4
            ),
            valid
        );
        assert_eq!(
            status(
                scan(Some(VOLUME), DataVolumeStatus::CrcMismatch, Some(2)),
                2
            ),
            DataVolumeStatus::CrcMismatch
        );
        assert_eq!(
            status(scan(Some(VOLUME), invalid.clone(), None), 2),
            invalid
        );
    }

    /// `.rev`s alone do not name a RAR3 set's data volumes: one of its data
    /// volumes must be there to take the naming from.
    #[test]
    fn rar3_survey_requires_a_data_volume_of_the_set() {
        let dir = tempfile::tempdir().unwrap();
        let rev = dir.path().join("movie.part01_02_03.rev");
        std::fs::write(&rev, b"old style recovery payload").unwrap();

        let error = plan_volume_restore(&[rev], &RecoveryOptions::default())
            .expect_err("a RAR3 set needs one of its data volumes");
        match error {
            RarError::CorruptArchive { detail } => assert!(
                detail.contains("requires at least one data volume of the recovery set"),
                "{detail}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rar3_naming_follows_new_numbering_at_the_volume_width() {
        let naming = Rar3Naming::of(Path::new("/tmp/movie.part01.rar"), true).unwrap();
        assert_eq!(naming.base(), "movie.part");
        assert_eq!(naming.data_name(0), "movie.part01.rar");
        assert_eq!(naming.data_name(6), "movie.part07.rar");
        assert_eq!(naming.data_name(99), "movie.part100.rar");
        let index = |name: &str| naming.data_index(Path::new(name));
        assert_eq!(index("/x/movie.part07.rar"), Some(6));
        assert_eq!(index("/x/MOVIE.PART07.RAR"), Some(6));
        assert_eq!(index("/x/movie.part100.rar"), Some(99));
        assert_eq!(index("/x/movie.part7.rar"), None);
        assert_eq!(index("/x/movie.part007.rar"), None);
        assert_eq!(index("/x/movie.part00.rar"), None);
        assert_eq!(index("/x/movie.part07.rev"), None);
        assert_eq!(index("/x/other.part07.rar"), None);

        // The extension keeps the case of the volume the naming came from.
        let upper = Rar3Naming::of(Path::new("/tmp/MOVIE.PART1.RAR"), true).unwrap();
        assert_eq!(upper.data_name(2), "MOVIE.PART3.RAR");

        // New numbering names a numbered `.rar`.
        assert!(Rar3Naming::of(Path::new("/tmp/movie.rar"), true).is_none());
        assert!(Rar3Naming::of(Path::new("/tmp/movie.part1.exe"), true).is_none());
    }

    #[test]
    fn rar3_naming_follows_old_letter_numbering() {
        let naming = Rar3Naming::of(Path::new("/tmp/movie.r00"), false).unwrap();
        assert_eq!(naming.base(), "movie");
        for (index, name) in [
            (0, "movie.rar"),
            (1, "movie.r00"),
            (2, "movie.r01"),
            (100, "movie.r99"),
            (101, "movie.s00"),
        ] {
            assert_eq!(naming.data_name(index), name);
            assert_eq!(naming.data_index(Path::new(name)), Some(index), "{name}");
        }
        assert_eq!(naming.data_index(Path::new("MOVIE.R01")), Some(2));
        assert_eq!(naming.data_index(Path::new("movie.001")), None);
        assert_eq!(naming.data_index(Path::new("movies.r01")), None);

        let upper = Rar3Naming::of(Path::new("/tmp/MOVIE.R00"), false).unwrap();
        assert_eq!(upper.data_name(0), "MOVIE.RAR");
        assert_eq!(upper.data_name(2), "MOVIE.R01");
    }

    #[test]
    fn rar3_naming_follows_old_numeric_numbering() {
        let naming = Rar3Naming::of(Path::new("/tmp/movie.001"), false).unwrap();
        for (index, name) in [
            (0, "movie.001"),
            (1, "movie.002"),
            (998, "movie.999"),
            (999, "movie.a00"),
        ] {
            assert_eq!(naming.data_name(index), name);
            assert_eq!(naming.data_index(Path::new(name)), Some(index), "{name}");
        }
        assert_eq!(naming.data_index(Path::new("movie.000")), None);
        assert_eq!(naming.data_index(Path::new("movie.rar")), None);
        assert_eq!(naming.data_index(Path::new("movie.r00")), None);
    }

    #[test]
    fn parse_old_rar3_extension_reads_both_numberings() {
        assert_eq!(parse_old_rar3_extension("rar", false), Some(0));
        assert_eq!(parse_old_rar3_extension("RAR", false), Some(0));
        assert_eq!(parse_old_rar3_extension("r00", false), Some(1));
        assert_eq!(parse_old_rar3_extension("S00", false), Some(101));
        assert_eq!(parse_old_rar3_extension("z99", false), Some(900));
        assert_eq!(parse_old_rar3_extension("001", false), None);
        assert_eq!(parse_old_rar3_extension("r0", false), None);
        assert_eq!(parse_old_rar3_extension("001", true), Some(0));
        assert_eq!(parse_old_rar3_extension("000", true), None);
        assert_eq!(parse_old_rar3_extension("a00", true), Some(999));
        assert_eq!(parse_old_rar3_extension("q99", true), Some(2698));
        assert_eq!(parse_old_rar3_extension("rar", true), None);
    }

    #[test]
    fn rar3_rev_membership_takes_the_set_names_only() {
        let footer = RevRead::Rar3 {
            header: Rar3RevHeader {
                rec_position: 1,
                rec_count: 2,
                data_count: 5,
                new_style: true,
            },
            payload: RevPayload {
                file: tempfile::tempfile().unwrap(),
                start: Some(0),
                len: 0,
                expected: 0,
            },
        };
        let params = |header: Option<Rar3RevHeader>| {
            header.map(|header| {
                (
                    header.data_count,
                    header.rec_count,
                    header.rec_position,
                    header.new_style,
                )
            })
        };
        let member = |path: &str, read: &RevRead| {
            rar3_rev_membership("movie.part", Path::new(path), read).map(params)
        };

        assert_eq!(
            member("/x/movie.part1.rev", &footer),
            Some(Some((5, 2, 1, true)))
        );
        assert_eq!(
            member("/x/MOVIE.PART001.REV", &footer),
            Some(Some((5, 2, 1, true)))
        );
        // The set's name over nothing a footer can be read from is the
        // set's, and states nothing.
        assert_eq!(
            member("/x/movie.part1.rev", &RevRead::Unrecognised),
            Some(None)
        );
        // Any other name is not the set's.
        assert_eq!(member("/x/movie.part1x.rev", &footer), None);
        assert_eq!(member("/x/movie.part.rev", &footer), None);
        assert_eq!(member("/x/other.part1.rev", &footer), None);

        // A RAR 3.0-style name states the set itself, after the base or
        // after an underscore.
        let old = |path: &str| {
            rar3_rev_membership("movie", Path::new(path), &RevRead::Rar3Old).map(params)
        };
        assert_eq!(old("/x/movie5_3_1.rev"), Some(Some((5, 3, 1, false))));
        assert_eq!(old("/x/movie_5_3_2.rev"), Some(Some((5, 3, 2, false))));
        // One whose numbers no set RAR wrote is the set's by name, and
        // states nothing.
        assert_eq!(old("/x/movie200_100_1.rev"), Some(None));
        assert_eq!(old("/x/movie5_0_1.rev"), Some(None));
        assert_eq!(old("/x/movie999_1_1.rev"), Some(None));
        assert_eq!(old("/x/movies5_3_1.rev"), None);
    }

    #[test]
    fn rar3_footer_parser_accepts_new_style_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part03.rev");
        let mut bytes = b"payload".to_vec();
        // Footer bytes are read as P[2], P[1], P[0], each stored minus one.
        bytes.extend_from_slice(&[2, 1, 0]);
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();

        let rev = rar3_footer_rev_at(&path).unwrap();
        assert_eq!(rev.header.data_count, 3);
        assert_eq!(rev.header.rec_count, 2);
        assert_eq!(rev.header.rec_position, 1);
        assert!(rev.header.new_style);
        assert_eq!(rev.crc, Rar3RevCrc::Matched);
        assert!(rev.accepted());
        assert_eq!(rev.test_status(), RevTestStatus::Ok);
    }

    /// A footer whose CRC32 fails is still read, with both CRCs, so a test
    /// can report it; the restore does not use it.
    #[test]
    fn rar3_footer_parser_reports_a_failed_crc_with_both_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part03.rev");
        let mut bytes = b"payload".to_vec();
        bytes.extend_from_slice(&[2, 1, 0]);
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes[0] ^= 0x5A;
        let actual = crc32fast::hash(&bytes[..bytes.len() - 4]);
        std::fs::write(&path, bytes).unwrap();

        let rev = rar3_footer_rev_at(&path).unwrap();

        assert_eq!(
            rev.crc,
            Rar3RevCrc::Mismatch {
                expected: crc,
                actual
            }
        );
        assert_ne!(crc, actual);
        assert!(!rev.accepted());
        assert_eq!(
            rev.test_status(),
            RevTestStatus::CrcMismatch {
                expected: crc,
                actual
            }
        );
    }

    /// A position past the set's recovery volumes is one reference UnRAR's
    /// plausibility check lets through and its restore never uses: the
    /// footer reads, and the survey lists the volume as unusable.
    #[test]
    fn rar3_footer_parser_reads_a_position_past_the_recovery_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part03.rev");
        let mut bytes = b"payload".to_vec();
        // Position 3 of a two-volume recovery set.
        bytes.extend_from_slice(&[2, 1, 2]);
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();

        let rev = rar3_footer_rev_at(&path).unwrap();
        assert_eq!(rev.header.rec_position, 3);
        assert_eq!(rev.header.rec_count, 2);
        assert_eq!(rev.crc, Rar3RevCrc::Matched);
    }

    /// Set parameters RAR 3.x could not have written make the footer no
    /// `.rev` footer at all, whatever its CRC32 says, as reference UnRAR
    /// passes such a volume over: more data and recovery volumes than 255,
    /// or a position past the 255th volume.
    #[test]
    fn rar3_footer_parser_rejects_a_set_past_255_volumes_even_with_a_matching_crc() {
        let dir = tempfile::tempdir().unwrap();
        // 201 data and 101 recovery volumes; then 251 data volumes and
        // position 6 of one recovery volume.
        for (name, params) in [
            ("movie.part01.rev", [200, 100, 0]),
            ("movie.part02.rev", [250, 0, 5]),
        ] {
            let path = dir.path().join(name);
            let mut bytes = b"payload".to_vec();
            bytes.extend_from_slice(&params);
            let crc = crc32fast::hash(&bytes);
            bytes.extend_from_slice(&crc.to_le_bytes());
            std::fs::write(&path, bytes).unwrap();

            assert!(rar3_footer_rev_at(&path).is_none(), "{name}");
            assert_eq!(
                test_recovery_volume(&path).status,
                RevTestStatus::InvalidHeader,
                "{name}"
            );
        }
    }

    #[test]
    fn rar3_rev_parser_accepts_old_style_name_without_footer_crc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie5_3_1.rev");
        std::fs::write(&path, b"old style recovery payload").unwrap();

        let read = read_rev(File::open(&path).unwrap(), &path).unwrap();
        assert!(matches!(read, RevRead::Rar3Old));
        let header = rar3_rev_membership("movie", &path, &read).unwrap().unwrap();
        assert_eq!(header.data_count, 5);
        assert_eq!(header.rec_count, 3);
        assert_eq!(header.rec_position, 1);
        assert!(!header.new_style);
        let rev = Rar3Rev {
            header,
            crc: Rar3RevCrc::Untestable,
        };
        assert!(rev.accepted());
        assert_eq!(rev.test_status(), RevTestStatus::Unverifiable);
    }

    #[test]
    fn rar3_restored_output_footer_scrub_is_new_style_only() {
        let dir = tempfile::tempdir().unwrap();
        let old_style = dir.path().join("old-style.rar");
        let new_style = dir.path().join("new-style.rar");
        let payload = b"archive bytes plus footer";
        std::fs::write(&old_style, payload).unwrap();
        std::fs::write(&new_style, payload).unwrap();

        let mut old_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&old_style)
            .unwrap();
        finalize_rar3_restored_output(&mut old_file, false, false).unwrap();
        drop(old_file);

        let mut new_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&new_style)
            .unwrap();
        finalize_rar3_restored_output(&mut new_file, true, false).unwrap();
        drop(new_file);

        assert_eq!(std::fs::read(&old_style).unwrap(), payload);

        let mut expected = payload.to_vec();
        let len = expected.len();
        expected[len - 7..].fill(0);
        assert_eq!(std::fs::read(&new_style).unwrap(), expected);
    }

    /// One RAR 1.5-4.x header block: the CRC16, type, flags and size over
    /// `body`, which holds the fields after the size.
    fn rar4_block(header_type: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; 7];
        header[2] = header_type;
        header[3..5].copy_from_slice(&flags.to_le_bytes());
        header[5..7].copy_from_slice(&((7 + body.len()) as u16).to_le_bytes());
        header.extend_from_slice(body);
        let crc = (crc32fast::hash(&header[2..]) & 0xFFFF) as u16;
        header[0..2].copy_from_slice(&crc.to_le_bytes());
        header
    }

    /// The signature and main header of a RAR 1.5-4.x volume with `flags`.
    fn rar4_volume_start(flags: u16) -> Vec<u8> {
        let mut bytes = crate::signature::RAR4_SIGNATURE.to_vec();
        bytes.extend_from_slice(&rar4_block(0x73, flags, &[0u8; 6]));
        bytes
    }

    /// A stored file header for `name` whose packed and unpacked sizes are
    /// `size`, with the LARGE high words when `size` needs them.
    fn rar4_stored_file_header(name: &[u8], size: u64) -> Vec<u8> {
        use crate::rar4::types::{common_flags, file_flags};
        let large = size > u64::from(u32::MAX);
        let mut body = Vec::new();
        body.extend_from_slice(&(size as u32).to_le_bytes()); // packed low
        body.extend_from_slice(&(size as u32).to_le_bytes()); // unpacked low
        body.push(2); // Windows
        body.extend_from_slice(&0u32.to_le_bytes()); // CRC32
        body.extend_from_slice(&0u32.to_le_bytes()); // mtime
        body.push(29);
        body.push(0x30); // store
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // attributes
        if large {
            body.extend_from_slice(&((size >> 32) as u32).to_le_bytes());
            body.extend_from_slice(&((size >> 32) as u32).to_le_bytes());
        }
        body.extend_from_slice(name);
        let flags = common_flags::HAS_DATA | if large { file_flags::LARGE } else { 0 };
        rar4_block(0x74, flags, &body)
    }

    fn rar4_end_block() -> Vec<u8> {
        rar4_block(0x7B, 0, &[])
    }

    fn open_rw(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn rar3_last_restored_volume_truncates_zero_padding_after_endarc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last-volume.rar");
        let mut bytes = rar4_volume_start(crate::rar4::types::archive_flags::VOLUME);
        bytes.extend_from_slice(&rar4_stored_file_header(b"a.bin", 5));
        bytes.extend_from_slice(b"hello");
        bytes.extend_from_slice(&rar4_end_block());
        let block_end = bytes.len();
        bytes.extend_from_slice(&[0u8; 32]);
        std::fs::write(&path, bytes).unwrap();

        let mut file = open_rw(&path);
        finalize_rar3_restored_output(&mut file, false, true).unwrap();
        drop(file);

        assert_eq!(std::fs::metadata(&path).unwrap().len(), block_end as u64);
    }

    /// A rebuilt last volume whose headers are encrypted (`-hp`) cannot be
    /// walked to its end-of-archive block: it is left as it is, and the
    /// restore does not fail on it. The volumes are RARLAB's `-hp` archives,
    /// padded as a `.rev`'s slot pads the set's last volume.
    #[test]
    fn rar3_last_restored_volume_with_encrypted_headers_is_left_uncut() {
        let dir = tempfile::tempdir().unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar4");
        let mut seen = 0;
        for name in ["rar4_hp_store.rar", "rar4_hp_lz.rar"] {
            let Ok(mut bytes) = std::fs::read(fixtures.join(name)) else {
                continue;
            };
            if !bytes.starts_with(b"Rar!") {
                continue;
            }
            seen += 1;
            bytes.resize(bytes.len() + 4096, 0);
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();

            let mut file = open_rw(&path);
            truncate_rar3_last_volume_padding(&mut file).unwrap();
            drop(file);

            assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name}");
        }
        if seen == 0 {
            eprintln!("skipping test: RAR4 -hp fixtures not present");
        }
    }

    /// A damaged rebuilt last volume is left as it is too, for
    /// `verify_restored` to judge, rather than failing the restore after it
    /// was written.
    #[test]
    fn rar3_last_restored_volume_with_damaged_headers_is_left_uncut() {
        let dir = tempfile::tempdir().unwrap();
        let mut sound = rar4_volume_start(crate::rar4::types::archive_flags::VOLUME);
        sound.extend_from_slice(&rar4_stored_file_header(b"a.bin", 5));
        sound.extend_from_slice(b"hello");
        sound.extend_from_slice(&rar4_end_block());
        sound.extend_from_slice(&[0u8; 32]);
        let mut bad_signature = sound.clone();
        bad_signature[0] ^= 0x5A;
        let mut bad_header_size = sound.clone();
        bad_header_size[7 + 13 + 5] = 1; // the file header says it is 1 byte long
        let truncated_header = sound[..7 + 13 + 4].to_vec();
        for (case, bytes) in [
            ("a damaged signature", bad_signature),
            ("a header shorter than its fixed part", bad_header_size),
            ("a header cut short by the volume's end", truncated_header),
        ] {
            let path = dir.path().join("last-volume.rar");
            std::fs::write(&path, &bytes).unwrap();
            let mut file = open_rw(&path);
            truncate_rar3_last_volume_padding(&mut file).unwrap();
            drop(file);
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "{case}");
        }
    }

    /// The walk to the end-of-archive block skips a member by its 64-bit
    /// packed size: a member over 4 GiB, whose low 32 bits alone would land
    /// the walk inside its data, is stepped over and the padding after the
    /// block is cut. The member's data is a hole in a sparse file.
    #[cfg(unix)]
    #[test]
    fn rar3_last_restored_volume_walks_a_member_over_4_gib() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last-volume.rar");
        let size = (1u64 << 32) + 100;
        let mut head = rar4_volume_start(crate::rar4::types::archive_flags::VOLUME);
        head.extend_from_slice(&rar4_stored_file_header(b"big.bin", size));
        let data_start = head.len() as u64;
        let mut file = File::create(&path).unwrap();
        file.write_all(&head).unwrap();
        file.seek(SeekFrom::Start(data_start + size)).unwrap();
        let tail_start = data_start + size;
        file.write_all(&rar4_end_block()).unwrap();
        let block_end = tail_start + 7;
        file.write_all(&[0u8; 32]).unwrap();
        drop(file);

        let mut file = open_rw(&path);
        truncate_rar3_last_volume_padding(&mut file).unwrap();
        drop(file);

        assert_eq!(std::fs::metadata(&path).unwrap().len(), block_end);
    }

    #[test]
    fn rar3_rev_parser_rejects_invalid_old_style_name_params() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie5_0_1.rev");
        std::fs::write(&path, b"old style recovery payload").unwrap();

        let read = read_rev(File::open(&path).unwrap(), &path).unwrap();
        assert!(matches!(read, RevRead::Rar3Old));
        assert!(matches!(
            rar3_rev_membership("movie", &path, &read),
            Some(None)
        ));
        assert_eq!(parse_old_rar3_rev_name(&path), None);
    }

    #[test]
    fn restore_reports_embedded_recovery_records_are_not_fake_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.rar");
        std::fs::write(&path, rar4_archive_with_recovery_flag()).unwrap();

        let err = restore_volumes_from_paths(&[path], &RecoveryOptions::default()).unwrap_err();
        match err {
            RarError::CorruptArchive { detail } => {
                assert!(detail.contains("embedded Rar4 recovery record detected"));
                assert!(detail.contains("standalone .rev recovery volumes only"));
                assert!(detail.contains("standalone .rev recovery volumes only"));
                assert!(detail.contains("does not consume embedded RR/protect data"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn data_entry(index: usize, status: DataVolumeStatus) -> DataVolumePlan {
        DataVolumePlan {
            index,
            path: None,
            status,
            output_path: PathBuf::from(format!("/out/movie.part{}.rar", index + 1)),
            set_aside_path: None,
        }
    }

    fn rev_entry(slot: usize, usable: bool) -> RecoveryVolumePlan {
        RecoveryVolumePlan {
            slot,
            volume_number: 4 + slot,
            path: PathBuf::from(format!("/out/movie.part{}.rev", slot + 1)),
            status: if usable {
                RevTestStatus::Ok
            } else {
                RevTestStatus::CrcMismatch {
                    expected: 1,
                    actual: 2,
                }
            },
            usable,
        }
    }

    /// The usable recovery count counts slots, so an entry repeated for one
    /// slot rebuilds one volume, and an unusable `.rev` rebuilds none.
    #[test]
    fn restore_plan_counts_each_usable_recovery_slot_once() {
        let plan = RestorePlan {
            format: ArchiveFormat::Rar5,
            data_count: 4,
            recovery_count: 3,
            data_volumes: vec![
                data_entry(0, DataVolumeStatus::Valid),
                data_entry(1, DataVolumeStatus::Missing),
                data_entry(2, DataVolumeStatus::Valid),
                data_entry(
                    3,
                    DataVolumeStatus::WrongSize {
                        expected: 10,
                        actual: 9,
                    },
                ),
            ],
            recovery_volumes: vec![rev_entry(0, true), rev_entry(0, true), rev_entry(1, false)],
            output_dir: PathBuf::from("/out"),
        };

        assert_eq!(plan.missing_volume_numbers(), vec![1, 3]);
        assert_eq!(plan.needed(), 2);
        assert_eq!(plan.usable_recovery_count(), 1);
        assert!(!plan.is_complete());
        assert!(!plan.is_sufficient());

        let mut covered = plan.clone();
        covered.recovery_volumes.push(rev_entry(2, true));
        assert_eq!(covered.usable_recovery_count(), 2);
        assert!(covered.is_sufficient());

        let complete = RestorePlan {
            data_volumes: vec![
                data_entry(0, DataVolumeStatus::Valid),
                data_entry(1, DataVolumeStatus::Valid),
            ],
            recovery_volumes: Vec::new(),
            ..plan
        };
        assert_eq!(complete.missing_volume_numbers(), Vec::<usize>::new());
        assert_eq!(complete.needed(), 0);
        assert!(complete.is_complete());
        assert!(complete.is_sufficient());
    }

    /// The `.bad` name is the restore's rename rule: only the file at the
    /// output name is set aside, and naming it moves nothing.
    #[test]
    fn set_aside_name_names_only_the_file_at_the_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.part01.rar");
        std::fs::write(&path, b"bad data").unwrap();

        assert_eq!(
            set_aside_name(&path, &path).unwrap(),
            Some(dir.path().join("movie.part01.rar.bad"))
        );
        assert_eq!(
            set_aside_name(&path, &dir.path().join(".").join("movie.part01.rar")).unwrap(),
            Some(dir.path().join("movie.part01.rar.bad"))
        );
        assert_eq!(
            set_aside_name(&path, &dir.path().join("out").join("movie.part01.rar")).unwrap(),
            None
        );
        let gone = dir.path().join("movie.part02.rar");
        assert_eq!(set_aside_name(&gone, &gone).unwrap(), None);
        assert_eq!(std::fs::read(&path).unwrap(), b"bad data");
        assert!(!dir.path().join("movie.part01.rar.bad").exists());
    }

    #[test]
    fn data_volume_plan_follows_the_restore_rename_rule() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("movie.part01.rar");
        std::fs::write(&present, b"volume").unwrap();
        let output = dir.path().join("out").join("movie.part01.rar");

        // A valid volume stays where it is.
        assert_eq!(
            data_volume_plan(
                0,
                Some(present.clone()),
                DataVolumeStatus::Valid,
                output.clone()
            )
            .unwrap(),
            DataVolumePlan {
                index: 0,
                path: Some(present.clone()),
                status: DataVolumeStatus::Valid,
                output_path: present.clone(),
                set_aside_path: None,
            }
        );

        // An invalid volume at its output name is set aside first.
        let in_place = data_volume_plan(
            0,
            Some(present.clone()),
            DataVolumeStatus::CrcMismatch,
            present.clone(),
        )
        .unwrap();
        assert_eq!(in_place.output_path, present);
        assert_eq!(in_place.set_aside_path, Some(bad_volume_path(&present)));

        // One anywhere else is left alone, and the rebuilt volume is written
        // to the output name.
        let elsewhere = data_volume_plan(
            0,
            Some(present.clone()),
            DataVolumeStatus::InvalidHeaders,
            output.clone(),
        )
        .unwrap();
        assert_eq!(elsewhere.path, Some(present.clone()));
        assert_eq!(elsewhere.output_path, output);
        assert_eq!(elsewhere.set_aside_path, None);

        // A path with no file behind it is reported as no file.
        let gone = dir.path().join("movie.part02.rar");
        assert_eq!(
            data_volume_plan(
                1,
                Some(gone.clone()),
                DataVolumeStatus::Missing,
                gone.clone()
            )
            .unwrap(),
            DataVolumePlan {
                index: 1,
                path: None,
                status: DataVolumeStatus::Missing,
                output_path: gone,
                set_aside_path: None,
            }
        );
        assert!(!dir.path().join("out").exists());
        assert!(!bad_volume_path(&present).exists());
    }

    #[test]
    fn test_recovery_volume_classifies_each_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let tested = |path: &Path| {
            let result = test_recovery_volume(path);
            assert_eq!(result.path, path);
            (result.format, result.status)
        };

        // The header states a payload CRC32 and the file has no payload.
        let rar5 = dir.path().join("movie.part0002.rev");
        std::fs::write(&rar5, build_rar5_rev_bytes(true)).unwrap();
        assert_eq!(
            tested(&rar5),
            (
                Some(ArchiveFormat::Rar5),
                RevTestStatus::CrcMismatch {
                    expected: 0xAABB_CCDD,
                    actual: crc32fast::hash(&[]),
                }
            )
        );

        // A RAR5 signature decides the format: a header that does not parse
        // is not tried as a RAR3 footer.
        let rar5_short = dir.path().join("movie.part0003.rev");
        std::fs::write(&rar5_short, build_rar5_rev_from_raw(&[1, 1, 0])).unwrap();
        assert_eq!(tested(&rar5_short), (None, RevTestStatus::InvalidHeader));

        let rar3 = dir.path().join("movie.part03.rev");
        let mut bytes = b"payload".to_vec();
        bytes.extend_from_slice(&[2, 1, 0]);
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        std::fs::write(&rar3, bytes).unwrap();
        assert_eq!(
            tested(&rar3),
            (Some(ArchiveFormat::Rar4), RevTestStatus::Ok)
        );

        let old_style = dir.path().join("movie5_3_1.rev");
        std::fs::write(&old_style, b"old style recovery payload").unwrap();
        assert_eq!(
            tested(&old_style),
            (Some(ArchiveFormat::Rar4), RevTestStatus::Unverifiable)
        );

        let data = dir.path().join("movie.part01.rar");
        std::fs::write(&data, rar4_archive_with_recovery_flag()).unwrap();
        assert_eq!(tested(&data), (None, RevTestStatus::NotRecoveryVolume));

        let gone = dir.path().join("movie.part0004.rev");
        assert_eq!(tested(&gone), (None, RevTestStatus::Missing));

        // A RAR 3.0-style name is untestable whatever numbers it carries.
        for name in ["movie200_100_1.rev", "movie5_0_1.rev", "movie999_1_1.rev"] {
            let path = dir.path().join(name);
            std::fs::write(&path, b"old style recovery payload").unwrap();
            assert_eq!(
                tested(&path),
                (Some(ArchiveFormat::Rar4), RevTestStatus::Unverifiable),
                "{name}"
            );
        }

        // A path that cannot be read is reported as such.
        let directory = dir.path().join("movie.part0005.rev");
        std::fs::create_dir(&directory).unwrap();
        let (format, status) = tested(&directory);
        assert_eq!(format, None);
        assert!(
            matches!(status, RevTestStatus::Unreadable { .. }),
            "{status:?}"
        );
        #[cfg(unix)]
        assert_eq!(
            status,
            RevTestStatus::Unreadable {
                kind: std::io::ErrorKind::IsADirectory
            }
        );
    }
}
