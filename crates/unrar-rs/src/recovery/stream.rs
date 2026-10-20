//! Recovery-volume restore over volumes the caller holds.
//!
//! The path restore in the parent module finds a set by its file names and
//! writes files beside it. This one is told the set's shape ([`RestoreSet`]),
//! reads through a [`VolumeSource`] and hands rebuilt bytes to a sink, so a
//! caller that keeps volumes in memory or in its own store restores without
//! staging files. The two share the format code: the RAR5 `.rev` header
//! parser, the RAR3 footer parser and header walk, and the decoders. They
//! keep separate I/O, so the path restore reads and writes as it did.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;

use rayon::prelude::*;
use reedsolomon_rs::decode_apply::apply_decode_matrix_gf8;
use reedsolomon_rs::rar3::Rar3RsCoder;
use reedsolomon_rs::rar5::Rar5RsCoder;
use reedsolomon_rs::{gf_simd, gf8, threading};

use super::{
    CRC_READ_SIZE, DataVolumeStatus, MAX_RAR3_SET, RAR3_PADDING_PROBE, REV5_PREFIX_LEN, REV5_SIGN,
    Rar3EndBlock, Rar3RevHeader, Rar3VolumeScan, Rar3Walk, Rar3WalkStep, Rar5DataVolumeInfo,
    Rar5RevHeader, RevTestStatus, parse_rar3_rev_footer, rar3_missing_rows, rar3_scan_verdict,
    rar3_volume_status, rar5_chunk_size, read_rar5_rev_header,
};
use crate::error::RarResult;
use crate::types::ArchiveFormat;

/// The default [`StreamRestoreOptions::memory_bytes`].
const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
/// The most threads [`StreamRestoreOptions::default`] asks for: the field
/// arithmetic is bound by memory bandwidth well before this, and one restore
/// should not claim every core of a large machine by default.
const MAX_DEFAULT_WORKERS: usize = 16;
/// The smallest read a pass over a volume makes, whatever the budget.
const MIN_READ_SIZE: usize = 4096;
/// The bytes a RAR3 header walk reads to find the signature.
const RAR3_SIGNATURE_READ: usize = 8;
/// The fixed part of every RAR3 header, the least a header step reads.
const RAR3_HEADER_MIN: usize = 7;
/// The longest run one fold task multiplies: long enough to repay handing it
/// to a worker, short enough that one read splits across the pool.
const FOLD_STRIPE: usize = 64 * 1024;

/// Positional reads of the volumes a [`RestoreSet`] lists, for
/// [`assess_volume_set`] and [`restore_volume_set`].
///
/// Data volume `index` is the set's zero-based volume number; recovery volume
/// `position` is its zero-based place among the set's recovery volumes, so
/// `name.part1.rev` is position 0. A read fills `into` from byte `offset` of
/// that volume and returns the count it placed at the front of `into`.
///
/// A count short of `into.len()` says the volume holds nothing at or past
/// `offset + count`: the restore takes that as the volume's end, or as a hole
/// in it, and judges the volume on it. It never asks again for the rest and
/// never reads zeros in its place. An implementation whose reads can stop
/// short of what it holds (a socket, a pipe) loops until `into` is full or
/// the bytes run out. An error ends the call with
/// [`VolumeRestoreError::Io`] naming the volume, except
/// [`ErrorKind::Interrupted`](io::ErrorKind::Interrupted), which is retried.
///
/// The restore asks only for volumes the set marks present, never for one it
/// was told is bad, and never past the length the set gives. Every call comes
/// from the thread that called the restore, one at a time and in the order
/// the restore needs the bytes, so the trait asks for neither `Send` nor
/// `Sync`: worker threads only multiply bytes already read.
pub trait VolumeSource {
    /// Read data volume `index` from byte `offset` into `into`.
    fn read_data(&mut self, index: usize, offset: u64, into: &mut [u8]) -> io::Result<usize>;

    /// Read the recovery volume at `position` from byte `offset` into `into`.
    fn read_recovery(&mut self, position: usize, offset: u64, into: &mut [u8])
    -> io::Result<usize>;
}

/// The volumes a caller holds, by slot: `data[i]` is data volume `i` and
/// `recovery[p]` the recovery volume at position `p`, each `Some` with the
/// volume's length in bytes when the caller has it and `None` when not.
///
/// The vectors' lengths are the set's counts, so they include the volumes
/// the caller lacks, the last ones too. A RAR5 `.rev` header and a RAR 3.10
/// `.rev` footer state the counts and must agree with them; a RAR 3.0 `.rev`
/// states nothing and is taken at the position given.
///
/// Built with [`new`](Self::new) or [`Default`] outside this crate, so a
/// later field does not break callers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestoreSet {
    pub data: Vec<Option<u64>>,
    pub recovery: Vec<Option<u64>>,
}

impl RestoreSet {
    /// The set of these volume lengths, by slot.
    pub fn new(data: Vec<Option<u64>>, recovery: Vec<Option<u64>>) -> Self {
        Self { data, recovery }
    }
}

/// How a stream restore spends threads and memory.
///
/// Built from [`Default`] outside this crate, with fields set after, so a
/// later field does not break callers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamRestoreOptions {
    /// Threads for the field arithmetic, at most the machine's available
    /// parallelism: more would only take turns on its cores. At 0 or 1, or
    /// on a machine that runs one thread at a time, it all runs on the
    /// calling thread. Above that the call builds its own pool, so the
    /// caller's rayon pool, global or installed, is never borrowed. Reads and
    /// sink calls stay on the calling thread either way. Default: the
    /// machine's available parallelism, at most 16.
    pub workers: usize,
    /// The most the decode aims to hold in buffers at once: a target, not a
    /// hard cap. When the rebuilt volumes fit in it beside one read buffer,
    /// the restore holds them whole and reads each data volume once;
    /// otherwise it reads each data volume once to check it and once more to
    /// decode, holding a slice of every volume at a time, and no slice is
    /// cut below 4 KiB (or the volume's length, when shorter) however small
    /// the budget. A pass over a volume reads up to 256 KiB at a time, never
    /// less than 4 KiB, and a RAR3 header walk buffers up to 4 MiB while it
    /// searches for a signature past the start of a volume; neither counts
    /// against this. Default: 64 MiB.
    pub memory_bytes: usize,
}

impl Default for StreamRestoreOptions {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(MAX_DEFAULT_WORKERS),
            memory_bytes: DEFAULT_MEMORY_BYTES,
        }
    }
}

/// The volume an error names. Indexes and positions are zero-based, as in
/// [`RestoreSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VolumeRef {
    /// A data volume, read through [`VolumeSource::read_data`].
    Data(usize),
    /// A recovery volume, read through [`VolumeSource::read_recovery`].
    Recovery(usize),
    /// The sink, while it took the rebuilt bytes of this data volume.
    Output(usize),
}

impl std::fmt::Display for VolumeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(index) => write!(f, "data volume {index}"),
            Self::Recovery(position) => write!(f, "recovery volume {position}"),
            Self::Output(index) => write!(f, "the sink for rebuilt data volume {index}"),
        }
    }
}

/// Why [`assess_volume_set`] or [`restore_volume_set`] stopped.
///
/// No variant has a [`source`](std::error::Error::source): `Io` renders its
/// I/O error, as [`RarError::Io`](crate::RarError::Io) does, so a reporter
/// that walks the chain prints it once. A caller reaches the I/O error by
/// matching `Io`.
#[derive(Debug)]
#[non_exhaustive]
pub enum VolumeRestoreError {
    /// A read of the source or a call of the sink failed, or a volume that
    /// passed its check came back shorter when it was read again.
    Io {
        volume: VolumeRef,
        source: io::Error,
    },
    /// A recovery volume whose header (RAR5) or footer (RAR3) passes its CRC
    /// states a place in the set other than the position it was given.
    CorruptRecoveryVolume { position: usize, reason: String },
    /// The volumes disagree with the set or with each other.
    InconsistentSet { reason: String },
    /// More data volumes to rebuild than usable recovery volumes. A restore
    /// raises it before reading any data volume when the ones absent, known
    /// bad or of the wrong length already outnumber the usable recovery
    /// volumes; `missing` counts only those then.
    Insufficient { missing: usize, usable: usize },
    /// The set has no recovery volume, or (RAR5) none whose header reads. A
    /// set is RAR5 when a `.rev` starts with the RAR5 signature or, when no
    /// `.rev` shows that signature or a RAR 3.10 footer, a data volume does.
    NoRecoveryVolumes,
}

impl std::fmt::Display for VolumeRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { volume, source } => write!(f, "I/O error on {volume}: {source}"),
            Self::CorruptRecoveryVolume { position, reason } => {
                write!(f, "recovery volume {position} is corrupt: {reason}")
            }
            Self::InconsistentSet { reason } => write!(f, "inconsistent recovery set: {reason}"),
            Self::Insufficient { missing, usable } => write!(
                f,
                "cannot rebuild {missing} data volumes from {usable} usable recovery volumes"
            ),
            Self::NoRecoveryVolumes => {
                f.write_str("the set has no recovery volume with a readable header")
            }
        }
    }
}

impl std::error::Error for VolumeRestoreError {}

/// What a set's volumes hold, as [`assess_volume_set`] finds them and as
/// [`restore_volume_set`] found them before rebuilding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeAssessment {
    /// [`ArchiveFormat::Rar5`] or, for a RAR 3.x set,
    /// [`ArchiveFormat::Rar4`], as the path restore reports it.
    pub format: ArchiveFormat,
    pub data_count: usize,
    pub recovery_count: usize,
    /// One per data volume, in index order.
    pub data: Vec<DataVolumeState>,
    /// One per recovery volume, in position order.
    pub recovery: Vec<RecoveryVolumeState>,
    /// Data volumes that are not [`DataVolumeStatus::Valid`]: the ones a
    /// restore rebuilds.
    pub missing: usize,
    /// Recovery volumes a restore can use.
    pub usable: usize,
}

impl VolumeAssessment {
    /// Whether a restore could rebuild every missing data volume.
    pub fn is_sufficient(&self) -> bool {
        self.missing <= self.usable
    }

    /// Whether every data volume is present and valid.
    pub fn is_complete(&self) -> bool {
        self.missing == 0
    }
}

/// One data volume of a [`VolumeAssessment`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataVolumeState {
    pub index: usize,
    pub status: DataVolumeStatus,
    /// The length the RAR5 `.rev` table states; `None` for RAR3, whose
    /// `.rev`s state none.
    pub expected_len: Option<u64>,
    /// The CRC32 the RAR5 `.rev` table states; `None` for RAR3.
    pub crc32: Option<u32>,
}

/// One recovery volume of a [`VolumeAssessment`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryVolumeState {
    pub position: usize,
    /// [`RevTestStatus::Missing`] when the set lacks it,
    /// [`RevTestStatus::Unreadable`] with
    /// [`UnexpectedEof`](io::ErrorKind::UnexpectedEof) when the source ran
    /// out before the length the set gives, and
    /// [`RevTestStatus::InvalidHeader`] for a RAR 3.0 `.rev` shorter than a
    /// data volume present and not known bad, as RAR writes each as long as
    /// the longest. That rule also fires when a slot holds something longer
    /// than the `.rev`s, bytes appended to a volume or a wrong file: every
    /// RAR 3.0 `.rev` is then unusable until that slot is passed in
    /// `known_bad`.
    pub status: RevTestStatus,
    /// Whether a restore uses it: its CRC matched, or it is a RAR 3.0
    /// `.rev`, which carries none, of the length RAR writes.
    pub usable: bool,
}

/// One data volume [`restore_volume_set`] rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestoredVolume {
    pub index: usize,
    /// The bytes the sink received for it.
    pub len: u64,
    /// The CRC32 of those bytes.
    pub crc32: u32,
    /// Whether the rebuilt bytes pass the check a present volume gets: a RAR5
    /// volume's CRC32 matches the `.rev` table; a RAR3 volume's headers read
    /// through to an end-of-archive header that numbers it as this volume,
    /// and the data CRC that header states, when it states one, matches. A
    /// RAR3 volume whose headers are encrypted passes on its main header
    /// alone, as a present one does. The RAR3 check covers the walk up to
    /// and including the end-of-archive block and no byte after it, so a
    /// RAR3 volume rebuilt past that block is not checked there.
    pub verified: bool,
}

/// What [`restore_volume_set`] found and rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VolumeRestoreReport {
    /// The set as the restore found it, before rebuilding.
    pub assessment: VolumeAssessment,
    /// The rebuilt data volumes, in index order; empty when nothing was
    /// missing.
    pub restored: Vec<RestoredVolume>,
}

/// Judge every volume of a set without rebuilding anything: what
/// [`restore_volume_set`] would find, and whether it could rebuild the set.
///
/// Each present recovery volume is read once, and each data volume that is
/// present and not in `known_bad` is read once, a damaged RAR3 volume only as
/// far as its header walk fails, beside the reads that tell a set's format
/// when its `.rev`s do not (see [`restore_volume_set`]). The checks are
/// [`restore_volume_set`]'s. A set short of usable recovery volumes is an
/// assessment whose [`is_sufficient`](VolumeAssessment::is_sufficient) is
/// false rather than an error, so a caller can say how many more volumes it
/// needs before fetching them. `options.workers` is unused: nothing is
/// decoded.
///
/// # Errors
///
/// As [`restore_volume_set`], without
/// [`Insufficient`](VolumeRestoreError::Insufficient).
pub fn assess_volume_set(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    known_bad: &[usize],
    options: &StreamRestoreOptions,
) -> Result<VolumeAssessment, VolumeRestoreError> {
    let mut survey = Survey::new(set, source, known_bad, options)?;
    survey.check_all(source)?;
    Ok(survey.assessment())
}

/// Rebuild a set's missing and damaged data volumes from its recovery
/// volumes, handing the rebuilt bytes to `write`.
///
/// `write(index, offset, bytes)` receives each rebuilt data volume once and
/// in order: for each index, the offsets start at 0 and run on without a gap
/// to the length the report gives. Calls for different volumes interleave
/// when the decode works a slice at a time. Nothing the sink was handed is
/// taken back, cut short afterwards or written again.
///
/// # Checks
///
/// A data volume in `known_bad` or absent from the set is rebuilt without
/// being read. The rest are checked before anything is rebuilt from them:
///
/// - RAR5. Every `.rev` header must parse, state the set's counts
///   (`data.len()` data and `recovery.len()` recovery volumes) and number
///   its volume as the position it was given, and every data volume table
///   the headers carry must be the same. A `.rev` is usable when its payload
///   CRC32 matches its header's, and the table may give no data volume more
///   bytes than a usable `.rev`'s payload holds. A data volume whose length
///   differs from the table is [`WrongSize`](DataVolumeStatus::WrongSize)
///   and is not read; the others must match the table's CRC32.
/// - RAR3. A `.rev` written by RAR 3.10 or later ends in a footer that
///   states the set's counts and its own position, under a CRC32 of the rest
///   of the file. A set where a `.rev` shows such a footer is checked on its
///   footers, which must agree with the set; a `.rev` whose CRC32 fails is
///   unusable. A set where none does is a RAR 3.0 set, whose `.rev`s state
///   nothing but their length: every one the source can read is used,
///   unverified, at the position given, unless it is shorter than a data
///   volume present and not known bad, as RAR writes each as long as the
///   longest. Such a set needs a data volume, present and not known bad,
///   whose RAR 1.5-4.x main header reads and marks it a volume; a data
///   volume that starts with the RAR5 signature makes it a RAR5 set whose
///   `.rev` headers all failed. A data volume's headers must read through
///   to its end-of-archive header, which must number it as its slot, and the
///   data CRC that header states, when it states one, must match.
///
/// # Reads
///
/// Every data volume the decode uses has passed its check before a rebuilt
/// byte goes to `write`. When the volumes to rebuild fit in
/// `options.memory_bytes`, each data volume is read once: the check and the
/// decode share the read, and the rebuilt volumes are held until every check
/// has passed, then written. If a check fails there, the held bytes are
/// dropped, the remaining volumes are checked, and the decode runs again over
/// the ones that passed. Otherwise each data volume is read once to check it
/// and once more to decode. Either way no data volume is read through more
/// than twice. Each recovery volume is read once to check it and once more if
/// the decode uses it; a RAR3 decode uses only as many as there are volumes
/// to rebuild. When no `.rev` shows the RAR5 signature or a RAR 3.10 footer,
/// the data volumes tell the format before anything is checked: the first
/// eight bytes of each, then each in turn up to its main header until one
/// reads as a RAR 1.5-4.x volume; a volume with no signature at its start is
/// searched for one up to the 4 MiB an SFX stub may take.
///
/// # Output
///
/// A RAR5 volume is rebuilt to the length its table states. A RAR3 volume is
/// rebuilt to the length of the longest volume the decode reads, the length
/// RAR3 recovery volumes are written at. When the set's `.rev`s carry
/// footers, a rebuilt volume's last seven bytes are written as zero: the
/// footer took their place in every `.rev`, and RAR reserves them as zero in
/// the volume. The set's last data volume ends at its end-of-archive block
/// when the 8 KiB after it, or all of it if shorter, are zero, as reference
/// UnRAR cuts it; those bytes are held back until that is decided, so the
/// sink never sees bytes the cut drops. When the walk cannot find that block
/// (headers encrypted, or damaged), nothing is cut, as UnRAR without a
/// password cuts nothing.
///
/// The field arithmetic runs on `options.workers` threads; the reads and the
/// calls of `write` stay on the calling thread.
///
/// # Errors
///
/// - [`Io`](VolumeRestoreError::Io): a source read or a call of `write`
///   failed ([`VolumeRef::Output`] names the volume being written), or a
///   volume that passed its check came back shorter when read again.
/// - [`CorruptRecoveryVolume`](VolumeRestoreError::CorruptRecoveryVolume): a
///   recovery volume states another position than the one it was given.
/// - [`InconsistentSet`](VolumeRestoreError::InconsistentSet): the volumes
///   disagree with the set or with each other (counts, tables), a RAR5 table
///   gives a data volume more bytes than a usable `.rev` carries, a RAR 3.0
///   set has no data volume whose main header reads, a `known_bad` index is
///   past the set, or a RAR3 set holds more than 255 volumes.
/// - [`Insufficient`](VolumeRestoreError::Insufficient): more data volumes to
///   rebuild than usable recovery volumes.
/// - [`NoRecoveryVolumes`](VolumeRestoreError::NoRecoveryVolumes): no
///   recovery volume is present, or no RAR5 `.rev` header reads, the set
///   being RAR5 by a `.rev` or, failing that, by a data volume.
// The sink's type is written out, not aliased, so the docs show what it takes.
#[allow(clippy::type_complexity)]
pub fn restore_volume_set(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    known_bad: &[usize],
    options: &StreamRestoreOptions,
    write: &mut dyn FnMut(usize, u64, &[u8]) -> io::Result<()>,
) -> Result<VolumeRestoreReport, VolumeRestoreError> {
    let mut survey = Survey::new(set, source, known_bad, options)?;
    let usable = survey.usable();
    // Absent, known-bad and wrongly sized volumes are rebuilt whatever the
    // rest hold, so too many of them settle it before a data volume is read.
    let candidates = survey.judged();
    if candidates.len() > usable {
        return Err(VolumeRestoreError::Insufficient {
            missing: candidates.len(),
            usable,
        });
    }

    let mut arith = Arith::new(options.workers);
    let fits = !candidates.is_empty()
        && survey.held_bytes(&candidates).is_some_and(|held| {
            held.saturating_add(survey.io_size as u64) <= options.memory_bytes as u64
        });
    if fits {
        if let Some(restored) = fold(&mut survey, source, &candidates, &mut arith, write)? {
            return Ok(VolumeRestoreReport {
                assessment: survey.assessment(),
                restored,
            });
        }
    } else {
        survey.check_all(source)?;
    }

    let missing = survey.missing();
    if missing.len() > usable {
        return Err(VolumeRestoreError::Insufficient {
            missing: missing.len(),
            usable,
        });
    }
    let restored = if missing.is_empty() {
        Vec::new()
    } else {
        decode(&survey, source, &missing, options, &mut arith, write)?
    };
    Ok(VolumeRestoreReport {
        assessment: survey.assessment(),
        restored,
    })
}

/// A [`VolumeSource`] over open files, one per slot.
///
/// Reads are positional (`read_at` on Unix, `seek_read` on Windows), so
/// nothing depends on or moves a file's cursor; on other targets each read
/// seeks first.
#[derive(Debug)]
pub struct FileVolumeSource {
    data: Vec<Option<File>>,
    recovery: Vec<Option<File>>,
}

impl FileVolumeSource {
    /// Files by slot, as [`RestoreSet`] lists volumes, with `None` for a
    /// volume the caller lacks.
    pub fn new(data: Vec<Option<File>>, recovery: Vec<Option<File>>) -> Self {
        Self { data, recovery }
    }

    /// The set these files make, each at its file's length now.
    pub fn restore_set(&self) -> io::Result<RestoreSet> {
        fn lengths(files: &[Option<File>]) -> io::Result<Vec<Option<u64>>> {
            files
                .iter()
                .map(|file| {
                    file.as_ref()
                        .map(|file| Ok(file.metadata()?.len()))
                        .transpose()
                })
                .collect()
        }
        Ok(RestoreSet::new(
            lengths(&self.data)?,
            lengths(&self.recovery)?,
        ))
    }
}

impl VolumeSource for FileVolumeSource {
    fn read_data(&mut self, index: usize, offset: u64, into: &mut [u8]) -> io::Result<usize> {
        read_file_at(slot(&self.data, index, "data volume")?, offset, into)
    }

    fn read_recovery(
        &mut self,
        position: usize,
        offset: u64,
        into: &mut [u8],
    ) -> io::Result<usize> {
        read_file_at(
            slot(&self.recovery, position, "recovery volume")?,
            offset,
            into,
        )
    }
}

/// A [`VolumeSource`] over volumes held in memory, one buffer per slot.
#[derive(Debug, Clone)]
pub struct SliceVolumeSource<T = Vec<u8>> {
    data: Vec<Option<T>>,
    recovery: Vec<Option<T>>,
}

impl<T: AsRef<[u8]>> SliceVolumeSource<T> {
    /// Buffers by slot, as [`RestoreSet`] lists volumes, with `None` for a
    /// volume the caller lacks.
    pub fn new(data: Vec<Option<T>>, recovery: Vec<Option<T>>) -> Self {
        Self { data, recovery }
    }

    /// The set these buffers make, each at its length.
    pub fn restore_set(&self) -> RestoreSet {
        fn lengths<T: AsRef<[u8]>>(buffers: &[Option<T>]) -> Vec<Option<u64>> {
            buffers
                .iter()
                .map(|buffer| buffer.as_ref().map(|buffer| buffer.as_ref().len() as u64))
                .collect()
        }
        RestoreSet::new(lengths(&self.data), lengths(&self.recovery))
    }
}

impl<T: AsRef<[u8]>> VolumeSource for SliceVolumeSource<T> {
    fn read_data(&mut self, index: usize, offset: u64, into: &mut [u8]) -> io::Result<usize> {
        let bytes = slot(&self.data, index, "data volume")?.as_ref();
        Ok(read_slice_at(bytes, offset, into))
    }

    fn read_recovery(
        &mut self,
        position: usize,
        offset: u64,
        into: &mut [u8],
    ) -> io::Result<usize> {
        let bytes = slot(&self.recovery, position, "recovery volume")?.as_ref();
        Ok(read_slice_at(bytes, offset, into))
    }
}

/// The volume a source holds in slot `at`, or `NotFound` when it holds none:
/// the set given with the source marked present a volume the source lacks.
fn slot<'a, T>(slots: &'a [Option<T>], at: usize, what: &str) -> io::Result<&'a T> {
    slots.get(at).and_then(Option::as_ref).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("the source holds no {what} {at}"),
        )
    })
}

fn read_slice_at(bytes: &[u8], offset: u64, into: &mut [u8]) -> usize {
    let start = usize::try_from(offset).map_or(bytes.len(), |offset| offset.min(bytes.len()));
    let count = (bytes.len() - start).min(into.len());
    into[..count].copy_from_slice(&bytes[start..start + count]);
    count
}

/// Fill `into` from byte `offset` of `file` until it is full or the file
/// ends, as [`VolumeSource`] asks: a positional read may return less than
/// the file holds.
fn read_file_at(file: &File, offset: u64, into: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < into.len() {
        match positional_read(file, offset + filled as u64, &mut into[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

#[cfg(unix)]
fn positional_read(file: &File, offset: u64, into: &mut [u8]) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, into, offset)
}

#[cfg(windows)]
fn positional_read(file: &File, offset: u64, into: &mut [u8]) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, into, offset)
}

#[cfg(not(any(unix, windows)))]
fn positional_read(mut file: &File, offset: u64, into: &mut [u8]) -> io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    file.read(into)
}

/// Where rebuilt bytes go: `(index, offset, bytes)`.
type Sink<'a> = &'a mut dyn FnMut(usize, u64, &[u8]) -> io::Result<()>;

/// A volume the restore reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Volume {
    Data(usize),
    Recovery(usize),
}

impl From<Volume> for VolumeRef {
    fn from(volume: Volume) -> Self {
        match volume {
            Volume::Data(index) => Self::Data(index),
            Volume::Recovery(position) => Self::Recovery(position),
        }
    }
}

fn io_error(volume: impl Into<VolumeRef>, source: io::Error) -> VolumeRestoreError {
    VolumeRestoreError::Io {
        volume: volume.into(),
        source,
    }
}

/// A volume that passed its check and holds fewer bytes when read again: the
/// source changed under the restore.
fn changed_volume(volume: Volume, at: u64, end: u64) -> VolumeRestoreError {
    io_error(
        volume,
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "the volume ended at byte {at} when read again, short of the {end} bytes it held when checked"
            ),
        ),
    )
}

/// The status of a recovery volume the source holds less of than the set
/// says.
fn short_status() -> RevTestStatus {
    RevTestStatus::Unreadable {
        kind: io::ErrorKind::UnexpectedEof,
    }
}

/// One read of `volume`: the count the source placed in `into`, short of
/// `into.len()` only where the volume ends or has a hole.
fn read_at(
    source: &mut dyn VolumeSource,
    volume: Volume,
    offset: u64,
    into: &mut [u8],
) -> Result<usize, VolumeRestoreError> {
    if into.is_empty() {
        return Ok(0);
    }
    loop {
        let read = match volume {
            Volume::Data(index) => source.read_data(index, offset, into),
            Volume::Recovery(position) => source.read_recovery(position, offset, into),
        };
        match read {
            Ok(count) if count <= into.len() => return Ok(count),
            Ok(count) => {
                return Err(io_error(
                    volume,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "the source reported {count} bytes read into a {}-byte buffer",
                            into.len()
                        ),
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error(volume, error)),
        }
    }
}

/// How a pass over part of a volume ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassEnd {
    /// Every byte of the range was read.
    Done,
    /// The source ran out at this offset, before the end of the range.
    Short(u64),
    /// The callback asked to stop.
    Stopped,
}

/// Read `range` of `volume` in `buf`-sized pieces, in order, handing each
/// piece and its offset to `each`, which returns whether to go on.
fn read_through(
    source: &mut dyn VolumeSource,
    volume: Volume,
    range: Range<u64>,
    buf: &mut [u8],
    mut each: impl FnMut(u64, &[u8]) -> bool,
) -> Result<PassEnd, VolumeRestoreError> {
    let mut at = range.start;
    while at < range.end {
        let want = (range.end - at).min(buf.len() as u64) as usize;
        let got = read_at(source, volume, at, &mut buf[..want])?;
        if got > 0 && !each(at, &buf[..got]) {
            return Ok(PassEnd::Stopped);
        }
        at += got as u64;
        if got < want {
            return Ok(PassEnd::Short(at));
        }
    }
    Ok(PassEnd::Done)
}

/// A [`Read`] over `pos..end` of one volume, for the parsers that take a
/// reader. A short read from the source ends it there; an error from the
/// source is kept for the caller to report as that volume's.
struct SourceReader<'a> {
    source: &'a mut dyn VolumeSource,
    volume: Volume,
    pos: u64,
    end: u64,
    /// The source ran out before `end`.
    short: bool,
    error: Option<VolumeRestoreError>,
}

impl Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.error.is_some() {
            return Err(io::Error::other("the volume source failed"));
        }
        let want = self.end.saturating_sub(self.pos).min(buf.len() as u64) as usize;
        if self.short || want == 0 {
            return Ok(0);
        }
        match read_at(self.source, self.volume, self.pos, &mut buf[..want]) {
            Ok(count) => {
                self.pos += count as u64;
                self.short = count < want;
                Ok(count)
            }
            Err(error) => {
                self.error = Some(error);
                Err(io::Error::other("the volume source failed"))
            }
        }
    }
}

/// The first bytes of a present `.rev`, which say what format the set is.
struct RevPrefix {
    len: u64,
    bytes: [u8; REV5_PREFIX_LEN],
    /// Bytes read: the whole prefix, or all of a shorter volume.
    got: usize,
    /// Whether the source held every byte asked for.
    whole: bool,
}

impl RevPrefix {
    fn rar5(&self) -> bool {
        self.got >= REV5_SIGN.len() && self.bytes[..REV5_SIGN.len()] == REV5_SIGN[..]
    }
}

/// A set as its checks have judged it so far.
struct Survey {
    data_len: Vec<Option<u64>>,
    rec_len: Vec<Option<u64>>,
    format: SetFormat,
    /// Each data volume's verdict, `None` while it waits to be read.
    data: Vec<Option<DataVolumeStatus>>,
    recovery: Vec<RecoveryVolumeState>,
    /// How much a pass over a volume reads at a time.
    io_size: usize,
}

/// What a set's recovery volumes say about it.
enum SetFormat {
    Rar5 {
        /// Every data volume's length and CRC32.
        table: Vec<Rar5DataVolumeInfo>,
        /// Where each usable `.rev`'s payload starts; 0 for the others.
        payload: Vec<u64>,
    },
    Rar3 {
        /// Whether the `.rev`s end in RAR 3.10 footers, which took the place
        /// of the last seven bytes a rebuilt volume gets.
        footers: bool,
    },
}

impl Survey {
    /// Check the set's shape and its recovery volumes, and judge the data
    /// volumes that need no read: absent, known bad, or (RAR5) of a length
    /// other than the table's.
    fn new(
        set: &RestoreSet,
        source: &mut dyn VolumeSource,
        known_bad: &[usize],
        options: &StreamRestoreOptions,
    ) -> Result<Self, VolumeRestoreError> {
        let data_count = set.data.len();
        if let Some(&index) = known_bad.iter().find(|&&index| index >= data_count) {
            return Err(VolumeRestoreError::InconsistentSet {
                reason: format!(
                    "known-bad data volume {index} is past the set's {data_count} data volumes"
                ),
            });
        }
        if set.recovery.iter().all(Option::is_none) {
            return Err(VolumeRestoreError::NoRecoveryVolumes);
        }
        let io_size = (CRC_READ_SIZE.min(options.memory_bytes) & !1).max(MIN_READ_SIZE);
        let mut buf = vec![0u8; io_size];

        let mut prefixes = Vec::with_capacity(set.recovery.len());
        for (position, len) in set.recovery.iter().enumerate() {
            let Some(len) = *len else {
                prefixes.push(None);
                continue;
            };
            let mut bytes = [0u8; REV5_PREFIX_LEN];
            let want = len.min(REV5_PREFIX_LEN as u64) as usize;
            let got = read_at(source, Volume::Recovery(position), 0, &mut bytes[..want])?;
            prefixes.push(Some(RevPrefix {
                len,
                bytes,
                got,
                whole: got == want,
            }));
        }
        let mut bad = vec![false; data_count];
        for &index in known_bad {
            bad[index] = true;
        }
        // The set is RAR5 when any `.rev` starts with the RAR5 signature;
        // RAR3 `.rev`s have no signature to look for. When none shows a
        // RAR 3.10 footer either, the data volumes say which it is, and they
        // do before the RAR3 survey refuses a set too large to be RAR3.
        let (format, recovery) = if prefixes.iter().flatten().any(RevPrefix::rar5) {
            survey_rar5(set, source, &prefixes, &mut buf)?
        } else {
            if data_count + set.recovery.len() > MAX_RAR3_SET && rar5_data(set, source, &bad)? {
                return Err(VolumeRestoreError::NoRecoveryVolumes);
            }
            let surveyed = survey_rar3(set, source, &prefixes, &bad, &mut buf)?;
            if let SetFormat::Rar3 { footers: false } = surveyed.0 {
                check_rar30_data(set, source, &bad)?;
            }
            surveyed
        };

        let data = set
            .data
            .iter()
            .zip(&bad)
            .enumerate()
            .map(|(index, (len, &bad))| match (len, &format) {
                (None, _) => Some(DataVolumeStatus::Missing),
                _ if bad => Some(DataVolumeStatus::Missing),
                (Some(len), SetFormat::Rar5 { table, .. }) if *len != table[index].file_size => {
                    Some(DataVolumeStatus::WrongSize {
                        expected: table[index].file_size,
                        actual: *len,
                    })
                }
                _ => None,
            })
            .collect();

        Ok(Self {
            data_len: set.data.clone(),
            rec_len: set.recovery.clone(),
            format,
            data,
            recovery,
            io_size,
        })
    }

    fn usable(&self) -> usize {
        self.recovery.iter().filter(|rev| rev.usable).count()
    }

    /// The data volumes judged without a read, every one of them to rebuild.
    fn judged(&self) -> Vec<usize> {
        self.data
            .iter()
            .enumerate()
            .filter(|(_, status)| status.is_some())
            .map(|(index, _)| index)
            .collect()
    }

    /// The data volumes judged anything but valid.
    fn missing(&self) -> Vec<usize> {
        self.data
            .iter()
            .enumerate()
            .filter(|(_, status)| status.as_ref() != Some(&DataVolumeStatus::Valid))
            .map(|(index, _)| index)
            .collect()
    }

    /// The bytes the rebuilt volumes take, held whole, when `missing` are
    /// rebuilt.
    fn held_bytes(&self, missing: &[usize]) -> Option<u64> {
        match &self.format {
            SetFormat::Rar5 { table, .. } => missing.iter().try_fold(0u64, |sum, &index| {
                let len = table[index].file_size;
                sum.checked_add(len.checked_add(len & 1)?)
            }),
            SetFormat::Rar3 { .. } => {
                let len = self
                    .rar3_inputs(missing)
                    .iter()
                    .map(|input| input.avail)
                    .max()
                    .unwrap_or(0);
                len.checked_mul(missing.len() as u64)
            }
        }
    }

    /// The RAR3 decode's inputs when `missing` are rebuilt: every other data
    /// volume, then as many usable `.rev`s as there are volumes to rebuild, in
    /// position order. A `.rev` past those would only add an equation the
    /// decode does not need.
    fn rar3_inputs(&self, missing: &[usize]) -> Vec<Input> {
        let mut rebuilt = vec![false; self.data_len.len()];
        for &index in missing {
            rebuilt[index] = true;
        }
        let data = self
            .data_len
            .iter()
            .zip(rebuilt)
            .enumerate()
            .filter(|(_, (_, rebuilt))| !rebuilt)
            .map(|(index, (len, _))| Input {
                volume: Volume::Data(index),
                start: 0,
                avail: len.unwrap_or(0),
            });
        let recovery = self
            .recovery
            .iter()
            .filter(|rev| rev.usable)
            .take(missing.len())
            .map(|rev| Input {
                volume: Volume::Recovery(rev.position),
                start: 0,
                avail: self.rec_len[rev.position].unwrap_or(0),
            });
        data.chain(recovery).collect()
    }

    /// Read and judge every data volume not judged yet, one after another.
    fn check_all(&mut self, source: &mut dyn VolumeSource) -> Result<(), VolumeRestoreError> {
        let mut buf = vec![0u8; self.io_size];
        for index in 0..self.data.len() {
            let (None, Some(len)) = (&self.data[index], self.data_len[index]) else {
                continue;
            };
            let mut check = DataCheck::new(self, index);
            let end = read_through(source, Volume::Data(index), 0..len, &mut buf, |_, bytes| {
                check.push(bytes);
                !check.failed()
            })?;
            self.data[index] = Some(check.finish(end));
        }
        Ok(())
    }

    fn assessment(&self) -> VolumeAssessment {
        let data = self
            .data
            .iter()
            .enumerate()
            .map(|(index, status)| {
                let (expected_len, crc32) = match &self.format {
                    SetFormat::Rar5 { table, .. } => {
                        (Some(table[index].file_size), Some(table[index].crc32))
                    }
                    SetFormat::Rar3 { .. } => (None, None),
                };
                DataVolumeState {
                    index,
                    status: status
                        .clone()
                        .expect("every data volume is judged before the assessment is built"),
                    expected_len,
                    crc32,
                }
            })
            .collect::<Vec<_>>();
        let missing = data
            .iter()
            .filter(|state| state.status != DataVolumeStatus::Valid)
            .count();
        VolumeAssessment {
            format: match self.format {
                SetFormat::Rar5 { .. } => ArchiveFormat::Rar5,
                SetFormat::Rar3 { .. } => ArchiveFormat::Rar4,
            },
            data_count: self.data.len(),
            recovery_count: self.recovery.len(),
            data,
            recovery: self.recovery.clone(),
            missing,
            usable: self.usable(),
        }
    }
}

/// Every recovery volume's state before its checks: `Missing` when the set
/// lacks it, and a present one `InvalidHeader` and unusable until a check
/// says otherwise.
fn recovery_states(prefixes: &[Option<RevPrefix>]) -> Vec<RecoveryVolumeState> {
    prefixes
        .iter()
        .enumerate()
        .map(|(position, prefix)| RecoveryVolumeState {
            position,
            status: if prefix.is_some() {
                RevTestStatus::InvalidHeader
            } else {
                RevTestStatus::Missing
            },
            usable: false,
        })
        .collect()
}

/// Check a RAR5 set's `.rev`s: read every header, hold the headers to the
/// set and to each other, then check each payload's CRC32. A header that
/// passes its own CRC32 but disagrees with the set is an error, not an
/// unusable volume: the caller placed it, or built the set, wrongly.
fn survey_rar5(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    prefixes: &[Option<RevPrefix>],
    buf: &mut [u8],
) -> Result<(SetFormat, Vec<RecoveryVolumeState>), VolumeRestoreError> {
    let data_count = set.data.len();
    let rec_count = set.recovery.len();
    let mut states = recovery_states(prefixes);
    let mut headers: Vec<Option<Rar5RevHeader>> = vec![None; rec_count];
    for (position, prefix) in prefixes.iter().enumerate() {
        let Some(prefix) = prefix else {
            continue;
        };
        if !prefix.whole {
            states[position].status = short_status();
            continue;
        }
        if prefix.got < REV5_PREFIX_LEN || !prefix.rar5() {
            continue;
        }
        let mut reader = SourceReader {
            source: &mut *source,
            volume: Volume::Recovery(position),
            pos: REV5_PREFIX_LEN as u64,
            end: prefix.len,
            short: false,
            error: None,
        };
        let parsed = read_rar5_rev_header(&mut reader, &prefix.bytes);
        if let Some(error) = reader.error.take() {
            return Err(error);
        }
        match parsed {
            Ok(Some(header)) => headers[position] = Some(header),
            _ if reader.short => states[position].status = short_status(),
            _ => {}
        }
    }

    let parsed = headers
        .iter()
        .enumerate()
        .filter_map(|(position, header)| Some((position, header.as_ref()?)))
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        return Err(VolumeRestoreError::NoRecoveryVolumes);
    }
    for &(position, header) in &parsed {
        if header.data_count != data_count || header.rec_count != rec_count {
            return Err(VolumeRestoreError::InconsistentSet {
                reason: format!(
                    "recovery volume {position} belongs to a set of {} data and {} recovery volumes, not {data_count} and {rec_count}",
                    header.data_count, header.rec_count
                ),
            });
        }
        if header.rec_num != data_count + position {
            let stated = match header.rec_num.checked_sub(data_count) {
                Some(stated) => format!("recovery volume {stated}"),
                None => format!("data volume {}", header.rec_num),
            };
            return Err(VolumeRestoreError::CorruptRecoveryVolume {
                position,
                reason: format!("its header numbers it as {stated}"),
            });
        }
    }
    let mut tables = parsed
        .iter()
        .filter_map(|&(position, header)| Some((position, header.data_volumes.as_ref()?)));
    let Some((first, table)) = tables.next() else {
        return Err(VolumeRestoreError::InconsistentSet {
            reason: format!(
                "none of the {} recovery volumes whose header reads carries the data volume table",
                parsed.len()
            ),
        });
    };
    for (position, other) in tables {
        let same = table.len() == other.len()
            && table
                .iter()
                .zip(other)
                .all(|(a, b)| a.file_size == b.file_size && a.crc32 == b.crc32);
        if !same {
            return Err(VolumeRestoreError::InconsistentSet {
                reason: format!(
                    "recovery volumes {first} and {position} carry different data volume tables"
                ),
            });
        }
    }
    let table = table.clone();

    let mut payload = vec![0u64; rec_count];
    for (position, header) in headers.iter().enumerate() {
        let (Some(header), Some(len)) = (header, set.recovery[position]) else {
            continue;
        };
        let mut hasher = crc32fast::Hasher::new();
        let end = read_through(
            source,
            Volume::Recovery(position),
            header.data_offset..len,
            buf,
            |_, bytes| {
                hasher.update(bytes);
                true
            },
        )?;
        let state = &mut states[position];
        if end != PassEnd::Done {
            state.status = short_status();
            continue;
        }
        let actual = hasher.finalize();
        if actual == header.rev_crc {
            state.status = RevTestStatus::Ok;
            state.usable = true;
            payload[position] = header.data_offset;
        } else {
            state.status = RevTestStatus::CrcMismatch {
                expected: header.rev_crc,
                actual,
            };
        }
    }

    // A missing volume is rebuilt at the length the table gives, from the
    // payloads of the usable `.rev`s, and RAR writes each payload as long as
    // the longest volume. A table that gives a volume more than a usable
    // `.rev` carries is not the set's, and would have the restore write past
    // anything the `.rev`s hold. A `.rev` cut short fails its CRC32 above
    // and is only left out.
    for (position, state) in states.iter().enumerate() {
        if !state.usable {
            continue;
        }
        let carried = set.recovery[position]
            .unwrap_or(0)
            .saturating_sub(payload[position]);
        if let Some((index, info)) = table
            .iter()
            .enumerate()
            .find(|(_, info)| info.file_size > carried)
        {
            return Err(VolumeRestoreError::InconsistentSet {
                reason: format!(
                    "the data volume table gives data volume {index} {} bytes, more than the {carried} bytes of recovery data recovery volume {position} carries",
                    info.file_size
                ),
            });
        }
    }
    Ok((SetFormat::Rar5 { table, payload }, states))
}

/// What one pass over a RAR3 `.rev` found.
struct Rar3RevRead {
    /// The set parameters and CRC32 its last seven bytes state, when they are
    /// plausible as a footer.
    footer: Option<(Rar3RevHeader, u32)>,
    /// The CRC32 of everything before its last four bytes.
    actual: u32,
}

impl Rar3RevRead {
    /// Whether this `.rev` shows a real footer: its CRC32 matches, or it
    /// names exactly this set and this position. Parity bytes do either by
    /// chance only rarely.
    fn vouched(&self, data_count: usize, rec_count: usize, position: usize) -> bool {
        self.footer.as_ref().is_some_and(|(header, expected)| {
            *expected == self.actual
                || (header.data_count == data_count
                    && header.rec_count == rec_count
                    && header.rec_position == position + 1)
        })
    }
}

/// Gathers, as a RAR3 `.rev` streams past, the CRC32 of everything before
/// its last four bytes and its last seven bytes.
struct Rar3RevTail {
    len: u64,
    hasher: crc32fast::Hasher,
    footer: [u8; 7],
}

impl Rar3RevTail {
    fn new(len: u64) -> Self {
        Self {
            len,
            hasher: crc32fast::Hasher::new(),
            footer: [0; 7],
        }
    }

    fn feed(&mut self, at: u64, bytes: &[u8]) {
        let end = at + bytes.len() as u64;
        let crc_end = self.len.saturating_sub(4);
        if at < crc_end {
            self.hasher
                .update(&bytes[..(crc_end.min(end) - at) as usize]);
        }
        let footer_start = self.len.saturating_sub(7);
        if self.len >= 7 && end > footer_start {
            let from = at.max(footer_start);
            let into = (from - footer_start) as usize;
            let bytes = &bytes[(from - at) as usize..];
            self.footer[into..into + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn finish(self) -> Rar3RevRead {
        Rar3RevRead {
            footer: if self.len >= 7 {
                parse_rar3_rev_footer(self.footer)
            } else {
                None
            },
            actual: self.hasher.finalize(),
        }
    }
}

/// Check a RAR3 set's `.rev`s: read each through once, then decide from all
/// of them whether the set carries footers. When one `.rev` shows a footer,
/// all are held to theirs; when none does, the set is taken as RAR 3.0's,
/// whose `.rev`s carry nothing to check but their length: RAR writes each as
/// long as the longest data volume, so one shorter than a data volume
/// present and not in `bad` was cut, and is unusable. A RAR 3.10 set whose
/// every footer is damaged reads as RAR 3.0's too, and its rebuilt volumes
/// can still pass `verified`: the footer's seven bytes sit in the reserved
/// space of a data volume's end-of-archive header, which the walk does not
/// hold to its CRC, so up to seven wrong bytes land there, and on the last
/// volume a non-zero tail past the block is kept. Reference UnRAR skips a
/// `.rev` whose footer fails its CRC and rebuilds nothing from such a set.
fn survey_rar3(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    prefixes: &[Option<RevPrefix>],
    bad: &[bool],
    buf: &mut [u8],
) -> Result<(SetFormat, Vec<RecoveryVolumeState>), VolumeRestoreError> {
    let data_count = set.data.len();
    let rec_count = set.recovery.len();
    if data_count == 0 {
        return Err(VolumeRestoreError::InconsistentSet {
            reason: "the set has no data volumes".into(),
        });
    }
    if data_count + rec_count > MAX_RAR3_SET {
        return Err(VolumeRestoreError::InconsistentSet {
            reason: format!(
                "a RAR3 set holds at most {MAX_RAR3_SET} volumes, not {data_count} data and {rec_count} recovery volumes"
            ),
        });
    }
    let mut states = recovery_states(prefixes);
    let mut reads = Vec::with_capacity(rec_count);
    for (position, prefix) in prefixes.iter().enumerate() {
        let read = match prefix {
            Some(prefix) if prefix.whole => {
                let mut tail = Rar3RevTail::new(prefix.len);
                tail.feed(0, &prefix.bytes[..prefix.got]);
                let end = read_through(
                    source,
                    Volume::Recovery(position),
                    prefix.got as u64..prefix.len,
                    buf,
                    |at, bytes| {
                        tail.feed(at, bytes);
                        true
                    },
                )?;
                (end == PassEnd::Done).then(|| tail.finish())
            }
            _ => None,
        };
        if read.is_none() && prefix.is_some() {
            states[position].status = short_status();
        }
        reads.push(read);
    }

    let footers = reads.iter().enumerate().any(|(position, read)| {
        read.as_ref()
            .is_some_and(|read| read.vouched(data_count, rec_count, position))
    });
    let longest = set
        .data
        .iter()
        .zip(bad)
        .filter_map(|(len, &bad)| if bad { None } else { *len })
        .max()
        .unwrap_or(0);
    for (position, read) in reads.into_iter().enumerate() {
        let Some(read) = read else {
            continue;
        };
        let state = &mut states[position];
        if !footers {
            if set.recovery[position].unwrap_or(0) < longest {
                state.status = RevTestStatus::InvalidHeader;
            } else {
                state.status = RevTestStatus::Unverifiable;
                state.usable = true;
            }
            continue;
        }
        let Some((header, expected)) = read.footer else {
            continue;
        };
        if expected != read.actual {
            state.status = RevTestStatus::CrcMismatch {
                expected,
                actual: read.actual,
            };
            continue;
        }
        if header.data_count != data_count || header.rec_count != rec_count {
            return Err(VolumeRestoreError::InconsistentSet {
                reason: format!(
                    "recovery volume {position}'s footer describes a set of {} data and {} recovery volumes, not {data_count} and {rec_count}",
                    header.data_count, header.rec_count
                ),
            });
        }
        if header.rec_position != position + 1 {
            return Err(VolumeRestoreError::CorruptRecoveryVolume {
                position,
                reason: format!(
                    "its footer numbers it as recovery volume {}",
                    header.rec_position - 1
                ),
            });
        }
        state.status = RevTestStatus::Ok;
        state.usable = true;
    }
    Ok((SetFormat::Rar3 { footers }, states))
}

/// The data volumes present and not in `bad`, with their lengths.
fn present_data(set: &RestoreSet, bad: &[bool]) -> Vec<(usize, u64)> {
    set.data
        .iter()
        .zip(bad)
        .enumerate()
        .filter_map(|(index, (len, &bad))| Some((index, (*len).filter(|_| !bad)?)))
        .collect()
}

/// Whether any data volume present and not in `bad` starts with the RAR5
/// signature, from the first eight bytes of each.
fn rar5_data(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    bad: &[bool],
) -> Result<bool, VolumeRestoreError> {
    use crate::signature::RAR5_SIGNATURE;

    let mut start = [0u8; RAR5_SIGNATURE.len()];
    for (index, len) in present_data(set, bad) {
        let want = len.min(start.len() as u64) as usize;
        let got = read_at(source, Volume::Data(index), 0, &mut start[..want])?;
        if start[..got] == RAR5_SIGNATURE {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Tell a set whose `.rev`s show neither the RAR5 signature nor a RAR 3.10
/// footer by its data volumes, as a RAR 3.0 `.rev` states nothing. A data
/// volume that starts with the RAR5 signature makes it a RAR5 set whose
/// every `.rev` header failed: [`VolumeRestoreError::NoRecoveryVolumes`].
/// Otherwise a data volume present and not in `bad` must have a RAR 1.5-4.x
/// main header that reads and marks it a volume, as the path restore
/// requires of the volume it takes the set's naming from; without one the
/// `.rev`s would rebuild volumes of a set nothing shows is RAR3. Each data
/// volume gives its first eight bytes, then each in turn is read through its
/// main header until one marks a volume.
fn check_rar30_data(
    set: &RestoreSet,
    source: &mut dyn VolumeSource,
    bad: &[bool],
) -> Result<(), VolumeRestoreError> {
    use crate::rar4::types::archive_flags;

    if rar5_data(set, source, bad)? {
        return Err(VolumeRestoreError::NoRecoveryVolumes);
    }
    let present = present_data(set, bad);
    let mut buf = vec![0u8; MIN_READ_SIZE];
    for &(index, len) in &present {
        let mut walker = Rar3Stream::new();
        read_through(source, Volume::Data(index), 0..len, &mut buf, |_, bytes| {
            walker.push(bytes);
            walker.walk.main_flags.is_none() && !walker.settled()
        })?;
        if walker
            .walk
            .main_flags
            .is_some_and(|flags| flags & archive_flags::VOLUME != 0)
        {
            return Ok(());
        }
    }
    let reason = if present.is_empty() {
        "no recovery volume shows a RAR 3.10 footer, and no data volume that is present and not known bad has a RAR 1.5-4.x main header to read".to_string()
    } else {
        format!(
            "no recovery volume shows a RAR 3.10 footer, and none of the {} data volumes read has a RAR 1.5-4.x main header that marks it a volume",
            present.len()
        )
    };
    Err(VolumeRestoreError::InconsistentSet { reason })
}

/// The check a data volume gets as its bytes are read.
enum DataCheck {
    Rar5 {
        hasher: crc32fast::Hasher,
        len: u64,
        crc32: u32,
    },
    Rar3 {
        index: usize,
        walker: Rar3Stream,
    },
}

impl DataCheck {
    fn new(survey: &Survey, index: usize) -> Self {
        match &survey.format {
            SetFormat::Rar5 { table, .. } => Self::Rar5 {
                hasher: crc32fast::Hasher::new(),
                len: table[index].file_size,
                crc32: table[index].crc32,
            },
            SetFormat::Rar3 { .. } => Self::Rar3 {
                index,
                walker: Rar3Stream::new(),
            },
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        match self {
            Self::Rar5 { hasher, .. } => hasher.update(bytes),
            Self::Rar3 { walker, .. } => walker.push(bytes),
        }
    }

    /// Whether the verdict is already a failure, so the rest of the volume
    /// need not be read for it.
    fn failed(&self) -> bool {
        match self {
            Self::Rar5 { .. } => false,
            Self::Rar3 { index, walker } => walker
                .status(*index)
                .is_some_and(|status| status != DataVolumeStatus::Valid),
        }
    }

    /// The verdict once the pass over the volume ended at `end`. A volume
    /// the source holds less of than the set says fails whatever its bytes
    /// say, as the decode would read past what is there.
    fn finish(self, end: PassEnd) -> DataVolumeStatus {
        match self {
            Self::Rar5 { hasher, len, crc32 } => match end {
                PassEnd::Short(actual) => DataVolumeStatus::WrongSize {
                    expected: len,
                    actual,
                },
                _ => {
                    if hasher.finalize() == crc32 {
                        DataVolumeStatus::Valid
                    } else {
                        DataVolumeStatus::CrcMismatch
                    }
                }
            },
            Self::Rar3 { index, mut walker } => {
                if let PassEnd::Short(_) = end {
                    return DataVolumeStatus::InvalidHeaders;
                }
                walker.finish();
                walker
                    .status(index)
                    .unwrap_or(DataVolumeStatus::InvalidHeaders)
            }
        }
    }
}

/// A [`Rar3Walk`] over a volume's bytes pushed in order, reaching the verdict
/// the walk reaches reading the same bytes from a file. It keeps only the
/// bytes the next header step reads and hashes the rest as they pass, so the
/// volume streams through it once.
struct Rar3Stream {
    walk: Rar3Walk,
    /// Bytes `base..pushed` of the volume.
    window: Vec<u8>,
    base: u64,
    pushed: u64,
    /// Where the next step starts.
    pos: u64,
    /// How many bytes past `pos` the next step is tried with: a header's
    /// fixed part, or more after a try that ran out.
    need: usize,
    /// The CRC32 of every byte before `base`, for the data CRC an
    /// end-of-archive header states over every byte before it.
    hasher: crc32fast::Hasher,
    verdict: Option<RarResult<Rar3VolumeScan>>,
    end: Option<Rar3EndBlock>,
}

impl Rar3Stream {
    fn new() -> Self {
        Self {
            walk: Rar3Walk::default(),
            window: Vec::new(),
            base: 0,
            pushed: 0,
            pos: 0,
            need: RAR3_SIGNATURE_READ,
            hasher: crc32fast::Hasher::new(),
            verdict: None,
            end: None,
        }
    }

    /// Take the volume's next bytes.
    fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.verdict.is_none() {
            let take = if self.pushed < self.pos {
                // Bytes a step skipped over: only the data CRC needs them.
                let take = (self.pos - self.pushed).min(bytes.len() as u64) as usize;
                self.hasher.update(&bytes[..take]);
                self.base += take as u64;
                take
            } else {
                let wanted = self.pos.saturating_add(self.need as u64);
                let take = wanted
                    .saturating_sub(self.pushed)
                    .clamp(1, bytes.len() as u64) as usize;
                self.window.extend_from_slice(&bytes[..take]);
                take
            };
            self.pushed += take as u64;
            bytes = &bytes[take..];
            self.run(false);
        }
    }

    /// The volume has ended: settle the walk on the bytes pushed.
    fn finish(&mut self) {
        self.run(true);
    }

    fn settled(&self) -> bool {
        self.verdict.is_some()
    }

    /// Where the next header step starts: no header the walk has yet to read
    /// starts before it.
    fn position(&self) -> u64 {
        self.pos
    }

    /// The end-of-archive block, once the walk has reached it.
    fn end(&self) -> Option<Rar3EndBlock> {
        self.end
    }

    /// The verdict for data slot `index`, once the walk has settled.
    fn status(&self, index: usize) -> Option<DataVolumeStatus> {
        self.verdict.as_ref().map(|verdict| match verdict {
            Ok(scan) => rar3_volume_status(scan, index),
            Err(_) => DataVolumeStatus::InvalidHeaders,
        })
    }

    fn run(&mut self, ended: bool) {
        while self.verdict.is_none() {
            if !ended && self.pushed < self.pos.saturating_add(self.need as u64) {
                return;
            }
            let before = self.walk;
            let mut reader = WindowReader {
                base: self.base,
                window: &self.window,
                pos: self.pos,
                ended,
                starved_at: None,
            };
            let step = self.walk.step(&mut reader);
            let (at, starved_at) = (reader.pos, reader.starved_at);
            if let Some(wanted) = starved_at {
                // Too few bytes yet: the step is tried again from its start
                // once more are in, at least twice as many each time.
                self.walk = before;
                let more = usize::try_from(wanted.saturating_sub(self.pos)).unwrap_or(usize::MAX);
                self.need = more.max(self.need.saturating_mul(2));
                continue;
            }
            match step {
                Ok(Rar3WalkStep::Next | Rar3WalkStep::Service(_)) => {
                    self.pos = at;
                    self.need = RAR3_HEADER_MIN;
                    self.drain();
                }
                Ok(Rar3WalkStep::Stopped(status)) => self.settle(Ok((status, None)), None),
                Ok(Rar3WalkStep::End(end)) => {
                    let status = match end.data_crc {
                        Some(expected) => {
                            let mut hasher = self.hasher.clone();
                            hasher.update(&self.window[..(end.offset - self.base) as usize]);
                            if hasher.finalize() == expected {
                                DataVolumeStatus::Valid
                            } else {
                                DataVolumeStatus::CrcMismatch
                            }
                        }
                        None => DataVolumeStatus::Valid,
                    };
                    self.settle(Ok((status, end.volume_number)), Some(end));
                }
                Err(error) => self.settle(Err(error), None),
            }
        }
    }

    /// Hash and drop the window's bytes before the next step's start.
    fn drain(&mut self) {
        let keep_from = self.pos.min(self.pushed);
        let dropped = (keep_from - self.base) as usize;
        self.hasher.update(&self.window[..dropped]);
        self.window.drain(..dropped);
        self.base = keep_from;
    }

    fn settle(
        &mut self,
        walked: RarResult<(DataVolumeStatus, Option<u16>)>,
        end: Option<Rar3EndBlock>,
    ) {
        self.verdict = Some(rar3_scan_verdict(self.walk.main_flags, walked));
        self.end = end;
        self.window = Vec::new();
    }
}

/// The view a [`Rar3Stream`] gives its walk: a [`Read`] and [`Seek`] over
/// the window that reads as a file holding the volume would, with whole reads
/// where the window holds the bytes and, once the volume has ended, short
/// reads at its end. Before then, a read the window cannot fill records how
/// far it reached and fails, and the step is tried again with more bytes.
struct WindowReader<'a> {
    base: u64,
    window: &'a [u8],
    pos: u64,
    ended: bool,
    starved_at: Option<u64>,
}

impl Read for WindowReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos < self.base {
            return Err(io::Error::other("RAR3 header walk read before its window"));
        }
        let held_end = self.base + self.window.len() as u64;
        let wanted = self.pos.saturating_add(buf.len() as u64);
        if wanted > held_end && !self.ended {
            self.starved_at = Some(wanted);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = held_end.saturating_sub(self.pos).min(buf.len() as u64) as usize;
        if count > 0 {
            let from = (self.pos - self.base) as usize;
            buf[..count].copy_from_slice(&self.window[from..from + count]);
        }
        self.pos += count as u64;
        Ok(count)
    }
}

impl Seek for WindowReader<'_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
            // The walk never seeks from the end, and a volume still arriving
            // has no end to seek from.
            SeekFrom::End(_) => return Err(io::ErrorKind::Unsupported.into()),
        };
        self.pos = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the volume",
            )
        })?;
        Ok(self.pos)
    }
}

/// One decode input: bytes `start..start + avail` of a volume, zero past them.
#[derive(Debug, Clone, Copy)]
struct Input {
    volume: Volume,
    start: u64,
    avail: u64,
}

/// One volume a decode rebuilds, and the length it gives it.
#[derive(Debug, Clone, Copy)]
struct Output {
    index: usize,
    len: u64,
}

/// The field a set's code works in: RAR5 multiplies 16-bit words, RAR3
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Gf16,
    Gf8,
}

impl Field {
    /// The length a region of `len` bytes is worked at: RAR5 pads an odd one
    /// with a zero byte to whole words.
    fn span(self, len: usize) -> usize {
        match self {
            Self::Gf16 => len + (len & 1),
            Self::Gf8 => len,
        }
    }

    fn mul_acc(self, factor: u16, src: &[u8], dst: &mut [u8]) {
        match self {
            Self::Gf16 => gf_simd::mul_acc_region(factor, src, dst),
            Self::Gf8 => gf8::mul_acc_region(factor as u8, src, dst),
        }
    }
}

enum Coder {
    Rar5(Rar5RsCoder),
    /// The rows of the RAR3 decode matrix that rebuild the missing volumes,
    /// one column per input.
    Rar3(Vec<u8>),
}

/// A decode: its inputs in the order the matrix takes them, and the volumes
/// it rebuilds, in index order.
struct Plan {
    field: Field,
    coder: Coder,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    /// Whether a rebuilt volume's last seven bytes are zero: the RAR3 footer
    /// took their place in every `.rev`.
    footers: bool,
}

impl Plan {
    fn new(survey: &Survey, missing: &[usize]) -> Result<Self, VolumeRestoreError> {
        let data_count = survey.data.len();
        let rec_count = survey.recovery.len();
        let undecodable = || VolumeRestoreError::InconsistentSet {
            reason: format!(
                "the decoder cannot rebuild {} data volumes from {} usable recovery volumes",
                missing.len(),
                survey.usable()
            ),
        };
        match &survey.format {
            SetFormat::Rar5 { table, payload } => {
                let mut valid = vec![true; data_count + rec_count];
                for &index in missing {
                    valid[index] = false;
                }
                for rev in &survey.recovery {
                    valid[data_count + rev.position] = rev.usable;
                }
                let coder = Rar5RsCoder::new_decoder(data_count, rec_count, &valid)
                    .ok_or_else(undecodable)?;
                // A missing volume's unit is the next usable `.rev` in
                // position order, the order the decoder's rows take them.
                let mut spare = survey
                    .recovery
                    .iter()
                    .filter(|rev| rev.usable)
                    .map(|rev| rev.position);
                let mut inputs = Vec::with_capacity(data_count);
                for (index, info) in table.iter().enumerate() {
                    if valid[index] {
                        inputs.push(Input {
                            volume: Volume::Data(index),
                            start: 0,
                            avail: info.file_size,
                        });
                    } else {
                        let position = spare.next().ok_or_else(undecodable)?;
                        let start = payload[position];
                        inputs.push(Input {
                            volume: Volume::Recovery(position),
                            start,
                            avail: survey.rec_len[position].unwrap_or(0).saturating_sub(start),
                        });
                    }
                }
                let outputs = missing
                    .iter()
                    .map(|&index| Output {
                        index,
                        len: table[index].file_size,
                    })
                    .collect();
                Ok(Self {
                    field: Field::Gf16,
                    coder: Coder::Rar5(coder),
                    inputs,
                    outputs,
                    footers: false,
                })
            }
            SetFormat::Rar3 { footers } => {
                let inputs = survey.rar3_inputs(missing);
                let total = data_count + rec_count;
                let present = inputs
                    .iter()
                    .map(|input| match input.volume {
                        Volume::Data(index) => index,
                        Volume::Recovery(position) => data_count + position,
                    })
                    .collect::<Vec<_>>();
                let mut erased = vec![true; total];
                for &slot in &present {
                    erased[slot] = false;
                }
                let erasures = (0..total).filter(|&slot| erased[slot]).collect::<Vec<_>>();
                let rows = Rar3RsCoder::new(rec_count)
                    .and_then(|coder| coder.decode_matrix(total, &erasures))
                    .map(|full| rar3_missing_rows(&full, total, &erasures, &present, missing))
                    .ok_or_else(undecodable)?;
                // RAR3 `.rev`s are as long as the longest data volume, and the
                // survey leaves out one cut shorter, so the longest input is
                // the length every volume is rebuilt at.
                let len = inputs.iter().map(|input| input.avail).max().unwrap_or(0);
                let outputs = missing.iter().map(|&index| Output { index, len }).collect();
                Ok(Self {
                    field: Field::Gf8,
                    coder: Coder::Rar3(rows),
                    inputs,
                    outputs,
                    footers: *footers,
                })
            }
        }
    }

    fn factor(&self, row: usize, column: usize) -> u16 {
        let at = row * self.inputs.len() + column;
        match &self.coder {
            Coder::Rar5(coder) => coder.matrix()[at],
            Coder::Rar3(rows) => u16::from(rows[at]),
        }
    }

    /// The longest rebuilt volume: how far the decode runs.
    fn reach(&self) -> u64 {
        self.outputs.iter().map(|out| out.len).max().unwrap_or(0)
    }

    /// How far into each input the decode reads: the longest rebuilt volume,
    /// and for RAR5 on to the next even byte. A RAR5 volume of odd length
    /// ends in the low byte of a word whose high byte comes from every input
    /// that holds one, as reference UnRAR reads whole words of each; an
    /// input that ends sooner is zero past its end, as the encoder padded it.
    fn read_end(&self) -> u64 {
        let reach = self.reach();
        match self.field {
            Field::Gf16 => reach.saturating_add(reach & 1),
            Field::Gf8 => reach,
        }
    }

    /// The bytes of every input and rebuilt volume one decode step holds,
    /// from the caller's memory budget, and never under [`MIN_READ_SIZE`]
    /// unless the decode reads less: a budget split over many volumes would
    /// otherwise turn each step into a run of tiny reads. RAR5 steps stay
    /// whole words.
    fn chunk(&self, memory_bytes: usize) -> usize {
        let reach = self.reach();
        let read_end = usize::try_from(self.read_end()).unwrap_or(usize::MAX);
        match self.field {
            Field::Gf16 => {
                rar5_chunk_size(reach, self.inputs.len(), self.outputs.len(), memory_bytes)
                    .max(MIN_READ_SIZE.min(read_end))
            }
            Field::Gf8 => (memory_bytes / (self.inputs.len() + self.outputs.len()).max(1))
                .max(MIN_READ_SIZE)
                .min(read_end),
        }
    }

    /// Zero the bytes of `chunk`, at `offset` in rebuilt volume `out`, that a
    /// RAR3 footer displaced.
    fn scrub(&self, out: &Output, offset: u64, chunk: &mut [u8]) {
        if !self.footers || out.len < 7 {
            return;
        }
        let from = (out.len - 7).max(offset);
        let to = out.len.min(offset + chunk.len() as u64);
        if from < to {
            chunk[(from - offset) as usize..(to - offset) as usize].fill(0);
        }
    }
}

/// Where the field arithmetic runs: on the calling thread, or on a pool of
/// the caller's size built for this call the first time it is needed.
struct Arith {
    workers: usize,
    pool: Option<Option<rayon::ThreadPool>>,
}

impl Arith {
    fn new(workers: usize) -> Self {
        Self {
            workers,
            pool: None,
        }
    }

    fn pool(&mut self) -> Option<&rayon::ThreadPool> {
        if self.workers < 2 || !threading::parallel_enabled() {
            return None;
        }
        let workers = self.workers;
        // A pool that cannot be built leaves the work on the calling thread,
        // as does a machine that runs one thread at a time.
        self.pool
            .get_or_insert_with(|| {
                // Threads past what the machine runs at once only take
                // turns, and a caller's `usize::MAX` must not become a
                // request for that many. Asked once: the count can cost a
                // read of the process's CPU quota.
                let workers =
                    workers.min(std::thread::available_parallelism().map_or(1, usize::from));
                if workers < 2 {
                    return None;
                }
                rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .thread_name(|index| format!("unrar-restore-{index}"))
                    .build()
                    .ok()
            })
            .as_ref()
    }

    /// Overwrite `outputs` with the plan's matrix applied to `units`.
    fn apply(&mut self, plan: &Plan, units: &[&[u8]], outputs: &mut [&mut [u8]]) {
        match (self.pool(), &plan.coder) {
            (Some(pool), Coder::Rar5(coder)) => pool.install(|| coder.apply_units(units, outputs)),
            (Some(pool), Coder::Rar3(rows)) => {
                pool.install(|| apply_decode_matrix_gf8(rows, units, outputs));
            }
            (None, _) => {
                for (row, output) in outputs.iter_mut().enumerate() {
                    output.fill(0);
                    for (column, unit) in units.iter().enumerate() {
                        let factor = plan.factor(row, column);
                        if factor != 0 {
                            plan.field.mul_acc(factor, unit, output);
                        }
                    }
                }
            }
        }
    }

    /// Add input `column`'s `bytes`, read at `at` in it, into every rebuilt
    /// volume, each times its own coefficient for that input.
    fn accumulate(
        &mut self,
        plan: &Plan,
        column: usize,
        at: u64,
        bytes: &[u8],
        outputs: &mut [Vec<u8>],
    ) {
        let field = plan.field;
        // RAR5 works in whole words: an odd last byte is a word whose high
        // byte is zero, as the decoder pads a volume of odd length.
        let (body, odd) = match field {
            Field::Gf16 if bytes.len() % 2 == 1 => {
                (&bytes[..bytes.len() - 1], bytes.last().copied())
            }
            _ => (bytes, None),
        };
        let at = usize::try_from(at).unwrap_or(usize::MAX);
        let mut jobs = Vec::new();
        for (row, output) in outputs.iter_mut().enumerate() {
            let factor = plan.factor(row, column);
            if factor == 0 || at >= output.len() {
                continue;
            }
            let count = body.len().min(output.len() - at);
            let (dst, rest) = output[at..].split_at_mut(count);
            if let Some(byte) = odd
                && count == body.len()
                && rest.len() >= 2
            {
                field.mul_acc(factor, &[byte, 0], &mut rest[..2]);
            }
            for (src, dst) in body[..count]
                .chunks(FOLD_STRIPE)
                .zip(dst.chunks_mut(FOLD_STRIPE))
            {
                jobs.push((factor, src, dst));
            }
        }
        match self.pool() {
            Some(pool) if jobs.len() > 1 => pool.install(|| {
                jobs.into_par_iter()
                    .for_each(|(factor, src, dst)| field.mul_acc(factor, src, dst));
            }),
            _ => {
                for (factor, src, dst) in jobs {
                    field.mul_acc(factor, src, dst);
                }
            }
        }
    }
}

/// The single-read restore: each data volume is checked and added into the
/// rebuilt volumes in one read, and the rebuilt volumes go to the sink only
/// once every check has passed. `None` when a check failed: the rebuilt bytes
/// are dropped, the remaining volumes have been checked, and the caller
/// decodes again over the volumes that passed.
fn fold(
    survey: &mut Survey,
    source: &mut dyn VolumeSource,
    candidates: &[usize],
    arith: &mut Arith,
    write: Sink<'_>,
) -> Result<Option<Vec<RestoredVolume>>, VolumeRestoreError> {
    let plan = Plan::new(survey, candidates)?;
    let mut held = plan
        .outputs
        .iter()
        .map(|out| vec![0u8; plan.field.span(out.len as usize)])
        .collect::<Vec<_>>();
    let mut buf = vec![0u8; survey.io_size];
    let mut alive = true;
    // Data volumes first: a failed check then costs no `.rev` read.
    for (column, input) in plan.inputs.iter().enumerate() {
        let Volume::Data(index) = input.volume else {
            continue;
        };
        let mut check = DataCheck::new(survey, index);
        let end = read_through(
            source,
            input.volume,
            0..input.avail,
            &mut buf,
            |at, bytes| {
                check.push(bytes);
                if alive && check.failed() {
                    alive = false;
                    held = Vec::new();
                }
                if alive {
                    arith.accumulate(&plan, column, at, bytes, &mut held);
                }
                alive || !check.failed()
            },
        )?;
        let status = check.finish(end);
        if status != DataVolumeStatus::Valid {
            alive = false;
            held = Vec::new();
        }
        survey.data[index] = Some(status);
    }
    if !alive {
        return Ok(None);
    }

    let read_end = plan.read_end();
    for (column, input) in plan.inputs.iter().enumerate() {
        if let Volume::Data(_) = input.volume {
            continue;
        }
        let range = input.start..input.start + input.avail.min(read_end);
        let end = read_through(
            source,
            input.volume,
            range.clone(),
            &mut buf,
            |at, bytes| {
                arith.accumulate(&plan, column, at - input.start, bytes, &mut held);
                true
            },
        )?;
        if let PassEnd::Short(at) = end {
            return Err(changed_volume(input.volume, at, range.end));
        }
    }

    let mut restored = Vec::with_capacity(held.len());
    for (out, mut bytes) in plan.outputs.iter().zip(held) {
        bytes.truncate(out.len as usize);
        plan.scrub(out, 0, &mut bytes);
        let mut emitter = Emitter::new(survey, out);
        emitter.push_owned(bytes, write)?;
        restored.push(emitter.finish(write)?);
    }
    Ok(Some(restored))
}

/// The streaming decode: every input read a slice at a time in lockstep,
/// each slice of every rebuilt volume handed to the sink before the next is
/// read.
fn decode(
    survey: &Survey,
    source: &mut dyn VolumeSource,
    missing: &[usize],
    options: &StreamRestoreOptions,
    arith: &mut Arith,
    write: Sink<'_>,
) -> Result<Vec<RestoredVolume>, VolumeRestoreError> {
    let plan = Plan::new(survey, missing)?;
    let emitters = plan
        .outputs
        .iter()
        .map(|out| Emitter::new(survey, out))
        .collect();
    run_decode(
        &plan,
        plan.chunk(options.memory_bytes),
        source,
        arith,
        emitters,
        write,
    )
}

/// The decode loop over `plan`, `chunk` bytes of every input at a time:
/// each slice of every rebuilt volume goes to its emitter, one per output in
/// order, before the next is read.
fn run_decode(
    plan: &Plan,
    chunk: usize,
    source: &mut dyn VolumeSource,
    arith: &mut Arith,
    mut emitters: Vec<Emitter>,
    write: Sink<'_>,
) -> Result<Vec<RestoredVolume>, VolumeRestoreError> {
    let reach = plan.reach();
    let mut inputs = vec![vec![0u8; chunk]; plan.inputs.len()];
    let mut outputs = vec![vec![0u8; chunk]; plan.outputs.len()];
    let mut offset = 0u64;
    while offset < reach {
        let count = (reach - offset).min(chunk as u64) as usize;
        let span = plan.field.span(count);
        for (input, buf) in plan.inputs.iter().zip(&mut inputs) {
            // The whole of a RAR5 slice's last word, where the input holds it.
            let have = input.avail.saturating_sub(offset).min(span as u64) as usize;
            let got = read_at(source, input.volume, input.start + offset, &mut buf[..have])?;
            if got < have {
                return Err(changed_volume(
                    input.volume,
                    input.start + offset + got as u64,
                    input.start + input.avail,
                ));
            }
            buf[have..span].fill(0);
        }
        let units = inputs.iter().map(|buf| &buf[..span]).collect::<Vec<_>>();
        let mut slices = outputs
            .iter_mut()
            .map(|buf| &mut buf[..span])
            .collect::<Vec<_>>();
        arith.apply(plan, &units, &mut slices);
        for ((out, buf), emitter) in plan.outputs.iter().zip(&mut outputs).zip(&mut emitters) {
            let bytes = &mut buf[..count];
            plan.scrub(out, offset, bytes);
            let keep = out.len.saturating_sub(offset).min(count as u64) as usize;
            emitter.push(&bytes[..keep], write)?;
        }
        offset += count as u64;
    }
    let mut restored = Vec::with_capacity(emitters.len());
    for emitter in emitters {
        restored.push(emitter.finish(write)?);
    }
    Ok(restored)
}

/// One rebuilt volume on its way to the sink: hashed as it goes, judged as a
/// present volume would be, and, for a RAR3 set's last volume, cut at its
/// end-of-archive block when only padding follows.
struct Emitter {
    /// The length the decode gives the volume.
    len: u64,
    produced: u64,
    sent: Sent,
    check: OutputCheck,
}

/// What has gone to the sink for one rebuilt volume.
struct Sent {
    index: usize,
    emitted: u64,
    hasher: crc32fast::Hasher,
}

enum OutputCheck {
    Rar5 {
        crc32: u32,
    },
    Rar3 {
        walker: Box<Rar3Stream>,
        /// For the set's last volume.
        last: Option<LastVolume>,
    },
}

/// A RAR3 set's last volume, whose bytes are held from the walk's position
/// on until it is known where the volume ends.
#[derive(Default)]
struct LastVolume {
    /// Bytes from what has been sent to what has been produced.
    held: Vec<u8>,
    /// Once decided, whether the volume ends at its end-of-archive block.
    cut: Option<bool>,
}

impl Emitter {
    fn new(survey: &Survey, out: &Output) -> Self {
        let check = match &survey.format {
            SetFormat::Rar5 { table, .. } => OutputCheck::Rar5 {
                crc32: table[out.index].crc32,
            },
            SetFormat::Rar3 { .. } => OutputCheck::Rar3 {
                walker: Box::new(Rar3Stream::new()),
                last: (out.index + 1 == survey.data.len()).then(LastVolume::default),
            },
        };
        Self::with_check(out.index, out.len, check)
    }

    fn with_check(index: usize, len: u64, check: OutputCheck) -> Self {
        Self {
            len,
            produced: 0,
            sent: Sent {
                index,
                emitted: 0,
                hasher: crc32fast::Hasher::new(),
            },
            check,
        }
    }

    /// Take the volume's next rebuilt bytes.
    fn push(&mut self, bytes: &[u8], write: Sink<'_>) -> Result<(), VolumeRestoreError> {
        self.produced += bytes.len() as u64;
        match &mut self.check {
            OutputCheck::Rar5 { .. } => self.sent.send(bytes, write),
            OutputCheck::Rar3 { walker, last } => {
                walker.push(bytes);
                let Some(last) = last else {
                    return self.sent.send(bytes, write);
                };
                match last.cut {
                    Some(true) => Ok(()),
                    Some(false) => self.sent.send(bytes, write),
                    None => {
                        last.held.extend_from_slice(bytes);
                        last.release(walker, &mut self.sent, self.len, self.produced, write)
                    }
                }
            }
        }
    }

    /// [`push`](Self::push) for bytes the caller is done with: a RAR3 set's
    /// last volume, which holds its bytes until it knows where it ends,
    /// takes them over rather than copying the whole volume.
    fn push_owned(&mut self, bytes: Vec<u8>, write: Sink<'_>) -> Result<(), VolumeRestoreError> {
        if let OutputCheck::Rar3 {
            walker,
            last: Some(last),
        } = &mut self.check
            && last.cut.is_none()
            && last.held.is_empty()
        {
            self.produced += bytes.len() as u64;
            walker.push(&bytes);
            last.held = bytes;
            return last.release(walker, &mut self.sent, self.len, self.produced, write);
        }
        self.push(&bytes, write)
    }

    /// Settle the volume once all of it has been pushed.
    fn finish(mut self, write: Sink<'_>) -> Result<RestoredVolume, VolumeRestoreError> {
        let walked = match &mut self.check {
            OutputCheck::Rar5 { .. } => None,
            OutputCheck::Rar3 { walker, last } => {
                walker.finish();
                if let Some(last) = last {
                    if last.cut.is_none() {
                        last.release(walker, &mut self.sent, self.len, self.produced, write)?;
                    }
                    if last.cut.is_none() {
                        last.cut = Some(false);
                        last.send_to(self.produced, &mut self.sent, write)?;
                    }
                }
                Some(walker.status(self.sent.index) == Some(DataVolumeStatus::Valid))
            }
        };
        let crc32 = self.sent.hasher.finalize();
        let verified = match self.check {
            OutputCheck::Rar5 { crc32: expected } => {
                self.sent.emitted == self.len && crc32 == expected
            }
            OutputCheck::Rar3 { .. } => walked == Some(true),
        };
        Ok(RestoredVolume {
            index: self.sent.index,
            len: self.sent.emitted,
            crc32,
            verified,
        })
    }
}

impl Sent {
    fn send(&mut self, bytes: &[u8], write: Sink<'_>) -> Result<(), VolumeRestoreError> {
        if bytes.is_empty() {
            return Ok(());
        }
        write(self.index, self.emitted, bytes).map_err(|source| VolumeRestoreError::Io {
            volume: VolumeRef::Output(self.index),
            source,
        })?;
        self.hasher.update(bytes);
        self.emitted += bytes.len() as u64;
        Ok(())
    }
}

impl LastVolume {
    /// Send what no cut can drop, and decide the cut once the walk has found
    /// the end-of-archive block and the bytes after it are in. The cut is
    /// reference UnRAR's: at the block's end, when the 8 KiB after it (or
    /// all of it, when less) are zero.
    fn release(
        &mut self,
        walker: &Rar3Stream,
        sent: &mut Sent,
        len: u64,
        produced: u64,
        write: Sink<'_>,
    ) -> Result<(), VolumeRestoreError> {
        if !walker.settled() {
            // A cut falls past the end-of-archive header, and that header
            // starts at or after the walk's position.
            return self.send_to(walker.position().min(produced), sent, write);
        }
        let block_end = match walker.end() {
            Some(end) if end.next < len => end.next,
            _ => {
                self.cut = Some(false);
                return self.send_to(produced, sent, write);
            }
        };
        self.send_to(block_end, sent, write)?;
        let probe_end = block_end.saturating_add(RAR3_PADDING_PROBE).min(len);
        if produced < probe_end {
            return Ok(());
        }
        let probe = (probe_end - sent.emitted) as usize;
        let zero = self.held[..probe].iter().all(|&byte| byte == 0);
        self.cut = Some(zero);
        if zero {
            self.held = Vec::new();
            Ok(())
        } else {
            self.send_to(produced, sent, write)
        }
    }

    /// Send the held bytes before offset `to`.
    fn send_to(
        &mut self,
        to: u64,
        sent: &mut Sent,
        write: Sink<'_>,
    ) -> Result<(), VolumeRestoreError> {
        let count = (to.saturating_sub(sent.emitted) as usize).min(self.held.len());
        if count == 0 {
            return Ok(());
        }
        sent.send(&self.held[..count], write)?;
        self.held.drain(..count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use crate::recovery::{rar3_volume_scan, truncate_rar3_last_volume_padding};

    const _: () = {
        const fn shareable<T: std::error::Error + Send + Sync + 'static>() {}
        shareable::<VolumeRestoreError>();
    };

    use crate::recovery::test_support::fixture;

    /// The RAR3 data volumes RARLAB wrote for the recovery tests, with the
    /// slot each takes in its set.
    fn rar3_data_volumes() -> Option<Vec<(String, usize, Vec<u8>)>> {
        (1..=5)
            .map(|part| (format!("rar3_recovery_volumes.part{part}.rar"), part - 1))
            .chain((1..=4).map(|part| {
                (
                    format!("rar3_recovery_volumes_large.part{part}.rar"),
                    part - 1,
                )
            }))
            .chain(std::iter::once(("rar4_recovery.rar".to_string(), 0)))
            .map(|(name, slot)| {
                let bytes = fixture("rar4", &name)?;
                bytes.starts_with(b"Rar!").then_some((name, slot, bytes))
            })
            .collect()
    }

    /// `bytes` as written, and damaged in memory the ways a volume arrives
    /// damaged.
    fn damage_cases(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let len = bytes.len();
        let with = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut copy = bytes.to_vec();
            edit(&mut copy);
            copy
        };
        let mut behind_a_stub = vec![0x4D; 1000];
        behind_a_stub.extend_from_slice(bytes);
        vec![
            ("as written", bytes.to_vec()),
            (
                "a byte flipped in the middle",
                with(&|b| b[len / 2] ^= 0x5A),
            ),
            ("a main header byte flipped", with(&|b| b[10] ^= 0x5A)),
            (
                "the first header after the main one retyped",
                with(&|b| b[22] ^= 0x5A),
            ),
            ("the last byte flipped", with(&|b| b[len - 1] ^= 0x5A)),
            ("the signature zeroed", with(&|b| b[..8].fill(0))),
            ("cut in half", bytes[..len / 2].to_vec()),
            ("cut one byte short", bytes[..len - 1].to_vec()),
            ("cut inside the signature", bytes[..3].to_vec()),
            ("empty", Vec::new()),
            ("behind a 1000-byte stub", behind_a_stub),
        ]
    }

    /// Push `bytes` through a [`Rar3Stream`] `chunk` bytes at a time: the
    /// stream once settled, and the most bytes its window held at once.
    fn stream_over(bytes: &[u8], chunk: usize) -> (Rar3Stream, usize) {
        let mut stream = Rar3Stream::new();
        let mut widest = 0;
        for piece in bytes.chunks(chunk) {
            stream.push(piece);
            widest = widest.max(stream.window.len());
        }
        stream.finish();
        (stream, widest)
    }

    /// The streaming walk reaches the verdict the walk over a file reaches,
    /// on every RARLAB volume, whole and damaged, however the bytes arrive.
    #[test]
    fn rar3_stream_reaches_the_file_walks_verdict() {
        let Some(volumes) = rar3_data_volumes() else {
            eprintln!("skipping test: RAR3 recovery fixtures not present");
            return;
        };
        for (name, _, bytes) in &volumes {
            let chunks: &[usize] = if bytes.len() <= 64 * 1024 {
                &[1, 7, 13, 4096, usize::MAX]
            } else {
                &[4096, 65_537, usize::MAX]
            };
            for (case, bytes) in damage_cases(bytes) {
                // The file walk also reports the volume's length; a stream
                // has no end to measure until its producer says so.
                let expected = rar3_volume_scan(&mut Cursor::new(&bytes))
                    .map(|scan| Rar3VolumeScan { len: None, ..scan });
                let expected = format!("{expected:?}");
                for &chunk in chunks {
                    let (stream, _) = stream_over(&bytes, chunk);
                    let verdict = format!("{:?}", stream.verdict.as_ref().unwrap());
                    assert_eq!(
                        verdict, expected,
                        "{name} {case}, pushed {chunk} bytes at a time"
                    );
                }
            }
        }
    }

    /// A volume streams through: the walk keeps only the header it is
    /// reading, never the file data between headers, and each set volume
    /// passes in its slot.
    #[test]
    fn rar3_stream_holds_only_the_header_it_reads() {
        let Some(volumes) = rar3_data_volumes() else {
            eprintln!("skipping test: RAR3 recovery fixtures not present");
            return;
        };
        for (name, slot, bytes) in volumes.iter().filter(|(name, ..)| name.contains(".part")) {
            for chunk in [4096, 65_537, usize::MAX] {
                let (stream, widest) = stream_over(bytes, chunk);
                assert_eq!(
                    stream.status(*slot),
                    Some(DataVolumeStatus::Valid),
                    "{name}, pushed {chunk} bytes at a time"
                );
                assert!(
                    widest <= 1024,
                    "{name}, pushed {chunk} bytes at a time, held {widest} bytes at once"
                );
            }
        }
    }

    /// Run a rebuilt last RAR3 volume, slot 4, through its emitter `chunk`
    /// bytes at a time, or with `None` handed over whole as the fold hands
    /// it: the bytes the sink received, in order, and the report.
    fn emit_last_volume(bytes: &[u8], chunk: Option<usize>) -> (Vec<u8>, RestoredVolume) {
        let check = OutputCheck::Rar3 {
            walker: Box::new(Rar3Stream::new()),
            last: Some(LastVolume::default()),
        };
        let mut emitter = Emitter::with_check(4, bytes.len() as u64, check);
        let mut sunk = Vec::new();
        let mut sink = |index: usize, offset: u64, piece: &[u8]| -> io::Result<()> {
            assert_eq!(index, 4);
            assert_eq!(offset, sunk.len() as u64, "the sink's offsets run on");
            assert!(!piece.is_empty(), "the sink is never handed nothing");
            sunk.extend_from_slice(piece);
            Ok(())
        };
        match chunk {
            Some(chunk) => {
                for piece in bytes.chunks(chunk) {
                    emitter.push(piece, &mut sink).unwrap();
                }
            }
            None => emitter.push_owned(bytes.to_vec(), &mut sink).unwrap(),
        }
        let restored = emitter.finish(&mut sink).unwrap();
        (sunk, restored)
    }

    /// `bytes` as the path restore leaves a rebuilt last volume.
    fn path_truncated(bytes: &[u8]) -> Vec<u8> {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        truncate_rar3_last_volume_padding(&mut file).unwrap();
        let mut out = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut out).unwrap();
        out
    }

    /// The stream restore cuts a rebuilt last volume where the path restore
    /// truncates it, and hands the sink nothing the cut drops.
    #[test]
    fn rar3_last_volume_is_cut_where_the_path_restore_cuts_it() {
        let Some(last) = fixture("rar4", "rar3_recovery_volumes.part5.rar") else {
            eprintln!("skipping test: RAR3 recovery fixtures not present");
            return;
        };
        let padded = |len: usize, nonzero_at: Option<usize>| {
            let mut bytes = last.clone();
            bytes.resize(len, 0);
            if let Some(at) = nonzero_at {
                bytes[at] = 1;
            }
            bytes
        };
        let end = last.len();
        let mut damaged = padded(1024, None);
        damaged[0] ^= 0x5A;
        let cases = [
            (
                "zero padding to the set's length",
                padded(1024, None),
                Some(end),
            ),
            (
                "one zero byte past the block",
                padded(end + 1, None),
                Some(end),
            ),
            ("no padding", last.clone(), None),
            (
                "a nonzero byte in the padding",
                padded(1024, Some(end + 100)),
                None,
            ),
            (
                "a nonzero byte at the probe's last byte",
                padded(end + 9000, Some(end + 8191)),
                None,
            ),
            (
                "a nonzero byte just past the probe",
                padded(end + 9000, Some(end + 8192)),
                Some(end),
            ),
            ("a damaged signature", damaged, None),
        ];
        for (case, bytes, cut) in cases {
            let expected = path_truncated(&bytes);
            assert_eq!(
                expected.len(),
                cut.unwrap_or(bytes.len()),
                "{case}: the path restore's cut"
            );
            for chunk in [1, 7, end, end + 1, 4096, usize::MAX]
                .map(Some)
                .into_iter()
                .chain([None])
            {
                let (sunk, restored) = emit_last_volume(&bytes, chunk);
                assert!(sunk == expected, "{case}, pushed {chunk:?} bytes at a time");
                assert_eq!(restored.len, expected.len() as u64, "{case}, {chunk:?}");
                assert_eq!(restored.crc32, crate::crc32fast::hash(&expected), "{case}");
                assert_eq!(restored.verified, case != "a damaged signature", "{case}");
            }
        }
    }

    /// A RAR5 plan over `valid.len() - rec_count` data volumes and
    /// `rec_count` recovery volumes, `valid` saying which are usable. Each
    /// missing data volume's column is read from the next usable `.rev`, as
    /// [`Plan::new`] takes them; input `column` is `avail[column]` bytes
    /// from `starts[column]`, and the missing volumes are rebuilt at
    /// `out_lens`, in index order.
    fn rar5_plan(
        valid: &[bool],
        rec_count: usize,
        starts: &[u64],
        avail: &[u64],
        out_lens: &[u64],
    ) -> Plan {
        let data_count = valid.len() - rec_count;
        let coder = Rar5RsCoder::new_decoder(data_count, rec_count, valid).unwrap();
        let mut spare = (0..rec_count).filter(|&position| valid[data_count + position]);
        let inputs = (0..data_count)
            .map(|index| Input {
                volume: if valid[index] {
                    Volume::Data(index)
                } else {
                    Volume::Recovery(spare.next().unwrap())
                },
                start: starts[index],
                avail: avail[index],
            })
            .collect();
        let missing = (0..data_count).filter(|&index| !valid[index]);
        let outputs = missing
            .zip(out_lens)
            .map(|(index, &len)| Output { index, len })
            .collect::<Vec<_>>();
        assert_eq!(
            outputs.len(),
            out_lens.len(),
            "one length per missing volume"
        );
        Plan {
            field: Field::Gf16,
            coder: Coder::Rar5(coder),
            inputs,
            outputs,
            footers: false,
        }
    }

    /// Whether some `.rev` column of `plan` has a coefficient other than 0
    /// and 1: only then does the last word's high byte reach its low byte.
    fn mixes_rev_bytes(plan: &Plan) -> bool {
        (0..plan.outputs.len()).any(|row| {
            plan.inputs.iter().enumerate().any(|(column, input)| {
                matches!(input.volume, Volume::Recovery(_)) && plan.factor(row, column) > 1
            })
        })
    }

    /// Multiply in GF(2^16) over RAR5's polynomial 0x1100B one bit at a
    /// time: a reference that shares nothing with the decoder's tables.
    fn gf16_mul(a: u16, b: u16) -> u16 {
        let (mut a, mut b, mut product) = (u32::from(a), b, 0u32);
        while b != 0 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a & 0x1_0000 != 0 {
                a ^= 0x1_100B;
            }
        }
        product as u16
    }

    /// Byte `at` of the rebuilt volume in `row`, worked out one word at a
    /// time from `units`, each input's bytes from its start, zero past its
    /// end, as reference UnRAR reads them: the word holding byte `at`, with
    /// its high byte from every unit that has one, times each coefficient.
    fn reference_byte(plan: &Plan, row: usize, units: &[Vec<u8>], at: usize) -> u8 {
        let word_at = at & !1;
        let word = units.iter().enumerate().fold(0u16, |acc, (column, unit)| {
            let byte = |at: usize| unit.get(at).copied().unwrap_or(0);
            let word = u16::from_le_bytes([byte(word_at), byte(word_at + 1)]);
            acc ^ gf16_mul(plan.factor(row, column), word)
        });
        word.to_le_bytes()[at - word_at]
    }

    /// The bit-by-bit multiply is the field the decoder works in, its words
    /// little-endian.
    #[test]
    fn gf16_reference_multiply_matches_the_decoder() {
        for (a, b) in [
            (2u16, 0x8000u16),
            (0x1234, 0xABCD),
            (0xFFFF, 0xFFFF),
            (3, 0x0101),
            (0x100B, 0x00FF),
        ] {
            let mut dst = [0u8; 2];
            gf_simd::mul_acc_region(a, &b.to_le_bytes(), &mut dst);
            assert_eq!(u16::from_le_bytes(dst), gf16_mul(a, b), "{a:#x} * {b:#x}");
        }
    }

    /// The fold adds each read into the rebuilt volumes as it arrives, odd
    /// last read included, and lands on the bytes the decode computes over
    /// whole padded volumes, on one thread or a pool. Data volumes are read
    /// whole and each `.rev` as far as the fold reads it, so a rebuilt
    /// volume of odd length shorter than the inputs takes its last word's
    /// high byte from them; the cases where a `.rev`'s coefficient is not 1
    /// are the ones where that byte changes the result.
    #[test]
    fn rar5_fold_matches_the_padded_decode() {
        let len = 1001usize;
        let units = (0..3)
            .map(|unit| {
                (0..len)
                    .map(|at| (at * 31 + unit * 7 + 1) as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let padded = units
            .iter()
            .map(|unit| [unit.as_slice(), &[0]].concat())
            .collect::<Vec<_>>();
        let refs = padded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut mixing = false;
        // One volume rebuilt from the first `.rev`, one from the second, and
        // two from both.
        for (valid, out_lens) in [
            (
                [true, false, true, true, true],
                vec![vec![1001], vec![501], vec![999], vec![500]],
            ),
            (
                [true, false, true, false, true],
                vec![vec![1001], vec![501], vec![999], vec![500]],
            ),
            (
                [false, true, false, true, true],
                vec![
                    vec![1001, 501],
                    vec![999, 501],
                    vec![501, 333],
                    vec![500, 1001],
                ],
            ),
        ] {
            for out_lens in out_lens {
                let plan = rar5_plan(&valid, 2, &[0; 3], &[len as u64; 3], &out_lens);
                mixing |= mixes_rev_bytes(&plan);
                let mut expected = vec![vec![0u8; len + 1]; out_lens.len()];
                let mut whole = expected
                    .iter_mut()
                    .map(Vec::as_mut_slice)
                    .collect::<Vec<_>>();
                Arith::new(1).apply(&plan, &refs, &mut whole);
                let mut pooled = vec![vec![0xEEu8; len + 1]; out_lens.len()];
                let mut whole = pooled.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>();
                Arith::new(4).apply(&plan, &refs, &mut whole);
                assert!(
                    pooled == expected,
                    "{valid:?} at {out_lens:?}: the pool's decode differs from one thread's"
                );
                for (row, &out_len) in out_lens.iter().enumerate() {
                    let at = out_len as usize - 1;
                    assert_eq!(
                        expected[row][at],
                        reference_byte(&plan, row, &units, at),
                        "{valid:?} at {out_lens:?}: rebuilt volume {row}'s last byte"
                    );
                }

                for workers in [1, 4] {
                    for piece in [2, 64, 1000] {
                        let mut arith = Arith::new(workers);
                        let mut held = plan
                            .outputs
                            .iter()
                            .map(|out| vec![0u8; Field::Gf16.span(out.len as usize)])
                            .collect::<Vec<_>>();
                        for (column, (input, unit)) in plan.inputs.iter().zip(&units).enumerate() {
                            // As the fold reads them: a data volume whole, a
                            // `.rev` as far as the plan reads its inputs.
                            let end = match input.volume {
                                Volume::Data(_) => input.avail,
                                Volume::Recovery(_) => input.avail.min(plan.read_end()),
                            };
                            let unit = &unit[..end as usize];
                            for (n, bytes) in unit.chunks(piece).enumerate() {
                                arith.accumulate(
                                    &plan,
                                    column,
                                    (n * piece) as u64,
                                    bytes,
                                    &mut held,
                                );
                            }
                        }
                        for (row, &out_len) in out_lens.iter().enumerate() {
                            let out_len = out_len as usize;
                            assert!(
                                held[row][..out_len] == expected[row][..out_len],
                                "{valid:?} at {out_lens:?}: rebuilt volume {row}, {workers} workers, {piece}-byte reads"
                            );
                        }
                    }
                }
            }
        }
        assert!(
            mixing,
            "no case has a `.rev` coefficient other than 0 and 1"
        );
    }

    /// However many workers a caller asks for, the pool holds no more
    /// threads than the machine runs at once.
    #[test]
    fn workers_are_capped_at_the_machines_parallelism() {
        let available = std::thread::available_parallelism().map_or(1, usize::from);
        let mut arith = Arith::new(usize::MAX);
        let threads = arith
            .pool()
            .map_or(1, rayon::ThreadPool::current_num_threads);
        assert!(
            threads <= available,
            "{threads} threads where the machine runs {available} at once"
        );
    }

    /// However small the budget, a decode step holds at least 4 KiB of
    /// every volume, or all the decode reads when that is less; a RAR5 step
    /// stays whole words, and none runs past what the decode reads.
    #[test]
    fn decode_steps_hold_at_least_4_kib() {
        for reach in [1001u64, 100_001] {
            let rar5 = rar5_plan(
                &[true, false, true, true, true],
                2,
                &[0, 0, 0],
                &[reach, reach + 1, reach],
                &[reach],
            );
            let rar3 = Plan {
                field: Field::Gf8,
                coder: Coder::Rar3(vec![1; 3]),
                inputs: (0..3)
                    .map(|index| Input {
                        volume: Volume::Data(index),
                        start: 0,
                        avail: reach,
                    })
                    .collect(),
                outputs: vec![Output {
                    index: 3,
                    len: reach,
                }],
                footers: false,
            };
            for plan in [&rar5, &rar3] {
                let read_end = plan.read_end() as usize;
                let floor = MIN_READ_SIZE.min(read_end);
                for budget in [0, 1, 3000, 64 << 20] {
                    let chunk = plan.chunk(budget);
                    let case = format!("{:?}, reach {reach}, budget {budget}", plan.field);
                    assert!((floor..=read_end).contains(&chunk), "{case}: {chunk}");
                    if plan.field == Field::Gf16 {
                        assert_eq!(chunk % 2, 0, "{case}");
                    }
                }
            }
        }
    }

    /// The decode loop over inputs that run past the longest rebuilt volume,
    /// which is of odd length: each input is read to the next even byte, so
    /// the last word takes its high byte from every input that holds one, as
    /// reference UnRAR reads it. Every rebuilt byte matches the matrix
    /// applied to whole padded volumes, and each volume's last byte a
    /// bit-by-bit multiply, at every slice size, on one thread and on a pool.
    #[test]
    fn rar5_decode_takes_the_last_words_high_byte_from_every_input() {
        // Four data and two recovery volumes; data volumes 1 and 2 are
        // rebuilt from both `.rev`s.
        let valid = [true, false, false, true, true, true];
        // The first `.rev`'s unit starts 3 bytes in, past filler the decode
        // must skip. Data volume 0 and the second `.rev` run well past the
        // longest rebuilt volume, the first `.rev` holds just the byte past
        // it, and data volume 3 ends at it.
        let starts = [0u64, 3, 0, 0];
        let avail = [1300u64, 1002, 1100, 1001];
        let out_lens = [1001u64, 777];
        let reach = 1001usize;
        let plan = rar5_plan(&valid, 2, &starts, &avail, &out_lens);
        assert!(mixes_rev_bytes(&plan), "every `.rev` coefficient is 0 or 1");

        let units = avail
            .iter()
            .enumerate()
            .map(|(column, &len)| {
                (0..len as usize)
                    .map(|at| (at * 29 + column * 101 + 7) as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let volume = |column: usize| {
            let mut bytes = vec![0xEEu8; starts[column] as usize];
            bytes.extend_from_slice(&units[column]);
            Some(bytes)
        };
        let source = SliceVolumeSource::new(
            vec![volume(0), None, None, volume(3)],
            vec![volume(1), volume(2)],
        );

        // The inputs as reference UnRAR reads them, zero past their ends,
        // through the word the longest rebuilt volume ends in.
        let padded = units
            .iter()
            .map(|unit| {
                let mut unit = unit.clone();
                unit.resize(reach + 1, 0);
                unit
            })
            .collect::<Vec<_>>();
        let refs = padded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mut whole = vec![vec![0u8; reach + 1]; out_lens.len()];
        let mut slices = whole.iter_mut().map(Vec::as_mut_slice).collect::<Vec<_>>();
        Arith::new(1).apply(&plan, &refs, &mut slices);
        let expected = whole
            .iter()
            .zip(out_lens)
            .map(|(bytes, len)| bytes[..len as usize].to_vec())
            .collect::<Vec<_>>();
        for (row, bytes) in expected.iter().enumerate() {
            let at = bytes.len() - 1;
            assert_eq!(
                bytes[at],
                reference_byte(&plan, row, &units, at),
                "rebuilt volume {row}'s last byte"
            );
        }
        // A zero in place of the byte past the longest volume rebuilds a
        // different last byte, so the case tells the two apart.
        let cut = units
            .iter()
            .map(|unit| unit[..reach].to_vec())
            .collect::<Vec<_>>();
        assert_ne!(
            reference_byte(&plan, 0, &cut, reach - 1),
            expected[0][reach - 1],
            "the byte past the longest volume does not change its last byte"
        );

        for workers in [1, 4] {
            for chunk in [2, 64, 500, 502, 1000, 1002, 4096] {
                let mut source = source.clone();
                let mut arith = Arith::new(workers);
                let emitters = plan
                    .outputs
                    .iter()
                    .zip(&expected)
                    .map(|(out, bytes)| {
                        let check = OutputCheck::Rar5 {
                            crc32: crate::crc32fast::hash(bytes),
                        };
                        Emitter::with_check(out.index, out.len, check)
                    })
                    .collect();
                let mut sunk = vec![Vec::new(); 3];
                let mut sink = |index: usize, offset: u64, bytes: &[u8]| -> io::Result<()> {
                    assert_eq!(
                        offset,
                        sunk[index].len() as u64,
                        "the sink's offsets run on"
                    );
                    sunk[index].extend_from_slice(bytes);
                    Ok(())
                };
                let restored =
                    run_decode(&plan, chunk, &mut source, &mut arith, emitters, &mut sink).unwrap();
                for (row, out) in plan.outputs.iter().enumerate() {
                    let case = format!(
                        "rebuilt volume {}, {workers} workers, {chunk}-byte slices",
                        out.index
                    );
                    let bytes = &sunk[out.index];
                    let last = bytes.len() - 1;
                    assert_eq!(bytes.len(), expected[row].len(), "{case}");
                    assert_eq!(
                        bytes[last],
                        reference_byte(&plan, row, &units, last),
                        "{case}: the last byte"
                    );
                    assert!(*bytes == expected[row], "{case}");
                    assert!(restored[row].verified, "{case}");
                }
            }
        }
    }
}
