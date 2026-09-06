//! Checking input files against a set, and locating the damage when they differ.
//!
//! Verification here is whole-file: a file matches when its bytes hash to the
//! 16-byte BLAKE3 fingerprint its File packet carries. When they do not, the
//! failure is narrowed down to individual input blocks using the checksums in the
//! set's External Data packets, which is what a repair would need in order to
//! know which blocks to rebuild.
//!
//! # What this does not do
//!
//! Nothing here repairs anything, and nothing here searches. A file whose bytes
//! have been *shifted* — content inserted or removed rather than overwritten —
//! will report every block after the shift that the file still reaches as
//! damaged, because finding the moved blocks needs the sliding rolling-hash
//! search that this crate does not implement.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::hash::{FingerprintHasher, TAIL_HASH_LEN, fingerprint, rolling_hash};
use crate::packet::{ChunkDescription, ChunkTail, InputSetId};
use crate::set::{Par3File, Par3Set};

/// Bytes read at a time when hashing a whole file.
///
/// The whole-file pass does not care where a block boundary falls, so this is a
/// plain I/O buffer rather than anything the set chose.
const READ_CHUNK: usize = 64 * 1024;

/// What checking one input file's bytes found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileVerdict {
    /// The bytes match the File packet's fingerprint.
    Complete,
    /// The file was not found where it was looked for.
    Missing,
    /// The file is present, but its bytes do not match.
    #[non_exhaustive]
    Damaged {
        /// Length the File packet describes.
        expected_size: u64,
        /// Length actually found.
        actual_size: u64,
        /// Input blocks whose bytes did not match the set's checksums.
        ///
        /// Only blocks the file actually reaches are listed. A block that
        /// begins past `actual_size` is absent rather than wrong, and a File
        /// packet may claim more of them than any file could hold, so the
        /// missing tail is left to be read off `expected_size`, `actual_size`
        /// and the chunk descriptions.
        damaged_blocks: Vec<u64>,
        /// Input blocks the set carries no checksum for.
        ///
        /// The reference implementation omits blocks that hold chunk tails from
        /// its External Data packets, so on a set with small files this is
        /// routine rather than a sign of a damaged set. These blocks are not
        /// known to be good.
        unchecked_blocks: Vec<u64>,
        /// Chunks whose trailing partial block did not match, as indices into
        /// [`Par3File::chunks`].
        damaged_chunks: Vec<usize>,
        /// Input blocks holding a chunk tail that did not match, ascending.
        ///
        /// This is the same damage [`damaged_chunks`](FileVerdict::Damaged) names,
        /// expressed in the blocks a codec works in: the block index a described
        /// tail's chunk description carries. A tail block may hold several tails,
        /// possibly from other files, and one wrong tail spoils the whole block,
        /// so a repair has to rebuild all of it. An inline tail lives in the File
        /// packet and occupies no block, so it never appears here.
        damaged_tail_blocks: Vec<u64>,
    },
    /// The file is present, but the set does not describe enough to check it.
    Unverifiable {
        /// Why the check could not be made.
        reason: &'static str,
    },
}

impl FileVerdict {
    /// Whether the file matched.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether the file was absent.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    /// Whether the file was present but wrong.
    #[must_use]
    pub fn is_damaged(&self) -> bool {
        matches!(self, Self::Damaged { .. })
    }

    /// The input blocks this verdict found damaged, if any.
    #[must_use]
    pub fn damaged_blocks(&self) -> &[u64] {
        match self {
            Self::Damaged { damaged_blocks, .. } => damaged_blocks,
            _ => &[],
        }
    }

    /// The input blocks holding a chunk tail this verdict found damaged.
    #[must_use]
    pub fn damaged_tail_blocks(&self) -> &[u64] {
        match self {
            Self::Damaged {
                damaged_tail_blocks,
                ..
            } => damaged_tail_blocks,
            _ => &[],
        }
    }
}

/// One file's line in a [`VerifyReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    path: String,
    verdict: FileVerdict,
}

impl FileReport {
    /// The file's path within the set.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What checking it found.
    #[must_use]
    pub fn verdict(&self) -> &FileVerdict {
        &self.verdict
    }
}

/// The result of checking every file in a set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    input_set_id: InputSetId,
    files: Vec<FileReport>,
}

impl VerifyReport {
    /// The set that was checked.
    #[must_use]
    pub fn input_set_id(&self) -> InputSetId {
        self.input_set_id
    }

    /// One entry per input file, in the set's path order.
    #[must_use]
    pub fn files(&self) -> &[FileReport] {
        &self.files
    }

    /// Whether every file matched.
    ///
    /// A file the set could not check counts against this: "not known to be
    /// wrong" is not the same as complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.files.iter().all(|report| report.verdict.is_complete())
    }

    /// How many files matched.
    #[must_use]
    pub fn complete_count(&self) -> usize {
        self.count(FileVerdict::is_complete)
    }

    /// How many files were absent.
    #[must_use]
    pub fn missing_count(&self) -> usize {
        self.count(FileVerdict::is_missing)
    }

    /// How many files were present but wrong.
    #[must_use]
    pub fn damaged_count(&self) -> usize {
        self.count(FileVerdict::is_damaged)
    }

    fn count(&self, predicate: fn(&FileVerdict) -> bool) -> usize {
        self.files
            .iter()
            .filter(|report| predicate(&report.verdict))
            .count()
    }

    /// Every damaged input block across the whole set, in ascending order.
    #[must_use]
    pub fn damaged_blocks(&self) -> Vec<u64> {
        let mut blocks: Vec<u64> = self
            .files
            .iter()
            .flat_map(|report| report.verdict.damaged_blocks())
            .copied()
            .collect();
        blocks.sort_unstable();
        blocks.dedup();
        blocks
    }
}

/// Check one input file's bytes against its File packet.
///
/// `data` is the whole file. The fast path is a single BLAKE3 pass; the block
/// checks only run once that pass has failed.
#[must_use]
pub fn verify_file(set: &Par3Set, file: &Par3File, data: &[u8]) -> FileVerdict {
    let expected_size = file.size();
    let actual_size = data.len() as u64;

    if file.packet().has_unprotected_data() {
        return FileVerdict::Unverifiable {
            reason: "the file has unprotected chunks, which this crate does not verify",
        };
    }
    if file.packet().fingerprint_is_unset() {
        return FileVerdict::Unverifiable {
            reason: "the File packet carries no fingerprint",
        };
    }
    if actual_size == expected_size && fingerprint(data) == file.fingerprint() {
        return FileVerdict::Complete;
    }

    let mut source = Source::Memory(data);
    let localised = localise(set, file, &mut source);
    localised.into_verdict(expected_size, actual_size)
}

/// Check one input file by reading it from `path`.
///
/// A path that does not exist yields [`FileVerdict::Missing`] rather than an
/// error; any other I/O failure is an error.
///
/// # Memory
///
/// The file is never held in memory. It is read once, in fixed-size pieces, to
/// hash it as a whole; only when that hash disagrees with the File packet is it
/// read a second time, and that pass holds one region at a time — a single input
/// block, or the shorter of a block and the file itself. So the working set is
/// `min(block_size, file_size)` plus a fixed 64 KiB, whatever the file's length.
///
/// The verdicts are the ones [`verify_file`] gives for the same bytes.
pub fn verify_file_at_path(set: &Par3Set, file: &Par3File, path: &Path) -> Result<FileVerdict> {
    let mut handle = match File::open(path) {
        Ok(handle) => handle,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileVerdict::Missing);
        }
        Err(error) => return Err(error.into()),
    };

    if file.packet().has_unprotected_data() {
        return Ok(FileVerdict::Unverifiable {
            reason: "the file has unprotected chunks, which this crate does not verify",
        });
    }
    if file.packet().fingerprint_is_unset() {
        return Ok(FileVerdict::Unverifiable {
            reason: "the File packet carries no fingerprint",
        });
    }

    // One pass for the whole-file hash, which is also what measures the file:
    // the bytes that can be read are the bytes it has, whatever its metadata
    // claims.
    let expected_size = file.size();
    let mut hasher = FingerprintHasher::new();
    let mut buffer = vec![0u8; READ_CHUNK];
    let mut actual_size: u64 = 0;
    loop {
        let read = match handle.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        hasher.update(&buffer[..read]);
        actual_size = actual_size.saturating_add(read as u64);
    }
    if actual_size == expected_size && hasher.finalize() == file.fingerprint() {
        return Ok(FileVerdict::Complete);
    }
    drop(buffer);

    // The bytes disagree, so the damage is narrowed down region by region.
    // Regions run forwards through the file, so the seeks are short.
    let mut source = Source::Stream(StreamSource {
        handle: &mut handle,
        len: actual_size,
        buffer: Vec::new(),
        error: None,
    });
    let localised = localise(set, file, &mut source);
    if let Source::Stream(stream) = source
        && let Some(error) = stream.error
    {
        return Err(error.into());
    }
    Ok(localised.into_verdict(expected_size, actual_size))
}

/// Check every file in a set against a base directory.
///
/// Paths are built by joining `base` with each path component in turn. The
/// components come from File and Directory packet names, which were refused at
/// parse time if they were empty, `.`, `..`, or contained a separator, so a set
/// cannot direct a read outside `base`.
///
/// A set whose Root packet claims an absolute path is still resolved relative to
/// `base`; this crate never reads from a location a packet chose.
pub fn verify_set(set: &Par3Set, base: &Path) -> Result<VerifyReport> {
    let mut files = Vec::with_capacity(set.files().len());
    for file in set.files() {
        let mut path = PathBuf::from(base);
        for component in file.path().split('/') {
            path.push(component);
        }
        files.push(FileReport {
            path: file.path().to_owned(),
            verdict: verify_file_at_path(set, file, &path)?,
        });
    }
    Ok(VerifyReport {
        input_set_id: set.input_set_id(),
        files,
    })
}

#[derive(Default)]
struct Localised {
    damaged_blocks: Vec<u64>,
    unchecked_blocks: Vec<u64>,
    damaged_chunks: Vec<usize>,
    damaged_tail_blocks: Vec<u64>,
}

impl Localised {
    fn into_verdict(self, expected_size: u64, actual_size: u64) -> FileVerdict {
        FileVerdict::Damaged {
            expected_size,
            actual_size,
            damaged_blocks: self.damaged_blocks,
            unchecked_blocks: self.unchecked_blocks,
            damaged_chunks: self.damaged_chunks,
            damaged_tail_blocks: self.damaged_tail_blocks,
        }
    }
}

/// Where the bytes being checked come from.
///
/// Localisation reads a bounded region at a time and never looks at the file as
/// a whole, so the same walk serves both a caller that already holds the bytes
/// and one that only knows where they are.
enum Source<'a> {
    Memory(&'a [u8]),
    Stream(StreamSource<'a>),
}

/// A file being read region by region.
///
/// `len` is how many bytes the file was measured at, not what its metadata
/// claims, so a region past the end is refused without a read. An I/O failure is
/// kept here rather than returned from the walk: the region reads as absent, and
/// the caller turns the stored failure into an error instead of a verdict.
struct StreamSource<'a> {
    handle: &'a mut File,
    len: u64,
    buffer: Vec<u8>,
    error: Option<std::io::Error>,
}

impl Source<'_> {
    /// The bytes at `start..start + len`, or `None` when the file is too short
    /// for them — or, for a stream, when they could not be read.
    fn region(&mut self, start: u64, len: u64) -> Option<&[u8]> {
        match self {
            Self::Memory(data) => slice(data, start, len),
            Self::Stream(stream) => stream.region(start, len),
        }
    }

    /// How many bytes there are to look at.
    fn len(&self) -> u64 {
        match self {
            Self::Memory(data) => data.len() as u64,
            Self::Stream(stream) => stream.len,
        }
    }
}

impl StreamSource<'_> {
    fn region(&mut self, start: u64, len: u64) -> Option<&[u8]> {
        if self.error.is_some() {
            return None;
        }
        let end = start.checked_add(len)?;
        if end > self.len {
            return None;
        }
        // The region lies inside the file, so its length is a length the file
        // system already managed; a platform whose pointers are narrower than
        // that cannot hold it, and it is reported rather than truncated.
        let Ok(len) = usize::try_from(len) else {
            self.error = Some(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "an input block is larger than this platform can address",
            ));
            return None;
        };
        if self.buffer.len() < len {
            self.buffer.resize(len, 0);
        }
        match self
            .handle
            .seek(SeekFrom::Start(start))
            .and_then(|_| self.handle.read_exact(&mut self.buffer[..len]))
        {
            Ok(()) => Some(&self.buffer[..len]),
            Err(error) => {
                self.error = Some(error);
                None
            }
        }
    }
}

/// Narrow a whole-file mismatch down to blocks and tails.
fn localise(set: &Par3Set, file: &Par3File, source: &mut Source<'_>) -> Localised {
    let mut out = Localised::default();
    let block_size = set.block_size();
    if block_size == 0 {
        return out;
    }
    let mut offset: u64 = 0;

    for (index, chunk) in file.chunks().iter().enumerate() {
        let ChunkDescription::Protected {
            length,
            first_block_index,
            tail,
        } = chunk
        else {
            offset = offset.saturating_add(chunk.length());
            continue;
        };

        let full_blocks = length / block_size;
        if let Some(first) = first_block_index {
            // A block whose first byte is past the end of the file is not there
            // to be looked at, and the size mismatch this verdict already
            // carries says so. Stopping at the bytes that exist keeps the work
            // and the output proportional to the file rather than to a chunk
            // length the packets chose: a chunk may honestly claim `u64::MAX`
            // bytes of one-byte blocks.
            let reachable = source.len().saturating_sub(offset).div_ceil(block_size);
            for step in 0..full_blocks.min(reachable) {
                let block_index = first.wrapping_add(step);
                let start = offset.saturating_add(step.saturating_mul(block_size));
                match source.region(start, block_size) {
                    Some(bytes) => match set.block_checksum(block_index) {
                        Some(checksum) => {
                            if rolling_hash(bytes) != checksum.rolling_hash
                                || fingerprint(bytes) != checksum.fingerprint
                            {
                                out.damaged_blocks.push(block_index);
                            }
                        }
                        None => out.unchecked_blocks.push(block_index),
                    },
                    // The file ends before this block does, so the block is not
                    // there to check.
                    None => out.damaged_blocks.push(block_index),
                }
            }
        }

        let tail_start = offset.saturating_add(full_blocks.saturating_mul(block_size));
        let tail_size = length % block_size;
        match tail {
            ChunkTail::None => {}
            ChunkTail::Inline(expected) => {
                if source.region(tail_start, expected.len() as u64) != Some(expected.as_slice()) {
                    out.damaged_chunks.push(index);
                }
            }
            ChunkTail::Described {
                rolling_hash: expected_rolling,
                fingerprint: expected_fingerprint,
                block_index,
                ..
            } => {
                let matched = match source.region(tail_start, tail_size) {
                    Some(bytes) => {
                        let head = &bytes[..bytes.len().min(TAIL_HASH_LEN)];
                        rolling_hash(head) == *expected_rolling
                            && fingerprint(bytes) == *expected_fingerprint
                    }
                    None => false,
                };
                if !matched {
                    out.damaged_chunks.push(index);
                    out.damaged_tail_blocks.push(*block_index);
                }
            }
        }

        offset = offset.saturating_add(*length);
    }

    out.damaged_blocks.sort_unstable();
    out.damaged_blocks.dedup();
    out.unchecked_blocks.sort_unstable();
    out.unchecked_blocks.dedup();
    out.damaged_tail_blocks.sort_unstable();
    out.damaged_tail_blocks.dedup();
    out
}

/// `data[start..start + len]`, or `None` if the file is too short for it.
fn slice(data: &[u8], start: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(start).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = start.checked_add(len)?;
    data.get(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::quick_rolling_hash;
    use crate::packet::{
        BlockChecksum, ExternalDataPacket, FilePacket, GaloisField, Packet, PacketBody, RootPacket,
        StartPacket,
    };

    const ID: InputSetId = InputSetId([7; 8]);

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn start(block_size: u64) -> Packet {
        Packet::new(
            ID,
            PacketBody::Start(StartPacket {
                parent_input_set_id: InputSetId::ZERO,
                parent_root_hash: [0u8; 16],
                block_size,
                galois_field: GaloisField {
                    size: 1,
                    generator: 0x1d,
                },
                legacy_random: None,
            }),
        )
    }

    /// A File packet describing `data` as one chunk under `block_size`.
    fn file_packet(data: &[u8], block_size: u64) -> FilePacket {
        let length = data.len() as u64;
        let full_blocks = length / block_size;
        let tail_bytes = &data[(full_blocks * block_size) as usize..];
        let tail = if tail_bytes.is_empty() {
            ChunkTail::None
        } else if tail_bytes.len() < TAIL_HASH_LEN {
            ChunkTail::Inline(tail_bytes.to_vec())
        } else {
            ChunkTail::Described {
                rolling_hash: rolling_hash(&tail_bytes[..TAIL_HASH_LEN]),
                fingerprint: fingerprint(tail_bytes),
                block_index: full_blocks,
                offset: 0,
            }
        };
        FilePacket {
            name: "a.bin".to_owned(),
            quick_rolling_hash: quick_rolling_hash(data),
            fingerprint: fingerprint(data),
            option_hashes: Vec::new(),
            chunks: vec![ChunkDescription::Protected {
                length,
                first_block_index: (length >= block_size).then_some(0),
                tail,
            }],
        }
    }

    /// Assemble a one-file set, optionally with the block checksums for it.
    fn assemble(file: FilePacket, data: &[u8], block_size: u64, with_checksums: bool) -> Par3Set {
        let length = data.len() as u64;
        let full_blocks = length / block_size;
        let block_count = full_blocks + u64::from(!length.is_multiple_of(block_size));
        let file = Packet::new(ID, PacketBody::File(file));
        let mut packets = vec![
            start(block_size),
            Packet::new(
                ID,
                PacketBody::Root(RootPacket {
                    lowest_unused_block_index: block_count,
                    attributes: 0,
                    option_hashes: Vec::new(),
                    children: vec![file.hash()],
                }),
            ),
            file,
        ];
        if with_checksums && full_blocks > 0 {
            let checksums = (0..full_blocks)
                .map(|index| {
                    let start = (index * block_size) as usize;
                    let block = &data[start..start + block_size as usize];
                    BlockChecksum {
                        rolling_hash: rolling_hash(block),
                        fingerprint: fingerprint(block),
                    }
                })
                .collect();
            packets.push(Packet::new(
                ID,
                PacketBody::ExternalData(ExternalDataPacket {
                    first_block_index: 0,
                    checksums,
                }),
            ));
        }
        Par3Set::from_packets_for(packets, ID).expect("builds")
    }

    fn build_set(data: &[u8], block_size: u64) -> Par3Set {
        assemble(file_packet(data, block_size), data, block_size, true)
    }

    #[test]
    fn intact_bytes_verify() {
        let data = body(100);
        let set = build_set(&data, 16);
        assert_eq!(
            verify_file(&set, &set.files()[0], &data),
            FileVerdict::Complete
        );
    }

    #[test]
    fn a_flipped_byte_localises_to_its_block() {
        let data = body(100);
        let set = build_set(&data, 16);
        let mut damaged = data.clone();
        damaged[35] ^= 0xff;
        match verify_file(&set, &set.files()[0], &damaged) {
            FileVerdict::Damaged {
                expected_size,
                actual_size,
                damaged_blocks,
                unchecked_blocks,
                damaged_chunks,
                damaged_tail_blocks,
                ..
            } => {
                assert_eq!(expected_size, 100);
                assert_eq!(actual_size, 100);
                assert_eq!(damaged_blocks, vec![2u64]);
                assert!(unchecked_blocks.is_empty());
                assert!(damaged_chunks.is_empty());
                assert!(damaged_tail_blocks.is_empty());
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn damage_in_a_described_tail_names_the_chunk() {
        // Two 64-byte blocks and a 50-byte tail: long enough to be described by
        // hashes rather than stored inline.
        let data = body(178);
        let set = build_set(&data, 64);
        assert!(matches!(
            set.files()[0].chunks()[0],
            ChunkDescription::Protected {
                tail: ChunkTail::Described { .. },
                ..
            }
        ));
        let mut damaged = data.clone();
        damaged[170] ^= 0x01;
        match verify_file(&set, &set.files()[0], &damaged) {
            FileVerdict::Damaged {
                damaged_blocks,
                damaged_chunks,
                ..
            } => {
                assert!(damaged_blocks.is_empty());
                assert_eq!(damaged_chunks, vec![0usize]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn damage_in_an_inline_tail_names_the_chunk() {
        // One 64-byte block and a 10-byte tail, stored verbatim in the packet.
        let data = body(74);
        let set = build_set(&data, 64);
        assert!(matches!(
            set.files()[0].chunks()[0],
            ChunkDescription::Protected {
                tail: ChunkTail::Inline(_),
                ..
            }
        ));
        let mut damaged = data.clone();
        damaged[70] ^= 0x80;
        match verify_file(&set, &set.files()[0], &damaged) {
            FileVerdict::Damaged {
                damaged_blocks,
                damaged_chunks,
                ..
            } => {
                assert!(damaged_blocks.is_empty());
                assert_eq!(damaged_chunks, vec![0usize]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn a_truncated_file_reports_the_blocks_it_still_reaches() {
        let data = body(100);
        let set = build_set(&data, 16);
        // Blocks 0 and 1 are intact, block 2 begins at 32 and runs off the end,
        // and blocks 3 to 5 begin past the end entirely: absent rather than
        // wrong, and left to be read off the two sizes.
        match verify_file(&set, &set.files()[0], &data[..40]) {
            FileVerdict::Damaged {
                expected_size,
                actual_size,
                damaged_blocks,
                damaged_chunks,
                ..
            } => {
                assert_eq!(expected_size, 100);
                assert_eq!(actual_size, 40);
                assert_eq!(damaged_blocks, vec![2u64]);
                assert_eq!(damaged_chunks, vec![0usize]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn a_chunk_cannot_make_verification_enumerate_more_blocks_than_the_file_holds() {
        // The whole point of the block-range check in `set`: a chunk claiming
        // `u64::MAX` bytes of one-byte blocks only builds into a set whose Root
        // packet claims just as many blocks, and verifying a two-byte file
        // against it must look at two blocks, not 2^64.
        let file = FilePacket {
            name: "a.bin".to_owned(),
            quick_rolling_hash: 0,
            fingerprint: [1u8; 16],
            option_hashes: Vec::new(),
            chunks: vec![ChunkDescription::Protected {
                length: u64::MAX,
                first_block_index: Some(0),
                tail: ChunkTail::None,
            }],
        };
        let file = Packet::new(ID, PacketBody::File(file));
        let packets = vec![
            start(1),
            Packet::new(
                ID,
                PacketBody::Root(RootPacket {
                    lowest_unused_block_index: u64::MAX,
                    attributes: 0,
                    option_hashes: Vec::new(),
                    children: vec![file.hash()],
                }),
            ),
            file,
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        match verify_file(&set, &set.files()[0], b"hi") {
            FileVerdict::Damaged {
                expected_size,
                actual_size,
                damaged_blocks,
                unchecked_blocks,
                ..
            } => {
                assert_eq!(expected_size, u64::MAX);
                assert_eq!(actual_size, 2);
                assert!(damaged_blocks.is_empty());
                assert_eq!(unchecked_blocks, vec![0u64, 1]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn blocks_without_a_checksum_are_reported_as_unchecked() {
        let data = body(100);
        let set = assemble(file_packet(&data, 16), &data, 16, false);
        let mut damaged = data.clone();
        damaged[3] ^= 0xff;
        match verify_file(&set, &set.files()[0], &damaged) {
            FileVerdict::Damaged {
                damaged_blocks,
                unchecked_blocks,
                ..
            } => {
                assert!(damaged_blocks.is_empty());
                assert_eq!(unchecked_blocks, vec![0u64, 1, 2, 3, 4, 5]);
            }
            other => panic!("unexpected verdict: {other:?}"),
        }
    }

    #[test]
    fn a_file_without_a_fingerprint_is_unverifiable() {
        let data = body(100);
        let mut file = file_packet(&data, 16);
        file.fingerprint = [0u8; 16];
        let set = assemble(file, &data, 16, true);
        assert!(matches!(
            verify_file(&set, &set.files()[0], &data),
            FileVerdict::Unverifiable { .. }
        ));
    }

    #[test]
    fn an_unprotected_chunk_makes_a_file_unverifiable() {
        let data = body(100);
        let mut file = file_packet(&data, 16);
        file.chunks
            .push(ChunkDescription::Unprotected { length: 8 });
        let set = assemble(file, &data, 16, true);
        assert!(matches!(
            verify_file(&set, &set.files()[0], &data),
            FileVerdict::Unverifiable { .. }
        ));
    }

    #[test]
    fn verify_set_reads_from_a_base_directory() {
        let data = body(100);
        let set = build_set(&data, 16);
        let dir = std::env::temp_dir().join(format!(
            "par3-rs-verify-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("a.bin"), &data).expect("write");

        let report = verify_set(&set, &dir).expect("verifies");
        assert!(report.is_complete());
        assert_eq!(report.complete_count(), 1);
        assert_eq!(report.input_set_id(), ID);
        assert_eq!(report.files()[0].path(), "a.bin");
        assert!(report.files()[0].verdict().is_complete());

        let mut damaged = data.clone();
        damaged[35] ^= 0xff;
        std::fs::write(dir.join("a.bin"), &damaged).expect("write");
        let report = verify_set(&set, &dir).expect("verifies");
        assert_eq!(report.damaged_count(), 1);
        assert_eq!(report.damaged_blocks(), vec![2u64]);

        std::fs::remove_file(dir.join("a.bin")).expect("remove");
        let report = verify_set(&set, &dir).expect("verifies");
        assert_eq!(report.missing_count(), 1);
        assert!(!report.is_complete());
        assert!(report.damaged_blocks().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_damaged_described_tail_names_the_block_that_holds_it() {
        let data = body(178);
        let set = build_set(&data, 64);
        let mut damaged = data.clone();
        damaged[170] ^= 0x01;
        let verdict = verify_file(&set, &set.files()[0], &damaged);
        assert_eq!(verdict.damaged_tail_blocks(), [2u64]);
        // An inline tail lives in the packet, so nothing is lost with a block.
        let short = body(74);
        let set = build_set(&short, 64);
        let mut damaged = short.clone();
        damaged[70] ^= 0x80;
        let verdict = verify_file(&set, &set.files()[0], &damaged);
        assert!(verdict.damaged_tail_blocks().is_empty());
        assert_eq!(verdict.damaged_blocks(), [] as [u64; 0]);
    }

    /// The two entry points must agree on every case, because a repair plans
    /// from the streaming one and rebuilds against the in-memory one.
    #[test]
    fn reading_a_file_gives_the_same_verdict_as_holding_its_bytes() {
        // Ten blocks and a described tail: many times the whole-file read
        // buffer, so the streaming pass cannot be holding the file.
        let data = body(64 * 1024 * 10 + 500);
        let set = build_set(&data, 64 * 1024);
        let file = &set.files()[0];

        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("intact", data.clone()),
            ("empty", Vec::new()),
            ("truncated to zero blocks", data[..100].to_vec()),
            ("truncated mid-block", data[..64 * 1024 * 3 + 7].to_vec()),
            ("truncated into the tail", data[..data.len() - 10].to_vec()),
        ];
        let mut flipped = data.clone();
        flipped[64 * 1024 * 4 + 3] ^= 0xff;
        cases.push(("a flipped byte in block 4", flipped));
        let mut tail = data.clone();
        let at = tail.len() - 1;
        tail[at] ^= 0xff;
        cases.push(("a flipped byte in the tail", tail));
        let mut longer = data.clone();
        longer.extend_from_slice(b"extra");
        cases.push(("over-long", longer));

        let dir = std::env::temp_dir().join(format!(
            "par3-rs-stream-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("a.bin");
        for (what, bytes) in &cases {
            std::fs::write(&path, bytes).expect("write");
            let streamed = verify_file_at_path(&set, file, &path).expect("reads");
            assert_eq!(streamed, verify_file(&set, file, bytes), "{what}");
        }
        std::fs::remove_file(&path).expect("remove");
        assert_eq!(
            verify_file_at_path(&set, file, &path).expect("reads"),
            FileVerdict::Missing
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_set_carries_a_checksum_for_each_full_block() {
        let data = body(100);
        let set = build_set(&data, 16);
        assert_eq!(set.block_checksums().len(), 6);
    }
}
