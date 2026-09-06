//! The one pass over the input data.
//!
//! Every byte of every input file is read exactly once, and on the way past it
//! feeds four things: the file's own two hashes, the checksums of the full input
//! block it belongs to, the tail buffer if it is part of a packed chunk tail, and
//! the Cauchy encoder. The block a byte belongs to is already known — [`BlockMap`]
//! settled that from the file sizes — so nothing has to be re-read or held longer
//! than the block it is in.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use super::CreateLimits;
use super::map::{BlockKind, BlockMap, PlannedTail};
use super::plan::PlannedFile;
use crate::cauchy::{CodecLimits, Encoder, Geometry, RecoveryRow};
use crate::error::{Par3Error, Result};
use crate::gf::{AnyField, Gf8, Gf16, for_set};
use crate::hash::{
    Fingerprint, FingerprintHasher, QUICK_HASH_LEN, RollingHasher, TAIL_HASH_LEN, fingerprint,
    rolling_hash,
};
use crate::packet::{BlockChecksum, GaloisField};

/// What reading one input file produced.
#[derive(Debug, Clone)]
pub(crate) struct FileDigest {
    /// CRC-64/GO-ISO of the file's first 16 KiB, or of all of it if shorter.
    pub quick_rolling_hash: u64,
    /// 16-byte BLAKE3 of the whole file.
    pub fingerprint: Fingerprint,
    /// What the File packet must say about the trailing partial block.
    pub tail: TailDigest,
}

/// The hashes or bytes a chunk tail contributes to its File packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TailDigest {
    /// No tail at all.
    None,
    /// A tail under 40 bytes, stored as itself.
    Inline(Vec<u8>),
    /// A tail of at least 40 bytes, stored as hashes and a location.
    Described {
        /// CRC-64/GO-ISO of the tail's first 40 bytes.
        rolling_hash: u64,
        /// 16-byte BLAKE3 of the whole tail.
        fingerprint: Fingerprint,
    },
}

/// Everything the read pass produced.
#[derive(Debug)]
pub(crate) struct EncodeOutcome {
    /// One entry per input file, in the same order as the files given.
    pub files: Vec<FileDigest>,
    /// Checksums of the full-size input blocks, which are the only ones an
    /// External Data packet describes.
    pub block_checksums: BTreeMap<u64, BlockChecksum>,
    /// The recovery blocks, in ascending index from zero. Empty when the set is
    /// index-only.
    pub recovery: Vec<RecoveryRow>,
}

/// Read every input file once, hashing and encoding as the bytes go past.
pub(crate) fn read_inputs(
    files: &[PlannedFile],
    map: &BlockMap,
    block_size: u64,
    field: GaloisField,
    recovery_count: u64,
    limits: &CreateLimits,
) -> Result<EncodeOutcome> {
    let block_len = usize::try_from(block_size).map_err(|_| Par3Error::CreateLimitExceeded {
        reason: format!("a block size of {block_size} bytes does not fit in memory"),
    })?;

    let mut encoder =
        AnyEncoder::new(field, block_size, map.block_count(), recovery_count, limits)?;
    let mut tail_blocks = TailBlocks::new(block_len, limits);
    let mut block_checksums: BTreeMap<u64, BlockChecksum> = BTreeMap::new();
    let mut digests: Vec<FileDigest> = Vec::with_capacity(files.len());
    let mut buffer = vec![0u8; block_len];

    // Which tail blocks each file finishes off, so that completing one costs a
    // lookup rather than a walk over every block in the set.
    let mut finished_by: Vec<Vec<u64>> = vec![Vec::new(); files.len()];
    for (index, kind) in map.kinds.iter().enumerate() {
        if *kind == BlockKind::Tail {
            finished_by[map.last_writer[index]].push(index as u64);
        }
    }

    for (file_index, file) in files.iter().enumerate() {
        let Some(chunk) = map.chunks[file_index] else {
            digests.push(FileDigest {
                quick_rolling_hash: 0,
                fingerprint: fingerprint(&[]),
                tail: TailDigest::None,
            });
            continue;
        };

        let mut reader = InputReader::open(file)?;
        let mut whole = FingerprintHasher::new();
        let mut quick = QuickHash::new();

        let full_blocks = chunk.length / block_size;
        for step in 0..full_blocks {
            reader.read_exact(&mut buffer)?;
            whole.update(&buffer);
            quick.update(&buffer);
            let index = chunk
                .first_block_index
                .expect("a file of a block or more has a first block index")
                + step;
            block_checksums.insert(
                index,
                BlockChecksum {
                    rolling_hash: rolling_hash(&buffer),
                    fingerprint: fingerprint(&buffer),
                },
            );
            encoder.add_input_block(index, &buffer)?;
        }

        let tail_length = chunk.tail.length();
        let tail_bytes = &mut buffer[..tail_length as usize];
        if tail_length > 0 {
            reader.read_exact(tail_bytes)?;
            whole.update(tail_bytes);
            quick.update(tail_bytes);
        }
        let tail = match chunk.tail {
            PlannedTail::None => TailDigest::None,
            PlannedTail::Inline { .. } => TailDigest::Inline(tail_bytes.to_vec()),
            PlannedTail::Described {
                block_index,
                offset,
                ..
            } => {
                let digest = TailDigest::Described {
                    rolling_hash: rolling_hash(&tail_bytes[..TAIL_HASH_LEN]),
                    fingerprint: fingerprint(tail_bytes),
                };
                tail_blocks.write(block_index, offset, tail_bytes)?;
                digest
            }
        };

        reader.finish()?;
        digests.push(FileDigest {
            quick_rolling_hash: quick.finalize(),
            fingerprint: whole.finalize(),
            tail,
        });

        // Hand over every tail block this file completed. Holding them any
        // longer would make the peak memory the whole set rather than the tails
        // still waiting for bytes.
        for index in &finished_by[file_index] {
            let block = tail_blocks.take(*index)?;
            encoder.add_input_block(*index, &block)?;
        }
    }

    tail_blocks.finish()?;
    Ok(EncodeOutcome {
        files: digests,
        block_checksums,
        recovery: encoder.finish(),
    })
}

/// An input file open for its one read, checked against the size it was planned
/// at.
struct InputReader<'a> {
    file: File,
    planned: &'a PlannedFile,
}

impl<'a> InputReader<'a> {
    fn open(planned: &'a PlannedFile) -> Result<Self> {
        let file = File::open(&planned.path).map_err(|source| Par3Error::FileIo {
            path: planned.path.display().to_string(),
            source,
        })?;
        Ok(Self { file, planned })
    }

    fn changed(&self) -> Par3Error {
        Par3Error::CreateInput {
            path: self.planned.path.display().to_string(),
            reason: format!(
                "changed size while it was being read; it was {} bytes when the set was planned",
                self.planned.size
            ),
        }
    }

    fn read_exact(&mut self, into: &mut [u8]) -> Result<()> {
        match self.file.read_exact(into) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Err(self.changed()),
            Err(source) => Err(Par3Error::FileIo {
                path: self.planned.path.display().to_string(),
                source,
            }),
        }
    }

    /// Check that the file ended where the plan said it would.
    fn finish(mut self) -> Result<()> {
        let mut extra = [0u8; 1];
        match self.file.read(&mut extra) {
            Ok(0) => Ok(()),
            Ok(_) => Err(self.changed()),
            Err(source) => Err(Par3Error::FileIo {
                path: self.planned.path.display().to_string(),
                source,
            }),
        }
    }
}

/// The rolling hash a File packet stores, over at most the first 16 KiB.
struct QuickHash {
    hasher: RollingHasher,
    remaining: usize,
}

impl QuickHash {
    fn new() -> Self {
        Self {
            hasher: RollingHasher::new(),
            remaining: QUICK_HASH_LEN,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let take = data.len().min(self.remaining);
        if take > 0 {
            self.hasher.update(&data[..take]);
            self.remaining -= take;
        }
    }

    fn finalize(&self) -> u64 {
        self.hasher.finalize()
    }
}

/// The blocks that hold chunk tails, held only while they are still filling.
///
/// A tail block is zero-padded to the block size, and that padding is part of
/// what the encoder sees, so the buffer starts as zeros and the tails are written
/// into it where they belong.
struct TailBlocks {
    block_len: usize,
    open: BTreeMap<u64, Vec<u8>>,
    budget: u64,
}

impl TailBlocks {
    fn new(block_len: usize, limits: &CreateLimits) -> Self {
        Self {
            block_len,
            open: BTreeMap::new(),
            budget: limits.max_tail_buffer_bytes,
        }
    }

    fn write(&mut self, index: u64, offset: u64, data: &[u8]) -> Result<()> {
        if !self.open.contains_key(&index) {
            let held = self.open.len() as u64 * self.block_len as u64;
            if held + self.block_len as u64 > self.budget {
                return Err(Par3Error::CreateLimitExceeded {
                    reason: format!(
                        "the chunk tails still being filled would need more than the {} bytes \
                         the limits allow",
                        self.budget
                    ),
                });
            }
            self.open.insert(index, vec![0u8; self.block_len]);
        }
        let block = self.open.get_mut(&index).expect("just inserted");
        let at = offset as usize;
        block[at..at + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn take(&mut self, index: u64) -> Result<Vec<u8>> {
        self.open.remove(&index).ok_or(Par3Error::CreateInput {
            path: String::new(),
            reason: format!("input block {index} was planned as a tail block but never filled"),
        })
    }

    fn finish(self) -> Result<()> {
        match self.open.keys().next() {
            None => Ok(()),
            Some(index) => Err(Par3Error::CreateInput {
                path: String::new(),
                reason: format!("input block {index} was left half filled"),
            }),
        }
    }
}

/// The encoder for whichever field the set chose, or none at all.
enum AnyEncoder {
    Gf8(Box<Encoder<Gf8>>),
    Gf16(Box<Encoder<Gf16>>),
    None,
}

impl AnyEncoder {
    fn new(
        field: GaloisField,
        block_size: u64,
        input_blocks: u64,
        recovery_blocks: u64,
        limits: &CreateLimits,
    ) -> Result<Self> {
        if recovery_blocks == 0 {
            return Ok(Self::None);
        }
        let geometry = Geometry {
            block_size,
            input_blocks,
            recovery_blocks,
            first_recovery: 0,
        };
        let codec: &CodecLimits = &limits.codec;
        Ok(match for_set(&field)? {
            AnyField::Gf8(field) => {
                Self::Gf8(Box::new(Encoder::with_limits(field, geometry, codec)?))
            }
            AnyField::Gf16(field) => {
                Self::Gf16(Box::new(Encoder::with_limits(field, geometry, codec)?))
            }
        })
    }

    fn add_input_block(&mut self, index: u64, data: &[u8]) -> Result<()> {
        match self {
            Self::Gf8(encoder) => encoder.add_input_block(index, data),
            Self::Gf16(encoder) => encoder.add_input_block(index, data),
            Self::None => Ok(()),
        }
    }

    fn finish(self) -> Vec<RecoveryRow> {
        match self {
            Self::Gf8(encoder) => encoder.finish(),
            Self::Gf16(encoder) => encoder.finish(),
            Self::None => Vec::new(),
        }
    }
}
