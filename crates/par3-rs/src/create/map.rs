//! Where every input byte goes: chunks, input blocks, and packed chunk tails.
//!
//! The whole map is decided from file names and sizes, before any file is
//! opened. Nothing here depends on file *contents*, which is what lets
//! [`super::create`] read each input exactly once: the block a byte belongs to
//! is already known when the byte arrives.

use super::plan::{MAX_TOTAL_BLOCKS, MIN_TAIL_BLOCK_LEN, PlannedFile};
use crate::error::{Par3Error, Result};

/// How a file's trailing partial block is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlannedTail {
    /// The file is a whole number of blocks long.
    None,
    /// A tail of 1 to 39 bytes, which lives in the File packet.
    Inline {
        /// Length of the tail in bytes.
        length: u64,
    },
    /// A tail of at least 40 bytes, which lives in an input block.
    Described {
        /// Length of the tail in bytes.
        length: u64,
        /// The input block holding it.
        block_index: u64,
        /// Where in that block it starts.
        offset: u64,
    },
}

impl PlannedTail {
    /// Bytes of the file this tail covers.
    pub(crate) fn length(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Inline { length } | Self::Described { length, .. } => length,
        }
    }
}

/// One input file's single protected chunk.
///
/// This crate never splits a file into more than one chunk: it does no
/// deduplication and writes no unprotected chunks, so chunk and file coincide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedChunk {
    /// Length of the chunk, which is the file size.
    pub length: u64,
    /// Index of the first whole input block, when the file fills at least one.
    pub first_block_index: Option<u64>,
    /// The index the file's first whole block would take.
    ///
    /// The reference implementation records this whether or not the file is long
    /// enough to have one, and feeds it to the InputSetID digest for a file that
    /// is; keeping it separate from `first_block_index` is what lets that digest
    /// be reproduced.
    pub block_hint: u64,
    /// The trailing partial block.
    pub tail: PlannedTail,
}

/// What one input block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockKind {
    /// A block filled by one file's data.
    ///
    /// Only these get an External Data checksum.
    Full,
    /// A block holding one or more chunk tails, zero-padded to the block size.
    Tail,
}

/// A tail that has been placed but whose block may still take another.
#[derive(Debug, Clone, Copy)]
struct OpenTail {
    block_index: u64,
    offset: u64,
    length: u64,
    /// Whether this is still the last tail in its block. A block only ever grows
    /// at its end, so a tail with something after it can never be extended.
    open: bool,
}

/// The complete layout of a set's input blocks.
#[derive(Debug, Clone)]
pub(crate) struct BlockMap {
    /// What each input block holds, indexed by block index.
    pub kinds: Vec<BlockKind>,
    /// One entry per input file in sorted order; `None` for an empty file, which
    /// gets no chunk description at all.
    pub chunks: Vec<Option<PlannedChunk>>,
    /// The input file that writes the last bytes of each block, so that a tail
    /// block can be handed to the encoder as soon as it is full instead of being
    /// held to the end.
    pub last_writer: Vec<usize>,
    /// How many tails were placed after an earlier tail rather than in a block
    /// of their own.
    pub packed_tails: u64,
}

impl BlockMap {
    /// Lay out the blocks for files that are already in the order they will be
    /// stored in.
    ///
    /// Each file takes consecutive whole blocks; its tail then goes after the
    /// first earlier tail it fits behind, or into a new block. That "first
    /// earlier tail it fits behind" is the reference implementation's rule,
    /// scanning the tails in the order they were placed and appending at the
    /// current fill of the block with no alignment, which is why the caller sorts
    /// the longest tails to the front.
    pub(crate) fn plan(files: &[PlannedFile], block_size: u64) -> Result<Self> {
        let mut kinds: Vec<BlockKind> = Vec::new();
        let mut last_writer: Vec<usize> = Vec::new();
        let mut chunks: Vec<Option<PlannedChunk>> = Vec::with_capacity(files.len());
        let mut tails: Vec<OpenTail> = Vec::new();
        let mut packed_tails = 0u64;

        for (file_index, file) in files.iter().enumerate() {
            if file.size == 0 {
                chunks.push(None);
                continue;
            }
            let block_hint = kinds.len() as u64;
            let full_blocks = file.size / block_size;
            let first_block_index = (file.size >= block_size).then_some(block_hint);
            for _ in 0..full_blocks {
                push_block(&mut kinds, &mut last_writer, BlockKind::Full, file_index)?;
            }

            let tail_length = file.size % block_size;
            let tail = if tail_length == 0 {
                PlannedTail::None
            } else if tail_length < MIN_TAIL_BLOCK_LEN {
                PlannedTail::Inline {
                    length: tail_length,
                }
            } else {
                let fits = tails.iter().position(|tail| {
                    tail.open && tail.offset + tail.length + tail_length <= block_size
                });
                match fits {
                    Some(at) => {
                        let block_index = tails[at].block_index;
                        let offset = tails[at].offset + tails[at].length;
                        tails[at].open = false;
                        last_writer[block_index as usize] = file_index;
                        packed_tails += 1;
                        tails.push(OpenTail {
                            block_index,
                            offset,
                            length: tail_length,
                            open: true,
                        });
                        PlannedTail::Described {
                            length: tail_length,
                            block_index,
                            offset,
                        }
                    }
                    None => {
                        let block_index = kinds.len() as u64;
                        push_block(&mut kinds, &mut last_writer, BlockKind::Tail, file_index)?;
                        tails.push(OpenTail {
                            block_index,
                            offset: 0,
                            length: tail_length,
                            open: true,
                        });
                        PlannedTail::Described {
                            length: tail_length,
                            block_index,
                            offset: 0,
                        }
                    }
                }
            };

            chunks.push(Some(PlannedChunk {
                length: file.size,
                first_block_index,
                block_hint,
                tail,
            }));
        }

        Ok(Self {
            kinds,
            chunks,
            last_writer,
            packed_tails,
        })
    }

    /// Number of input blocks the set stores.
    pub(crate) fn block_count(&self) -> u64 {
        self.kinds.len() as u64
    }

    /// The runs of consecutive full-size blocks, as `(first index, count)`.
    ///
    /// One External Data packet is written per run: a block holding chunk tails
    /// carries no checksum, and it breaks the run.
    pub(crate) fn full_block_runs(&self) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for (index, kind) in self.kinds.iter().enumerate() {
            if *kind != BlockKind::Full {
                continue;
            }
            // A tail block between two full ones leaves a gap in the indices,
            // which is what ends the run.
            match runs.last_mut() {
                Some(run) if run.0 + run.1 == index as u64 => run.1 += 1,
                _ => runs.push((index as u64, 1)),
            }
        }
        runs
    }
}

/// Append one input block, refusing a set that outgrows the format's ceiling.
fn push_block(
    kinds: &mut Vec<BlockKind>,
    last_writer: &mut Vec<usize>,
    kind: BlockKind,
    file_index: usize,
) -> Result<()> {
    if kinds.len() as u64 >= MAX_TOTAL_BLOCKS {
        return Err(Par3Error::CreateInput {
            path: String::new(),
            reason: format!(
                "the inputs need more than the {MAX_TOTAL_BLOCKS} input blocks a set can address; \
                 use a larger block size"
            ),
        });
    }
    kinds.push(kind);
    last_writer.push(file_index);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file(name: &str, size: u64) -> PlannedFile {
        PlannedFile {
            name: name.to_owned(),
            path: PathBuf::from(name),
            size,
        }
    }

    #[test]
    fn the_oracle_layout_is_two_files_of_blocks_around_one_tail_block() {
        // The order the reference sorts these into: tail 1000, tail 10, tail 0.
        let files = [
            file("a.bin", 5000),
            file("b.txt", 10),
            file("sub/c.bin", 4000),
        ];
        let map = BlockMap::plan(&files, 2000).expect("a layout");

        assert_eq!(map.block_count(), 5);
        assert_eq!(map.packed_tails, 0);
        assert_eq!(
            map.kinds,
            [
                BlockKind::Full,
                BlockKind::Full,
                BlockKind::Tail,
                BlockKind::Full,
                BlockKind::Full
            ]
        );
        assert_eq!(map.full_block_runs(), [(0, 2), (3, 2)]);
        assert_eq!(
            map.chunks[0].expect("a.bin has a chunk").tail,
            PlannedTail::Described {
                length: 1000,
                block_index: 2,
                offset: 0
            }
        );
        assert_eq!(
            map.chunks[1].expect("b.txt has a chunk").tail,
            PlannedTail::Inline { length: 10 }
        );
        assert_eq!(
            map.chunks[2].expect("c.bin has a chunk").tail,
            PlannedTail::None
        );
    }

    #[test]
    fn tails_fill_an_open_block_before_opening_another() {
        // Sorted longest tail first: 500, 300, 300, 300.
        let files = [
            file("w", 500),
            file("x", 300),
            file("y", 300),
            file("z", 300),
        ];
        let map = BlockMap::plan(&files, 1000).expect("a layout");

        // 500 opens block 0; 300 goes after it at 500; the next 300 does not fit
        // in the 200 bytes left, so it opens block 1; the last 300 follows it.
        assert_eq!(map.block_count(), 2);
        assert_eq!(map.packed_tails, 2);
        let at = |index: usize| map.chunks[index].expect("a chunk").tail;
        assert_eq!(
            at(0),
            PlannedTail::Described {
                length: 500,
                block_index: 0,
                offset: 0
            }
        );
        assert_eq!(
            at(1),
            PlannedTail::Described {
                length: 300,
                block_index: 0,
                offset: 500
            }
        );
        assert_eq!(
            at(2),
            PlannedTail::Described {
                length: 300,
                block_index: 1,
                offset: 0
            }
        );
        assert_eq!(
            at(3),
            PlannedTail::Described {
                length: 300,
                block_index: 1,
                offset: 300
            }
        );
        assert_eq!(map.last_writer[0], 1);
        assert_eq!(map.last_writer[1], 3);
    }

    #[test]
    fn a_full_block_is_never_treated_as_a_tail_to_pack_behind() {
        let files = [file("a", 1040), file("b", 40)];
        let map = BlockMap::plan(&files, 1000).expect("a layout");
        // Block 0 is a.bin's full block, block 1 its 40-byte tail; b's tail packs
        // in behind that tail, not behind the full block.
        assert_eq!(map.kinds, [BlockKind::Full, BlockKind::Tail]);
        assert_eq!(
            map.chunks[1].expect("a chunk").tail,
            PlannedTail::Described {
                length: 40,
                block_index: 1,
                offset: 40
            }
        );
    }

    #[test]
    fn empty_files_take_no_chunk_and_no_block() {
        let files = [file("a", 0), file("b", 0)];
        let map = BlockMap::plan(&files, 1000).expect("a layout");
        assert_eq!(map.block_count(), 0);
        assert!(map.chunks.iter().all(Option::is_none));
        assert!(map.full_block_runs().is_empty());
    }

    #[test]
    fn a_set_beyond_the_block_ceiling_is_refused() {
        let files = [file("a", 70_000)];
        assert!(BlockMap::plan(&files, 1).is_err());
    }
}
