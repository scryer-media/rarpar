//! Which file writes which bytes of which input block.
//!
//! A repair has to work in blocks, because that is what the code is defined
//! over, but it reads and writes files. This is the table between the two: for
//! every input block, the file stretches that fill it, and for every file, the
//! blocks it lands in. It is built from the chunk descriptions alone, before any
//! file is opened, and a set whose descriptions contradict each other is refused
//! here rather than discovered halfway through a rebuild.

use std::collections::BTreeMap;

use crate::error::{Par3Error, Result};
use crate::packet::{ChunkDescription, ChunkTail};
use crate::set::Par3Set;

/// One stretch of one input file that lands inside one input block.
///
/// A whole block written by a file is a region as long as the block; a chunk
/// tail is a shorter one at whatever offset its File packet gave it. Nothing
/// else writes an input block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Region {
    /// The input block this lands in.
    pub block_index: u64,
    /// Where the bytes are in the file.
    pub file_offset: u64,
    /// Where they go in the block.
    pub block_offset: u64,
    /// How many there are.
    pub length: u64,
}

impl Region {
    /// The first byte after this region, in the file.
    pub(crate) fn file_end(&self) -> u64 {
        self.file_offset.saturating_add(self.length)
    }
}

/// The whole set's block ownership, seen from both sides.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// Bytes per input block.
    pub block_size: u64,
    /// Each file's regions, in ascending file offset. Indexed the way
    /// [`Par3Set::files`] is.
    pub per_file: Vec<Vec<Region>>,
    /// How many regions write each block. A block with more than one is a block
    /// of packed chunk tails.
    pub writers: BTreeMap<u64, u32>,
}

impl Layout {
    /// Build the table, refusing a set whose chunk descriptions do not agree.
    ///
    /// `max_blocks` bounds the work: every region belongs to a distinct block or
    /// a distinct chunk, so refusing an implausible block count up front is what
    /// keeps a File packet that claims `u64::MAX` bytes of one-byte blocks from
    /// being enumerated.
    pub(crate) fn build(set: &Par3Set, max_blocks: u64) -> Result<Self> {
        let block_size = set.block_size();
        if block_size == 0 {
            return Err(unrepairable(
                "its Start packet declares a block size of zero",
            ));
        }
        let block_count = set.block_count();
        if block_count > max_blocks {
            return Err(Par3Error::RepairLimitExceeded {
                reason: format!(
                    "the set has {block_count} input blocks, over the {max_blocks} the limits allow"
                ),
            });
        }

        let mut claimed: BTreeMap<u64, Vec<Region>> = BTreeMap::new();
        let mut per_file: Vec<Vec<Region>> = Vec::with_capacity(set.files().len());

        for file in set.files() {
            let mut regions: Vec<Region> = Vec::new();
            let mut offset: u64 = 0;
            for chunk in file.chunks() {
                let ChunkDescription::Protected {
                    length,
                    first_block_index,
                    tail,
                } = chunk
                else {
                    return Err(unrepairable(format!(
                        "{} has unprotected chunks, whose bytes no input block covers",
                        file.path()
                    )));
                };

                let full_blocks = length / block_size;
                if full_blocks > block_count {
                    return Err(unrepairable(format!(
                        "{} claims {full_blocks} whole input blocks in a set of {block_count}",
                        file.path()
                    )));
                }
                if full_blocks > 0 {
                    let first = first_block_index.ok_or_else(|| {
                        unrepairable(format!(
                            "{} is at least one block long but names no first block",
                            file.path()
                        ))
                    })?;
                    for step in 0..full_blocks {
                        let index = first.checked_add(step).ok_or_else(|| {
                            unrepairable(format!("{}'s block range overflows", file.path()))
                        })?;
                        regions.push(Region {
                            block_index: index,
                            file_offset: offset.saturating_add(step * block_size),
                            block_offset: 0,
                            length: block_size,
                        });
                    }
                }

                let tail_size = length % block_size;
                if let ChunkTail::Described {
                    block_index,
                    offset: block_offset,
                    ..
                } = tail
                {
                    if block_offset
                        .checked_add(tail_size)
                        .is_none_or(|end| end > block_size)
                    {
                        return Err(unrepairable(format!(
                            "{}'s {tail_size}-byte chunk tail does not fit in block {block_index} \
                             at offset {block_offset}",
                            file.path()
                        )));
                    }
                    regions.push(Region {
                        block_index: *block_index,
                        file_offset: offset.saturating_add(full_blocks * block_size),
                        block_offset: *block_offset,
                        length: tail_size,
                    });
                }

                offset = offset.checked_add(*length).ok_or_else(|| {
                    unrepairable(format!("{}'s chunk lengths overflow", file.path()))
                })?;
            }

            for region in &regions {
                place(&mut claimed, region, block_count, file.path())?;
            }
            per_file.push(regions);
        }

        // Every block the code covers has to come from somewhere: an input the
        // decoder is never given is one it cannot solve around, and a block no
        // file writes is one no repair could put back.
        if claimed.len() as u64 != block_count {
            let missing = (0..block_count)
                .find(|index| !claimed.contains_key(index))
                .unwrap_or(block_count);
            return Err(unrepairable(format!(
                "input block {missing} is written by no file"
            )));
        }

        let writers = claimed
            .into_iter()
            .map(|(index, regions)| (index, regions.len() as u32))
            .collect();
        Ok(Self {
            block_size,
            per_file,
            writers,
        })
    }

    /// How many regions write `block`, or zero for a block outside the set.
    pub(crate) fn writers_of(&self, block: u64) -> u32 {
        self.writers.get(&block).copied().unwrap_or(0)
    }
}

/// Record one region against its block, refusing an index outside the set and
/// two writers that claim the same bytes.
fn place(
    claimed: &mut BTreeMap<u64, Vec<Region>>,
    region: &Region,
    block_count: u64,
    path: &str,
) -> Result<()> {
    if region.block_index >= block_count {
        return Err(unrepairable(format!(
            "{path} writes input block {} in a set of {block_count} blocks",
            region.block_index
        )));
    }
    let end = region.block_offset + region.length;
    let existing = claimed.entry(region.block_index).or_default();
    for other in existing.iter() {
        let other_end = other.block_offset + other.length;
        if region.block_offset < other_end && other.block_offset < end {
            return Err(unrepairable(format!(
                "{path} and another chunk both claim bytes {}..{end} of input block {}",
                region.block_offset, region.block_index
            )));
        }
    }
    existing.push(*region);
    Ok(())
}

fn unrepairable(reason: impl Into<String>) -> Par3Error {
    Par3Error::UnrepairableSet {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Fingerprint, fingerprint};
    use crate::packet::{
        FilePacket, GaloisField, InputSetId, Packet, PacketBody, RootPacket, StartPacket,
    };

    const ID: InputSetId = InputSetId([5; 8]);

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

    fn file(name: &str, chunks: Vec<ChunkDescription>) -> FilePacket {
        FilePacket {
            name: name.to_owned(),
            quick_rolling_hash: 0,
            fingerprint: fingerprint(name.as_bytes()),
            option_hashes: Vec::new(),
            chunks,
        }
    }

    fn set_of(block_size: u64, block_count: u64, files: Vec<FilePacket>) -> Par3Set {
        let files: Vec<Packet> = files
            .into_iter()
            .map(|file| Packet::new(ID, PacketBody::File(file)))
            .collect();
        let children: Vec<Fingerprint> = files.iter().map(Packet::hash).collect();
        let mut packets = vec![
            start(block_size),
            Packet::new(
                ID,
                PacketBody::Root(RootPacket {
                    lowest_unused_block_index: block_count,
                    attributes: 0,
                    option_hashes: Vec::new(),
                    children,
                }),
            ),
        ];
        packets.extend(files);
        Par3Set::from_packets_for(packets, ID).expect("builds")
    }

    fn described(block_index: u64, offset: u64) -> ChunkTail {
        ChunkTail::Described {
            rolling_hash: 0,
            fingerprint: [0u8; 16],
            block_index,
            offset,
        }
    }

    #[test]
    fn two_tails_share_a_block_without_overlapping() {
        let set = set_of(
            100,
            1,
            vec![
                file(
                    "a",
                    vec![ChunkDescription::Protected {
                        length: 40,
                        first_block_index: None,
                        tail: described(0, 0),
                    }],
                ),
                file(
                    "b",
                    vec![ChunkDescription::Protected {
                        length: 50,
                        first_block_index: None,
                        tail: described(0, 40),
                    }],
                ),
            ],
        );
        let layout = Layout::build(&set, 65_536).expect("a consistent set");
        assert_eq!(layout.block_size, 100);
        assert_eq!(layout.writers_of(0), 2);
        assert_eq!(layout.per_file.len(), 2);
        assert_eq!(
            layout.per_file[0][0],
            Region {
                block_index: 0,
                file_offset: 0,
                block_offset: 0,
                length: 40,
            }
        );
    }

    #[test]
    fn two_tails_claiming_the_same_bytes_are_refused() {
        let set = set_of(
            100,
            1,
            vec![
                file(
                    "a",
                    vec![ChunkDescription::Protected {
                        length: 40,
                        first_block_index: None,
                        tail: described(0, 0),
                    }],
                ),
                file(
                    "b",
                    vec![ChunkDescription::Protected {
                        length: 50,
                        first_block_index: None,
                        tail: described(0, 20),
                    }],
                ),
            ],
        );
        assert!(matches!(
            Layout::build(&set, 65_536),
            Err(Par3Error::UnrepairableSet { .. })
        ));
    }

    #[test]
    fn a_tail_that_runs_off_the_end_of_its_block_is_refused() {
        let set = set_of(
            100,
            1,
            vec![file(
                "a",
                vec![ChunkDescription::Protected {
                    length: 90,
                    first_block_index: None,
                    tail: described(0, 40),
                }],
            )],
        );
        assert!(matches!(
            Layout::build(&set, 65_536),
            Err(Par3Error::UnrepairableSet { .. })
        ));
    }

    #[test]
    fn a_block_no_file_writes_is_refused() {
        let set = set_of(
            100,
            3,
            vec![file(
                "a",
                vec![ChunkDescription::Protected {
                    length: 100,
                    first_block_index: Some(0),
                    tail: ChunkTail::None,
                }],
            )],
        );
        let error = Layout::build(&set, 65_536).expect_err("block 1 has no writer");
        assert!(
            matches!(&error, Par3Error::UnrepairableSet { reason } if reason.contains("block 1")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_unprotected_chunk_is_refused() {
        let set = set_of(
            100,
            1,
            vec![file(
                "a",
                vec![
                    ChunkDescription::Protected {
                        length: 100,
                        first_block_index: Some(0),
                        tail: ChunkTail::None,
                    },
                    ChunkDescription::Unprotected { length: 8 },
                ],
            )],
        );
        assert!(matches!(
            Layout::build(&set, 65_536),
            Err(Par3Error::UnrepairableSet { .. })
        ));
    }

    #[test]
    fn a_chunk_claiming_more_blocks_than_the_set_has_is_refused_without_enumerating_them() {
        // The set's own validation allows this only because the Root packet
        // claims just as many blocks; the layout refuses it before walking
        // `u64::MAX` one-byte blocks.
        let set = set_of(
            1,
            u64::MAX,
            vec![file(
                "a",
                vec![ChunkDescription::Protected {
                    length: u64::MAX,
                    first_block_index: Some(0),
                    tail: ChunkTail::None,
                }],
            )],
        );
        assert!(matches!(
            Layout::build(&set, 65_536),
            Err(Par3Error::RepairLimitExceeded { .. })
        ));
    }

    #[test]
    fn a_block_size_of_zero_is_refused() {
        let packets = vec![
            start(0),
            Packet::new(
                ID,
                PacketBody::Root(RootPacket {
                    lowest_unused_block_index: 0,
                    attributes: 0,
                    option_hashes: Vec::new(),
                    children: Vec::new(),
                }),
            ),
        ];
        let set = Par3Set::from_packets_for(packets, ID).expect("builds");
        assert!(matches!(
            Layout::build(&set, 65_536),
            Err(Par3Error::UnrepairableSet { .. })
        ));
    }
}
