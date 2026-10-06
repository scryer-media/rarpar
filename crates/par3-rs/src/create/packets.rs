//! Turning a planned, hashed set into the packets that describe it.
//!
//! Order matters here, twice over. Every packet header carries the InputSetID,
//! and the InputSetID is derived from the file hashes and the Start packet body,
//! so the Start packet's body has to exist before any header can be written. And
//! a Directory packet names its children by *their* packet hashes, so children
//! are built before parents — which is why the directory names arrive sorted
//! deepest first.

use std::collections::BTreeMap;

use super::encode::{EncodeOutcome, TailDigest};
use super::map::{BlockMap, PlannedTail};
use super::plan::PlannedFile;
use crate::hash::{Fingerprint, FingerprintHasher};
use crate::packet::{
    BlockRange, CauchyMatrixPacket, ChunkDescription, ChunkTail, CommentPacket, CreatorPacket,
    DirectoryPacket, ExternalDataPacket, FilePacket, GaloisField, InputSetId, Packet, PacketBody,
    RootPacket, StartPacket,
};

/// Every packet a set needs, ready to be written.
#[derive(Debug, Clone)]
pub(crate) struct BuiltPackets {
    /// The identifier every one of these packets carries.
    pub set_id: InputSetId,
    /// The Creator packet, which every file begins with.
    pub creator: Vec<u8>,
    /// The Comment packet, which every file ends with when there is one.
    pub comment: Option<Vec<u8>>,
    /// Start, Matrix, File, Directory, Root and External Data packets, in the
    /// order a recovery volume repeats them.
    pub common: Vec<Vec<u8>>,
    /// Hash of the Root packet, which every Recovery Data packet names.
    pub root_hash: Fingerprint,
    /// Hash of the Matrix packet, which every Recovery Data packet names.
    /// Absent for an index-only set, which has no Matrix packet.
    pub matrix_hash: Option<Fingerprint>,
}

/// What the caller settled before any packet could be built.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SetShape {
    /// Bytes per input and recovery block.
    pub block_size: u64,
    /// The field recovery data is computed in.
    pub field: GaloisField,
    /// How many recovery blocks the set will carry.
    pub recovery_count: u64,
}

/// Build every packet of a set.
///
/// `files` and `outcome.files` are in the set's storage order; `directories` are
/// sorted so that a directory follows everything inside it.
pub(crate) fn build(
    files: &[PlannedFile],
    directories: &[String],
    map: &BlockMap,
    outcome: &EncodeOutcome,
    shape: SetShape,
    creator: &str,
    comment: Option<&str>,
) -> BuiltPackets {
    let start = StartPacket {
        parent_input_set_id: InputSetId::ZERO,
        parent_root_hash: [0u8; 16],
        block_size: shape.block_size,
        galois_field: shape.field,
        legacy_random: None,
    };
    let start_body = start.to_body_bytes();
    // Built once: the InputSetID digests what these packets carry, and then
    // they are written.
    let file_packets: Vec<FilePacket> = files
        .iter()
        .enumerate()
        .map(|(index, file)| file_packet(file, map, outcome, index))
        .collect();
    let set_id = generate_set_id(
        files,
        &file_packets,
        directories,
        shape.block_size,
        &start_body,
    );

    let mut common: Vec<Vec<u8>> = Vec::new();
    common.push(Packet::new(set_id, PacketBody::Start(start)).to_bytes());

    let matrix_hash = (shape.recovery_count > 0).then(|| {
        // Covering every input block is written as the two zeros, and a zero
        // hint means the number of rows is not declared in advance.
        let matrix = Packet::new(
            set_id,
            PacketBody::CauchyMatrix(CauchyMatrixPacket {
                range: BlockRange { first: 0, end: 0 },
                recovery_block_hint: 0,
            }),
        );
        let hash = matrix.hash();
        common.push(matrix.to_bytes());
        hash
    });

    // File packets, in storage order. Two identical files in different
    // directories produce identical packets; the second copy is dropped from the
    // stream, but both parents still name that one hash as a child.
    let mut file_hashes: Vec<Fingerprint> = Vec::with_capacity(files.len());
    let mut written: Vec<Fingerprint> = Vec::new();
    for file_packet in file_packets {
        let packet = Packet::new(set_id, PacketBody::File(file_packet));
        let hash = packet.hash();
        file_hashes.push(hash);
        if !written.contains(&hash) {
            written.push(hash);
            common.push(packet.to_bytes());
        }
    }

    // Directory packets, children first.
    let mut directory_hashes: BTreeMap<&str, Fingerprint> = BTreeMap::new();
    let mut written: Vec<Fingerprint> = Vec::new();
    for (index, name) in directories.iter().enumerate() {
        let children = children_of(
            Some(name),
            files,
            &file_hashes,
            &directories[..index],
            &directory_hashes,
        );
        let packet = Packet::new(
            set_id,
            PacketBody::Directory(DirectoryPacket {
                name: last_component(name).to_owned(),
                option_hashes: Vec::new(),
                children,
            }),
        );
        let hash = packet.hash();
        directory_hashes.insert(name.as_str(), hash);
        if !written.contains(&hash) {
            written.push(hash);
            common.push(packet.to_bytes());
        }
    }

    let root = Packet::new(
        set_id,
        PacketBody::Root(RootPacket {
            lowest_unused_block_index: map.block_count(),
            attributes: 0,
            option_hashes: Vec::new(),
            children: children_of(None, files, &file_hashes, directories, &directory_hashes),
        }),
    );
    let root_hash = root.hash();
    common.push(root.to_bytes());

    for (first, count) in map.full_block_runs() {
        let checksums = (first..first + count)
            .map(|index| outcome.block_checksums[&index])
            .collect();
        common.push(
            Packet::new(
                set_id,
                PacketBody::ExternalData(ExternalDataPacket {
                    first_block_index: first,
                    checksums,
                }),
            )
            .to_bytes(),
        );
    }

    BuiltPackets {
        set_id,
        creator: Packet::new(set_id, PacketBody::Creator(CreatorPacket::new(creator))).to_bytes(),
        comment: comment.map(|text| {
            Packet::new(set_id, PacketBody::Comment(CommentPacket::new(text))).to_bytes()
        }),
        common,
        root_hash,
        matrix_hash,
    }
}

/// One file's packet.
fn file_packet(
    file: &PlannedFile,
    map: &BlockMap,
    outcome: &EncodeOutcome,
    index: usize,
) -> FilePacket {
    let digest = &outcome.files[index];
    let chunks = match map.chunks[index] {
        // An empty file has no chunk description at all: there is nothing to
        // describe, and a zero length would mean an unprotected chunk.
        None => Vec::new(),
        Some(chunk) => {
            let tail = match &digest.tail {
                TailDigest::None => ChunkTail::None,
                TailDigest::Inline(bytes) => ChunkTail::Inline(bytes.clone()),
                TailDigest::Described {
                    rolling_hash,
                    fingerprint,
                } => {
                    let PlannedTail::Described {
                        block_index,
                        offset,
                        ..
                    } = chunk.tail
                    else {
                        unreachable!("a described tail digest comes from a described tail")
                    };
                    ChunkTail::Described {
                        rolling_hash: *rolling_hash,
                        fingerprint: *fingerprint,
                        block_index,
                        offset,
                    }
                }
            };
            vec![ChunkDescription::Protected {
                length: chunk.length,
                first_block_index: chunk.first_block_index,
                tail,
            }]
        }
    };
    FilePacket {
        name: last_component(&file.name).to_owned(),
        quick_rolling_hash: digest.quick_rolling_hash,
        fingerprint: digest.fingerprint,
        option_hashes: Vec::new(),
        chunks,
    }
}

/// The packet hashes of everything directly inside `parent`, or inside the top
/// level when it is `None`, sorted the way the format asks for: by the hash
/// bytes.
fn children_of(
    parent: Option<&str>,
    files: &[PlannedFile],
    file_hashes: &[Fingerprint],
    directories: &[String],
    directory_hashes: &BTreeMap<&str, Fingerprint>,
) -> Vec<Fingerprint> {
    let mut children: Vec<Fingerprint> = Vec::new();
    for (file, hash) in files.iter().zip(file_hashes) {
        if parent_of(&file.name) == parent {
            children.push(*hash);
        }
    }
    for name in directories {
        if parent_of(name) == parent
            && let Some(hash) = directory_hashes.get(name.as_str())
        {
            children.push(*hash);
        }
    }
    sort_children(&mut children);
    children
}

/// Put a Directory or Root packet's children in the order the format asks for
/// and the reference writes them: by their packet hash bytes.
pub(crate) fn sort_children(children: &mut [Fingerprint]) {
    children.sort_unstable();
}

/// The directory a `/`-separated name sits in, or `None` for the top level.
fn parent_of(name: &str) -> Option<&str> {
    name.rsplit_once('/').map(|(parent, _)| parent)
}

/// The last `/`-separated component of a name, which is all a File or Directory
/// packet stores.
fn last_component(name: &str) -> &str {
    name.rsplit_once('/').map_or(name, |(_, last)| last)
}

/// Derive the set's InputSetID for this module's planned files.
///
/// The chunk descriptions fed to the digest are the ones the File packets
/// carry, so this and the streaming engine in [`crate::creation`] share one
/// derivation through [`input_set_id`].
fn generate_set_id(
    files: &[PlannedFile],
    packets: &[FilePacket],
    directories: &[String],
    block_size: u64,
    start_body: &[u8],
) -> InputSetId {
    input_set_id(
        files.iter().zip(packets).map(|(file, packet)| SetIdFile {
            name: &file.name,
            size: file.size,
            fingerprint: &packet.fingerprint,
            chunks: &packet.chunks,
        }),
        directories.iter().map(String::as_str),
        block_size,
        start_body,
    )
}

/// One file as the InputSetID digest sees it.
pub(crate) struct SetIdFile<'a> {
    /// Relative `/`-separated name, as given for the whole path rather than
    /// the last component a File packet stores.
    pub name: &'a str,
    /// File size in bytes.
    pub size: u64,
    /// The 16-byte hash of the file's protected chunks.
    pub fingerprint: &'a Fingerprint,
    /// The chunk descriptions its File packet carries.
    pub chunks: &'a [ChunkDescription],
}

/// Derive an InputSetID the reference implementation's way.
///
/// The reference calls this a globally unique random number, and it is not
/// derivable from anything a reader can see, so nothing validates it. It is
/// built the same way here anyway — a digest over every file of its name with a
/// zero terminator, its size, its hash and its chunk layout, then every
/// directory name with a zero terminator; then a second digest of the first
/// eight bytes of that and the Start packet body — so that output matches the
/// reference byte for byte, two runs over identical inputs agree, and two runs
/// over different ones do not.
///
/// Each chunk contributes its length; for a chunk of at least one block (or an
/// unprotected chunk, which the reference stores as length zero with the real
/// length in the block field) the first block index; and for a tail of at least
/// 40 bytes the block and offset holding it. Modification times and
/// permissions feed the digest only when the matching option packets are
/// written, and this crate writes none.
pub(crate) fn input_set_id<'a>(
    files: impl IntoIterator<Item = SetIdFile<'a>>,
    directories: impl IntoIterator<Item = &'a str>,
    block_size: u64,
    start_body: &[u8],
) -> InputSetId {
    let mut hasher = FingerprintHasher::new();
    for file in files {
        hasher.update(file.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(&file.size.to_le_bytes());
        hasher.update(file.fingerprint);
        if file.size == 0 {
            continue;
        }
        for chunk in file.chunks {
            match chunk {
                ChunkDescription::Unprotected { length } => {
                    hasher.update(&0u64.to_le_bytes());
                    hasher.update(&length.to_le_bytes());
                }
                ChunkDescription::Protected {
                    length,
                    first_block_index,
                    tail,
                } => {
                    hasher.update(&length.to_le_bytes());
                    if *length >= block_size {
                        hasher.update(&first_block_index.unwrap_or(0).to_le_bytes());
                    }
                    if let ChunkTail::Described {
                        block_index,
                        offset,
                        ..
                    } = tail
                    {
                        hasher.update(&block_index.to_le_bytes());
                        hasher.update(&offset.to_le_bytes());
                    }
                }
            }
        }
    }
    for name in directories {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
    }
    let seed = hasher.finalize();

    let mut hasher = FingerprintHasher::new();
    hasher.update(&seed[..8]);
    hasher.update(start_body);
    let digest = hasher.finalize();
    InputSetId(digest[..8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_splits_into_a_parent_and_a_last_component() {
        assert_eq!(parent_of("a.bin"), None);
        assert_eq!(parent_of("sub/c.bin"), Some("sub"));
        assert_eq!(parent_of("a/b/c"), Some("a/b"));
        assert_eq!(last_component("a.bin"), "a.bin");
        assert_eq!(last_component("a/b/c"), "c");
    }
}
